use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Cached certificate entry for an SNI hostname.
/// - Stores PEM paths and metadata for change detection
/// - Holds parsed X509 chain and private key for per-handshake assignment (no I/O on handshake)
#[derive(Debug)]
pub struct CertEntry {
    pub cert_path: String,
    pub key_path: String,
    pub cert_mtime: SystemTime,
    pub key_mtime: SystemTime,
    pub cert_hash: u64,
    pub key_hash: u64,
    pub x509_chain: Option<Vec<pingora_core::tls::x509::X509>>,
    pub pkey: Option<pingora_core::tls::pkey::PKey<pingora_core::tls::pkey::Private>>,
}

/// In-memory TLS certificate store keyed by SNI hostname.
/// The first discovered SNI is used as the default fallback.
#[derive(Default, Debug)]
pub struct TlsCertStore {
    pub entries: HashMap<String, CertEntry>,
    pub default_sni: Option<String>,
}

impl TlsCertStore {
    /// Scan a directory for per-domain subfolders containing `cert.pem` and `privkey.pem`.
    /// Initializes metadata and placeholders; does not parse PEMs here.
    pub fn load_from_dir(dir: &str) -> Result<Self> {
        use std::fs;

        let mut entries = HashMap::new();
        let mut default_sni: Option<String> = None;

        for entry in fs::read_dir(dir).context("reading tls_cert_dir")? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let sni = match path.file_name().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            let cert_path = Path::new(&path).join("cert.pem");
            let key_path = Path::new(&path).join("privkey.pem");
            if !cert_path.is_file() || !key_path.is_file() {
                continue;
            }

            if default_sni.is_none() {
                default_sni = Some(sni.clone());
            }
            entries.insert(
                sni,
                CertEntry {
                    cert_path: cert_path.display().to_string(),
                    key_path: key_path.display().to_string(),
                    cert_mtime: SystemTime::UNIX_EPOCH,
                    key_mtime: SystemTime::UNIX_EPOCH,
                    cert_hash: 0,
                    key_hash: 0,
                    x509_chain: None,
                    pkey: None,
                },
            );
        }

        Ok(TlsCertStore { entries, default_sni })
    }

    /// Get the cert entry for a given SNI, falling back to default if not found.
    pub fn get(&self, sni: &str) -> Option<&CertEntry> {
        self.entries.get(sni).or_else(|| {
            self.default_sni
                .as_ref()
                .and_then(|d| self.entries.get(d))
        })
    }
}

/// Periodic task to refresh TLS certificates from disk.
/// - Parses PEMs into X509 chain and private key
/// - Detects changes via mtime and content hash
/// - Updates the cache atomically
pub async fn run_cert_refresh_task(
    store: Arc<RwLock<TlsCertStore>>,
    tls_cert_dir: String,
    period: Duration,
) {
    use std::fs;

    fn hash_bytes(data: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }

    let mut tick = tokio::time::interval(period);
    loop {
        tick.tick().await;

        let mut new_entries: HashMap<String, CertEntry> = HashMap::new();
        let mut new_default: Option<String> = None;

        match fs::read_dir(&tls_cert_dir) {
            Ok(dir_iter) => {
                for entry_res in dir_iter {
                    if let Ok(entry) = entry_res {
                        let path = entry.path();
                        if !path.is_dir() {
                            continue;
                        }
                        let sni = match path.file_name().and_then(|s| s.to_str()) {
                            Some(s) => s.to_string(),
                            None => continue,
                        };
                        let cert_path = Path::new(&path).join("cert.pem");
                        let key_path = Path::new(&path).join("privkey.pem");
                        if !cert_path.is_file() || !key_path.is_file() {
                            continue;
                        }

                        // Metadata and content
                        let cert_meta = match fs::metadata(&cert_path) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        let key_meta = match fs::metadata(&key_path) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        let cert_bytes = match fs::read(&cert_path) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };
                        let key_bytes = match fs::read(&key_path) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        // Parse X509 chain and private key once per refresh
                        let parsed_chain =
                            pingora_core::tls::x509::X509::stack_from_pem(&cert_bytes).ok();
                        let parsed_pkey =
                            pingora_core::tls::pkey::PKey::private_key_from_pem(&key_bytes).ok();

                        let entry = CertEntry {
                            cert_path: cert_path.display().to_string(),
                            key_path: key_path.display().to_string(),
                            cert_mtime: cert_meta
                                .modified()
                                .unwrap_or(SystemTime::UNIX_EPOCH),
                            key_mtime: key_meta
                                .modified()
                                .unwrap_or(SystemTime::UNIX_EPOCH),
                            cert_hash: hash_bytes(&cert_bytes),
                            key_hash: hash_bytes(&key_bytes),
                            x509_chain: parsed_chain,
                            pkey: parsed_pkey,
                        };

                        if new_default.is_none() {
                            new_default = Some(sni.clone());
                        }
                        new_entries.insert(sni, entry);
                    }
                }
            }
            Err(e) => {
                warn!("TLS cert refresh failed to read dir {}: {}", tls_cert_dir, e);
                continue;
            }
        }

        // Diff and update the cache atomically
        {
            let mut guard = store.write().await;

            // Remove entries that no longer exist
            guard.entries.retain(|sni, _| new_entries.contains_key(sni));

            // Add or update changed entries
            for (sni, new_entry) in new_entries.into_iter() {
                match guard.entries.get(&sni) {
                    Some(old) => {
                        if old.cert_hash != new_entry.cert_hash
                            || old.key_hash != new_entry.key_hash
                            || old.cert_mtime != new_entry.cert_mtime
                            || old.key_mtime != new_entry.key_mtime
                            || old.cert_path != new_entry.cert_path
                            || old.key_path != new_entry.key_path
                        {
                            guard.entries.insert(sni.clone(), new_entry);
                            info!("TLS cert cache updated for SNI {}", sni);
                        }
                    }
                    None => {
                        guard.entries.insert(sni.clone(), new_entry);
                        info!("TLS cert cache added for SNI {}", sni);
                    }
                }
            }

            // Update default SNI if not set
            if guard.default_sni.is_none() {
                guard.default_sni = new_default;
            }
        }

        info!("TLS cert store refresh cycle completed for {}", tls_cert_dir);
    }
}

use std::collections::hash_map::DefaultHasher;
