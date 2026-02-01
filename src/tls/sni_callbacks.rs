use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;

use crate::tls::cert_cache::TlsCertStore;

/// SNI callback that assigns certificate/key during the handshake from the cache.
/// This avoids per-handshake file I/O by using parsed, cached X509 chain and PKey.
pub struct SniCallbacks {
    pub cache: Arc<RwLock<TlsCertStore>>,
    pub default_sni: String,
}

#[async_trait]
impl TlsAccept for SniCallbacks {
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        // Read requested SNI hostname, defaulting if none is provided
        let sni = ssl
            .servername(pingora_core::tls::ssl::NameType::HOST_NAME)
            .unwrap_or(&self.default_sni)
            .to_string();

        // Snapshot the cache
        let cache = self.cache.read().await;

        // Choose entry for SNI or default
        let chosen = cache.entries.get(&sni).or_else(|| {
            cache
                .default_sni
                .as_ref()
                .and_then(|d| cache.entries.get(d))
        });

        if let Some(entry) = chosen {
            // Attach cached certificate and private key to the ongoing handshake
            if let (Some(chain), Some(pkey)) = (entry.x509_chain.as_ref(), entry.pkey.as_ref()) {
                // Use the first cert in the chain as the leaf cert
                if let Some(leaf) = chain.first() {
                    let _ = pingora_core::tls::ext::ssl_use_certificate(ssl, leaf);
                }
                let _ = pingora_core::tls::ext::ssl_use_private_key(ssl, pkey);
            }
        }
    }
}
