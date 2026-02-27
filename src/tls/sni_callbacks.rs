use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;

use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;

use crate::tls::cert_cache::TlsCertStore;

pub struct SniCallbacks {
    pub cache: Arc<RwLock<TlsCertStore>>,
}

#[async_trait]
impl TlsAccept for SniCallbacks {
    async fn certificate_callback(&self, ssl: &mut TlsRef) -> () {
        let cache = self.cache.read().await;

        let requested_sni = ssl
            .servername(pingora_core::tls::ssl::NameType::HOST_NAME)
            .map(|s| s.to_string());

        let chosen = requested_sni
            .as_ref()
            .and_then(|sni| cache.entries.get(sni))
            .or_else(|| {
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
