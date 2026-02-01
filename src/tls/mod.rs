use anyhow::{anyhow, Result};

pub mod cert_cache;
pub mod sni_callbacks;

pub use cert_cache::{CertEntry, TlsCertStore, run_cert_refresh_task};
pub use sni_callbacks::SniCallbacks;

/// Build Pingora TLS settings using callbacks, enabling HTTP/2 ALPN.
/// Returns a configured `TlsSettings` ready to add to a listener.
pub fn tls_settings_with_callbacks(
    callbacks: Box<dyn pingora_core::listeners::TlsAccept + Send + Sync>,
) -> Result<pingora_core::listeners::tls::TlsSettings> {
    let mut settings = pingora_core::listeners::tls::TlsSettings::with_callbacks(callbacks)
        .map_err(|e| anyhow!("failed to build TLS settings with callbacks: {e}"))?;
    settings.enable_h2();
    Ok(settings)
}
