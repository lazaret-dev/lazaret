//! What the library takes from the operating system: the clock and the CA bundle files. Behind the
//! `net` feature; the pure verification part of the crate is handed the time and the trust anchors.

use crate::error::{cert, Result};
use crate::x509::TrustStore;
use std::path::Path;

/// Loads the trust anchors from a PEM file (a CA bundle).
pub fn trust_store_from_pem_file(path: impl AsRef<Path>) -> Result<TrustStore> {
    let text = std::fs::read_to_string(path)?;
    let mut store = TrustStore::empty();
    store.add_pem(&text);
    if store.is_empty() {
        return cert("no usable certificates found in PEM file");
    }
    Ok(store)
}

/// Loads the operating system's CA bundle from its conventional file location.
///
/// Honors `SSL_CERT_FILE` first. Common Linux, macOS and BSD bundle paths follow. This crate
/// cannot read the Windows certificate store without extra FFI; on Windows, supply a PEM file.
pub fn system_trust_store() -> Result<TrustStore> {
    let mut candidates: Vec<String> = Vec::new();
    if let Ok(p) = std::env::var("SSL_CERT_FILE") {
        candidates.push(p);
    }
    for p in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/usr/local/etc/openssl@3/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
        "/opt/homebrew/etc/openssl@3/cert.pem",
        "/usr/local/share/certs/ca-root-nss.crt",
    ] {
        candidates.push(p.to_string());
    }
    for c in &candidates {
        if let Ok(store) = trust_store_from_pem_file(c) {
            return Ok(store);
        }
    }
    cert("could not find a system CA bundle; set SSL_CERT_FILE or load a PEM file explicitly")
}

/// Current time as Unix seconds.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
