//! A [`CrlSource`] that downloads lists over HTTP. Behind the `net` feature; the revocation checking
//! itself (`crate::revocation`) is pure and is handed whatever a source returns.

use crate::revocation::{Crl, CrlSource, Revocation};
use crate::verify_error::{Error, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Fetches CRLs over plain HTTP from the distribution points named in a certificate, and keeps
/// them until their `nextUpdate`.
///
/// The download is not a secure channel and does not need to be: the list is verified against the
/// certificate's issuer before it counts. Fetches are limited in size (16 MiB) and time (10 s),
/// follow no more than three redirects, and only `http://` URLs are used.
pub struct HttpCrlSource {
    client: crate::http::Client,
    cache: Mutex<HashMap<String, Arc<Crl>>>,
}

impl HttpCrlSource {
    pub fn new() -> HttpCrlSource {
        let mut tls = crate::tls::ClientConfig::new(crate::x509::TrustStore::empty());
        tls.revocation = Revocation::off();
        let client = crate::http::Client::with_tls_config(tls)
            .allow_insecure_http(true)
            .timeout(Duration::from_secs(10))
            .connect_timeout(Duration::from_secs(5))
            .total_timeout(Duration::from_secs(20))
            .max_redirects(3)
            .max_body_bytes(16 << 20);
        HttpCrlSource { client, cache: Mutex::new(HashMap::new()) }
    }
}

impl Default for HttpCrlSource {
    fn default() -> Self {
        HttpCrlSource::new()
    }
}

impl CrlSource for HttpCrlSource {
    fn fetch(&self, url: &str) -> Result<Arc<Crl>> {
        if !url.starts_with("http://") {
            return Err(Error::Unavailable(format!("not fetching a CRL from {:?}: only http:// URLs are used", url)));
        }
        let now = crate::sys::now_unix();
        if let Some(c) = self.cache.lock().unwrap_or_else(|e| e.into_inner()).get(url) {
            if !c.is_stale(now) {
                return Ok(c.clone());
            }
        }
        let response = self.client.get(url).map_err(|e| Error::Unavailable(format!("{}: {}", url, e)))?;
        if response.status != 200 {
            return Err(Error::Unavailable(format!("CRL download answered {}", response.status)));
        }
        let crl = if response.body.starts_with(b"-----BEGIN") {
            Crl::from_pem(&String::from_utf8_lossy(&response.body))?
        } else {
            Crl::from_der(&response.body)?
        };
        let crl = Arc::new(crl);
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(url.to_string(), crl.clone());
        Ok(crl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Serves `answers` (one raw HTTP response per connection, in order) on a local port.
    fn serve(answers: Vec<Vec<u8>>) -> (u16, Arc<AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = Arc::new(AtomicUsize::new(0));
        let count = served.clone();
        std::thread::spawn(move || {
            for answer in answers {
                let Ok((mut s, _)) = listener.accept() else { return };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                count.fetch_add(1, Ordering::SeqCst);
                let _ = s.write_all(&answer);
            }
        });
        (port, served)
    }

    fn http_ok(body: &[u8]) -> Vec<u8> {
        let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        r.extend_from_slice(body);
        r
    }

    #[test]
    fn the_http_source_downloads_parses_and_refuses_bad_answers() {
        let good = include_bytes!("../../tests/data/rev_crl_empty.der").as_slice();
        let (port, served) = serve(vec![
            http_ok(good),
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            http_ok(b"this is not a CRL"),
            http_ok(good),
        ]);
        let source = HttpCrlSource::new();
        let url = format!("http://127.0.0.1:{}/inter.crl", port);
        let crl = source.fetch(&url).unwrap();
        assert_eq!(crl.len(), 1);
        // the fixture's window closed long before the real clock (nextUpdate is 2026-09-20 in the
        // fixtures), so the cached copy is stale and the next call downloads again
        assert!(crl.is_stale(crate::sys::now_unix()));
        let err = source.fetch(&url).err().expect("a 404 is an error").to_string();
        assert!(err.contains("404"), "{}", err);
        assert!(source.fetch(&url).is_err(), "garbage is not a CRL");
        assert!(source.fetch(&url).is_ok());
        assert_eq!(served.load(Ordering::SeqCst), 4);
        // only plain http is used: nothing is sent for other schemes
        for bad in ["https://crl.example.test/x.crl", "ldap://crl.example.test/x", "file:///etc/passwd", "ftp://example.test/x.crl"] {
            let err = source.fetch(bad).err().expect("only http:// URLs are fetched").to_string();
            assert!(err.contains("only http://"), "{}: {}", bad, err);
        }
        assert_eq!(served.load(Ordering::SeqCst), 4);
    }
}
