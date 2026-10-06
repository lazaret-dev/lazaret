//! Interoperability tests against `openssl s_server` (an independent TLS 1.3 implementation).
//!
//! The tests generate throwaway certificates with the `openssl` command line tool at run time and
//! are skipped (with a message) when that tool is not installed.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tiny_https::http::HttpCrlSource;
use tiny_https::revocation::{Crl, Revocation, RevocationMode};
use tiny_https::tls::{ClientConfig, Suite, TlsStream};
use tiny_https::x509::TrustStore;

fn have_openssl() -> bool {
    Command::new("openssl").arg("version").stdout(Stdio::null()).stderr(Stdio::null()).status().map(|s| s.success()).unwrap_or(false)
}

fn run(args: &[&str], dir: &Path) {
    let out = Command::new("openssl").args(args).current_dir(dir).output().expect("failed to run openssl");
    assert!(out.status.success(), "openssl {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    /// `key_kind` is one of "rsa", "p256", "p384", "ed25519". The CA's key is RSA.
    fn new(name: &str, key_kind: &str) -> Fixture {
        Fixture::with_extensions(name, key_kind, "")
    }

    /// Like `new`, with extra lines for the server certificate's extension section.
    fn with_extensions(name: &str, key_kind: &str, extra_extensions: &str) -> Fixture {
        Fixture::with_ca(name, "rsa", key_kind, extra_extensions)
    }

    /// `ca_kind` and `key_kind` are each one of "rsa", "p256", "p384", "ed25519".
    fn with_ca(name: &str, ca_kind: &str, key_kind: &str, extra_extensions: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("tiny_https_interop_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let key_args = |kind: &str| -> Vec<&'static str> {
            match kind {
                "rsa" => vec!["-newkey", "rsa:2048"],
                "p256" => vec!["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"],
                "p384" => vec!["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp384r1"],
                "ed25519" => vec!["-newkey", "ed25519"],
                _ => unreachable!(),
            }
        };
        // Ed25519 takes no digest argument
        let digest: Vec<&str> = if ca_kind == "ed25519" { vec![] } else { vec!["-sha256"] };
        let mut args = vec!["req", "-x509"];
        args.extend(key_args(ca_kind));
        args.extend([
            "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "36500", "-subj", "/CN=Interop Test CA", "-addext",
            "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        args.extend(&digest);
        run(&args, &dir);
        let mut args = vec!["req"];
        args.extend(key_args(key_kind));
        args.extend(["-nodes", "-keyout", "srv.key", "-out", "srv.csr", "-subj", "/CN=localhost"]);
        run(&args, &dir);
        fs::write(
            dir.join("ext.cnf"),
            format!(
                "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n{}",
                extra_extensions
            ),
        )
        .unwrap();
        let mut args = vec!["x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "srv.pem", "-days", "36500"];
        args.extend(&digest);
        args.extend(["-extfile", "ext.cnf"]);
        run(&args, &dir);
        Fixture { dir }
    }

    fn trust(&self) -> TrustStore {
        tiny_https::sys::trust_store_from_pem_file(self.dir.join("ca.pem")).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Starts `openssl s_server`; `extra` are additional arguments (e.g. cipher suite, -www).
fn start_server(fx: &Fixture, extra: &[&str]) -> Server {
    start_server_with_stdout(fx, extra, Stdio::null())
}

/// Like `start_server`, with the server's stdout redirected (`s_server -quiet` writes the
/// application data it receives to stdout).
fn start_server_with_stdout(fx: &Fixture, extra: &[&str], stdout: Stdio) -> Server {
    let port = free_port();
    let mut cmd = Command::new("openssl");
    cmd.args(["s_server", "-accept", &format!("127.0.0.1:{}", port), "-cert", "srv.pem", "-key", "srv.key", "-no_ticket"])
        .args(extra)
        .current_dir(&fx.dir)
        .stdin(Stdio::piped())
        .stdout(stdout)
        .stderr(Stdio::null());
    let child = cmd.spawn().expect("failed to start openssl s_server");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            // that probe connection made s_server try a handshake and fail; give it a moment to loop
            std::thread::sleep(Duration::from_millis(150));
            break;
        }
        assert!(Instant::now() < deadline, "s_server did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
    Server { child, port }
}

fn connect(server: &Server, name: &str, config: &ClientConfig) -> tiny_https::error::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    TlsStream::connect(tcp, name, config)
}

fn get_root(tls: &mut TlsStream<TcpStream>) -> String {
    tls.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut body = Vec::new();
    tls.read_to_end(&mut body).unwrap();
    String::from_utf8_lossy(&body).into_owned()
}

fn suite_arg(s: Suite) -> &'static str {
    s.name()
}

#[test]
fn handshake_matrix_all_suites_and_key_types() {
    if !have_openssl() {
        eprintln!("skipping: openssl not installed");
        return;
    }
    for kind in ["rsa", "p256", "p384", "ed25519"] {
        let fx = Fixture::new(kind, kind);
        for suite in Suite::ALL {
            let server = start_server(&fx, &["-www", "-tls1_3", "-ciphersuites", suite_arg(suite)]);
            let config = ClientConfig::new(fx.trust());
            let mut tls = connect(&server, "localhost", &config).unwrap_or_else(|e| panic!("{} / {}: {}", kind, suite.name(), e));
            assert_eq!(tls.cipher_suite(), Some(suite), "wrong suite negotiated for {}", kind);
            let page = get_root(&mut tls);
            assert!(page.starts_with("HTTP/1.0 200 ok"), "{} / {}: unexpected response {:?}", kind, suite.name(), &page[..page.len().min(80)]);
            assert!(page.contains(suite.name()), "server did not report suite {}: {}", suite.name(), page);
        }
    }
}

/// Certificates and CertificateVerify signatures that are all Ed25519, and the mixed pairings: an Ed25519 CA
/// issuing a P-256 certificate, a P-256 CA issuing an Ed25519 one.
#[test]
fn ed25519_chains_in_every_pairing() {
    if !have_openssl() {
        eprintln!("skipping: openssl not installed");
        return;
    }
    for (ca, key) in [("ed25519", "ed25519"), ("ed25519", "p256"), ("p256", "ed25519"), ("ed25519", "rsa")] {
        let fx = Fixture::with_ca(&format!("ed_{ca}_{key}"), ca, key, "");
        let server = start_server(&fx, &["-www", "-tls1_3"]);
        let config = ClientConfig::new(fx.trust());
        let mut tls = connect(&server, "localhost", &config).unwrap_or_else(|e| panic!("CA {ca}, server key {key}: {e}"));
        assert!(get_root(&mut tls).starts_with("HTTP/1.0 200 ok"), "CA {ca}, server key {key}");
    }
}

/// Starts `openssl s_server` with its standard output in the file `log`.
fn start_logging_server(fx: &Fixture, extra: &[&str], log: &Path) -> Server {
    start_server_with_stdout(fx, extra, Stdio::from(fs::File::create(log).unwrap()))
}

#[test]
fn a_server_that_accepts_only_nist_groups_makes_the_client_retry() {
    if !have_openssl() {
        eprintln!("skipping: openssl not installed");
        return;
    }
    // The ClientHello carries an x25519 key share only. A server restricted to P-256 or P-384 has
    // to answer with a HelloRetryRequest, and the client then sends a second ClientHello with a
    // key share for that curve.
    let fx = Fixture::new("hrr", "p256");
    let log = fx.dir.join("server.log");
    for group in ["P-256", "P-384"] {
        for suite in Suite::ALL {
            let server = start_logging_server(&fx, &["-www", "-tls1_3", "-ciphersuites", suite_arg(suite), "-groups", group, "-trace"], &log);
            let config = ClientConfig::new(fx.trust());
            let mut tls = connect(&server, "localhost", &config).unwrap_or_else(|e| panic!("{group} / {}: {e}", suite.name()));
            assert_eq!(tls.cipher_suite(), Some(suite));
            let page = get_root(&mut tls);
            assert!(page.starts_with("HTTP/1.0 200 ok"), "{group} / {}: unexpected response {:?}", suite.name(), &page[..page.len().min(80)]);
            assert!(page.contains(suite.name()), "{group}: {page}");
            // the trace shows a HelloRetryRequest as a ServerHello whose random is the fixed RFC 8446 value
            wait_for(&log, b"gmt_unix_time=0xCF21AD74", "the server's trace");
            drop(server);
        }
    }
}

#[test]
fn the_retry_works_with_every_server_key_type() {
    if !have_openssl() {
        return;
    }
    for kind in ["rsa", "p384", "ed25519"] {
        let fx = Fixture::new(&format!("hrr_{kind}"), kind);
        let server = start_server(&fx, &["-www", "-tls1_3", "-groups", "P-384"]);
        let config = ClientConfig::new(fx.trust());
        let mut tls = connect(&server, "localhost", &config).unwrap_or_else(|e| panic!("{kind}: {e}"));
        assert!(get_root(&mut tls).starts_with("HTTP/1.0 200 ok"));
    }
}

#[test]
fn a_server_that_prefers_p256_but_accepts_x25519_still_works() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("prefer_p256", "p256");
    for groups in ["P-256:X25519", "X25519:P-256:P-384"] {
        let server = start_server(&fx, &["-www", "-tls1_3", "-groups", groups]);
        let config = ClientConfig::new(fx.trust());
        let mut tls = connect(&server, "localhost", &config).unwrap_or_else(|e| panic!("{groups}: {e}"));
        assert!(get_root(&mut tls).starts_with("HTTP/1.0 200 ok"), "{groups}");
    }
}

#[test]
fn ip_address_san_matches() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("ip", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let config = ClientConfig::new(fx.trust());
    let mut tls = connect(&server, "127.0.0.1", &config).unwrap();
    assert!(get_root(&mut tls).starts_with("HTTP/1.0 200"));
}

#[test]
fn rejects_wrong_hostname() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("host", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let config = ClientConfig::new(fx.trust());
    let err = connect(&server, "not-localhost.example", &config).err().expect("handshake must fail");
    assert!(err.to_string().contains("not valid for host name"), "{}", err);
}

#[test]
fn rejects_untrusted_issuer() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("untrusted", "rsa");
    let other = Fixture::new("untrusted_other", "rsa");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let config = ClientConfig::new(other.trust());
    let err = connect(&server, "localhost", &config).err().expect("an untrusted chain must be rejected");
    // the failure names the certificate involved, so it can be diagnosed without a packet capture
    assert!(err.to_string().contains("[CN="), "{}", err);
}

#[test]
fn expired_time_is_rejected_via_clock_override() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("clock", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let mut config = ClientConfig::new(fx.trust());
    config.time_override = Some(4_900_000_000); // year 2125 is still valid, 2200 is not
    assert!(connect(&server, "localhost", &config).is_ok());
    let server2 = start_server(&fx, &["-www", "-tls1_3"]);
    config.time_override = Some(7_300_000_000);
    let err = connect(&server2, "localhost", &config).err().unwrap();
    assert!(err.to_string().contains("expired"), "{}", err);
}

#[test]
fn tls12_only_server_gives_clear_error() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("tls12", "p256");
    let server = start_server(&fx, &["-www", "-tls1_2"]);
    let config = ClientConfig::new(fx.trust());
    let err = connect(&server, "localhost", &config).err().expect("must fail");
    let msg = err.to_string();
    assert!(msg.contains("TLS 1.3") || msg.contains("alert"), "{}", msg);
}

fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut data = Vec::with_capacity(len);
    let mut x: u32 = seed;
    while data.len() < len {
        x = x.wrapping_mul(1664525).wrapping_add(1013904223);
        data.push((x >> 24) as u8);
    }
    data
}

/// Downloads `blob.bin` (served by `s_server -WWW`) and returns the body.
fn download_blob<S: Read + Write>(tls: &mut TlsStream<S>) -> Vec<u8> {
    tls.write_all(b"GET /blob.bin HTTP/1.0\r\n\r\n").unwrap();
    let mut resp = Vec::new();
    tls.read_to_end(&mut resp).unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end") + 4;
    resp.split_off(split)
}

#[test]
fn large_download_roundtrips_exactly() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("large", "p256");
    // 3 MiB plus an odd tail, so the last record is short
    let data = pseudo_random((3 << 20) + 777, 12345);
    fs::write(fx.dir.join("blob.bin"), &data).unwrap();
    for suite in Suite::ALL {
        let server = start_server(&fx, &["-WWW", "-tls1_3", "-ciphersuites", suite_arg(suite)]);
        let config = ClientConfig::new(fx.trust());
        let mut tls = connect(&server, "localhost", &config).unwrap();
        assert_eq!(tls.cipher_suite(), Some(suite));
        assert!(download_blob(&mut tls) == data, "{suite:?}: downloaded body differs from file");
    }
}

/// A transport that hands out and accepts at most a few bytes per call, so records straddle reads
/// and writes in every possible way.
struct Dribble {
    inner: TcpStream,
    max_read: usize,
    max_write: usize,
}

impl Read for Dribble {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.max_read);
        self.inner.read(&mut buf[..n])
    }
}

impl Write for Dribble {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.max_write);
        self.inner.write(&buf[..n])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn download_over_transport_that_returns_tiny_reads() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("dribble", "p256");
    let data = pseudo_random(150_000, 99);
    fs::write(fx.dir.join("blob.bin"), &data).unwrap();
    let server = start_server(&fx, &["-WWW", "-tls1_3", "-ciphersuites", suite_arg(Suite::Chacha20Poly1305Sha256)]);
    let config = ClientConfig::new(fx.trust());
    for (max_read, max_write) in [(1usize, 1usize), (7, 3), (100, 1000), (4096, 5), (20_000, 70_000)] {
        let tcp = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut tls = TlsStream::connect(Dribble { inner: tcp, max_read, max_write }, "localhost", &config).unwrap();
        assert!(download_blob(&mut tls) == data, "body differs with max_read={max_read} max_write={max_write}");
    }
}

#[test]
fn large_upload_roundtrips_exactly() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("upload", "p256");
    // One big write, then many tiny ones, then writes sized right at record and batch boundaries.
    let mut parts: Vec<Vec<u8>> = vec![pseudo_random(1_234_567, 7)];
    for i in 1..=50usize {
        parts.push(pseudo_random(i, i as u32));
    }
    for (i, n) in [16_384usize, 16_385, 16_383, 65_536, 65_537, 3 * 16_384 + 1, 0, 1].into_iter().enumerate() {
        parts.push(pseudo_random(n, 1000 + i as u32));
    }
    let expected: Vec<u8> = parts.concat();

    for suite in Suite::ALL {
        let out_path = fx.dir.join(format!("received-{}.bin", suite.id()));
        let out = fs::File::create(&out_path).unwrap();
        let server = start_server_with_stdout(&fx, &["-quiet", "-tls1_3", "-ciphersuites", suite_arg(suite)], Stdio::from(out));
        let config = ClientConfig::new(fx.trust());
        let mut tls = connect(&server, "localhost", &config).unwrap();
        for p in &parts {
            tls.write_all(p).unwrap();
        }
        tls.flush().unwrap();

        // s_server copies what it decrypts to stdout as it arrives; wait until it all got there.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let len = fs::metadata(&out_path).unwrap().len() as usize;
            if len >= expected.len() {
                break;
            }
            assert!(Instant::now() < deadline, "{suite:?}: server received only {len} of {} bytes", expected.len());
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(100)); // would reveal surplus bytes
        let received = fs::read(&out_path).unwrap();
        assert_eq!(received.len(), expected.len(), "{suite:?}: length differs");
        assert!(received == expected, "{suite:?}: uploaded bytes differ");
    }
}

#[test]
fn alpn_http11_is_negotiated() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("alpn", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3", "-alpn", "http/1.1"]);
    let config = ClientConfig::new(fx.trust());
    let tls = connect(&server, "localhost", &config).unwrap();
    assert_eq!(tls.alpn_protocol(), Some(&b"http/1.1"[..]));
    // the whole chain the server sent is available, leaf first, and agrees with peer_certificate()
    let chain = tls.peer_certificates();
    assert!(!chain.is_empty());
    assert_eq!(Some(chain[0].as_slice()), tls.peer_certificate());
    let leaf = tiny_https::x509::Certificate::from_der(&chain[0]).unwrap();
    assert!(leaf.subject_summary().starts_with("CN="), "{}", leaf.subject_summary());
}

#[test]
fn http_client_over_tls_read_until_close() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("httpc", "rsa");
    fs::write(fx.dir.join("hello.txt"), "hello over tls\n").unwrap();
    let server = start_server(&fx, &["-WWW", "-tls1_3"]);
    let client = tiny_https::Client::with_tls_config(ClientConfig::new(fx.trust())).timeout(Duration::from_secs(10));
    let resp = client.get(&format!("https://localhost:{}/hello.txt", server.port)).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.text(), "hello over tls\n");
    assert!(resp.url.is_https());
}

#[test]
fn http_client_rejects_bad_certificate_by_default() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("httpc_bad", "p256");
    let other = Fixture::new("httpc_bad_other", "p256");
    let server = start_server(&fx, &["-WWW", "-tls1_3"]);
    let client = tiny_https::Client::with_tls_config(ClientConfig::new(other.trust())).timeout(Duration::from_secs(10));
    let err = client.get(&format!("https://localhost:{}/", server.port)).unwrap_err();
    assert!(matches!(err, tiny_https::error::Error::Verify(tiny_https::verify_error::Error::Certificate(_))), "{:?}", err);
}

#[test]
fn shared_client_works_from_many_threads() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("threads", "p256");
    fs::write(fx.dir.join("t.txt"), "threaded\n").unwrap();
    let server = start_server(&fx, &["-WWW", "-tls1_3"]);
    let client = std::sync::Arc::new(tiny_https::Client::with_tls_config(ClientConfig::new(fx.trust())).timeout(Duration::from_secs(20)));
    let url = format!("https://localhost:{}/t.txt", server.port);
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let client = client.clone();
            let url = url.clone();
            std::thread::spawn(move || {
                for _ in 0..3 {
                    let r = client.get(&url).expect("request failed");
                    assert_eq!(r.text(), "threaded\n");
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("a worker thread panicked");
    }
}

/// Counts the `write` calls the TLS layer makes on the transport.
struct CountingWrites {
    inner: TcpStream,
    writes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Read for CountingWrites {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for CountingWrites {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn client_finished_travels_with_the_first_request() {
    if !have_openssl() {
        return;
    }
    use std::sync::atomic::Ordering;
    for (name, key) in [("fin_p256", "p256"), ("fin_rsa", "rsa")] {
        let fx = Fixture::new(name, key);
        let server = start_server(&fx, &["-www", "-tls1_3"]);
        let tcp = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let io = CountingWrites { inner: tcp, writes: writes.clone() };
        let config = ClientConfig::new(fx.trust());
        let mut tls = TlsStream::connect(io, "localhost", &config).unwrap();
        // ClientHello + compatibility CCS went out in one write; the Finished is still queued
        assert_eq!(writes.load(Ordering::SeqCst), 1, "handshake must end without sending the Finished");
        // the first request carries the Finished with it: exactly one more write, and it works
        tls.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 2, "Finished and request must share one write");
        let mut body = String::new();
        tls.read_to_string(&mut body).unwrap();
        assert!(body.starts_with("HTTP/1.0 200"), "{}", &body[..body.len().min(80)]);
        // later writes are not delayed or merged with anything else
        assert_eq!(writes.load(Ordering::SeqCst), 2);
    }
}

#[test]
fn flush_and_close_send_the_pending_finished() {
    if !have_openssl() {
        return;
    }
    use std::sync::atomic::Ordering;
    let fx = Fixture::new("fin_flush", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let config = ClientConfig::new(fx.trust());
    for action in ["flush", "close", "drop"] {
        let tcp = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
        let writes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut tls = TlsStream::connect(CountingWrites { inner: tcp, writes: writes.clone() }, "localhost", &config).unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        match action {
            "flush" => tls.flush().unwrap(),
            "close" => tls.close().unwrap(),
            _ => drop(tls),
        }
        assert_eq!(writes.load(Ordering::SeqCst), 2, "{} must send the queued Finished", action);
    }
    // s_server survived all three and still answers
    let tls = connect(&server, "localhost", &config);
    assert!(tls.is_ok());
}

#[test]
fn server_that_speaks_first_still_completes_the_handshake() {
    if !have_openssl() {
        return;
    }
    // Without a flush before the first blocking read, both sides would wait for each other: the
    // server cannot send until it has our Finished, and we would not send it until we wrote.
    let fx = Fixture::new("fin_first", "p256");
    let mut server = start_server(&fx, &["-quiet", "-tls1_3"]);
    let config = ClientConfig::new(fx.trust());
    let tcp = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut tls = TlsStream::connect(tcp, "localhost", &config).unwrap();
    let mut stdin = server.child.stdin.take().unwrap();
    stdin.write_all(b"greeting from the server\n").unwrap();
    stdin.flush().unwrap();
    let mut buf = [0u8; 64];
    let n = tls.read(&mut buf).expect("the server's greeting never arrived (handshake deadlock?)");
    assert_eq!(&buf[..n], b"greeting from the server\n");
}

// ------------------------------------------------------------------------------------ KeyUpdate

/// Waits until the file at `path` contains `needle`.
fn wait_for(path: &Path, needle: &[u8], what: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let data = fs::read(path).unwrap_or_default();
        if data.windows(needle.len()).any(|w| w == needle) {
            return;
        }
        assert!(Instant::now() < deadline, "{what}: the server never printed {:?}", String::from_utf8_lossy(needle));
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn read_exactly(tls: &mut TlsStream<TcpStream>, want: &[u8]) {
    let mut got = vec![0u8; want.len()];
    tls.read_exact(&mut got).unwrap_or_else(|e| panic!("waiting for {:?}: {}", String::from_utf8_lossy(want), e));
    assert_eq!(got, want);
}

#[test]
fn our_key_updates_are_accepted_by_openssl_on_every_suite() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("rekey", "p256");
    // 300 KB in one write, then many small ones: with a key limited to 8 records that is dozens of rotations
    let mut parts = vec![pseudo_random(300_000, 21)];
    for i in 1..=120usize {
        parts.push(pseudo_random(i * 13, i as u32));
    }
    let expected: Vec<u8> = parts.concat();
    for suite in Suite::ALL {
        let out_path = fx.dir.join(format!("rekeyed-{}.bin", suite.id()));
        let out = fs::File::create(&out_path).unwrap();
        let server = start_server_with_stdout(&fx, &["-quiet", "-tls1_3", "-ciphersuites", suite_arg(suite)], Stdio::from(out));
        let config = ClientConfig::new(fx.trust()).with_rekey_after_records(8);
        let mut tls = connect(&server, "localhost", &config).unwrap();
        for p in &parts {
            tls.write_all(p).unwrap();
        }
        tls.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while (fs::metadata(&out_path).unwrap().len() as usize) < expected.len() {
            assert!(Instant::now() < deadline, "{suite:?}: the server stopped receiving (it rejected a KeyUpdate?)");
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(100));
        assert!(fs::read(&out_path).unwrap() == expected, "{suite:?}: the data differs");
    }
}

#[test]
fn key_updates_started_by_openssl_are_followed_with_and_without_a_request() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("peer_rekey", "p256");
    let out_path = fx.dir.join("server-out.txt");
    let out = fs::File::create(&out_path).unwrap();
    // Not -quiet: s_server only treats a line on its stdin as a command ("k" sends a KeyUpdate that
    // does not ask for ours, "K" one that does) when it is not in quiet mode.
    // -msg makes it print every protocol message it sends and receives, which shows whether our
    // answer to "k" (a KeyUpdate of our own) arrives: OpenSSL keeps accepting our old keys until it
    // gets one, so the data alone would not tell.
    let mut server = start_server_with_stdout(&fx, &["-tls1_3", "-msg"], Stdio::from(out));
    let mut stdin = server.child.stdin.take().unwrap();
    // One line per read of s_server's stdin: it looks only at the start of what it read, so a
    // command and the line after it written together would lose the second.
    let mut say = |text: &str| {
        stdin.write_all(text.as_bytes()).unwrap();
        stdin.flush().unwrap();
        std::thread::sleep(Duration::from_millis(250));
    };
    let config = ClientConfig::new(fx.trust());
    let tcp = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut tls = TlsStream::connect(tcp, "localhost", &config).unwrap();

    say("one\n");
    read_exactly(&mut tls, b"one\n");
    // update_not_requested: the server's sending keys change, ours stay
    say("k\n");
    say("two\n");
    read_exactly(&mut tls, b"two\n");
    tls.write_all(b"client-a\n").unwrap();
    tls.flush().unwrap();
    wait_for(&out_path, b"client-a", "after k");
    let received_key_updates = || String::from_utf8_lossy(&fs::read(&out_path).unwrap()).matches("<<< TLS 1.3, Handshake [length 0005], KeyUpdate").count();
    assert_eq!(received_key_updates(), 0, "nothing was asked of us yet");
    // update_requested: we answer with a KeyUpdate of our own and rotate
    say("K\n");
    say("three\n");
    read_exactly(&mut tls, b"three\n");
    tls.write_all(b"client-b\n").unwrap();
    tls.flush().unwrap();
    wait_for(&out_path, b"client-b", "after K");
    assert_eq!(received_key_updates(), 1, "the answer to the request");
    // and once more each way, to show the generations keep following one another
    say("K\n");
    say("four\n");
    read_exactly(&mut tls, b"four\n");
    say("k\n");
    say("five\n");
    read_exactly(&mut tls, b"five\n");
    tls.write_all(b"client-c\n").unwrap();
    tls.flush().unwrap();
    wait_for(&out_path, b"client-c", "after K and k");
    assert_eq!(received_key_updates(), 2, "one answer per request, none for update_not_requested");
}

// ------------------------------------------------------------------------------------ async

use std::pin::Pin;
use std::task::{Context, Poll};
use tiny_https::asyncio::{block_on, AsyncRead, AsyncReadExt, AsyncTlsStream, AsyncWrite, AsyncWriteExt, Pool, ThreadedStream};
use tiny_https::tls::ClientConnection;

fn tcp_to(server: &Server) -> TcpStream {
    let tcp = TcpStream::connect(("127.0.0.1", server.port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    tcp
}

fn async_connect(server: &Server, name: &str, config: &ClientConfig) -> tiny_https::error::Result<AsyncTlsStream<ThreadedStream>> {
    block_on(AsyncTlsStream::connect(ThreadedStream::new(tcp_to(server), Pool::global()), name, config))
}

async fn download_blob_async<S: AsyncRead + AsyncWrite + Unpin>(tls: &mut S) -> Vec<u8> {
    tls.write_all(b"GET /blob.bin HTTP/1.0\r\n\r\n").await.unwrap();
    tls.flush().await.unwrap();
    let mut resp = Vec::new();
    tls.read_to_end(&mut resp).await.unwrap();
    let split = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("no header end") + 4;
    resp.split_off(split)
}

/// A transport that answers `Pending` (after waking the task) on every other poll and moves at
/// most a few bytes per call, so every waiting and partial-progress path of the async stream runs.
struct Stutter {
    inner: TcpStream,
    max_read: usize,
    max_write: usize,
    read_turn: bool,
    write_turn: bool,
}

impl Stutter {
    fn new(inner: TcpStream, max_read: usize, max_write: usize) -> Stutter {
        Stutter { inner, max_read, max_write, read_turn: false, write_turn: false }
    }
}

impl AsyncRead for Stutter {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        self.read_turn = !self.read_turn;
        if self.read_turn {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = buf.len().min(self.max_read);
        Poll::Ready(self.inner.read(&mut buf[..n]))
    }
}

impl AsyncWrite for Stutter {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        self.write_turn = !self.write_turn;
        if self.write_turn {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let n = buf.len().min(self.max_write);
        Poll::Ready(self.inner.write(&buf[..n]))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(self.get_mut().inner.flush())
    }
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let _ = self.inner.shutdown(std::net::Shutdown::Write);
        Poll::Ready(Ok(()))
    }
}

#[test]
fn async_download_roundtrips_exactly_on_every_suite() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("async_large", "p256");
    let data = pseudo_random((3 << 20) + 777, 4242);
    fs::write(fx.dir.join("blob.bin"), &data).unwrap();
    for suite in Suite::ALL {
        let server = start_server(&fx, &["-WWW", "-tls1_3", "-ciphersuites", suite_arg(suite)]);
        let config = ClientConfig::new(fx.trust());
        let mut tls = async_connect(&server, "localhost", &config).unwrap();
        assert_eq!(tls.cipher_suite(), Some(suite));
        assert_eq!(tls.peer_certificates().len(), 1);
        let body = block_on(download_blob_async(&mut tls));
        assert!(body == data, "{suite:?}: downloaded body differs from file");
        block_on(tls.close()).unwrap();
    }
}

#[test]
fn the_async_client_answers_a_hello_retry_request_too() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("async_hrr", "p256");
    let data = pseudo_random(300_000, 99);
    fs::write(fx.dir.join("blob.bin"), &data).unwrap();
    for group in ["P-256", "P-384"] {
        let server = start_server(&fx, &["-WWW", "-tls1_3", "-groups", group]);
        let config = ClientConfig::new(fx.trust());
        let mut tls = async_connect(&server, "localhost", &config).unwrap_or_else(|e| panic!("{group}: {e}"));
        let body = block_on(download_blob_async(&mut tls));
        assert!(body == data, "{group}: downloaded body differs from file");
        block_on(tls.close()).unwrap();
    }
}

#[test]
fn async_stream_over_a_transport_that_stalls_and_dribbles() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("async_stutter", "p256");
    let data = pseudo_random(120_000, 31337);
    fs::write(fx.dir.join("blob.bin"), &data).unwrap();
    let server = start_server(&fx, &["-WWW", "-tls1_3", "-ciphersuites", suite_arg(Suite::Aes128GcmSha256)]);
    let config = ClientConfig::new(fx.trust());
    for (max_read, max_write) in [(1usize, 1usize), (7, 3), (100, 1000), (4096, 5), (20_000, 70_000)] {
        let io = Stutter::new(tcp_to(&server), max_read, max_write);
        let mut tls = block_on(AsyncTlsStream::connect(io, "localhost", &config)).unwrap();
        let body = block_on(download_blob_async(&mut tls));
        assert!(body == data, "body differs with max_read={max_read} max_write={max_write}");
    }
}

#[test]
fn async_upload_roundtrips_exactly() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("async_upload", "p256");
    let mut parts: Vec<Vec<u8>> = vec![pseudo_random(700_001, 17)];
    for i in 1..=30usize {
        parts.push(pseudo_random(i, 500 + i as u32));
    }
    for (i, n) in [16_384usize, 16_385, 65_536, 65_537, 0, 1].into_iter().enumerate() {
        parts.push(pseudo_random(n, 2000 + i as u32));
    }
    let expected: Vec<u8> = parts.concat();
    for (label, stutter) in [("threaded", false), ("stuttering", true)] {
        let out_path = fx.dir.join(format!("received-{label}.bin"));
        let out = fs::File::create(&out_path).unwrap();
        let server = start_server_with_stdout(&fx, &["-quiet", "-tls1_3"], Stdio::from(out));
        let config = ClientConfig::new(fx.trust());
        // the stream stays open until the server has everything: dropping a socket with data
        // still in flight can reset the connection and lose it
        let mut closer: Box<dyn FnMut()> = if stutter {
            let mut tls = block_on(AsyncTlsStream::connect(Stutter::new(tcp_to(&server), 50_000, 9), "localhost", &config)).unwrap();
            block_on(async {
                for p in &parts {
                    tls.write_all(p).await.unwrap();
                }
                tls.flush().await.unwrap();
            });
            Box::new(move || block_on(tls.close()).unwrap())
        } else {
            let mut tls = async_connect(&server, "localhost", &config).unwrap();
            block_on(async {
                for p in &parts {
                    tls.write_all(p).await.unwrap();
                }
                tls.flush().await.unwrap();
            });
            Box::new(move || block_on(tls.close()).unwrap())
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let len = fs::metadata(&out_path).unwrap().len() as usize;
            if len >= expected.len() {
                break;
            }
            assert!(Instant::now() < deadline, "{label}: server received only {len} of {} bytes", expected.len());
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(100));
        let received = fs::read(&out_path).unwrap();
        assert_eq!(received.len(), expected.len(), "{label}: length differs");
        assert!(received == expected, "{label}: uploaded bytes differ");
        closer();
    }
}

#[test]
fn async_handshake_failures_are_errors() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("async_fail", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let config = ClientConfig::new(fx.trust());
    let err = async_connect(&server, "not-localhost.example", &config).err().expect("handshake must fail");
    assert!(err.to_string().contains("not valid for host name"), "{}", err);
    let err = async_connect(&server, "localhost", &ClientConfig::new(TrustStore::empty())).err().expect("untrusted issuer");
    assert!(err.to_string().contains("trusted root"), "{}", err);

    let tls12 = start_server(&fx, &["-www", "-tls1_2"]);
    let err = async_connect(&tls12, "localhost", &config).err().expect("must fail");
    assert!(err.to_string().contains("TLS 1.3") || err.to_string().contains("alert"), "{}", err);
}

#[test]
fn async_stream_reports_a_truncated_connection_but_accepts_close_notify() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("async_close", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let config = ClientConfig::new(fx.trust());
    // a normal HTTP/1.0 exchange ends with the server's close_notify: a clean end of stream
    let mut tls = async_connect(&server, "localhost", &config).unwrap();
    let text = block_on(async {
        tls.write_all(b"GET / HTTP/1.0\r\n\r\n").await.unwrap();
        let mut body = Vec::new();
        tls.read_to_end(&mut body).await.unwrap();
        String::from_utf8_lossy(&body).into_owned()
    });
    assert!(text.starts_with("HTTP/1.0 200 ok"), "{}", &text[..text.len().min(80)]);
}

/// The sans-IO API on its own: a hand-written driver loop over a plain TcpStream.
#[test]
fn sans_io_connection_can_be_driven_by_hand() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("sansio", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let config = ClientConfig::new(fx.trust());
    let mut tcp = tcp_to(&server);
    let mut conn = ClientConnection::new("localhost", &config).unwrap();

    // handshake: send what is queued, read, process
    while conn.is_handshaking() {
        if conn.wants_write() {
            tcp.write_all(conn.output()).unwrap();
            let n = conn.output().len();
            conn.consume_output(n);
        }
        let n = tcp.read(conn.recv_buf()).unwrap();
        assert!(n > 0, "server closed during the handshake");
        conn.recv_filled(n);
        conn.process().unwrap();
    }
    assert!(conn.is_established() && conn.cipher_suite().is_some());
    // our Finished is still queued: nothing forces it out before the first request
    assert!(conn.wants_write());

    let request = b"GET / HTTP/1.0\r\n\r\n";
    assert_eq!(conn.write_plaintext(request).unwrap(), request.len());
    tcp.write_all(conn.output()).unwrap();
    let n = conn.output().len();
    conn.consume_output(n);

    let mut body = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = conn.read_plaintext(&mut buf);
        if n > 0 {
            body.extend_from_slice(&buf[..n]);
            continue;
        }
        if conn.peer_closed() {
            break;
        }
        conn.process().unwrap();
        if conn.has_plaintext() || conn.peer_closed() {
            continue;
        }
        let got = tcp.read(conn.recv_buf()).unwrap();
        if got == 0 {
            conn.recv_eof().expect("the server must send close_notify before it closes");
            break;
        }
        conn.recv_filled(got);
    }
    assert!(String::from_utf8_lossy(&body).starts_with("HTTP/1.0 200 ok"));
    conn.send_close_notify();
    assert!(conn.wants_write() && conn.write_closed());
    assert!(conn.write_plaintext(b"more").is_err(), "no data after close_notify");
}

#[test]
fn async_http_client_over_tls() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("async_httpc", "rsa");
    let data = pseudo_random(1_500_000, 77);
    fs::write(fx.dir.join("blob.bin"), &data).unwrap();
    fs::write(fx.dir.join("hello.txt"), "hello over async tls\n").unwrap();
    let server = start_server(&fx, &["-WWW", "-tls1_3"]);
    let client = tiny_https::Client::with_tls_config(ClientConfig::new(fx.trust())).timeout(Duration::from_secs(10)).total_timeout(Duration::from_secs(60)).into_async();
    let base = format!("https://localhost:{}", server.port);

    let r = block_on(client.get(&format!("{base}/hello.txt"))).unwrap();
    assert_eq!((r.status, r.text().as_str()), (200, "hello over async tls\n"));
    assert!(r.url.is_https());
    let r = block_on(client.get(&format!("{base}/blob.bin"))).unwrap();
    assert!(r.body == data, "large body differs");

    // several at once, from one executor thread
    let urls: Vec<String> = (0..4).map(|_| format!("{base}/hello.txt")).collect();
    let results = block_on(async {
        let mut out = Vec::new();
        for u in &urls {
            out.push(client.get(u).await);
        }
        out
    });
    assert!(results.iter().all(|r| matches!(r, Ok(resp) if resp.status == 200)));

    // an untrusted certificate is an error here too
    let other = Fixture::new("async_httpc_other", "p256");
    let bad = tiny_https::Client::with_tls_config(ClientConfig::new(other.trust())).into_async();
    let err = block_on(bad.get(&format!("{base}/hello.txt"))).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("certificate"), "{}", err);
}

// ------------------------------------------------------------------------------ revocation

/// What `openssl ocsp` and `openssl ca` produce for the fixture's server certificate, signed by the
/// CA itself (so the staple's signer is the certificate's issuer).
struct Evidence {
    /// A DER OCSP response file name inside the fixture directory.
    ocsp: String,
}

impl Fixture {
    fn serial(&self) -> String {
        let out = Command::new("openssl").args(["x509", "-in", "srv.pem", "-noout", "-serial"]).current_dir(&self.dir).output().unwrap();
        String::from_utf8_lossy(&out.stdout).trim().trim_start_matches("serial=").to_string()
    }

    /// Writes `index.txt` the way `openssl ca`/`openssl ocsp -index` read it.
    fn write_index(&self, revoked: bool) {
        let status = if revoked { "R\t491231235959Z\t260101000000Z,keyCompromise" } else { "V\t491231235959Z\t" };
        fs::write(self.dir.join("index.txt"), format!("{}\t{}\tunknown\t/CN=localhost\n", status, self.serial())).unwrap();
    }

    /// An OCSP response for the server certificate, saved as `name`.
    fn ocsp_response(&self, name: &str, revoked: bool, responder_by_key_hash: bool) -> Evidence {
        self.write_index(revoked);
        run(&["ocsp", "-issuer", "ca.pem", "-cert", "srv.pem", "-reqout", "req.der"], &self.dir);
        let mut args = vec![
            "ocsp", "-index", "index.txt", "-CA", "ca.pem", "-rsigner", "ca.pem", "-rkey", "ca.key", "-reqin", "req.der", "-respout", name,
            "-ndays", "7",
        ];
        if responder_by_key_hash {
            args.push("-resp_key_id");
        }
        run(&args, &self.dir);
        Evidence { ocsp: name.to_string() }
    }

    /// A CRL from the CA, with the server certificate listed as revoked or not.
    fn crl(&self, revoked: bool) -> Crl {
        self.write_index(false);
        fs::write(self.dir.join("crlnumber"), "01\n").unwrap();
        fs::write(
            self.dir.join("ca.cnf"),
            "[ca]\ndefault_ca = CA_default\n[CA_default]\ndatabase = index.txt\ncrlnumber = crlnumber\ndefault_md = sha256\n\
             default_crl_days = 7\ncertificate = ca.pem\nprivate_key = ca.key\n",
        )
        .unwrap();
        if revoked {
            run(&["ca", "-config", "ca.cnf", "-revoke", "srv.pem", "-crl_reason", "keyCompromise"], &self.dir);
        }
        run(&["ca", "-config", "ca.cnf", "-gencrl", "-out", "crl.pem"], &self.dir);
        Crl::from_pem(&fs::read_to_string(self.dir.join("crl.pem")).unwrap()).unwrap()
    }
}

fn revocation_config(fx: &Fixture, mode: RevocationMode) -> ClientConfig {
    ClientConfig::new(fx.trust()).revocation_mode(mode)
}

#[test]
fn a_stapled_ocsp_response_from_openssl_satisfies_hard_fail() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("ocsp_good", "p256");
    // the responder named by its subject, and by the hash of its key (the two ResponderID forms)
    for (name, by_key_hash) in [("good_by_name.der", false), ("good_by_key.der", true)] {
        let ev = fx.ocsp_response(name, false, by_key_hash);
        let server = start_server(&fx, &["-www", "-tls1_3", "-status_file", &ev.ocsp]);
        for mode in [RevocationMode::SoftFail, RevocationMode::HardFail] {
            let mut tls = connect(&server, "localhost", &revocation_config(&fx, mode)).unwrap_or_else(|e| panic!("{} {:?}: {}", name, mode, e));
            assert!(get_root(&mut tls).contains("HTTP/1.0 200"));
        }
    }
}

#[test]
fn a_revoked_staple_from_openssl_is_refused() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("ocsp_revoked", "p256");
    let ev = fx.ocsp_response("revoked.der", true, false);
    let server = start_server(&fx, &["-www", "-tls1_3", "-status_file", &ev.ocsp]);
    for mode in [RevocationMode::SoftFail, RevocationMode::HardFail] {
        let err = connect(&server, "localhost", &revocation_config(&fx, mode)).err().expect("a revoked certificate must be refused");
        let text = err.to_string();
        assert!(text.contains("certificate_revoked") && text.contains("key compromise"), "{:?}: {}", mode, text);
    }
    // with revocation checking off the client does not ask for a staple and the connection works
    let mut tls = connect(&server, "localhost", &revocation_config(&fx, RevocationMode::Off)).unwrap();
    assert!(get_root(&mut tls).contains("HTTP/1.0 200"));
}

#[test]
fn a_server_without_a_staple_is_tolerated_in_soft_fail_only() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("ocsp_none", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let mut tls = connect(&server, "localhost", &revocation_config(&fx, RevocationMode::SoftFail)).unwrap();
    assert!(get_root(&mut tls).contains("HTTP/1.0 200"));
    drop(tls); // s_server serves one connection at a time and waits for this one to close
    let err = connect(&server, "localhost", &revocation_config(&fx, RevocationMode::HardFail)).err().expect("hard-fail needs evidence");
    assert!(err.to_string().contains("bad_certificate_status_response"), "{}", err);
}

#[test]
fn a_must_staple_certificate_needs_a_staple_even_in_soft_fail() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::with_extensions("must_staple", "p256", "tlsfeature=status_request\n");
    let ev = fx.ocsp_response("good.der", false, false);
    let without = start_server(&fx, &["-www", "-tls1_3"]);
    let err = connect(&without, "localhost", &revocation_config(&fx, RevocationMode::SoftFail)).err().expect("a missing staple must be refused");
    assert!(err.to_string().contains("requires a stapled OCSP response"), "{}", err);
    let with = start_server(&fx, &["-www", "-tls1_3", "-status_file", &ev.ocsp]);
    let mut tls = connect(&with, "localhost", &revocation_config(&fx, RevocationMode::SoftFail)).unwrap();
    assert!(get_root(&mut tls).contains("HTTP/1.0 200"));
}

#[test]
fn crls_made_by_openssl_are_understood() {
    if !have_openssl() {
        return;
    }
    let fx = Fixture::new("crl", "p256");
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    // a current CRL that does not list the certificate satisfies hard-fail without any staple
    let clean = fx.crl(false);
    let cfg = ClientConfig::new(fx.trust()).with_revocation(Revocation::hard_fail().with_crl(clean));
    let mut tls = connect(&server, "localhost", &cfg).unwrap();
    assert!(get_root(&mut tls).contains("HTTP/1.0 200"));
    drop(tls); // s_server serves one connection at a time and waits for this one to close
    // one that lists it is refused, in the lenient mode too
    let listed = fx.crl(true);
    let cfg = ClientConfig::new(fx.trust()).with_revocation(Revocation::soft_fail().with_crl(listed));
    let err = connect(&server, "localhost", &cfg).err().expect("a listed certificate must be refused");
    assert!(err.to_string().contains("certificate_revoked") && err.to_string().contains("a CRL"), "{}", err);
}

/// A plain-HTTP server that answers every request with the current contents of `body`; the count
/// is the number of requests it has seen.
fn serve_crl(port: u16, body: Arc<Mutex<Vec<u8>>>) -> Arc<AtomicUsize> {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { continue };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") && s.read(&mut byte).unwrap_or(0) == 1 {
                head.push(byte[0]);
            }
            count.fetch_add(1, Ordering::SeqCst);
            let body = body.lock().unwrap().clone();
            let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).as_bytes());
            let _ = s.write_all(&body);
        }
    });
    requests
}

#[test]
fn hard_fail_fetches_the_crl_named_in_the_certificate_and_caches_it() {
    if !have_openssl() {
        return;
    }
    let crl_port = free_port();
    let fx = Fixture::with_extensions("crl_fetch", "p256", &format!("crlDistributionPoints=URI:http://127.0.0.1:{}/ca.crl\n", crl_port));
    let body = Arc::new(Mutex::new(Vec::new()));
    let requests = serve_crl(crl_port, body.clone());

    // a CRL that does not list the certificate: downloaded once, then served from the cache
    fx.crl(false);
    *body.lock().unwrap() = fs::read(fx.dir.join("crl.pem")).unwrap();
    let server = start_server(&fx, &["-www", "-tls1_3"]);
    let cfg = ClientConfig::new(fx.trust()).with_revocation(Revocation::hard_fail().with_crl_source(Arc::new(HttpCrlSource::new())));
    for _ in 0..2 {
        let mut tls = connect(&server, "localhost", &cfg).unwrap_or_else(|e| panic!("{}", e));
        assert!(get_root(&mut tls).contains("HTTP/1.0 200"));
    }
    assert_eq!(requests.load(Ordering::SeqCst), 1, "the second connection should use the cached CRL");

    // the same certificate once the CA lists it: a fresh source downloads the new list and refuses
    fx.crl(true);
    *body.lock().unwrap() = fs::read(fx.dir.join("crl.pem")).unwrap();
    let cfg = ClientConfig::new(fx.trust()).with_revocation(Revocation::soft_fail().with_crl_source(Arc::new(HttpCrlSource::new())));
    let err = connect(&server, "localhost", &cfg).err().expect("a listed certificate must be refused");
    assert!(err.to_string().contains("certificate_revoked") && err.to_string().contains("a fetched CRL"), "{}", err);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}
