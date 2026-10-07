//! The rules against a real TLS 1.3 peer on 127.0.0.1: tiny_https's test server (its `server` feature, for tests
//! only), with a throwaway root that the shared client is configured to trust.

use super::*;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
use std::thread;
use tiny_https::tls::pki::TestPki;
use tiny_https::http::h2_server;
use tiny_https::tls::server::{ServerConfig, ServerStream};

/// One root for every test (the trust anchors are the process's), configured once.
fn pki() -> &'static TestPki {
    static PKI: OnceLock<TestPki> = OnceLock::new();
    PKI.get_or_init(|| {
        let pki = TestPki::new(&["127.0.0.1", "localhost"]).unwrap();
        configure(Some(&pki.root_pem())).unwrap();
        pki
    })
}

/// A request as the server saw it: the head (request line and fields) and the body.
#[derive(Clone, Debug, Default)]
struct Seen {
    head: String,
    body: Vec<u8>,
}

impl Seen {
    fn path(&self) -> &str {
        self.head.split(' ').nth(1).unwrap_or("")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().skip(1).find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
    }
}

struct Server {
    port: u16,
    connections: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

fn response(status: u16, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\n", body.len()).into_bytes();
    for h in headers {
        out.extend_from_slice(h.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

/// A server with `pki`'s certificate (or `other`'s) that answers each request with `handler`'s bytes; None closes.
fn serve_with(pki: &TestPki, handler: impl Fn(&Seen) -> Option<Vec<u8>> + Send + Sync + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(ServerConfig::from_pki(pki));
    let handler = Arc::new(handler);
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (c, s) = (connections.clone(), seen.clone());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let (config, handler, s) = (config.clone(), handler.clone(), s.clone());
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                let Ok(mut tls) = ServerStream::accept(stream, &config) else { return };
                loop {
                    let Some(req) = read_request(&mut tls) else { return };
                    s.lock().unwrap().push(req.clone());
                    match handler(&req) {
                        Some(bytes) => {
                            if tls.write_all(&bytes).and_then(|_| tls.flush()).is_err() {
                                return;
                            }
                        }
                        None => return,
                    }
                }
            });
        }
    });
    Server { port, connections, seen }
}

fn serve(handler: impl Fn(&Seen) -> Option<Vec<u8>> + Send + Sync + 'static) -> Server {
    serve_with(pki(), handler)
}

/// A server that offers `h2` (and `http/1.1`): what it answers each request with over HTTP/2, the request's path
/// and body in hand.
fn serve_h2(handler: impl Fn(&str, &[u8]) -> (u16, Vec<u8>) + Send + Sync + 'static) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(ServerConfig::from_pki(pki()).with_alpn(&["h2", "http/1.1"]));
    let handler = Arc::new(handler);
    let connections = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (c, s) = (connections.clone(), seen.clone());
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            c.fetch_add(1, Ordering::SeqCst);
            let (config, handler, s) = (config.clone(), handler.clone(), s.clone());
            thread::spawn(move || {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));      // (the h2 loop sets its own after)
                let Ok(mut tls) = ServerStream::accept(stream, &config) else { return };
                if tls.alpn_protocol() != Some(b"h2".as_slice()) {
                    return;
                }
                let mut answer = |r: &h2_server::Request| {
                    s.lock().unwrap().push(Seen { head: format!("{} {} HTTP/2", r.method, r.path), body: r.body.clone() });
                    let (status, body) = handler(&r.path, &r.body);
                    h2_server::response(status, &[("content-length", &body.len().to_string())], &body)
                };
                let _ = h2_server::serve(&mut tls, &h2_server::Settings::default(), &mut answer);
            });
        }
    });
    Server { port, connections, seen }
}

fn read_request(tls: &mut ServerStream<TcpStream>) -> Option<Seen> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if tls.read(&mut byte).ok()? == 0 || buf.len() > 65536 {
            return None;
        }
        buf.push(byte[0]);
    }
    let head = String::from_utf8(buf).ok()?;
    let mut seen = Seen { head, body: Vec::new() };
    if let Some(n) = seen.header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        let mut body = vec![0u8; n];
        tls.read_exact(&mut body).ok()?;
        seen.body = body;
    }
    Some(seen)
}

fn request(server: &Server, path: &str) -> Request {
    let host = format!("localhost:{}", server.port);
    let mut r = Request::get(&format!("https://{host}{path}"), &[host.as_str()]);
    r.proxy = Proxy::Direct;
    r.timeout = Duration::from_secs(5);
    r
}

#[test]
fn a_request_to_an_allowed_host_is_answered() {
    let server = serve(|seen| Some(response(200, &["X-Test: 1"], format!("hello {}", seen.path()).as_bytes())));
    let reply = fetch(&request(&server, "/a")).unwrap();
    assert_eq!((reply.status, reply.body.as_slice()), (200, b"hello /a".as_slice()));
    assert_eq!(reply.version, "HTTP/1.1");
    assert!(reply.headers.iter().any(|(n, v)| n.eq_ignore_ascii_case("x-test") && v == "1"));
    assert_eq!(reply.url, format!("https://localhost:{}/a", server.port));
    let seen = server.seen.lock().unwrap()[0].clone();
    assert_eq!(seen.header("user-agent"), Some(USER_AGENT));
}

#[test]
fn connections_are_kept_and_shared() {
    let server = serve(|_| Some(response(200, &[], b"ok")));
    for _ in 0..3 {
        assert_eq!(fetch(&request(&server, "/")).unwrap().body, b"ok");
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 1, "three requests, one connection");
}

#[test]
fn a_post_carries_its_body_and_fields() {
    let server = serve(|seen| Some(response(200, &[], &seen.body)));
    let mut req = request(&server, "/q");
    req.method = "POST".to_string();
    req.body = br#"{"a":1}"#.to_vec();
    req.headers = vec![("Accept".into(), "application/json;api-version=3.0-preview.1".into()),
                       ("Content-Type".into(), "application/json".into())];
    assert_eq!(fetch(&req).unwrap().body, br#"{"a":1}"#);
    let seen = server.seen.lock().unwrap()[0].clone();
    assert!(seen.head.starts_with("POST /q "));
    assert_eq!(seen.header("accept"), Some("application/json;api-version=3.0-preview.1"));
    assert_eq!(seen.header("content-type"), Some("application/json"));
}

#[test]
fn a_redirect_is_followed_only_to_a_host_of_the_rule() {
    let target = serve(|_| Some(response(200, &[], b"landed")));
    let elsewhere = format!("https://127.0.0.1:{}/x", target.port);
    let allowed = format!("https://localhost:{}/x", target.port);
    let hop = serve(move |seen| {
        let to = if seen.path() == "/out" { &elsewhere } else { &allowed };
        Some(response(302, &[&format!("Location: {to}")], b""))
    });
    let mut req = request(&hop, "/in");
    req.hosts.push(format!("localhost:{}", target.port));
    assert_eq!(fetch(&req).unwrap().body, b"landed");
    let mut req = request(&hop, "/out");
    req.hosts.push(format!("localhost:{}", target.port));
    let before = target.connections.load(Ordering::SeqCst);
    match fetch(&req) {
        Err(Failure::Refused(m)) => assert!(m.contains("host not allowed"), "{m}"),
        other => panic!("a hop to a host the rule does not name: {other:?}"),
    }
    assert_eq!(target.connections.load(Ordering::SeqCst), before, "nothing connected to the refused host");
}

#[test]
fn redirects_stop_at_the_callers_number() {
    let server = serve(|seen| {
        let n: u32 = seen.path().trim_start_matches('/').parse().unwrap_or(0);
        Some(response(302, &[&format!("Location: /{}", n + 1)], b""))
    });
    let mut req = request(&server, "/0");
    req.max_redirects = 3;
    assert!(matches!(fetch(&req), Err(Failure::Http(m)) if m.contains("too many redirects")));
}

#[test]
fn a_body_over_the_budget_is_too_large() {
    let server = serve(|seen| {
        if seen.path() == "/chunked" {
            let mut out = b"HTTP/1.1 200 X\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for _ in 0..4 {
                out.extend_from_slice(b"400\r\n");
                out.extend_from_slice(&[b'a'; 0x400]);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"0\r\n\r\n");
            Some(out)
        } else {
            Some(response(200, &[], &[b'a'; 4096]))
        }
    });
    for path in ["/declared", "/chunked"] {
        let mut req = request(&server, path);
        req.max_bytes = 4095;
        assert_eq!(fetch(&req).unwrap_err(), Failure::TooLarge, "{path}");
        req.max_bytes = 4096;
        assert_eq!(fetch(&req).unwrap().body.len(), 4096, "{path}: exactly the budget is fine");
    }
}

#[test]
fn a_stream_reads_in_pieces_within_the_budget() {
    let server = serve(|_| Some(response(200, &[], &[b'z'; 10_000])));
    let mut stream = open(&request(&server, "/")).unwrap();
    assert_eq!(stream.status, 200);
    let mut got = 0;
    let mut buf = [0u8; 999];
    loop {
        let n = stream.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        got += n;
    }
    assert_eq!(got, 10_000);
    let mut req = request(&server, "/");
    req.max_bytes = 9_999;
    let failed = open(&req).and_then(|mut s| loop {
        if s.read(&mut buf)? == 0 {
            break Ok(());
        }
    });
    assert_eq!(failed.unwrap_err(), Failure::TooLarge);
}

#[test]
fn the_url_rules_hold() {
    let server = serve(|_| Some(response(200, &[], b"ok")));
    for url in [format!("http://localhost:{}/", server.port), format!("https://user:pw@localhost:{}/", server.port),
                format!("https://localhost:{}/{}", server.port, "a".repeat(2100)), format!("https://localhost:{}/a b", server.port)] {
        let mut req = request(&server, "/");
        req.url = url.clone();
        assert!(matches!(fetch(&req), Err(Failure::Refused(_))), "{url}");
    }
    let mut req = request(&server, "/");
    req.hosts.clear();
    assert!(matches!(fetch(&req), Err(Failure::Setup(_))), "a request without a rule");
    let mut req = request(&server, "/");
    req.hosts = vec!["elsewhere.invalid".to_string()];
    req.any_host = true;
    assert_eq!(fetch(&req).unwrap().body, b"ok", "no host rule when the caller says any host");
    req.url = format!("http://localhost:{}/", server.port);
    assert!(matches!(fetch(&req), Err(Failure::Refused(_))), "the URL limits hold without a host rule");
    let mut req = request(&server, "/");
    req.hosts = vec!["localhost".to_string()];
    assert!(matches!(fetch(&req), Err(Failure::Refused(_))), "an entry without a port is the default port only");
    let mut req = request(&server, "/");
    req.method = "DELETE".to_string();
    assert!(matches!(fetch(&req), Err(Failure::Setup(_))));
    let mut req = request(&server, "/");
    req.headers = vec![("X-Bad".into(), "a\r\nInjected: 1".into())];
    assert!(matches!(fetch(&req), Err(Failure::Setup(_))));
    assert_eq!(server.connections.load(Ordering::SeqCst), 1, "only the any-host request was sent");
}

#[test]
fn a_wildcard_is_one_label_on_the_default_port() {
    let rules = HostRules::new(["marketplace.visualstudio.com", "*.gallerycdn.vsassets.io"]).unwrap()
        .one_label_wildcards(true).default_port_only(true);
    assert!(rules.allows("ms-python.gallerycdn.vsassets.io", 443, 443));
    assert!(!rules.allows("a.b.gallerycdn.vsassets.io", 443, 443), "two labels");
    assert!(!rules.allows("gallerycdn.vsassets.io", 443, 443), "the domain itself");
    assert!(!rules.allows("ms-python.gallerycdn.vsassets.io", 8443, 443), "another port");
    assert!(!rules.allows("evil_x.gallerycdn.vsassets.io", 443, 443), "not a label");
    assert!(rules.allows("marketplace.visualstudio.com", 443, 443));
    assert!(!rules.allows("marketplace.visualstudio.com", 444, 443));
}

#[test]
fn a_server_the_anchors_do_not_vouch_for_is_refused() {
    let _ = pki();
    let other = TestPki::new(&["127.0.0.1", "localhost"]).unwrap();
    let server = serve_with(&other, |_| Some(response(200, &[], b"ok")));
    match fetch(&request(&server, "/")) {
        Err(Failure::Tls(_)) => {}
        other => panic!("an unknown root: {other:?}"),
    }
}

#[test]
fn a_server_that_says_nothing_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let held = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(3));
        drop(stream);
    });
    let host = format!("localhost:{port}");
    let mut req = Request::get(&format!("https://{host}/"), &[host.as_str()]);
    req.proxy = Proxy::Direct;
    req.timeout = Duration::from_millis(500);
    let started = std::time::Instant::now();
    assert!(matches!(fetch(&req), Err(Failure::Timeout(_))));
    assert!(started.elapsed() < Duration::from_secs(3));
    held.join().unwrap();
}

#[test]
fn a_failure_says_its_kind() {
    assert_eq!(classify(NetError::Http("host not allowed: x".into())).kind(), "refused");
    assert_eq!(classify(NetError::Http("response body exceeds the configured size limit".into())), Failure::TooLarge);
    assert_eq!(classify(NetError::Tls("protocol_version: server did not negotiate TLS 1.3".into())).kind(), "tls-version");
    assert_eq!(classify(NetError::Alert(2, 70)).kind(), "tls-version");
    assert_eq!(classify(NetError::Alert(2, 40)).kind(), "tls");
    assert_eq!(classify(NetError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut))).kind(), "timeout");
    assert_eq!(classify(NetError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))).kind(), "network");
    let wrapped = std::io::Error::new(std::io::ErrorKind::InvalidData, NetError::Http("response body exceeds the configured size limit".into()));
    assert_eq!(classify(unwrap_io(wrapped)), Failure::TooLarge);
    let refused = |hop, by| NetError::Refused(tiny_https::error::Refused { hop, by, reason: "host not allowed: x".into() });
    assert_eq!(classify(refused(0, tiny_https::error::RefusedBy::HostRule)),
               Failure::Refused("request refused: host not allowed: x".into()));
    assert_eq!(classify(refused(2, tiny_https::error::RefusedBy::Scheme)),
               Failure::Refused("redirect 2 refused: host not allowed: x".into()));
}

#[test]
fn a_server_that_offers_h2_is_spoken_to_in_http2_on_one_connection() {
    let server = serve_h2(|path, body| (200, format!("{path} {}", body.len()).into_bytes()));
    let mut threads = Vec::new();
    for i in 0..8 {
        let req = request(&server, &format!("/p{i}"));
        threads.push(thread::spawn(move || fetch(&req).unwrap()));
    }
    for (i, t) in threads.into_iter().enumerate() {
        let reply = t.join().unwrap();
        assert_eq!((reply.status, reply.version.as_str()), (200, "HTTP/2"));
        assert_eq!(reply.body, format!("/p{i} 0").into_bytes());
    }
    let mut req = request(&server, "/post");
    req.method = "POST".to_string();
    req.body = vec![b'x'; 70_000];
    assert_eq!(fetch(&req).unwrap().body, b"/post 70000");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1, "every request on the origin's one HTTP/2 connection");
}

#[test]
fn over_http2_the_budget_holds_too() {
    let server = serve_h2(|_, _| (200, vec![b'b'; 50_000]));
    let mut req = request(&server, "/");
    req.max_bytes = 49_999;
    assert_eq!(fetch(&req).unwrap_err(), Failure::TooLarge);
    req.max_bytes = 50_000;
    assert_eq!(fetch(&req).unwrap().body.len(), 50_000);
}
