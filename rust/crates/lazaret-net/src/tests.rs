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
    serve_h2_located(move |path, body| {
        let (status, body) = handler(path, body);
        (status, None, body)
    })
}

/// `serve_h2` whose answer may carry a `location`.
fn serve_h2_located(handler: impl Fn(&str, &[u8]) -> (u16, Option<String>, Vec<u8>) + Send + Sync + 'static) -> Server {
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
                    let fields: String = r.headers.iter().map(|(n, v)| format!("\r\n{n}: {v}")).collect();
                    s.lock().unwrap().push(Seen { head: format!("{} {} HTTP/2{fields}", r.method, r.path), body: r.body.clone() });
                    let (status, location, body) = handler(&r.path, &r.body);
                    let length = body.len().to_string();
                    let mut fields = vec![("content-length", length.as_str())];
                    if let Some(to) = &location {
                        fields.push(("location", to.as_str()));
                    }
                    h2_server::response(status, &fields, &body)
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

// ---------------------------------------------------------------- credentials (0.1.9, decision 14)

fn credential(host: &str, path: &str, name: &str, value: &str) -> Credential {
    Credential { host: host.into(), path: path.into(), name: name.into(), value: value.into(), first_only: false }
}

fn hop<'a>(url: &'a tiny_https::http::Url, hop: usize, from: Option<&'a tiny_https::http::Url>) -> HopInfo<'a> {
    HopInfo { url, method: "GET", hop, from }
}

#[test]
fn a_credential_is_granted_to_its_host_and_path() {
    use tiny_https::http::Url;
    let creds = vec![
        credential("registry.example", "/", "Authorization", "Bearer whole"),
        credential("registry.example", "/team/", "Authorization", "Bearer team"),
        credential("registry.example:8443", "/", "Authorization", "Bearer port"),
        credential("[::1]:8443", "/", "Authorization", "Bearer v6"),
        credential("registry.example", "/team/", "PRIVATE-TOKEN", "glpat"),
    ];
    let at = |u: &str| {
        let url = Url::parse(u).unwrap();
        granted(&creds, &hop(&url, 0, None))
    };
    let pair = |n: &str, v: &str| (n.to_string(), v.to_string());
    assert_eq!(at("https://registry.example/pkg"), vec![pair("Authorization", "Bearer whole")]);
    assert_eq!(at("https://registry.example/team/pkg"),
               vec![pair("Authorization", "Bearer team"), pair("PRIVATE-TOKEN", "glpat")], "the longest path, each name");
    assert_eq!(at("https://registry.example/team"), vec![pair("Authorization", "Bearer whole")], "/team is not under /team/");
    assert_eq!(at("https://registry.example/a?x=/team/b"), vec![pair("Authorization", "Bearer whole")], "the query is not the path");
    assert_eq!(at("https://registry.example:443/pkg"), vec![pair("Authorization", "Bearer whole")], "443 is the host's own");
    assert_eq!(at("https://registry.example:8443/pkg"), vec![pair("Authorization", "Bearer port")]);
    assert_eq!(at("https://[::1]:8443/pkg"), vec![pair("Authorization", "Bearer v6")]);
    assert_eq!(at("https://REGISTRY.example/pkg"), vec![pair("Authorization", "Bearer whole")], "a host is lower case");
    assert!(at("https://other.example/pkg").is_empty());
    assert!(at("https://sub.registry.example/pkg").is_empty(), "a host is the host, not its domain");
    assert!(at("http://registry.example/pkg").is_empty(), "never over plain http");
}

#[test]
fn the_urls_own_login_goes_with_the_request_alone() {
    use tiny_https::http::Url;
    let mut first = credential("registry.example", "/", "Authorization", "Basic own");
    first.first_only = true;
    let creds = vec![credential("registry.example", "/team/", "Authorization", "Bearer settings"), first];
    let url = Url::parse("https://registry.example/team/pkg").unwrap();
    let pair = |v: &str| vec![("Authorization".to_string(), v.to_string())];
    assert_eq!(granted(&creds, &hop(&url, 0, None)), pair("Basic own"), "the request: the URL's own, before the settings'");
    let from = Url::parse("https://registry.example/elsewhere").unwrap();
    assert_eq!(granted(&creds, &hop(&url, 1, Some(&from))), pair("Bearer settings"), "a redirect: the settings' alone");
    let root = Url::parse("https://registry.example/x").unwrap();
    assert!(granted(&creds, &hop(&root, 1, Some(&from))).is_empty(), "a redirect: never the URL's own");
}

#[test]
fn a_credential_stays_with_its_host_across_redirects() {
    let target = serve(|_| Some(response(200, &[], b"landed")));
    let to = format!("https://localhost:{}/x", target.port);
    let hop_server = serve(move |seen| {
        if seen.path() == "/again" {
            return Some(response(302, &[&format!("Location: {to}")], b""));
        }
        Some(response(302, &["Location: /again"], b""))
    });
    let here = format!("localhost:{}", hop_server.port);
    let there = format!("localhost:{}", target.port);
    let mut req = request(&hop_server, "/in");
    req.hosts.push(there.clone());
    let mut own = credential(&here, "/", "Authorization", "Basic own");
    own.first_only = true;
    req.credentials = vec![own, credential(&here, "/", "PRIVATE-TOKEN", "glpat-here"),
                           credential(&here, "/again/", "Authorization", "Bearer never")];
    assert_eq!(fetch(&req).unwrap().body, b"landed");
    let seen = hop_server.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    assert_eq!((seen[0].header("authorization"), seen[0].header("private-token")), (Some("Basic own"), Some("glpat-here")));
    assert_eq!((seen[1].header("authorization"), seen[1].header("private-token")), (None, Some("glpat-here")),
               "the same host on a redirect: its credentials, not the URL's own (and /again is not under /again/)");
    let landed = target.seen.lock().unwrap()[0].clone();
    assert_eq!((landed.header("authorization"), landed.header("private-token")), (None, None),
               "another origin gets none of them, PRIVATE-TOKEN included");

    // the other host's own credential goes there, and only there
    let mut req = request(&hop_server, "/in");
    req.hosts.push(there.clone());
    req.credentials = vec![credential(&there, "/", "Authorization", "Bearer there")];
    assert_eq!(fetch(&req).unwrap().body, b"landed");
    let seen = hop_server.seen.lock().unwrap().clone();
    assert!(seen[2..].iter().all(|s| s.header("authorization").is_none()));
    assert_eq!(target.seen.lock().unwrap()[1].header("authorization"), Some("Bearer there"));

    // and a request without credentials on the same kept connections carries none
    let mut req = request(&hop_server, "/in");
    req.hosts.push(there);
    assert_eq!(fetch(&req).unwrap().body, b"landed");
    assert!(hop_server.seen.lock().unwrap()[4..].iter().all(|s| s.header("authorization").is_none() && s.header("private-token").is_none()));
    assert!(target.seen.lock().unwrap()[2].header("authorization").is_none());
}

#[test]
fn over_http2_a_credential_goes_with_its_own_request_and_host() {
    let target = serve_h2(|_, _| (200, b"landed".to_vec()));
    let to = format!("https://localhost:{}/x", target.port);
    let hop_server = serve_h2_located(move |path, _| match path {
        "/in" => (302, Some(to.clone()), Vec::new()),
        _ => (200, None, b"here".to_vec()),
    });
    let here = format!("localhost:{}", hop_server.port);
    let there = format!("localhost:{}", target.port);
    let mut req = request(&hop_server, "/in");
    req.hosts.push(there);
    req.credentials = vec![credential(&here, "/", "Authorization", "Bearer h2"),
                           credential(&here, "/", "PRIVATE-TOKEN", "glpat-h2")];
    let reply = fetch(&req).unwrap();
    assert_eq!((reply.version.as_str(), reply.body.as_slice()), ("HTTP/2", b"landed".as_slice()));
    assert_eq!(hop_server.seen.lock().unwrap()[0].header("authorization"), Some("Bearer h2"));
    let landed = target.seen.lock().unwrap()[0].clone();
    assert_eq!((landed.header("authorization"), landed.header("private-token")), (None, None));
    // the next request on the origin's one connection, without credentials, carries none
    assert_eq!(fetch(&request(&hop_server, "/plain")).unwrap().body, b"here");
    let seen = hop_server.seen.lock().unwrap()[1].clone();
    assert_eq!((seen.header("authorization"), seen.header("private-token")), (None, None));
    assert_eq!(hop_server.connections.load(Ordering::SeqCst), 1);
}

#[test]
fn a_credential_is_never_a_header_of_the_request() {
    let server = serve(|_| Some(response(200, &[], b"ok")));
    let host = format!("localhost:{}", server.port);
    for name in ["Authorization", "PRIVATE-TOKEN", "cookie", "Proxy-Authorization", "Job-Token", "Deploy-Token"] {
        let mut req = request(&server, "/");
        req.headers = vec![(name.into(), "secret".into())];
        match fetch(&req) {
            Err(Failure::Setup(m)) => assert!(m.contains("carries a credential") && !m.contains("secret"), "{m}"),
            other => panic!("{name} set by the request: {other:?}"),
        }
    }
    let mut req = request(&server, "/");
    req.headers = vec![("X-Token".into(), "secret".into())];
    req.credentials = vec![credential(&host, "/", "X-Token", "secret")];
    assert!(matches!(fetch(&req), Err(Failure::Setup(_))), "a header of a credential's name");
    for bad in [credential("Localhost", "/", "Authorization", "x"), credential(&host, "/a", "Authorization", "x"),
                credential(&host, "a/", "Authorization", "x"), credential(&host, "/", "Authorization", "x\r\nInjected: 1"),
                credential(&host, "/", "Bad Name", "x"), credential(&host, "/", "Host", "x"), credential("", "/", "Authorization", "x"),
                credential(&host, "/?q/", "Authorization", "x")] {
        let mut req = request(&server, "/");
        req.credentials = vec![bad.clone()];
        match fetch(&req) {
            Err(Failure::Setup(m)) => assert!(!m.contains("Injected") && !m.contains("\"x\""), "{m}"),
            other => panic!("{bad:?}: {other:?}"),
        }
    }
    assert_eq!(server.connections.load(Ordering::SeqCst), 0, "nothing was sent");
    let debug = format!("{:?}", credential(&host, "/", "Authorization", "Bearer s3cr3t"));
    assert!(!debug.contains("s3cr3t"), "{debug}");
}

/// pmsettings.Credentials.header's choice, written as Python's is (from the directory of the path up to `/`, the
/// first prefix the host has), for the property below.
fn pmsettings_choice<'a>(table: &'a [(String, String, String)], host: &str, path: &str) -> Option<&'a str> {
    let mut d = path[..path.rfind('/').map_or(0, |k| k + 1)].to_string();
    if d.is_empty() {
        d = "/".to_string();
    }
    loop {
        if let Some((_, _, v)) = table.iter().find(|(h, p, _)| h == host && *p == d) {
            return Some(v);
        }
        if d == "/" {
            return None;
        }
        let trimmed = &d[..d.len() - 1];
        d = trimmed[..trimmed.rfind('/').map_or(0, |k| k + 1)].to_string();
    }
}

#[test]
fn the_choice_is_pmsettings_choice() {
    use tiny_https::http::Url;
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    let hosts = ["registry.example", "registry.example:8443", "[::1]:8443", "other.example"];
    let segments = ["a", "b", "team", "npm", "a.b", "-"];
    for _ in 0..3000 {
        // a table as pmsettings keeps one: (host, a path prefix ending in '/') -> header, one header per prefix
        let mut table: Vec<(String, String, String)> = Vec::new();
        for i in 0..next(6) {
            let mut path = "/".to_string();
            for _ in 0..next(3) {
                path.push_str(segments[next(segments.len())]);
                path.push('/');
            }
            let host = hosts[next(hosts.len())].to_string();
            if !table.iter().any(|(h, p, _)| *h == host && *p == path) {
                table.push((host, path, format!("Bearer {i}")));
            }
        }
        let creds: Vec<Credential> = table.iter().map(|(h, p, v)| credential(h, p, "Authorization", v)).collect();
        let host = hosts[next(hosts.len())];
        let mut path = String::new();
        for _ in 0..next(4) {
            path.push('/');
            path.push_str(segments[next(segments.len())]);
        }
        if next(2) == 0 || path.is_empty() {
            path.push('/');
        }
        let query = if next(3) == 0 { "?x=/team/" } else { "" };
        let url = Url::parse(&format!("https://{host}{path}{query}")).unwrap();
        let got = granted(&creds, &hop(&url, 0, None));
        let want = pmsettings_choice(&table, host, &path);
        assert_eq!(got.first().map(|(_, v)| v.as_str()), want, "{host}{path}{query} with {table:?}");
        assert!(got.len() <= 1);
    }
}
