//! What a client with a rule about hosts ([`Client::allowed_hosts`]) does, and what a POST that carries JSON and says what it accepts sends.
//! The rule is about the host a request is going to: the first URL and every redirect, before anything is sent there. These settle, that
//! the rule's own tests cannot, that it is applied where a request is made (blocking, async, streamed, whole) and at every hop, that a
//! refused host is not so much as connected to, and that what a redirect keeps and drops is what a caller who sends JSON needs. The
//! tighter rule that a caller can ask for (one-label wildcards, the default port only, and the limits of [`UrlLimits`]) is settled here
//! too, for the rule of a module that reaches the Marketplace's hosts: on the first URL and on every hop.

use super::testserver::*;
use super::{Hop, HostRules};
use crate::asyncio::block_on;
use crate::error::Error;
use crate::http::{Url, UrlLimits};

fn rules(entries: &[&str]) -> HostRules {
    HostRules::new(entries.iter().copied()).unwrap()
}

/// The URL of `server` with its host written as `host` (`localhost` reaches the same server as `127.0.0.1` does).
fn as_host(server: &TestServer, host: &str, path: &str) -> String {
    server.url(path).replace("127.0.0.1", host)
}

fn refused(e: &Error) -> bool {
    matches!(e, Error::Http(m) if m.starts_with("host not allowed"))
}

/// Refused by a limit of the URL (not by the rule about hosts).
fn limited(e: &Error) -> bool {
    matches!(e, Error::Http(m) if m.starts_with("URL not allowed"))
}

fn port_of(server: &TestServer) -> u16 {
    Url::parse(&server.url("/")).unwrap().port
}

/// A client with the rule that a module reaching the Marketplace has: the hosts of its CDNs (one label under each domain, on the default
/// port), and the strictest limits on a URL. It has no connection to make: the tests ask it what it decides.
fn marketplace() -> crate::Client {
    crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .allowed_hosts(rules(&["marketplace.visualstudio.com", "*.gallerycdn.vsassets.io", "*.gallery.vsassets.io"]).one_label_wildcards(true).default_port_only(true))
        .url_limits(UrlLimits::strict())
}

/// What `client` decides about a request to `url`: the host it is to go to, or why not.
fn first(client: &crate::Client, url: &str) -> Result<String, Error> {
    client.start("GET".into(), url, vec![], vec![]).map(|hop| hop.url.host)
}

/// What `client` decides about a redirect from `from` to `location`: the host it goes to, or why not.
fn hop_to(client: &crate::Client, from: &str, location: &str) -> Result<String, Error> {
    let mut hop = Hop { method: "GET".into(), url: Url::parse(from).unwrap(), headers: vec![], body: vec![] };
    client.follow(&mut hop, 302, &[("Location".to_string(), location.to_string())], &mut 0)?;
    Ok(hop.url.host)
}

#[derive(Debug)]
enum Verdict {
    /// Goes to this host.
    Goes(&'static str),
    /// The rule about hosts refuses it.
    Host,
    /// A limit of the URL refuses it.
    Url,
    /// A redirect from https to plain http is refused (as it is of every client).
    Plain,
}

fn check(what: &str, got: Result<String, Error>, want: &Verdict) {
    let ok = match (&got, want) {
        (Ok(h), Verdict::Goes(w)) => h == w,
        (Err(e), Verdict::Host) => refused(e),
        (Err(e), Verdict::Url) => limited(e),
        (Err(Error::Http(m)), Verdict::Plain) => m.contains("plain http"),
        _ => false,
    };
    assert!(ok, "{what}: wanted {want:?}, got {got:?}");
}

#[test]
fn a_request_to_a_host_the_rule_does_not_name_is_refused_and_nothing_connects() {
    let server = TestServer::start(|_| ok("hello"));
    let client = server.client().allowed_hosts(rules(&["api.example.com", "*.example.org"]));
    for url in [server.url("/"), as_host(&server, "localhost", "/"), as_host(&server, "example.org", "/")] {
        let e = client.get(&url).unwrap_err();
        assert!(refused(&e), "{url}: {e}");
    }
    assert_eq!(server.connections(), 0, "a host that is refused is not connected to");
    // the rule names the host: it goes through
    let client = server.client().allowed_hosts(rules(&["api.example.com", "127.0.0.1"]));
    assert_eq!(client.get(&server.url("/")).unwrap().text(), "hello");
    // (the same for a request that is streamed, and for the other methods)
    let none = server.client().allowed_hosts(rules(&["api.example.com"]));
    assert!(refused(&none.get_stream(&server.url("/")).err().unwrap()));
    assert!(refused(&none.post(&server.url("/"), "x").unwrap_err()));
    assert!(refused(&none.head(&server.url("/")).unwrap_err()));
    assert!(refused(&none.request("PUT", &server.url("/")).body("x").send().unwrap_err()));
    assert_eq!(server.connections(), 1);
}

#[test]
fn a_redirect_to_a_host_the_rule_does_not_name_is_refused_before_anything_is_sent_there() {
    let target = TestServer::start(|_| ok("target"));
    let landed = as_host(&target, "localhost", "/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"moved")));
    let client = origin.client().allowed_hosts(rules(&["127.0.0.1"]));
    let e = client.get(&origin.url("/")).unwrap_err();
    assert!(refused(&e) && e.to_string().contains("localhost"), "{e}");
    assert_eq!((origin.connections(), target.connections()), (1, 0), "the redirect was seen, and the host it names was not connected to");
    // streamed, the same
    assert!(refused(&client.get_stream(&origin.url("/")).err().unwrap()));
    assert_eq!(target.connections(), 0);
    // with the host in the rule, the same redirect is followed
    let client = origin.client().allowed_hosts(rules(&["127.0.0.1", "localhost"]));
    assert_eq!(client.get(&origin.url("/")).unwrap().text(), "target");
    assert_eq!(target.connections(), 1);
    // and with no rule at all
    assert_eq!(origin.client().get(&origin.url("/")).unwrap().text(), "target");
}

#[test]
fn every_hop_is_checked_not_only_the_first_and_the_last() {
    // a (127.0.0.1) -> b (127.0.0.1) -> c (written as localhost) -> last (127.0.0.1): with a rule that names only 127.0.0.1 the hop in the
    // middle of the chain is the one that is refused, though the host at the end of it is allowed
    let last = TestServer::start(|_| ok("end"));
    let last_url = last.url("/end");
    let c = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {last_url}")], b"")));
    let c_url = as_host(&c, "localhost", "/c");
    let b = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {c_url}")], b"")));
    let b_url = b.url("/b");
    let a = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {b_url}")], b"")));
    let client = a.client().allowed_hosts(rules(&["127.0.0.1"]));
    let e = client.get(&a.url("/a")).unwrap_err();
    assert!(refused(&e), "{e}");
    assert_eq!((a.connections(), b.connections(), c.connections(), last.connections()), (1, 1, 0, 0));
    // a rule that names all of them follows the chain to the end
    let client = a.client().allowed_hosts(rules(&["127.0.0.1", "localhost"]));
    assert_eq!(client.get(&a.url("/a")).unwrap().text(), "end");
}

#[test]
fn a_user_name_in_the_url_does_not_make_a_host_allowed() {
    let server = TestServer::start(|_| ok("hello"));
    let client = server.client().allowed_hosts(rules(&["127.0.0.1"]));
    // the host is what follows the last `@`, whatever comes before it
    let evil = server.url("/").replace("://127.0.0.1", "://127.0.0.1@localhost");
    assert!(refused(&client.get(&evil).unwrap_err()), "{evil}");
    let fine = server.url("/").replace("://127.0.0.1", "://localhost@127.0.0.1");
    assert_eq!(client.get(&fine).unwrap().text(), "hello");
    // nor does a redirect that has one
    let target = TestServer::start(|_| ok("target"));
    let landed = target.url("/").replace("://127.0.0.1", "://127.0.0.1@localhost");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"")));
    assert!(refused(&origin.client().allowed_hosts(rules(&["127.0.0.1"])).get(&origin.url("/")).unwrap_err()));
    assert_eq!(target.connections(), 0);
}

#[test]
fn a_clone_has_the_rule_that_was_set_on_it() {
    let server = TestServer::start(|_| ok("hello"));
    let shared = server.client();
    let module_a = shared.clone().allowed_hosts(rules(&["127.0.0.1"]));
    let module_b = shared.clone().allowed_hosts(rules(&["api.example.com"]));
    assert_eq!(module_a.get(&server.url("/")).unwrap().text(), "hello");
    assert!(refused(&module_b.get(&server.url("/")).unwrap_err()));
    // the client they came from has none
    assert_eq!(shared.get(&server.url("/")).unwrap().text(), "hello");
    // and a rule can be taken away from a clone
    assert_eq!(module_b.clone().any_host().get(&server.url("/")).unwrap().text(), "hello");
    // they share their connections: one was made, and it served all three that got through
    assert_eq!(server.connections(), 1);
}

#[test]
fn the_wildcard_is_applied_to_the_hop_that_a_redirect_makes() {
    // (no network: the decision of `follow` for the redirect's `Location`)
    let client = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty())).allowed_hosts(rules(&["api.example.com", "*.cdn.example.net"]));
    let hop = |url: &str| Hop { method: "GET".into(), url: Url::parse(url).unwrap(), headers: vec![], body: vec![] };
    let location = |value: &str| vec![("Location".to_string(), value.to_string())];
    // (where the redirect goes, the host it ends up at if it is followed)
    for (to, goes_to) in [
        ("https://a.cdn.example.net/x", Some("a.cdn.example.net")),
        ("https://a.b.cdn.example.net/x", Some("a.b.cdn.example.net")),
        ("https://API.example.com/x", Some("api.example.com")),
        ("/relative", Some("api.example.com")),
        ("https://cdn.example.net/x", None),
        ("https://evilcdn.example.net/x", None),
        ("https://a.cdn.example.net.evil.org/x", None),
        ("https://example.com/x", None),
        ("//evil.example.org/x", None),
        ("https://api.example.com@evil.example.org/x", None),
        ("https://a.cdn.example.net:8443@evil.example.org/x", None),
    ] {
        let mut h = hop("https://api.example.com/start");
        let r = client.follow(&mut h, 302, &location(to), &mut 0);
        match (r, goes_to) {
            (Ok(true), Some(host)) => assert_eq!(h.url.host, host, "{to}"),
            (Err(e), None) => assert!(refused(&e), "{to}: {e}"),
            (r, _) => panic!("{to}: {r:?}"),
        }
    }
    // a refused hop leaves the request as it was
    let mut h = hop("https://api.example.com/start");
    assert!(client.follow(&mut h, 302, &location("https://evil.example.org/"), &mut 0).is_err());
    assert_eq!(h.url.host, "api.example.com");
}

#[test]
fn the_async_client_applies_the_rule_too() {
    let target = TestServer::start(|_| ok("target"));
    let landed = as_host(&target, "localhost", "/landed");
    let origin = TestServer::start(move |s| if s.path() == "/ok" { ok("fine") } else { Reply::Send(response(302, &[&format!("Location: {landed}")], b"")) });
    let client = origin.client().allowed_hosts(rules(&["127.0.0.1"])).into_async();
    assert_eq!(block_on(client.get(&origin.url("/ok"))).unwrap().text(), "fine");
    let e = block_on(client.get(&origin.url("/redirect"))).unwrap_err();
    assert!(refused(&e), "{e}");
    assert_eq!(target.connections(), 0);
    let e = block_on(client.get(&as_host(&origin, "localhost", "/ok"))).unwrap_err();
    assert!(refused(&e), "{e}");
    // (and the blocking client's `*_async` methods)
    let e = block_on(origin.client().allowed_hosts(rules(&["127.0.0.1"])).get_async(&origin.url("/redirect"))).unwrap_err();
    assert!(refused(&e), "{e}");
    assert_eq!(target.connections(), 0);
}

#[test]
fn the_limits_hold_at_every_hop_of_a_followed_redirect() {
    // the redirect limit, the size limit of the body of the last response and the time limit are the ones of the client the request was made with
    let server = TestServer::start(|s| match s.path() {
        "/loop" => Reply::Send(response(302, &["Location: /loop"], b"")),
        "/big" => Reply::Send(response(200, &[], &[b'x'; 5000])),
        "/slow" => Reply::Send(response(302, &["Location: /big"], b"")),
        _ => ok("hello"),
    });
    let client = server.client().allowed_hosts(rules(&["127.0.0.1"]));
    let e = client.clone().max_redirects(3).get(&server.url("/loop")).unwrap_err();
    assert!(e.to_string().contains("too many redirects"), "{e}");
    assert_eq!(server.requests().iter().filter(|s| s.path() == "/loop").count(), 4, "the first request and three redirects");
    let e = client.clone().max_body_bytes(1000).get(&server.url("/slow")).unwrap_err();
    assert!(e.to_string().contains("size limit"), "{e}");
    assert_eq!(client.request("GET", &server.url("/slow")).max_body_bytes(10_000).send().unwrap().body.len(), 5000);
}

// ------------------------------------------------------------------------------------------------ a POST of JSON

#[test]
fn a_post_of_json_that_says_what_it_accepts() {
    let server = TestServer::start(|s| {
        let body = String::from_utf8_lossy(&s.body).to_string();
        Reply::Send(response(200, &["Content-Type: application/json"], format!("{{\"got\":{}}}", body.len()).as_bytes()))
    });
    let client = server.client().allowed_hosts(rules(&["127.0.0.1"]));
    let json = r#"{"module":"market","query":"café \"quoted\"","n":[1,2,3]}"#;
    let r = client
        .request("POST", &server.url("/api/v1/search"))
        .header("Accept", "application/json")
        .header("Content-Type", "application/json; charset=utf-8")
        .body(json)
        .send()
        .unwrap();
    assert_eq!((r.status, r.text()), (200, format!("{{\"got\":{}}}", json.len())));
    let seen = server.requests().remove(0);
    assert_eq!(seen.method(), "POST");
    assert_eq!(seen.path(), "/api/v1/search");
    assert_eq!(seen.body, json.as_bytes());
    assert_eq!(seen.header("content-length"), Some(json.len().to_string().as_str()));
    assert_eq!(seen.header("content-type"), Some("application/json; charset=utf-8"));
    // the caller's Accept is the one sent, and the default (`*/*`) is not sent besides it
    assert_eq!(seen.header("accept"), Some("application/json"));
    assert_eq!(seen.head.to_ascii_lowercase().matches("\naccept:").count(), 1, "{}", seen.head);
    // without one, the default is
    client.post(&server.url("/x"), "{}").unwrap();
    assert_eq!(server.requests().last().unwrap().header("accept"), Some("*/*"));
}

#[test]
fn a_redirect_that_keeps_the_method_keeps_the_json_and_what_is_accepted() {
    let target = TestServer::start(|s| Reply::Send(response(200, &[], format!("{} {}", s.method(), String::from_utf8_lossy(&s.body)).as_bytes())));
    let landed = target.url("/landed");
    let origin = TestServer::start(move |s| {
        let status = match s.path() {
            "/temporary" => 307,
            "/permanent" => 308,
            "/see-other" => 303,
            _ => 302,
        };
        Reply::Send(response(status, &[&format!("Location: {landed}")], b""))
    });
    let client = origin.client().allowed_hosts(rules(&["127.0.0.1"]));
    let post = |path: &str| {
        client
            .request("POST", &origin.url(path))
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Authorization", "Bearer secret")
            .body(r#"{"a":1}"#)
            .send()
            .unwrap()
    };
    // 307 and 308: the same method and the same body, to the same host
    for path in ["/temporary", "/permanent"] {
        assert_eq!(post(path).text(), r#"POST {"a":1}"#, "{path}");
        let landed = target.requests().pop().unwrap();
        assert_eq!(landed.header("accept"), Some("application/json"), "{path}");
        assert_eq!(landed.header("content-type"), Some("application/json"), "{path}");
    }
    // 303 (and 302 for a POST): a GET without the body or what described it; what is accepted stays
    for path in ["/see-other", "/found"] {
        assert_eq!(post(path).text(), "GET ", "{path}");
        let landed = target.requests().pop().unwrap();
        assert_eq!(landed.header("accept"), Some("application/json"), "{path}");
        assert_eq!(landed.header("content-type"), None, "{path}");
    }
    // (the credential is not sent to another origin by any of them)
    assert!(target.requests().iter().all(|s| s.header("authorization").is_none()));
}

// ------------------------------------------------------------------------------------------------ the tighter rule

const CDN: &str = "x.gallerycdn.vsassets.io";

#[test]
fn the_rule_of_a_module_that_reaches_the_marketplace_holds_on_the_first_url() {
    let client = marketplace();
    let long = |n: usize| format!("https://{CDN}/{}", "a".repeat(n - format!("https://{CDN}/").len()));
    for (url, want) in [
        ("https://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes(CDN)),
        ("https://X.GalleryCDN.vsassets.io/a".to_string(), Verdict::Goes(CDN)),
        ("https://x.gallerycdn.vsassets.io:443/a".to_string(), Verdict::Goes(CDN)),
        ("https://p-1.gallery.vsassets.io/a".to_string(), Verdict::Goes("p-1.gallery.vsassets.io")),
        ("https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery".to_string(), Verdict::Goes("marketplace.visualstudio.com")),
        // one label, and no other: not the domain, not two labels, not a name that only ends like the domain
        ("https://gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://a.b.gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://evilgallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://x_y.gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        (format!("https://{}.gallerycdn.vsassets.io/a", "a".repeat(64)), Verdict::Host),
        // the default port only: a wildcard never matches another port, and nor does a plain entry
        ("https://x.gallerycdn.vsassets.io:8443/a".to_string(), Verdict::Host),
        ("https://marketplace.visualstudio.com:8443/a".to_string(), Verdict::Host),
        // https only, no credentials, printable ASCII only, at most 2,048 bytes
        ("http://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        ("https://u@x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        ("https://u:p@x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/a b".to_string(), Verdict::Url),
        (" https://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/a\n".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/caf\u{e9}".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/\u{7f}".to_string(), Verdict::Url),
        (long(2048), Verdict::Goes(CDN)),
        (long(2049), Verdict::Url),
    ] {
        check(&url, first(&client, &url), &want);
    }
}

#[test]
fn the_rule_of_a_module_that_reaches_the_marketplace_holds_on_every_redirect() {
    let client = marketplace();
    let from = "https://marketplace.visualstudio.com/start";
    let long = |n: usize| format!("https://{CDN}/{}", "a".repeat(n - format!("https://{CDN}/").len()));
    for (location, want) in [
        ("https://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes(CDN)),
        ("https://x.gallerycdn.vsassets.io:443/a".to_string(), Verdict::Goes(CDN)),
        ("//x.gallery.vsassets.io/a".to_string(), Verdict::Goes("x.gallery.vsassets.io")),
        ("/relative".to_string(), Verdict::Goes("marketplace.visualstudio.com")),
        ("https://gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://a.b.gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://evilgallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://x.gallerycdn.vsassets.io:8443/a".to_string(), Verdict::Host),
        ("https://x.gallerycdn.vsassets.io:80/a".to_string(), Verdict::Host),
        ("https://x.gallerycdn.vsassets.io.evil.org/a".to_string(), Verdict::Host),
        ("https://u@x.gallerycdn.vsassets.io/a".to_string(), Verdict::Url),
        // (refused twice over: it has a user name, and its host is evil.org; the limit speaks first)
        ("https://x.gallerycdn.vsassets.io@evil.org/a".to_string(), Verdict::Url),
        ("https://u:p@x.gallerycdn.vsassets.io:443/a".to_string(), Verdict::Url),
        ("http://x.gallerycdn.vsassets.io/a".to_string(), Verdict::Plain),
        ("https://x.gallerycdn.vsassets.io/a b".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/caf\u{e9}".to_string(), Verdict::Url),
        ("https://x.gallerycdn.vsassets.io/\u{7f}".to_string(), Verdict::Url),
        (long(2048), Verdict::Goes(CDN)),
        (long(2049), Verdict::Url),
        (format!("/{}", "a".repeat(3000)), Verdict::Url),
    ] {
        check(&location, hop_to(&client, from, &location), &want);
    }
    // a short Location can make a long URL: it is the URL that is sent to that is judged, as well as what the server said
    let base = format!("https://marketplace.visualstudio.com/{}", "p".repeat(1980));
    assert!(base.len() < 2048);
    assert!(hop_to(&client, &base, "?q=1").is_ok());
    assert!(limited(&hop_to(&client, &base, &format!("?q={}", "a".repeat(100))).unwrap_err()));
    // (a hop that follows a hop: it is the one the redirect has made that the next is judged from, and every one is judged)
    let mut hop = Hop { method: "GET".into(), url: Url::parse(from).unwrap(), headers: vec![], body: vec![] };
    let at = |v: &str| vec![("Location".to_string(), v.to_string())];
    let mut hops = 0;
    assert!(client.follow(&mut hop, 302, &at("https://x.gallerycdn.vsassets.io/one"), &mut hops).unwrap());
    assert!(client.follow(&mut hop, 302, &at("https://y.gallery.vsassets.io/two"), &mut hops).unwrap());
    assert!(limited(&client.follow(&mut hop, 302, &at("https://u:p@z.gallery.vsassets.io/three"), &mut hops).unwrap_err()));
    assert_eq!(hop.url.host, "y.gallery.vsassets.io", "a refused hop leaves the request where it was");
}

#[test]
fn without_the_switches_the_rule_is_the_loose_one() {
    // the same locations through a client that has the hosts but neither switch nor a limit: any depth, any port, credentials and
    // a long URL are what the rule lets through (a caller that wants less says so)
    let client = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .allowed_hosts(rules(&["marketplace.visualstudio.com", "*.gallerycdn.vsassets.io"]));
    let from = "https://marketplace.visualstudio.com/start";
    let long = format!("https://{CDN}/{}", "a".repeat(3000));
    for (location, want) in [
        ("https://a.b.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes("a.b.gallerycdn.vsassets.io")),
        ("https://x.gallerycdn.vsassets.io:8443/a".to_string(), Verdict::Goes(CDN)),
        ("https://u:p@x.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes(CDN)),
        ("https://x_y.gallerycdn.vsassets.io/a".to_string(), Verdict::Goes("x_y.gallerycdn.vsassets.io")),
        (long, Verdict::Goes(CDN)),
        // what no switch lets through: the domain itself, a name that only ends like it, a host that is not named
        ("https://gallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://evilgallerycdn.vsassets.io/a".to_string(), Verdict::Host),
        ("https://evil.org/a".to_string(), Verdict::Host),
    ] {
        check(&location, hop_to(&client, from, &location), &want);
    }
    assert_eq!(first(&client, " https://u:p@a.b.gallerycdn.vsassets.io:8443/a").unwrap(), "a.b.gallerycdn.vsassets.io");
    // one switch at a time
    let one_label = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .allowed_hosts(rules(&["*.gallerycdn.vsassets.io"]).one_label_wildcards(true));
    assert!(refused(&first(&one_label, "https://a.b.gallerycdn.vsassets.io/").unwrap_err()));
    assert!(first(&one_label, "https://a.gallerycdn.vsassets.io:8443/").is_ok(), "a port is not looked at unless the rule asks");
    let default_port = crate::Client::with_tls_config(crate::tls::ClientConfig::new(crate::x509::TrustStore::empty()))
        .allowed_hosts(rules(&["*.gallerycdn.vsassets.io"]).default_port_only(true));
    assert!(refused(&first(&default_port, "https://a.gallerycdn.vsassets.io:8443/").unwrap_err()));
    assert!(first(&default_port, "https://a.b.gallerycdn.vsassets.io/").is_ok(), "the depth is not looked at unless the rule asks");
}

#[test]
fn a_port_is_judged_at_every_hop_and_nothing_is_connected_to_that_is_refused() {
    // origin and target are on the same host and on different ports: with the default port only and an entry for the origin's port, the
    // redirect to the target's port is refused (the host is the one the rule names), and with an entry for each it is followed
    let target = TestServer::start(|_| ok("target"));
    let landed = target.url("/landed");
    let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {landed}")], b"moved")));
    let (po, pt) = (port_of(&origin), port_of(&target));
    let tight = |entries: &[String]| origin.client().allowed_hosts(HostRules::new(entries.iter().map(|e| e.as_str())).unwrap().default_port_only(true));
    let e = tight(&[format!("127.0.0.1:{po}")]).get(&origin.url("/")).unwrap_err();
    assert!(refused(&e) && e.to_string().contains(&pt.to_string()), "{e}");
    assert_eq!((origin.connections(), target.connections()), (1, 0));
    // (a plain entry is the default port only: the origin is not reached either)
    let e = tight(&["127.0.0.1".to_string()]).get(&origin.url("/")).unwrap_err();
    assert!(refused(&e), "{e}");
    assert_eq!(origin.connections(), 1, "nothing was connected to for that");
    assert_eq!(tight(&[format!("127.0.0.1:{po}"), format!("127.0.0.1:{pt}")]).get(&origin.url("/")).unwrap().text(), "target");
    // the loose rule: a host is every port, and an entry with a port is that port
    assert_eq!(origin.client().allowed_hosts(rules(&["127.0.0.1"])).get(&origin.url("/")).unwrap().text(), "target");
    let by_port = origin.client().allowed_hosts(rules(&[&format!("127.0.0.1:{po}")]));
    assert!(refused(&by_port.get(&origin.url("/")).unwrap_err()));
}

#[test]
fn a_redirect_that_a_limit_refuses_is_refused_before_anything_is_sent_there() {
    let target = TestServer::start(|_| ok("target"));
    let creds = target.url("/").replace("://", "://user:pw@");
    let long = format!("{}{}", target.url("/"), "a".repeat(2100));
    let spaced = format!("{}a b", target.url("/"));
    for (location, limits, without) in [
        (creds, UrlLimits::new().refuse_credentials(true), "target"),
        (long, UrlLimits::new().max_length(2048), "target"),
        // (what the URL parser refuses anyway, in the middle of a URL: the limit says so first and in its own words)
        (spaced, UrlLimits::new().printable_ascii_only(true), "invalid URL"),
    ] {
        let at = location.clone();
        let reached = target.connections();
        let origin = TestServer::start(move |_| Reply::Send(response(302, &[&format!("Location: {at}")], b"moved")));
        let client = origin.client().allowed_hosts(rules(&["127.0.0.1"])).url_limits(limits);
        let e = client.get(&origin.url("/")).unwrap_err();
        assert!(limited(&e), "{limits:?}: {e}");
        assert!(limited(&client.get_stream(&origin.url("/")).err().unwrap()));
        assert!(limited(&block_on(client.clone().into_async().get(&origin.url("/"))).unwrap_err()));
        assert_eq!(target.connections(), reached, "{limits:?}: the target was connected to");
        // the same redirect, with no limit, is what it would have been
        let unlimited = origin.client().get(&origin.url("/"));
        let got = match &unlimited {
            Ok(r) => r.text(),
            Err(e) => e.to_string(),
        };
        assert!(got.contains(without), "{limits:?}: {got}");
    }
    // https only: a request to a plain http URL is refused before a connection, though the client may use plain http
    let server = TestServer::start(|_| ok("hello"));
    let client = server.client().url_limits(UrlLimits::new().https_only(true));
    let e = client.get(&server.url("/")).unwrap_err();
    assert!(limited(&e) && e.to_string().contains("not https"), "{e}");
    assert_eq!(server.connections(), 0);
    assert_eq!(server.client().get(&server.url("/")).unwrap().text(), "hello");
}

#[test]
fn a_clone_has_the_limits_that_were_set_on_it() {
    let server = TestServer::start(|_| ok("hello"));
    let shared = server.client();
    let strict = shared.clone().url_limits(UrlLimits::strict());
    assert!(limited(&strict.get(&server.url("/")).unwrap_err()));
    assert_eq!(shared.get(&server.url("/")).unwrap().text(), "hello");
    assert_eq!(strict.clone().url_limits(UrlLimits::new()).get(&server.url("/")).unwrap().text(), "hello");
}
