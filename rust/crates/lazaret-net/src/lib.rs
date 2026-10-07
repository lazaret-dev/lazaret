//! Lazaret's network layer (NET-1): tiny_https's HTTPS client with Lazaret's rules, for the requests the Python
//! package makes to registries, feeds and APIs (through the native library's C ABI, `lazaret-ffi`).
//!
//! Every request carries its caller's rule and is held to it by the client on the first URL and on every redirect
//! hop, before anything connects:
//!
//! * **hosts**: the hosts the caller may reach, as Lazaret writes them (`registry.npmjs.org`,
//!   `*.gallerycdn.vsassets.io`): a `*.` entry stands for exactly one DNS label, and an entry without a port is
//!   the default port only (tiny_https's `HostRules` with `one_label_wildcards` and `default_port_only`). A
//!   request without a rule is refused here: there is no "any host".
//! * **the URL**: https only, no credentials, printable ASCII, at most 2,048 bytes (`UrlLimits::strict`).
//! * **bounds**: a byte budget for the body (a larger body is [`Failure::TooLarge`], whatever the server
//!   declared), a timeout for connecting and for each read and write, an optional limit on the whole request,
//!   and a number of redirects.
//!
//! **HTTP/2 is the protocol** (John, Oct 6): the handshake offers `h2` and `http/1.1`, a server that picks `h2` gets
//! one connection per origin that every request to it shares, and any other is spoken to in HTTP/1.1 with
//! keep-alive. The clients share their connections (tiny_https's clones share the pool and the HTTP/2 registry),
//! made on first use with the trust anchors [`configure`] was given or else the system's CA bundle
//! (`SSL_CERT_FILE` first). A process that forks gets new connections in the child: the parent's are left alone,
//! neither used nor closed from the child (a TLS close from the child would end the parent's session, and an
//! HTTP/2 connection's reader and writer threads are not in the child). Proxies are the caller's to choose: from
//! the environment (`HTTPS_PROXY`, `NO_PROXY`), one given, or none.
//!
//! What it does not do: HTTP/3 is off (tiny_https has it, opt-in), and nothing is cached. TLS is 1.3 only: a
//! server that offers nothing newer than TLS 1.2 is [`Failure::TlsVersion`], which the Python side answers by
//! asking that server again with Python's own transport.

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tiny_https::error::Error as NetError;
use tiny_https::http::{HostRules, RequestBuilder, ResponseStream, UrlLimits};
use tiny_https::tls::ClientConfig;
use tiny_https::x509::TrustStore;
use tiny_https::Client;

/// The redirects a request follows at most (a caller asks for fewer).
pub const MAX_REDIRECTS: usize = 10;
/// The most a caller may ask for in one body (the Python side's largest budget is 500 MB).
pub const MAX_BODY: u64 = 2 * 1024 * 1024 * 1024;
/// The default User-Agent, when the caller gives none.
pub const USER_AGENT: &str = concat!("lazaret/", env!("CARGO_PKG_VERSION"));

/// Why a request did not give a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The caller's rule refused the URL or a redirect (a host it does not name, http, credentials, a long URL).
    Refused(String),
    /// The body was over the caller's budget (declared or read).
    TooLarge,
    /// The server offered no TLS 1.3.
    TlsVersion(String),
    /// TLS failed otherwise: the certificate, the handshake, an alert.
    Tls(String),
    /// Connecting, or a read or write, took longer than the timeout; or the whole request did.
    Timeout(String),
    /// The network: name resolution, a refused or reset connection.
    Network(String),
    /// HTTP: a malformed response, too many redirects, https to http.
    Http(String),
    /// The request itself: a bad method, header, rule or trust store.
    Setup(String),
}

impl Failure {
    /// A short name for the kind, for the C ABI and the Python side.
    pub fn kind(&self) -> &'static str {
        match self {
            Failure::Refused(_) => "refused",
            Failure::TooLarge => "too-large",
            Failure::TlsVersion(_) => "tls-version",
            Failure::Tls(_) => "tls",
            Failure::Timeout(_) => "timeout",
            Failure::Network(_) => "network",
            Failure::Http(_) => "http",
            Failure::Setup(_) => "setup",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Failure::TooLarge => "the response is larger than the budget".to_string(),
            Failure::Refused(m) | Failure::TlsVersion(m) | Failure::Tls(m) | Failure::Timeout(m) | Failure::Network(m)
            | Failure::Http(m) | Failure::Setup(m) => m.clone(),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind(), self.message())
    }
}

/// What tiny_https said, as one of ours.
fn classify(e: NetError) -> Failure {
    match e {
        NetError::Http(m) => {
            if m.starts_with("host not allowed") || m.starts_with("URL not allowed") || m.starts_with("invalid host rule") {
                Failure::Refused(m)
            } else if m.starts_with("response body exceeds") {
                Failure::TooLarge
            } else {
                Failure::Http(m)
            }
        }
        NetError::Tls(m) if m.starts_with("protocol_version") => Failure::TlsVersion(m),
        // alert 70 is protocol_version: what a server that speaks no TLS 1.3 answers a hello that offers only 1.3
        NetError::Alert(_, 70) => Failure::TlsVersion("the server answered with a protocol_version alert".to_string()),
        NetError::Tls(m) => Failure::Tls(m),
        NetError::Alert(level, desc) => Failure::Tls(format!("TLS alert received (level {level}, description {desc})")),
        NetError::Verify(v) => Failure::Tls(format!("certificate: {v}")),
        NetError::Io(io) => match io.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Failure::Timeout(io.to_string()),
            _ => Failure::Network(io.to_string()),
        },
        // the client's rules (the host rule, the URL limits, the scheme) or the hop hook said no, before anything was
        // sent there: "request refused: …", "redirect 2 refused: …" (the reason names the host, never the path,
        // a credential or a header's value)
        NetError::Refused(r) => Failure::Refused(r.to_string()),
    }
}

/// Which proxy a request goes through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proxy {
    /// `HTTPS_PROXY` / `https_proxy`, except for the hosts `NO_PROXY` names: what Python's urllib does with the
    /// environment.
    Env,
    /// None: straight to the host.
    Direct,
    /// This one (`http://[user:password@]host:port`; a proxy reached over TLS is not supported).
    Url(String),
}

/// One request and its caller's rule.
#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The caller's hosts (see the module documentation); required unless `any_host`.
    pub hosts: Vec<String>,
    /// No host rule: any host, on the first URL and every hop (a caller that checked the first URL itself and lets
    /// a redirect go to any https host: a feed that moved, a proxy's storage). The URL limits still hold.
    pub any_host: bool,
    /// The most bytes the body may have.
    pub max_bytes: u64,
    /// For connecting, and for each read and write.
    pub timeout: Duration,
    /// For the whole request, redirects included.
    pub total_timeout: Option<Duration>,
    pub max_redirects: usize,
    pub proxy: Proxy,
    /// Offer `h2` (the default); false: HTTP/1.1 only, on the shared HTTP/1.1 connections.
    pub http2: bool,
}

impl Request {
    pub fn get(url: &str, hosts: &[&str]) -> Request {
        Request {
            method: "GET".to_string(),
            url: url.to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            any_host: false,
            max_bytes: 64 * 1024 * 1024,
            timeout: Duration::from_secs(30),
            total_timeout: None,
            max_redirects: 3,
            proxy: Proxy::Env,
            http2: true,
        }
    }
}

/// A response read whole.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    /// "HTTP/2" or "HTTP/1.1".
    pub version: String,
    pub headers: Vec<(String, String)>,
    /// The URL that answered, after redirects.
    pub url: String,
    pub body: Vec<u8>,
}

/// The shared client, the process it was made in, and its trust anchors' origin.
struct Base {
    pid: u32,
    client: Client,
}

static BASE: Mutex<Option<Base>> = Mutex::new(None);
static ROOTS: Mutex<Option<Arc<String>>> = Mutex::new(None);

fn new_base(roots: Option<&str>) -> Result<Client, Failure> {
    let store = match roots {
        Some(pem) => {
            let mut store = TrustStore::empty();
            store.add_pem(pem);
            if store.is_empty() {
                return Err(Failure::Setup("the trust anchors given hold no certificate".to_string()));
            }
            store
        }
        None => tiny_https::sys::system_trust_store()
            .map_err(|e| Failure::Setup(format!("no trust anchors: {e} (set SSL_CERT_FILE, or give them to configure)")))?,
    };
    Ok(Client::with_tls_config(ClientConfig::new(store)).user_agent(USER_AGENT).http2(true))
}

/// Sets the trust anchors (PEM; None: the system's CA bundle) for the requests made from now on, and closes the
/// connections kept so far. The first request makes the pool with the system's bundle when this was never called.
pub fn configure(roots_pem: Option<&str>) -> Result<(), Failure> {
    let client = new_base(roots_pem)?;
    *ROOTS.lock().unwrap_or_else(|p| p.into_inner()) = roots_pem.map(|r| Arc::new(r.to_string()));
    let mut base = BASE.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(old) = base.take() {
        if old.pid == std::process::id() {
            old.client.close_idle_connections();
        } else {
            std::mem::forget(old);
        }
    }
    *base = Some(Base { pid: std::process::id(), client });
    Ok(())
}

/// The shared client of this process (made, or made again after a fork).
fn base() -> Result<Client, Failure> {
    let mut base = BASE.lock().unwrap_or_else(|p| p.into_inner());
    let pid = std::process::id();
    if let Some(b) = base.as_ref() {
        if b.pid == pid {
            return Ok(b.client.clone());
        }
    }
    if let Some(old) = base.take() {
        // a child of the process that made it: its connections are the parent's, so they are neither used nor closed here
        std::mem::forget(old);
    }
    let roots = ROOTS.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let client = new_base(roots.as_deref().map(|s| s.as_str()))?;
    *base = Some(Base { pid, client: client.clone() });
    Ok(client)
}

fn client_for(req: &Request) -> Result<Client, Failure> {
    if req.hosts.is_empty() && !req.any_host {
        return Err(Failure::Setup("a request needs the hosts its caller may reach".to_string()));
    }
    if req.max_bytes > MAX_BODY {
        return Err(Failure::Setup(format!("a budget of more than {MAX_BODY} bytes")));
    }
    let mut client = base()?;
    if !req.any_host {
        let rules = HostRules::new(&req.hosts).map_err(classify)?.one_label_wildcards(true).default_port_only(true);
        client = client.allowed_hosts(rules);
    }
    let timeout = if req.timeout.is_zero() { Duration::from_secs(30) } else { req.timeout };
    let mut client = client
        .url_limits(UrlLimits::strict())
        .timeout(timeout)
        .connect_timeout(timeout)
        .max_redirects(req.max_redirects.min(MAX_REDIRECTS))
        .max_body_bytes(req.max_bytes);
    if let Some(t) = req.total_timeout {
        client = client.total_timeout(t);
    }
    if !req.http2 {
        client = client.http2(false);         // (this request only: the shared HTTP/2 connections stay)
    }
    client = match &req.proxy {
        Proxy::Env => client.proxy_from_env(),
        Proxy::Direct => client,
        Proxy::Url(u) => client.proxy(u).map_err(classify)?,
    };
    Ok(client)
}

fn method_of(req: &Request) -> Result<String, Failure> {
    let method = req.method.to_ascii_uppercase();
    if !matches!(method.as_str(), "GET" | "HEAD" | "POST") {
        return Err(Failure::Setup(format!("method {:?} is not one Lazaret sends", req.method)));
    }
    Ok(method)
}

/// The request on `client`: its method, fields and (a POST's) body.
fn prepared<'c>(client: &'c Client, req: &Request, method: &str) -> Result<RequestBuilder<'c>, Failure> {
    let mut builder = client.request(method, &req.url);
    for (name, value) in &req.headers {
        if !valid_header(name, value) {
            return Err(Failure::Setup(format!("header {name:?} is not one that can be sent")));
        }
        builder = builder.header(name, value);
    }
    if method == "POST" {
        builder = builder.body(req.body.clone());
    }
    Ok(builder)
}

fn start(req: &Request) -> Result<ResponseStream, Failure> {
    let method = method_of(req)?;
    let client = client_for(req)?;
    prepared(&client, req, &method)?.send_stream().map_err(classify)
}

/// A field name of token characters and a value of visible ASCII and spaces: nothing that could end the head.
fn valid_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        && value.len() <= 8192
        && value.bytes().all(|b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b))
}

fn reply_head(s: &ResponseStream) -> (u16, String, Vec<(String, String)>, String) {
    (s.status, s.version.to_string(), s.headers.clone(), s.url.to_string())
}

/// Sends `req` and reads the whole body (at most `max_bytes`: the client's limit, which a declared length over it
/// fails at once). Read whole, an HTTP/2 body is kept as it comes and its flow-control credit goes back as it arrives,
/// with no copy more (tiny_https's `send`).
pub fn fetch(req: &Request) -> Result<Reply, Failure> {
    let method = method_of(req)?;
    let client = client_for(req)?;
    let resp = prepared(&client, req, &method)?.send().map_err(classify)?;
    if resp.body.len() as u64 > req.max_bytes {
        return Err(Failure::TooLarge);
    }
    Ok(Reply { status: resp.status, version: resp.version.to_string(), headers: resp.headers, url: resp.url.to_string(),
               body: resp.body })
}

/// A response whose body is read in pieces (a download spooled to a file, a stream handed on).
pub struct Stream {
    pub status: u16,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub url: String,
    inner: ResponseStream,
    read: u64,
    limit: u64,
}

impl Stream {
    /// The next bytes of the body into `buf` (0 at its end). Over the budget is [`Failure::TooLarge`].
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, Failure> {
        let n = self.inner.read(buf).map_err(|e| classify(unwrap_io(e)))?;
        self.read += n as u64;
        if self.read > self.limit {
            return Err(Failure::TooLarge);
        }
        Ok(n)
    }
}

/// tiny_https's body reader reports its own errors through `std::io::Error` (an `Other` that wraps one of its
/// errors); take that one out again when it is there.
fn unwrap_io(e: std::io::Error) -> NetError {
    if e.get_ref().map_or(false, |inner| inner.is::<NetError>()) {
        match e.into_inner().map(|inner| inner.downcast::<NetError>()) {
            Some(Ok(net)) => return *net,
            Some(Err(other)) => return NetError::Io(std::io::Error::other(other)),
            None => unreachable!("an error with an inner error has one"),
        }
    }
    NetError::Io(e)
}

/// Sends `req` and returns once the head is in.
pub fn open(req: &Request) -> Result<Stream, Failure> {
    let inner = start(req)?;
    let (status, version, headers, url) = reply_head(&inner);
    Ok(Stream { status, version, headers, url, inner, read: 0, limit: req.max_bytes })
}

#[cfg(test)]
mod tests;
