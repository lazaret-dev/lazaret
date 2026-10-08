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
//! * **credentials** (0.1.9, decision 14): a token or a login goes with the hops to its own host only, given by
//!   tiny_https's hop hook ([`Credential`], [`granted`]), never as a header of the request, which a redirect would
//!   carry on (tiny_https drops `Authorization`, `Cookie` and `Proxy-Authorization` on a change of origin, and no
//!   other); a request that sets one of [`CREDENTIAL_HEADERS`] itself is refused, and so is one that sets a header
//!   that is not one of [`PLAIN_HEADERS`]. A hop's path counts as under a credential's when it is so as it is sent,
//!   with its dot segments resolved and as a server that decodes it reads it, and a redirect from another origin gets
//!   a credential of the whole host only ([`granted`]).
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
//! **TLS 1.3, or TLS 1.2 with a server that speaks nothing newer** (tiny_https's B-36, its default minimum since the
//! drop of Oct 7: ECDHE with AEAD suites only, the extended master secret required, the downgrade check of RFC 8446
//! that catches a TLS 1.3 server pushed down to 1.2, no renegotiation or resumption, and the same certificate checks
//! as 1.3); every reply says which ([`Reply::tls`]). A server that speaks neither is [`Failure::TlsVersion`], and
//! Lazaret refuses it: TLS 1.2 is its floor on every transport (John, Oct 7), so the Python side does not ask that
//! server again with Python's own (`nativenet.TLS_FLOOR`).
//!
//! **A document comes compressed** (John, Oct 7: gzip for registry documents, "Add after Q-1"): a request that is a
//! document ([`Request::decompress`]: metadata, an API's answer; never a download, whose bytes are checked as they
//! were published) asks for `gzip` and `deflate`, and a body that comes as one of them is decoded on the way by
//! tiny_https's own inflate (its B-37). The decoded body is held to the request's byte budget as the body on the wire
//! is (over it: [`Failure::TooLarge`]), and to [`MAX_DECODE_RATIO`] times its compressed size once it is
//! [`DECODE_RATIO_FLOOR`] bytes long; a compressed body that is cut short, corrupt, past the ratio or followed by
//! anything is [`Failure::Http`]. Every reply says whether its body was decoded ([`Reply::decoded`]). Any other
//! request asks for the body as it is (`Accept-Encoding: identity`) and gets it so.
//!
//! What it does not do: HTTP/3 is off (tiny_https has it, opt-in), nothing is cached, and tiny_https's other opt-in
//! extras are never asked for: no cookie is kept, and a body goes with its head (no `Expect: 100-continue`).

use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tiny_https::error::Error as NetError;
use tiny_https::http::{HopInfo, HostRules, RequestBuilder, ResponseStream, UrlLimits};
use tiny_https::tls::ClientConfig;
use tiny_https::x509::TrustStore;
use tiny_https::Client;

/// The redirects a request follows at most (a caller asks for fewer).
pub const MAX_REDIRECTS: usize = 10;
/// The most a caller may ask for in one body (the Python side's largest budget is 500 MB).
pub const MAX_BODY: u64 = 2 * 1024 * 1024 * 1024;
/// The default User-Agent, when the caller gives none.
pub const USER_AGENT: &str = concat!("lazaret/", env!("CARGO_PKG_VERSION"));
/// A document's decoded body may come to at most this many times its compressed size, once it is
/// [`DECODE_RATIO_FLOOR`] bytes long: JSON and text compress 5 to 10 to 1 (npm's packument of react, 7.0 MB, comes as
/// 1.4), and a bomb is made to come near DEFLATE's most, 1,032 to 1.
pub const MAX_DECODE_RATIO: u64 = 200;
/// The decoded size from which [`MAX_DECODE_RATIO`] holds (a small body of one byte repeated compresses further).
pub const DECODE_RATIO_FLOOR: u64 = 1024 * 1024;

/// Why a request did not give a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The caller's rule refused the URL or a redirect (a host it does not name, http, credentials, a long URL).
    Refused(String),
    /// The body was over the caller's budget (declared or read).
    TooLarge,
    /// The server offered neither TLS 1.3 nor TLS 1.2: the message, and the host of the hop it was (as a Host header
    /// writes it), when it is known: on a redirect, that host and not the first URL's, which the error names (it
    /// is refused, not asked again with another transport).
    TlsVersion { message: String, host: Option<String> },
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
            Failure::TlsVersion { .. } => "tls-version",
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
            Failure::Refused(m) | Failure::TlsVersion { message: m, .. } | Failure::Tls(m) | Failure::Timeout(m)
            | Failure::Network(m) | Failure::Http(m) | Failure::Setup(m) => m.clone(),
        }
    }

    /// The host of the hop that offered no version the client speaks ([`Failure::TlsVersion`]), when it is known.
    pub fn host(&self) -> Option<&str> {
        match self {
            Failure::TlsVersion { host, .. } => host.as_deref(),
            _ => None,
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
        NetError::Tls(m) if m.starts_with("protocol_version") => Failure::TlsVersion { message: m, host: None },
        // alert 70 is protocol_version: what a server that speaks neither version the hello offers answers
        NetError::Alert(_, 70) => {
            Failure::TlsVersion { message: "the server answered with a protocol_version alert".to_string(), host: None }
        }
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
        // a document's body over the caller's budget once decoded; a compressed body cut short, corrupt or past the
        // ratio is the server's fault, as a broken response is ("response body could not be decoded: …", below)
        NetError::Decode(tiny_https::inflate::Error::OutputLimit { .. }) => Failure::TooLarge,
        // (and whatever a later tiny_https adds)
        other => Failure::Http(other.to_string()),
    }
}

/// A credential (0.1.9, decision 14): the header `name: value` for the hops to `host` whose path is under `path`,
/// over https. `host` is written as a Host header is (lower case, an IPv6 address in brackets, `:port` when the port
/// is not 443), which is how pmsettings.Credentials keys a host; `path` is a prefix that ends in `/` (`/` for the
/// whole host). With `first_only` it is for the request itself and no redirect (the user:password of the URL that
/// was asked for). tiny_https's hop hook gives them hop by hop ([`granted`]): a redirect to another host gets that
/// host's or none, and the client never carries one on.
#[derive(Clone)]
pub struct Credential {
    pub host: String,
    pub path: String,
    pub name: String,
    pub value: String,
    pub first_only: bool,
}

/// The headers that carry a credential, which a request may not set itself: its credentials go as [`Credential`]s.
/// (tiny_https drops the first three on a redirect to another origin; a header such as `PRIVATE-TOKEN` it carries on.)
pub const CREDENTIAL_HEADERS: [&str; 6] =
    ["authorization", "proxy-authorization", "cookie", "private-token", "job-token", "deploy-token"];

/// The headers a request may set itself, which go with every hop it takes: those Lazaret's callers send, none of which
/// carries a credential. Any other is refused, so that a token in a header of another name (`X-API-Key`) cannot
/// follow a redirect to another host: it goes as a [`Credential`] (the credentials review of decision 14). Live secret
/// verification's requests (0.1.9, V-1) send two more beside their credential: Anthropic's API version and the time
/// AWS's signature holds (`x-amz-date`, which says nothing without the signature, a credential).
pub const PLAIN_HEADERS: [&str; 6] =
    ["accept", "content-type", "user-agent", "x-github-api-version", "anthropic-version", "x-amz-date"];

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // (a credential's value is never printed)
        write!(f, "Credential {{ host: {:?}, path: {:?}, name: {:?}, first_only: {} }}", self.host, self.path, self.name,
               self.first_only)
    }
}

/// A path as npm, uv and browsers read it (the WHATWG URL standard's reading, and pmsettings.normal_path): its "." and
/// ".." segments resolved, "%2e" spellings included, and a backslash read as a slash; an empty segment stays ("/a//b"
/// is not "/a/b").
fn resolved_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let rest = path.strip_prefix('/').unwrap_or(&path);
    let segments: Vec<&str> = rest.split('/').collect();
    let last = segments.len() - 1;
    let mut out: Vec<&str> = Vec::with_capacity(segments.len());
    for (i, segment) in segments.iter().enumerate() {
        let lower = segment.to_ascii_lowercase();
        if matches!(lower.as_str(), ".." | ".%2e" | "%2e." | "%2e%2e") {
            out.pop();
            if i == last {
                out.push("");
            }
        } else if matches!(lower.as_str(), "." | "%2e") {
            if i == last {
                out.push("");
            }
        } else {
            out.push(segment);
        }
    }
    format!("/{}", out.join("/"))
}

/// A path as a server that decodes it before it routes it may read it (pmsettings.server_path: nginx's location
/// matching decodes "%XX", merges slashes and resolves "." and ".."; Tomcat drops a segment's ";parameters"): a
/// backslash and an encoded "/" or "\" a slash, an encoded "." a dot, ";…" dropped from each segment, a run of "/" one,
/// and the dot segments resolved.
fn server_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut decoded: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escape = (bytes[i] == b'%' && i + 2 < bytes.len()).then(|| (bytes[i + 1], bytes[i + 2].to_ascii_lowercase()));
        match escape {
            Some((b'2', b'f') | (b'5', b'c')) => {
                decoded.push(b'/');
                i += 3;
            }
            Some((b'2', b'e')) => {
                decoded.push(b'.');
                i += 3;
            }
            _ => {
                decoded.push(if bytes[i] == b'\\' { b'/' } else { bytes[i] });
                i += 1;
            }
        }
    }
    // (only ASCII bytes were replaced, by ASCII ones: what was UTF-8 still is)
    let decoded = String::from_utf8(decoded).unwrap_or_default();
    let rest = decoded.strip_prefix('/').unwrap_or(&decoded);
    let segments: Vec<&str> = rest.split('/').collect();
    let last = segments.len() - 1;
    let mut out: Vec<&str> = Vec::with_capacity(segments.len());
    for (i, segment) in segments.iter().enumerate() {
        let segment = segment.split(';').next().unwrap_or("");
        if segment == ".." {
            out.pop();
            if i == last {
                out.push("");
            }
        } else if segment == "." {
            if i == last {
                out.push("");
            }
        } else if !segment.is_empty() || i == last {
            out.push(segment);
        }
    }
    format!("/{}", out.join("/"))
}

/// The directory of a path: up to its last `/`.
fn directory(path: &str) -> &str {
    &path[..path.rfind('/').map_or(0, |k| k + 1)]
}

/// The headers the credentials give a hop: over https, for each name, the credential of the hop's host whose path is
/// the longest that covers the hop's path (what pmsettings.Credentials.header gives a URL), and on the request itself a
/// `first_only` one before any other (urllib sends the URL's own user:password with the request and with no redirect,
/// the settings' credentials of each hop's URL with a redirect).
///
/// A credential's path covers a hop's when the directory of the hop's path is under it read three ways: as it is sent,
/// as npm and uv resolve it (`resolved_path`), and as a server that decodes it may route it (`server_path`, the
/// credential's path read so too). tiny_https sends a redirect's path as the `Location` gives it, and "/team/../x" is
/// under /team/ to a server that reads it as it is, and /x to one that resolves it, as "/team/..%2fx" is to nginx (the
/// credentials reviews of decision 14). A redirect from another origin gets only a credential of the whole host (`/`):
/// npm sends none on a redirect to another host, and pip a `.netrc` login for it.
pub fn granted(credentials: &[Credential], info: &HopInfo<'_>) -> Vec<(String, String)> {
    let url = info.url;
    if url.scheme != "https" {
        return Vec::new();
    }
    let host = url.host_header();
    let crossed = info.hop > 0 && info.from.map_or(true, |from| from.origin() != url.origin());
    let path = url.path_and_query.split(['?', '#']).next().unwrap_or("/");
    let (resolved, server) = (resolved_path(path), server_path(path));
    let dirs = [directory(path), directory(&resolved), directory(&server)];
    let covers = |prefix: &str| {
        dirs[0].starts_with(prefix) && dirs[1].starts_with(prefix) && dirs[2].starts_with(server_path(prefix).as_str())
    };
    let rank = |c: &Credential| (c.first_only, c.path.len());
    let mut best: Vec<&Credential> = Vec::new();
    for c in credentials {
        if c.host != host || (c.first_only && info.hop > 0) || (crossed && c.path != "/") || !covers(&c.path) {
            continue;
        }
        match best.iter_mut().find(|b| b.name.eq_ignore_ascii_case(&c.name)) {
            Some(b) if rank(b) < rank(c) => *b = c,
            Some(_) => {}
            None => best.push(c),
        }
    }
    best.into_iter().map(|c| (c.name.clone(), c.value.clone())).collect()
}

/// Which proxy a request goes through.
#[derive(Clone, PartialEq, Eq)]
pub enum Proxy {
    /// `HTTPS_PROXY` / `https_proxy`, except for the hosts `NO_PROXY` names: what Python's urllib does with the
    /// environment.
    Env,
    /// None: straight to the host.
    Direct,
    /// This one (`http://[user:password@]host:port`; a proxy reached over TLS is not supported).
    Url(String),
}

/// A URL as `Debug` shows it: without a `user:password@` (a proxy's setting may have no scheme).
fn without_userinfo(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), url),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..end].rfind('@') {
        Some(at) => format!("{scheme}<redacted>@{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

impl std::fmt::Debug for Proxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Proxy::Env => write!(f, "Env"),
            Proxy::Direct => write!(f, "Direct"),
            Proxy::Url(u) => write!(f, "Url({:?})", without_userinfo(u)),          // (a proxy's password is never shown)
        }
    }
}

/// One request and its caller's rule.
#[derive(Clone)]
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
    /// A document: ask for `gzip` and `deflate` and decode the body (see the module's documentation). Never for a
    /// download, whose bytes are checked as they were published.
    pub decompress: bool,
    /// The credentials the hops may get (see [`Credential`]); none in `headers`.
    pub credentials: Vec<Credential>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // (no user:password of a URL, no credential's value, a body's length only)
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("url", &without_userinfo(&self.url))
            .field("headers", &self.headers)
            .field("body", &format_args!("{} bytes", self.body.len()))
            .field("hosts", &self.hosts)
            .field("any_host", &self.any_host)
            .field("max_bytes", &self.max_bytes)
            .field("timeout", &self.timeout)
            .field("total_timeout", &self.total_timeout)
            .field("max_redirects", &self.max_redirects)
            .field("proxy", &self.proxy)
            .field("http2", &self.http2)
            .field("decompress", &self.decompress)
            .field("credentials", &self.credentials)
            .finish()
    }
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
            decompress: false,
            credentials: Vec::new(),
        }
    }
}

/// A response read whole.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    /// "HTTP/2" or "HTTP/1.1".
    pub version: String,
    /// The TLS version the response came over: "TLS 1.3" or "TLS 1.2" (None: not over TLS).
    pub tls: Option<String>,
    pub headers: Vec<(String, String)>,
    /// The URL that answered, after redirects.
    pub url: String,
    /// The body came compressed and was decoded (a document's: [`Request::decompress`]); its `Content-Encoding` and
    /// `Content-Length` are gone from `headers`, since they described the bytes on the wire.
    pub decoded: bool,
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

/// Where the hops of one request went: the host of the last one the client was about to send (as a Host header writes
/// it), which a TLS failure is of.
#[derive(Default)]
struct Hops {
    last: Mutex<Option<String>>,
}

impl Hops {
    /// The failure, with the host of its hop when it is a [`Failure::TlsVersion`].
    fn of(&self, failure: Failure) -> Failure {
        match failure {
            Failure::TlsVersion { message, host: None } => {
                Failure::TlsVersion { message, host: self.last.lock().unwrap_or_else(|p| p.into_inner()).clone() }
            }
            other => other,
        }
    }
}

fn client_for(req: &Request, hops: &Arc<Hops>) -> Result<Client, Failure> {
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
    if req.decompress {
        // a document: asked for compressed, decoded within the caller's budget and the ratio (this request only)
        client = client.decompress(true).max_decoded_bytes(req.max_bytes).max_decode_ratio(MAX_DECODE_RATIO, DECODE_RATIO_FLOOR);
    }
    for c in &req.credentials {
        if !valid_credential(c) {
            // (the host and the header's name, never its value)
            return Err(Failure::Setup(format!("a credential ({:?} for {:?}) is not one that can be sent", c.name, c.host)));
        }
    }
    // (every request has a hook of its own: the shared client's clones carry none of an earlier request's)
    let credentials = Arc::new(req.credentials.clone());
    let hops = hops.clone();
    client = client.hop_headers(move |info| {
        *hops.last.lock().unwrap_or_else(|p| p.into_inner()) = Some(info.url.host_header());
        Ok(granted(&credentials, info))
    });
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
        if CREDENTIAL_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name))
            || req.credentials.iter().any(|c| c.name.eq_ignore_ascii_case(name))
        {
            // a header of the request goes with every hop it may take; a credential goes with its own host's alone
            return Err(Failure::Setup(format!("header {name:?} carries a credential: the request gives it as one")));
        }
        if !PLAIN_HEADERS.iter().any(|h| h.eq_ignore_ascii_case(name)) {
            return Err(Failure::Setup(format!("header {name:?} is not one a request sets (a credential goes as one)")));
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
    let hops = Arc::new(Hops::default());
    let client = client_for(req, &hops)?;
    prepared(&client, req, &method)?.send_stream().map_err(|e| hops.of(classify(e)))
}

/// A credential that can be sent: a header that can be, and not one the client sets itself; a host as a Host header
/// writes it (lower case); a path prefix that ends in `/`.
fn valid_credential(c: &Credential) -> bool {
    valid_header(&c.name, &c.value)
        && !["host", "connection", "content-length", "transfer-encoding"].iter().any(|h| h.eq_ignore_ascii_case(&c.name))
        && !c.host.is_empty()
        && c.host.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-_[]:".contains(&b))
        && c.path.starts_with('/')
        && c.path.ends_with('/')
        && c.path.bytes().all(|b| (0x21..=0x7e).contains(&b) && b != b'?' && b != b'#')
}

/// A field name of token characters and a value of visible ASCII and spaces: nothing that could end the head.
fn valid_header(name: &str, value: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        && value.len() <= 8192
        && value.bytes().all(|b| b == b' ' || b == b'\t' || (0x21..=0x7e).contains(&b))
}

fn reply_head(s: &ResponseStream) -> (u16, String, Option<String>, Vec<(String, String)>, String, bool) {
    (s.status, s.version.to_string(), s.tls_version.map(|v| v.to_string()), s.headers.clone(), s.url.to_string(), s.uncompressed)
}

/// Sends `req` and reads the whole body (at most `max_bytes`: the client's limit, which a declared length over it
/// fails at once). Read whole, an HTTP/2 body is kept as it comes and its flow-control credit goes back as it arrives,
/// with no copy more (tiny_https's `send`).
pub fn fetch(req: &Request) -> Result<Reply, Failure> {
    let method = method_of(req)?;
    let hops = Arc::new(Hops::default());
    let client = client_for(req, &hops)?;
    let resp = prepared(&client, req, &method)?.send().map_err(|e| hops.of(classify(e)))?;
    if resp.body.len() as u64 > req.max_bytes {
        return Err(Failure::TooLarge);
    }
    Ok(Reply { status: resp.status, version: resp.version.to_string(), tls: resp.tls_version.map(|v| v.to_string()),
               headers: resp.headers, url: resp.url.to_string(), decoded: resp.uncompressed, body: resp.body })
}

/// A response whose body is read in pieces (a download spooled to a file, a stream handed on).
pub struct Stream {
    pub status: u16,
    pub version: String,
    /// The TLS version the response comes over (as [`Reply::tls`]).
    pub tls: Option<String>,
    pub headers: Vec<(String, String)>,
    pub url: String,
    /// The body is decoded as it is read (as [`Reply::decoded`]).
    pub decoded: bool,
    inner: ResponseStream,
    read: u64,
    limit: u64,
}

impl Stream {
    /// The next bytes of the body into `buf` (0 at its end). Over the budget is [`Failure::TooLarge`], decoded or not.
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
    let (status, version, tls, headers, url, decoded) = reply_head(&inner);
    Ok(Stream { status, version, tls, headers, url, decoded, inner, read: 0, limit: req.max_bytes })
}

#[cfg(test)]
mod tests;
