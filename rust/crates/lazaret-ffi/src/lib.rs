//! The C ABI of Lazaret's native engine and of its network layer: the only
//! `unsafe` code of Lazaret's own, and all of it in this file (tiny_https,
//! taken into rust/crates as it was handed over, has its own: its SIMD
//! kernels, randomness and the wiping of secrets).
//!
//! One call carries everything: a request buffer
//!
//! ```text
//! [u32 LE name length][name, UTF-8][u32 LE args length][args, JSON][text]
//! ```
//!
//! where the text is the rest of the buffer, a Python str encoded as UTF-8
//! with surrogates passed through (Python: `s.encode("utf-8",
//! "surrogatepass")`; the npm package writes the same from a JS string, lone
//! surrogates included). The answer is JSON (ASCII) in a buffer the engine
//! allocates and the caller hands back to `lazaret_engine_free`.
//!
//! Native builds export `lazaret_engine_call`, read by Python's ctypes
//! (lazaret/scanner/_native.py), and the network layer's calls
//! (`lazaret_net_request`, `_open`, `_read`, `_close`, `_configure`: see
//! [`net`]), which only the native library has; its `lazaret_engine_call`
//! also answers the `verify.*` calls ([`verify`]: the Go checksum database's
//! check and npm's and PyPI's attestations, on tiny_https's pure part).
//! WebAssembly builds (wasm32-unknown-unknown,
//! loaded by Node's built-in WebAssembly: js/src/lib/native.js) export
//! `lazaret_alloc`, `lazaret_call` and `lazaret_free` instead, the same
//! request and answer in the module's memory. A panic never crosses the
//! boundary: it is caught and reported as status 3.

use lazaret_engine::api::{self, CallError};
use lazaret_engine::json::{self, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub const STATUS_OK: i32 = 0;
pub const STATUS_ERROR: i32 = 1;
pub const STATUS_EXHAUSTED: i32 = 2;
pub const STATUS_PANIC: i32 = 3;

/// UTF-8 with surrogates passed through (CPython's "surrogatepass"): the
/// code points of a Python str. None for bytes no such encoder writes.
pub fn decode_wtf8(b: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as u32;
        if c < 0x80 {
            out.push(c);
            i += 1;
            continue;
        }
        let (n, min, init) = if c & 0xE0 == 0xC0 {
            (1, 0x80, c & 0x1F)
        } else if c & 0xF0 == 0xE0 {
            (2, 0x800, c & 0x0F)
        } else if c & 0xF8 == 0xF0 {
            (3, 0x10000, c & 0x07)
        } else {
            return None;
        };
        let mut v = init;
        for k in 1..=n {
            let x = *b.get(i + k)? as u32;
            if x & 0xC0 != 0x80 {
                return None;
            }
            v = (v << 6) | (x & 0x3F);
        }
        if v < min || v > 0x10FFFF {
            return None;
        }
        out.push(v);
        i += n + 1;
    }
    Some(out)
}

fn read_u32(b: &[u8], at: usize) -> Option<usize> {
    let w = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([w[0], w[1], w[2], w[3]]) as usize)
}

/// Run one request: (status, JSON answer).
pub fn handle(req: &[u8]) -> (i32, String) {
    let r = catch_unwind(AssertUnwindSafe(|| handle_inner(req)));
    match r {
        Ok(v) => v,
        Err(_) => (STATUS_PANIC, json::write(&Value::obj(vec![("error", Value::str("panic in the native engine"))]))),
    }
}

fn error(status: i32, msg: &str) -> (i32, String) {
    (status, json::write(&Value::obj(vec![("error", Value::str(msg))])))
}

fn handle_inner(req: &[u8]) -> (i32, String) {
    let parsed = (|| {
        let nlen = read_u32(req, 0)?;
        let name = std::str::from_utf8(req.get(4..4 + nlen)?).ok()?;
        let alen = read_u32(req, 4 + nlen)?;
        let astart = 8 + nlen;
        let args = std::str::from_utf8(req.get(astart..astart + alen)?).ok()?;
        let text = req.get(astart + alen..)?;
        Some((name, args, text))
    })();
    let (name, args, text) = match parsed {
        Some(p) => p,
        None => return error(STATUS_ERROR, "malformed request"),
    };
    let args = if args.is_empty() {
        Value::Obj(Vec::new())
    } else {
        match json::parse_str(args) {
            Ok(v) => v,
            Err(e) => return error(STATUS_ERROR, &format!("bad arguments: {}", e.0)),
        }
    };
    let text = match decode_wtf8(text) {
        Some(t) => t,
        None => return error(STATUS_ERROR, "text is not UTF-8"),
    };
    #[cfg(not(target_arch = "wasm32"))]
    if let Some(answer) = verify::call(name, &args) {
        return answer;
    }
    match api::call_owned(name, &args, text) {
        Ok(v) => (STATUS_OK, json::write(&v)),
        Err(CallError::Exhausted) => error(STATUS_EXHAUSTED, "work budget spent"),
        Err(CallError::Unknown(n)) => error(STATUS_ERROR, &format!("unknown call {}", n)),
        Err(CallError::BadArgs(m)) => error(STATUS_ERROR, &m),
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use super::*;

    /// The engine's version, NUL-terminated (static).
    #[no_mangle]
    pub extern "C" fn lazaret_engine_version() -> *const u8 {
        concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr()
    }

    /// Run one request (see the module docs). The answer is written to
    /// `*out` / `*out_len`, to be released with `lazaret_engine_free`.
    ///
    /// # Safety
    /// `req` points to `req_len` readable bytes; `out` and `out_len` are
    /// writable.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_engine_call(
        req: *const u8,
        req_len: usize,
        out: *mut *mut u8,
        out_len: *mut usize,
    ) -> i32 {
        if req.is_null() || out.is_null() || out_len.is_null() {
            return STATUS_ERROR;
        }
        let request = std::slice::from_raw_parts(req, req_len);
        let (status, answer) = handle(request);
        let boxed: Box<[u8]> = answer.into_bytes().into_boxed_slice();
        let len = boxed.len();
        *out = Box::into_raw(boxed) as *mut u8;
        *out_len = len;
        status
    }

    /// Release an answer of `lazaret_engine_call`.
    ///
    /// # Safety
    /// `p` and `len` are exactly what `lazaret_engine_call` wrote.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_engine_free(p: *mut u8, len: usize) {
        if !p.is_null() {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)));
        }
    }
}

/// The network layer's C ABI (NET-1), native builds only: Lazaret's requests to registries, feeds and APIs over
/// tiny_https (`lazaret-net`), read by the Python package (lazaret/registry/nativenet.py).
///
/// A request is JSON, with its body (a POST's) apart:
///
/// ```text
/// {"method": "GET", "url": "https://…", "headers": [["Accept", "…"], …], "hosts": ["registry.npmjs.org", …],
///  "max_bytes": 5242880, "timeout_ms": 30000, "total_timeout_ms": null, "max_redirects": 3,
///  "proxy": "env" | "direct" | "http://host:port", "http2": true, "any_host": false,
///  "credentials": [{"host": "api.github.com", "path": "/", "name": "Authorization", "value": "…", "first": false}, …]}
/// ```
///
/// A credential goes to the hops to its own host only (lazaret_net::Credential: tiny_https's hop hook), never as a
/// header a redirect could carry on.
///
/// The answer is JSON too, in a buffer the library allocates: `{"status": 200, "version": "HTTP/2", "headers":
/// [[name, value], …], "url": "…"}` with the body in a second buffer (status 0), or `{"kind": "refused" |
/// "too-large" | "tls-version" | "tls" | "timeout" | "network" | "http" | "setup", "error": "…"}` (status 1), and for
/// "tls-version" `"host"`, the host of the hop that offered no TLS 1.3 (a redirect's, when it was one). Every buffer
/// goes back to `lazaret_engine_free`. A panic never crosses the boundary (status 3).
#[cfg(not(target_arch = "wasm32"))]
pub mod net {
    use super::*;
    use lazaret_net::{Credential, Failure, Proxy, Request, Stream};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn text(v: Option<&Value>, what: &str) -> Result<String, String> {
        v.and_then(Value::as_string).ok_or_else(|| format!("the request has no {what}"))
    }

    fn millis(v: Option<&Value>, what: &str) -> Result<Option<Duration>, String> {
        match v {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Int(n)) if *n > 0 && *n <= 86_400_000 => Ok(Some(Duration::from_millis(*n as u64))),
            _ => Err(format!("the request's {what} is not a number of milliseconds")),
        }
    }

    /// The request a JSON description and a body make.
    pub fn request_of(spec: &Value, body: &[u8]) -> Result<Request, String> {
        let pairs = |key: &str| -> Result<Vec<(String, String)>, String> {
            let mut out = Vec::new();
            for item in spec.get(key).and_then(Value::as_arr).unwrap_or(&[]) {
                match item.as_arr() {
                    Some([n, v]) => out.push((text(Some(n), "header name")?, text(Some(v), "header value")?)),
                    _ => return Err(format!("the request's {key} are not pairs")),
                }
            }
            Ok(out)
        };
        let hosts = spec.get("hosts").and_then(Value::as_arr).unwrap_or(&[])
            .iter().map(|h| text(Some(h), "host")).collect::<Result<Vec<_>, _>>()?;
        let proxy = match spec.get("proxy") {
            None | Some(Value::Null) => Proxy::Env,
            Some(v) => match text(Some(v), "proxy")?.as_str() {
                "env" => Proxy::Env,
                "direct" => Proxy::Direct,
                url => Proxy::Url(url.to_string()),
            },
        };
        let max_bytes = spec.get("max_bytes").and_then(Value::as_i64).filter(|n| *n >= 0)
            .ok_or("the request has no byte budget")? as u64;
        let max_redirects = spec.get("max_redirects").and_then(Value::as_i64).filter(|n| (0..=10).contains(n)).unwrap_or(3) as usize;
        let listed = match spec.get("credentials") {
            None | Some(Value::Null) => &[][..],
            Some(v) => v.as_arr().ok_or("the request's credentials are not a list")?,
        };
        let mut credentials = Vec::new();
        for item in listed {
            credentials.push(Credential {
                host: text(item.get("host"), "credential's host")?,
                path: text(item.get("path"), "credential's path")?,
                name: text(item.get("name"), "credential's name")?,
                value: text(item.get("value"), "credential's value")?,
                first_only: matches!(item.get("first"), Some(Value::Bool(true))),
            });
        }
        Ok(Request {
            method: text(spec.get("method"), "method")?,
            url: text(spec.get("url"), "URL")?,
            headers: pairs("headers")?,
            body: body.to_vec(),
            hosts,
            any_host: matches!(spec.get("any_host"), Some(Value::Bool(true))),
            max_bytes,
            timeout: millis(spec.get("timeout_ms"), "timeout")?.unwrap_or(Duration::from_secs(30)),
            total_timeout: millis(spec.get("total_timeout_ms"), "total timeout")?,
            max_redirects,
            proxy,
            http2: !matches!(spec.get("http2"), Some(Value::Bool(false))),
            credentials,
        })
    }

    pub fn failure(f: &Failure) -> String {
        let mut fields = vec![("kind", Value::str(f.kind())), ("error", Value::str(&f.message()))];
        if let Some(host) = f.host() {
            fields.push(("host", Value::str(host)));       // (the hop that offered no TLS 1.3)
        }
        json::write(&Value::obj(fields))
    }

    fn head(status: u16, version: &str, headers: &[(String, String)], url: &str) -> String {
        let headers = headers.iter().map(|(n, v)| Value::Arr(vec![Value::str(n), Value::str(v)])).collect();
        json::write(&Value::obj(vec![("status", Value::Int(status as i64)), ("version", Value::str(version)),
                                     ("headers", Value::Arr(headers)), ("url", Value::str(url))]))
    }

    /// (status, answer, body) for one request description.
    pub fn handle_request(spec: &[u8], body: &[u8]) -> (i32, String, Vec<u8>) {
        let r = catch_unwind(AssertUnwindSafe(|| {
            let spec = match std::str::from_utf8(spec).ok().map(json::parse_str) {
                Some(Ok(v)) => v,
                _ => return (STATUS_ERROR, failure(&Failure::Setup("the request is not JSON".into())), Vec::new()),
            };
            let req = match request_of(&spec, body) {
                Ok(r) => r,
                Err(m) => return (STATUS_ERROR, failure(&Failure::Setup(m)), Vec::new()),
            };
            match lazaret_net::fetch(&req) {
                Ok(reply) => (STATUS_OK, head(reply.status, &reply.version, &reply.headers, &reply.url), reply.body),
                Err(f) => (STATUS_ERROR, failure(&f), Vec::new()),
            }
        }));
        r.unwrap_or_else(|_| (STATUS_PANIC, failure(&Failure::Setup("panic in the network layer".into())), Vec::new()))
    }

    static STREAMS: Mutex<Option<HashMap<u64, Arc<Mutex<Stream>>>>> = Mutex::new(None);
    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn streams() -> std::sync::MutexGuard<'static, Option<HashMap<u64, Arc<Mutex<Stream>>>>> {
        STREAMS.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// (status, answer, handle) for a request whose body is read in pieces.
    pub fn handle_open(spec: &[u8], body: &[u8]) -> (i32, String, u64) {
        let r = catch_unwind(AssertUnwindSafe(|| {
            let spec = match std::str::from_utf8(spec).ok().map(json::parse_str) {
                Some(Ok(v)) => v,
                _ => return (STATUS_ERROR, failure(&Failure::Setup("the request is not JSON".into())), 0),
            };
            let req = match request_of(&spec, body) {
                Ok(r) => r,
                Err(m) => return (STATUS_ERROR, failure(&Failure::Setup(m)), 0),
            };
            match lazaret_net::open(&req) {
                Ok(stream) => {
                    let answer = head(stream.status, &stream.version, &stream.headers, &stream.url);
                    let id = NEXT.fetch_add(1, Ordering::Relaxed);
                    streams().get_or_insert_with(HashMap::new).insert(id, Arc::new(Mutex::new(stream)));
                    (STATUS_OK, answer, id)
                }
                Err(f) => (STATUS_ERROR, failure(&f), 0),
            }
        }));
        r.unwrap_or_else(|_| (STATUS_PANIC, failure(&Failure::Setup("panic in the network layer".into())), 0))
    }

    /// (status, bytes read, answer on failure) for the next piece of a stream's body.
    pub fn handle_read(id: u64, buf: &mut [u8]) -> (i32, usize, String) {
        let stream = streams().as_ref().and_then(|m| m.get(&id).cloned());
        let Some(stream) = stream else {
            return (STATUS_ERROR, 0, failure(&Failure::Setup("no such stream".into())));
        };
        let r = catch_unwind(AssertUnwindSafe(|| stream.lock().unwrap_or_else(|p| p.into_inner()).read(buf)));
        match r {
            Ok(Ok(n)) => (STATUS_OK, n, String::new()),
            Ok(Err(f)) => (STATUS_ERROR, 0, failure(&f)),
            Err(_) => (STATUS_PANIC, 0, failure(&Failure::Setup("panic in the network layer".into()))),
        }
    }

    pub fn handle_close(id: u64) {
        let stream = streams().as_mut().and_then(|m| m.remove(&id));
        drop(stream);
    }

    pub fn handle_configure(roots: &[u8]) -> (i32, String) {
        let r = catch_unwind(AssertUnwindSafe(|| {
            let pem = if roots.is_empty() { None } else { std::str::from_utf8(roots).ok() };
            if !roots.is_empty() && pem.is_none() {
                return (STATUS_ERROR, failure(&Failure::Setup("the trust anchors are not PEM text".into())));
            }
            match lazaret_net::configure(pem) {
                Ok(()) => (STATUS_OK, "{}".to_string()),
                Err(f) => (STATUS_ERROR, failure(&f)),
            }
        }));
        r.unwrap_or_else(|_| (STATUS_PANIC, failure(&Failure::Setup("panic in the network layer".into()))))
    }

    /// # Safety
    /// `p` is null or points to `len` readable bytes.
    unsafe fn bytes<'a>(p: *const u8, len: usize) -> &'a [u8] {
        if p.is_null() || len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(p, len)
        }
    }

    /// # Safety
    /// `out` and `out_len` are writable.
    unsafe fn give(data: Vec<u8>, out: *mut *mut u8, out_len: *mut usize) {
        let boxed: Box<[u8]> = data.into_boxed_slice();
        *out_len = boxed.len();
        *out = Box::into_raw(boxed) as *mut u8;
    }

    /// One request, its body read whole: the answer in `*meta`, the response body in `*body`.
    ///
    /// # Safety
    /// `spec` points to `spec_len` readable bytes, `req_body` to `req_body_len` (or is null); the four out
    /// pointers are writable.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_net_request(spec: *const u8, spec_len: usize, req_body: *const u8, req_body_len: usize,
                                                 meta: *mut *mut u8, meta_len: *mut usize, body: *mut *mut u8,
                                                 body_len: *mut usize) -> i32 {
        if spec.is_null() || meta.is_null() || meta_len.is_null() || body.is_null() || body_len.is_null() {
            return STATUS_ERROR;
        }
        let (status, answer, data) = handle_request(bytes(spec, spec_len), bytes(req_body, req_body_len));
        give(answer.into_bytes(), meta, meta_len);
        give(data, body, body_len);
        status
    }

    /// A request whose body is read with `lazaret_net_read`: the answer (the head) in `*meta`, the stream's
    /// handle in `*handle`, to be given back to `lazaret_net_close`.
    ///
    /// # Safety
    /// As `lazaret_net_request`; `handle` is writable.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_net_open(spec: *const u8, spec_len: usize, req_body: *const u8, req_body_len: usize,
                                              meta: *mut *mut u8, meta_len: *mut usize, handle: *mut u64) -> i32 {
        if spec.is_null() || meta.is_null() || meta_len.is_null() || handle.is_null() {
            return STATUS_ERROR;
        }
        let (status, answer, id) = handle_open(bytes(spec, spec_len), bytes(req_body, req_body_len));
        give(answer.into_bytes(), meta, meta_len);
        *handle = id;
        status
    }

    /// The next bytes of a stream's body into `buf` (`*n` of them; 0 at its end). On failure (status 1) the
    /// answer is in `*meta`; on success `*meta` is null.
    ///
    /// # Safety
    /// `buf` points to `cap` writable bytes; `n`, `meta` and `meta_len` are writable.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_net_read(handle: u64, buf: *mut u8, cap: usize, n: *mut usize, meta: *mut *mut u8,
                                              meta_len: *mut usize) -> i32 {
        if buf.is_null() || n.is_null() || meta.is_null() || meta_len.is_null() {
            return STATUS_ERROR;
        }
        let out = std::slice::from_raw_parts_mut(buf, cap);
        let (status, got, answer) = handle_read(handle, out);
        *n = got;
        if answer.is_empty() {
            *meta = std::ptr::null_mut();
            *meta_len = 0;
        } else {
            give(answer.into_bytes(), meta, meta_len);
        }
        status
    }

    /// Ends a stream (its connection is closed unless its body was read to the end).
    #[no_mangle]
    pub extern "C" fn lazaret_net_close(handle: u64) {
        let _ = catch_unwind(|| handle_close(handle));
    }

    /// The trust anchors for the requests from now on: PEM text, or nothing for the system's CA bundle. The
    /// answer in `*meta`.
    ///
    /// # Safety
    /// `roots` points to `roots_len` readable bytes (or is null); `meta` and `meta_len` are writable.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_net_configure(roots: *const u8, roots_len: usize, meta: *mut *mut u8,
                                                   meta_len: *mut usize) -> i32 {
        if meta.is_null() || meta_len.is_null() {
            return STATUS_ERROR;
        }
        let (status, answer) = handle_configure(bytes(roots, roots_len));
        give(answer.into_bytes(), meta, meta_len);
        status
    }
}

/// The calls the native library answers itself, over tiny_https's pure part (`lazaret-verify`), before the engine's:
/// `verify.go_sumdb` checks the Go checksum database's answer for a module (NET-1; lazaret/registry/ecosystems/golang.py),
/// and `verify.sigstore` npm's or PyPI's attestations of a file (NET-1's provenance; lazaret/registry/provenance.py).
///
/// ```text
/// {"module": "golang.org/x/mod", "version": "v0.17.0", "key": "sum.golang.org+033de0ae+…", "lookup": "<the body of
///  /lookup/…>", "head": null | "<a signed tree head kept from before>", "tiles": null | {"tile/8/0/…": "<base64>", …}}
/// ```
///
/// Without `tiles` the answer names those to fetch, `{"needed": [{"path", "full", "len", "full_len"}, …]}`; with them,
/// `{"verified": true, "lines": [the record's lines for the module's files], "record": "<the whole record>", "id": n,
/// "size": n, "latest": "<the newest signed tree head>"}`, or an error (status 1) when anything does not hold.
#[cfg(not(target_arch = "wasm32"))]
pub mod verify {
    use super::*;
    use lazaret_verify::{gosum, pem};

    pub fn call(name: &str, args: &Value) -> Option<(i32, String)> {
        let run: fn(&Value) -> Result<Value, String> = match name {
            "verify.go_sumdb" => go_sumdb,
            "verify.sigstore" => sigstore,
            _ => return None,
        };
        let r = catch_unwind(AssertUnwindSafe(|| run(args)));
        Some(match r {
            Ok(Ok(v)) => (STATUS_OK, json::write(&v)),
            Ok(Err(m)) => error(STATUS_ERROR, &m),
            Err(_) => error(STATUS_PANIC, &format!("panic in {name}")),
        })
    }

    fn text(args: &Value, key: &str) -> Result<String, String> {
        args.get(key).and_then(Value::as_string).ok_or_else(|| format!("needs {key}"))
    }

    fn opt_str(v: &Option<String>) -> Value {
        v.as_deref().map_or(Value::Null, Value::str)
    }

    /// Lower-case or upper-case hex, nothing else.
    fn unhex(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 != 0 {
            return None;
        }
        s.as_bytes().chunks(2).map(|p| Some(((p[0] as char).to_digit(16)? * 16 + (p[1] as char).to_digit(16)?) as u8)).collect()
    }

    /// `verify.sigstore`: npm's or PyPI's attestations of one file (NET-1's provenance findings).
    ///
    /// ```text
    /// {"registry": "npm" | "pypi", "document": "<the registry's answer>", "digest": "<hex: the tarball's SHA-512,
    ///  or the file's SHA-256>", "root": "<Sigstore's trusted_root.json>", "npm_keys": null | "<npm's key list>"}
    /// ```
    ///
    /// -> `{"attestations": [{"predicateType", "outcome": "verified" | "invalid" | "unchecked", "reason",
    /// "signer": {"kind": "certificate", "issuer", "repository", "repositoryId", "owner", "ownerId", "workflow",
    /// "ref", "commit", "runner", "trigger", "names"} | {"kind": "key", "id"}, "time", "format"}, …]}`; an error
    /// (status 1) when the document is not attestations or the trust cannot be read.
    fn sigstore(args: &Value) -> Result<Value, String> {
        use lazaret_verify::provenance::{self, Outcome, Registry, Who};
        let registry = match text(args, "registry")?.as_str() {
            "npm" => Registry::Npm,
            "pypi" => Registry::PyPI,
            other => return Err(format!("no registry {other:?}")),
        };
        let (document, root) = (text(args, "document")?, text(args, "root")?);
        let digest = unhex(&text(args, "digest")?).ok_or("the digest is not hex")?;
        let keys = match args.get("npm_keys") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_string().ok_or("npm_keys is not text")?),
        };
        let (root, ring) = provenance::trust(root.as_bytes(), keys.as_deref().map(str::as_bytes))?;
        let checked = provenance::check(registry, document.as_bytes(), &digest, &root, &ring)?;
        let list = checked.into_iter().map(|c| {
            let mut fields = vec![("predicateType", Value::str(&c.predicate_type))];
            match c.outcome {
                Outcome::Verified { who, time, format } => {
                    let signer = match who {
                        Who::Certificate { issuer, repository, repository_id, owner, owner_id, workflow, git_ref, commit,
                                           runner, trigger, names } => Value::obj(vec![
                            ("kind", Value::str("certificate")), ("issuer", opt_str(&issuer)),
                            ("repository", opt_str(&repository)), ("repositoryId", opt_str(&repository_id)),
                            ("owner", opt_str(&owner)), ("ownerId", opt_str(&owner_id)), ("workflow", opt_str(&workflow)),
                            ("ref", opt_str(&git_ref)), ("commit", opt_str(&commit)), ("runner", opt_str(&runner)),
                            ("trigger", opt_str(&trigger)),
                            ("names", Value::Arr(names.iter().map(|n| Value::str(n)).collect())),
                        ]),
                        Who::Key { id } => Value::obj(vec![("kind", Value::str("key")), ("id", Value::str(&id))]),
                    };
                    fields.extend([("outcome", Value::str("verified")), ("signer", signer), ("time", Value::Int(time)),
                                   ("format", Value::str(format))]);
                }
                Outcome::Invalid(reason) => fields.extend([("outcome", Value::str("invalid")), ("reason", Value::str(&reason))]),
                Outcome::Unchecked(reason) => fields.extend([("outcome", Value::str("unchecked")), ("reason", Value::str(&reason))]),
            }
            Value::obj(fields)
        }).collect();
        Ok(Value::obj(vec![("attestations", Value::Arr(list))]))
    }

    fn go_sumdb(args: &Value) -> Result<Value, String> {
        let (module, version, key, lookup) = (text(args, "module")?, text(args, "version")?, text(args, "key")?,
                                              text(args, "lookup")?);
        let head = match args.get("head") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_string().ok_or("verify.go_sumdb: head is not text")?),
        };
        let head = head.as_ref().map(|h| h.as_bytes());
        let tiles = match args.get("tiles") {
            None | Some(Value::Null) => None,
            Some(Value::Obj(items)) => {
                let mut out = Vec::new();
                for (path, data) in items {
                    let path = lazaret_engine::pystr::to_string(path);
                    let b64 = data.as_string().ok_or_else(|| format!("tile {path} is not base64 text"))?;
                    let bytes = pem::base64_decode_strict(&b64).ok_or_else(|| format!("tile {path} is not base64"))?;
                    out.push((path, bytes));
                }
                Some(out)
            }
            Some(_) => return Err("verify.go_sumdb: tiles is not an object".into()),
        };
        match tiles {
            None => {
                let needed = gosum::tiles_needed(&key, head, &module, &version, lookup.as_bytes())?;
                let list = needed.iter().map(|t| Value::obj(vec![
                    ("path", Value::str(&t.path)), ("full", Value::str(&t.full_path)),
                    ("len", Value::Int(t.len as i64)), ("full_len", Value::Int(t.full_len as i64)),
                ])).collect();
                Ok(Value::obj(vec![("needed", Value::Arr(list))]))
            }
            Some(tiles) => {
                let v = gosum::verify(&key, head, &module, &version, lookup.as_bytes(), &tiles)?;
                Ok(Value::obj(vec![
                    ("verified", Value::Bool(true)),
                    ("lines", Value::Arr(v.lines.iter().map(|l| Value::str(l)).collect())),
                    ("record", Value::str(&v.record)),
                    ("id", Value::Int(v.id as i64)),
                    ("size", Value::Int(v.size as i64)),
                    ("latest", Value::str(&String::from_utf8_lossy(&v.latest_note))),
                ]))
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;

    /// Room for a request of `len` bytes in the module's memory.
    #[no_mangle]
    pub extern "C" fn lazaret_alloc(len: usize) -> *mut u8 {
        let boxed: Box<[u8]> = vec![0u8; len].into_boxed_slice();
        Box::into_raw(boxed) as *mut u8
    }

    /// Release a buffer of `lazaret_alloc` or `lazaret_call`.
    ///
    /// # Safety
    /// `p` and `len` are a buffer this module handed out.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_free(p: *mut u8, len: usize) {
        if !p.is_null() {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)));
        }
    }

    /// Run the request at `req` (`len` bytes, from `lazaret_alloc`; freed
    /// here). Returns a buffer: [u32 LE status][u32 LE length][answer],
    /// released with `lazaret_free(ptr, 8 + length)`.
    ///
    /// # Safety
    /// `req` and `len` are a buffer of `lazaret_alloc`.
    #[no_mangle]
    pub unsafe extern "C" fn lazaret_call(req: *mut u8, len: usize) -> *mut u8 {
        let request: Box<[u8]> = Box::from_raw(std::ptr::slice_from_raw_parts_mut(req, len));
        let (status, answer) = handle(&request);
        drop(request);
        let mut buf = Vec::with_capacity(8 + answer.len());
        buf.extend_from_slice(&(status as u32).to_le_bytes());
        buf.extend_from_slice(&(answer.len() as u32).to_le_bytes());
        buf.extend_from_slice(answer.as_bytes());
        Box::into_raw(buf.into_boxed_slice()) as *mut u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, args: &str, text: &[u8]) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&(name.len() as u32).to_le_bytes());
        r.extend_from_slice(name.as_bytes());
        r.extend_from_slice(&(args.len() as u32).to_le_bytes());
        r.extend_from_slice(args.as_bytes());
        r.extend_from_slice(text);
        r
    }

    #[test]
    fn wtf8() {
        assert_eq!(decode_wtf8("a\u{e9}\u{1F600}".as_bytes()), Some(vec![0x61, 0xE9, 0x1F600]));
        assert_eq!(decode_wtf8(&[0xED, 0xA0, 0x80]), Some(vec![0xD800]));
        assert_eq!(decode_wtf8(&[0xC0, 0x80]), None);
        assert_eq!(decode_wtf8(&[0xE2, 0x82]), None);
    }

    #[test]
    fn calls() {
        let (s, a) = handle(&request("version", "", b""));
        assert_eq!(s, STATUS_OK);
        assert!(a.contains("\"rust\""));
        let (s, _) = handle(&request("nope", "{}", b""));
        assert_eq!(s, STATUS_ERROR);
        let (s, _) = handle(b"\xff\xff\xff\xff");
        assert_eq!(s, STATUS_ERROR);
    }

    /// `verify.go_sumdb` (native only), on tiny_https's capture of the real sum.golang.org (its
    /// tests/data/sumdb/README.txt): the lookup of golang.org/x/mod@v0.17.0, an older head and the seven tiles.
    #[cfg(not(target_arch = "wasm32"))]
    mod go_sumdb {
        use super::*;

        const LOOKUP: &str = include_str!("../../tiny_https/tests/data/sumdb/lookup.txt");
        const LATEST: &str = include_str!("../../tiny_https/tests/data/sumdb/latest.txt");
        const TILES: [(&str, &[u8]); 7] = [
            ("tile/8/0/x097/482", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/0/x097/482")),
            ("tile/8/0/x260/730.p/101", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/0/x260/730.p/101")),
            ("tile/8/1/380", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/1/380")),
            ("tile/8/1/x001/018.p/122", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/1/x001/018.p/122")),
            ("tile/8/2/001", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/2/001")),
            ("tile/8/2/003.p/250", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/2/003.p/250")),
            ("tile/8/3/000.p/3", include_bytes!("../../tiny_https/tests/data/sumdb/tile/8/3/000.p/3")),
        ];
        const KEY: &str = "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";

        fn go_sumdb(head: Option<&str>, tiles: Option<Vec<(&str, Vec<u8>)>>) -> (i32, Value) {
            let mut args = vec![("module", Value::str("golang.org/x/mod")), ("version", Value::str("v0.17.0")),
                                ("key", Value::str(KEY)), ("lookup", Value::str(LOOKUP)),
                                ("head", head.map_or(Value::Null, Value::str))];
            if let Some(tiles) = tiles {
                let items = tiles.iter().map(|(p, d)| (*p, Value::str(&lazaret_verify::pem::base64_encode(d)))).collect();
                args.push(("tiles", Value::obj(items)));
            }
            let (s, a) = handle(&request("verify.go_sumdb", &json::write(&Value::obj(args)), b""));
            (s, json::parse_str(&a).unwrap())
        }

        #[test]
        fn the_checksum_database_check_names_the_tiles_then_vouches_for_the_record() {
            let (s, a) = go_sumdb(Some(LATEST), None);
            assert_eq!(s, STATUS_OK, "{}", json::write(&a));
            let mut named: Vec<String> = a.get("needed").and_then(Value::as_arr).unwrap().iter()
                .map(|t| t.get("path").and_then(Value::as_string).unwrap()).collect();
            named.sort();
            let mut want: Vec<String> = TILES.iter().map(|(p, _)| p.to_string()).collect();
            want.sort();
            assert_eq!(named, want);
            let (s, a) = go_sumdb(Some(LATEST), Some(TILES.iter().map(|(p, d)| (*p, d.to_vec())).collect()));
            assert_eq!(s, STATUS_OK, "{}", json::write(&a));
            assert_eq!(a.get("verified"), Some(&Value::Bool(true)));
            let lines: Vec<String> = a.get("lines").and_then(Value::as_arr).unwrap().iter()
                .map(|l| l.as_string().unwrap()).collect();
            assert_eq!(lines, vec!["golang.org/x/mod v0.17.0 h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA="]);
            assert!(a.get("record").and_then(Value::as_string).unwrap()
                .contains("golang.org/x/mod v0.17.0/go.mod h1:hTbmBsO62+eylJbnUtE2MGJUyE7QWk4xUqPFrRgJ+7c="));
            assert_eq!(a.get("id"), Some(&Value::Int(24955599)));
            assert_eq!(a.get("size"), Some(&Value::Int(66746981)));
            assert!(a.get("latest").and_then(Value::as_string).unwrap().starts_with("go.sum database tree\n66746981\n"));
        }

        #[test]
        fn the_checksum_database_check_refuses_what_does_not_hold() {
            let all = || TILES.iter().map(|(p, d)| (*p, d.to_vec())).collect::<Vec<_>>();
            let mut changed = all();
            changed[2].1[7] ^= 0x10;
            let (s, a) = go_sumdb(Some(LATEST), Some(changed));
            assert_eq!(s, STATUS_ERROR, "a changed tile: {}", json::write(&a));
            let (s, _) = go_sumdb(Some(LATEST), Some(all()[1..].to_vec()));
            assert_eq!(s, STATUS_ERROR, "a missing tile");
            let (s, _) = go_sumdb(Some(&LATEST.replace("66746896", "66746897")), None);
            assert_eq!(s, STATUS_ERROR, "a head that is not signed");
            // a tile that is not base64, and arguments missing
            let (s, a) = handle(&request("verify.go_sumdb", &format!(
                "{{\"module\": \"m\", \"version\": \"v1.0.0\", \"key\": \"{KEY}\", \"lookup\": \"x\", \"tiles\": {{\"tile/8/0/000\": \"!\"}}}}"), b""));
            assert_eq!(s, STATUS_ERROR, "{a}");
            let (s, a) = handle(&request("verify.go_sumdb", "{}", b""));
            assert_eq!(s, STATUS_ERROR);
            assert!(a.contains("needs module"), "{a}");
        }
    }

    /// A request's description (native only): its credentials (decision 14).
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn a_requests_credentials_are_read_from_its_description() {
        let spec = json::parse_str(r#"{"method": "GET", "url": "https://a.example/x", "hosts": ["a.example"], "max_bytes": 10,
            "credentials": [{"host": "a.example", "path": "/x/", "name": "Authorization", "value": "Bearer t", "first": true},
                            {"host": "b.example:8443", "path": "/", "name": "PRIVATE-TOKEN", "value": "glpat"}]}"#).unwrap();
        let req = net::request_of(&spec, b"").unwrap();
        let got: Vec<_> = req.credentials.iter().map(|c| (c.host.as_str(), c.path.as_str(), c.name.as_str(), c.value.as_str(),
                                                          c.first_only)).collect();
        assert_eq!(got, vec![("a.example", "/x/", "Authorization", "Bearer t", true),
                             ("b.example:8443", "/", "PRIVATE-TOKEN", "glpat", false)]);
        assert!(!format!("{req:?}").contains("Bearer t"), "a request's debug form shows no credential's value");
        let none = json::parse_str(r#"{"method": "GET", "url": "https://a.example/x", "hosts": ["a.example"], "max_bytes": 10}"#).unwrap();
        assert!(net::request_of(&none, b"").unwrap().credentials.is_empty());
        for bad in [r#""credentials": {"host": "a.example"}"#, r#""credentials": [{"host": "a.example", "path": "/"}]"#,
                    r#""credentials": ["Bearer t"]"#] {
            let spec = json::parse_str(&format!(r#"{{"method": "GET", "url": "https://a.example/x", "max_bytes": 10, {bad}}}"#)).unwrap();
            let err = net::request_of(&spec, b"").unwrap_err();
            assert!(!err.contains("Bearer"), "{err}");
        }
    }

    /// `verify.sigstore` (native only), on tiny_https's real Sigstore data (its tests/data/sigstore/README.txt).
    #[cfg(not(target_arch = "wasm32"))]
    mod sigstore_call {
        use super::*;

        const ROOT: &str = include_str!("../../tiny_https/tests/data/sigstore/trusted_root.json");
        const NPM_KEYS: &str = include_str!("../../tiny_https/tests/data/sigstore/npm-registry-keys.json");
        const ATTESTATIONS: &str = include_str!("../../tiny_https/tests/data/sigstore/sigstore-4.0.0.attestations.json");
        const TARBALL: &[u8] = include_bytes!("../../tiny_https/tests/data/sigstore/sigstore-4.0.0.tgz");

        fn call(registry: &str, digest: &str, keys: Option<&str>) -> (i32, Value) {
            let args = Value::obj(vec![("registry", Value::str(registry)), ("document", Value::str(ATTESTATIONS)),
                                       ("digest", Value::str(digest)), ("root", Value::str(ROOT)),
                                       ("npm_keys", keys.map_or(Value::Null, Value::str))]);
            let (s, a) = handle(&request("verify.sigstore", &json::write(&args), b""));
            (s, json::parse_str(&a).unwrap())
        }

        fn sha512_hex(data: &[u8]) -> String {
            use lazaret_verify::sigstore::{ArtifactDigest, DigestAlgorithm};
            lazaret_verify::util::hex(ArtifactDigest::of(DigestAlgorithm::Sha512, data).bytes())
        }

        #[test]
        fn npm_attestations_verify_and_say_who_built_the_file() {
            let (s, a) = call("npm", &sha512_hex(TARBALL), Some(NPM_KEYS));
            assert_eq!(s, STATUS_OK, "{}", json::write(&a));
            let list = a.get("attestations").and_then(Value::as_arr).unwrap();
            assert_eq!(list.len(), 2);
            for item in list {
                assert_eq!(item.get("outcome").and_then(Value::as_string).as_deref(), Some("verified"), "{}", json::write(item));
            }
            let signer = list[1].get("signer").unwrap();
            assert_eq!(signer.get("kind").and_then(Value::as_string).as_deref(), Some("certificate"));
            assert_eq!(signer.get("repository").and_then(Value::as_string).as_deref(), Some("https://github.com/sigstore/sigstore-js"));
            assert_eq!(list[0].get("signer").and_then(|s| s.get("kind")).and_then(Value::as_string).as_deref(), Some("key"));
            // upper-case hex is the same digest
            let (s, _) = call("npm", &sha512_hex(TARBALL).to_uppercase(), Some(NPM_KEYS));
            assert_eq!(s, STATUS_OK);
        }

        #[test]
        fn another_file_is_invalid_and_bad_arguments_are_errors() {
            let (s, a) = call("npm", &sha512_hex(b"another file"), Some(NPM_KEYS));
            assert_eq!(s, STATUS_OK);
            for item in a.get("attestations").and_then(Value::as_arr).unwrap() {
                assert_eq!(item.get("outcome").and_then(Value::as_string).as_deref(), Some("invalid"));
                assert!(item.get("reason").and_then(Value::as_string).unwrap().contains("subject"));
            }
            let (s, a) = call("npm", &sha512_hex(TARBALL), None);              // (npm's own attestation needs its key)
            assert_eq!(s, STATUS_OK);
            let list = a.get("attestations").and_then(Value::as_arr).unwrap();
            assert_eq!(list[0].get("outcome").and_then(Value::as_string).as_deref(), Some("unchecked"));
            assert_eq!(list[1].get("outcome").and_then(Value::as_string).as_deref(), Some("verified"));
            assert_eq!(call("cargo", &sha512_hex(TARBALL), None).0, STATUS_ERROR);
            assert_eq!(call("npm", "xyz", None).0, STATUS_ERROR);
            assert_eq!(call("npm", "abc", None).0, STATUS_ERROR);
            assert_eq!(call("pypi", &sha512_hex(TARBALL), None).0, STATUS_ERROR, "not PEP 740 provenance, nor a SHA-256");
        }
    }
}
