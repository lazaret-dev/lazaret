"""Lazaret's network transport (0.1.9, NET-1): the native library's HTTPS client, the default for the registry's
requests since John's decision 12 (Oct 6), with Python's urllib (OpenSSL) behind it.

The client is rust/crates/lazaret-net, on tiny_https (rust/crates/tiny_https: TLS 1.3, and TLS 1.2 with a server
that speaks nothing newer; HTTP/2 with one shared connection per origin, and HTTP/1.1 with kept-alive connections;
documents go over HTTP/2 and downloads over HTTP/1.1, see `http2`), reached through the native library's C ABI
(`lazaret_net_*`, rust/crates/lazaret-ffi). Every request carries its caller's host rule, which the client applies
to the first URL and to every redirect before it connects (a `*.` entry is one DNS label; an entry without a port is
the default port only), with https only, no credentials in a URL, a byte budget for the body, a timeout for
connecting and for each read and write, and a number of redirects.

Python's transport is used instead:

* where the native library is missing or older than the network layer (no `lazaret_net_request`);
* when `LAZARET_NETWORK=python` asks for it;
* for a server that speaks neither TLS 1.3 nor TLS 1.2, from then on for that host, in this process
  (`python_hosts`). tiny_https speaks 1.2 only to a server that speaks nothing newer, as its drop of Oct 7 does
  (B-36): ECDHE with AEAD suites only, the extended master secret required, RFC 8446's downgrade check, no
  renegotiation or resumption, the certificate checks of 1.3. Every reply says which version it came over (`tls`);
* for a proxy reached over TLS (`https://` in the proxy's URL), which tiny_https does not speak;
* where no trust anchors can be found for it (below).

Trust anchors: `SSL_CERT_FILE` when it is set (as OpenSSL reads it); else the system's CA bundle (the files
tiny_https knows: Debian's, Red Hat's, SUSE's, macOS's /etc/ssl/cert.pem, Homebrew's, FreeBSD's); else the
certificates Python's default context loads (on Windows, the system's certificate store). A proxy: the one urllib
would use, from `HTTPS_PROXY` / `NO_PROXY` (followed on every redirect hop), or from the system's settings (macOS,
Windows) when the environment names none.

`request` reads a body whole, `open_stream` hands it over in pieces. A request that gets no response raises `NetError`
(`kind`: "refused", "too-large", "tls", "timeout", "network", "http", "setup"); one that should go through Python's
transport raises `UsePython`. The caller turns either into its own error (repo.py: FetchError).

Credentials (decision 14, John, Oct 6: they go over tiny_https in 0.1.9): a token or a login is a `Credential` of a
request, never one of its headers. The native client gives each hop the credentials of the host it goes to and no
other (tiny_https's hop hook, called for the request and for every redirect before anything is sent there; lazaret-net
refuses a request that sets `Authorization`, `Cookie`, `PRIVATE-TOKEN` and the like as a header, which a redirect to
another host could carry on). A credential the native client cannot send (a value or path outside printable ASCII, a
host it would not write that way) makes the request Python's, as before 0.1.9.
"""
import ctypes
import json
import os
import ssl
import threading
import urllib.parse
import urllib.request
from typing import NamedTuple

from lazaret.scanner import _native

ENV = "LAZARET_NETWORK"
#: which protocol: "auto" (the default: documents over HTTP/2, downloads over HTTP/1.1), "2" (HTTP/2 for every
#: request), "1.1" (HTTP/1.1 only). HTTP/2 is offered, never forced: a server that does not pick it gets HTTP/1.1.
HTTP_ENV = "LAZARET_HTTP"
#: the largest budget of a request that is a document (registry metadata, an API's answer, a query); a request that
#: may be larger is a download (an artifact, a feed's archive)
DOCUMENT_BUDGET = 32 * 1024 * 1024
STATUS_OK, STATUS_ERROR = 0, 1


class NetError(Exception):
    """A request that got no response."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class UsePython(Exception):
    """Send this request with Python's transport (the reason is the message)."""


class Reply(NamedTuple):
    status: int
    version: str
    headers: list
    url: str
    body: bytes
    #: the TLS version the reply came over: "TLS 1.3" or "TLS 1.2"
    tls: str = None

    def header(self, name):
        name = name.lower()
        return next((v for n, v in self.headers if n.lower() == name), None)


class Credential(NamedTuple):
    """The header `name: value` for the hops to `host` whose path is under `path`, over https (decision 14). `host` is
    written as a Host header is, and as pmsettings.Credentials keys a host: lower case, an IPv6 address in brackets,
    ":port" when the port is not 443 (`host_key`). `path` is a prefix that ends in "/" ("/": the whole host); where
    several fit a hop, the longest is given, for each name. `first`: for the request itself and no redirect (the
    URL's own user:password, which urllib sends with the request alone); on the request it comes before the others."""
    host: str
    path: str
    name: str
    value: str
    first: bool = False

    def __repr__(self):                    # (a credential's value is never shown)
        return f"Credential(host={self.host!r}, path={self.path!r}, name={self.name!r}, first={self.first})"


def host_key(url):
    """The host of an https URL as a `Credential` names it: lower case, an IPv6 address in brackets, ":port" when the
    port is not 443. "" for a URL without one."""
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        return ""
    if not host:
        return ""
    shown = f"[{host}]" if ":" in host else host
    return shown if port in (None, 443) else f"{shown}:{port}"


_TOKEN = frozenset("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_HOST = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-_[]:")


def _sendable(c):
    """Can the native client send this credential (lazaret-net's rule; it refuses the request otherwise)?"""
    return (0 < len(c.name) <= 256 and all(ch in _TOKEN for ch in c.name)
            and c.name.lower() not in ("host", "connection", "content-length", "transfer-encoding")
            and len(c.value) <= 8192 and all(ch in " \t" or "!" <= ch <= "~" for ch in c.value)
            and c.host != "" and all(ch in _HOST for ch in c.host)
            and c.path.startswith("/") and c.path.endswith("/")
            and all("!" <= ch <= "~" and ch not in "?#" for ch in c.path))


_lock = threading.Lock()
_ready = None                    # None: not tried; True: the native transport works here; False: it does not
_why_not = None                  # why it does not
_python_hosts = set()            # hosts that offered no TLS version the client speaks (lower-case host[:port])


def _bind(lib):
    vp, sz = ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t)
    lib.lazaret_net_request.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, vp, sz, vp, sz]
    lib.lazaret_net_request.restype = ctypes.c_int
    lib.lazaret_net_open.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, vp, sz,
                                     ctypes.POINTER(ctypes.c_uint64)]
    lib.lazaret_net_open.restype = ctypes.c_int
    lib.lazaret_net_read.argtypes = [ctypes.c_uint64, ctypes.c_void_p, ctypes.c_size_t, sz, vp, sz]
    lib.lazaret_net_read.restype = ctypes.c_int
    lib.lazaret_net_close.argtypes = [ctypes.c_uint64]
    lib.lazaret_net_close.restype = None
    lib.lazaret_net_configure.argtypes = [ctypes.c_char_p, ctypes.c_size_t, vp, sz]
    lib.lazaret_net_configure.restype = ctypes.c_int


def _take(lib, ptr, size):
    """The bytes of a buffer the library handed over, which is then given back."""
    if not ptr.value:
        return b""
    try:
        return ctypes.string_at(ptr.value, size.value)
    finally:
        lib.lazaret_engine_free(ptr.value, size.value)


def _configure(lib, pem):
    meta, meta_len = ctypes.c_void_p(), ctypes.c_size_t()
    status = lib.lazaret_net_configure(pem, len(pem or b""), ctypes.byref(meta), ctypes.byref(meta_len))
    answer = _take(lib, meta, meta_len)
    if status == STATUS_OK:
        return None
    try:
        return json.loads(answer).get("error") or "the network layer said no"
    except ValueError:
        return "the network layer said no"


def python_roots():
    """The certificates Python's default context trusts, as PEM (on Windows the system's certificate store; empty
    where they are read lazily from a directory)."""
    try:
        context = ssl.create_default_context()
        ders = context.get_ca_certs(binary_form=True)
    except (ssl.SSLError, OSError, ValueError):
        return ""
    return "".join(ssl.DER_cert_to_PEM_cert(der) for der in ders)


def _setup():
    """(the library, or None) with the network layer's trust anchors set, once per process."""
    global _ready, _why_not
    if _ready is not None:
        return _native._load() if _ready else None
    with _lock:
        if _ready is not None:
            return _native._load() if _ready else None
        lib = _native._load()
        if lib is None:
            _ready, _why_not = False, _native.load_error() or "no native library"
            return None
        if not hasattr(lib, "lazaret_net_request"):
            _ready, _why_not = False, "the native library has no network layer (older than 0.1.9)"
            return None
        try:
            _bind(lib)
        except AttributeError as exc:
            _ready, _why_not = False, f"the native library's network layer is incomplete: {exc}"
            return None
        problem = _configure(lib, None)                 # SSL_CERT_FILE, else the system's CA bundle
        if problem is not None:
            pem = python_roots()                         # (Windows: the system's certificate store, through ssl)
            problem = _configure(lib, pem.encode("ascii")) if pem else problem
        if problem is not None:
            _ready, _why_not = False, f"no trust anchors for the native transport ({problem})"
            return None
        _ready, _why_not = True, None
        return lib


def disabled():
    """Does the environment ask for Python's transport?"""
    return os.environ.get(ENV, "").strip().lower() == "python"


def available():
    """Can requests go through the native transport here (the library, its network layer, trust anchors)?"""
    return not disabled() and _setup() is not None


def why_not():
    """Why the native transport is not used (None when it is)."""
    if disabled():
        return f"{ENV}=python"
    _setup()
    return _why_not


def python_hosts():
    """The hosts this process sends through Python's transport because they offered no TLS version the native client
    speaks (neither 1.3 nor 1.2)."""
    with _lock:
        return frozenset(_python_hosts)


def _netloc(url):
    try:
        parts = urllib.parse.urlsplit(url)
        host, port = (parts.hostname or "").lower(), parts.port
    except ValueError:
        return ""
    return host if port in (None, 443) else f"{host}:{port}"


def chosen(url):
    """Does a request to `url` go through the native transport?"""
    if not available():
        return False
    with _lock:
        return _netloc(url) not in _python_hosts


def _env_proxies():
    """The environment's https proxy and no-proxy list as urllib reads them (a lower-case name first, and an empty one
    unsets the setting) and as the native client does (an upper-case name first, set or empty): (urllib's, the
    native client's), each (proxy, no-proxy list), "" for none."""
    env = urllib.request.getproxies_environment()

    def native(name):
        upper = os.environ.get(name.upper())
        return (upper if upper is not None else os.environ.get(name, "")).strip()

    return ((env.get("https") or "").strip(), (env.get("no") or "").strip()), (native("https_proxy"), native("no_proxy"))


def _urllib_proxy(value):
    """Where urllib's ProxyHandler takes an https request for this proxy setting: (host, port, Basic login or None),
    the port 443 when it names none (an https request's connection class's); None when it cannot read it."""
    try:
        _scheme, user, password, hostport = urllib.request._parse_proxy(value)
        parts = urllib.parse.urlsplit("//" + urllib.parse.unquote(hostport))
        login = f"{urllib.parse.unquote(user)}:{urllib.parse.unquote(password)}" if user and password else None
        return (parts.hostname or "").lower(), parts.port or 443, login
    except (ValueError, AttributeError, TypeError):
        return None


def _native_proxy(value):
    """The same as tiny_https's `Proxy::parse` reads it: "http://" before a setting without a scheme; the port only
    when the setting ends with it (with a path after it, even "/", or none, 8080); the login as written."""
    text = value.strip()
    text = text if "://" in text else "http://" + text
    try:
        parts = urllib.parse.urlsplit(text)
        last = text.rsplit("/", 1)[-1]
        port = parts.port if ":" in last and not last.endswith("]") else 8080
        login = parts.netloc.rpartition("@")[0] if "@" in parts.netloc else None
        return (parts.hostname or "").lower(), port, login
    except ValueError:
        return None


def _native_bypass(host):
    """tiny_https's `no_proxy_matches` for a host (lower case, an IPv6 address without brackets): NO_PROXY, or
    no_proxy when NO_PROXY is not set; an entry is a host or a domain, its leading dots aside, or "*"."""
    value = os.environ.get("NO_PROXY")
    if value is None:
        value = os.environ.get("no_proxy", "")
    for entry in value.split(","):
        entry = entry.strip().lstrip(".").lower()
        if entry and (entry == "*" or host == entry or host.endswith("." + entry)):
            return True
    return False


def _proxy_for(url):
    """What urllib would do for `url`: "env" (HTTPS_PROXY, with NO_PROXY, which the native client reads again on
    every hop), "direct", or the proxy the system's settings name. UsePython for a proxy reached over TLS, and where
    urllib and the native client would read the settings differently (the credentials review of decision 14): the
    environment's variables (HTTPS_PROXY and https_proxy both set, and not to the same), the proxy's address (tiny_https
    takes port 8080 when a path follows the port, or none is given), and whether the URL's host is one NO_PROXY names
    (tiny_https takes "*" anywhere in the list, and no entry with a port)."""
    ours, native = _env_proxies()
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        raise UsePython("a URL the native client is not given") from None
    if ours[0] or native[0]:
        if ours != native:
            raise UsePython("HTTPS_PROXY and https_proxy (or NO_PROXY and no_proxy) say different things")
        if ours[0].lower().startswith("https://"):
            raise UsePython("a proxy reached over TLS")
        bypass = urllib.request.proxy_bypass_environment(parts.netloc.rpartition("@")[2],
                                                         urllib.request.getproxies_environment())
        if bool(bypass) != _native_bypass((parts.hostname or "").lower()):
            raise UsePython("NO_PROXY reads differently to urllib and the native client for this host")
        if not bypass and _urllib_proxy(ours[0]) != _native_proxy(ours[0]):
            raise UsePython("the proxy's address reads differently to urllib and the native client")
        return "env"
    try:
        proxies = urllib.request.getproxies()                # (macOS and Windows: the system's settings)
        proxy = proxies.get("https")
        if not proxy or urllib.request.proxy_bypass(parts.hostname or ""):
            return "direct"
    except (OSError, ValueError):
        return "direct"
    if proxy.strip().lower().startswith("https://"):
        raise UsePython("a proxy reached over TLS")
    if _urllib_proxy(proxy) != _native_proxy(proxy):
        raise UsePython("the proxy's address reads differently to urllib and the native client")
    return proxy


def _spec(url, hosts, method, headers, max_bytes, timeout, max_redirects, total_timeout, h2=None, proxy=None,
          credentials=()):
    if hosts is not None and not hosts:
        raise NetError("setup", "a request needs the hosts its caller may reach")
    credentials = [Credential(*c) for c in credentials or ()]
    if not all(_sendable(c) for c in credentials):
        raise UsePython("a credential the native client cannot send")
    spec = {
        "method": method, "url": url, "headers": [[str(n), str(v)] for n, v in (headers or ())],
        "hosts": sorted(hosts or ()), "any_host": hosts is None, "max_bytes": int(max_bytes),
        "timeout_ms": max(1, int(timeout * 1000)),
        "total_timeout_ms": None if total_timeout is None else max(1, int(total_timeout * 1000)),
        "max_redirects": int(max_redirects), "proxy": _proxy_for(url) if proxy is None else proxy,
        "http2": http2(max_bytes) if h2 is None else bool(h2),
    }
    if credentials:
        spec["credentials"] = [{"host": c.host, "path": c.path, "name": c.name, "value": c.value, "first": bool(c.first)}
                               for c in credentials]
    return json.dumps(spec, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def http2(max_bytes=None):
    """Is h2 offered for a request with this budget? Measured on the registries (docs/DESIGN.md, NET-1): HTTP/2's one
    shared connection answers a burst of small documents fastest, and HTTP/1.1's parallel connections bring large
    and concurrent downloads in two to three times faster than one HTTP/2 connection does. So by default a document
    (a budget of at most DOCUMENT_BUDGET) is offered h2 and a download goes over HTTP/1.1; `LAZARET_HTTP=2` offers h2
    to every request, `LAZARET_HTTP=1.1` to none."""
    mode = os.environ.get(HTTP_ENV, "").strip().lower()
    if mode in ("1.1", "1", "http/1.1"):
        return False
    if mode in ("2", "h2", "http/2"):
        return True
    return max_bytes is None or max_bytes <= DOCUMENT_BUDGET


def _failure(url, answer):
    try:
        doc = json.loads(answer)
        kind, message, host = doc.get("kind", "setup"), doc.get("error", ""), doc.get("host")
    except ValueError:
        kind, message, host = "setup", answer.decode("ascii", "replace"), None
    if kind == "tls-version":
        # (the host of the hop that offered no version the client speaks, a redirect's when it was one: the first URL's
        # host stays on the native transport; the credentials review of decision 14)
        if isinstance(host, str) and host:
            with _lock:
                _python_hosts.add(_netloc(f"https://{host}/"))
        raise UsePython(f"the server speaks neither TLS 1.3 nor TLS 1.2 ({message})")
    raise NetError(kind, message)


def _head(answer):
    """(status, version, headers, url, tls) of an answer's head."""
    doc = json.loads(answer)
    return doc["status"], doc["version"], [tuple(h) for h in doc["headers"]], doc["url"], doc.get("tls")


def request(url, *, hosts, method="GET", headers=(), data=None, max_bytes, timeout, max_redirects=3,
            total_timeout=None, h2=None, proxy=None, credentials=()):
    """Send one request and read its body whole (at most `max_bytes`): a `Reply`, whatever its status. NetError when
    no response came; UsePython when Python's transport is to send it. `hosts`: the hosts the URL and every redirect
    may go to, or None for any (https, the URL limits, still hold: a caller that checked the first URL itself). `h2`:
    offer HTTP/2 (True), or not (False); None: as `http2` says for the budget. `proxy`: "direct", "env" or a proxy's
    URL; None: as urllib would choose. `credentials`: `Credential`s, each given to the hops to its own host alone
    (none of them may be in `headers`)."""
    lib = _setup()
    if lib is None or disabled():
        raise UsePython(why_not() or "the native transport is not available")
    spec = _spec(url, hosts, method, headers, max_bytes, timeout, max_redirects, total_timeout, h2, proxy, credentials)
    meta, meta_len, body, body_len = ctypes.c_void_p(), ctypes.c_size_t(), ctypes.c_void_p(), ctypes.c_size_t()
    status = lib.lazaret_net_request(spec, len(spec), data, len(data or b""), ctypes.byref(meta), ctypes.byref(meta_len),
                                     ctypes.byref(body), ctypes.byref(body_len))
    answer, payload = _take(lib, meta, meta_len), _take(lib, body, body_len)
    if status != STATUS_OK:
        _failure(url, answer)
    status, version, headers, final, tls = _head(answer)
    return Reply(status, version, headers, final, payload, tls)


class Stream:
    """A response whose body is read in pieces: `status`, `version`, `headers`, `url`, `tls` (as a Reply's); `read(n)`
    (b"" at the end), iteration by chunks, and `close()` (a context manager closes it)."""

    def __init__(self, lib, handle, head, url):
        self._lib, self._handle, self._url = lib, handle, url
        self.status, self.version, self.headers, self.url, self.tls = head
        self._buf = ctypes.create_string_buffer(64 * 1024)

    def header(self, name):
        name = name.lower()
        return next((v for n, v in self.headers if n.lower() == name), None)

    def read(self, n=64 * 1024):
        if self._handle is None:
            return b""
        if n > len(self._buf):
            self._buf = ctypes.create_string_buffer(n)
        got, meta, meta_len = ctypes.c_size_t(), ctypes.c_void_p(), ctypes.c_size_t()
        status = self._lib.lazaret_net_read(self._handle, self._buf, min(n, len(self._buf)), ctypes.byref(got),
                                            ctypes.byref(meta), ctypes.byref(meta_len))
        answer = _take(self._lib, meta, meta_len)
        if status != STATUS_OK:
            self.close()
            _failure(self._url, answer)
        return ctypes.string_at(self._buf, got.value)

    def __iter__(self):
        while True:
            chunk = self.read()
            if not chunk:
                return
            yield chunk

    def close(self):
        if self._handle is not None:
            handle, self._handle = self._handle, None
            self._lib.lazaret_net_close(handle)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:                   # (interpreter shutdown)
            pass


def open_stream(url, *, hosts, method="GET", headers=(), data=None, max_bytes, timeout, max_redirects=3,
                total_timeout=None, h2=None, proxy=None, credentials=()):
    """Send one request and return once its head is in: a `Stream` (the body read with `read`), whatever its
    status. NetError, UsePython, `hosts`, `h2`, `proxy` and `credentials` as `request`."""
    lib = _setup()
    if lib is None or disabled():
        raise UsePython(why_not() or "the native transport is not available")
    spec = _spec(url, hosts, method, headers, max_bytes, timeout, max_redirects, total_timeout, h2, proxy, credentials)
    meta, meta_len, handle = ctypes.c_void_p(), ctypes.c_size_t(), ctypes.c_uint64()
    status = lib.lazaret_net_open(spec, len(spec), data, len(data or b""), ctypes.byref(meta), ctypes.byref(meta_len),
                                  ctypes.byref(handle))
    answer = _take(lib, meta, meta_len)
    if status != STATUS_OK:
        _failure(url, answer)
    return Stream(lib, handle.value, _head(answer), url)


def configure_roots(pem):
    """Use these trust anchors (PEM text; None: the default ones, as on first use) for the requests from now on
    (tests point the transport at a local server's root this way)."""
    global _ready, _why_not
    lib = _native._load()
    if lib is None or not hasattr(lib, "lazaret_net_configure"):
        raise NetError("setup", "the native library has no network layer")
    with _lock:
        _bind(lib)
        problem = _configure(lib, None if pem is None else pem.encode("ascii"))
        if problem is not None:
            raise NetError("setup", problem)
        _ready, _why_not = True, None
