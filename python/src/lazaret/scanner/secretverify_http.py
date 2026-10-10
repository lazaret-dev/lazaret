"""One HTTPS request for live secret verification (0.1.9, V-1).

A credential is sent to its provider in a header, so this is the one place a secret leaves the machine, and it is written to
do as little as it can. Two transports make the call, held to the same rules: lazaret-net's (`native_transport`: the native
library's client on pratique, as every other request Lazaret makes; John's decision 7, Oct 7, V-1 stage 2), and urllib's
(`https_transport`, stage 1's) for a request the native client is not to send: no native library, `LAZARET_NETWORK=python`, a
proxy reached over TLS, proxy settings the two would read differently (`nativenet.UsePython`). `default_transport` chooses for
each request.

- **https, port 443, one host.** The host and the path are checked before anything is opened: a lower-case DNS name with a dot
  in it (no address, no port, no credentials), a path that is printable ASCII. The caller (`secretverify`) takes the host from
  its provider table, never from scanned text. lazaret-net holds the request to that host alone, and gives the fields that
  carry the credential (`Request.secret_headers`) as `Credential`s for that host and the request alone.
- **TLS 1.2 at least** (`TLS_FLOOR`, the floor of every transport Lazaret has): pratique speaks TLS 1.3, and 1.2 only to a
  server that speaks nothing newer; urllib's context states the floor rather than leaving it to Python's defaults
  (`default_context`). The system's trust anchors, the hostname checked.
- **No redirect is followed.** A 301, 302, 303, 307 or 308 that names a Location is TransportError "redirect"; the secret is
  not sent anywhere the table does not name.
- **The answer is bounded**: `max_bytes` of body (the rest is not read), and one deadline for the whole call (lazaret-net's
  limit on the whole request; urllib's kept by a watchdog that closes the socket), so a server that answers a byte at a time
  cannot hold the run. The body is asked for as it is (`Accept-Encoding: identity`).
- **Proxies**: `HTTPS_PROXY` / `https_proxy` and `NO_PROXY` / `no_proxy` are honoured with an `http://` proxy (a CONNECT
  tunnel, so the proxy sees the host and nothing else; the credential in the proxy URL, if any, goes to the proxy only), and
  lazaret-net takes the system's proxy where the environment names none, as urllib's openers do. An `https://` proxy is not
  supported and the request is refused, not sent without it.
- **Nothing the answer says is trusted**: the body is returned as bytes and read by the caller.

`TransportError.kind` is one of `timeout`, `connection`, `tls`, `proxy`, `redirect` (the provider answered with one), `refused`
(the request itself is not allowed), and its message never holds a header or a URL.

urllib's transport is the standard library's alone; lazaret-net's imports `nativenet` when it is first used."""

import base64
import collections
import http.client
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request

__all__ = ["Request", "Response", "TransportError", "default_transport", "native_transport", "https_transport", "check_request",
           "default_context", "MAX_ANSWER_BYTES", "DEFAULT_TIMEOUT", "HOST_RE", "TLS_FLOOR"]

MAX_ANSWER_BYTES = 64 * 1024
DEFAULT_TIMEOUT = 10.0
MAX_HEADERS = 64
MAX_HEADER_VALUE = 512
MAX_PATH = 2000
USER_AGENT = "lazaret-secret-verify"
#: the oldest TLS version a secret is sent over (nativenet.TLS_FLOOR: Lazaret's floor on every transport)
TLS_FLOOR = ssl.TLSVersion.TLSv1_2
#: the statuses that redirect (pratique's `is_redirect`): with a Location, one is TransportError "redirect"
REDIRECTS = (301, 302, 303, 307, 308)
#: the budget lazaret-net's request is opened with: an answer that declares a length up to it is read to `max_bytes` and cut,
#: as urllib's transport cuts it (a declared length over a request's budget fails it before its status is read)
NATIVE_BUDGET = 1 << 30

HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
_PATH_RE = re.compile(r"/[\x21-\x7e]{0,%d}" % (MAX_PATH - 1))
_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_VALUE_RE = re.compile(r"[\x20-\x7e]{0,%d}" % MAX_HEADER_VALUE)
_METHODS = ("GET", "POST")

#: `secret_headers`: the names of the fields that carry the credential or a signature by it (lazaret-net gives them to the
#: request's host alone, as `Credential`s; urllib's transport sends every field to that host alone anyway)
Request = collections.namedtuple("Request", "method host path headers body secret_headers", defaults=((),))
Response = collections.namedtuple("Response", "status headers body truncated")


class TransportError(Exception):
    """The request did not get an answer. `kind`: timeout, connection, tls, proxy, redirect or refused."""

    def __init__(self, kind, message=""):
        super().__init__(f"{kind}: {message}" if message else kind)
        self.kind = kind


def check_request(request):
    """`request` if it may be sent; TransportError("refused") if not. Never echoes the request."""
    if not isinstance(request, Request) or request.method not in _METHODS:
        raise TransportError("refused", "not a request this module sends")
    if not isinstance(request.host, str) or len(request.host) > 253 or not HOST_RE.fullmatch(request.host):
        raise TransportError("refused", "the host is not a lower-case DNS name")
    if not isinstance(request.path, str) or not _PATH_RE.fullmatch(request.path):
        raise TransportError("refused", "the path is not printable ASCII that starts with /")
    if not isinstance(request.headers, dict) or len(request.headers) > MAX_HEADERS:
        raise TransportError("refused", "the headers are not a small mapping")
    for name, value in request.headers.items():
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name) or not isinstance(value, str) or not _VALUE_RE.fullmatch(value):
            raise TransportError("refused", "a header is not printable ASCII")
        if name.lower() in ("host", "content-length", "transfer-encoding", "connection"):
            raise TransportError("refused", f"the {name.lower()} header is the transport's")
    if request.body is not None and not isinstance(request.body, bytes):
        raise TransportError("refused", "the body is not bytes")
    names = {name.lower() for name in request.headers}
    if not isinstance(request.secret_headers, (tuple, list)) or not all(
            isinstance(name, str) and name.lower() in names for name in request.secret_headers):
        raise TransportError("refused", "a field said to carry the credential is not one of the request's")
    return request


def _proxy(host, environ):
    """(host, port, headers) of the proxy to tunnel through for this host, or None. TransportError("proxy") for one that is not an
    http:// proxy."""
    value = environ.get("HTTPS_PROXY") or environ.get("https_proxy")
    if not value:
        return None
    no = environ.get("NO_PROXY") or environ.get("no_proxy")
    proxies = {"https": value}
    if no:
        proxies["no"] = no
    if urllib.request.proxy_bypass_environment(host, proxies):
        return None
    parts = urllib.parse.urlsplit(value if "//" in value else "http://" + value)
    try:
        port = parts.port
    except ValueError:
        raise TransportError("proxy", "the proxy's port is not one") from None
    if parts.scheme != "http" or not parts.hostname:
        raise TransportError("proxy", "only an http:// proxy is supported")
    headers = {}
    if parts.username is not None:
        raw = f"{urllib.parse.unquote(parts.username)}:{urllib.parse.unquote(parts.password or '')}".encode("utf-8")
        headers["Proxy-Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    return parts.hostname, port or 80, headers


class _Connection(http.client.HTTPSConnection):
    """An HTTPS connection that can be pointed at another address than the host's (the tests' stub server), the host's name
    still being what the certificate is checked for."""

    def __init__(self, host, timeout, context, connect_to):
        super().__init__(host, 443, timeout=timeout, context=context)
        self._connect_to = connect_to

    def connect(self):
        if self._connect_to is None:
            return super().connect()
        sock = socket.create_connection(self._connect_to, self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        return None


def default_context():
    """Python's default context (the system's trust anchors, the hostname checked) with `TLS_FLOOR` as its floor."""
    context = ssl.create_default_context()
    low = context.minimum_version
    if low == ssl.TLSVersion.MINIMUM_SUPPORTED or 0 <= low < TLS_FLOOR:
        context.minimum_version = TLS_FLOOR
    return context


def https_transport(ssl_context=None, connect_to=None, environ=None, clock=time.monotonic):
    """A `send(request, timeout, max_bytes) -> Response` for `secretverify`. `ssl_context` and `connect_to` (an address to connect
    to in place of the host's own) are for tests; `environ` is the mapping the proxy settings are read from (the process's by
    default)."""
    if environ is None:
        environ = os.environ

    def send(request, timeout=DEFAULT_TIMEOUT, max_bytes=MAX_ANSWER_BYTES):
        check_request(request)
        if not isinstance(max_bytes, int) or max_bytes < 1:
            raise TransportError("refused", "no room for an answer")
        context = ssl_context if ssl_context is not None else default_context()
        proxy = None if connect_to is not None else _proxy(request.host, environ)
        if proxy is not None:
            conn = http.client.HTTPSConnection(proxy[0], proxy[1], timeout=timeout, context=context)
            conn.set_tunnel(request.host, 443, headers=proxy[2])
        else:
            conn = _Connection(request.host, timeout, context, connect_to)
        expired = threading.Event()
        held = []                                               # (the connection lets go of its socket once the answer starts)

        def stop():
            expired.set()
            for sock in held:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(timeout, stop)
        watchdog.daemon = True
        watchdog.start()
        deadline = clock() + timeout
        headers = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity", "Connection": "close"}
        headers.update(request.headers)
        try:
            conn.connect()
            held.append(conn.sock)
            conn.request(request.method, request.path, body=request.body, headers=headers)
            response = conn.getresponse()
            if response.status in REDIRECTS and response.getheader("Location") is not None:
                raise TransportError("redirect", "the provider answered with a redirect, which is not followed")
            chunks, total, truncated = [], 0, False
            while True:
                if expired.is_set() or clock() > deadline:
                    raise TransportError("timeout", "the answer took too long")
                block = response.read1(min(8192, max_bytes + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > max_bytes:
                    truncated = True
                    break
            if expired.is_set():
                raise TransportError("timeout", "the answer took too long")
            if not truncated and response.length:                # (the connection ended before the length it promised)
                raise TransportError("connection", "the answer was cut short")
            body = b"".join(chunks)[:max_bytes]
            seen = {}
            for name, value in response.getheaders()[:MAX_HEADERS]:
                seen.setdefault(name.lower(), value[:MAX_HEADER_VALUE])
            return Response(response.status, seen, body, truncated)
        except TransportError:
            raise
        except TimeoutError:
            raise TransportError("timeout", "no answer in time") from None
        except ssl.SSLError as exc:
            if expired.is_set():
                raise TransportError("timeout", "no answer in time") from None
            raise TransportError("tls", type(exc).__name__) from None
        except (OSError, http.client.HTTPException, ValueError) as exc:
            if expired.is_set():
                raise TransportError("timeout", "no answer in time") from None
            if isinstance(exc, ValueError):
                raise TransportError("refused", "the request could not be formed") from None
            raise TransportError("proxy" if proxy is not None and not held else "connection", type(exc).__name__) from None
        finally:
            watchdog.cancel()
            conn.close()

    return send


def native_transport(proxy=None, clock=time.monotonic):
    """A `send(request, timeout, max_bytes) -> Response` over lazaret-net (`nativenet.open_stream`): the request's host the only
    host it may reach, no redirect, nothing compressed, one deadline for the call (its `total_timeout`, and checked again between
    reads); the fields that carry the credential (`Request.secret_headers`) go as `Credential`s for that host and the request
    alone, the others as the request's own (lazaret-net sends only the plain ones it knows). `nativenet.UsePython` when the
    native client is not to send it (`default_transport` then hands it to urllib's). `proxy` is for tests: "direct", "env" or a
    proxy's URL (None: the one urllib would use)."""

    def send(request, timeout=DEFAULT_TIMEOUT, max_bytes=MAX_ANSWER_BYTES):
        from . import nativenet
        check_request(request)
        if not isinstance(max_bytes, int) or max_bytes < 1:
            raise TransportError("refused", "no room for an answer")
        secret = {name.lower() for name in request.secret_headers}
        plain, credentials = {"user-agent": ("User-Agent", USER_AGENT)}, []
        for name, value in request.headers.items():
            if name.lower() in secret:
                credentials.append(nativenet.Credential(request.host, "/", name, value, True))
            else:
                plain[name.lower()] = (name, value)
        deadline = clock() + timeout
        try:
            stream = nativenet.open_stream(f"https://{request.host}{request.path}", hosts=[request.host], method=request.method,
                                           headers=list(plain.values()), data=request.body, max_bytes=NATIVE_BUDGET,
                                           timeout=timeout, max_redirects=0, total_timeout=timeout, h2=False, proxy=proxy,
                                           credentials=credentials, compressed=False)
        except nativenet.NetError as exc:
            raise _native_error(exc) from None
        chunks, total = [], 0
        try:
            while total <= max_bytes:
                if clock() > deadline:
                    raise TransportError("timeout", "the answer took too long")
                block = stream.read(min(8192, max_bytes + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
        except nativenet.NetError as exc:
            raise _native_error(exc) from None
        finally:
            stream.close()
        seen = {}
        for name, value in stream.headers[:MAX_HEADERS]:
            seen.setdefault(name.lower(), value[:MAX_HEADER_VALUE])
        return Response(stream.status, seen, b"".join(chunks)[:max_bytes], total > max_bytes)

    return send


def _native_error(exc):
    """lazaret-net's failure as a TransportError: its kind, and words of this module's (not lazaret-net's message, which may
    name the host)."""
    kind, message = getattr(exc, "kind", ""), str(exc)
    if kind == "http" and message.startswith("too many redirects"):
        return TransportError("redirect", "the provider answered with a redirect, which is not followed")
    if kind == "http" and message.startswith("proxy "):
        return TransportError("proxy", "the proxy did not open a tunnel")
    if kind in ("timeout", "tls"):
        return TransportError(kind, "lazaret-net")
    if kind in ("refused", "setup"):
        return TransportError("refused", "lazaret-net would not send it")
    return TransportError("connection", kind or "lazaret-net")


def default_transport():
    """The transport `secretverify.Verifier` uses: lazaret-net's (`native_transport`), and urllib's (`https_transport`) for a
    request the native client is not to send (`nativenet.UsePython`: no native library, LAZARET_NETWORK=python, a proxy reached
    over TLS, proxy settings the two would read differently). The process's proxy settings, read at each request."""
    native, python = native_transport(), https_transport()

    def send(request, timeout=DEFAULT_TIMEOUT, max_bytes=MAX_ANSWER_BYTES):
        from . import nativenet
        try:
            return native(request, timeout, max_bytes)
        except nativenet.UsePython:
            return python(request, timeout, max_bytes)

    return send
