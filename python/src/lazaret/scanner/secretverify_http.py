"""One HTTPS request for live secret verification (0.1.9, V-1 stage 1).

A credential is sent to its provider in a header, so this is the one place a secret leaves the machine, and it is written to
do as little as it can:

- **https, port 443, one host.** The host and the path are checked before anything is opened: a lower-case DNS name with a dot
  in it (no address, no port, no credentials), a path that is printable ASCII. The caller (`secretverify`) takes the host from
  its provider table, never from scanned text.
- **No redirect is followed.** A 3xx answer is returned as it is; the secret is not sent anywhere the table does not name.
- **The answer is bounded**: `max_bytes` of body (the rest is not read), and one deadline for the whole call, kept by a
  watchdog that closes the socket, so a server that answers a byte at a time cannot hold the run.
- **Proxies**: `HTTPS_PROXY` / `https_proxy` and `NO_PROXY` / `no_proxy` are honoured with an `http://` proxy (a CONNECT
  tunnel, so the proxy sees the host and nothing else; the credential in the proxy URL, if any, goes to the proxy only).
  An `https://` proxy is not supported and the request is refused, not sent without it.
- **Nothing the answer says is trusted**: the body is returned as bytes and read by the caller.

`TransportError.kind` is one of `timeout`, `connection`, `tls`, `proxy`, `refused` (the request itself is not allowed), and its
message never holds a header or a URL.

Standard library only; imports nothing else from Lazaret."""

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

__all__ = ["Request", "Response", "TransportError", "https_transport", "check_request", "MAX_ANSWER_BYTES", "DEFAULT_TIMEOUT",
           "HOST_RE"]

MAX_ANSWER_BYTES = 64 * 1024
DEFAULT_TIMEOUT = 10.0
MAX_HEADERS = 64
MAX_HEADER_VALUE = 512
MAX_PATH = 2000
USER_AGENT = "lazaret-secret-verify"

HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]")
_PATH_RE = re.compile(r"/[\x21-\x7e]{0,%d}" % (MAX_PATH - 1))
_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")
_VALUE_RE = re.compile(r"[\x20-\x7e]{0,%d}" % MAX_HEADER_VALUE)
_METHODS = ("GET", "POST")

Request = collections.namedtuple("Request", "method host path headers body")
Response = collections.namedtuple("Response", "status headers body truncated")


class TransportError(Exception):
    """The request did not get an answer. `kind`: timeout, connection, tls, proxy or refused."""

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
        context = ssl_context if ssl_context is not None else ssl.create_default_context()
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
