"""Connections that stay open between requests (0.1.9, P-15), for the guard's fetches.

`urllib` sends `Connection: close`, so each of the 25 to 50 requests of a guarded install (the
index's pages, `.metadata` files, the files themselves) opens a TCP connection and a TLS
session of its own, where pip's own client reuses them. This module is the part that can be
had without a policy: a small thread-safe pool of `http.client` connections, and one GET that
takes a connection from it, or opens one, and gives it back when the body has been read.

What it does not decide, the caller does (`guard.Fetcher`): which hosts may be reached, what a
redirect may lead to, which credentials go to which URL. `request` follows no redirect and adds
no header of its own beyond `http.client`'s (`Host`, `Accept-Encoding: identity`).

- **A connection is reused only when it is certainly clean**: the response was read to its end
  and the server did not say `Connection: close` (or speak HTTP/1.0 without keep-alive, or send a
  body that ends when the connection does). A response closed early takes its connection with it.
- **A stale connection is not an error.** A server closes an idle one after a while; the request
  that finds it so (`RemoteDisconnected`, a reset, a broken pipe, a TLS EOF) is sent once more on
  a fresh connection, and only when the failed one was a reused one and the request a GET. A fresh
  connection that fails is the caller's error.
- **Idle connections are kept 30 seconds and at most 8 per (scheme, host, port, proxy)**, newest
  first; an older one is closed rather than tried.
- **A proxy** named by the environment (`https_proxy`, `no_proxy`) is used the way `urllib` uses
  it for an https URL: one CONNECT through an `http://` proxy, with `Proxy-Authorization` from the
  proxy URL's user and password. A proxy of another kind (an `https://` proxy, or any proxy for a
  plain-http URL) raises `Unsupported`, and the caller takes the `urllib` path as before.
- **TLS** is `nativenet.tls_context()`: the same verification `urllib` does, with the same
  certificate store and environment (`SSL_CERT_FILE`), and nothing older than TLS 1.2.
- Connecting (TCP, the tunnel, TLS) is a `network`/`connect` span; each answer is counted under
  `connections` as `new` or `reused`, so a timed run shows what reuse did.
- **A download's deadline** (0.1.9, F-07: the caller's, `guard._Deadline`) is given to `request`: a
  new connection is made by its `connect` (each address's attempt within the time left, the socket
  watched, so that its watchdog can shut it down while a call waits on it), a reused one is watched
  too, and a response read to its end lets the deadline go of its connection before giving it back,
  or closes it when the deadline has shut it down. A body that ended short of its length is no clean
  end either: its connection is closed, not given back. A reused connection the watchdog shut down
  while its answer was awaited is not a stale one: it is not retried, and the host's other idle
  connections are kept (`deadline.expired()`)."""

import base64
import http.client
import ssl
import threading
import time
import urllib.parse
import urllib.request

from lazaret.scanner import nativenet, timings

__all__ = ["Pool", "Response", "Unsupported", "proxy_for", "STALE", "MAX_IDLE", "IDLE_SECONDS"]

MAX_IDLE = 8
IDLE_SECONDS = 30.0

#: What a request on a connection the server has closed raises.
STALE = (http.client.RemoteDisconnected, http.client.BadStatusLine, ConnectionResetError, ConnectionAbortedError,
         BrokenPipeError, ssl.SSLEOFError, ssl.SSLZeroReturnError)


class Unsupported(Exception):
    """A request this pool does not carry: the caller uses `urllib`."""


def proxy_for(url, env_proxies=None):
    """-> None (reach the host directly), or `(host, port, headers)` of the http proxy to tunnel
    an https URL through. Raises Unsupported for a proxy this module does not speak to."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    try:
        if urllib.request.proxy_bypass(host):
            return None
    except (OSError, ValueError):
        pass
    proxies = urllib.request.getproxies() if env_proxies is None else env_proxies
    proxy = proxies.get(parts.scheme)
    if not proxy:
        return None
    p = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
    if parts.scheme != "https" or p.scheme != "http" or not p.hostname:
        raise Unsupported(f"a {p.scheme or 'plain'} proxy for a {parts.scheme} URL")
    headers = {}
    if p.username is not None:
        who = urllib.parse.unquote(p.username) + ":" + urllib.parse.unquote(p.password or "")
        headers["Proxy-Authorization"] = "Basic " + base64.b64encode(who.encode("utf-8")).decode("ascii")
    return p.hostname, p.port or 80, headers


class Response:
    """What `Pool.request` answers: `status`, `reason`, `headers` (`.get` is case-insensitive), `url`,
    `read(n)`, `read1(n)` (at most one read of the socket: what has come) and `close()`; a context
    manager. Read to its end, it gives its connection back to the pool; closed before that, it
    closes the connection."""

    def __init__(self, pool, key, conn, raw, url, deadline=None):
        self._pool, self._key, self._conn, self._raw = pool, key, conn, raw
        self.status, self.reason, self.headers, self.url = raw.status, raw.reason, raw.msg, url
        self._deadline = deadline
        self._done = False

    def _finish(self):
        """The body has ended (`read` and `read1` call this once): the connection goes back to the
        pool unless the server said it would close it, the body ended short of its length (a peer
        that hung up, or a deadline's watchdog that shut the socket down: http.client reads either
        as an end), or the deadline has shut it down."""
        self._done = True
        conn, self._conn = self._conn, None
        released = self._deadline is None or self._deadline.release(conn.sock)
        if self._raw.will_close or self._raw.length or not released:
            conn.close()
        else:
            self._pool._give(self._key, conn)

    def read(self, amt=None):
        if self._done:
            return b""
        try:
            data = self._raw.read(amt)
        except BaseException:
            self.close()
            raise
        if self._raw.isclosed():
            self._finish()
        return data

    def read1(self, amt=-1):
        if self._done:
            return b""
        try:
            data = self._raw.read1(amt)
        except BaseException:
            self.close()
            raise
        if self._raw.length == 0 and not self._raw.isclosed():
            self._raw.close()                               # (Python before 3.11: read1 leaves a body read to its length open)
        if self._raw.isclosed():
            self._finish()
        return data

    def drain(self, limit=64 * 1024):
        """Read what is left of a small body (a redirect's, an error's) so that the connection can go
        back. A larger one is not read to its end: the `close()` that follows closes the connection."""
        left = limit
        while not self._done and left > 0:
            chunk = self.read(min(left, 16 * 1024))
            if not chunk:
                break
            left -= len(chunk)

    def close(self):
        if self._done:
            return
        self._done = True
        self._raw.close()                                   # (a response that will close keeps reading from its socket's file)
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Pool:
    """Idle connections by (scheme, host, port, proxy). Any number of threads may call `request`; a
    connection is used by one at a time."""

    def __init__(self, context=None, max_idle=MAX_IDLE, idle_seconds=IDLE_SECONDS, clock=time.monotonic):
        self._context = context
        self._max_idle, self._idle_seconds, self._clock = max_idle, idle_seconds, clock
        self._lock = threading.Lock()
        self._idle = {}                                     # key -> [(connection, last used)], oldest first
        self.stats = {"new": 0, "reused": 0, "stale": 0}

    def _tls(self):
        if self._context is None:
            self._context = nativenet.tls_context()
        return self._context

    # ---- the idle list
    def _take(self, key):
        now = self._clock()
        with self._lock:
            items = self._idle.get(key) or []
            while items:
                conn, last = items.pop()
                if now - last <= self._idle_seconds and conn.sock is not None:
                    return conn
                conn.close()
        return None

    def _give(self, key, conn):
        with self._lock:
            items = self._idle.setdefault(key, [])
            if len(items) >= self._max_idle or conn.sock is None:
                spare = conn
            else:
                items.append((conn, self._clock()))
                spare = None
        if spare is not None:
            spare.close()

    def _drop(self, key):
        with self._lock:
            held = [c for c, _ in self._idle.pop(key, [])]
        for conn in held:
            conn.close()

    def idle(self):
        with self._lock:
            return sum(len(v) for v in self._idle.values())

    def close(self):
        with self._lock:
            held, self._idle = [c for items in self._idle.values() for c, _ in items], {}
        for conn in held:
            conn.close()

    # ---- connections
    def _connect(self, scheme, host, port, via, timeout, deadline=None):
        if scheme == "https":
            if via:
                conn = http.client.HTTPSConnection(via[0], via[1], timeout=timeout, context=self._tls())
                conn.set_tunnel(host, port, headers=via[2])
            else:
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=self._tls())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        if deadline is not None:
            conn._create_connection = deadline.connect      # (the TCP connection, the tunnel and TLS within its time)
        try:
            with timings.span("network", "connect"):
                conn.connect()
            if deadline is not None:
                deadline.using(conn.sock)
        except BaseException:
            conn.close()
            raise
        return conn

    def request(self, url, headers, timeout, via=None, deadline=None):
        """One GET of `url` with `headers` -> Response (any status: the caller decides what a 404 or a
        redirect means). `via` is `proxy_for`'s answer. `deadline` (guard._Deadline): the download's
        whole time, which the connection, the request, the answer's head and its body are held to.
        OSError and `http.client.HTTPException` are the caller's to turn into its own errors."""
        parts = urllib.parse.urlsplit(url)
        scheme, host = parts.scheme, parts.hostname
        if scheme not in ("http", "https") or not host:
            raise Unsupported(f"not an http(s) URL: {scheme!r}")
        port = parts.port or (443 if scheme == "https" else 80)
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        key = (scheme, host, port, via[:2] if via else None)
        fresh = False
        for attempt in (0, 1):
            conn = None if fresh else self._take(key)
            reused = conn is not None
            if conn is None:
                conn = self._connect(scheme, host, port, via, timeout, deadline)
            else:
                conn.timeout = timeout
                try:
                    if deadline is None:
                        conn.sock.settimeout(timeout)
                    else:
                        conn.sock.settimeout(deadline.timeout(timeout))
                        deadline.watch(conn.sock)
                        deadline.using(conn.sock)
                except BaseException:
                    conn.close()
                    raise
            try:
                conn.request("GET", target, headers=headers)
                raw = conn.getresponse()
            except STALE:
                conn.close()
                if deadline is not None and deadline.expired():
                    raise                                   # (the deadline's watchdog shut it down: not stale)
                if reused and attempt == 0:
                    self._drop(key)                          # what one idle connection found, the others will too
                    with self._lock:
                        self.stats["stale"] += 1
                    fresh = True
                    continue
                raise
            except BaseException:
                conn.close()
                raise
            with self._lock:
                self.stats["reused" if reused else "new"] += 1
            timings.add("connections", 0.0, "reused" if reused else "new")
            return Response(self, key, conn, raw, url, deadline)
        raise AssertionError("unreachable")                 # (the second attempt raises or returns)
