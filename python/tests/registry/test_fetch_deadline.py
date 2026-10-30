"""A download's deadline covers the whole request and holds while a read is pending (F-07, the external review of
Oct 18, P2).

`guard.download_deadline()` (GR-3: 15 minutes, `LAZARET_GUARD_DOWNLOAD_SECONDS`) is the longest one download may take.
On urllib's path and the pool's (`--keepalive`; the native transport has its own total timeout) it began once the
response was open, so the connection, the redirects and the headers were outside it, and it was checked only after
`read(64 KiB)` or `read(1 MiB)` returned: a buffered read waits until it has its bytes, and a socket's timeout starts
again with every byte, so a server that drips its bytes kept a download going long past it (the review's server sending
100 bytes over a second, with a 0.1 s deadline and a 0.2 s socket timeout: 1.007 s). Now the deadline (guard._Deadline)
runs from before the request, a watchdog shuts the connection down when it is up, whatever call waits on it, each read
of the body waits at most the time left and returns what has come, and a body the watchdog ended is an error, never a
download.

Each test runs a server on 127.0.0.1 in a thread, which answers from a script of bytes and pauses (no other network).
The deadline is patched to fractions of a second (its setting takes whole seconds). A download must end with the
deadline's error within ALLOWANCE of it, and every hostile script lasts 4 s or more, so a download that waits for the
script fails the bound however generous the allowance. WatchdogTests hold the shapes only the watchdog ends in time
(each fails with its `_fire` a no-op); the others are held by the time cut on each call too."""

import hashlib
import http.client
import io
import os
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from lazaret.registry import goproxy, guard, repo
from tests.registry.test_guard import options

DEADLINE = 0.2      # the download's seconds
TIMEOUT = 0.5       # each socket call's (the fetcher's timeout): more than the deadline, and no drip's pause trips it
#: past the deadline: the watchdog thread's turn and the error's way out on a loaded runner (alone, 0.2 s deadlines end
#: by 0.21 s; a 2-vCPU machine running four CPU-bound processes once took 1.37 s)
ALLOWANCE = 1.5
CLOSE = (None, 0)   # a script's step: the server closes the connection (a body that ends when the connection does)
BODY = bytes(range(256)) * 1200                 # 300 KiB
#: Windows: the watchdog's shutdown does not wake a call that already waits on a silent socket (Python waits on a
#: socket with a timeout in select(), and Winsock's select() does not see a shutdown made here; a call that has
#: something to read once the time is up ends at once, as the drips' tests show). CI's windows-2025 (PR #17, Oct 29):
#: a recv waited out its 10 s timeout through the shutdown and one begun after it its 5 s, and a head dripped then
#: silent ended at 3.92 s, its socket's timeout cut to the time left when it connected, for a 2 s deadline. The
#: download still fails with the deadline's error, at most that timeout late. A gap in the product there, not in the
#: tests: the tests of it are expected to fail on Windows (`until_the_watchdog_wakes`), so that one passing (the gap
#: closed) fails the run until its mark goes.
WATCHDOG_WAKES = sys.platform != "win32"


def until_the_watchdog_wakes(test):
    """A test of the watchdog waking a call that waits: an expected failure where it cannot (WATCHDOG_WAKES)."""
    return test if WATCHDOG_WAKES else unittest.expectedFailure(test)


def head(status=200, headers=(), length=None):
    reason = {200: "OK", 302: "Found", 404: "Not Found"}.get(status, "Status")
    lines = [f"HTTP/1.1 {status} {reason}"] + [f"{k}: {v}" for k, v in headers]
    if length is not None:
        lines.append(f"Content-Length: {length}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")


def drip(data, pause):
    """A step for each byte of data, `pause` seconds after it."""
    return [(data[i:i + 1], pause) for i in range(len(data))]


def wait_for(condition, seconds=10.0):
    """Has condition() come true within `seconds` (polled: a loaded machine's threads are late)?"""
    end = time.monotonic() + seconds
    while not condition():
        if time.monotonic() > end:
            return False
        time.sleep(0.01)
    return True


class ScriptServer:
    """An HTTP/1.1 server on 127.0.0.1 that answers a path from its script: (bytes, pause) steps sent in turn, each
    followed by its pause; CLOSE ends the connection, else it stays open for the next request (urllib's ask to close
    is the client's to keep). `tls`: (certificate, key), the answers over TLS. `close()` stops what is being sent."""

    def __init__(self, routes, tls=None):
        self.routes, self.done, self.connections = routes, threading.Event(), 0
        self.context = None
        if tls is not None:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.context.load_cert_chain(*tls)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.host = f"{'localhost' if tls else '127.0.0.1'}:{self.port}"
        self.url = f"{'https' if tls else 'http'}://{self.host}"
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        buf = b""
        try:
            conn.settimeout(10)
            if self.context is not None:
                conn = self.context.wrap_socket(conn, server_side=True)
            while not self.done.is_set():
                while b"\r\n\r\n" not in buf:
                    data = conn.recv(4096)
                    if not data:
                        return
                    buf += data
                first, buf = buf.split(b"\r\n\r\n", 1)
                path = first.split(b"\r\n", 1)[0].split(b" ")[1].decode("ascii")
                for data, pause in self.routes.get(path, [(head(404, length=0), 0)]):
                    if data is None or self.done.is_set():
                        return
                    if data:
                        conn.sendall(data)
                    if pause:
                        self.done.wait(pause)
        except (OSError, ssl.SSLError):
            pass                                            # (a client that gave up)
        finally:
            conn.close()

    def close(self):
        self.done.set()
        self.listener.close()


class SlowRelay:
    """A TCP relay to `port` on 127.0.0.1 that hands the client what the server sends a byte every `pause` seconds (and
    the server what the client sends as it comes): a TLS handshake dripped."""

    def __init__(self, port, pause):
        self.target, self.pause, self.done = port, pause, threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            server = socket.create_connection(("127.0.0.1", self.target), timeout=10)
            threading.Thread(target=self._pipe, args=(client, server, 0), daemon=True).start()
            threading.Thread(target=self._pipe, args=(server, client, self.pause), daemon=True).start()

    def _pipe(self, src, dst, pause):
        try:
            src.settimeout(10)
            while not self.done.is_set():
                data = src.recv(4096)
                if not data:
                    break
                for piece in (drip(data, pause) if pause else [(data, 0)]):
                    if self.done.is_set():
                        break
                    dst.sendall(piece[0])
                    if pause:
                        self.done.wait(pause)
        except OSError:
            pass
        finally:
            src.close()
            dst.close()

    def close(self):
        self.done.set()
        self.listener.close()


def redirects(prefix, last, slow_head=None, pause=0.0):
    """Routes prefix0 -> prefix1 -> prefix2 -> prefix3 (repo.MAX_REDIRECTS hops), prefix3 answering `last`; each answer
    `pause` seconds late, or its head dripped a byte every `slow_head` seconds."""
    routes = {}
    for n in range(repo.MAX_REDIRECTS + 1):
        answer = last if n == repo.MAX_REDIRECTS else head(302, [("Location", f"{prefix}{n + 1}")], length=0)
        routes[f"{prefix}{n}"] = drip(answer, slow_head) if slow_head else [(b"", pause), (answer, 0)]
    return routes


CHUNKED = [("Transfer-Encoding", "chunked")]
ROUTES = {
    # a body of 200 bytes, one every 20 ms: 4 s
    "/body": [(head(length=200), 0)] + drip(b"x" * 200, 0.02),
    # the review's (bytes every 10 ms; its 100 bytes took 1.007 s), held 4 s
    "/review": [(head(length=400), 0)] + drip(b"x" * 400, 0.01),
    # no length: the body ends when the connection does, and the watchdog's shutdown must not read as that end
    "/until-close": [(head(), 0)] + drip(b"x" * 200, 0.02) + [CLOSE],
    "/chunked": [(head(headers=CHUNKED), 0)] + drip(b"1\r\nx\r\n" * 80 + b"0\r\n\r\n", 0.01),
    # the status line and headers, a byte every 20 ms: 4.8 s
    "/head": drip(head(headers=[("X-Pad", "a" * 200)], length=2) + b"ok", 0.02),
    # an accepted connection and nothing said
    "/mute": [(b"", 5)],
    # part of a head over 1.85 s, then nothing: for a deadline longer than that
    "/head-then-silence": drip(b"HTTP/1.1 200 OK\r\nX-Pad: " + b"a" * 14, 0.05) + [(b"", 10)],
    # a chunk's size line whose extension is dripped (http.client reads the line in one call): 4 s
    "/chunk-ext": [(head(headers=CHUNKED) + b"2;", 0)] + drip(b"a" * 200, 0.02) + [(b"\r\nok\r\n0\r\n\r\n", 0)],
    # the trailer, a line every 50 ms (read in one call, as many lines as come): 4 s
    "/trailer": [(head(headers=CHUNKED) + b"2\r\nok\r\n0\r\n", 0)] + [(b"X-T: y\r\n", 0.05)] * 80 + [(b"\r\n", 0)],
    # "100 Continue" every 50 ms (http.client skips each in the call that reads the head): 4 s
    "/continue": [(head(100), 0.05)] * 80 + [(head(length=2) + b"ok", 0)],
    # a redirect whose body ends with its connection, dripped (urllib reads the watchdog's end as its end), then a
    # host whose name is never to be looked up
    "/redirect-dripped": [(head(302, [("Location", "http://slow-name.invalid:9/fast")]), 0)] + drip(b"y" * 200, 0.02)
    + [CLOSE],
    "/hold": [(head(length=2), 0.3), (b"ok", 0)],
    "/slow-head": drip(head(length=2) + b"ok", 0.05),
    # the head, then nothing
    "/stall": [(head(length=100), 5)],
    "/fast": [(head(length=len(BODY)) + BODY, 0)],
    "/huge": [(head(length=10 ** 12) + b"0123456789", 0), (b"", 5)],
    "/short": [(head(length=100) + b"0123456789", 0), CLOSE],
    "/no-length": [(head() + BODY, 0), CLOSE],
}
ROUTES.update(redirects("/hop", head(length=2) + b"ok", pause=0.15))          # each hop answers 0.15 s late: 0.6 s
ROUTES.update(redirects("/drip-hop", head(length=2) + b"ok", slow_head=0.02))  # each hop's head dripped: about 4.5 s
ROUTES.update(redirects("/fast-hop", head(length=len(BODY)) + BODY))
ROUTES["/example.test/m/@v/v1.0.0.zip"] = ROUTES["/body"]


class _Case(unittest.TestCase):
    PATHS = ((False, "urllib"), (True, "the pool"))

    @classmethod
    def setUpClass(cls):
        cls.server = ScriptServer(ROUTES)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.folder)

    def fetcher(self, keepalive, server=None):
        f = guard.Fetcher({(server or self.server).host}, keepalive=keepalive)
        self.addCleanup(f.close)
        return f

    def calls(self, f, url, timeout=TIMEOUT, max_bytes=10 * 1024 * 1024):
        """(name, a call of fetch or fetch_to_file on url) for each: both read the body within the deadline."""
        path = os.path.join(self.folder, "x")
        yield "fetch", lambda: f.fetch(url, max_bytes, timeout=timeout)
        yield "fetch_to_file", lambda: f.fetch_to_file(url, path, max_bytes, timeout=timeout)

    def assert_stops_in_time(self, path, deadline=DEADLINE, timeout=TIMEOUT, host=None, names=None, hosts=()):
        """fetch and fetch_to_file of path (on `host`, the server's by default; `names`: only these calls), on both
        paths, end with the deadline's error within ALLOWANCE of it."""
        host = host or self.server.host
        url = f"{self.server.url.split(':', 1)[0]}://{host}{path}"
        for keepalive, label in self.PATHS:
            f = guard.Fetcher({host, *hosts}, http_hosts=hosts, keepalive=keepalive)
            self.addCleanup(f.close)
            for name, call in self.calls(f, url, timeout):
                if names is not None and name not in names:
                    continue
                with self.subTest(path=path, transport=label, call=name), \
                        mock.patch.object(guard, "download_deadline", return_value=deadline):
                    started = time.monotonic()
                    with self.assertRaises(repo.FetchError) as caught:
                        call()
                    took = time.monotonic() - started
                    self.assertEqual(str(caught.exception), f"the download took over {deadline} s: {url}")
                    self.assertLess(took, deadline + ALLOWANCE, f"{took:.3f} s for a {deadline} s deadline")
                    self.assertGreaterEqual(took, deadline * 0.9)


class BodyTests(_Case):
    def test_a_body_dripped_stops_at_the_deadline(self):
        self.assert_stops_in_time("/body")                      # (before: the whole drip)

    def test_the_reviews_shape(self):
        self.assert_stops_in_time("/review", deadline=0.1, timeout=0.2)     # (before: the whole drip)

    def test_a_body_that_ends_with_its_connection_is_not_ended_by_the_watchdog(self):
        # (fail closed: the shutdown reads as the end of such a body; what came before it is no download)
        self.assert_stops_in_time("/until-close")

    def test_a_chunked_body_dripped(self):
        self.assert_stops_in_time("/chunked")

    def test_a_read_waits_no_longer_than_the_time_left(self):
        # (without the watchdog, a read of the body still waits at most the time left, not the socket's 0.5 s timeout,
        # and the deadline is checked between reads: the second line of defence)
        with mock.patch.object(guard._Deadline, "_fire", lambda self: None):
            self.assert_stops_in_time("/stall")
            self.assert_stops_in_time("/body")


class HeadTests(_Case):
    def test_headers_dripped_stop_at_the_deadline(self):
        self.assert_stops_in_time("/head")                      # (before: the whole drip, and the body taken)

    def test_a_server_that_says_nothing_meets_the_deadline_not_the_socket_timeout(self):
        self.assert_stops_in_time("/mute")                      # (before: the 0.5 s timeout's "timed out")


class WatchdogTests(_Case):
    """What only the watchdog ends at the deadline: data that keeps coming within one call of http.client, which the
    time cut on each socket call cannot stop (a header line, a chunk's size line, the trailer, "100 Continue" answers),
    and a call that waits on a socket whose timeout, cut to the time left when it was connected, outlasts the stop.
    Each of these fails with the watchdog off."""

    @until_the_watchdog_wakes
    def test_a_head_dripped_then_silent(self):
        # (the socket's timeout is the fetcher's 5 s cut to the time left at its connection, 2 s: the read waiting from
        # 1.85 s would end at 3.85 s, past the bound; the watchdog ends it at 2 s, nothing coming to wake it)
        self.assert_stops_in_time("/head-then-silence", deadline=2.0, timeout=5.0, names=("fetch",))

    def test_a_chunk_size_line_dripped(self):
        self.assert_stops_in_time("/chunk-ext")

    def test_a_trailer_dripped(self):
        self.assert_stops_in_time("/trailer")

    def test_a_flood_of_100_continue(self):
        self.assert_stops_in_time("/continue")

    @until_the_watchdog_wakes
    def test_it_wakes_a_call_waiting_on_its_socket(self):
        d = guard._Deadline(DEADLINE, "u")
        self.addCleanup(d.close)
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(10)
        d.watch(a)
        started = time.monotonic()
        try:
            got = a.recv(10)                                    # (the watchdog shut it down: the end)
        except socket.timeout:
            self.fail("the watchdog did not wake the call")
        except OSError:
            got = b""                                           # (Windows: WSAESHUTDOWN)
        self.assertEqual(got, b"")
        self.assertLess(time.monotonic() - started, DEADLINE + ALLOWANCE)


class RedirectTests(_Case):
    def test_no_hop_after_the_deadline_not_even_its_name_looked_up(self):
        # (urllib takes the end of the redirect's body that the watchdog made for its end and follows the Location; the
        # pool checks the deadline after the body: neither looks the next host up, which could take the resolver's time)
        looked = []
        real = socket.getaddrinfo

        def lookup(host, *args, **kwargs):
            looked.append(host)
            return real(host, *args, **kwargs)

        with mock.patch.object(socket, "getaddrinfo", lookup):
            self.assert_stops_in_time("/redirect-dripped", hosts=("slow-name.invalid:9",))
        self.assertNotIn("slow-name.invalid", looked)

    def test_a_redirect_is_not_followed_once_the_time_is_up(self):
        f = self.fetcher(False)
        (handler,) = [h for h in f._opener(self.server.url).handlers
                      if isinstance(h, urllib.request.HTTPRedirectHandler)]
        req = urllib.request.Request(self.server.url + "/hop0")
        req.lazaret_deadline = guard._Deadline(0, "u")
        with self.assertRaisesRegex(urllib.error.URLError, "are up"):
            handler.redirect_request(req, None, 302, "Found", {}, self.server.url + "/hop1")

    def test_slow_hops_count_against_the_deadline(self):
        self.assert_stops_in_time("/hop0")                      # (before: 0.6 s, and the body taken)

    def test_hops_with_dripped_heads(self):
        self.assert_stops_in_time("/drip-hop0")                 # (before: 4.5 s, and the body taken)

    def test_hops_within_the_deadline_are_followed(self):
        for keepalive, label in self.PATHS:
            with self.subTest(transport=label):
                body, _ = self.fetcher(keepalive).fetch(self.server.url + "/fast-hop0")
                self.assertEqual(body, BODY)


class NormalTests(_Case):
    def test_a_fast_download(self):
        for keepalive, label in self.PATHS:
            f = self.fetcher(keepalive)
            path = os.path.join(self.folder, f"x-{keepalive}")
            with self.subTest(transport=label):
                body, headers = f.fetch(self.server.url + "/fast")
                self.assertEqual((body, headers.get("Content-Length")), (BODY, str(len(BODY))))
                size, sha = f.fetch_to_file(self.server.url + "/fast", path, len(BODY))
                self.assertEqual((size, sha), (len(BODY), hashlib.sha256(BODY).hexdigest()))
                with open(path, "rb") as fh:
                    self.assertEqual(fh.read(), BODY)

    def test_a_fast_download_within_a_short_deadline(self):
        with mock.patch.object(guard, "download_deadline", return_value=5):
            for keepalive, label in self.PATHS:
                with self.subTest(transport=label):
                    size, sha = self.fetcher(keepalive).fetch_to_file(self.server.url + "/fast",
                                                                      os.path.join(self.folder, "x"), len(BODY))
                    self.assertEqual((size, sha), (len(BODY), hashlib.sha256(BODY).hexdigest()))

    def test_the_watchdog_ends_with_the_download(self):
        before = time.monotonic()
        for keepalive, _ in self.PATHS:
            f = self.fetcher(keepalive)
            f.get(self.server.url + "/fast")
            with self.assertRaises(repo.FetchError):
                f.get(self.server.url + "/short")
        while time.monotonic() - before < 2 and any(t.name == "lazaret-download-deadline" for t in threading.enumerate()):
            time.sleep(0.01)
        self.assertEqual([t for t in threading.enumerate() if t.name == "lazaret-download-deadline"], [])

    def test_the_pool_still_reuses_a_connection(self):
        server = ScriptServer(ROUTES)
        self.addCleanup(server.close)
        f = self.fetcher(True, server)
        for _ in range(3):
            self.assertEqual(f.get(server.url + "/fast"), BODY)
        self.assertEqual((server.connections, f.pool.idle()), (1, 1))
        self.assertEqual(f.pool.stats, {"new": 1, "reused": 2, "stale": 0})

    def test_a_body_the_watchdog_ended_does_not_give_its_connection_back(self):
        server = ScriptServer(ROUTES)
        self.addCleanup(server.close)
        f = self.fetcher(True, server)
        with mock.patch.object(guard, "download_deadline", return_value=DEADLINE), \
                self.assertRaisesRegex(repo.FetchError, "the download took over"):
            f.get(server.url + "/body", timeout=TIMEOUT)
        self.assertEqual(f.pool.idle(), 0)
        self.assertEqual(f.get(server.url + "/fast"), BODY)        # (on a new connection)
        self.assertEqual(server.connections, 2)

    def test_a_reused_connection_the_watchdog_shut_is_not_stale(self):
        # (a stale one costs the host's other idle connections; the deadline's is this download's alone)
        server = ScriptServer(ROUTES)
        self.addCleanup(server.close)
        f = self.fetcher(True, server)
        threads = [threading.Thread(target=f.get, args=(server.url + "/hold",)) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual((f.pool.idle(), f.pool.stats["new"]), (3, 3))
        with mock.patch.object(guard, "download_deadline", return_value=DEADLINE), \
                self.assertRaisesRegex(repo.FetchError, "the download took over"):
            f.get(server.url + "/slow-head", timeout=TIMEOUT)
        self.assertEqual((f.pool.idle(), f.pool.stats), (2, {"new": 3, "reused": 0, "stale": 0}))

    def test_a_watchdog_that_cannot_start_fails_the_download(self):
        with mock.patch.object(threading.Timer, "start", side_effect=RuntimeError("can't start new thread")):
            for keepalive, label in self.PATHS:
                f = self.fetcher(keepalive)
                for name, call in self.calls(f, self.server.url + "/fast"):
                    with self.subTest(transport=label, call=name), \
                            self.assertRaisesRegex(repo.FetchError, r"watchdog could not start \(can't start new"):
                        call()

    def test_the_byte_budget_and_the_length_are_held_as_before(self):
        for keepalive, label in self.PATHS:
            f = self.fetcher(keepalive)
            for name, call in self.calls(f, self.server.url + "/huge", max_bytes=3 * 1024 * 1024):
                with self.subTest(transport=label, call=name), self.assertRaises(guard.TooLarge) as caught:
                    call()                                  # (the declared length, before the body: no 5 s wait)
                self.assertEqual(str(caught.exception), f"response over 3MB: {self.server.url}/huge")
            for name, call in self.calls(f, self.server.url + "/no-length", max_bytes=len(BODY) - 1):
                with self.subTest(transport=label, call=name), self.assertRaises(guard.TooLarge):
                    call()                                  # (no length: held as it is read)
            for name, call in self.calls(f, self.server.url + "/short"):
                with self.subTest(transport=label, call=name), \
                        self.assertRaisesRegex(repo.FetchError, r"^incomplete response \(10 of 100 bytes\)"):
                    call()
            self.assertEqual(f.get(self.server.url + "/no-length", max_bytes=len(BODY)), BODY)


class TlsTests(_Case):
    """Over TLS on Python's transport (the native one is set aside here). An SSL socket's pending read is woken by the
    watchdog too: dripped headers, which http.client reads in many calls, each waiting up to the socket's timeout,
    need it. A dripped handshake does not: Python keeps the socket's timeout (cut to the time left when it was
    connected) as one limit for the whole handshake."""

    @classmethod
    def setUpClass(cls):
        from tests.scanner.test_nativenet import make_pki
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root, cert, key = make_pki(cls.tmp.name)
        cls.server = ScriptServer(ROUTES, tls=(cert, key))
        cls.relay = SlowRelay(cls.server.port, 0.02)

    @classmethod
    def tearDownClass(cls):
        cls.relay.close()
        cls.server.close()
        cls.tmp.cleanup()

    def setUp(self):
        super().setUp()
        for patch in (mock.patch.object(guard.nativenet, "chosen", return_value=False),
                      mock.patch.object(ssl, "_create_default_https_context",
                                        lambda: ssl.create_default_context(cadata=self.root))):
            patch.start()
            self.addCleanup(patch.stop)

    def test_a_download(self):
        for keepalive, label in self.PATHS:
            with self.subTest(transport=label):
                size, sha = self.fetcher(keepalive).fetch_to_file(self.server.url + "/fast",
                                                                  os.path.join(self.folder, "x"), len(BODY))
                self.assertEqual((size, sha), (len(BODY), hashlib.sha256(BODY).hexdigest()))

    def test_a_body_dripped(self):
        self.assert_stops_in_time("/body")

    def test_headers_dripped(self):
        self.assert_stops_in_time("/head")

    def test_a_handshake_dripped(self):
        self.assert_stops_in_time("/fast", host=f"localhost:{self.relay.port}")


class GoRelayTests(_Case):
    def test_a_zip_past_the_deadline_is_blocked_and_its_spooled_bytes_removed(self):
        ctx = guard.Context(options(tool="go", min_age=0), out=io.StringIO())
        self.addCleanup(ctx.close)
        spool = os.path.join(self.folder, "spool")
        os.mkdir(spool)
        relay = guard.GoRelay(ctx, self.fetcher(False), [goproxy.Proxy(self.server.url + "/", False)], spool)
        started = time.monotonic()
        with mock.patch.object(guard, "download_deadline", return_value=DEADLINE):
            check, spooled = relay._scan(goproxy.parse_request("/example.test/m/@v/v1.0.0.zip"))
        self.assertLess(time.monotonic() - started, DEADLINE + ALLOWANCE)      # (its socket timeout is 60 s)
        self.assertIsNone(spooled)
        self.assertEqual(os.listdir(spool), [])
        self.assertEqual(check.blocked, [f"could not be checked: the download took over {DEADLINE} s: "
                                         f"{self.server.url}/example.test/m/@v/v1.0.0.zip"])


class GoRelayWatchdogTests(_Case):
    def test_a_watchdog_that_cannot_start_blocks_the_zip_and_leaves_nothing(self):
        ctx = guard.Context(options(tool="go", min_age=0), out=io.StringIO())
        self.addCleanup(ctx.close)
        spool = os.path.join(self.folder, "spool")
        os.mkdir(spool)
        relay = guard.GoRelay(ctx, self.fetcher(False), [goproxy.Proxy(self.server.url + "/", False)], spool)
        with mock.patch.object(threading.Timer, "start", side_effect=RuntimeError("can't start new thread")):
            check, spooled = relay._scan(goproxy.parse_request("/example.test/m/@v/v1.0.0.zip"))
        self.assertIsNone(spooled)
        self.assertEqual(os.listdir(spool), [])
        (reason,) = check.blocked
        self.assertIn("watchdog could not start", reason)

    def test_whatever_else_stops_the_scan_leaves_nothing_in_the_spool(self):
        ctx = guard.Context(options(tool="go", min_age=0), out=io.StringIO())
        self.addCleanup(ctx.close)
        spool = os.path.join(self.folder, "spool")
        os.mkdir(spool)
        fetcher = mock.Mock(fetch_to_file=mock.Mock(side_effect=MemoryError()))
        relay = guard.GoRelay(ctx, fetcher, [goproxy.Proxy(self.server.url + "/", False)], spool)
        with self.assertRaises(MemoryError):
            relay._scan(goproxy.parse_request("/example.test/m/@v/v1.0.0.zip"))
        self.assertEqual(os.listdir(spool), [])


class DeadlineTests(unittest.TestCase):
    def test_a_socket_watched_once_the_time_is_up_is_refused(self):
        d = guard._Deadline(0.05, "u")
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        d.watch(a)
        self.assertTrue(wait_for(lambda: d._fired), "the watchdog did not fire")
        self.assertTrue(d.expired())
        with self.assertRaises(TimeoutError):
            d.watch(b)
        with self.assertRaises(TimeoutError):
            d.wait(5)
        with self.assertRaisesRegex(repo.FetchError, r"^the download took over 0\.05 s: u$"):
            d.check()
        if WATCHDOG_WAKES:
            a.settimeout(5)
            try:
                got = a.recv(10)                                # (the watchdog shut it down: the end, at once)
            except socket.timeout:
                self.fail("the socket was not shut down")
            except OSError:
                got = b""                                       # (the read refused: the end too)
        else:                                                   # (a read waits there: the other end sees it shut)
            b.settimeout(5)
            try:
                got = b.recv(10)
            except socket.timeout:
                self.fail("the socket was not shut down")
        self.assertEqual(got, b"")
        d.close()

    def test_the_time_left_cuts_a_timeout(self):
        d = guard._Deadline(10, "u")
        self.assertEqual(d.wait(1), (1, False))
        wait, cut = d.wait(60)
        self.assertTrue(cut and 9 < wait <= 10)
        self.assertTrue(d.wait(None)[1])
        d.close()

    def test_a_released_socket_is_not_shut_down(self):
        d = guard._Deadline(0.05, "u")
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        d.watch(a)
        self.assertTrue(d.release(a))
        self.assertTrue(wait_for(lambda: d._fired), "the watchdog did not fire")
        b.sendall(b"still open")
        self.assertEqual(a.recv(20), b"still open")
        d.close()

    def test_closed_it_fires_no_more(self):
        d = guard._Deadline(0.05, "u")
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        d.watch(a)
        d.close()
        time.sleep(0.3)
        b.sendall(b"x")
        self.assertEqual(a.recv(1), b"x")
        self.assertFalse(d._fired)

    def test_a_status_line_cut_short_is_the_deadlines_error(self):
        # (BadStatusLine is an HTTPException, which urllib hands on as it is)
        f = guard.Fetcher({"127.0.0.1:9"})
        self.addCleanup(f.close)
        d = guard._Deadline(0, "u")
        with mock.patch.object(f, "_opener", lambda url: mock.Mock(open=mock.Mock(
                side_effect=http.client.BadStatusLine("HTTP/1.1 2")))), \
                self.assertRaisesRegex(repo.FetchError, r"^the download took over 0 s: u$"):
            f.open("http://127.0.0.1:9/x", deadline=d)


if __name__ == "__main__":
    unittest.main()
