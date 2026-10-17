"""Connections that stay open (0.1.9, P-15): `lazaret.registry.keepalive` and `guard.Fetcher(keepalive=True)`.

A local HTTP/1.1 server counts the connections it is given and the requests on them, and can be told to
close, answer in HTTP/1.0, send a short or chunked body, close behind its answer without saying so (a stale
connection), or redirect. The pool must reuse a connection only when the response was read to its end and
the server did not close it; a stale one is retried once on a new connection; the guard's rules for
redirects and credentials stay the guard's, and a request the pool does not carry goes the old way.
TLS and a CONNECT proxy are tested with a certificate made by `openssl` when there is one."""

import contextlib
import http.client
import http.server
import io
import json
import os
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from unittest import mock

from lazaret.registry import guard, keepalive, pmsettings, repo
from lazaret.scanner import timings
from tests import _support

BODY = bytes(range(256)) * 4000                      # about 1 MB


class Server:
    """A keep-alive HTTP/1.1 server on 127.0.0.1 (optionally TLS) that counts connections and requests."""

    def __init__(self, tls=None):
        outer = self
        self.connections, self.log, self.lock = 0, [], threading.Lock()

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def setup(self):
                super().setup()
                with outer.lock:
                    outer.connections += 1

            def send(self, code, body=b"", headers=(), length=True):
                self.send_response(code)
                for k, v in headers:
                    self.send_header(k, v)
                if length:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                with outer.lock:
                    outer.log.append((self.path, {k: v for k, v in self.headers.items()}))
                path = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(path.query)
                p = path.path
                if p == "/ok":
                    self.send(200, b"hello")
                elif p == "/big":
                    self.send(200, BODY)
                elif p == "/chunked":
                    self.send_response(200)
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    for part in (b"abc", b"defgh", b""):
                        self.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                elif p == "/close":
                    self.send(200, b"bye", [("Connection", "close")])
                    self.close_connection = True
                elif p == "/http10":
                    self.wfile.write(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi")
                    self.close_connection = True
                elif p == "/silent":                    # an answer in good order, then the socket closes: a stale connection
                    self.send(200, b"quiet")
                    self.close_connection = True
                elif p == "/short":                     # fewer bytes than it promised
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
                    self.close_connection = True
                elif p == "/huge":                      # promises more than any budget, sends a little
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000000\r\n\r\n0123456789")
                    self.close_connection = True
                elif p == "/untilclose":                # no length: the body ends when the connection does
                    self.wfile.write(b"HTTP/1.1 200 OK\r\n\r\nuntil the end")
                    self.close_connection = True
                elif p == "/redirect":
                    self.send(int(query.get("code", ["302"])[0]), b"moved", [("Location", query["to"][0])])
                elif p == "/loop":
                    self.send(302, b"moved", [("Location", "/loop")])
                elif p == "/noloc":
                    self.send(302, b"moved")
                elif p.startswith("/status/"):
                    self.send(int(p.rsplit("/", 1)[1]), b"status body")
                elif p == "/errorwithlocation":                  # a Location on an answer that is not a redirect is not followed
                    self.send(404, b"nope", [("Location", "/ok")])
                elif p.startswith("/bigstatus/"):               # an error with a body too large to be read for the sake of a connection
                    self.send(int(p.rsplit("/", 1)[1]), BODY)
                elif p == "/echo":
                    self.send(200, json.dumps({k.lower(): v for k, v in self.headers.items()}).encode())
                else:
                    self.send(404, b"nope")

        class Plain(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):        # (a client that hangs up is not news)
                pass

        self.server = Plain(("127.0.0.1", 0), Handler)
        self.scheme = "http"
        if tls is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(*tls)
            self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
            self.scheme = "https"
        self.port = self.server.server_address[1]
        self.url = f"{self.scheme}://127.0.0.1:{self.port}"
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Proxy:
    """A CONNECT proxy: replies 200 and pipes bytes both ways; keeps the CONNECT requests it saw."""

    def __init__(self):
        self.seen, self.lock = [], threading.Lock()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            head = data.split(b"\r\n\r\n")[0].decode("latin-1")
            with self.lock:
                self.seen.append(head)
            target = head.split()[1]
            host, port = target.rsplit(":", 1)
            upstream = socket.create_connection((host, int(port)))
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            def pipe(a, b):
                try:
                    while True:
                        chunk = a.recv(65536)
                        if not chunk:
                            break
                        b.sendall(chunk)
                except OSError:
                    pass
                finally:
                    for s in (a, b):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
            threading.Thread(target=pipe, args=(conn, upstream), daemon=True).start()
            pipe(upstream, conn)
            upstream.close()
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.sock.close()


def make_certificate(folder):
    """-> (certfile, keyfile) for 127.0.0.1 and localhost, or None without openssl."""
    if shutil.which("openssl") is None:
        return None
    cert, key = os.path.join(folder, "cert.pem"), os.path.join(folder, "key.pem")
    run = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                          "-days", "2", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                         capture_output=True)
    return (cert, key) if run.returncode == 0 else None


@contextlib.contextmanager
def recording_connections():
    """The connections the pool makes, as a list, to see whether each was closed."""
    made = []

    def recording(real):
        def init(self, *args, **kwargs):
            real(self, *args, **kwargs)
            if not any(self is c for c in made):
                made.append(self)
        return init
    with contextlib.ExitStack() as stack:
        for cls in (http.client.HTTPConnection, http.client.HTTPSConnection):
            stack.enter_context(mock.patch.object(cls, "__init__", recording(cls.__init__)))
        yield made


class Mute:
    """A listening socket that accepts connections and does what `mode` says: "hold" them open and say nothing, or
    "hang up" at once."""

    def __init__(self, mode):
        self.mode, self.accepted, self.held = mode, 0, []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            if self.mode == "hold":
                self.held.append(conn)
            else:
                conn.close()

    def close(self):
        self.sock.close()
        for conn in self.held:
            conn.close()


def get(pool, url, headers=None, timeout=10, via=None, read=True):
    resp = pool.request(url, headers or {"User-Agent": "t"}, timeout, via)
    if read:
        body = resp.read()
        resp.close()
        return resp.status, body
    return resp


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.addCleanup(self.server.close)
        self.pool = keepalive.Pool()
        self.addCleanup(self.pool.close)

    def test_one_connection_serves_many_requests(self):
        for _ in range(5):
            self.assertEqual(get(self.pool, self.server.url + "/ok"), (200, b"hello"))
        self.assertEqual(self.server.connections, 1)
        self.assertEqual(self.pool.stats, {"new": 1, "reused": 4, "stale": 0})
        self.assertEqual(self.pool.idle(), 1)

    def test_a_body_read_in_pieces_is_read_to_its_end_and_gives_the_connection_back(self):
        resp = get(self.pool, self.server.url + "/big", read=False)
        got = b""
        while True:
            chunk = resp.read(64 * 1024)
            if not chunk:
                break
            got += chunk
        self.assertEqual(got, BODY)
        self.assertEqual(self.pool.idle(), 1)
        self.assertEqual(get(self.pool, self.server.url + "/ok")[0], 200)
        self.assertEqual(self.server.connections, 1)

    def test_a_chunked_body(self):
        self.assertEqual(get(self.pool, self.server.url + "/chunked"), (200, b"abcdefgh"))
        self.assertEqual(self.pool.idle(), 1)

    def test_a_response_closed_early_takes_its_connection_with_it(self):
        resp = get(self.pool, self.server.url + "/big", read=False)
        resp.read(10)
        resp.close()
        self.assertEqual(self.pool.idle(), 0)
        self.assertEqual(get(self.pool, self.server.url + "/ok")[0], 200)
        self.assertEqual(self.server.connections, 2)

    def test_the_context_manager_closes(self):
        with get(self.pool, self.server.url + "/big", read=False) as resp:
            resp.read(1)
        self.assertEqual((self.pool.idle(), resp.read()), (0, b""))

    def test_a_closed_response_reads_nothing_more(self):
        for path in ("/big", "/untilclose"):             # (a body that ends with the connection keeps its file open)
            with self.subTest(path):
                resp = get(self.pool, self.server.url + path, read=False)
                self.assertEqual(len(resp.read(5)), 5)
                resp.close()
                self.assertEqual((resp.read(), resp.read(5)), (b"", b""))
                resp.close()                                # twice is harmless
                self.assertEqual(self.pool.idle(), 0)

    def test_drain_gives_a_small_bodys_connection_back_and_stops_at_its_limit(self):
        small = get(self.pool, self.server.url + "/status/404", read=False)
        small.drain()
        self.assertEqual((small.read(), self.pool.idle()), (b"", 1))
        big = get(self.pool, self.server.url + "/big", read=False)
        self.assertEqual(self.server.connections, 1)         # (the small one's connection carried it)
        big.drain(limit=40 * 1024)
        self.assertEqual(len(big.read()), len(BODY) - 40 * 1024)
        big = get(self.pool, self.server.url + "/big", read=False)
        big.drain()
        self.assertEqual(len(big.read()), len(BODY) - 64 * 1024)
        big.close()

    def test_what_the_server_closes_is_not_reused(self):
        for path in ("/close", "/http10", "/untilclose"):
            with self.subTest(path):
                before = self.server.connections
                status, _ = get(self.pool, self.server.url + path)
                self.assertEqual((status, self.pool.idle()), (200, 0))
                self.assertEqual(get(self.pool, self.server.url + "/ok")[0], 200)
                self.assertEqual(self.server.connections, before + 2)
                self.pool.close()

    def test_a_short_body_is_an_error_and_not_reused(self):
        resp = get(self.pool, self.server.url + "/short", read=False)
        with self.assertRaises(http.client.IncompleteRead):
            resp.read()
        self.assertEqual(self.pool.idle(), 0)

    def test_a_stale_connection_is_retried_once_on_a_new_one(self):
        self.assertEqual(get(self.pool, self.server.url + "/silent"), (200, b"quiet"))
        self.assertEqual(self.pool.idle(), 1)                 # the server did not say it would close
        self.assertEqual(get(self.pool, self.server.url + "/ok"), (200, b"hello"))
        self.assertEqual(self.pool.stats["stale"], 1)
        self.assertEqual(self.server.connections, 2)
        # a request that found a reused connection stale asked the server once, not twice
        self.assertEqual([p for p, _ in self.server.log], ["/silent", "/ok"])

    def test_idle_connections_of_a_stale_host_are_all_dropped(self):
        resps = [get(self.pool, self.server.url + "/silent", read=False) for _ in range(3)]
        for r in resps:
            r.read()
        self.assertEqual(self.pool.idle(), 3)
        self.assertEqual(get(self.pool, self.server.url + "/ok")[0], 200)
        self.assertEqual(self.pool.idle(), 1)                 # the three went, the new one came back

    def test_a_new_connection_that_fails_is_the_callers_error(self):
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        with self.assertRaises(OSError):
            get(self.pool, f"http://127.0.0.1:{port}/ok")
        self.assertEqual(self.pool.stats, {"new": 0, "reused": 0, "stale": 0})

    def test_an_idle_connection_expires(self):
        now = [1000.0]
        pool = keepalive.Pool(idle_seconds=30, clock=lambda: now[0])
        self.addCleanup(pool.close)
        get(pool, self.server.url + "/ok")
        now[0] += 29
        get(pool, self.server.url + "/ok")
        self.assertEqual(pool.stats["reused"], 1)
        now[0] += 31
        get(pool, self.server.url + "/ok")
        self.assertEqual((pool.stats["reused"], pool.stats["new"]), (1, 2))
        self.assertEqual(self.server.connections, 2)

    def test_a_connection_is_good_for_exactly_its_idle_seconds(self):
        now = [1000.0]
        pool = keepalive.Pool(idle_seconds=30, clock=lambda: now[0])
        self.addCleanup(pool.close)
        get(pool, self.server.url + "/ok")
        now[0] += 30.0
        get(pool, self.server.url + "/ok")                    # (30 s since it was last used: still good)
        self.assertEqual((pool.stats["reused"], pool.stats["new"]), (1, 1))
        now[0] += 30.5
        get(pool, self.server.url + "/ok")
        self.assertEqual((pool.stats["reused"], pool.stats["new"]), (1, 2))

    def test_a_connection_is_made_when_asked_for_not_on_its_first_request(self):
        conn = self.pool._connect("http", "127.0.0.1", self.server.port, None, 5)
        self.addCleanup(conn.close)
        self.assertIsNotNone(conn.sock)

    def test_idle_connections_are_capped(self):
        pool = keepalive.Pool(max_idle=2)
        self.addCleanup(pool.close)
        held = [get(pool, self.server.url + "/ok", read=False) for _ in range(4)]
        for r in held:
            r.read()
        self.assertEqual(pool.idle(), 2)

    def test_the_defaults_are_eight_idle_connections_for_thirty_seconds(self):
        self.assertEqual((keepalive.MAX_IDLE, keepalive.IDLE_SECONDS), (8, 30.0))
        held = [get(self.pool, self.server.url + "/ok", read=False) for _ in range(10)]
        for r in held:
            r.read()
        self.assertEqual(self.pool.idle(), 8)
        self.assertEqual(self.pool._max_idle, 8)
        self.assertEqual(self.pool._idle_seconds, 30.0)

    def test_a_connection_over_the_cap_is_closed(self):
        pool = keepalive.Pool(max_idle=2)
        self.addCleanup(pool.close)
        made, real = [], pool._connect

        def connect(*args, **kwargs):
            made.append(real(*args, **kwargs))
            return made[-1]
        pool._connect = connect
        held = [get(pool, self.server.url + "/ok", read=False) for _ in range(4)]
        for r in held:
            r.read()
        self.assertEqual(len(made), 4)
        self.assertEqual([c.sock is not None for c in made].count(True), 2)

    def test_a_connection_without_a_socket_is_neither_kept_nor_taken(self):
        key = ("http", "127.0.0.1", 1, None)
        dead = http.client.HTTPConnection("127.0.0.1", 1)    # never connected
        self.pool._give(key, dead)
        self.assertEqual(self.pool.idle(), 0)
        self.pool._idle[key] = [(dead, self.pool._clock())]
        self.assertIsNone(self.pool._take(key))

    def test_the_tls_context_is_made_once_and_shared(self):
        first = self.pool._tls()
        self.assertIsInstance(first, ssl.SSLContext)
        self.assertIs(self.pool._tls(), first)
        mine = ssl.create_default_context()
        self.assertIs(keepalive.Pool(context=mine)._tls(), mine)

    def test_the_newest_idle_connection_is_taken_first(self):
        a = get(self.pool, self.server.url + "/ok", read=False)
        b = get(self.pool, self.server.url + "/ok", read=False)
        a.read()
        b.read()
        conn_b = self.pool._idle[next(iter(self.pool._idle))][-1][0]
        get(self.pool, self.server.url + "/ok")
        self.assertIs(self.pool._idle[next(iter(self.pool._idle))][-1][0], conn_b)

    def test_threads_share_it_without_mixing_answers(self):
        errors = []

        def work(i):
            try:
                for _ in range(25):
                    status, body = get(self.pool, self.server.url + "/ok")
                    if (status, body) != (200, b"hello"):
                        errors.append((status, body))
            except Exception as exc:                          # noqa: BLE001
                errors.append(exc)
        threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertLessEqual(self.server.connections, 8)
        self.assertEqual(self.pool.stats["new"] + self.pool.stats["reused"], 200)
        self.assertGreater(self.pool.stats["reused"], 150)

    def test_the_headers_sent_are_the_callers_and_the_response_headers_are_case_blind(self):
        resp = get(self.pool, self.server.url + "/echo", {"User-Agent": "ua", "Accept": "x/y"}, read=False)
        sent = json.loads(resp.read())
        self.assertEqual((sent["user-agent"], sent["accept"], sent["accept-encoding"]), ("ua", "x/y", "identity"))
        self.assertEqual(resp.headers.get("content-LENGTH"), str(len(json.dumps(sent))))
        self.assertEqual((resp.status, resp.reason), (200, "OK"))

    def test_the_target_keeps_its_query_and_a_path_is_never_empty(self):
        get(self.pool, self.server.url + "/echo?a=1&b=%20")
        self.assertEqual(self.server.log[-1][0], "/echo?a=1&b=%20")
        get(self.pool, self.server.url)                        # no path at all
        self.assertEqual(self.server.log[-1][0], "/")

    def test_what_it_does_not_carry(self):
        for url in ("ftp://127.0.0.1/x", "file:///etc/passwd", "http:///x", "//127.0.0.1/x"):
            with self.subTest(url), self.assertRaises(keepalive.Unsupported):
                self.pool.request(url, {}, 5)
        self.assertEqual(self.server.connections, 0)

    def test_close_closes_the_idle_ones_and_the_pool_still_works(self):
        get(self.pool, self.server.url + "/ok")
        self.pool.close()
        self.assertEqual(self.pool.idle(), 0)
        self.assertEqual(get(self.pool, self.server.url + "/ok")[0], 200)

    def test_timings_say_what_was_new_and_what_was_reused(self):
        with timings.capture() as t:
            for _ in range(3):
                get(self.pool, self.server.url + "/ok")
        report = t.report()["phases"]
        self.assertEqual(report["connections"]["by"], {"new": {"seconds": 0.0, "calls": 1},
                                                       "reused": {"seconds": 0.0, "calls": 2}})
        self.assertEqual(report["network"]["by"]["connect"]["calls"], 1)


def closed(conn):
    return conn.sock is None


class ResourceTests(unittest.TestCase):
    """Every connection the pool made is either idle in it or closed, whichever way a request ended."""

    def setUp(self):
        self.server = Server()
        self.addCleanup(self.server.close)
        self.pool = keepalive.Pool()
        self.addCleanup(self.pool.close)

    def test_a_response_closed_early_closes_its_connection_and_its_file(self):
        with recording_connections() as made:
            resp = get(self.pool, self.server.url + "/big", read=False)
            resp.read(10)
            raw = resp._raw
            resp.close()
        self.assertEqual([closed(c) for c in made], [True])
        self.assertTrue(raw.isclosed())

    def test_a_response_that_will_close_closes_its_connection_and_its_file_too(self):
        with recording_connections() as made:
            resp = get(self.pool, self.server.url + "/untilclose", read=False)
            resp.read(5)
            raw = resp._raw
            resp.close()
        self.assertEqual([closed(c) for c in made], [True])
        self.assertTrue(raw.isclosed())

    def test_a_failed_read_closes_the_connection(self):
        with recording_connections() as made:
            resp = get(self.pool, self.server.url + "/short", read=False)
            with self.assertRaises(http.client.IncompleteRead):
                resp.read()
        self.assertEqual([closed(c) for c in made], [True])

    def test_only_a_body_read_to_its_end_on_a_connection_that_stays_open_is_given_back(self):
        # (the pool also refuses a connection without a socket; this is the response not offering one)
        cases = (("/ok", True, True), ("/close", True, False), ("/http10", True, False), ("/untilclose", True, False),
                 ("/big", False, False), ("/short", True, False))
        for path, to_the_end, offered in cases:
            with self.subTest(path), mock.patch.object(self.pool, "_give", wraps=self.pool._give) as give:
                resp = get(self.pool, self.server.url + path, read=False)
                try:
                    resp.read() if to_the_end else resp.read(10)
                except http.client.IncompleteRead:
                    pass
                self.assertEqual(give.called, offered)
                resp.close()
                resp.read()
                resp.close()
                self.assertEqual(give.call_count, 1 if offered else 0)
                self.pool.close()

    def test_drain_stops_when_the_body_stops_giving(self):
        class Dry:                                              # (a body that is not finished and gives nothing more)
            status, reason, msg = 200, "OK", {}

            def read(self, amt=None):
                return b""

            def isclosed(self):
                return False

            def close(self):
                pass

        conn = mock.Mock()
        resp = keepalive.Response(self.pool, ("http", "h", 80, None), conn, Dry(), "http://h/")
        resp.drain()
        resp.close()
        conn.close.assert_called_once_with()

    def test_a_reused_connection_that_fails_when_sent_on_is_closed_and_the_request_goes_on_a_new_one(self):
        with recording_connections() as made:
            self.assertEqual(get(self.pool, self.server.url + "/ok"), (200, b"hello"))
            made[0].request = mock.Mock(side_effect=BrokenPipeError())   # (what a socket the server closed says on a send)
            self.assertEqual(get(self.pool, self.server.url + "/ok"), (200, b"hello"))
        self.assertEqual(len(made), 2)
        self.assertTrue(closed(made[0]))
        self.assertEqual(self.pool.stats, {"new": 2, "reused": 0, "stale": 1})

    def test_the_second_try_is_on_a_new_connection_even_if_another_was_given_back_meanwhile(self):
        with recording_connections() as made:
            held = [get(self.pool, self.server.url + "/silent", read=False) for _ in range(2)]
            for r in held:
                r.read()                                       # (two idle connections; the server has closed both)
            self.assertEqual(self.pool.idle(), 2)
            with mock.patch.object(self.pool, "_drop"):      # (as if another thread gave one back after the drop)
                self.assertEqual(get(self.pool, self.server.url + "/ok"), (200, b"hello"))
        self.assertEqual((len(made), self.pool.stats["stale"]), (3, 1))

    def test_a_connection_that_expired_is_closed_when_it_is_found_so(self):
        now = [100.0]
        pool = keepalive.Pool(idle_seconds=30, clock=lambda: now[0])
        self.addCleanup(pool.close)
        with recording_connections() as made:
            get(pool, self.server.url + "/ok")
            now[0] += 31
            get(pool, self.server.url + "/ok")
        self.assertEqual([closed(c) for c in made], [True, False])

    def test_the_idle_connections_of_a_stale_host_are_closed_not_just_forgotten(self):
        with recording_connections() as made:
            held = [get(self.pool, self.server.url + "/silent", read=False) for _ in range(3)]
            for r in held:
                r.read()
            self.assertEqual(self.pool.idle(), 3)
            get(self.pool, self.server.url + "/ok")          # the newest is stale: all three go
        self.assertEqual([closed(c) for c in made], [True, True, True, False])

    def test_close_closes_the_idle_connections(self):
        with recording_connections() as made:
            held = [get(self.pool, self.server.url + "/ok", read=False) for _ in range(2)]
            for r in held:
                r.read()
            self.pool.close()
        self.assertEqual([closed(c) for c in made], [True, True])

    def test_a_connection_that_never_answers_is_closed_when_the_request_gives_up(self):
        mute = Mute("hold")
        self.addCleanup(mute.close)
        with recording_connections() as made:
            with self.assertRaises(OSError):
                get(self.pool, mute.url + "/x", timeout=0.2)
        self.assertEqual([closed(c) for c in made], [True])

    def test_a_new_connection_that_is_hung_up_on_is_the_callers_error_and_is_not_retried(self):
        mute = Mute("hang up")
        self.addCleanup(mute.close)
        with recording_connections() as made:
            with self.assertRaises(keepalive.STALE):
                get(self.pool, mute.url + "/x")
        self.assertEqual((mute.accepted, [closed(c) for c in made], self.pool.stats["stale"]), (1, [True], 0))

    def test_a_reused_connection_gets_the_new_requests_timeout(self):
        with recording_connections() as made:
            get(self.pool, self.server.url + "/ok", timeout=5)
            get(self.pool, self.server.url + "/ok", timeout=9)
        self.assertEqual((len(made), made[0].timeout, made[0].sock.gettimeout()), (1, 9, 9))

    def test_the_default_port_of_each_scheme(self):
        asked = []

        def connect(scheme, host, port, via, timeout):
            asked.append((scheme, host, port))
            raise ConnectionRefusedError

        self.pool._connect = connect
        for url in ("http://h.example/x", "https://h.example/x", "http://h.example:81/x", "https://h.example:8443/x"):
            with self.assertRaises(ConnectionRefusedError):
                get(self.pool, url)
        self.assertEqual(asked, [("http", "h.example", 80), ("https", "h.example", 443),
                                 ("http", "h.example", 81), ("https", "h.example", 8443)])


class ProxyFor(unittest.TestCase):
    def test_none_when_nothing_is_set_or_the_host_is_exempt(self):
        self.assertIsNone(keepalive.proxy_for("https://pypi.org/simple/", {}))
        with mock.patch("urllib.request.proxy_bypass", return_value=True):
            self.assertIsNone(keepalive.proxy_for("https://pypi.org/", {"https": "http://proxy:3128"}))

    def test_the_exemption_is_asked_about_the_urls_host(self):
        env = {"https": "http://proxy:3128"}
        with mock.patch("urllib.request.proxy_bypass", side_effect=lambda host: host == "pypi.org") as bypass:
            self.assertIsNone(keepalive.proxy_for("https://pypi.org:443/simple/", env))
            self.assertEqual(keepalive.proxy_for("https://files.pythonhosted.org/x", env), ("proxy", 3128, {}))
        self.assertEqual([c.args for c in bypass.call_args_list], [("pypi.org",), ("files.pythonhosted.org",)])

    def test_the_environment_is_read_when_no_proxies_are_given(self):
        with mock.patch("urllib.request.proxy_bypass", return_value=False):
            with mock.patch("urllib.request.getproxies", return_value={"https": "http://envproxy:8080"}):
                self.assertEqual(keepalive.proxy_for("https://pypi.org/"), ("envproxy", 8080, {}))
            with mock.patch("urllib.request.getproxies", return_value={}):
                self.assertIsNone(keepalive.proxy_for("https://pypi.org/"))

    def test_an_http_proxy_for_an_https_url_is_a_tunnel(self):
        with mock.patch("urllib.request.proxy_bypass", return_value=False):
            self.assertEqual(keepalive.proxy_for("https://pypi.org/", {"https": "http://proxy.example:3128"}),
                             ("proxy.example", 3128, {}))
            self.assertEqual(keepalive.proxy_for("https://pypi.org/", {"https": "proxy.example"}),
                             ("proxy.example", 80, {}))

    def test_the_proxy_url_s_user_and_password_are_its_credentials(self):
        with mock.patch("urllib.request.proxy_bypass", return_value=False):
            _, _, headers = keepalive.proxy_for("https://pypi.org/", {"https": "http://us%40er:p%3Aw@proxy:3128"})
        import base64
        self.assertEqual(headers, {"Proxy-Authorization": "Basic " + base64.b64encode(b"us@er:p:w").decode()})

    def test_other_proxies_are_for_urllib(self):
        with mock.patch("urllib.request.proxy_bypass", return_value=False):
            for env, url in (({"https": "https://proxy:3128"}, "https://pypi.org/"),
                             ({"https": "socks5://proxy:1080"}, "https://pypi.org/"),
                             ({"http": "http://proxy:3128"}, "http://registry.internal/")):
                with self.subTest(env, url=url), self.assertRaises(keepalive.Unsupported):
                    keepalive.proxy_for(url, env)

    def test_a_proxy_for_the_other_scheme_is_not_this_urls(self):
        with mock.patch("urllib.request.proxy_bypass", return_value=False):
            self.assertIsNone(keepalive.proxy_for("https://pypi.org/", {"http": "http://proxy:3128"}))


@unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a certificate")
class TlsTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="lazaret-ka-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.cert = make_certificate(self.dir)
        if self.cert is None:
            self.skipTest("openssl could not make a certificate")
        self.server = Server(tls=self.cert)
        self.addCleanup(self.server.close)
        self.ctx = ssl.create_default_context(cafile=self.cert[0])
        self.pool = keepalive.Pool(context=self.ctx)
        self.addCleanup(self.pool.close)

    def test_tls_connections_are_reused(self):
        for _ in range(4):
            self.assertEqual(get(self.pool, self.server.url + "/ok"), (200, b"hello"))
        self.assertEqual((self.server.connections, self.pool.stats["reused"]), (1, 3))

    def test_the_certificate_is_verified_and_a_connection_that_failed_it_is_closed(self):
        pool = keepalive.Pool()
        self.addCleanup(pool.close)
        with recording_connections() as made:
            with self.assertRaises(ssl.SSLError):
                get(pool, self.server.url + "/ok")                  # the default store does not know it
        self.assertEqual([closed(c) for c in made], [True])

    def test_through_a_connect_proxy(self):
        proxy = Proxy()
        self.addCleanup(proxy.close)
        via = ("127.0.0.1", proxy.port, {"Proxy-Authorization": "Basic dTpw"})
        for _ in range(3):
            self.assertEqual(get(self.pool, self.server.url + "/ok", via=via), (200, b"hello"))
        self.assertEqual(len(proxy.seen), 1)                          # one tunnel, three requests
        self.assertTrue(proxy.seen[0].startswith(f"CONNECT 127.0.0.1:{self.server.port} HTTP/1."))   # (1.0 before 3.12)
        self.assertIn("Proxy-Authorization: Basic dTpw", proxy.seen[0])
        self.assertEqual(self.pool.stats["reused"], 2)
        direct = get(self.pool, self.server.url + "/ok")              # the same host without the proxy is another key
        self.assertEqual(direct, (200, b"hello"))
        self.assertEqual(self.pool.stats["new"], 2)


def fetcher(server, test, **kw):
    f = guard.Fetcher(set(), **kw)
    f.allow(server.url)
    test.addCleanup(f.close)
    return f


class FetcherKeepAliveTests(unittest.TestCase):
    def setUp(self):
        self.server = Server()
        self.addCleanup(self.server.close)

    def test_the_answers_are_the_old_paths_answers(self):
        for path in ("/ok", "/big", "/chunked"):
            with self.subTest(path):
                old, new = fetcher(self.server, self), fetcher(self.server, self, keepalive=True)
                a, b = old.fetch(self.server.url + path), new.fetch(self.server.url + path)
                self.assertEqual(a[0], b[0])
                self.assertEqual(a[1].get("Content-Length"), b[1].get("Content-Length"))
                self.assertEqual(a[1].get("Content-Type"), b[1].get("Content-Type"))

    def test_the_requests_are_the_old_paths_requests(self):
        sent = []
        for keep in (False, True):
            body = fetcher(self.server, self, keepalive=keep).get(self.server.url + "/echo", accept="application/json")
            sent.append({k: v for k, v in json.loads(body).items() if k != "connection"})   # (urllib says close; this does not)
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(sent[1]["user-agent"], guard.USER_AGENT)
        self.assertEqual((sent[1]["accept"], sent[1]["accept-encoding"]), ("application/json", "identity"))

    def test_close_gives_the_connections_up_and_is_harmless_without_a_pool(self):
        f = fetcher(self.server, self, keepalive=True)
        f.get(self.server.url + "/ok")
        self.assertEqual(f.pool.idle(), 1)
        f.close()
        self.assertEqual(f.pool.idle(), 0)
        fetcher(self.server, self).close()

    def test_the_local_index_closes_its_fetchers_connections_when_it_ends(self):
        import argparse
        import types
        from tests.registry.test_guard import options
        ctx = guard.Context(argparse.Namespace(keepalive=True, **vars(options(tool="pip"))), out=io.StringIO())
        index = types.SimpleNamespace(url="https://pypi.example/simple/")
        with mock.patch.object(guard.Fetcher, "close", autospec=True) as closed:
            with guard.LocalIndex(ctx, [index], False, None) as li:
                self.assertIsNotNone(li.fetcher.pool)
                closed.assert_not_called()
        closed.assert_called_once_with(li.fetcher)

    def test_the_old_path_is_the_default_and_one_connection_per_request(self):
        f = fetcher(self.server, self)
        self.assertIsNone(f.pool)
        for _ in range(3):
            f.get(self.server.url + "/ok")
        self.assertEqual(self.server.connections, 3)

    def test_requests_share_a_connection(self):
        f = fetcher(self.server, self, keepalive=True)
        for _ in range(6):
            self.assertEqual(f.get(self.server.url + "/ok"), b"hello")
        self.assertEqual(self.server.connections, 1)

    def test_errors_are_the_same_errors(self):
        for keep in (False, True):
            f = fetcher(self.server, self, keepalive=keep)
            with self.subTest(keep=keep):
                with self.assertRaises(repo.FetchError) as cm:
                    f.get(self.server.url + "/missing")
                self.assertEqual((cm.exception.status, str(cm.exception)),
                                 (404, f"HTTP 404 fetching {self.server.url}/missing"))
                with self.assertRaises(repo.FetchError) as cm:
                    f.get(self.server.url + "/status/403")
                self.assertEqual(cm.exception.status, 403)
                self.assertIn("settings give no credentials", str(cm.exception))
                with self.assertRaises(repo.FetchError) as cm:
                    f.get(self.server.url + "/status/500")
                self.assertEqual(cm.exception.status, 500)
                with self.assertRaisesRegex(repo.FetchError, "response over"):
                    f.get(self.server.url + "/big", max_bytes=1024)

    def test_a_status_that_is_not_a_success_or_a_redirect_is_an_error(self):
        f = fetcher(self.server, self, keepalive=True)
        for code in (300, 304, 404, 410, 500, 502):
            with self.subTest(code), self.assertRaises(repo.FetchError) as cm:
                f.get(self.server.url + f"/status/{code}")
            self.assertEqual(cm.exception.status, code)

    def test_a_location_on_an_answer_that_is_not_a_redirect_is_not_followed(self):
        for keep in (False, True):
            f = fetcher(self.server, self, keepalive=keep)
            self.server.log.clear()
            with self.subTest(keepalive=keep), self.assertRaises(repo.FetchError) as cm:
                f.get(self.server.url + "/errorwithlocation")
            self.assertEqual(cm.exception.status, 404)
            self.assertEqual([p for p, _ in self.server.log], ["/errorwithlocation"])

    def test_an_error_does_not_cost_the_connection(self):
        f = fetcher(self.server, self, keepalive=True)
        for _ in range(3):
            with self.assertRaises(repo.FetchError):
                f.get(self.server.url + "/missing")
        f.get(self.server.url + "/ok")
        self.assertEqual(self.server.connections, 1)                   # an error's small body is read, so it is reusable

    def test_a_body_over_the_budget_closes_its_connection(self):
        f = fetcher(self.server, self, keepalive=True)
        with self.assertRaisesRegex(repo.FetchError, "response over"):
            f.get(self.server.url + "/big", max_bytes=1024)
        self.assertEqual(f.pool.idle(), 0)
        self.assertEqual(f.get(self.server.url + "/ok"), b"hello")
        self.assertEqual(self.server.connections, 2)

    def test_a_connection_that_cannot_be_made_is_a_fetch_error(self):
        f = fetcher(self.server, self, keepalive=True)
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        port = dead.getsockname()[1]
        dead.close()
        f.allow(f"http://127.0.0.1:{port}")
        with self.assertRaisesRegex(repo.FetchError, "network error fetching"):
            f.get(f"http://127.0.0.1:{port}/x")

    def test_a_body_shorter_than_its_length_is_an_error_on_both_paths(self):
        for keep in (False, True):
            with self.subTest(keep=keep), self.assertRaisesRegex(repo.FetchError, "incomplete response"):
                fetcher(self.server, self, keepalive=keep).get(self.server.url + "/short")

    def test_a_body_with_no_length_is_held_to_the_budget_as_it_is_read(self):
        for keep in (False, True):
            f = fetcher(self.server, self, keepalive=keep)
            for path, body in (("/chunked", b"abcdefgh"), ("/untilclose", b"until the end")):
                with self.subTest(keep=keep, path=path):
                    self.assertEqual(f.get(self.server.url + path, max_bytes=len(body)), body)
                    with self.assertRaisesRegex(repo.FetchError, "response over"):
                        f.get(self.server.url + path, max_bytes=len(body) - 1)

    def test_a_declared_length_over_the_budget_is_refused_before_the_body_is_read(self):
        for keep in (False, True):                      # (read first, the short body would be "incomplete", not "over")
            with self.subTest(keep=keep), self.assertRaises(repo.FetchError) as cm:
                fetcher(self.server, self, keepalive=keep).get(self.server.url + "/huge", max_bytes=3 * 1024 * 1024)
            self.assertEqual(str(cm.exception), f"response over 3MB: {self.server.url}/huge")

    def test_a_body_of_exactly_the_budget_is_taken(self):
        for keep in (False, True):
            with self.subTest(keep=keep):
                f = fetcher(self.server, self, keepalive=keep)
                self.assertEqual(f.get(self.server.url + "/big", max_bytes=len(BODY)), BODY)
                with self.assertRaisesRegex(repo.FetchError, "response over"):
                    f.get(self.server.url + "/big", max_bytes=len(BODY) - 1)

    def test_the_host_rules_still_apply(self):
        for keep in (False, True):
            f = fetcher(self.server, self, keepalive=keep)
            for bad, why in (("http://evil.example/a", "only https is fetched"),
                             ("https://127.0.0.1:1/a", "host not allowed for this install: '127.0.0.1:1'"),
                             ("ftp://127.0.0.1/x", "only https is fetched")):
                with self.subTest(bad, keepalive=keep), self.assertRaisesRegex(repo.FetchError, why):
                    f.get(bad)
        self.assertEqual(self.server.connections, 0)

    def test_an_error_with_a_body_too_large_to_drain_closes_its_connection(self):
        for keep in (False, True):
            f = fetcher(self.server, self, keepalive=keep)
            with self.subTest(keepalive=keep), recording_connections() as made:
                with self.assertRaisesRegex(repo.FetchError, "HTTP 404"):
                    f.get(self.server.url + "/bigstatus/404")
                self.assertTrue(made and all(closed(c) for c in made), made)


class HttpErrorHints(unittest.TestCase):
    """What a refused request says about credentials (`Fetcher._http_error`): only for 401 and 403."""

    URL = "https://reg.example/x"

    def error(self, code, withheld=False, sent=False):
        f = guard.Fetcher({"reg.example"}, auth=mock.Mock(withheld=mock.Mock(return_value=withheld)))
        req = urllib.request.Request(self.URL)
        if sent:
            req.add_unredirected_header("Authorization", "Basic dTpw")
        return f._http_error(code, self.URL, req)

    def test_the_hint_is_for_401_and_403_only(self):
        for code in (401, 403):
            with self.subTest(code):
                self.assertEqual(str(self.error(code, withheld=True)),
                                 f"HTTP {code} fetching {self.URL} (its credentials are sent over https only)")
                self.assertEqual(str(self.error(code)), f"HTTP {code} fetching {self.URL} "
                                 "(the package manager's settings give no credentials for this registry)")
                self.assertEqual(str(self.error(code, sent=True)), f"HTTP {code} fetching {self.URL}")
        for code in (400, 402, 404, 500):
            with self.subTest(code):
                self.assertEqual(str(self.error(code, withheld=True)), f"HTTP {code} fetching {self.URL}")
                self.assertEqual(str(self.error(code)), f"HTTP {code} fetching {self.URL}")

    def test_the_status_is_kept_for_the_caller(self):
        self.assertEqual([self.error(c).status for c in (401, 404, 503)], [401, 404, 503])


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.server, self.other = Server(), Server()
        self.addCleanup(self.server.close)
        self.addCleanup(self.other.close)
        self.f = fetcher(self.server, self, keepalive=True)

    def redirect(self, to, code=302):
        return self.server.url + "/redirect?" + urllib.parse.urlencode({"to": to, "code": code})

    def test_a_relative_redirect_is_followed_on_the_same_connection(self):
        self.assertEqual(self.f.get(self.redirect("/ok")), b"hello")
        self.assertEqual(self.server.connections, 1)
        self.assertEqual([p for p, _ in self.server.log], [self.redirect("/ok")[len(self.server.url):], "/ok"])

    def test_every_redirecting_status(self):
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code):
                self.assertEqual(self.f.get(self.redirect("/ok", code)), b"hello")

    def test_a_fragment_is_dropped_and_a_bare_host_gets_a_path(self):
        self.f.allow(self.other.url)
        self.assertEqual(self.f.get(self.redirect("/ok#frag")), b"hello")
        self.assertEqual(self.server.log[-1][0], "/ok")
        with self.assertRaises(repo.FetchError) as cm:                      # "/" on the other server is a 404
            self.f.get(self.redirect(self.other.url))
        self.assertEqual(cm.exception.status, 404)
        self.assertEqual([p for p, _ in self.other.log], ["/"])

    def test_a_redirect_to_another_allowed_host_goes_there(self):
        self.f.allow(self.other.url)
        self.assertEqual(self.f.get(self.redirect(self.other.url + "/ok")), b"hello")
        self.assertEqual([p for p, _ in self.other.log], ["/ok"])

    def test_a_redirect_to_a_host_that_is_not_allowed_is_blocked_and_not_followed(self):
        with self.assertRaisesRegex(repo.FetchError, "redirect blocked"):
            self.f.get(self.redirect(self.other.url + "/ok"))
        self.assertEqual(self.other.log, [])
        with self.assertRaisesRegex(repo.FetchError, "redirect blocked"):
            self.f.get(self.redirect("http://evil.example/ok"))
        with self.assertRaisesRegex(repo.FetchError, "redirect blocked"):
            self.f.get(self.redirect("file:///etc/passwd"))

    def test_the_number_of_hops_is_capped(self):
        self.f.allow(self.other.url)
        # a chain of MAX_REDIRECTS hops is followed; one more is an error with the redirect's status
        chain = "/ok"
        for _ in range(repo.MAX_REDIRECTS):
            chain = "/redirect?to=" + urllib.parse.quote(chain, safe="")
        self.assertEqual(self.f.get(self.server.url + chain), b"hello")
        chain = "/redirect?to=" + urllib.parse.quote(chain, safe="")
        with self.assertRaises(repo.FetchError) as cm:
            self.f.get(self.server.url + chain)
        self.assertEqual(cm.exception.status, 302)

    def test_a_redirect_loop_stops(self):
        with self.assertRaises(repo.FetchError) as cm:
            self.f.get(self.server.url + "/loop")
        self.assertEqual(cm.exception.status, 302)
        self.assertLess(len(self.server.log), repo.MAX_REDIRECTS + 3)

    def test_a_redirect_loop_makes_the_same_requests_as_urllib_does(self):
        counts = []
        for keep in (False, True):
            server = Server()
            self.addCleanup(server.close)
            with self.assertRaises(repo.FetchError) as cm:
                fetcher(server, self, keepalive=keep).get(server.url + "/loop")
            self.assertEqual(cm.exception.status, 302)
            counts.append(len(server.log))
        self.assertEqual(counts, [5, 5])                # urllib's max_repeats is 4: the fifth sight of a URL is the one refused

    def test_a_redirect_without_a_location_is_an_error(self):
        with self.assertRaises(repo.FetchError) as cm:
            self.f.get(self.server.url + "/noloc")
        self.assertEqual(cm.exception.status, 302)

    def test_credentials_stay_with_the_url_they_were_for(self):
        user_url = f"http://user:secret@127.0.0.1:{self.server.port}/redirect?" + urllib.parse.urlencode(
            {"to": self.other.url + "/echo"})
        self.f.allow(self.other.url)
        body = self.f.get(user_url)
        self.assertNotIn("authorization", json.loads(body))            # the second host never saw them
        first = self.server.log[0][1]
        self.assertTrue(first["Authorization"].startswith("Basic "))   # the first one did
        self.assertEqual(self.other.log[0][1].get("Authorization"), None)

    def test_a_hop_gets_the_credentials_of_its_own_url(self):
        auth = pmsettings.Credentials()
        auth.add(self.other.url + "/", "Bearer for-the-other-host", whole_host=True)
        for keep in (False, True):
            with self.subTest(keepalive=keep):
                f = fetcher(self.server, self, keepalive=keep, auth=auth)
                f.allow(self.other.url)
                self.other.log.clear()
                self.server.log.clear()
                body = json.loads(f.get(self.redirect(self.other.url + "/echo")))
                self.assertEqual(body["authorization"], "Bearer for-the-other-host")
                self.assertNotIn("Authorization", self.server.log[0][1])          # (the first host has none, so none was sent)

    def test_the_headers_are_carried_over_a_hop(self):
        body = json.loads(self.f.get(self.redirect("/echo"), accept="application/json"))
        self.assertEqual(body["accept"], "application/json")
        self.assertEqual(body["user-agent"], guard.USER_AGENT)


@mock.patch.dict(os.environ, _support.PYTHON_TRANSPORT)        # (the pool is urllib's)
class FallbackTests(unittest.TestCase):
    def test_a_request_the_pool_cannot_carry_goes_through_urllib(self):
        server = Server()
        self.addCleanup(server.close)
        f = fetcher(server, self, keepalive=True)
        with mock.patch.object(f.pool, "request", side_effect=keepalive.Unsupported("x")):
            self.assertEqual(f.get(server.url + "/ok"), b"hello")
            self.assertEqual(f.get(server.url + "/ok"), b"hello")
        self.assertEqual(server.connections, 2)                        # the old way: a connection each
        self.assertEqual(server.log[0][1].get("Connection"), "close")

    def test_what_proxy_for_says_is_what_the_pool_is_given_and_loopback_is_not_asked(self):
        server = Server()
        self.addCleanup(server.close)
        f = fetcher(server, self, keepalive=True)
        via = ("proxy.example", 3128, {"Proxy-Authorization": "Basic dTpw"})
        with mock.patch.object(guard.keepalive_, "proxy_for", return_value=via) as asked, \
                mock.patch.object(f.pool, "request", side_effect=OSError("stop here")) as request:
            f.allow("https://pypi.org/")
            with self.assertRaisesRegex(repo.FetchError, "stop here"):
                f.get("https://pypi.org/simple/x/")
            self.assertEqual((asked.call_args.args, request.call_args.args[3]), (("https://pypi.org/simple/x/",), via))
            asked.reset_mock()
            with self.assertRaisesRegex(repo.FetchError, "stop here"):
                f.get(server.url + "/ok")
            self.assertEqual(asked.call_count, 0)
            self.assertIsNone(request.call_args.args[3])

    def test_loopback_is_never_sent_through_a_proxy(self):
        server = Server()
        self.addCleanup(server.close)
        f = fetcher(server, self, keepalive=True)
        with mock.patch.object(guard.keepalive_, "proxy_for", side_effect=AssertionError("asked about a proxy")):
            self.assertEqual(f.get(server.url + "/ok"), b"hello")


class CloseTests(unittest.TestCase):
    """The fetcher the npm lockfile check makes is closed when the check ends, whether it ends well or not."""

    def check(self, fails):
        import argparse
        made = []

        class Recording(guard.Fetcher):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.closed = 0
                made.append(self)

            def close(self):
                self.closed += 1
                super().close()

        opts = argparse.Namespace(min_age=0, allow_new=[], trust=[], block_warn=False, plan=False, json=None,
                                  no_cache=True, jobs=1, scan_timeout=60.0, tool="npm", args=[], keepalive=True)
        ctx = guard.Context(opts, out=io.StringIO())
        entry = {"name": "a", "version": "1.0.0", "resolved": "https://reg.example/a/-/a-1.0.0.tgz",
                 "integrity": "sha512-AAA=", "os": [], "cpu": [], "libc": [], "lock_digest": None}
        step = mock.Mock(side_effect=RuntimeError("boom") if fails else None)
        with mock.patch.object(guard, "Fetcher", Recording), mock.patch.object(guard, "check_npm_package", step), \
                mock.patch.object(guard, "node_platform", return_value=("linux", "x64", "glibc")):
            if fails:
                with self.assertRaisesRegex(RuntimeError, "boom"):
                    guard.check_lock_entries(ctx, [entry], guard.Registries({"registry": "https://reg.example/"}),
                                             set(), "package-lock.json")
            else:
                self.assertIsNone(guard.check_lock_entries(ctx, [entry], guard.Registries(
                    {"registry": "https://reg.example/"}), set(), "package-lock.json"))
        self.assertEqual(step.call_count, 1)
        return made

    def test_closed_when_the_check_ends(self):
        made = self.check(fails=False)
        self.assertEqual([f.closed for f in made], [1])
        self.assertIsNotNone(made[0].pool)                  # (it was the pool's fetcher: `keepalive` reached it)

    def test_closed_when_a_check_raises(self):
        self.assertEqual([f.closed for f in self.check(fails=True)], [1])


class OptionTests(unittest.TestCase):
    def test_the_option_reaches_the_context(self):
        self.assertFalse(guard.build_parser().parse_args(["pip", "install", "x"]).keepalive)
        opts = guard.build_parser().parse_args(["--keepalive", "pip", "install", "x"])
        self.assertTrue(opts.keepalive)
        import argparse
        base = dict(min_age=0, allow_new=[], trust=[], block_warn=False, plan=False, json=None, no_cache=True, jobs=1,
                    scan_timeout=60.0, tool="pip", args=[])
        self.assertTrue(guard.Context(argparse.Namespace(keepalive=True, **base)).keepalive)
        self.assertFalse(guard.Context(argparse.Namespace(**base)).keepalive)         # (an options object that predates it)


if __name__ == "__main__":
    unittest.main()
