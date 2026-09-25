"""Review fixes: a FATAL error the server sends just before it closes the
connection (57P01 pg_terminate_backend / admin shutdown, 57P05 idle session
timeout, ...) is raised with its SQLSTATE instead of a bare "server closed
the connection unexpectedly"; SQLSTATE classes 08 and 53 and 57P01-57P05 are
OperationalErrors; keepalive settings; Connection.reconnect()."""

import pickle
import socket
import struct
import threading
import unittest

from lazaret import pg
from lazaret.pg.errors import error_from_fields
from tests.pg.test_hostile_server import FakeServer, connect, msg
from tests.pg.test_review_hostile import ready_for_query


def fatal(code, text):
    return msg(b"E", b"SFATAL\x00VFATAL\x00C" + code.encode() + b"\x00M" + text.encode() + b"\x00\x00")


class SqlstateMappingTests(unittest.TestCase):
    def test_operational_classes(self):
        for code in ("08006", "08P01", "53300", "53100", "57P01", "57P02", "57P03", "57P04", "57P05"):
            with self.subTest(code=code):
                err = error_from_fields({"S": "FATAL", "C": code, "M": "m"})
                self.assertIs(type(err), pg.ServerOperationalError)
                self.assertIsInstance(err, pg.OperationalError)
                self.assertIsInstance(err, pg.DatabaseError)
                self.assertEqual(err.sqlstate, code)
                self.assertEqual(pickle.loads(pickle.dumps(err)).sqlstate, code)
        self.assertIs(type(error_from_fields({"C": "57014"})), pg.QueryCanceledError)
        self.assertIs(type(error_from_fields({"C": "57000"})), pg.DatabaseError)


class FatalBeforeCloseTests(unittest.TestCase):
    def test_terminated_during_a_query(self):
        def script(conn, srv):
            ready_for_query(conn, srv)
            srv.read_message(conn)
            conn.sendall(fatal("57P01", "terminating connection due to administrator command"))
        c = connect(FakeServer(script))
        with self.assertRaises(pg.ServerOperationalError) as info:
            c.execute("SELECT pg_sleep(5)")
        self.assertEqual((info.exception.sqlstate, info.exception.severity), ("57P01", "FATAL"))
        self.assertTrue(c.closed)

    def test_idle_session_timeout(self):
        sent = threading.Event()

        def script(conn, srv):
            ready_for_query(conn, srv)
            conn.sendall(fatal("57P05", "terminating connection due to idle-session timeout"))
            sent.set()
        c = connect(FakeServer(script))
        sent.wait(5)
        with self.assertRaises(pg.OperationalError) as info:
            c.execute("SELECT 1")
        self.assertEqual(info.exception.sqlstate, "57P05")
        self.assertTrue(c.closed)

    def test_other_fatal_errors_are_chained(self):
        def script(conn, srv):
            ready_for_query(conn, srv)
            srv.read_message(conn)
            conn.sendall(fatal("XX000", "internal error"))
        c = connect(FakeServer(script))
        with self.assertRaisesRegex(pg.OperationalError, "the server reported: FATAL: internal error") as info:
            c.execute("SELECT 1")
        self.assertIsInstance(info.exception.__cause__, pg.DatabaseError)

    def test_error_during_startup_keeps_its_class(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(fatal("53300", "sorry, too many clients already"))
        with self.assertRaises(pg.ServerOperationalError) as info:
            connect(FakeServer(script))
        self.assertEqual(info.exception.sqlstate, "53300")


class SequentialServer:
    """Accepts one connection per script, in order."""

    def __init__(self, *scripts):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(len(scripts))
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._run, args=(scripts,), daemon=True)
        self.thread.start()

    def _run(self, scripts):
        helper = FakeServer.__new__(FakeServer)
        helper.received = []
        try:
            for script in scripts:
                conn, _ = self.sock.accept()
                conn.settimeout(5)
                try:
                    script(conn, helper)
                except OSError:
                    pass
                finally:
                    conn.close()
        finally:
            self.sock.close()


def answer_one_query(conn, srv):
    ready_for_query(conn, srv)
    while srv.read_message(conn)[0] != b"S":
        pass
    conn.sendall(msg(b"1") + msg(b"2") + msg(b"n") + msg(b"C", b"SELECT 0\x00") + msg(b"Z", b"I"))
    srv.read_message(conn)


class ReconnectTests(unittest.TestCase):
    def test_reconnect_after_the_server_ended_the_session(self):
        def terminated(conn, srv):
            ready_for_query(conn, srv)
            srv.read_message(conn)
            conn.sendall(fatal("57P01", "terminating connection due to administrator command"))
        srv = SequentialServer(terminated, answer_one_query)
        c = connect(srv)
        c.register_decoder(99999, str.upper)
        with self.assertRaises(pg.ServerOperationalError):
            c.execute("SELECT 1")
        self.assertTrue(c.closed)
        c.reconnect()
        self.assertFalse(c.closed)
        self.assertEqual(c.execute("SELECT 1").tag, "SELECT 0")
        self.assertIn(99999, c._decoders)  # registered decoders survive
        c.close()

    def test_reconnect_refused_inside_a_transaction_block(self):
        def script(conn, srv):
            ready_for_query(conn, srv)
            while True:
                kind, _ = srv.read_message(conn)
                if kind == b"S":
                    conn.sendall(msg(b"1") + msg(b"2") + msg(b"n") + msg(b"C", b"BEGIN\x00") + msg(b"Z", b"T"))
                elif kind == b"X":
                    return
        c = connect(FakeServer(script))
        with self.assertRaisesRegex(pg.InterfaceError, "transaction"):
            with c.transaction():
                c.reconnect()
        c.close()


@unittest.skipUnless(hasattr(socket, "TCP_KEEPIDLE") and hasattr(socket, "TCP_KEEPCNT"), "Linux-style keepalive options")
class KeepaliveTests(unittest.TestCase):
    def idle_server(self):
        def script(conn, srv):
            ready_for_query(conn, srv)
            try:
                srv.read_message(conn)
            except OSError:
                pass
        return FakeServer(script)

    def test_libpq_keepalive_parameters(self):
        c = connect(self.idle_server(), keepalives_idle=42, keepalives_interval=7, keepalives_count=3)
        get = c._sock.getsockopt
        self.assertEqual(get(socket.SOL_SOCKET, socket.SO_KEEPALIVE), 1)
        self.assertEqual((get(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE), get(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL),
                          get(socket.IPPROTO_TCP, socket.TCP_KEEPCNT)), (42, 7, 3))
        c.close()

    def test_keepalives_off(self):
        c = connect(self.idle_server(), keepalives=0)
        self.assertEqual(c._sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE), 0)
        c.close()

    def test_keepalives_in_a_url(self):
        from lazaret.pg._dsn import resolve
        p = resolve("postgresql://db.example.invalid/lz?keepalives=1&keepalives_idle=30&keepalives_count=0")
        self.assertEqual((p.keepalives, p.keepalives_idle, p.keepalives_count), (True, 30, None))
        with self.assertRaises(pg.InterfaceError):
            resolve("postgresql://db.example.invalid/lz?keepalives_idle=soon")


if __name__ == "__main__":
    unittest.main()
