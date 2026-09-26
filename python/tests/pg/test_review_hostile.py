"""Review fixes: malformed server messages and TLS setup failures must surface
as lazaret.pg errors (and close the connection), never as struct.error,
ValueError, UnicodeDecodeError or FileNotFoundError."""

import os
import struct
import tempfile
import unittest

from lazaret import pg
from tests.pg.test_hostile_server import FakeServer, auth, connect, msg, recv_exact


def ready_for_query(conn, srv):
    srv.read_startup(conn)
    conn.sendall(auth(0) + msg(b"K", struct.pack("!ii", 1, 2)) + msg(b"Z", b"I"))


def read_until(conn, srv, kind):
    while True:
        got, _ = srv.read_message(conn)
        if got == kind:
            return


def after_query(*replies):
    """Complete startup, wait for one extended-protocol query, send replies."""
    def script(conn, srv):
        ready_for_query(conn, srv)
        read_until(conn, srv, b"S")
        conn.sendall(b"".join(replies))
        try:
            srv.read_message(conn)  # wait for the client to hang up
        except OSError:
            pass
    return script


class MalformedStartupTests(unittest.TestCase):
    CASES = {
        "short authentication request": msg(b"R", b"\x00\x00"),
        "MD5 request without a salt": auth(5, b"ab"),
        "ErrorResponse field without NUL": msg(b"E", b"SFATAL"),
        "ParameterStatus without NUL": auth(0) + msg(b"S", b"x"),
        "short BackendKeyData": auth(0) + msg(b"K", b"\x00\x01"),
        "NoticeResponse field without NUL": auth(0) + msg(b"N", b"Mhello"),
        "NotificationResponse without NUL": auth(0) + msg(b"A", b"\x00\x00\x00\x01chan"),
        "non-UTF-8 SASL mechanism": auth(10, b"\xff\x00\x00"),
    }

    def test_each_is_an_operational_error(self):
        for name, reply in self.CASES.items():
            def script(conn, srv, reply=reply):
                srv.read_startup(conn)
                conn.sendall(reply)
            with self.subTest(name), self.assertRaises(pg.OperationalError):
                connect(FakeServer(script))

    def test_non_utf8_scram_server_first(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(auth(10, b"SCRAM-SHA-256\x00\x00"))
            srv.read_message(conn)
            conn.sendall(auth(11, b"r=\xff\xfe,s=c2FsdA==,i=4096"))
        with self.assertRaisesRegex(pg.AuthenticationError, "malformed SCRAM"):
            connect(FakeServer(script))


class MalformedResultTests(unittest.TestCase):
    def run_query(self, *replies):
        c = connect(FakeServer(after_query(*replies)))
        with self.assertRaises(pg.OperationalError):
            c.fetch("SELECT 1")
        self.assertTrue(c.closed)

    def test_truncated_row_description(self):
        self.run_query(msg(b"1") + msg(b"2") + msg(b"T", b"\x00\x01ab"))

    def test_data_row_shorter_than_its_lengths(self):
        column = b"x\x00" + struct.pack("!IhIhih", 0, 0, 25, -1, -1, 0)
        self.run_query(msg(b"1") + msg(b"2") + msg(b"T", b"\x00\x01" + column)
                       + msg(b"D", b"\x00\x01" + struct.pack("!i", 100) + b"abc"))

    def test_parameter_status_mid_query(self):
        self.run_query(msg(b"1") + msg(b"S", b"only-a-name"))

    def test_malformed_error_response_mid_query(self):
        self.run_query(msg(b"E", b"SERROR\x00Mno terminator"))


class TlsSetupErrorTests(unittest.TestCase):
    """Missing or unreadable certificate files are OperationalErrors."""

    def tls_accepting_server(self):
        def script(conn, srv):
            recv_exact(conn, 8)  # SSLRequest
            conn.sendall(b"S")
            try:
                conn.recv(1)
            except OSError:
                pass
        return FakeServer(script)

    def test_bad_files(self):
        d = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, d)
        garbage = os.path.join(d, "garbage.pem")
        with open(garbage, "w", encoding="utf-8", newline="\n") as f:
            f.write("not a certificate\n")
        missing = os.path.join(d, "missing.crt")
        cases = [
            {"sslmode": "require", "sslcert": missing, "sslkey": missing},
            {"sslmode": "require", "sslcert": garbage, "sslkey": garbage},
            {"sslmode": "verify-ca", "sslrootcert": garbage},
            {"sslmode": "verify-ca", "sslrootcert": d},  # a directory
        ]
        for kwargs in cases:
            with self.subTest(**kwargs), self.assertRaises(pg.OperationalError):
                connect(self.tls_accepting_server(), **kwargs)


if __name__ == "__main__":
    unittest.main()
