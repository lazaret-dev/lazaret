"""Audit finding (minor) — lazaret.pg.

A DataRow before any RowDescription made fetch() call decode(None) and
raise a raw TypeError instead of a pg.Error (iterate() already refused it as
a protocol violation). A hostile or broken server must never crash the
caller with a non-pg exception.

The server is a scripted local fake on 127.0.0.1; credentials are dummies.
"""

import struct
import unittest

from lazaret import pg
from tests.pg.test_hostile_server import FakeServer, auth, connect, msg

DATA_ROW = msg(b"D", struct.pack("!h", 1) + struct.pack("!i", 1) + b"1")
ROW_WITHOUT_DESCRIPTION = (msg(b"1") + msg(b"2") + DATA_ROW + msg(b"C", b"SELECT 1\x00")
                           + msg(b"Z", b"I"))


def serve(reply):
    def script(conn, srv):
        srv.read_startup(conn)
        conn.sendall(auth(0) + msg(b"K", struct.pack("!i", 1) + b"abcd") + msg(b"Z", b"I"))
        for _ in range(5):                    # Parse, Bind, Describe, Execute, Sync/Flush
            srv.read_message(conn)
        conn.sendall(reply)
        try:
            conn.recv(100)                    # until the client hangs up
        except OSError:
            pass
    return FakeServer(script)


class DataRowBeforeRowDescription(unittest.TestCase):
    CALLS = {
        "fetch": lambda c: c.fetch("SELECT 1"),
        "fetchrow": lambda c: c.fetchrow("SELECT 1"),
        "fetchval": lambda c: c.fetchval("SELECT 1"),
        "execute": lambda c: c.execute("SELECT 1"),
        "iterate": lambda c: list(c.iterate("SELECT 1")),
    }

    def test_is_a_protocol_error_that_closes_the_connection(self):
        for name, call in self.CALLS.items():
            with self.subTest(name):
                srv = serve(ROW_WITHOUT_DESCRIPTION)
                conn = connect(srv)
                self.addCleanup(conn.close)
                with self.assertRaisesRegex(pg.OperationalError, "data row before row description"):
                    call(conn)
                self.assertTrue(conn.closed)


if __name__ == "__main__":
    unittest.main()
