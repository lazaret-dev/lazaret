"""Review fixes in executemany() (fake servers; the live checks are in
test_review_live.py)."""

import struct
import unittest

from lazaret import pg
from tests.pg.test_hostile_server import FakeServer, connect, msg
from tests.pg.test_review_hostile import ready_for_query

ROW = msg(b"D", b"\x00\x01" + struct.pack("!i", 1) + b"7")


def batch_server(on_flush, on_other=None):
    """Startup, then answer each Flush with on_flush(executes) and each Sync
    with ReadyForQuery. on_other(kind) may answer other messages."""
    def script(conn, srv):
        ready_for_query(conn, srv)
        executes = 0
        while True:
            kind, _ = srv.read_message(conn)
            if kind == b"E":
                executes += 1
            elif kind == b"H":
                conn.sendall(on_flush(executes))
                executes = 0
            elif kind == b"S":
                conn.sendall(msg(b"Z", b"I"))
            elif kind == b"X":
                return
            elif on_other:
                conn.sendall(on_other(kind))
    return script


class ExecutemanyRowsTests(unittest.TestCase):
    def test_returning_rows_are_discarded(self):
        srv = FakeServer(batch_server(lambda n: msg(b"1") + (msg(b"2") + ROW + msg(b"C", b"INSERT 0 1\x00")) * n))
        c = connect(srv)
        result = c.executemany("INSERT INTO t (v) VALUES ($1) RETURNING id", [(1,), (2,), (3,)])
        self.assertEqual((result.tag, result.rowcount), ("executemany 3", 3))
        self.assertFalse(c.closed)
        c.close()

    def test_copy_in_fails_cleanly(self):
        error = msg(b"E", b"SERROR\x00C57014\x00MCOPY from stdin failed\x00\x00")
        srv = FakeServer(batch_server(lambda n: msg(b"1") + msg(b"2") + msg(b"G", b"\x00\x00\x00"),
                                      lambda kind: error if kind == b"f" else b""))
        c = connect(srv)
        with self.assertRaisesRegex(pg.InterfaceError, "COPY FROM STDIN.*nothing was committed"):
            c.executemany("COPY t FROM STDIN", [(), ()])
        self.assertFalse(c.closed)
        c.close()
        srv.thread.join(5)
        self.assertIn(b"f", srv.received)  # CopyFail, so the server never waits for data


if __name__ == "__main__":
    unittest.main()
