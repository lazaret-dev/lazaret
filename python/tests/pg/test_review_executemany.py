"""Review fixes in executemany() (fake servers; the live checks are in
test_review_live.py)."""

import socket
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


class NoticeFloodTests(unittest.TestCase):
    """A server that answers every row with a big NOTICE, and doesn't read
    more input until its output is consumed, used to deadlock a pipelined
    chunk: the client was stuck in sendall() and never read (repro r9)."""

    def test_large_batch_with_a_notice_per_row(self):
        notice = msg(b"N", b"SNOTICE\x00M" + b"n" * 20_000 + b"\x00\x00")
        flushes = []

        def script(conn, srv):
            ready_for_query(conn, srv)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
            conn.settimeout(20)
            while True:
                kind, _ = srv.read_message(conn)
                replies = {b"P": msg(b"1"), b"B": msg(b"2"), b"S": msg(b"Z", b"I"),
                           b"E": notice + msg(b"C", b"INSERT 0 1\x00")}
                if kind in replies:
                    conn.sendall(replies[kind])
                elif kind == b"H":
                    flushes.append(1)
                elif kind == b"X":
                    return

        srv = FakeServer(script)
        c = connect(srv, timeout=15)
        c._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768)
        c._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
        seen = []
        c.notice_handler = seen.append
        result = c.executemany("INSERT INTO t VALUES ($1)", [("x" * 20_000,)] * 150)
        self.assertEqual((result.rowcount, len(seen)), (150, 150))
        c.close()
        srv.thread.join(5)
        # 3 MB of parameters: the first row alone, then chunks capped at about 1 MiB.
        self.assertGreaterEqual(len(flushes), 4)


if __name__ == "__main__":
    unittest.main()
