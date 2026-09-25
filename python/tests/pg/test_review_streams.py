"""Review fix: an iterate() that is still open must not break close() or
transaction(). close() made the suspended iterator crash with
AttributeError ('NoneType' object has no attribute 'sendall'), and an
exception inside transaction() while an iterator was suspended made
ROLLBACK fail and closed the connection (repro r7)."""

import struct
import unittest

from lazaret import pg
from tests.pg.test_hostile_server import FakeServer, connect, msg
from tests.pg.test_review_hostile import ready_for_query

COLUMN = b"n\x00" + struct.pack("!IhIhih", 0, 0, 23, 4, -1, 0)


def mini_server(total_rows=10, commit_error=None):
    """Just enough of PostgreSQL for execute() and iterate(): SELECT streams
    total_rows integers, honoring Execute's row limit; BEGIN/COMMIT/ROLLBACK
    change the transaction status reported in ReadyForQuery. If commit_error
    is set, a Sync outside a transaction block answers it (a failed commit)."""
    def script(conn, srv):
        ready_for_query(conn, srv)
        status, sql, sent = b"I", "", 0
        while True:
            kind, body = srv.read_message(conn)
            if kind == b"P":
                sql = body[1:body.index(b"\x00", 1)].decode()
                sent = 0
                conn.sendall(msg(b"1"))
            elif kind == b"B":
                conn.sendall(msg(b"2"))
            elif kind == b"D":
                conn.sendall(msg(b"T", b"\x00\x01" + COLUMN) if sql.startswith("SELECT") else msg(b"n"))
            elif kind == b"E":
                if sql.startswith("SELECT"):
                    limit = struct.unpack("!i", body[-4:])[0] or total_rows
                    out = b""
                    while sent < total_rows and limit:
                        sent += 1
                        limit -= 1
                        text = str(sent).encode()
                        out += msg(b"D", b"\x00\x01" + struct.pack("!i", len(text)) + text)
                    out += msg(b"s") if sent < total_rows else msg(b"C", b"SELECT %d\x00" % sent)
                    conn.sendall(out)
                else:
                    status = {"BEGIN": b"T", "COMMIT": b"I", "ROLLBACK": b"I"}.get(sql, status)
                    conn.sendall(msg(b"C", sql.encode() + b"\x00"))
            elif kind == b"S":
                if commit_error and status == b"I" and sql.startswith("SELECT"):
                    conn.sendall(commit_error)
                conn.sendall(msg(b"Z", status))
            elif kind == b"X":
                return
    return script


class OpenStreamTests(unittest.TestCase):
    def setUp(self):
        self.srv = FakeServer(mini_server())
        self.conn = connect(self.srv)
        self.addCleanup(self.conn.close)

    def test_close_while_suspended(self):
        it = self.conn.iterate("SELECT n", batch_size=2)
        self.assertEqual(next(it), (1,))
        self.conn.close()
        with self.assertRaisesRegex(pg.InterfaceError, "closed"):
            list(it)
        self.srv.thread.join(5)
        self.assertEqual(self.srv.received[-1], b"X")  # the server got Terminate

    def test_exception_in_transaction_with_suspended_iterator(self):
        with self.assertRaises(ValueError):
            with self.conn.transaction():
                rows = self.conn.iterate("SELECT n", batch_size=2)  # still referenced: stays suspended
                for _ in rows:
                    raise ValueError("app bug")
        self.assertFalse(self.conn.closed)
        self.assertFalse(self.conn.in_transaction)
        self.assertEqual(self.conn.execute("SELECT n").tag, "SELECT 10")
        self.assertIn(b"S", self.srv.received)

    def test_leaving_the_block_ends_the_stream(self):
        with self.conn.transaction():
            it = self.conn.iterate("SELECT n", batch_size=3)
            self.assertEqual(next(it), (1,))
        self.assertFalse(self.conn.in_transaction)  # committed despite the open iterator
        self.assertEqual([next(it), next(it)], [(2,), (3,)])  # the rest of the batch already read
        with self.assertRaisesRegex(pg.InterfaceError, "ended early"):
            next(it)
        self.assertEqual(self.conn.execute("SELECT n").tag, "SELECT 10")

    def test_other_queries_still_refused_while_streaming(self):
        it = self.conn.iterate("SELECT n", batch_size=2)
        next(it)
        with self.assertRaisesRegex(pg.InterfaceError, "iterate"):
            self.conn.execute("SELECT n")
        it.close()
        self.assertEqual(self.conn.execute("SELECT n").tag, "SELECT 10")


class EarlyCloseCommitErrorTests(unittest.TestCase):
    def test_closing_the_iterator_raises_a_failed_commit(self):
        error = msg(b"E", b"SERROR\x00C23503\x00Mdeferred constraint\x00\x00")
        c = connect(FakeServer(mini_server(commit_error=error)))
        it = c.iterate("SELECT n", batch_size=2)
        next(it)
        with self.assertRaises(pg.IntegrityError):
            it.close()
        self.assertFalse(c.closed)
        c.close()


if __name__ == "__main__":
    unittest.main()
