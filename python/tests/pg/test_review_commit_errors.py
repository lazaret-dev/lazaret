"""Review fix: an error the server reports when Sync commits the implicit
transaction (a DEFERRABLE INITIALLY DEFERRED foreign key, a serialization
failure) must be raised by executemany() and iterate(), not discarded while
draining to ReadyForQuery. Live checks are in test_review_live.py."""

import struct
import unittest

from lazaret import pg
from tests.pg.test_hostile_server import FakeServer, connect, msg
from tests.pg.test_review_hostile import ready_for_query

FK_ERROR = msg(b"E", b"SERROR\x00VERROR\x00C23503\x00Mviolates foreign key constraint\x00\x00")
COLUMN = b"id\x00" + struct.pack("!IhIhih", 0, 0, 23, 4, -1, 0)
ROW = msg(b"D", b"\x00\x01" + struct.pack("!i", 1) + b"3")


def server(on_flush):
    """Answer each Flush with on_flush(), and the final Sync with an error
    followed by ReadyForQuery, as PostgreSQL does for a failed commit."""
    def script(conn, srv):
        ready_for_query(conn, srv)
        while True:
            kind, _ = srv.read_message(conn)
            if kind == b"H":
                conn.sendall(on_flush())
            elif kind == b"S":
                conn.sendall(FK_ERROR + msg(b"Z", b"I"))
            elif kind == b"X":
                return
    return script


class CommitErrorTests(unittest.TestCase):
    def test_executemany(self):
        c = connect(FakeServer(server(lambda: msg(b"1") + msg(b"2") + msg(b"C", b"INSERT 0 1\x00"))))
        with self.assertRaises(pg.IntegrityError) as info:
            c.executemany("INSERT INTO child VALUES ($1, $2)", [(1, 999)])
        self.assertEqual(info.exception.sqlstate, "23503")
        self.assertFalse(c.closed)
        c.close()

    def test_iterate(self):
        reply = msg(b"1") + msg(b"2") + msg(b"T", b"\x00\x01" + COLUMN) + ROW + msg(b"C", b"INSERT 0 1\x00")
        c = connect(FakeServer(server(lambda: reply)))
        rows = []
        with self.assertRaises(pg.IntegrityError):
            for row in c.iterate("INSERT INTO child VALUES (3, 999) RETURNING id"):
                rows.append(row)
        self.assertEqual(rows, [(3,)])  # the rows were delivered, then the commit failed
        self.assertFalse(c.closed)
        c.close()


if __name__ == "__main__":
    unittest.main()
