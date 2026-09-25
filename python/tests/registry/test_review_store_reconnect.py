"""Review follow-up: the registry state DB survives a dropped Postgres session.

The MCP server and `scan-all` keep one Store open for a long time. When the
server ended the session (admin shutdown / pg_terminate_backend 57P01,
idle_session_timeout 57P05, a network blip), lazaret.pg raised
OperationalError / ServerOperationalError and closed the connection, and
every later Store call failed with "connection is closed" until restart.
Store's Postgres helpers now reopen a connection found closed, and after an
OperationalError call conn.reconnect() once and retry once — never inside a
transaction (a caller's open transaction is not retried; save_scan's own
transaction() block is retried only as a whole, after it was left).

Unit tests use a fake connection with lazaret.pg's real exception classes;
the live class (LAZARET_TEST_PG_DSN) terminates the Store's backend with
pg_terminate_backend() from a second connection.
"""
import contextlib
import os
import unittest
from unittest import mock

from lazaret import pg
from lazaret.registry import repo
from tests import _support


def terminated():
    return pg.ServerOperationalError({"S": "FATAL", "V": "FATAL", "C": "57P01",
                                      "M": "terminating connection due to administrator command"})


class FakeConn:
    """Enough of lazaret.pg.Connection for Store: fails the next `fail`
    operations by closing itself and raising `error()`."""

    def __init__(self, fail=0, error=terminated, reconnect_error=None):
        self.fail, self.error, self.reconnect_error = fail, error, reconnect_error
        self.closed = False
        self.tx_status = "I"
        self.tx_depth = 0
        self.ops = []
        self.reconnects = 0

    @property
    def in_transaction(self):
        return self.tx_status in ("T", "E")

    def execute_script(self, sql):
        self.ops.append("schema")

    def _op(self, name):
        if self.closed:
            raise pg.InterfaceError("connection is closed")
        self.ops.append(name)
        if self.fail:
            self.fail -= 1
            self.closed = True                     # like _lost(): status stays stale
            raise self.error()

    def fetchrow(self, sql, *args):
        self._op("fetchrow")
        if "RETURNING" in sql:
            return (7, True)                      # add_package: id, created
        if "s.issues" in sql:
            return ("1.0.0", "default", "t", "OK", [], [])   # report()
        return (7,)

    def fetch(self, sql, *args):
        self._op("fetch")
        return [("npm", "x", "1.0.0", "default", "t", "OK", 0, 0)]

    def execute(self, sql, *args):
        self._op(sql.split()[0])
        if sql == "BEGIN":
            self.tx_status = "T"
        elif sql in ("COMMIT", "ROLLBACK"):
            self.tx_status = "I"

    @contextlib.contextmanager
    def transaction(self):
        if self.tx_depth == 0:
            self.execute("BEGIN")
        self.tx_depth += 1
        try:
            yield self
        except BaseException:
            self.tx_depth -= 1
            if not self.closed:
                self.execute("ROLLBACK")
            raise
        self.tx_depth -= 1
        self.execute("COMMIT")

    def reconnect(self):
        if self.tx_depth:
            raise pg.InterfaceError("cannot reconnect inside a transaction() block")
        self.reconnects += 1
        if self.reconnect_error is not None:
            raise self.reconnect_error
        self.closed, self.tx_status = False, "I"
        self.ops.append("reconnect")

    def close(self):
        self.closed = True


def pg_store(conn):
    with mock.patch.object(pg, "connect", return_value=conn):
        return repo.Store("postgres://lazaret@192.0.2.1/lazaret")


RESULT = {"version": "1.0.0", "profile": "default", "verdict": "OK",
          "scannedAt": "2026-09-25T00:00:00+00:00", "filesScanned": 1, "archiveBytes": 10,
          "supplyChain": 0, "sevCounts": {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0}, "issues": []}


class ReconnectOnce(unittest.TestCase):
    def test_reads_survive_a_terminated_session(self):
        for name, call in (("status", lambda s: s.status()), ("packages", lambda s: s.packages()),
                           ("has_scan", lambda s: s.has_scan(1, "1.0.0", "default")),
                           ("report", lambda s: s.report("npm", "x"))):
            conn = FakeConn()
            store = pg_store(conn)
            conn.fail = 1
            with self.subTest(call=name):
                self.assertTrue(call(store))      # no exception, a result
                self.assertEqual(conn.reconnects, 1)
                self.assertEqual(conn.ops[1:], [conn.ops[1], "reconnect", conn.ops[1]])

    def test_add_package_is_retried_once(self):
        conn = FakeConn()
        store = pg_store(conn)
        conn.fail = 1
        self.assertEqual(store.add_package("npm", "x"), (7, True))
        self.assertEqual(conn.ops, ["schema", "fetchrow", "reconnect", "fetchrow"])

    def test_save_scan_retries_the_whole_transaction(self):
        # dropped at BEGIN, and dropped inside the block: either way the block
        # is left (rolled back) and run again from BEGIN, once
        for fail_at, first in ((1, ["BEGIN"]), (2, ["BEGIN", "INSERT"])):
            conn = FakeConn()
            store = pg_store(conn)
            conn.ops.clear()
            ops = []

            def execute(sql, *args, _orig=conn.execute):
                ops.append(sql.split()[0])
                if len(ops) == fail_at:
                    conn.closed = True
                    raise terminated()
                _orig(sql, *args)
            with self.subTest(fail_at=fail_at), mock.patch.object(conn, "execute", execute):
                store.save_scan(1, RESULT)
                self.assertEqual(ops, first + ["BEGIN", "INSERT", "COMMIT"])
                self.assertEqual(conn.reconnects, 1)

    def test_a_second_failure_propagates(self):
        conn = FakeConn()
        store = pg_store(conn)
        conn.fail = 2
        with self.assertRaises(pg.ServerOperationalError):
            store.status()
        self.assertEqual(conn.reconnects, 1)
        self.assertEqual(conn.ops[1:], ["fetch", "reconnect", "fetch"])

    def test_a_failed_reconnect_propagates(self):
        conn = FakeConn(reconnect_error=pg.OperationalError("could not connect to 192.0.2.1:5432"))
        store = pg_store(conn)
        conn.fail = 1
        with self.assertRaisesRegex(pg.OperationalError, "could not connect"):
            store.packages()
        self.assertEqual(conn.ops[1:], ["fetch"])

    def test_plain_network_failure_counts_too(self):
        conn = FakeConn(error=lambda: pg.OperationalError("server closed the connection unexpectedly"))
        store = pg_store(conn)
        conn.fail = 1
        store.status()
        self.assertEqual(conn.reconnects, 1)

    def test_other_errors_are_not_retried(self):
        for error in (lambda: pg.IntegrityError({"C": "23505", "M": "duplicate key"}),
                      lambda: pg.QueryCanceledError({"C": "57014", "M": "statement timeout"}),
                      lambda: pg.InterfaceError("misuse")):
            conn = FakeConn(error=error)
            store = pg_store(conn)
            conn.fail = 1
            with self.subTest(error=error().__class__.__name__):
                with self.assertRaises(pg.Error):
                    store.status()
                self.assertEqual(conn.reconnects, 0)

    def test_never_retried_inside_the_callers_transaction(self):
        conn = FakeConn()
        store = pg_store(conn)
        with self.assertRaises(pg.ServerOperationalError):
            with conn.transaction():
                conn.fail = 1
                store.add_package("npm", "x")
        self.assertEqual(conn.reconnects, 0)
        self.assertEqual(conn.ops[1:], ["BEGIN", "fetchrow"])

    def test_plain_sql_transaction_is_not_retried_either(self):
        conn = FakeConn()
        store = pg_store(conn)
        conn.execute("BEGIN")
        conn.fail = 1
        with self.assertRaises(pg.ServerOperationalError):
            store.status()
        self.assertEqual(conn.reconnects, 0)

    def test_a_session_lost_earlier_is_reopened_first(self):
        # e.g. lost inside a transaction, where nothing was retried: the
        # status is stale ("T"), the connection closed
        conn = FakeConn()
        store = pg_store(conn)
        conn.closed, conn.tx_status = True, "T"
        self.assertEqual(len(store.status()), 1)
        self.assertEqual(conn.ops[1:], ["reconnect", "fetch"])

    def test_closed_inside_a_transaction_block_is_an_error_not_a_split(self):
        conn = FakeConn()
        store = pg_store(conn)
        with self.assertRaisesRegex(pg.InterfaceError, "inside a transaction"):
            with conn.transaction():
                conn.closed = True
                store.status()
        self.assertEqual(conn.reconnects, 0)

    def test_sqlite_store_unchanged(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            store = repo.Store(os.path.join(d, "state.db"))
            try:
                pid, created = store.add_package("npm", "x")
                self.assertTrue(created)
                store.save_scan(pid, RESULT)
                self.assertEqual(store.report("npm", "x")["verdict"], "OK")
            finally:
                store.conn.close()


@_support.requires_env("LAZARET_TEST_PG_DSN")
class LiveTerminatedSession(unittest.TestCase):
    DB = "lz_review_reconnect"

    @classmethod
    def setUpClass(cls):
        base = os.environ["LAZARET_TEST_PG_DSN"]
        admin = pg.connect(base, timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.DB}"')
            admin.execute(f'CREATE DATABASE "{cls.DB}"')
        finally:
            admin.close()
        cls.dsn = base.rsplit("/", 1)[0] + "/" + cls.DB

    @classmethod
    def tearDownClass(cls):
        admin = pg.connect(os.environ["LAZARET_TEST_PG_DSN"], timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.DB}" WITH (FORCE)')
        finally:
            admin.close()

    def setUp(self):
        self.store = repo.Store(self.dsn)
        self.addCleanup(self.store.conn.close)
        self.admin = pg.connect(self.dsn, timeout=10)
        self.addCleanup(self.admin.close)

    def kill(self):
        pid = self.store.conn.backend_pid
        self.assertTrue(self.admin.fetchval("SELECT pg_terminate_backend($1)", pid))
        for _ in range(100):                 # until the backend is gone
            if not self.admin.fetchval("SELECT count(*) FROM pg_stat_activity WHERE pid = $1", pid):
                break
            import time
            time.sleep(0.02)
        return pid

    def test_reads_and_writes_after_pg_terminate_backend(self):
        pid, _ = self.store.add_package("npm", "left-pad")
        old = self.kill()
        self.assertEqual([tuple(r)[1:] for r in self.store.packages()], [("npm", "left-pad")])
        self.assertNotEqual(self.store.conn.backend_pid, old)
        self.kill()
        self.store.save_scan(pid, RESULT)                   # the transaction() block, retried whole
        self.kill()
        self.assertEqual(self.store.report("npm", "left-pad")["verdict"], "OK")
        self.kill()
        self.assertEqual(self.store.add_package("npm", "left-pad"), (pid, False))

    def test_not_retried_inside_a_transaction(self):
        with self.assertRaises(pg.OperationalError):
            with self.store.conn.transaction():
                self.store.add_package("npm", "in-tx")
                self.kill()
                self.store.add_package("npm", "in-tx-2")
        # the next call outside the block reopens the session; nothing of the
        # rolled-back transaction was written
        self.assertEqual([tuple(r)[2] for r in self.store.packages()
                          if tuple(r)[2].startswith("in-tx")], [])


if __name__ == "__main__":
    unittest.main()
