"""The state database keeps a discovery cursor per registry.

`discover --resume` continues each registry's change feed where the last
run stopped (PyPI's changelog serial, npm's replication sequence number),
so a scheduled job sees every release in between. The cursor lives in a
discovery_cursors table, created in place in databases made before it, in
SQLite and Postgres alike.

SQLite runs for real. Postgres runs through the Store's fake wire
connection from test_review_store_reconnect, extended so the cursor
statements Store sends (its SQL, $n placeholders and argument order) are
executed by an in-memory SQLite database; the live class
(LAZARET_TEST_PG_DSN) runs them on a real server.
"""

import datetime
import os
import re
import sqlite3
import tempfile
import unittest

from lazaret.registry import repo
from tests import _support
from tests.registry.test_review_store_reconnect import FakeConn, pg_store

UTC = datetime.timezone.utc
WHEN = datetime.datetime(2026, 9, 26, 17, 47, 30, tzinfo=UTC)

# the state schema as 0.1.2 created it (before discovery_cursors)
OLD_SQLITE = """
CREATE TABLE packages (id INTEGER PRIMARY KEY AUTOINCREMENT, ecosystem TEXT NOT NULL,
    name TEXT NOT NULL, added_at TEXT NOT NULL, UNIQUE (ecosystem, name));
CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id INTEGER NOT NULL REFERENCES packages(id), version TEXT NOT NULL,
    profile TEXT NOT NULL, scanned_at TEXT NOT NULL, engine_version TEXT NOT NULL,
    files_scanned INTEGER, archive_bytes INTEGER, blockers INTEGER, criticals INTEGER,
    majors INTEGER, supply_chain INTEGER, issue_count INTEGER, verdict TEXT, issues TEXT,
    artifacts TEXT, UNIQUE (package_id, version, profile, engine_version));
INSERT INTO packages (ecosystem, name, added_at) VALUES ('npm', 'kept', '2026-09-01T00:00:00+00:00');
"""


def parse_time(text):
    return datetime.datetime.fromisoformat(text)


class SqliteCursorTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.path = os.path.join(d.name, "state.db")

    def open(self):
        store = repo.Store(self.path)
        self.addCleanup(store.close)
        return store

    def test_round_trip(self):
        store = self.open()
        self.assertIsNone(store.discovery_cursor("pypi"))
        before = datetime.datetime.now(UTC).replace(microsecond=0)
        store.save_discovery_cursor("pypi", 30000000, WHEN)
        seq, seq_time, updated = store.discovery_cursor("pypi")
        self.assertEqual((seq, seq_time), ("30000000", "2026-09-26T17:47:30+00:00"))
        self.assertGreaterEqual(parse_time(updated), before)
        store.save_discovery_cursor("npm", 123)                     # time unknown
        store.save_discovery_cursor("pypi", 30000100, WHEN + datetime.timedelta(hours=1))
        store.close()
        store = self.open()                                          # persisted
        self.assertEqual(store.discovery_cursor("pypi")[:2], ("30000100", "2026-09-26T18:47:30+00:00"))
        self.assertEqual(store.discovery_cursor("npm")[:2], ("123", None))
        rows = store.conn.execute("SELECT count(*) FROM discovery_cursors").fetchone()[0]
        self.assertEqual(rows, 2)                                    # one row per registry

    def test_times_are_stored_in_utc(self):
        store = self.open()
        plus2 = datetime.timezone(datetime.timedelta(hours=2))
        store.save_discovery_cursor("pypi", 7, datetime.datetime(2026, 9, 26, 19, 47, 30, tzinfo=plus2))
        self.assertEqual(store.discovery_cursor("pypi")[1], "2026-09-26T17:47:30+00:00")

    def test_an_existing_database_gets_the_table(self):
        conn = sqlite3.connect(self.path)
        conn.executescript(OLD_SQLITE)
        conn.close()
        for _ in range(2):                                           # idempotent
            self.open().close()
        store = self.open()
        store.save_discovery_cursor("npm", 42)
        self.assertEqual(store.discovery_cursor("npm")[0], "42")
        self.assertEqual([tuple(r)[1:] for r in store.packages()], [("npm", "kept")])

    def test_schema_sql_declares_the_table(self):
        with open(os.path.join(_support.PKG, "registry", "schema.sql"), encoding="utf-8") as fh:
            sql = fh.read()
        self.assertIn("CREATE TABLE IF NOT EXISTS discovery_cursors (", sql)
        self.assertIn("ON packages, scans, discovery_cursors TO lazaret_app", sql)


class CursorConn(FakeConn):
    """FakeConn (the Store's fake lazaret.pg connection) that executes the
    discovery_cursors statements on SQLite, $n mapped to ?n. Everything else
    behaves as in FakeConn, including a scripted dropped session."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.db = sqlite3.connect(":memory:")
        self.scripts, self.sent = [], []

    def execute_script(self, sql):
        super().execute_script(sql)
        self.scripts.append(sql)
        for statement in sql.split(";"):
            if "discovery_cursors" in statement:
                self.db.execute(statement)

    def _run(self, op, sql, args):
        self._op(op)
        self.sent.append((sql, args))
        return self.db.execute(re.sub(r"\$(\d+)", r"?\1", sql), args)

    def fetchrow(self, sql, *args):
        if "discovery_cursors" not in sql:
            return super().fetchrow(sql, *args)
        return self._run("fetchrow", sql, args).fetchone()

    def execute(self, sql, *args):
        if "discovery_cursors" not in sql:
            return super().execute(sql, *args)
        self._run("INSERT", sql, args)


class PostgresFakeCursorTests(unittest.TestCase):
    def test_the_table_comes_with_the_schema(self):
        conn = CursorConn()
        pg_store(conn)
        self.assertEqual(conn.ops, ["schema"])                  # still one script
        self.assertIn("CREATE TABLE IF NOT EXISTS discovery_cursors (", conn.scripts[0])

    def test_round_trip(self):
        conn = CursorConn()
        store = pg_store(conn)
        self.assertIsNone(store.discovery_cursor("npm"))
        store.save_discovery_cursor("npm", 123456, WHEN)
        store.save_discovery_cursor("npm", 123999)
        self.assertEqual(store.discovery_cursor("npm")[:2], ("123999", None))
        store.save_discovery_cursor("pypi", 30000000, WHEN)
        self.assertEqual(store.discovery_cursor("pypi")[:2], ("30000000", "2026-09-26T17:47:30+00:00"))
        insert, args = next(s for s in conn.sent if s[0].startswith("INSERT"))
        self.assertIn("VALUES ($1,$2,$3,$4) ON CONFLICT (ecosystem) DO UPDATE", insert)
        self.assertEqual(args[:3], ("npm", "123456", "2026-09-26T17:47:30+00:00"))
        select, args = next(s for s in conn.sent if s[0].startswith("SELECT"))
        self.assertIn("WHERE ecosystem=$1", select)
        self.assertEqual(args, ("npm",))

    def test_a_dropped_session_is_retried_once(self):
        conn = CursorConn()
        store = pg_store(conn)
        conn.fail = 1
        store.save_discovery_cursor("pypi", 5)
        conn.fail = 1
        self.assertEqual(store.discovery_cursor("pypi")[0], "5")
        self.assertEqual(conn.ops, ["schema", "INSERT", "reconnect", "INSERT",
                                    "fetchrow", "reconnect", "fetchrow"])


@_support.requires_env("LAZARET_TEST_PG_DSN")
class LivePostgresCursorTests(unittest.TestCase):
    DB = "lz_review_discovery_cursor"

    @classmethod
    def setUpClass(cls):
        from lazaret import pg
        base = os.environ["LAZARET_TEST_PG_DSN"]
        admin = pg.connect(base, timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.DB}"')
            admin.execute(f'CREATE DATABASE "{cls.DB}"')
        finally:
            admin.close()
        cls.dsn = base.rsplit("/", 1)[0] + "/" + cls.DB
        conn = pg.connect(cls.dsn, timeout=10)                # the 0.1.2 schema
        try:
            conn.execute_script("""CREATE TABLE packages (id SERIAL PRIMARY KEY,
                ecosystem TEXT NOT NULL, name TEXT NOT NULL, added_at TEXT NOT NULL,
                UNIQUE (ecosystem, name));
                CREATE TABLE scans (id SERIAL PRIMARY KEY,
                package_id INTEGER NOT NULL REFERENCES packages(id), version TEXT NOT NULL,
                profile TEXT NOT NULL, scanned_at TEXT NOT NULL, engine_version TEXT NOT NULL,
                files_scanned INTEGER, archive_bytes INTEGER, blockers INTEGER,
                criticals INTEGER, majors INTEGER, supply_chain INTEGER, issue_count INTEGER,
                verdict TEXT, issues JSONB, artifacts JSONB,
                UNIQUE (package_id, version, profile, engine_version))""")
        finally:
            conn.close()

    @classmethod
    def tearDownClass(cls):
        from lazaret import pg
        admin = pg.connect(os.environ["LAZARET_TEST_PG_DSN"], timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.DB}"')
        finally:
            admin.close()

    def test_existing_database_round_trip(self):
        for _ in range(2):
            repo.Store(self.dsn).close()
        store = repo.Store(self.dsn)
        try:
            self.assertIsNone(store.discovery_cursor("pypi"))
            store.save_discovery_cursor("pypi", 30000000, WHEN)
            store.save_discovery_cursor("pypi", 30000100)
            store.save_discovery_cursor("npm", 99)
            self.assertEqual(store.discovery_cursor("pypi")[:2], ("30000100", None))
            self.assertEqual(store.discovery_cursor("npm")[:2], ("99", None))
            self.assertEqual(store.conn.fetchval("SELECT count(*) FROM discovery_cursors"), 2)
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
