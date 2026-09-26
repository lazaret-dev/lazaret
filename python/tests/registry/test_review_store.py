"""Review findings 10, 14 and 17: the registry state store.

10. Postgres rejected issues holding NUL (a hook command "node i.js\\u0000")
    or lone surrogates (a member name that is not UTF-8) — and save_scan ran
    outside cmd_scan's per-package try, so the sweep aborted and the verdict
    was lost. Text is now made storable first, and a failure to store is a
    visible error that fails the run at the end without stopping the sweep.
14. scan-all specs carry no version, so has_scan never matched: every sweep
    re-downloaded and re-scanned everything. The current version is now
    resolved first and an already-scanned one is skipped before download.
6.  (schema) scans.artifacts, the per-file detail of a multi-file PyPI
    scan, is added in place to existing SQLite and Postgres databases.
17. Only lower-case postgres:// selected Postgres; a libpq keyword DSN
    ("host=… password=… dbname=…") silently created a SQLite FILE named
    after it, password included.
"""

import contextlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from lazaret.registry import repo
from tests import _support
from tests.registry._review_support import DECODE_EXEC_JS, tarball
from tests.registry.test_review_pypi_artifacts import EVIL_WHEEL, SDIST, Release

NUL_HOOK = tarball({"package.json": json.dumps({"name": "b", "scripts": {"postinstall": "node i.js\u0000"}}),
                    "i.js": "1\n"})


def badname_tgz():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", encoding="utf-8", errors="surrogateescape") as tf:
        data = DECODE_EXEC_JS.encode()
        ti = tarfile.TarInfo("package/\udcff.js")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


ARTIFACTS = {"a-good": tarball({"index.js": "module.exports = 1;\n"}),
             "b-nul": NUL_HOOK, "c-badname": badname_tgz(),
             "d-good": tarball({"index.js": "module.exports = 2;\n"})}


def fake_registry(calls=None):
    def resolve_npm(name, version):
        return ("1.0.0", f"https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz", "tgz", "npm", {})

    def http_bytes(url):
        if calls is not None:
            calls.append(url)
        return ARTIFACTS[url.split("/")[3]]
    return (mock.patch.object(repo, "resolve_npm", side_effect=resolve_npm),
            mock.patch.object(repo, "http_bytes", side_effect=http_bytes),
            mock.patch.object(repo, "verify_digest", return_value=None))


def sweep(store, specs, rescan=False, errors=None):
    patches = fake_registry()
    with patches[0], patches[1], patches[2], contextlib.redirect_stdout(io.StringIO()) as out, \
            contextlib.redirect_stderr(io.StringIO()) as err:
        bad = repo.cmd_scan(store, specs, False, rescan, errors=errors)
    return bad, out.getvalue(), err.getvalue()


class SanitizeTests(unittest.TestCase):
    def test_db_text(self):
        self.assertEqual(repo._db_text("node i.js\x00"), "node i.js\\x00")
        self.assertEqual(repo._db_text("a\udcff.js"), "a\\udcff.js")
        self.assertEqual(repo._db_text("é ok"), "é ok")
        blob = repo.db_json([{"cmd": "x\x00", "file": "\udcff.js", "n": 1}])
        self.assertNotIn("\\u0000", blob)
        self.assertEqual(json.loads(blob), [{"cmd": "x\\x00", "file": "\\udcff.js", "n": 1}])

    def test_sqlite_sweep_keeps_every_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            store = repo.Store(os.path.join(d, "r.db"))
            try:
                bad, out, _err = sweep(store, [f"npm:{n}" for n in ARTIFACTS])
                verdicts = {r[1]: r[5] for r in store.status()}
            finally:
                store.conn.close()
        self.assertTrue(bad)
        self.assertEqual(verdicts, {"a-good": "OK", "b-nul": "WARN", "c-badname": "SUSPICIOUS",
                                    "d-good": "OK"})


class SaveFailureTests(unittest.TestCase):
    def test_store_failure_is_an_error_but_the_sweep_continues(self):
        with tempfile.TemporaryDirectory() as d:
            store = repo.Store(os.path.join(d, "r.db"))
            try:
                real = store.save_scan

                def flaky(pid, res):
                    if res["name"] == "b-nul":
                        raise OSError("disk full")
                    return real(pid, res)
                store.save_scan = flaky
                errors = []
                bad, out, err = sweep(store, ["npm:a-good", "npm:b-nul", "npm:d-good"], errors=errors)
                verdicts = {r[1]: r[5] for r in store.status()}
            finally:
                store.conn.close()
        self.assertEqual(errors, ["npm:b-nul"])
        self.assertIn("error storing the scan of npm:b-nul", err)
        self.assertIn("npm:b-nul@1.0.0", out)              # the verdict is still printed
        self.assertEqual(verdicts["d-good"], "OK")         # later packages still stored
        self.assertIsNone(verdicts["b-nul"])

    def test_bad_watchlist_entry_does_not_stop_the_sweep(self):
        with tempfile.TemporaryDirectory() as d:
            store = repo.Store(os.path.join(d, "r.db"))
            try:
                bad, out, err = sweep(store, ["npm:.bad", "npm:a-good"])
            finally:
                store.conn.close()
        self.assertIn("error scanning npm:.bad", err)
        self.assertIn("npm:a-good@1.0.0", out)


class IncrementalTests(unittest.TestCase):
    def test_scan_all_skips_known_versions_before_downloading(self):
        with tempfile.TemporaryDirectory() as d:
            store = repo.Store(os.path.join(d, "r.db"))
            calls = []
            patches = fake_registry(calls)
            try:
                with patches[0], patches[1], patches[2], contextlib.redirect_stdout(io.StringIO()) as out:
                    repo.cmd_scan(store, ["npm:a-good"], False, False)
                    repo.cmd_scan(store, ["npm:a-good"], False, False)
                    self.assertEqual(len(calls), 1)
                    self.assertIn("already scanned", out.getvalue())
                    repo.cmd_scan(store, ["npm:a-good"], False, True)          # --rescan
                    self.assertEqual(len(calls), 2)
            finally:
                store.conn.close()

    def test_metadata_fetched_once_per_package(self):
        with tempfile.TemporaryDirectory() as d:
            store = repo.Store(os.path.join(d, "r.db"))
            patches = fake_registry()
            try:
                with patches[0] as resolve, patches[1], patches[2], \
                        contextlib.redirect_stdout(io.StringIO()):
                    repo.cmd_scan(store, ["npm:a-good"], False, False)
                    self.assertEqual(resolve.call_count, 1)
            finally:
                store.conn.close()


class DsnTests(unittest.TestCase):
    def test_classification(self):
        cases = {
            "postgres://u@h/db": ("pg", "postgres://u@h/db"),
            "POSTGRESQL://u@h/db": ("pg", "postgresql://u@h/db"),
            "PostgreS://u@h/db": ("pg", "postgres://u@h/db"),
            "host=db user=app password=S3cret dbname=lazaret": ("pg", "host=db user=app password=S3cret dbname=lazaret"),
            " dbname=lazaret": ("pg", "dbname=lazaret"),
            "sqlite:r.db": ("sqlite", "r.db"),
            "sqlite:///r.db": ("sqlite", "r.db"),
            "sqlite:////abs/r.db": ("sqlite", "/abs/r.db"),
            "SQLITE::memory:": ("sqlite", ":memory:"),
            "lazaret-registry.db": ("sqlite", "lazaret-registry.db"),
            ":memory:": ("sqlite", ":memory:"),
        }
        for dsn, want in cases.items():
            with self.subTest(dsn=dsn):
                self.assertEqual(repo.classify_dsn(dsn), want)

    def test_refused_without_echoing_the_value(self):
        for dsn in ("hostname=db pwd=S3cret", "db=S3cret.sqlite", "mysql://u:S3cret@h/db", ""):
            with self.subTest(dsn=dsn):
                with self.assertRaises(repo.StoreConfigError) as ctx:
                    repo.classify_dsn(dsn)
                self.assertNotIn("S3cret", str(ctx.exception))
                self.assertIsInstance(ctx.exception, RuntimeError)

    def test_keyword_dsn_never_creates_a_file(self):
        with tempfile.TemporaryDirectory() as d:
            dsn = "host=127.0.0.1 port=1 user=app password=S3cret dbname=lazaret connect_timeout=2"
            p = subprocess.run([sys.executable, _support.REGISTRY, "list", "--db", dsn],
                               capture_output=True, text=True, cwd=d, timeout=40, encoding="utf-8", errors="replace")
            self.assertNotEqual(p.returncode, 0)
            self.assertIn("Postgres backend unreachable", p.stderr)
            self.assertNotIn("S3cret", p.stderr + p.stdout)
            self.assertEqual(os.listdir(d), [])
            p = subprocess.run([sys.executable, _support.REGISTRY, "list", "--db", "db=S3cret"],
                               capture_output=True, text=True, cwd=d, timeout=40, encoding="utf-8", errors="replace")
            self.assertNotEqual(p.returncode, 0)
            self.assertNotIn("S3cret", p.stderr + p.stdout)
            self.assertEqual(os.listdir(d), [])


@_support.requires_env("LAZARET_TEST_PG_DSN")
class PostgresStoreTests(unittest.TestCase):
    DB = "lz_review_store"

    @classmethod
    def setUpClass(cls):
        from lazaret import pg
        base = os.environ["LAZARET_TEST_PG_DSN"]
        admin = pg.connect(base, timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.DB}"')
            admin.execute(f"CREATE DATABASE \"{cls.DB}\" ENCODING 'UTF8' TEMPLATE template0")
        finally:
            admin.close()
        cls.dsn = base.rsplit("/", 1)[0] + "/" + cls.DB

    @classmethod
    def tearDownClass(cls):
        from lazaret import pg
        admin = pg.connect(os.environ["LAZARET_TEST_PG_DSN"], timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.DB}"')
        finally:
            admin.close()

    def test_nul_and_surrogates_are_stored(self):
        store = repo.Store(self.dsn.replace("postgres://", "POSTGRES://", 1))
        try:
            bad, _out, err = sweep(store, [f"npm:{n}" for n in ARTIFACTS], rescan=True)
            self.assertNotIn("error", err)
            verdicts = {r[1]: r[5] for r in store.status()}
            self.assertEqual(verdicts, {"a-good": "OK", "b-nul": "WARN", "c-badname": "SUSPICIOUS",
                                        "d-good": "OK"})
            rep = store.report("npm", "c-badname")
            self.assertEqual(rep["issues"][0]["file"], "\\udcff.js")
            rep = store.report("npm", "b-nul")
            self.assertEqual(rep["issues"][0]["cmd"], "node i.js\\x00")
        finally:
            store.conn.close()



def _old_schema_sqlite(path):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE packages (id INTEGER PRIMARY KEY AUTOINCREMENT,
        ecosystem TEXT NOT NULL, name TEXT NOT NULL, added_at TEXT NOT NULL,
        UNIQUE (ecosystem, name))""")
    conn.execute("""CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_id INTEGER NOT NULL REFERENCES packages(id), version TEXT NOT NULL,
        profile TEXT NOT NULL, scanned_at TEXT NOT NULL, engine_version TEXT NOT NULL,
        files_scanned INTEGER, archive_bytes INTEGER, blockers INTEGER, criticals INTEGER,
        majors INTEGER, supply_chain INTEGER, issue_count INTEGER, verdict TEXT, issues TEXT,
        UNIQUE (package_id, version, profile, engine_version))""")
    conn.commit()
    conn.close()


class SchemaTests(unittest.TestCase):
    def result(self):
        rel = Release([("x-1.0.tar.gz", SDIST, "sdist"),
                       ("x-1.0-py3-none-any.whl", EVIL_WHEEL, "bdist_wheel")])
        return rel.scan()

    def test_sqlite_migrates_in_place_and_round_trips(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.db")
            _old_schema_sqlite(path)
            for _ in range(2):                       # idempotent
                store = repo.Store(path)
                store.conn.close()
            store = repo.Store(path)
            try:
                pid, _ = store.add_package("pypi", "x")
                store.save_scan(pid, self.result())
                rep = store.report("pypi", "x", "1.0")
                self.assertEqual([a["verdict"] for a in rep["artifacts"]], ["OK", "SUSPICIOUS"])
                self.assertEqual(rep["verdict"], "SUSPICIOUS")
            finally:
                store.conn.close()

    def test_schema_sql_declares_the_column(self):
        with open(os.path.join(_support.PKG, "registry", "schema.sql"), encoding="utf-8") as fh:
            sql = fh.read()
        self.assertIn("artifacts      JSONB", sql)
        self.assertIn("ADD COLUMN IF NOT EXISTS artifacts JSONB", sql)


@_support.requires_env("LAZARET_TEST_PG_DSN")
class PostgresSchemaTests(unittest.TestCase):
    DB = "lz_review_artifacts"

    @classmethod
    def setUpClass(cls):
        from lazaret import pg
        base = os.environ["LAZARET_TEST_PG_DSN"]
        admin = pg.connect(base, timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.DB}"')
            admin.execute(f"CREATE DATABASE \"{cls.DB}\" ENCODING 'UTF8' TEMPLATE template0")
        finally:
            admin.close()
        cls.dsn = base.rsplit("/", 1)[0] + "/" + cls.DB
        conn = pg.connect(cls.dsn, timeout=10)          # the pre-2.4 schema
        try:
            conn.execute_script("""CREATE TABLE packages (id SERIAL PRIMARY KEY,
                ecosystem TEXT NOT NULL, name TEXT NOT NULL, added_at TEXT NOT NULL,
                UNIQUE (ecosystem, name));
                CREATE TABLE scans (id SERIAL PRIMARY KEY,
                package_id INTEGER NOT NULL REFERENCES packages(id), version TEXT NOT NULL,
                profile TEXT NOT NULL, scanned_at TEXT NOT NULL, engine_version TEXT NOT NULL,
                files_scanned INTEGER, archive_bytes INTEGER, blockers INTEGER,
                criticals INTEGER, majors INTEGER, supply_chain INTEGER, issue_count INTEGER,
                verdict TEXT, issues JSONB,
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

    def test_postgres_migrates_in_place_and_round_trips(self):
        for _ in range(2):
            repo.Store(self.dsn).conn.close()
        store = repo.Store(self.dsn)
        try:
            pid, _ = store.add_package("pypi", "x")
            store.save_scan(pid, SchemaTests.result(self))
            rep = store.report("pypi", "x", "1.0")
            self.assertEqual([a["verdict"] for a in rep["artifacts"]], ["OK", "SUSPICIOUS"])
        finally:
            store.conn.close()


if __name__ == "__main__":
    unittest.main()
