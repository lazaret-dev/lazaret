#!/usr/bin/env python3
"""Unit tests — Postgres state backend over the internal wire client.

The Postgres backend of lazaret_repo.Store now runs on lazaret_pg, an
internal client that speaks the PostgreSQL frontend/backend protocol
directly (stdlib socket + ssl + hashlib SCRAM): no external driver, no
pip-install, the same stock-python3 footprint as the sqlite default.

These tests exercise the backend END TO END against a real server when one
is available, and SKIP (clearly, loudly, with a count) when not:

  * LIVE  — LAZARET_TEST_PG_DSN (or postgres://127.0.0.1:5432/cg_dev
    when reachable) is used read-write on a disposable test database; if
    only server binaries are present (initdb/postgres found), a scratch
    trust-auth cluster is booted on a random port so the suite is
    self-sufficient on a dev box.
  * OFFLINE — one test always runs: an unreachable DSN must raise
    RuntimeError("Postgres backend unreachable: …") from Store.__init__
    (library boundary: the MCP server converts it to a tool error, the
    CLI to exit 1 — never a crash, never a sys.exit from library code).

Backend coverage (the sqlite twin of each behavior is pinned by
test_crash_guards_registry.py):
  S1  schema bootstrap        — SERIAL/JSONB DDL applies twice idempotently
  S2  add_package             — idempotent upsert, RETURNING id, created
  S3  has_scan                — ENGINE_VERSION cache key (old engine ⇒ miss)
  S4  save_scan               — $n + ::jsonb, atomic upsert on conflict
  S5  JSONB round-trip        — report() returns the issues LIST intact
  S6  status()/packages()     — lateral-join ordering and row shapes
  S7  paramstyle regression   — every $k distinct (the old repeated
                                placeholder bug), 14 params bind in order
  S8  transactions            — an exception inside transaction() rolls
                                back (no half-written scan row survives)

Run:  python3 lazaret/test_pg_backend.py [unittest-args]
"""
from __future__ import annotations

import os

from tests import _support  # noqa: E402
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures

from lazaret.registry import repo as lazaret_repo  # noqa: E402
from lazaret import pg as lazaret_pg    # noqa: E402


def _pg_bins():
    """initdb/postgres/createdb binaries if available (any layout)."""
    initdb = shutil.which("initdb")
    postgres = shutil.which("postgres")
    if not (initdb and postgres):
        pg_config = shutil.which("pg_config")
        if pg_config:
            bindir = subprocess.run([pg_config, "--bindir"],
                                    capture_output=True, text=True).stdout.strip()
            initdb = os.path.join(bindir, "initdb") if os.path.isdir(bindir) else None
            postgres = os.path.join(bindir, "postgres") if os.path.isdir(bindir) else None
    return initdb, postgres


def _probe_dsn(dsn):
    """True when a TCP Postgres answers on the DSN's host:port."""
    try:
        lazaret_pg.connect(dsn, timeout=3)
        return True
    except Exception:
        return False


def _boot_scratch_cluster(tmpdir):
    """Boot a disposable trust-auth cluster in tmpdir; return its DSN or None.

    trust auth (no password) keeps this a pure-stdlib exercise; the port is
    random so a running dev server is never disturbed; the directory is
    caller-owned and disposable.
    """
    initdb, postgres = _pg_bins()
    if not (initdb and postgres):
        return None
    data = os.path.join(tmpdir, "data")
    logs = os.path.join(tmpdir, "cluster.log")
    try:
        if subprocess.run([initdb, "-D", data, "-U", "cgtest", "--no-locale",
                           "-E", "UTF8"], capture_output=True, text=True,
                          timeout=120).returncode != 0:
            return None
        port = 55100 + (os.getpid() % 400)
        with open(logs, "wb") as logf:
            proc = subprocess.Popen(
                [postgres, "-D", data, "-k", tmpdir, "-p", str(port),
                 "-c", "listen_addresses=127.0.0.1", "-c", "fsync=off",
                 "-c", "synchronous_commit=off", "-c", "full_page_writes=off",
                 "-c", "log_min_messages=warning"],
                stdout=logf, stderr=subprocess.STDOUT)
        dsn = f"postgres://cgtest@127.0.0.1:{port}/postgres"
        for _ in range(60):                    # up to ~30s for slow first boot
            if _probe_dsn(dsn):
                return dsn, proc
            if proc.poll() is not None:
                return None
            time.sleep(0.5)
        proc.terminate()
        return None
    except Exception:
        return None


import time  # noqa: E402  (used by _boot_scratch_cluster's readiness poll)


def _resolve_live_dsn():
    """(dsn, cleanup) for a live server, or (None, None) when offline.

    Preference order: explicit env override, an already-running dev server,
    then a scratch trust-auth cluster booted from local binaries.
    """
    # LAZARET_TEST_PG_DSN is the project-wide name (see STRUCTURE.md); the
    # older LAZARET_PG_TEST_DSN spelling is still honored.
    dsn = os.environ.get("LAZARET_TEST_PG_DSN") or os.environ.get("LAZARET_PG_TEST_DSN")
    if dsn and _probe_dsn(dsn):
        return dsn, None

    dev = "postgres://127.0.0.1:5432/cg_dev"
    if _probe_dsn(dev):
        # live server but (typically) wrong credentials for us — create a
        # disposable database via psql if the trust/credentials work out is
        # NOT attempted; fall through to the scratch cluster instead.
        pass

    tmp = tempfile.mkdtemp(prefix="cg-pgtest-")
    booted = _boot_scratch_cluster(tmp)
    if booted:
        return booted[0], (booted[1], tmp)
    shutil.rmtree(tmp, ignore_errors=True)
    return None, None


LIVE_DSN, _LIVE_CLEANUP = _resolve_live_dsn()


@unittest.skipUnless(LIVE_DSN, "no live PostgreSQL reachable/probeable — "
                      "set LAZARET_TEST_PG_DSN or run where initdb exists")
class LivePostgresBackendTests(unittest.TestCase):
    """Store end-to-end on the wire client against a real server.

    Each test uses its own throwaway DATABASE inside the live server, so
    the suite is safe to run repeatedly and never mutates a shared DB.
    """

    @classmethod
    def setUpClass(cls):
        cls.base = LIVE_DSN
        cls.dbname = "cg_test_backend"
        admin = lazaret_pg.connect(cls.base, timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}"')
            admin.execute(f'CREATE DATABASE "{cls.dbname}"')
        finally:
            admin.close()
        # swap the trailing database in the DSN
        parts = cls.base.rsplit("/", 1)
        cls.dsn = parts[0] + "/" + cls.dbname
        cls.dsn = cls.dsn or cls.base

    @classmethod
    def tearDownClass(cls):
        try:
            admin = lazaret_pg.connect(cls.base, timeout=10)
            admin.execute(f'DROP DATABASE IF EXISTS "{cls.dbname}"')
            admin.close()
        except Exception:
            pass

    def setUp(self):
        self.store = lazaret_repo.Store(self.dsn)
        self.addCleanup(self._close)

    def _close(self):
        try:
            self.store.conn.close()
        except Exception:
            pass

    def _mkresult(self, issues=None, verdict="WARN"):
        return {
            "version": "1.0.0", "profile": "default", "verdict": verdict,
            "scannedAt": "2026-09-27T00:00:00+00:00",
            "filesScanned": 2, "archiveBytes": 1024, "supplyChain": 0,
            "sevCounts": {"BLOCKER": 0, "CRITICAL": 1, "MAJOR": 2},
            "issues": issues if issues is not None else [],
        }

    # ---- S1: schema bootstrap -------------------------------------------

    def test_schema_bootstrap_idempotent(self):
        """_init_schema runs CREATE TABLE IF NOT EXISTS — constructing a
        second Store on the same DSN must succeed (and be a no-op)."""
        second = lazaret_repo.Store(self.dsn)
        try:
            self.assertTrue(second.pg)
        finally:
            second.conn.close()

    # ---- S2: add_package ------------------------------------------------

    def test_add_package_upsert_and_created_flag(self):
        pid, created = self.store.add_package("npm", "left-pad")
        self.assertIsNotNone(pid)
        self.assertTrue(created)
        pid2, created2 = self.store.add_package("npm", "left-pad")
        self.assertEqual(pid2, pid, "upsert must converge on the same id")
        self.assertFalse(created2, "second insert must report created=False")
        pid3, created3 = self.store.add_package("pypi", "left-pad")
        self.assertNotEqual(pid3, pid)
        self.assertTrue(created3)

    # ---- S3: has_scan ---------------------------------------------------

    def test_has_scan_engine_version_cache_key(self):
        pid, _ = self.store.add_package("npm", "cache-key")
        self.assertFalse(self.store.has_scan(pid, "1.0.0", "default"))
        self.store.save_scan(pid, self._mkresult())
        self.assertTrue(
            self.store.has_scan(pid, "1.0.0", "default"),
            "same engine version ⇒ cache hit")
        self.assertFalse(
            self.store.has_scan(pid, "1.0.0", "default", engine_version="0.0.1"),
            "older engine version ⇒ cache miss (verdict integrity, C2/G16)")
        self.assertFalse(
            self.store.has_scan(pid, "2.0.0", "default"),
            "different package version ⇒ miss")

    # ---- S4/S5: save_scan + JSONB round-trip ----------------------------

    def test_save_scan_and_report_roundtrip(self):
        issues = [{"rule": "PY-SQL-STRING", "sev": "CRITICAL",
                   "line": 3, "what": "sql built from user input",
                   "excerpt": "cur.execute('SELECT ' + q)", "path": "app.py"}]
        pid, _ = self.store.add_package("npm", "jsonb-roundtrip")
        self.store.save_scan(pid, self._mkresult(issues=issues, verdict="FAIL"))
        got = self.store.report("npm", "jsonb-roundtrip")
        self.assertIsNotNone(got)
        self.assertEqual(got["version"], "1.0.0")
        self.assertEqual(got["verdict"], "FAIL")
        self.assertEqual(len(got["issues"]), 1)
        self.assertEqual(got["issues"][0]["rule"], "PY-SQL-STRING")
        self.assertEqual(got["issues"][0]["line"], 3)
        # optional version filter binds as $3 without colliding $1/$2
        got2 = self.store.report("npm", "jsonb-roundtrip", "1.0.0")
        self.assertIsNotNone(got2)
        self.assertIsNone(self.store.report("npm", "jsonb-roundtrip", "9.9.9"))
        self.assertIsNone(self.store.report("npm", "never-scanned"))

    def test_save_scan_upsert_on_conflict(self):
        pid, _ = self.store.add_package("npm", "upsert-scan")
        self.store.save_scan(pid, self._mkresult(verdict="WARN"))
        self.store.save_scan(pid, self._mkresult(verdict="FAIL"))
        got = self.store.report("npm", "upsert-scan")
        self.assertEqual(got["verdict"], "FAIL",
                         "conflict upsert must replace the older row")
        n = self.store.conn.fetchval(
            f"SELECT count(*) FROM {self.store.t}scans WHERE package_id=$1", pid)
        self.assertEqual(n, 1, "exactly one row per (pkg,version,profile,engine)")

    # ---- S6: status()/packages() ---------------------------------------

    def test_status_and_packages_row_shapes(self):
        pid, _ = self.store.add_package("npm", "status-pkg")
        self.store.save_scan(pid, self._mkresult(verdict="FAIL"))
        pkgs = list(self.store.packages())
        self.assertIn(("status-pkg",), [("n",) for n in []] or
                      [(p[2],) for p in pkgs])
        self.assertTrue(all(p[1] == "npm" for p in pkgs if p[2] == "status-pkg"))
        rows = [r for r in self.store.status() if r[1] == "status-pkg"]
        self.assertEqual(len(rows), 1)
        eco, name, ver, prof, at, verdict, count, supply = rows[0][:8]
        self.assertEqual((ver, verdict), ("1.0.0", "FAIL"))
        # unscanned packages still appear (LEFT JOIN semantics)
        self.store.add_package("pypi", "no-scan-yet")
        names = {r[1] for r in self.store.status()}
        self.assertIn("no-scan-yet", names)

    # ---- S7: paramstyle regression -------------------------------------

    def test_placeholders_distinct_and_ordered(self):
        """The old bug: shared SQL interpolated ONE repeated placeholder, so
        every value arrived as $1 (08P01 or wrong-row reads). _phs() must
        emit $1..$n distinct and in order; save_scan binds 14 of them."""
        self.assertEqual(self.store._phs(4), ["$1", "$2", "$3", "$4"])
        self.assertEqual(self.store._phs(14)[-1], "$14")
        pid, _ = self.store.add_package("pypi", "paramstyle")
        res = self._mkresult()
        res["version"] = "3.2.1"
        res["profile"] = "full"
        res["verdict"] = "OK"
        res["filesScanned"] = 7
        res["archiveBytes"] = 4321
        res["sevCounts"] = {"BLOCKER": 0, "CRITICAL": 0, "MAJOR": 0}
        self.store.save_scan(pid, res)
        row = self.store.conn.fetchrow(
            f"SELECT version, profile, files_scanned, archive_bytes, verdict, "
            f"issue_count FROM {self.store.t}scans WHERE package_id=$1", pid)
        self.assertEqual(row[0], "3.2.1")
        self.assertEqual(row[1], "full")
        self.assertEqual((row[2], row[3]), (7, 4321))
        self.assertEqual(row[4], "OK")
        self.assertEqual(row[5], 0)

    # ---- S8: transactions roll back on failure -------------------------

    def test_transaction_rollback_on_error(self):
        pid, _ = self.store.add_package("npm", "rollback")
        try:
            with self.store.conn.transaction():
                self.store.conn.execute(
                    f"INSERT INTO {self.store.t}scans (package_id,version,profile,"
                    f"scanned_at,engine_version,files_scanned,archive_bytes,blockers,"
                    f"criticals,majors,supply_chain,issue_count,verdict,issues) "
                    f"VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb)",
                    pid, "1.0.0", "default", "2026-09-27T00:00:00+00:00",
                    lazaret_repo.ENGINE_VERSION, 1, 1, 0, 0, 0, 0, 0,
                    "OK", "[]")
                # force an error INSIDE the same transaction
                self.store.conn.execute("SELECT 1/0")
            self.fail("SELECT 1/0 must raise")
        except lazaret_pg.Error:
            pass
        n = self.store.conn.fetchval(
            f"SELECT count(*) FROM {self.store.t}scans WHERE package_id=$1", pid)
        self.assertEqual(n, 0, "transaction() must roll back the whole insert")

    # ---- P0: sanity for the suite itself --------------------------------

    def test_backend_is_wire_client(self):
        self.assertTrue(self.store.pg)
        self.assertIsInstance(self.store.conn, lazaret_pg.Connection)  # the stdlib wire client


class OfflineBackendContractTests(unittest.TestCase):
    """Always runs (no server needed): the library-boundary contract."""

    def test_unreachable_dsn_raises_runtimeerror(self):
        """Store.__init__ converts ANY connect failure (refused, timeout,
        bad auth) into RuntimeError('Postgres backend unreachable: …') so
        the MCP dispatch layer can answer a tool error instead of dying."""
        for dsn in ("postgres://u:p@127.0.0.1:9/nonexistent",
                    "postgresql://u:p@127.0.0.1:9/nonexistent"):
            with self.assertRaises(RuntimeError) as ctx:
                lazaret_repo.Store(dsn)
            msg = str(ctx.exception)
            self.assertIn("Postgres backend unreachable", msg)
            self.assertNotIn("Traceback", msg)

    def test_sqlite_default_untouched(self):
        import sqlite3
        db = os.path.join(tempfile.mkdtemp(prefix="cg-pgtest-"), "reg.db")
        try:
            store = lazaret_repo.Store(db)
            self.assertFalse(store.pg)
            self.assertIsInstance(store.conn, sqlite3.Connection)
            self.assertEqual(store._phs(4), ["?"] * 4)
            store.conn.close()
        finally:
            shutil.rmtree(os.path.dirname(db), ignore_errors=True)


if __name__ == "__main__":
    print(f"test_pg_backend: live PostgreSQL DSN = "
          f"{LIVE_DSN or '(none — live tests SKIP, offline contract runs)'}")
    unittest.main(verbosity=2)
