"""Integration tests against a real server.

Set LAZARET_TEST_PG_DSN to a DSN for a user with CREATEDB (the registry
backend tests share this variable and create a scratch database), e.g.
    LAZARET_TEST_PG_DSN=postgresql://lazaret:secret@localhost/lazaret_test
Skipped when unset.
"""

import ipaddress
import os
import threading
import time as time_mod
import unittest
import uuid
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal

from lazaret import pg
from tests import _support

DSN = os.environ.get("LAZARET_TEST_PG_DSN")


@_support.requires_env("LAZARET_TEST_PG_DSN")
class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.conn = c = pg.connect(DSN)
        c.execute("DROP TABLE IF EXISTS lz_t")
        c.execute("CREATE TABLE lz_t (id int PRIMARY KEY, name text, data jsonb)")

    def tearDown(self):
        if not self.conn.closed:
            self.conn.execute("DROP TABLE IF EXISTS lz_t")
            self.conn.close()

    def still_works(self):
        self.assertEqual(self.conn.fetchval("SELECT 1"), 1)

    def test_round_trip(self):
        cases = [
            (0, ""), (-(2**63), ""), (1.25, ""), (float("inf"), ""),
            (Decimal("12345678901234567890.123456789"), ""),
            ("héllo 🌍 'quotes' \"double\" \\back", "::text"), ("", "::text"),
            (True, ""), (False, ""), (b"\x00\x01\xff" * 1000, ""),
            (date(2026, 9, 24), ""), (datetime(2026, 9, 24, 13, 30, 5, 123456), ""),
            (datetime(2026, 9, 24, 13, 30, 5, 1, tzinfo=timezone(timedelta(hours=-5))), ""),
            (time(23, 59, 59, 999999), ""), (time(1, 2, 3, tzinfo=timezone(timedelta(hours=2))), ""),
            (timedelta(days=3, hours=4, microseconds=5), ""), (timedelta(days=-1, seconds=1), ""),
            (uuid.uuid4(), ""),
            ({"nested": {"list": [1, 2.5, None, "x"]}, "unicode": "ü"}, ""),
            (ipaddress.ip_address("2001:db8::1"), ""), (ipaddress.ip_interface("10.1.2.3/24"), ""),
            (ipaddress.ip_network("192.168.0.0/16"), ""),
            ([1, 2, None, 4], ""), (["a,b", 'q"q', "back\\slash", "NULL", ""], ""),
            ([[1, 2], [3, 4]], ""), ([True, False], ""), ([uuid.UUID(int=5)], ""), ([], "::int[]"),
        ]
        for value, cast in cases:
            with self.subTest(value=repr(value)[:40]):
                got = self.conn.fetchval(f"SELECT $1{cast}", value)
                self.assertEqual(got, value)
                self.assertIs(type(got), type(value))
        # beyond int8, ints are sent and returned as numeric
        self.assertEqual(self.conn.fetchval("SELECT $1", 2**63 + 7), Decimal(2**63 + 7))
        self.assertTrue(self.conn.fetchval("SELECT $1", Decimal("NaN")).is_nan())

    def test_json_wrapper_and_nulls(self):
        self.assertEqual(self.conn.fetchval("SELECT $1::jsonb", pg.Json([1, "a"])), [1, "a"])
        self.assertEqual(self.conn.fetchval("SELECT $1::jsonb", pg.Json("just a string")), "just a string")
        self.assertIsNone(self.conn.fetchval("SELECT $1::int", None))

    def test_server_side_values(self):
        row = self.conn.fetchrow("""
            SELECT 'infinity'::timestamptz AS inf, '1 mon 2 days'::interval AS mon,
                   '1 day 2 hours'::interval AS dh, 'NaN'::numeric AS nan,
                   '[0:1]={7,8}'::int[] AS bounds, ARRAY['x y', NULL, '"q"'] AS texts,
                   '{"a": 1}'::json AS j, 1.5::real AS r, 32767::smallint AS s,
                   'abc'::char(5) AS padded, '2026-01-01'::date - 3 AS d, 'x'::name AS n
        """)
        self.assertEqual((row.inf, row.mon, row.dh), ("infinity", "P1M2D", timedelta(days=1, hours=2)))
        self.assertTrue(row.nan.is_nan())
        self.assertEqual((row.bounds, row.texts), ([7, 8], ["x y", None, '"q"']))
        self.assertEqual((row.j, row.r, row.s), ({"a": 1}, 1.5, 32767))
        self.assertEqual((row.padded, row.d, row.n), ("abc  ", date(2025, 12, 29), "x"))

    def test_bytea_escape_output(self):
        self.conn.execute("SET bytea_output = 'escape'")
        self.assertEqual(self.conn.fetchval("SELECT $1::bytea", b"a\x00\\\xff"), b"a\x00\\\xff")

    def test_parameters_are_never_interpolated(self):
        evil = "x'); DROP TABLE lz_t; --"
        self.conn.execute("INSERT INTO lz_t (id, name) VALUES ($1, $2)", 1, evil)
        self.assertEqual(self.conn.fetchval("SELECT name FROM lz_t WHERE id = $1", 1), evil)
        self.assertEqual(self.conn.fetchval("SELECT count(*) FROM lz_t"), 1)

    def test_fetch_results_and_columns(self):
        c = self.conn
        self.assertEqual(c.execute("INSERT INTO lz_t VALUES (1,'a',NULL),(2,'b',NULL)").rowcount, 2)
        rows = c.fetch("SELECT id, name FROM lz_t ORDER BY id")
        self.assertEqual((rows, rows.columns), ([(1, "a"), (2, "b")], ("id", "name")))
        self.assertEqual((rows[1].name, rows[1].as_dict()), ("b", {"id": 2, "name": "b"}))
        empty = c.fetch("SELECT id, name FROM lz_t WHERE false")
        self.assertEqual((empty, empty.columns), ([], ("id", "name")))
        self.assertIsNone(c.fetchrow("SELECT 1 WHERE false"))
        self.assertEqual(c.execute("UPDATE lz_t SET name = 'z'").rowcount, 2)
        self.assertIsNone(c.execute("CREATE TEMP TABLE lz_tmp (x int)").rowcount)
        self.assertEqual(c.execute("").tag, "")

    def test_many_parameters(self):
        values = list(range(5000))
        placeholders = ",".join(f"${i + 1}" for i in values)
        self.assertEqual(self.conn.fetchval(f"SELECT array_length(ARRAY[{placeholders}], 1)", *values), 5000)

    def test_errors_leave_connection_usable(self):
        cases = [
            ("SELEC 1", (), pg.ProgrammingError, "42601"),
            ("SELECT * FROM no_such_table", (), pg.ProgrammingError, "42P01"),
            ("SELECT 1 / $1::int", (0,), pg.DataError, "22012"),
            ("SELECT $1::text", ("nul\x00byte",), pg.DataError, "22021"),
        ]
        for sql, args, exc, sqlstate in cases:
            with self.subTest(sql=sql):
                with self.assertRaises(exc) as info:
                    self.conn.fetch(sql, *args)
                self.assertEqual(info.exception.sqlstate, sqlstate)
                self.still_works()

    def test_integrity_error_details(self):
        self.conn.execute("INSERT INTO lz_t (id) VALUES (1)")
        with self.assertRaises(pg.IntegrityError) as info:
            self.conn.execute("INSERT INTO lz_t (id) VALUES (1)")
        self.assertEqual((info.exception.constraint, info.exception.table), ("lz_t_pkey", "lz_t"))
        self.assertIn("already exists", info.exception.detail)

    def test_transactions(self):
        c = self.conn
        with c.transaction():
            c.execute("INSERT INTO lz_t (id) VALUES (1)")
            self.assertTrue(c.in_transaction)
        self.assertFalse(c.in_transaction)
        with self.assertRaises(ZeroDivisionError):
            with c.transaction():
                c.execute("INSERT INTO lz_t (id) VALUES (2)")
                1 / 0
        with c.transaction():
            c.execute("INSERT INTO lz_t (id) VALUES (3)")
            with self.assertRaises(pg.IntegrityError):
                with c.transaction():  # savepoint
                    c.execute("INSERT INTO lz_t (id) VALUES (4)")
                    c.execute("INSERT INTO lz_t (id) VALUES (1)")
            c.execute("INSERT INTO lz_t (id) VALUES (5)")
        self.assertEqual([r.id for r in c.fetch("SELECT id FROM lz_t ORDER BY id")], [1, 3, 5])

    def test_swallowed_error_does_not_silently_commit(self):
        with self.assertRaisesRegex(pg.InterfaceError, "rolled back"):
            with self.conn.transaction():
                self.conn.execute("INSERT INTO lz_t (id) VALUES (1)")
                try:
                    self.conn.execute("SELEC")
                except pg.ProgrammingError:
                    pass
        self.assertEqual(self.conn.fetchval("SELECT count(*) FROM lz_t"), 0)

    def test_transaction_options(self):
        c = self.conn
        with c.transaction(isolation="serializable"):
            self.assertEqual(c.fetchval("SHOW transaction_isolation"), "serializable")
        with self.assertRaises(pg.DatabaseError) as info:
            with c.transaction(readonly=True):
                c.execute("INSERT INTO lz_t (id) VALUES (1)")
        self.assertEqual(info.exception.sqlstate, "25006")  # read_only_sql_transaction
        self.assertFalse(c.in_transaction)
        with self.assertRaises(pg.InterfaceError):
            with c.transaction(isolation="whenever"):
                pass

    def test_executemany(self):
        rows = [(i, f"n{i}" if i % 3 else None) for i in range(1, 1201)]  # spans chunks, types vary
        self.assertEqual(self.conn.executemany("INSERT INTO lz_t (id, name) VALUES ($1, $2)", rows).rowcount, 1200)
        self.assertEqual(self.conn.fetchval("SELECT count(name) FROM lz_t"), 800)

    def test_executemany_is_atomic(self):
        with self.assertRaises(pg.IntegrityError):
            self.conn.executemany("INSERT INTO lz_t (id) VALUES ($1)", [(1,), (2,), (1,), (3,)])
        self.assertEqual(self.conn.fetchval("SELECT count(*) FROM lz_t"), 0)
        self.still_works()

    def test_iterate(self):
        got = [r[0] for r in self.conn.iterate("SELECT generate_series(1, 2500)", batch_size=1000)]
        self.assertEqual(got, list(range(1, 2501)))

    def test_iterate_early_exit_and_lockout(self):
        it = self.conn.iterate("SELECT generate_series(1, 10000)", batch_size=100)
        self.assertEqual(next(it)[0], 1)
        with self.assertRaisesRegex(pg.InterfaceError, "iterate"):
            self.conn.fetch("SELECT 1")
        it.close()
        self.still_works()
        for row in self.conn.iterate("SELECT generate_series(1, 10000)", batch_size=7):
            if row[0] == 20:
                break
        self.still_works()

    def test_iterate_error_mid_stream(self):
        with self.assertRaises(pg.DataError):
            for _ in self.conn.iterate("SELECT 1 / (i - 1500) FROM generate_series(1, 2000) i", batch_size=100):
                pass
        self.still_works()

    def test_execute_script(self):
        c = self.conn
        results = c.execute_script("INSERT INTO lz_t (id) VALUES (1); INSERT INTO lz_t (id) VALUES (2); SELECT 1;")
        self.assertEqual([r.tag for r in results], ["INSERT 0 1", "INSERT 0 1", "SELECT 1"])
        with self.assertRaises(pg.IntegrityError):
            c.execute_script("INSERT INTO lz_t (id) VALUES (3); INSERT INTO lz_t (id) VALUES (1);")
        self.assertEqual(c.fetchval("SELECT count(*) FROM lz_t"), 2)  # the script was one transaction
        self.still_works()

    def test_copy_is_refused_cleanly(self):
        for method in ("execute", "execute_script", "iterate"):
            for sql in ("COPY lz_t FROM STDIN", "COPY (SELECT 1) TO STDOUT"):
                with self.subTest(method=method, sql=sql):
                    with self.assertRaisesRegex(pg.InterfaceError, "COPY"):
                        if method == "iterate":
                            list(self.conn.iterate(sql))
                        else:
                            getattr(self.conn, method)(sql)
                    self.still_works()

    def test_notices_and_notifications(self):
        seen = []
        self.conn.notice_handler = seen.append
        self.conn.execute("DO $$ BEGIN RAISE NOTICE 'hello %', 42; END $$")
        self.assertEqual((seen[0].message, seen[0].severity), ("hello 42", "NOTICE"))
        self.conn.execute("LISTEN lz_chan")
        self.conn.execute("SELECT pg_notify('lz_chan', 'payload ü')")
        note = self.conn.notifications.popleft()
        self.assertEqual((note.channel, note.payload, note.pid), ("lz_chan", "payload ü", self.conn.backend_pid))

    def test_cancel_from_another_thread(self):
        timer = threading.Timer(0.3, self.conn.cancel)
        timer.start()
        start = time_mod.monotonic()
        with self.assertRaises(pg.QueryCanceledError):
            self.conn.execute("SELECT pg_sleep(10)")
        self.assertLess(time_mod.monotonic() - start, 5)
        self.still_works()

    def test_register_decoder(self):
        c = self.conn
        c.execute("DROP TYPE IF EXISTS lz_mood")
        c.execute("CREATE TYPE lz_mood AS ENUM ('ok', 'bad')")
        oid = c.fetchval("SELECT 'lz_mood'::regtype::oid")
        self.assertEqual(c.fetchval("SELECT 'ok'::lz_mood"), "ok")
        c.register_decoder(oid, str.upper)
        self.assertEqual(c.fetchval("SELECT 'ok'::lz_mood"), "OK")
        c.execute("DROP TYPE lz_mood")


@_support.requires_env("LAZARET_TEST_PG_DSN")
class ConnectionLifecycleTests(unittest.TestCase):
    def test_socket_timeout_closes_connection(self):
        c = pg.connect(DSN, timeout=0.3)
        with self.assertRaisesRegex(pg.OperationalError, "timed out"):
            c.execute("SELECT pg_sleep(3)")
        self.assertTrue(c.closed)
        with self.assertRaisesRegex(pg.InterfaceError, "closed"):
            c.execute("SELECT 1")

    def test_context_manager_and_repr(self):
        with pg.connect(DSN) as c:
            self.assertIn("open", repr(c))
            self.assertGreaterEqual(c.server_version, (12,))
        self.assertTrue(c.closed)
        c.close()  # idempotent

    def test_unknown_database_error_is_reported(self):
        with self.assertRaises(pg.DatabaseError) as info:
            pg.connect(DSN, dbname="lazaret_no_such_db")
        self.assertEqual(info.exception.sqlstate, "3D000")


if __name__ == "__main__":
    unittest.main()
