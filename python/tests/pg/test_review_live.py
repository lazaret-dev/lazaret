"""Review fixes that need a real server. Gated like test_integration.py:
set LAZARET_TEST_PG_DSN to a DSN for a user with CREATEDB. Skipped when unset.
"""

import os
import unittest
import uuid
from datetime import date, timedelta
from decimal import Decimal

from lazaret import pg
from tests import _support

DSN = os.environ.get("LAZARET_TEST_PG_DSN")


class LiveCase(unittest.TestCase):
    tables = ()

    def setUp(self):
        self.conn = pg.connect(DSN, timeout=20)
        self.addCleanup(self._cleanup)

    def _cleanup(self):
        if self.conn.closed:
            self.conn = pg.connect(DSN, timeout=20)
        for table in self.tables:
            self.conn.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
        self.conn.close()

    def still_works(self, conn=None):
        self.assertEqual((conn or self.conn).fetchval("SELECT 1"), 1)


@_support.requires_env("LAZARET_TEST_PG_DSN")
class IntervalStyleTests(LiveCase):
    def test_timedelta_means_the_same_under_every_interval_style(self):
        values = [timedelta(days=-1, seconds=5), timedelta(days=3, hours=4, microseconds=5),
                  timedelta(microseconds=-1), timedelta(0), timedelta(days=-2, seconds=86399)]
        for style in ("postgres", "postgres_verbose", "sql_standard", "iso_8601"):
            self.conn.execute(f"SET IntervalStyle = '{style}'")
            for value in values:
                with self.subTest(style=style, value=value):
                    micros = self.conn.fetchval(
                        "SELECT (extract(epoch FROM $1::interval) * 1000000)::bigint", value)
                    self.assertEqual(micros, value // timedelta(microseconds=1))
        self.conn.execute("SET IntervalStyle = 'iso_8601'")
        self.assertEqual(self.conn.fetchval("SELECT $1::interval", values[0]), values[0])


@_support.requires_env("LAZARET_TEST_PG_DSN")
class DecoderFailureTests(LiveCase):
    def test_deep_jsonb_comes_back_as_text(self):
        deep = "[" * 3000 + "]" * 3000   # PostgreSQL accepts it; json.loads hits the recursion limit
        self.assertEqual(self.conn.fetchval("SELECT $1::jsonb", deep), deep)
        self.assertEqual([r[0] for r in self.conn.iterate("SELECT $1::jsonb FROM generate_series(1, 3)", deep)],
                         [deep] * 3)
        self.still_works()

    def test_registered_decoder_that_raises(self):
        self.conn.register_decoder(25, lambda s: {"a": 1}[s])   # KeyError for anything but "a"
        self.assertEqual(self.conn.fetch("SELECT 'zzz'::text UNION ALL SELECT 'a'"), [("zzz",), (1,)])
        self.still_works()

    def test_non_utf8_client_encoding(self):
        with self.assertLogs("lazaret.pg", "WARNING"):
            self.conn.execute("SET client_encoding = 'LATIN1'")
        self.assertEqual(self.conn.fetchval("SELECT 'caf' || chr(233)"), "caf\ufffd")
        self.still_works()


@_support.requires_env("LAZARET_TEST_PG_DSN")
class ParameterTypeTests(LiveCase):
    def test_int_parameters_fit_int4_functions(self):
        c = self.conn
        self.assertEqual(c.fetchval("SELECT repeat('x', $1)", 3), "xxx")
        self.assertEqual(c.fetchval("SELECT left($1, $2)", "abcdef", 2), "ab")
        self.assertEqual(c.fetchval("SELECT make_date($1, $2, $3)", 2026, 9, 25), date(2026, 9, 25))
        self.assertEqual(c.fetchval("SELECT $1::date + $2", date(2026, 9, 25), 7), date(2026, 10, 2))
        self.assertEqual(c.fetchval("SELECT generate_series($1, $2) LIMIT 1", 2**40, 2**40 + 1), 2**40)

    def test_int_sizes_round_trip(self):
        for value, expected in ((5, 5), (2**31, 2**31), (-(2**63), -(2**63)), (2**63, Decimal(2**63))):
            with self.subTest(value=value):
                got = self.conn.fetchval("SELECT $1", value)
                self.assertEqual((got, type(got)), (expected, type(expected)))
        self.assertEqual(self.conn.fetchval("SELECT $1 * 1000", 2**31), 2**31 * 1000)
        self.assertEqual(self.conn.fetchval("SELECT $1::bigint * $2", 100_000, 100_000), 10**10)

    def test_string_list_takes_its_type_from_the_query(self):
        u = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
        c = self.conn
        self.assertIs(c.fetchval("SELECT $1::uuid = ANY($2)", u, [u]), True)
        self.assertIs(c.fetchval(f"SELECT '{u}'::uuid = ANY($1)", [u]), True)
        self.assertIs(c.fetchval("SELECT 5 = ANY($1)", ["5"]), True)
        self.assertIs(c.fetchval("SELECT 'b'::text = ANY($1)", ["a", "b"]), True)
        self.assertEqual(c.fetchval("SELECT array_length($1::text[], 1)", ["a", "b"]), 2)
        self.assertEqual([r[0] for r in c.fetch("SELECT unnest($1::text[])", ["x", "y"])], ["x", "y"])
        self.assertIs(c.fetchval("SELECT $1 = ANY($2)", uuid.UUID(u), [uuid.UUID(u)]), True)


if __name__ == "__main__":
    unittest.main()
