"""Review fixes that need a real server. Gated like test_integration.py:
set LAZARET_TEST_PG_DSN to a DSN for a user with CREATEDB. Skipped when unset.
"""

import os
import unittest
from datetime import timedelta

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


if __name__ == "__main__":
    unittest.main()
