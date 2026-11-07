"""test_ghdiscover_concurrency's OrderTests on a live Postgres (GH-SCAN-GQL-SPEED): LAZARET_TEST_PG_DSN, a user with
CREATEDB; a scratch database each, dropped after. Skipped without it. One at a time and calls at once, answered in
other orders, store the same, and the connection is used from the run's thread alone."""

import os
import threading
import unittest

from tests import _support
from lazaret import pg
from lazaret.registry import repo
from tests.registry import test_ghdiscover_concurrency as concurrency
from tests.registry.test_ghdiscover import NOW


@_support.requires_env("LAZARET_TEST_PG_DSN")
class LivePostgresTests(concurrency.OrderTests):
    """OrderTests' runs on a live Postgres (LAZARET_TEST_PG_DSN: a user with CREATEDB; a scratch database each, dropped
    after): one at a time and at once alike, the connection used from the run's thread alone."""

    PICKS = (("last", concurrency.last), ("random 1", concurrency.at_random(1)))

    def setUp(self):
        dsn = os.environ["LAZARET_TEST_PG_DSN"]
        self.name = f"lz_gqlspeed_{os.getpid()}_{len(getattr(self, 'made', []))}"
        self.made = getattr(self, "made", []) + [self.name]
        admin = pg.connect(dsn, timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{self.name}"')
            admin.execute(f'CREATE DATABASE "{self.name}"')
        finally:
            admin.close()
        self.store = repo.Store(dsn.rsplit("/", 1)[0] + "/" + self.name)
        self.addCleanup(self.drop, dsn, self.name, self.store)
        conn, threads = self.store.conn, set()
        for method in ("execute", "fetch", "fetchrow", "fetchval"):
            if hasattr(conn, method):
                real = getattr(conn, method)

                def watched(*a, _real=real, **kw):
                    threads.add(threading.get_ident())
                    return _real(*a, **kw)
                setattr(conn, method, watched)
        self.addCleanup(lambda: self.assertEqual(threads, {threading.get_ident()}))
        self.store.save_discovery_cursor("github", 1000, NOW)
        self.store.save_discovery_cursor("github-scan-all", 1000)

    @staticmethod
    def drop(dsn, name, store):
        store.close()
        admin = pg.connect(dsn, timeout=10)
        try:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}"')
        finally:
            admin.close()

    def test_the_due_asks_start_in_their_order_whatever_order_they_end_in(self):
        pass                                                                   # (OrderTests' SQLite one suffices)


if __name__ == "__main__":
    unittest.main()
