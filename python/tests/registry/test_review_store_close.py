"""Every Store that is opened is closed (STRUCTURE.md, "Cross-platform rules",
rule 3).

The MCP tools and the registry CLI opened a Store per call and never closed
it. On Linux and macOS nothing noticed; on Windows the open SQLite file could
not be deleted, so every test that used a temporary database failed its
cleanup with WinError 32, and a long-running MCP server held one handle per
tool call. Deleting an open file works here, so these tests count the Stores
that were opened and check each one was closed, on every OS.
"""

import contextlib
import datetime
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

from lazaret.mcp import server
from lazaret.registry import repo
from tests.registry._review_support import tarball

GOOD_TGZ = tarball({"package.json": '{"name": "g"}', "index.js": "module.exports = 1;\n"})
RESOLVED = ("1.0.0", "https://registry.npmjs.org/g/-/g-1.0.0.tgz", "tgz", "npm", {})


class Tracked(repo.Store):
    opened = []

    def __init__(self, *args, **kwargs):
        Tracked.opened.append(self)
        super().__init__(*args, **kwargs)


class Base(unittest.TestCase):
    def setUp(self):
        Tracked.opened = []
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)        # would fail on Windows with a Store left open
        self.db = os.path.join(d.name, "r.db")
        self.start(mock.patch.object(repo, "Store", Tracked),
                   mock.patch.object(server, "REGISTRY_DB", self.db))

    def start(self, *patches):
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def assert_all_closed(self, at_least=1):
        self.assertGreaterEqual(len(Tracked.opened), at_least, "no Store was opened")
        still_open = [s for s in Tracked.opened if not getattr(s, "_closed", False)]
        self.assertEqual(still_open, [], f"{len(still_open)} of {len(Tracked.opened)} Stores left open")


class McpToolsCloseTheirStore(Base):
    def setUp(self):
        super().setUp()
        self.start(mock.patch.object(repo, "resolve_npm", return_value=RESOLVED),
                   mock.patch.object(repo, "http_bytes", return_value=GOOD_TGZ),
                   mock.patch.object(repo, "verify_digest", return_value=None))

    def test_scan_package(self):
        self.assertEqual(server.tool_scan_package({"spec": "npm:g"})["verdict"], "OK")
        self.assert_all_closed()

    def test_scan_package_that_raises(self):
        self.start(mock.patch.object(repo, "scan_package", side_effect=repo.FetchError("HTTP 404")))
        with self.assertRaises(repo.FetchError):
            server.tool_scan_package({"spec": "npm:g"})
        self.assert_all_closed()

    def test_registry_status(self):
        self.assertEqual(server.tool_registry_status({})["tracked"], 0)
        self.assert_all_closed()

    def test_discover_and_scan(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        self.start(mock.patch.object(repo, "discover_pypi", return_value=[]),
                   mock.patch.object(repo, "discover_npm", return_value=[("npm", "g", "1.0.0", now)]))
        out = server.tool_discover_packages({"since": "1d", "scan": True})
        self.assertEqual([r["verdict"] for r in out["scanned"]], ["OK"])
        self.assert_all_closed()


class RegistryCliClosesItsStore(Base):
    def main(self, *argv):
        with mock.patch.object(sys, "argv", ["lazaret-registry", "--db", self.db, *argv]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try:
                repo.main()
            except SystemExit as exc:
                return exc.code
        return 0

    def test_a_command_that_succeeds(self):
        self.assertEqual(self.main("add", "npm:g"), 0)
        self.assert_all_closed()

    def test_a_command_that_exits_early(self):
        self.assertTrue(self.main("scan"))               # "scan needs at least one package spec"
        self.assert_all_closed()


class StoreItself(unittest.TestCase):
    def test_close_is_idempotent_and_a_context_manager(self):
        with tempfile.TemporaryDirectory() as d:
            with repo.Store(os.path.join(d, "r.db")) as st:
                st.add_package("npm", "g")
            self.assertTrue(st._closed)
            st.close()                                     # no error the second time

    def test_a_failed_schema_setup_closes_the_connection(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(repo.Store, "_init_schema", side_effect=RuntimeError("boom")), \
                mock.patch.object(repo, "Store", Tracked):
            Tracked.opened = []
            with self.assertRaises(RuntimeError):
                repo.Store(os.path.join(d, "r.db"))
            self.assertTrue(Tracked.opened[0]._closed)


if __name__ == "__main__":
    unittest.main()
