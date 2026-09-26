"""`discover --resume`: a scheduled run sees every release since the last one.

A daily `discover --since 25h --scan --ci` covered minutes: PyPI's RSS feeds
hold the latest 100 updates and npm's walk reads the newest few hundred
feed rows. With --resume each registry continues its change feed from a
cursor stored in the state database: PyPI's changelog serial (one XML-RPC
changelog_since_serial call per run), npm's replication sequence number
(the feed paged forward, at most NPM_RESUME_PAGES pages, then one registry
lookup per package). The first run checks the --since window as before and
records where each feed is. A run that stops early (PyPI's 50,000-row
answer, npm's page budget, --limit) says so, fails --ci, and leaves the
cursor where it stopped, so the next run continues there. The cursor is
stored only after listing, tracking and scanning.

Network is mocked throughout: PyPI's RSS feeds and XML-RPC endpoint, npm's
replication feed and registry documents are fakes with harmless names.
"""

import contextlib
import datetime
import io
import os
import sqlite3
import tempfile
import unittest
import urllib.parse
import xmlrpc.client
from unittest import mock

from lazaret.registry import repo

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 26, 17, 47, 30, tzinfo=UTC)


def later(minutes):
    return NOW + datetime.timedelta(minutes=minutes)


def rss(items):
    body = "".join(f"<item><title>{t}</title><pubDate>{w.strftime('%a, %d %b %Y %H:%M:%S GMT')}"
                   f"</pubDate></item>" for t, w in items)
    return f"<rss><channel>{body}</channel></rss>".encode()


def answer(value):
    return xmlrpc.client.dumps((value,), methodresponse=True, allow_none=True).encode()


def release(serial, name, version, minutes, action="new release"):
    """A changelog row: (name, version, timestamp, action, serial)."""
    return [name, version, int(later(minutes).timestamp()), action, serial]


class FakePypi:
    """_fetch stand-in for pypi.org: the RSS feeds and the XML-RPC endpoint.
    changelog_since_serial answers the rows after the serial, at most
    PYPI_CHANGELOG_MAX of them, like PyPI."""

    def __init__(self, changelog=(), last_serial=1000, updates=None, packages=None):
        self.changelog, self.last_serial = list(changelog), last_serial
        self.feeds = {"updates.xml": updates if updates is not None else
                      [("recent-rel 1.0", NOW - datetime.timedelta(minutes=2))],
                      "packages.xml": packages if packages is not None else []}
        self.calls, self.fail = [], None

    def __call__(self, url, **kw):
        if url == repo.PYPI_XMLRPC_URL:
            params, method = xmlrpc.client.loads(kw["data"])
            self.calls.append((method, params))
            if self.fail is not None:
                raise self.fail
            if method == "changelog_last_serial":
                return answer(self.last_serial)
            return answer([r for r in self.changelog if r[4] > params[0]][:repo.PYPI_CHANGELOG_MAX])
        name = url.rsplit("/", 1)[1]
        self.calls.append(("rss", name))
        return rss(self.feeds[name])


class FakeNpm:
    """http_json stand-in for npm: the replication feed, read newest first
    (descending=true, the window) or forward (since=), and the registry's
    abbreviated documents (a name without a modified time is a 404)."""

    def __init__(self, rows=(), modified=None):
        self.rows, self.modified = list(rows), dict(modified or {})
        self.feed_urls, self.lookups, self.fail = [], [], {}

    def add(self, first, last, minutes):
        for seq in range(first, last + 1):
            self.rows.append((seq, f"p{seq}"))
            self.modified[f"p{seq}"] = later(minutes)

    def __call__(self, url, accept=None):
        if url.startswith(repo.NPM_CHANGES_URL):
            self.feed_urls.append(url)
            failure = self.fail.get(len(self.feed_urls))
            if failure is not None:
                raise failure
            query = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
            limit = int(query["limit"])
            if query.get("descending") == "true":
                picked = sorted(self.rows, reverse=True)[:limit]
            else:
                picked = [r for r in sorted(self.rows) if r[0] > int(query["since"])][:limit]
            return {"results": [{"seq": s, "id": n, "changes": [{"rev": "1-a"}]} for s, n in picked]}
        name = urllib.parse.unquote(url.rsplit("/", 1)[1])
        self.lookups.append(name)
        when = self.modified.get(name)
        if when is None:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return {"name": name, "dist-tags": {"latest": "1.0.0"}, "versions": {},
                "modified": when.isoformat().replace("+00:00", "Z")}


class ResumeCase(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.db = os.path.join(d.name, "state.db")
        self.pypi, self.npm = FakePypi(), FakeNpm()

    def run_cli(self, *argv, at=NOW, patches=()):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(repo, "_now", return_value=at))
            stack.enter_context(mock.patch.object(repo, "_fetch", side_effect=self.pypi))
            stack.enter_context(mock.patch.object(repo, "http_json", side_effect=self.npm))
            for p in patches:
                stack.enter_context(p)
            stack.enter_context(mock.patch("sys.argv", ["lazaret-registry", "discover", *argv,
                                                        "--db", self.db]))
            out = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            err = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def cursor(self, eco):
        with repo.Store(self.db) as store:
            return store.discovery_cursor(eco)

    def seed(self, eco, seq, when=NOW):
        with repo.Store(self.db) as store:
            store.save_discovery_cursor(eco, seq, when)

    @staticmethod
    def listed(out):
        return [line.split()[-1] for line in out.splitlines() if line.startswith("  2026-")]


class PypiResumeTests(ResumeCase):
    def test_first_run_then_every_release_since(self):
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci")
        # the first run checks the --since window (7 days: the feeds reach minutes)
        self.assertEqual(code, 1)
        self.assertIn("pypi: first --resume run: the window since 2026-09-19 17:47 UTC; the next "
                      "run continues from changelog serial 1000", out)
        self.assertIn("pypi partly checked: covered 17:45–17:47 UTC only", err)
        self.assertEqual(self.listed(out), ["pypi:recent-rel@1.0"])
        self.assertEqual(self.pypi.calls[0], ("changelog_last_serial", ()))    # before the feeds
        self.assertEqual([c for c in self.pypi.calls if c[0] != "rss"], [("changelog_last_serial", ())])
        self.assertEqual(self.cursor("pypi")[:2], ("1000", "2026-09-26T17:47:30+00:00"))

        self.pypi.changelog = [
            release(1001, "alpha", "1.0.0", 5),
            release(1002, "alpha", "1.0.0", 5, "add py3 file alpha-1.0.0-py3-none-any.whl"),
            release(1003, "alpha", "1.0.1", 20),               # both releases are listed
            release(1004, "brand-new", None, 30, "create"),
            release(1005, "brand-new", "0.1", 30),
            release(1006, "only-created", None, 40, "create"),
            release(1007, "gone", None, 50, "remove project"),
        ]
        self.pypi.calls.clear()
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci", at=later(60))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.pypi.calls, [("changelog_since_serial", (1000,))])   # one call, no RSS
        self.assertIn("pypi: changelog serial 1000 → 1007, 17:47–18:37 UTC", out)
        self.assertIn("Discovered 4 package(s):", out)
        self.assertEqual(self.listed(out), ["pypi:only-created", "pypi:brand-new@0.1",
                                            "pypi:alpha@1.0.1", "pypi:alpha@1.0.0"])
        self.assertNotIn("warning", err)
        self.assertEqual(self.cursor("pypi")[:2], ("1007", "2026-09-26T18:37:30+00:00"))

        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci", at=later(90))
        self.assertEqual(code, 0, err)
        self.assertIn("pypi: no changes after changelog serial 1007", out)
        self.assertIn("No new packages in pypi.", out)
        self.assertEqual(self.cursor("pypi")[0], "1007")

    def test_a_full_changelog_answer_is_continued_next_run(self):
        self.seed("pypi", 1000)
        self.pypi.changelog = [release(1000 + i, f"proj-{i}", "1.0", i) for i in range(1, 8)]
        seen = []
        with mock.patch.object(repo, "PYPI_CHANGELOG_MAX", 3):
            for expect_code, expect_cursor in ((1, "1003"), (1, "1006"), (0, "1007")):
                code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci", at=later(60))
                self.assertEqual(code, expect_code, err)
                self.assertEqual(self.cursor("pypi")[0], expect_cursor)
                seen += self.listed(out)
        self.assertEqual(sorted(seen), sorted(f"pypi:proj-{i}@1.0" for i in range(1, 8)))
        self.seed("pypi", 1000)
        with mock.patch.object(repo, "PYPI_CHANGELOG_MAX", 3):
            code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", at=later(60))
        self.assertEqual(code, 0)                         # without --ci: a warning
        self.assertIn("Discovered 3 package(s), but not everything was checked", out)
        self.assertIn("warning: discovery incomplete: pypi partly checked: covered changes up to "
                      "2026-09-26 17:50 UTC only: PyPI's changelog answers with at most 3 changes "
                      "per call; the next --resume run continues from serial 1003.", err)

    def test_the_limit_leaves_the_rest_for_the_next_run(self):
        self.seed("pypi", 1000)
        self.pypi.changelog = [release(1000 + i, f"proj-{i}", "1.0", i) for i in range(1, 6)]
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--limit", "2", "--ci",
                                      at=later(60))
        self.assertEqual(code, 1)
        self.assertEqual(self.listed(out), ["pypi:proj-2@1.0", "pypi:proj-1@1.0"])   # the oldest
        self.assertIn("pypi partly checked: stopped at --limit 2; 3 more release(s) are left for "
                      "the next --resume run", err)
        self.assertEqual(self.cursor("pypi")[:2], ("1002", "2026-09-26T17:49:30+00:00"))
        code, out, _ = self.run_cli("--resume", "--ecosystem", "pypi", "--limit", "2", at=later(60))
        self.assertEqual(self.listed(out), ["pypi:proj-4@1.0", "pypi:proj-3@1.0"])
        code, out, _ = self.run_cli("--resume", "--ecosystem", "pypi", "--limit", "2", "--ci",
                                    at=later(60))
        self.assertEqual((code, self.listed(out)), (0, ["pypi:proj-5@1.0"]))

    def test_a_changelog_that_cannot_be_read(self):
        self.seed("pypi", 1000)
        self.pypi.fail = repo.FetchError("URL error fetching https://pypi.org/pypi: timed out")
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci", at=later(60))
        self.assertEqual(code, 1)
        self.assertIn("pypi: not checked (see the warning at the end)", out)
        self.assertIn("Nothing was checked.", out)
        self.assertIn("warning: could not read PyPI's changelog (URL error fetching "
                      "https://pypi.org/pypi: timed out); PyPI was not checked.", err)
        self.assertEqual(self.cursor("pypi")[:2], ("1000", "2026-09-26T17:47:30+00:00"))

    def test_an_answer_with_nothing_after_the_position(self):
        # older rows only: not "no changes" (a silent gap), but not checked
        self.seed("pypi", 1000)
        stale = answer([release(990, "old", "1.0", -60)])
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci", at=later(60),
                                      patches=[mock.patch.object(repo, "_fetch", return_value=stale)])
        self.assertEqual(code, 1)
        self.assertIn("could not read PyPI's changelog (PyPI's changelog answer had no readable row "
                      "after serial 1000); PyPI was not checked.", err)
        self.assertNotIn("No new packages", out)
        self.assertEqual(self.cursor("pypi")[0], "1000")
        # the row at the position itself, alone: nothing new
        echo = answer([release(1000, "same", "1.0", 0)])
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci", at=later(60),
                                      patches=[mock.patch.object(repo, "_fetch", return_value=echo)])
        self.assertEqual(code, 0, err)
        self.assertIn("No new packages in pypi.", out)

    def test_a_fault_is_printed_safely(self):
        self.seed("pypi", 1000)
        faulty = xmlrpc.client.dumps(xmlrpc.client.Fault(-32500, "slow down \u202e\u2066gnp.exe"),
                                     methodresponse=True).encode()
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci",
                                      patches=[mock.patch.object(repo, "_fetch", return_value=faulty)])
        self.assertEqual(code, 1)
        self.assertIn("fault -32500: slow down", err)
        self.assertNotIn("\u202e", err + out)
        self.assertNotIn("\u2066", err + out)

    def test_the_head_position_that_cannot_be_read(self):
        self.pypi.fail = repo.FetchError("HTTP 429 fetching https://pypi.org/pypi")
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--since", "1h")
        self.assertEqual(code, 0)
        self.assertIn("warning: could not read PyPI's changelog position (HTTP 429 fetching "
                      "https://pypi.org/pypi); the next --resume run checks a --since window "
                      "again.", err)
        self.assertEqual(self.listed(out), ["pypi:recent-rel@1.0"])   # the window still ran
        self.assertIsNone(self.cursor("pypi"))


class NpmResumeTests(ResumeCase):
    def test_first_run_then_forward_pages(self):
        self.npm.add(491, 500, -30)
        code, out, err = self.run_cli("--resume", "--ecosystem", "npm", "--ci")
        self.assertEqual(code, 0, err)                     # a 10-row feed is read whole
        self.assertIn("npm: first --resume run: the window since 2026-09-19 17:47 UTC; the next "
                      "run continues from change 500", out)
        self.assertEqual(len(self.listed(out)), 10)
        self.assertEqual(self.cursor("npm")[:2], ("500", "2026-09-26T17:47:30+00:00"))

        self.npm.add(501, 525, 10)
        self.npm.feed_urls.clear()
        with mock.patch.object(repo, "NPM_CHANGES_MAX", 10):
            code, out, err = self.run_cli("--resume", "--ecosystem", "npm", "--ci", at=later(60))
        self.assertEqual(code, 0, err)
        self.assertEqual([urllib.parse.urlsplit(u).query for u in self.npm.feed_urls],
                         ["since=500&limit=10", "since=510&limit=10", "since=520&limit=10"])
        self.assertIn("npm: replication feed 500 → 525, 25 changes in 3 page(s)", out)
        self.assertEqual(sorted(self.listed(out)), sorted(f"npm:p{s}@1.0.0" for s in range(501, 526)))
        self.assertEqual(self.cursor("npm")[:2], ("525", "2026-09-26T18:47:30+00:00"))

    def test_the_page_budget_is_continued_next_run(self):
        self.seed("npm", 500)
        self.npm.add(501, 545, 10)
        seen = []
        with mock.patch.object(repo, "NPM_CHANGES_MAX", 10), \
                mock.patch.object(repo, "NPM_RESUME_PAGES", 2):
            for expect_code, expect_cursor in ((1, ("520", None)), (1, ("540", None)),
                                               (0, ("545", "2026-09-26T18:47:30+00:00"))):
                code, out, err = self.run_cli("--resume", "--ecosystem", "npm", "--ci", at=later(60))
                self.assertEqual(code, expect_code, err)
                self.assertEqual(self.cursor("npm")[:2], expect_cursor)
                seen += self.listed(out)
                if expect_code:
                    self.assertIn(f"npm partly checked: read 2 pages (20 changes) of its replication "
                                  f"feed, the most one run reads; the next --resume run continues "
                                  f"from change {expect_cursor[0]}", err)
        self.assertEqual(sorted(seen), sorted(f"npm:p{s}@1.0.0" for s in range(501, 546)))

    def test_the_limit_and_failed_lookups(self):
        self.seed("npm", 500)
        self.npm.add(501, 505, 10)
        del self.npm.modified["p502"]                       # its lookup fails
        code, out, err = self.run_cli("--resume", "--ecosystem", "npm", "--limit", "3", "--ci",
                                      at=later(60))
        self.assertEqual(code, 1)
        self.assertEqual(sorted(self.listed(out)), ["npm:p501@1.0.0", "npm:p502", "npm:p503@1.0.0"])
        self.assertIn("npm partly checked: stopped at --limit 3; 2 more changed package(s) are left "
                      "for the next --resume run", err)
        self.assertIn("could not read the registry entry of 1 npm package(s)", err)
        self.assertEqual(self.cursor("npm")[:2], ("503", None))
        code, out, err = self.run_cli("--resume", "--ecosystem", "npm", "--ci", at=later(60))
        self.assertEqual((code, sorted(self.listed(out))), (0, ["npm:p504@1.0.0", "npm:p505@1.0.0"]))

    def test_a_feed_that_fails(self):
        self.seed("npm", 500)
        self.npm.add(501, 530, 10)
        rejected = repo.FetchError("HTTP 400 fetching …")
        rejected.status = 400
        self.npm.fail = {1: rejected}
        code, out, err = self.run_cli("--resume", "--ecosystem", "npm", "--ci", at=later(60))
        self.assertEqual(code, 1)
        self.assertIn("npm: not checked (see the warning at the end)", out)
        self.assertIn("discovery incomplete: npm not checked: npm rejected the changes-feed request "
                      "(HTTP 400; its replication API may have changed)", err)
        self.assertEqual(self.cursor("npm")[0], "500")
        # a later page failing: what was read stands, and the next run continues after it
        self.npm.feed_urls.clear()
        self.npm.fail = {2: repo.FetchError("URL error fetching …: timed out")}
        with mock.patch.object(repo, "NPM_CHANGES_MAX", 10):
            code, out, err = self.run_cli("--resume", "--ecosystem", "npm", "--ci", at=later(60))
        self.assertEqual(code, 1)
        self.assertEqual(len(self.listed(out)), 10)
        self.assertIn("npm partly checked: its replication feed failed after 1 page(s) (could not "
                      "reach replicate.npmjs.com (URL error fetching …: timed out)); the next "
                      "--resume run continues from change 510", err)
        self.assertEqual(self.cursor("npm")[0], "510")


class CliResumeTests(ResumeCase):
    def test_both_registries_and_a_limit_per_registry(self):
        self.seed("pypi", 1000)
        self.seed("npm", 500)
        self.pypi.changelog = [release(1000 + i, f"proj-{i}", "1.0", i) for i in range(1, 4)]
        self.npm.add(501, 503, 30)
        code, out, err = self.run_cli("--resume", "--limit", "2", at=later(60))
        self.assertEqual(code, 0)
        self.assertEqual(sorted(self.listed(out)), ["npm:p501@1.0.0", "npm:p502@1.0.0",
                                                   "pypi:proj-1@1.0", "pypi:proj-2@1.0"])
        self.assertEqual((self.cursor("pypi")[0], self.cursor("npm")[0]), ("1002", "502"))

    def test_scan_gets_every_release_and_the_cursor_waits_for_it(self):
        self.seed("pypi", 1000)
        self.pypi.changelog = [release(1001, "alpha", "1.0.0", 5), release(1002, "alpha", "1.0.1", 6),
                               release(1003, "fresh", None, 7, "create")]
        scanned = []

        def fake_scan(store, specs, full, rescan, errors=None):
            scanned.extend(specs)
            return False
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--scan", "--ci",
                                      at=later(60),
                                      patches=[mock.patch.object(repo, "cmd_scan", side_effect=fake_scan)])
        self.assertEqual(code, 0, err)
        self.assertEqual(scanned, ["pypi:fresh", "pypi:alpha@1.0.1", "pypi:alpha@1.0.0"])
        self.assertEqual(self.cursor("pypi")[0], "1003")
        # a run that dies while scanning leaves the cursor: the next run sees them again
        self.pypi.changelog.append(release(1004, "beta", "2.0", 8))
        with self.assertRaises(KeyboardInterrupt):
            self.run_cli("--resume", "--ecosystem", "pypi", "--scan", at=later(60),
                         patches=[mock.patch.object(repo, "cmd_scan", side_effect=KeyboardInterrupt)])
        self.assertEqual(self.cursor("pypi")[0], "1003")

    def test_a_cursor_that_cannot_be_stored(self):
        self.seed("pypi", 1000)
        self.pypi.changelog = [release(1001, "alpha", "1.0.0", 5)]
        broken = mock.patch.object(repo.Store, "save_discovery_cursor",
                                   side_effect=sqlite3.OperationalError("disk I/O error"))
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", at=later(60), patches=[broken])
        self.assertEqual(code, 0)
        self.assertIn("warning: could not store the pypi discovery cursor (OperationalError: disk "
                      "I/O error); the next --resume run repeats this part.", err)
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci", at=later(60),
                                      patches=[broken])
        self.assertEqual(code, 1)
        self.assertEqual(self.cursor("pypi")[0], "1000")

    def test_a_stored_cursor_that_is_not_a_number(self):
        with repo.Store(self.db) as store:
            store.save_discovery_cursor("pypi", "not-a-serial")
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--since", "1h")
        self.assertIn("warning: the stored pypi discovery cursor is not a sequence number; this run "
                      "starts over from the --since window.", err)
        self.assertIn("pypi: first --resume run", out)
        self.assertEqual(self.cursor("pypi")[0], "1000")

    def test_a_cursor_that_cannot_be_read(self):
        broken = mock.patch.object(repo.Store, "discovery_cursor",
                                   side_effect=sqlite3.OperationalError("database is locked"))
        code, out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--ci", patches=[broken])
        self.assertEqual(code, 1)
        self.assertIn("warning: pypi: could not read its discovery cursor (OperationalError: "
                      "database is locked); pypi was not checked.", err)
        self.assertEqual(self.pypi.calls, [])

    def test_without_resume_the_cursor_is_left_alone(self):
        self.seed("pypi", 1000)
        before = self.cursor("pypi")
        code, out, err = self.run_cli("--since", "1h", "--ecosystem", "pypi", at=later(60))
        self.assertEqual(self.cursor("pypi"), before)
        self.assertEqual([c for c in self.pypi.calls if c[0] != "rss"], [])   # no XML-RPC
        self.assertNotIn("Resuming", out)

    def test_the_window_mode_points_at_resume(self):
        code, _out, err = self.run_cli("--since", "24h", "--ecosystem", "pypi")
        self.assertIn("pypi partly checked: covered 17:45–17:47 UTC only", err)
        self.assertIn("hint: `discover --resume` continues where the previous --resume run stopped",
                      err)
        self.seed("pypi", 1000)
        _code, _out, err = self.run_cli("--resume", "--ecosystem", "pypi", "--limit", "1",
                                        at=later(60))
        self.assertNotIn("hint:", err)

    def test_help_documents_resume(self):
        with mock.patch("sys.argv", ["lazaret-registry", "--help"]), \
                contextlib.redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit):
            repo.main()
        text = " ".join(out.getvalue().split())
        self.assertIn("--resume", text)
        self.assertIn("with --resume, per registry and no limit by default", text)


if __name__ == "__main__":
    unittest.main()
