"""discover says how much of the window it covered.

`discover --since 24h --ecosystem pypi` printed "Discovered 122 package(s)
since <yesterday>", but PyPI's RSS feeds hold only the newest 100 updates
(updates.xml, about 20 minutes) and 40 new projects (packages.xml, about an
hour), and the npm walk reads at most 3 x --limit names of the replication
feed. A daily `discover --since 25h --scan --ci` covered minutes and passed.

Now a registry whose feed or walk doesn't reach back to the start of the
window is noted as partly checked, with the part that was covered ("covered
17:28–17:47 UTC only; its RSS feeds hold the latest 100 updates"); so is
what --limit leaves out. The heading no longer claims the whole window, and
--ci fails the run. The notes reach the MCP tool too (incompleteReason).

Network is mocked: RSS documents and npm feed rows are built in memory, with
harmless names.
"""

import contextlib
import datetime
import io
import os
import tempfile
import unittest
import urllib.parse
from unittest import mock

from lazaret.mcp import server as mcp_server
from lazaret.registry import repo

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 26, 17, 47, 30, tzinfo=UTC)
DAY = NOW - datetime.timedelta(hours=24)


def at(hh, mm, day=26):
    return datetime.datetime(2026, 9, day, hh, mm, tzinfo=UTC)


def minutes_ago(n):
    return NOW - datetime.timedelta(minutes=n)


def rss(items):
    """[(title, datetime)] -> RSS bytes."""
    body = "".join(f"<item><title>{t}</title><pubDate>{w.strftime('%a, %d %b %Y %H:%M:%S GMT')}"
                   f"</pubDate></item>" for t, w in items)
    return f"<rss><channel>{body}</channel></rss>".encode()


def spread(n, newest, oldest):
    """n times from newest to oldest, both ends exact."""
    last = max(n - 1, 1)
    return [oldest + (newest - oldest) * (last - i) // last for i in range(n)]


def updates(n, newest, oldest):
    """updates.xml: n releases "pkg-<i> 1.0" spread from newest to oldest."""
    return [(f"pkg-{i} 1.0", w) for i, w in enumerate(spread(n, newest, oldest))]


def projects(n, newest, oldest):
    """packages.xml: n new projects "new-<i> added to PyPI"."""
    return [(f"new-{i} added to PyPI", w) for i, w in enumerate(spread(n, newest, oldest))]


# PyPI as it looked when this was found: 100 updates in 19 minutes, 40 new
# projects in 54
SHORT = {"updates_xml": updates(100, at(17, 47), at(17, 28)),
         "packages": projects(40, at(17, 46), at(16, 52))}


def pypi_fetch(packages=None, updates_xml=None):
    """_fetch stand-in serving the two feeds (an exception value is raised)."""
    feeds = {"packages.xml": packages, "updates.xml": updates_xml}

    def fetch(url, **kw):
        doc = feeds[url.rsplit("/", 1)[1]]
        if isinstance(doc, Exception):
            raise doc
        return rss(doc or [])
    return fetch


def discover_pypi(cutoff=DAY, limit=0, **feeds):
    notes = {}
    with mock.patch.object(repo, "_now", return_value=NOW), \
            mock.patch.object(repo, "_fetch", side_effect=pypi_fetch(**feeds)), \
            contextlib.redirect_stderr(io.StringIO()):
        found = repo.discover_pypi(cutoff, limit, notes)
    return found, notes


class PypiReachTests(unittest.TestCase):
    def test_feeds_that_stop_short_of_the_window_are_noted(self):
        found, notes = discover_pypi(**SHORT)
        self.assertEqual(len(found), 140)
        self.assertEqual(notes, {"pypi": "partly checked: covered 17:28–17:47 UTC only; its RSS "
                                         "feeds hold the latest 100 updates (new projects: "
                                         "16:52–17:47 UTC)"})

    def test_feeds_that_reach_back_cover_the_window(self):
        _found, notes = discover_pypi(cutoff=minutes_ago(10), **SHORT)
        self.assertEqual(notes, {})

    def test_new_projects_can_cover_more_than_releases(self):
        _found, notes = discover_pypi(cutoff=at(17, 0), **SHORT)
        self.assertEqual(notes, {"pypi": "partly checked: covered 17:28–17:47 UTC only; its RSS feeds "
                                         "hold the latest 100 updates (new projects: the whole "
                                         "window)"})

    def test_a_span_across_midnight_has_dates(self):
        _found, notes = discover_pypi(cutoff=at(20, 0, day=24),
                                      updates_xml=updates(3, at(0, 10), at(23, 50, day=25)),
                                      packages=projects(2, at(0, 5), at(23, 55, day=25)))
        self.assertEqual(notes, {"pypi": "partly checked: covered 2026-09-25 23:50 – 2026-09-26 17:47 "
                                         "UTC only; its RSS feeds hold the latest 3 updates"})

    def test_a_failed_feed_and_a_short_one(self):
        _found, notes = discover_pypi(updates_xml=repo.FetchError("URL error fetching …"),
                                      packages=SHORT["packages"])
        self.assertEqual(notes, {"pypi": "partly checked: the updates.xml feed failed; new projects "
                                         "covered 16:52–17:47 UTC only; packages.xml holds the "
                                         "latest 40"})
        _found, notes = discover_pypi(updates_xml=SHORT["updates_xml"],
                                      packages=repo.FetchError("URL error fetching …"))
        self.assertEqual(notes, {"pypi": "partly checked: the packages.xml feed failed; covered "
                                         "17:28–17:47 UTC only; its RSS feeds hold the latest 100 "
                                         "updates"})

    def test_an_empty_feed_covers_nothing(self):
        _found, notes = discover_pypi(updates_xml=[], packages=projects(2, at(17, 46), at(17, 40)))
        self.assertEqual(notes, {"pypi": "partly checked: the updates.xml feed was empty "
                                         "(new projects: 17:40–17:47 UTC)"})

    def test_what_the_limit_leaves_out_is_noted(self):
        # the MCP tool passes its limit to discover_pypi: 48 of these 50
        # releases are in the window, and the feed reaches back past it
        found, notes = discover_pypi(cutoff=at(17, 0), limit=30, packages=[],
                                     updates_xml=[(f"p{i} 1.0", minutes_ago(i)) for i in range(50)])
        self.assertEqual(len(found), 30)
        self.assertEqual(notes, {"pypi": "partly checked: 18 more not listed (limit 30)"})


class FakeNpm:
    """http_json stand-in: the replication feed (names, newest first; the
    rows asked for, or fewer when the feed is shorter) and abbreviated
    documents (a name without one is a 404)."""

    def __init__(self, names, docs):
        self.names, self.docs = names, docs

    def __call__(self, url, accept=None):
        if url.startswith(repo.NPM_CHANGES_URL):
            want = int(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["limit"][0])
            return {"results": [{"seq": 1000 - i, "id": n, "changes": [{"rev": "1-a"}]}
                                for i, n in enumerate(self.names[:want])]}
        name = urllib.parse.unquote(url.rsplit("/", 1)[1])
        modified = self.docs.get(name)
        if modified is None:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return {"name": name, "dist-tags": {"latest": "1.0.0"}, "versions": {},
                "modified": modified.isoformat().replace("+00:00", "Z")}


def discover_npm(names, docs, cutoff=DAY, limit=50):
    notes = {}
    with mock.patch.object(repo, "_now", return_value=NOW), \
            mock.patch.object(repo, "http_json", side_effect=FakeNpm(names, docs)), \
            contextlib.redirect_stderr(io.StringIO()):
        found = repo.discover_npm(cutoff, limit, notes)
    return found, notes


class NpmReachTests(unittest.TestCase):
    def test_a_walk_stopped_by_the_limit(self):
        names = [f"p{i}" for i in range(20)]
        found, notes = discover_npm(names, {n: minutes_ago(i) for i, n in enumerate(names)}, limit=5)
        self.assertEqual([n for _, n, _, _ in found], ["p0", "p1", "p2", "p3", "p4"])
        self.assertEqual(notes, {"npm": "partly checked: covered 17:43–17:47 UTC only: stopped at "
                                        "the limit of 5 packages"})

    def test_a_walk_that_runs_out_of_feed_rows(self):
        # --limit 0 reads 300 rows; all 300 changed inside the 24-hour window
        names = [f"p{i}" for i in range(400)]
        found, notes = discover_npm(names, {n: minutes_ago(i // 10) for i, n in enumerate(names)},
                                    limit=0)
        self.assertEqual(len(found), 300)
        self.assertEqual(notes, {"npm": "partly checked: covered 17:18–17:47 UTC only; read the newest "
                                        "300 changes of its replication feed"})

    def test_a_walk_that_passes_the_window_is_complete(self):
        names = [f"p{i}" for i in range(30)]
        docs = {n: (minutes_ago(i) if i < 3 else NOW - datetime.timedelta(days=3))
                for i, n in enumerate(names)}
        found, notes = discover_npm(names, docs)
        self.assertEqual(len(found), 3)
        self.assertEqual(notes, {})

    def test_a_last_row_older_than_the_window_is_enough(self):
        # all 9 rows asked for (3 x limit 3), fewer than NPM_OLDER_STOP older
        # ones in a row, but the walk ended on a package older than the cutoff
        old = NOW - datetime.timedelta(days=3)
        when = [NOW, old, old, old, old, minutes_ago(5), old, old, old]
        names = [f"p{i}" for i in range(9)]
        found, notes = discover_npm(names, dict(zip(names, when)), limit=3)
        self.assertEqual([n for _, n, _, _ in found], ["p0", "p5"])
        self.assertEqual(notes, {})

    def test_a_short_feed_is_read_whole(self):
        names = ["a", "b", "c"]
        _found, notes = discover_npm(names, {n: minutes_ago(1) for n in names}, limit=3)
        self.assertEqual(notes, {})           # the limit fell on the last name of a 3-row feed

    def test_nothing_could_be_looked_up(self):
        names = [f"p{i}" for i in range(9)]
        found, notes = discover_npm(names, {}, limit=3)
        self.assertEqual(len(found), 3)       # still listed: the feed says they changed
        self.assertEqual(notes, {"npm": "partly checked: none of the 9 packages in the newest 9 "
                                        "changes of its replication feed could be looked up"})


class CliTests(unittest.TestCase):
    def run_cli(self, *argv, fetch=None, npm=None):
        with tempfile.TemporaryDirectory() as d, contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(repo, "_now", return_value=NOW))
            if fetch is not None:
                stack.enter_context(mock.patch.object(repo, "_fetch", side_effect=fetch))
            if npm is not None:
                stack.enter_context(mock.patch.object(repo, "http_json", side_effect=npm))
            stack.enter_context(mock.patch("sys.argv", ["lazaret-registry", "discover", *argv,
                                                        "--db", os.path.join(d, "r.db")]))
            out = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            err = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_a_day_of_pypi_is_not_claimed(self):
        argv = ("--since", "24h", "--ecosystem", "pypi", "--limit", "0")
        code, out, err = self.run_cli(*argv, fetch=pypi_fetch(**SHORT))
        self.assertEqual(code, 0)                     # without --ci: a warning
        self.assertIn("Discovered 140 package(s) since 2026-09-25 17:47 UTC, but not all of that "
                      "window was checked", out)
        self.assertNotIn("since 2026-09-25 17:47 UTC:", out)
        self.assertIn("warning: discovery incomplete: pypi partly checked: covered 17:28–17:47 UTC "
                      "only; its RSS feeds hold the latest 100 updates", err)
        code, _out, _err = self.run_cli(*argv, "--ci", fetch=pypi_fetch(**SHORT))
        self.assertEqual(code, 1)

    # 20 releases a minute apart (17:47:30 back to 17:28:30); an old new
    # project. 16 of the releases are in the 15 minutes since CUTOFF.
    CUTOFF = "2026-09-26T17:32:30+00:00"
    RECENT = {"updates_xml": [(f"pkg-{i} 1.0", minutes_ago(i)) for i in range(20)],
              "packages": [("older added to PyPI", minutes_ago(90))]}

    def test_a_window_the_feeds_cover_passes_ci(self):
        code, out, err = self.run_cli("--since", self.CUTOFF, "--ecosystem", "pypi", "--ci",
                                      fetch=pypi_fetch(**self.RECENT))
        self.assertEqual(code, 0, err)
        self.assertIn("Discovered 16 package(s) since 2026-09-26 17:32 UTC:", out)
        self.assertNotIn("warning", err)

    def test_what_the_limit_leaves_out_is_a_gap(self):
        code, out, err = self.run_cli("--since", self.CUTOFF, "--ecosystem", "pypi", "--limit", "10",
                                      "--ci", fetch=pypi_fetch(**self.RECENT))
        self.assertEqual(code, 1)
        self.assertIn("Discovered 10 package(s) since 2026-09-26 17:32 UTC, but not all", out)
        self.assertIn("warning: discovery incomplete: pypi partly checked: 6 more not listed "
                      "(--limit 10).", err)

    def test_the_limit_is_shared_by_both_registries(self):
        names = ["n0", "n1", "n2"]
        npm = FakeNpm(names, {n: minutes_ago(3 * i) for i, n in enumerate(names)})
        fetch = pypi_fetch(updates_xml=[("u0 1.0", minutes_ago(1)), ("u1 1.0", minutes_ago(4)),
                                        ("u2 1.0", minutes_ago(120))],
                           packages=[("older added to PyPI", minutes_ago(120))])
        code, out, err = self.run_cli("--since", "1h", "--limit", "3", fetch=fetch, npm=npm)
        self.assertEqual(code, 0)
        listed = [line.split()[-1] for line in out.splitlines() if line.startswith("  2026")]
        self.assertEqual(listed, ["npm:n0@1.0.0", "pypi:u0@1.0", "npm:n1@1.0.0"])
        self.assertIn("pypi partly checked: 1 more not listed (--limit 3)", err)
        self.assertIn("npm partly checked: 1 more not listed (--limit 3)", err)

    def test_nothing_new_in_a_window_that_was_covered(self):
        stale = pypi_fetch(updates_xml=updates(100, at(17, 0), at(16, 0)),
                           packages=projects(40, at(17, 0), at(15, 0)))
        code, out, _err = self.run_cli("--since", "2026-09-26T17:17:30+00:00", "--ecosystem", "pypi",
                                       "--ci", fetch=stale)
        self.assertEqual(code, 0)
        self.assertIn("No packages published/updated since 2026-09-26 17:17 UTC in pypi.", out)

    def test_nothing_found_in_the_part_that_was_checked(self):
        code, out, err = self.run_cli("--since", "2026-09-26T17:37:30", "--ecosystem", "pypi",
                                      fetch=pypi_fetch(updates_xml=[], packages=[]))
        self.assertEqual(code, 0)
        self.assertIn("Nothing found in the part of the window that was checked in pypi", out)
        self.assertNotIn("No packages published/updated", out)
        self.assertIn("warning: discovery incomplete: pypi partly checked: the updates.xml feed "
                      "was empty.", err)

    def test_an_iso_cutoff_is_read_as_utc(self):
        # the heading prints the cutoff as "… UTC"
        cutoff = repo.parse_since("2026-09-26T19:30+02:00")
        self.assertEqual(cutoff, at(17, 30))
        self.assertEqual(cutoff.utcoffset(), datetime.timedelta(0))


class McpTests(unittest.TestCase):
    def test_the_tool_is_marked_incomplete(self):
        with mock.patch.object(repo, "_now", return_value=NOW), \
                mock.patch.object(repo, "_fetch", side_effect=pypi_fetch(**SHORT)), \
                contextlib.redirect_stderr(io.StringIO()):
            out = mcp_server.tool_discover_packages({"since": "1d", "ecosystem": ["pypi"], "limit": 50})
        self.assertTrue(out["incomplete"])
        self.assertEqual(out["incompleteReason"],
                         "pypi partly checked: covered 17:28–17:47 UTC only; its RSS feeds hold the "
                         "latest 100 updates (new projects: 16:52–17:47 UTC); 90 more not listed "
                         "(limit 50)")


if __name__ == "__main__":
    unittest.main()
