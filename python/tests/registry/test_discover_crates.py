"""crates.io discovery (CRATES-DISCOVER, 0.1.9): `lazaret-registry discover --ecosystem crates`, with and without
`--resume`.

crates.io has no change feed to page forward. Its API lists crates by their last update, newest first, 100 a page,
each next page named by the answer's own `next_page` (a seek key), and asks crawlers for one request a second. The
crates module walks that list back to a position (`Crates.recent_updates`); `repo.discover_crates` reads a --since
window from it, `repo.discover_crates_since` everything after a stored cursor (the newest update read, in microseconds).
A walk that cannot get back to where it should says which part it covered, and --ci fails the run.

Network is mocked throughout: the API's answers come from `FakeCrates`, a list of harmless made-up crate names paged
as the API pages them, through the module's own `base.Fetch` (its URL rule and pacing, with a clock that never
sleeps).
"""

import contextlib
import datetime
import io
import json
import os
import tempfile
import unittest
import urllib.parse
from unittest import mock

from lazaret.registry import repo
from lazaret.registry.ecosystems import base, crates

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 26, 17, 47, 30, tzinfo=UTC)
LIST = "https://crates.io/api/v1/crates?sort=recent-updates&per_page=100"


def ago(minutes, micro=0):
    return NOW - datetime.timedelta(minutes=minutes, microseconds=-micro)


def stamp(when):
    return when.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class FakeCrates:
    """The API's list by last update, as a `base.Fetch` transport: rows (name, updated_at, newest_version,
    default_version), newest first, `per_page` to a page, a seek key per next page; an updated_at given as (datetime,
    text) is sorted by the one and answered as the other. `fail` maps a request's number
    (1 for the first) to the FetchError it raises; `answers` maps one to the document it answers instead."""

    def __init__(self, rows=(), per_page=100):
        self.rows, self.per_page = list(rows), per_page
        self.urls, self.fail, self.answers = [], {}, {}

    def add(self, name, minutes, version="1.0.0", default=None, micro=0):
        self.rows.append((name, ago(minutes, micro), version, default))

    def __call__(self, url, max_bytes=None, accept=None, timeout=None, check_redirect=None, **extra):
        check_redirect(url)
        self.urls.append(url)
        n = len(self.urls)
        if n in self.fail:
            raise self.fail[n]
        if n in self.answers:
            return json.dumps(self.answers[n]).encode()
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        assert query["sort"] == "recent-updates" and query["per_page"] == "100", url
        start = int(query.get("seek", 0))
        ordered = sorted(self.rows, key=lambda r: (r[1][0] if isinstance(r[1], tuple) else r[1], r[0]), reverse=True)
        page = ordered[start:start + self.per_page]
        nxt = start + self.per_page
        rows = []
        for name, when, version, default in page:
            row = {"name": name, "updated_at": when[1] if isinstance(when, tuple) else stamp(when)}
            if version is not None:
                row["newest_version"] = version
            if default is not None:
                row["default_version"] = default
            rows.append(row)
        meta = {"total": len(ordered),
                "next_page": f"?sort=recent-updates&per_page=100&seek={nxt}" if nxt < len(ordered) else None}
        return json.dumps({"crates": rows, "meta": meta}).encode()


def fetch_for(fake):
    sleeps = []
    return base.Fetch(crates.ECOSYSTEM, fake, clock=lambda: 0.0, sleep=sleeps.append), sleeps


@contextlib.contextmanager
def crates_api(fake):
    with mock.patch.object(repo, "_crates_fetch", side_effect=lambda: fetch_for(fake)[0]):
        yield


class WalkTests(unittest.TestCase):
    """Crates.recent_updates: the list read back to a position."""

    def walk(self, fake, minutes, pages=10, want=0):
        fetch, sleeps = fetch_for(fake)
        out = crates.ECOSYSTEM.recent_updates(fetch, crates.micros(ago(minutes)), pages, want=want)
        return out, fetch, sleeps

    def test_back_to_the_position_and_no_further(self):
        fake = FakeCrates(per_page=3)
        for i in range(8):
            fake.add(f"crate-{i}", i * 10)
        out, fetch, sleeps = self.walk(fake, 45)
        self.assertEqual([n for n, _v, _w in out["items"]], ["crate-0", "crate-1", "crate-2", "crate-3", "crate-4"])
        self.assertTrue(out["reached"])
        self.assertEqual((out["pages"], out["rejected"], out["error"]), (2, 0, None))
        self.assertEqual(out["head"], crates.micros(NOW))
        # the module's own fetch: crates.io's API, its pages as the answers name them, paced (one a second)
        self.assertEqual(fetch.requests, [LIST, LIST + "&seek=3"])
        self.assertEqual(len(sleeps), 1)

    def test_the_position_itself_is_not_listed(self):
        fake = FakeCrates()
        fake.add("after", 10, micro=1)
        fake.add("at", 10)
        out, _f, _s = self.walk(fake, 10)
        self.assertEqual([n for n, _v, _w in out["items"]], ["after"])
        self.assertTrue(out["reached"])

    def test_the_end_of_the_list(self):
        fake = FakeCrates()
        fake.add("only", 5)
        out, _f, _s = self.walk(fake, 60)
        self.assertEqual(len(out["items"]), 1)
        self.assertTrue(out["reached"])

    def test_the_page_budget(self):
        fake = FakeCrates(per_page=2)
        for i in range(10):
            fake.add(f"c{i}", i)
        out, fetch, _s = self.walk(fake, 60, pages=2)
        self.assertEqual(len(out["items"]), 4)
        self.assertFalse(out["reached"])
        self.assertEqual(out["pages"], 2)
        self.assertEqual(len(fetch.requests), 2)

    def test_want_stops_after_the_page_that_reaches_it(self):
        fake = FakeCrates(per_page=3)
        for i in range(9):
            fake.add(f"c{i}", i)
        out, fetch, _s = self.walk(fake, 60, want=4)
        self.assertEqual(len(out["items"]), 6)          # (the second page's three)
        self.assertFalse(out["reached"])
        self.assertEqual(len(fetch.requests), 2)

    def test_each_crate_once_and_its_version(self):
        fake = FakeCrates()
        fake.add("Serde_Like", 1, "2.0.0-rc.1", "1.9.0")
        fake.add("serde-like", 2, "1.9.0")                   # (the same crate to crates.io; a row a page apart)
        fake.add("no-newest", 3, None, "0.4.1")
        fake.add("bad-newest", 4, "not a version", "0.2.0")
        fake.add("no-version", 5, None)
        out, _f, _s = self.walk(fake, 60)
        self.assertEqual([(n, v) for n, v, _w in out["items"]],
                         [("Serde_Like", "2.0.0-rc.1"), ("no-newest", "0.4.1"), ("bad-newest", "0.2.0"),
                          ("no-version", None)])

    def test_rows_that_are_not_crates(self):
        fake = FakeCrates()
        fake.add("good", 1)
        fake.add("-leading-dash", 2)
        fake.add("x" * 65, 3)
        fake.add("sp ace", 4)
        fake.rows.append(("no-time", (ago(4, 1), "yesterday"), "1.0.0", None))
        fake.add("also-good", 5)
        out, _f, _s = self.walk(fake, 60)
        self.assertEqual([n for n, _v, _w in out["items"]], ["good", "also-good"])
        self.assertEqual(out["rejected"], 4)

    def test_a_first_page_that_fails_is_an_error(self):
        fake = FakeCrates()
        fake.fail[1] = base.FetchError("HTTP 503 fetching https://crates.io/api/v1/crates")
        with self.assertRaises(base.FetchError):
            self.walk(fake, 60)

    def test_a_later_page_that_fails_ends_the_walk(self):
        fake = FakeCrates(per_page=2)
        for i in range(6):
            fake.add(f"c{i}", i)
        fake.fail[2] = base.FetchError("timed out")
        out, _f, _s = self.walk(fake, 60)
        self.assertEqual(len(out["items"]), 2)
        self.assertFalse(out["reached"])
        self.assertIsInstance(out["error"], base.FetchError)

    def test_answers_that_are_not_the_list(self):
        for doc in ({"crates": {}}, {"meta": {}}, [], {"crates": [], "meta": None},
                    {"crates": [{}] * 1001, "meta": {}},
                    {"crates": [], "meta": {"next_page": "https://elsewhere.invalid/?sort=recent-updates"}},
                    {"crates": [], "meta": {"next_page": "?sort=alphabetical&seek=1"}},
                    {"crates": [], "meta": {"next_page": "?sort=recent-updates&seek=a b"}},
                    {"crates": [], "meta": {"next_page": "?sort=recent-updates-x&seek=1"}},
                    {"crates": [], "meta": {"next_page": "?" + "a" * 600 + "&sort=recent-updates"}},
                    {"crates": [], "meta": {"next_page": 5}}):
            with self.subTest(doc=str(doc)[:80]):
                fake = FakeCrates()
                fake.answers[1] = doc
                with self.assertRaises(base.FetchError):
                    self.walk(fake, 60)

    def test_micros_is_exact(self):
        when = datetime.datetime(2026, 10, 16, 1, 49, 41, 435544, tzinfo=UTC)
        self.assertEqual(crates.micros(when), 1792115381435544)
        self.assertEqual(crates.from_micros(crates.micros(when)), when)


class WindowTests(unittest.TestCase):
    """discover_crates: the --since window, newest first."""

    def discover(self, fake, minutes, limit):
        notes = {}
        with crates_api(fake), mock.patch.object(repo, "_now", return_value=NOW), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            found = repo.discover_crates(ago(minutes), limit, notes)
        return found, notes, err.getvalue()

    def test_the_window(self):
        fake = FakeCrates()
        for i in range(5):
            fake.add(f"c{i}", i * 10)
        found, notes, _err = self.discover(fake, 25, 0)
        self.assertEqual(found, [("crates", f"c{i}", "1.0.0", ago(i * 10)) for i in range(3)])
        self.assertEqual(notes, {})

    def test_the_limit(self):
        fake = FakeCrates()
        for i in range(5):
            fake.add(f"c{i}", i * 10)
        found, notes, _err = self.discover(fake, 60, 2)
        self.assertEqual([n for _e, n, _v, _w in found], ["c0", "c1"])
        self.assertEqual(notes, {"crates": "partly checked: covered 17:37–17:47 UTC only: stopped at the limit of "
                                           "2 crates"})

    def test_the_page_budget(self):
        fake = FakeCrates(per_page=2)
        for i in range(10):
            fake.add(f"c{i}", i)
        with mock.patch.object(repo, "CRATES_DISCOVER_PAGES", 2):
            found, notes, _err = self.discover(fake, 60, 0)
        self.assertEqual(len(found), 4)
        self.assertEqual(notes, {"crates": "partly checked: covered 17:44–17:47 UTC only; read 2 pages of its "
                                           "list of recently updated crates, the most one run reads"})

    def test_a_list_that_cannot_be_read(self):
        fake = FakeCrates()
        fake.fail[1] = base.FetchError("HTTP 503 fetching https://crates.io/api/v1/crates")
        found, notes, err = self.discover(fake, 60, 0)
        self.assertEqual(found, [])
        self.assertEqual(notes, {"crates": "not checked: could not read crates.io's list of recently updated "
                                           "crates (HTTP 503 fetching https://crates.io/api/v1/crates)"})
        self.assertIn("crates.io was not checked", err)

    def test_a_page_that_fails_part_way(self):
        fake = FakeCrates(per_page=2)
        for i in range(6):
            fake.add(f"c{i}", i)
        fake.fail[2] = base.FetchError("timed out")
        found, notes, _err = self.discover(fake, 60, 0)
        self.assertEqual(len(found), 2)
        self.assertEqual(notes, {"crates": "partly checked: covered 17:46–17:47 UTC only: its list failed after 1 "
                                           "page(s) (could not read crates.io's list of recently updated crates "
                                           "(timed out))"})

    def test_a_long_walk_says_so_as_it_goes(self):
        fake = FakeCrates(per_page=1)
        for i in range(7):
            fake.add(f"c{i}", i)
        found, _notes, err = self.discover(fake, 60, 0)
        self.assertEqual(len(found), 7)
        self.assertEqual(err.count("crates.io: read "), 1)
        self.assertIn("crates.io: read 5 of at most 200 pages of its list of recently updated crates (5 crates, "
                      "back to 2026-09-26 17:43 UTC); one page a second…", err)
        with mock.patch.object(repo, "CRATES_PROGRESS_EVERY", 2):
            _found, _notes, err = self.discover(fake, 60, 0)
        self.assertEqual([line.split(" of at most")[0] for line in err.splitlines()],
                         ["crates.io: read 5", "crates.io: read 6"])

    def test_rejected_rows_are_a_warning(self):
        fake = FakeCrates()
        fake.add("good", 1)
        fake.add("-bad", 2)
        found, _notes, err = self.discover(fake, 60, 0)
        self.assertEqual(len(found), 1)
        self.assertIn("skipped 1 row(s) of crates.io's list whose crate name or time is not valid", err)


class SinceTests(unittest.TestCase):
    """discover_crates_since: everything after a stored cursor, oldest first."""

    def since(self, fake, minutes, limit=0, pages=None):
        notes = {}
        cursor = (crates.micros(ago(minutes)), ago(minutes))
        with contextlib.ExitStack() as stack:
            stack.enter_context(crates_api(fake))
            stack.enter_context(mock.patch.object(repo, "_now", return_value=NOW))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            if pages is not None:
                stack.enter_context(mock.patch.object(repo, "CRATES_DISCOVER_PAGES", pages))
            found, new, covered = repo.discover_crates_since(cursor, limit, notes)
        return found, new, covered, notes

    def test_every_crate_after_the_cursor(self):
        fake = FakeCrates(per_page=2)
        for i in range(7):
            fake.add(f"c{i}", i * 10)
        found, new, covered, notes = self.since(fake, 45)
        self.assertEqual([n for _e, n, _v, _w in found], ["c4", "c3", "c2", "c1", "c0"])
        self.assertEqual(new, (crates.micros(NOW), NOW))
        self.assertEqual(covered, "the updates of 17:02–17:47 UTC, 3 page(s) of its list")
        self.assertEqual(notes, {})

    def test_nothing_new(self):
        fake = FakeCrates()
        fake.add("old", 30)
        found, new, covered, notes = self.since(fake, 10)
        self.assertEqual(found, [])
        self.assertEqual(new, (crates.micros(ago(10)), ago(10)))
        self.assertEqual(covered, "no updates after 2026-09-26 17:37:30 UTC")
        self.assertEqual(notes, {})

    def test_the_limit_moves_the_cursor_to_the_last_listed(self):
        fake = FakeCrates()
        for i in range(5):
            fake.add(f"c{i}", i * 10)
        found, new, _covered, notes = self.since(fake, 45, limit=2)
        self.assertEqual([n for _e, n, _v, _w in found], ["c4", "c3"])
        self.assertEqual(new, (crates.micros(ago(30)), ago(30)))
        self.assertEqual(notes, {"crates": "partly checked: stopped at --limit 2; 3 more crate(s) are left for the "
                                           "next --resume run"})

    def test_a_list_longer_than_a_run_reads(self):
        fake = FakeCrates(per_page=2)
        for i in range(10):
            fake.add(f"c{i}", i * 5)
        found, new, _covered, notes = self.since(fake, 60, pages=2)
        self.assertEqual([n for _e, n, _v, _w in found], ["c3", "c2", "c1", "c0"])
        self.assertEqual(new, (crates.micros(NOW), NOW))        # on, from the newest: the part before is named
        self.assertEqual(notes, {"crates": "partly checked: the updates of 16:47–17:32 UTC were not listed: the "
                                           "list runs back further than the 2 pages one run reads (run it more "
                                           "often)"})

    def test_a_page_that_fails_keeps_the_cursor(self):
        fake = FakeCrates(per_page=2)
        for i in range(6):
            fake.add(f"c{i}", i * 5)
        fake.fail[2] = base.FetchError("timed out")
        found, new, _covered, notes = self.since(fake, 60)
        self.assertEqual([n for _e, n, _v, _w in found], ["c1", "c0"])
        self.assertIsNone(new)
        self.assertIn("the next --resume run reads back to 2026-09-26 16:47 UTC again", notes["crates"])

    def test_a_list_that_cannot_be_read(self):
        fake = FakeCrates()
        fake.fail[1] = base.FetchError("HTTP 429 fetching https://crates.io/api/v1/crates")
        self.assertEqual(self.since(fake, 60)[:3], ([], None, None))


class CliTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.db = os.path.join(d.name, "state.db")
        self.fake = FakeCrates()

    def run_cli(self, *argv, at=NOW, patches=()):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(repo, "_now", return_value=at))
            stack.enter_context(crates_api(self.fake))
            for p in patches:
                stack.enter_context(p)
            stack.enter_context(mock.patch("sys.argv", ["lazaret-registry", "discover", *argv, "--db", self.db]))
            out = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            err = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def cursor(self):
        with repo.Store(self.db) as store:
            return store.discovery_cursor("crates")

    @staticmethod
    def listed(out):
        return [line.split()[-1] for line in out.splitlines() if line.startswith("  2026-")]

    def test_the_window(self):
        self.fake.add("fresh-crate", 5, "0.1.0")
        self.fake.add("older-crate", 120, "2.0.0")
        code, out, err = self.run_cli("--since", "1h", "--ecosystem", "crates", "--ci")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.listed(out), ["crates:fresh-crate@0.1.0"])
        self.assertIsNone(self.cursor())                 # only --resume runs read and write cursors

    def test_first_resume_then_every_crate_since(self):
        self.fake.add("first", 5, "0.1.0")
        code, out, err = self.run_cli("--resume", "--since", "1h", "--ecosystem", "crates", "--ci")
        self.assertEqual(code, 0, err)
        self.assertIn("crates: first --resume run: the window since 2026-09-26 16:47 UTC; the next run continues "
                      "from the update of 2026-09-26 17:42:30 UTC", out)
        self.assertEqual(self.listed(out), ["crates:first@0.1.0"])
        self.assertEqual(self.cursor()[:2], (str(crates.micros(ago(5))), "2026-09-26T17:42:30+00:00"))

        later = NOW + datetime.timedelta(minutes=30)
        self.fake.rows.append(("second", later - datetime.timedelta(minutes=10), "1.2.3", None))
        self.fake.rows.append(("first", later - datetime.timedelta(minutes=1), "0.2.0", None))
        scanned = []

        def fake_scan(store, specs, full, rescan, errors=None):
            scanned.extend(specs)
            return False
        code, out, err = self.run_cli("--resume", "--ecosystem", "crates", "--scan", "--ci", at=later,
                                      patches=[mock.patch.object(repo, "cmd_scan", side_effect=fake_scan)])
        self.assertEqual(code, 0, err)
        self.assertIn("crates: the updates of 17:42–18:16 UTC, 1 page(s) of its list", out)
        self.assertEqual(scanned, ["crates:first@0.2.0", "crates:second@1.2.3"])
        self.assertEqual(self.cursor()[0], str(crates.micros(later - datetime.timedelta(minutes=1))))

    def test_the_first_resume_run_reads_the_last_hour_unless_since_says(self):
        self.fake.add("recent", 30, "0.1.0")
        self.fake.add("older", 120, "0.2.0")
        code, out, err = self.run_cli("--resume", "--ecosystem", "crates", "--ci")
        self.assertEqual(code, 0, err)
        self.assertIn("crates: first --resume run: the window since 2026-09-26 16:47 UTC", out)
        self.assertEqual(self.listed(out), ["crates:recent@0.1.0"])
        os.remove(self.db)
        code, out, err = self.run_cli("--resume", "--ecosystem", "crates", "--since", "3h", "--ci")
        self.assertEqual(code, 0, err)
        self.assertIn("crates: first --resume run: the window since 2026-09-26 14:47 UTC", out)
        self.assertEqual(self.listed(out), ["crates:recent@0.1.0", "crates:older@0.2.0"])

    def test_a_list_that_cannot_be_read_fails_ci_and_keeps_the_cursor(self):
        with repo.Store(self.db) as store:
            store.save_discovery_cursor("crates", crates.micros(ago(30)), ago(30))
        self.fake.fail[1] = base.FetchError("HTTP 503 fetching https://crates.io/api/v1/crates")
        code, _out, err = self.run_cli("--resume", "--ecosystem", "crates", "--ci")
        self.assertEqual(code, 1)
        self.assertIn("warning: discovery incomplete: crates not checked: could not read crates.io's list of "
                      "recently updated crates", err)
        self.assertEqual(self.cursor()[0], str(crates.micros(ago(30))))

    def test_crates_is_one_of_the_default_registries(self):
        self.assertEqual(repo.DISCOVER_ECOSYSTEMS, ("pypi", "npm", "crates"))
        self.fake.add("fresh-crate", 5, "0.1.0")
        patches = [mock.patch.object(repo, "discover_pypi", return_value=[]),
                   mock.patch.object(repo, "discover_npm", return_value=[])]
        code, out, err = self.run_cli("--since", "1h", "--ci", patches=patches)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.listed(out), ["crates:fresh-crate@0.1.0"])


if __name__ == "__main__":
    unittest.main()
