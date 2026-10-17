"""GitHub discovery with GH Archive's events (GH-SCAN-ALL, 0.1.9: lazaret.registry.ghevents and ghdiscover's
--github-archive, --github-scan-all and --max-scans).

GH Archive is a fake throughout (the network seam ghevents.fetch takes): hourly files built here, gzipped, of events
in the Events API's shape, a 404 for an hour not published yet. GitHub is test_ghdiscover's FakeGitHub. Covered:
reading an hour (the events kept, the lines passed over, the bounds, a file sent unpacked); the fetch (the one host,
no credential, a 404 waited for); the archive's cursor (the first run's hour, an unpublished hour, at most
ARCHIVE_HOURS a run); a kept candidate made ready by a push without a content check; a repository made public through
the filters; every new repository that gets code queued, pending until the listing reaches it, excluded, reported
when a campaign's and never downloaded; the scans' cap and order; the queue's bound; the CLI's options, `list` and
the help's examples. Everything is inert: names and hosts are made up, nothing is fetched or run.
"""
import contextlib
import datetime
import gzip
import io
import json
import os
import re
import sys
import tempfile
import unittest
from unittest import mock

from tests import _support  # noqa: F401
from lazaret.registry import ghdiscover, ghevents, repo
from tests.registry.test_ghdiscover import BENIGN, ENV, NOW, Case, FakeGitHub, at, failure, item

UTC = datetime.timezone.utc
HOUR = NOW - datetime.timedelta(hours=1)          # the last complete hour at NOW (11:00 UTC)


def event(kind, rid, name, when=HOUR, **payload):
    return {"id": str(rid * 10), "type": kind, "actor": {"login": "someone"},
            "repo": {"id": rid, "name": name, "url": f"https://api.github.com/repos/{name}"},
            "payload": payload, "public": True, "created_at": when.strftime("%Y-%m-%dT%H:%M:%SZ")}


def push(rid, name, when=HOUR):
    return event("PushEvent", rid, name, when, repository_id=rid, push_id=1, ref="refs/heads/main",
                 head="0" * 40, before="1" * 40)


def created(rid, name, description=None, when=HOUR):
    return event("CreateEvent", rid, name, when, ref=None, ref_type="repository", master_branch="main",
                 description=description, pusher_type="user")


def public(rid, name, when=HOUR):
    return event("PublicEvent", rid, name, when)


def hour_file(events, raw=None):
    lines = b"".join(json.dumps(e).encode() + b"\n" for e in events) + (raw or b"")
    return gzip.compress(lines)


class FakeArchive:
    """GH Archive's hours: {hour name: [events]}; an hour not in it is not published (404)."""

    def __init__(self, hours=None):
        self.hours = dict(hours or {})
        self.seen = []

    def __call__(self, url, headers, max_bytes, hosts, auth_host, **kw):
        self.seen.append((url, dict(headers), set(hosts)))
        m = re.fullmatch(r"https://data\.gharchive\.org/(\d{4}-\d\d-\d\d-\d{1,2})\.json\.gz", url)
        if not m or m.group(1) not in self.hours:
            raise failure("reading GH Archive: not found", 404)
        got = self.hours[m.group(1)]
        return got if isinstance(got, bytes) else hour_file(got)


class ReadTests(unittest.TestCase):
    def test_the_events_discovery_reads(self):
        body = hour_file([
            created(1001, "a/new", "a new tool"), push(1001, "a/new"),
            event("CreateEvent", 1002, "b/branchy", ref="dev", ref_type="branch"),
            public(55, "old/now-public"), event("WatchEvent", 1003, "c/starred", action="started"),
            push(1004, "bad/../name"), {**push(1005, "d/x"), "repo": {"id": "1005", "name": "d/x"}},
        ], raw=b"not json, a PushEvent\n" + b"{" + b"x" * (ghevents.LINE_BYTES + 10) + b"PushEvent}\n")
        hour = ghevents.read(body)
        self.assertEqual(hour.pushed, {1001: ("a/new", "2026-10-14T11:00:00+00:00"),
                                       1002: ("b/branchy", "2026-10-14T11:00:00+00:00")})
        self.assertEqual(hour.created, {1001: ("a/new", "a new tool", "2026-10-14T11:00:00+00:00")})
        self.assertEqual(hour.public, {55: ("old/now-public", "2026-10-14T11:00:00+00:00")})
        self.assertEqual((hour.events, hour.skipped), (8, 4))      # (two bad repositories, not JSON; too long)

    def test_keep_says_whose_pushes_are_kept(self):
        hour = ghevents.read(hour_file([push(1, "a/one"), push(2, "b/two")]), keep=lambda rid: rid == 2)
        self.assertEqual(list(hour.pushed), [2])

    def test_a_file_sent_unpacked_is_read_and_one_that_is_not_gzip_refused(self):
        lines = json.dumps(push(7, "a/seven")).encode() + b"\n"
        self.assertEqual(list(ghevents.read(lines).pushed), [7])
        with self.assertRaises(ghevents.ArchiveError):
            ghevents.read(b"\x1f\x8b" + b"broken")

    def test_the_hour_names(self):
        t = datetime.datetime(2026, 10, 17, 3, 59, tzinfo=UTC)
        self.assertEqual((ghevents.hour_name(t), ghevents.url(t)),
                         ("2026-10-17-3", "https://data.gharchive.org/2026-10-17-3.json.gz"))
        self.assertEqual(ghevents.parse_hour("2026-10-17-3"), t.replace(minute=0))
        for bad in ("2026-10-17", "2026-10-17-24", "x-3"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ghevents.parse_hour(bad)

    def test_the_fetch_goes_to_gh_archive_alone_with_no_credential(self):
        archive = FakeArchive({"2026-10-14-11": [push(1, "a/b")]})
        self.assertTrue(ghevents.fetch(HOUR, archive))
        url, headers, hosts = archive.seen[0]
        self.assertEqual((hosts, sorted(headers)), ({"data.gharchive.org"}, ["User-Agent"]))
        self.assertIsNone(ghevents.fetch(NOW, archive))             # (not published yet)

        def broken(*a, **kw):
            raise failure("reading GH Archive: network error (timeout)", None)
        with self.assertRaises(ghevents.ArchiveError):
            ghevents.fetch(HOUR, broken)


class ArchiveCase(Case):
    def setUp(self):
        super().setUp()
        self.store.save_discovery_cursor("github", 1000, NOW)

    def run_gh(self, gh, when=NOW, events=None, **kw):
        kw.setdefault("filters", ghdiscover.Filters())
        return ghdiscover.run(self.store, env=ENV, http=gh, now=when, archive_http=events, **kw)


class ArchiveTests(ArchiveCase):
    def test_a_push_makes_a_kept_repository_ready_without_a_check(self):
        gh = FakeGitHub([item(1001, "shopsprint/decimal")], info={"shopsprint/decimal": {"size": 0}})
        self.run_gh(gh, when=at(-0.5))                              # (listed, waiting)
        archive = FakeArchive({"2026-10-14-11": [push(1001, "shopsprint/decimal", at(-0.25))]})
        out = self.run_gh(gh, events=archive, archive=True)
        cand = self.candidates()["shopsprint/decimal"]
        self.assertEqual((cand["state"], cand["pushed_at"]), ("ready", "2026-10-14T11:45:00+00:00"))
        self.assertEqual(gh.asked("/repos/shopsprint"), [])         # no content check
        self.assertEqual((out["archive"]["hours"], out["archive"]["ready"]), (["2026-10-14-11"], 1))

    def test_a_repository_made_public_goes_through_the_filters(self):
        archive = FakeArchive({"2026-10-14-11": [public(77, "shopsprint/decimal"), public(78, "someone/notes"),
                                                 public(79, "spf31/cobra"), push(79, "spf31/cobra")]})
        out = self.run_gh(FakeGitHub(), events=archive, archive=True)
        self.assertEqual({k: c["state"] for k, c in self.candidates().items()},
                         {"shopsprint/decimal": "waiting", "spf31/cobra": "ready"})    # (pushed too: code)
        self.assertEqual(out["archive"]["public"], 3)

    def test_the_cursor_waits_for_an_unpublished_hour_and_reads_three_at_most(self):
        archive = FakeArchive({"2026-10-14-11": []})
        first = self.run_gh(FakeGitHub(), events=archive, archive=True)
        self.assertEqual((first["archive"]["hours"], self.store.discovery_cursor("gharchive")[0]),
                         (["2026-10-14-11"], "2026-10-14-11"))
        later = self.run_gh(FakeGitHub(), when=at(1.5), events=archive, archive=True)
        self.assertEqual((later["archive"]["hours"], later["archive"]["unpublished"], later["archive"]["next"]),
                         ([], True, "2026-10-14-12"))
        archive.hours.update({f"2026-10-14-{h}": [] for h in range(12, 20)})
        caught = self.run_gh(FakeGitHub(), when=at(8), events=archive, archive=True)
        self.assertEqual(caught["archive"]["hours"], ["2026-10-14-12", "2026-10-14-13", "2026-10-14-14"])
        self.assertEqual(self.store.discovery_cursor("gharchive")[0], "2026-10-14-14")

    def test_an_hour_never_published_is_passed_over(self):
        archive = FakeArchive({"2026-10-14-11": [], "2026-10-14-13": []})
        self.run_gh(FakeGitHub(), events=archive, archive=True)
        out = self.run_gh(FakeGitHub(), when=at(10), events=archive, archive=True)
        self.assertEqual((out["archive"]["hours"], out["archive"]["missing"]),
                         (["2026-10-14-13"], ["2026-10-14-12", "2026-10-14-14"]))
        self.assertEqual(self.store.discovery_cursor("gharchive")[0], "2026-10-14-14")

    def test_an_hour_that_cannot_be_read_stops_the_archive_not_the_run(self):
        archive = FakeArchive({"2026-10-14-11": b"\x1f\x8bbroken"})
        out = self.run_gh(FakeGitHub([item(1001, "a/b")]), events=archive, archive=True)
        self.assertIn("not one GH Archive writes", out["archive"]["error"])
        self.assertEqual((out["listed"], self.store.discovery_cursor("gharchive")), (1, None))


class ScanAllTests(ArchiveCase):
    def scan_all(self, gh, archive, when=NOW, **kw):
        return self.run_gh(gh, when=when, events=archive, scan_all=True, **kw)

    def test_every_new_repository_that_gets_code_is_scanned(self):
        first = self.scan_all(FakeGitHub(), FakeArchive())         # (scan-all begins at the listing's cursor)
        self.assertEqual(first["queue"]["since"], 1000)
        self.assertEqual(self.store.discovery_cursor("github-scan-all")[0], "1000")
        names = {1001: "u1/tool", 1002: "u2/site", 1003: "u3/empty"}
        gh = FakeGitHub([item(k, v) for k, v in names.items()], files={"u1/tool": BENIGN, "u2/site": BENIGN})
        archive = FakeArchive({"2026-10-14-11": [push(999, "old/repo"), push(1001, "u1/tool"),
                                                 push(1002, "u2/site")]})
        self.run_gh(gh, when=at(-0.9))                              # (the listing reaches them first)
        self.store.save_discovery_cursor("gharchive", "2026-10-14-10", NOW)
        out = self.scan_all(gh, archive)
        self.assertEqual(sorted(r["name"] for r in out["scans"]), ["u1/tool", "u2/site"])
        self.assertEqual({c["full_name"]: c["state"] for c in self.store.github_candidates()},
                         {"u1/tool": "scanned", "u2/site": "scanned"})
        self.assertEqual(gh.asked("old/repo") + gh.asked("u3/empty"), [])   # not new; no code
        self.assertEqual((out["archive"]["pushed"], out["queue"]["queued"]), (2, 2))

    def test_a_push_before_the_listing_waits_for_it(self):
        self.store.save_discovery_cursor("github-scan-all", 1000)
        archive = FakeArchive({"2026-10-14-11": [created(1005, "fresh/repo", "x"), push(1005, "fresh/repo"),
                                                 created(1006, "fresh/hidden"), push(1006, "fresh/hidden")]})
        patterns = {"exclude": {"full_name": [re.compile("hidden$")]}, "include": {}}
        filters = ghdiscover.Filters(patterns=patterns)
        out = self.scan_all(FakeGitHub(), archive, filters=filters, max_scans=0)
        self.assertEqual({c["full_name"]: c["state"] for c in self.store.github_candidates()},
                         {"fresh/repo": "pending", "fresh/hidden": "excluded"})
        self.assertEqual((out["queue"]["pending"], out["queue"]["excluded"]), (1, 1))
        gh = FakeGitHub([item(1005, "fresh/repo", "x")])
        later = self.scan_all(gh, FakeArchive(), when=at(0.5), filters=filters, max_scans=0)
        self.assertEqual((later["queue"]["promoted"], self.candidates()["fresh/repo"]["state"]), (1, "queued"))

    def test_a_campaign_repository_is_reported_and_never_downloaded(self):
        self.store.save_discovery_cursor("github-scan-all", 900)
        archive = FakeArchive({"2026-10-14-11": [created(950, "victim/x", "Shai-Hulud Migration"),
                                                 push(950, "victim/x"), push(951, "victim2/shai-hulud")]})
        gh = FakeGitHub(files={"victim/x": BENIGN, "victim2/shai-hulud": BENIGN})
        out = self.scan_all(gh, archive)
        self.assertEqual({c["full_name"]: c["state"] for c in self.store.github_candidates()},
                         {"victim/x": "reported", "victim2/shai-hulud": "reported"})
        self.assertEqual(sorted(f for f, _m, _u in out["campaigns"]), ["victim/x", "victim2/shai-hulud"])
        self.assertEqual(gh.asked("victim"), [])

    def test_the_scans_are_capped_filter_matches_first_then_the_newest(self):
        self.store.save_discovery_cursor("github-scan-all", 900)
        repos = {901 + k: f"user{k}/r{k}" for k in range(6)}
        archive = FakeArchive({"2026-10-14-11": [push(k, v, HOUR + datetime.timedelta(minutes=k - 900))
                                                 for k, v in repos.items()]})
        self.store.add_github_candidate(800, "shopsprint/decimal", None, False, ["look-alike"],
                                        "2026-10-14T09:00:00+00:00", "ready", None)
        files = {v: BENIGN for v in repos.values()}
        files["shopsprint/decimal"] = BENIGN
        out = self.scan_all(FakeGitHub(files=files), archive, max_scans=3)
        self.assertEqual([r["name"] for r in out["scans"]], ["shopsprint/decimal", "user5/r5", "user4/r4"])
        self.assertEqual(out["queue"]["left"], 4)

    def test_the_queue_keeps_the_newest(self):
        self.store.save_discovery_cursor("github-scan-all", 900)
        archive = FakeArchive({"2026-10-14-11": [push(901 + k, f"u{k}/r", HOUR + datetime.timedelta(minutes=k))
                                                 for k in range(8)]})
        with mock.patch.object(ghdiscover, "QUEUE_MAX", 5):
            out = self.scan_all(FakeGitHub(), archive, max_scans=0)
        self.assertEqual((out["queue"]["queued"], out["queue"]["skipped"], out["queue"]["left"]), (8, 3, 5))
        self.assertEqual(sorted(c["repo_id"] for c in self.store.github_candidates()), [904, 905, 906, 907, 908])

    def test_a_pending_repository_the_listing_never_reaches_is_dropped_after_three_days(self):
        self.store.save_discovery_cursor("github-scan-all", 1000)
        self.scan_all(FakeGitHub(), FakeArchive({"2026-10-14-11": [push(5000, "far/ahead")]}), max_scans=0)
        self.assertEqual(self.candidates()["far/ahead"]["state"], "pending")
        out = self.scan_all(FakeGitHub(), FakeArchive(), when=at(73), max_scans=0)
        self.assertEqual((self.candidates(), out["queue"]["skipped"]), ({}, 1))

    def test_a_failed_scan_drops_a_queued_repository(self):
        self.store.save_discovery_cursor("github-scan-all", 900)
        out = self.scan_all(FakeGitHub(), FakeArchive({"2026-10-14-11": [push(901, "u/gone")]}))
        self.assertEqual(self.candidates()["u/gone"]["state"], "dropped")
        self.assertEqual(len(out["errors"]), 1)


class CommandLineTests(Case):
    def cli(self, *argv, env=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["lazaret-registry", *argv]), mock.patch.dict(os.environ, env or {}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_the_options_go_with_github_discovery(self):
        for argv in (("discover", "--github-scan-all"), ("scan", "npm:x", "--max-scans", "3"),
                     ("discover", "--ecosystem", "npm", "--github-archive")):
            with self.subTest(argv=argv):
                code, _out, err = self.cli(*argv, "--db", self.db)
                self.assertEqual(code, 2)
                self.assertIn("go with discover --ecosystem github --resume", err)

    def test_the_help_shows_examples(self):
        code, out, _err = self.cli("--help")
        self.assertEqual(code, 0)
        for text in ("examples:", "lazaret-registry scan npm:left-pad@1.3.0", "lazaret-registry scan-all --ci",
                     "discover --ecosystem github --resume --github-scan-all --max-scans 50"):
            self.assertIn(text, out)

    def test_a_run_says_what_it_kept_and_what_gh_archive_gave(self):
        self.store.save_discovery_cursor("github", 1001, NOW)          # (an earlier run listed u1/tool)
        self.store.save_discovery_cursor("github-scan-all", 1000)
        gh = FakeGitHub([item(1001, "u1/tool"), item(1002, "u2/other")], files={"u1/tool": BENIGN})
        archive = FakeArchive({ghevents.hour_name(datetime.datetime.now(UTC) - datetime.timedelta(hours=1)):
                               [push(1001, "u1/tool")]})
        def both(url, *a, **kw):
            return (archive if "gharchive" in url else gh)(url, *a, **kw)
        with mock.patch.object(ghdiscover.sources, "_http", both):
            code, out, _err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all",
                                       "--db", self.db, env=ENV)
        self.assertIn("kept 0: no look-alike", out)
        self.assertIn("GH Archive: read 1 hour(s)", out)
        self.assertRegex(out, r"every new repository \(newer than ID 1000\): 1 got code; queued 1")
        self.assertIn("scanned 1 this run", out)
        code, out, _err = self.cli("list", "--db", self.db)
        self.assertIn("Every new repository (--github-scan-all): scanned 1", out)


class PostgresTests(unittest.TestCase):
    def test_the_batch_insert_the_states_and_the_pruning(self):
        from tests.registry.test_ghdiscover import CandidateConn
        from tests.registry.test_review_store_reconnect import pg_store
        conn = CandidateConn()
        store = pg_store(conn)
        store.add_github_candidates([(k, f"u{k}/r", None, False, [ghdiscover.ALL_PUSHED],
                                      f"2026-10-14T11:0{k}:00+00:00", "queued", None) for k in range(1, 6)])
        self.assertEqual(store.github_candidate_states([1, 2, 99]), {1: "queued", 2: "queued"})
        self.assertEqual(store.prune_github_candidates("queued", keep=2), 3)
        self.assertEqual([c["repo_id"] for c in store.github_candidates(newest_first=True, limit=5)], [5, 4])
        self.assertEqual(store.prune_github_candidates("queued", before="2026-10-14T11:05:00+00:00"), 1)
        sent = [s for s, _ in conn.sent]
        self.assertTrue(any("LIMIT 9223372036854775807 OFFSET 2" in s for s in sent))
        self.assertTrue(any(s.startswith("DELETE FROM github_candidates WHERE repo_id IN ($1,$2,$3)") for s in sent))


class ScanHelpTests(unittest.TestCase):
    def test_lazaret_help_shows_examples(self):
        from lazaret.scanner import core
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            core.main(["--help"])
        for text in ("examples:", "lazaret github:owner/repo@v1.2.0", "lazaret . --ci", "lazaret-registry --help"):
            self.assertIn(text, out.getvalue())


if __name__ == "__main__":
    unittest.main()
