"""SC-VERSION-INFLATION (RA-7): a release whose version is inflated like a dependency-confusion squat's, or one
published in a flood of releases. The heuristic (`registry/version_anomaly.py`) is pure and tested here directly; the
registry wiring (`repo.version_inflation_issues`) with `prior.version_times` mocked; `prior.version_times` and the
release scan's `prior.History` over made-up registry answers (`repo._fetch` and `repo.module_transport` patched), so
nothing opens a socket and no native library is needed. All names and versions are made up."""
import datetime
import json
import os
import unittest
from unittest import mock

from lazaret.registry import prior, repo, version_anomaly as va
from lazaret.registry.ecosystems import base, crates

UTC = datetime.timezone.utc
ON = {prior.OFF_ENV: "", "LAZARET_NO_DEPENDENCY_HISTORY": ""}
INDEX = "https://index.crates.io/"


def dt(day, hour=0, year=2026, month=10):
    return datetime.datetime(year, month, day, hour, tzinfo=UTC)


def hist(*pairs):
    """[(version, time)] as version_reason and flood_reason read it."""
    return list(pairs)


def flagged(version, history):
    return va.version_reason(version, history) is not None


class PartsTests(unittest.TestCase):
    def test_rank_and_major(self):
        self.assertEqual([va.rank(v) for v in ("99.0.0", "v100.1", "2024.1", "1!0.0.1", "1.2.3", "", "x")],
                         [(0, 99), (0, 100), (0, 2024), (1, 0), (0, 1), None, None])
        self.assertEqual([va.major(v) for v in ("99.0.0", "1!2.0", "x")], [99, 2, None])

    def test_calendar_like_is_bounded_by_the_year_after_publication(self):
        for m in (1990, 2024, 2027, 202401, 202712, 20240101, 20271231):
            self.assertTrue(va.calendar_like(m, latest_year=2027), m)
        for m in (99, 1989, 2028, 2099, 2100, 19999, 19993299, 100001, 999912, 99991231, 100):
            self.assertFalse(va.calendar_like(m, latest_year=2027), m)
        self.assertTrue(va.calendar_like(datetime.datetime.now(UTC).year + 1))        # (no year given: now's, + 1)

    def test_inflated(self):
        when = dt(1)                                                   # (2026: a calendar year up to 2027)
        self.assertEqual([va.inflated(v, when) for v in ("99.0.0", "100.0.0", "19999.0.0", "98.0.0", "2024.1.0",
                                                         "20240101.0.0", "2099.0.0", "99991231.0.0", "999912.0.0",
                                                         "100001.0.0", "1!0.0.1", "0!99.0", "x")],
                         [True, True, True, False, False, False, True, True, True, True, True, True, False])

    def test_prerelease(self):
        self.assertEqual([va.prerelease("npm", v) for v in ("1.0.0-canary.1", "1.0.0", "1.0.0+build-7")],
                         [True, False, False])
        self.assertEqual([va.prerelease("crates", v) for v in ("1.0.0-beta.1", "1.0.0")], [True, False])
        self.assertEqual([va.prerelease("pypi", v) for v in ("1.0a1", "1.0b2", "1.0rc1", "1.0.dev3", "2.0c1",
                                                             "1.0", "1.0.post1", "2024.10.1", "1!1.0", "1.0+dev")],
                         [True, True, True, True, True, False, False, False, False, False])


class VersionReasonTests(unittest.TestCase):
    def test_an_inflated_first_release(self):
        r = va.version_reason("99.0.0", hist(("99.0.0", dt(1))))
        self.assertIn("is the package's first published version", r)
        self.assertIn("a major of 99", r)

    def test_a_squats_99_0_0_and_99_0_1_are_both_flagged(self):
        h = hist(("99.0.0", dt(1, 0)), ("99.0.1", dt(1, 1)))
        self.assertIn("is the package's first published version", va.version_reason("99.0.0", h))
        self.assertIn("continues the inflated line 99.0.0 began, the package's first published version",
                      va.version_reason("99.0.1", h))

    def test_a_jump_and_what_continues_it(self):
        h = hist(("1.0.0", dt(1, month=9)), ("99.0.0", dt(1)), ("99.0.1", dt(1, 1)))
        self.assertIn("is a jump of 98 majors from 1.0.0, the highest version published before it",
                      va.version_reason("99.0.0", h))
        self.assertIn("continues the inflated line 99.0.0 began, a jump of 98 majors from 1.0.0",
                      va.version_reason("99.0.1", h))

    def test_a_gradual_climb_is_not_new_to_the_package(self):
        # chromedriver follows Chrome's numbers: 97, 98, then 99 and 100 are a climb, not a jump
        h = hist(("2.46.0", dt(1, year=2019)), ("97.0.0", dt(5, year=2022, month=1)),
                 ("98.0.0", dt(2, year=2022, month=2)), ("98.0.1", dt(20, year=2022, month=2)),
                 ("99.0.0", dt(2, year=2022, month=3)), ("100.0.0", dt(30, year=2022, month=3)))
        self.assertEqual([flagged(v, h) for v in ("99.0.0", "100.0.0")], [False, False])

    def test_a_climb_past_99_and_then_a_jump_is_caught_at_the_jump(self):
        # the origin is the latest jump at or before the release, not the earliest inflated version
        h = hist(("97.0.0", dt(1, month=1)), ("99.0.0", dt(1, month=2)), ("130.0.0", dt(1, month=3)),
                 ("9999.0.0", dt(1, month=4)), ("9999.0.1", dt(1, month=5)))
        self.assertEqual([flagged(v, h) for v in ("99.0.0", "130.0.0")], [False, False])
        self.assertIn("is a jump of 9869 majors from 130.0.0", va.version_reason("9999.0.0", h))
        self.assertIn("continues the inflated line 9999.0.0 began, a jump of 9869 majors from 130.0.0",
                      va.version_reason("9999.0.1", h))
        # a squat that started inflated and jumps again names the later jump
        squat = hist(("99.0.0", dt(1, month=1)), ("9999.0.0", dt(1, month=2)))
        self.assertIn("is a jump of 9900 majors from 99.0.0", va.version_reason("9999.0.0", squat))

    def test_the_verdict_does_not_change_when_later_versions_appear(self):
        # only versions published at or before the release are read
        squat = hist(("99.0.0", dt(1)))
        later = squat + hist(("99.0.1", dt(2)), ("1.0.0", dt(3)))
        self.assertEqual((flagged("99.0.0", squat), flagged("99.0.0", later)), (True, True))
        climb = hist(("97.0.0", dt(1, month=1)), ("98.0.0", dt(1, month=2)), ("99.0.0", dt(1, month=3)))
        self.assertEqual((flagged("99.0.0", climb), flagged("99.0.0", climb + hist(("100.0.0", dt(1, month=4))))),
                         (False, False))
        # a version published after the release is not "before it" (a 1.0.0 published after 99.0.0 is no history)
        self.assertIn("is the package's first published version",
                      va.version_reason("99.0.0", hist(("1.0.0", dt(2)), ("99.0.0", dt(1)))))

    def test_a_package_that_started_inflated_stays_flagged(self):
        h = hist(("99.0.0", dt(1, month=1)), ("99.1.0", dt(1, month=3)), ("100.0.0", dt(1, month=6)))
        self.assertTrue(all(flagged(v, h) for v in ("99.0.0", "99.1.0", "100.0.0")))

    def test_normal_and_calendar_versions_are_left_alone(self):
        self.assertIsNone(va.version_reason("3.0.0", hist(("1.0.0", dt(1)), ("2.0.0", dt(2)), ("3.0.0", dt(3)))))
        self.assertIsNone(va.version_reason("2026.10", hist(("2026.9", dt(1, month=9)), ("2026.10", dt(1)))))
        self.assertIsNone(va.version_reason("20261017.0.0", hist(("20261016.0.0", dt(16)), ("20261017.0.0", dt(17)))))
        # a version above a calendar version is not a jump from it (it does not outrank it)
        self.assertIsNone(va.version_reason("99.0.0", hist(("2024.1.0", dt(1, year=2024)), ("99.0.0", dt(1)))))

    def test_calendar_bounds_are_not_a_way_around_it(self):
        for v in ("99991231.0.0", "999912.0.0", "100001.0.0", "2099.0.0"):
            with self.subTest(v=v):
                self.assertIn("is a jump", va.version_reason(v, hist(("1.0.0", dt(1, month=1)), (v, dt(1)))))

    def test_a_pypi_epoch(self):
        h = hist(("1.0", dt(1, month=1)), ("2.0", dt(1, month=2)), ("1!0.0.1", dt(1)), ("1!0.0.2", dt(2)))
        r = va.version_reason("1!0.0.1", h)
        self.assertIn("an epoch of 1, which outranks every version without one", r)
        self.assertIn("is an epoch above that of every version published before it (the highest, 2.0)", r)
        self.assertIn("continues the inflated line 1!0.0.1 began", va.version_reason("1!0.0.2", h))
        self.assertIsNone(va.version_reason("2.0", h))

    def test_versions_without_a_time_were_published_first(self):
        # a crate's index lines from before pubtime: in the index's order, before every line with a time
        climb = hist(("97.0.0", None), ("98.0.0", None), ("99.0.0", dt(1)))
        self.assertFalse(flagged("99.0.0", climb))                      # (dropped, 99.0.0 would look first)
        jump = hist(("1.0.0", None), ("1.1.0", None), ("99.0.0", dt(1)))
        self.assertIn("a jump of 98 majors from 1.1.0", va.version_reason("99.0.0", jump))
        self.assertEqual(va.timeline(hist(("2.0.0", dt(2)), ("0.1.0", None), ("1.0.0", dt(1)), ("0.2.0", None))),
                         [("0.1.0", None), ("0.2.0", None), ("1.0.0", dt(1)), ("2.0.0", dt(2))])


class FloodReasonTests(unittest.TestCase):
    def test_more_than_five_in_a_day_with_this_release(self):
        h = [(f"1.0.{n}", dt(1, n)) for n in range(6)]                  # six within six hours
        self.assertIn("6 of its releases (pre-releases not counted) were published within 24 hours",
                      va.flood_reason("npm", "1.0.5", h))
        self.assertIsNotNone(va.flood_reason("npm", "1.0.0", h))

    def test_a_burst_that_does_not_hold_this_release_is_not_its_flood(self):
        burst = [(f"0.0.{n}", dt(1, n, year=2019)) for n in range(6)]  # a package's first day, years ago
        self.assertIsNone(va.flood_reason("npm", "2.1.0", burst + [("2.1.0", dt(1))]))
        later = [(f"2.0.{n}", dt(1, n)) for n in range(6)]              # a burst after an old release
        self.assertIsNone(va.flood_reason("npm", "1.0.0", [("1.0.0", dt(1, year=2020))] + later))

    def test_the_window_holds_the_release_on_either_side(self):
        before = [(f"1.0.{n}", dt(1, n)) for n in range(5)] + [("1.1.0", dt(1, 23))]
        self.assertIsNotNone(va.flood_reason("npm", "1.1.0", before))   # five earlier the same day, then this one
        after = [("1.1.0", dt(1, 0))] + [(f"1.2.{n}", dt(1, 20 + n)) for n in range(4)] + [("1.3.0", dt(2, 0))]
        self.assertIsNotNone(va.flood_reason("npm", "1.1.0", after))    # this one, then five within 24 hours
        apart = [("1.1.0", dt(1, 0))] + [(f"1.2.{n}", dt(2, 1 + n)) for n in range(5)]
        self.assertIsNone(va.flood_reason("npm", "1.1.0", apart))       # the five start 25 hours later

    def test_exactly_five_and_spread_out_are_not_a_flood(self):
        self.assertIsNone(va.flood_reason("npm", "1.0.4", [(f"1.0.{n}", dt(1, n)) for n in range(5)]))
        self.assertIsNone(va.flood_reason("npm", "1.0.5", [(f"1.0.{n}", dt(1 + n)) for n in range(6)]))

    def test_prereleases_do_not_count(self):
        canaries = [(f"15.0.0-canary.{n}", dt(1, n)) for n in range(6)]
        self.assertIsNone(va.flood_reason("npm", "15.0.0", canaries + [("15.0.0", dt(1, 7))]))
        self.assertIsNone(va.flood_reason("npm", "15.0.0-canary.5", canaries))
        self.assertIsNone(va.flood_reason("crates", "1.0.0", [(f"1.0.0-rc.{n}", dt(1, n)) for n in range(6)]
                                          + [("1.0.0", dt(1, 7))]))
        pypi = [(v, dt(1, n)) for n, v in enumerate(("2.0a1", "2.0a2", "2.0b1", "2.0rc1", "2.0.dev1", "2.0"))]
        self.assertIsNone(va.flood_reason("pypi", "2.0", pypi))
        finals = [(f"2.0.{n}", dt(1, n)) for n in range(6)]
        self.assertIsNotNone(va.flood_reason("pypi", "2.0.5", finals))

    def test_versions_without_a_time_do_not_count(self):
        self.assertIsNone(va.flood_reason("crates", "1.0.5", [(f"1.0.{n}", None) for n in range(5)]
                                          + [("1.0.5", dt(1))]))
        self.assertIsNone(va.flood_reason("crates", "1.0.0", [("1.0.0", None)]))


class IssueTests(unittest.TestCase):
    """repo.version_inflation_issues with the registry history mocked."""

    def issues(self, eco, name, version, times, found=()):
        with mock.patch.object(repo._prior, "version_times", return_value=times) as asked:
            out = repo.version_inflation_issues(eco, name, version, resolved=None, found=found)
        self.asked = asked
        return out

    def test_an_inflated_first_release_is_major(self):
        out = self.issues("npm", "left-pad-internal", "99.0.0", {"99.0.0": dt(1).isoformat()})
        self.assertEqual([(i["rule"], i["sev"]) for i in out], [("SC-VERSION-INFLATION", "MAJOR")])
        self.assertIn("99.0.0", out[0]["msg"])

    def test_a_jump_to_an_inflated_major_is_major(self):
        times = {"1.0.0": dt(1).isoformat(), "1.1.0": dt(2).isoformat(), "99.0.0": dt(3).isoformat()}
        out = self.issues("pypi", "acme-utils", "99.0.0", times)
        self.assertEqual([i["sev"] for i in out], ["MAJOR"])

    def test_a_flood_alongside_an_inflated_version_is_reported(self):
        times = {f"99.0.{n}": dt(1, n).isoformat() for n in range(6)}        # six 99.0.x within six hours
        out = self.issues("crates", "fastcrate", "99.0.5", times)
        self.assertEqual([i["rule"] for i in out], ["SC-VERSION-INFLATION"])
        self.assertIn("continues the inflated line 99.0.0 began, the package's first published version", out[0]["msg"])
        self.assertIn("; and 6 of its releases", out[0]["msg"])

    def test_a_pure_flood_on_normal_versions_is_flagged(self):
        # unconditional (John, Oct 17): the history is read for every release, so a publish-flood on normally-versioned
        # releases is caught, not only one that also has an inflated version
        times = {f"1.0.{n}": dt(1, n).isoformat() for n in range(6)}         # six 1.0.x within six hours
        out = self.issues("npm", "busy", "1.0.5", times)
        self.assertEqual([i["rule"] for i in out], ["SC-VERSION-INFLATION"])
        self.assertIn("within 24 hours", out[0]["msg"])
        self.assertNotIn("inflated —", out[0]["msg"])

    def test_a_crate_line_without_a_time_is_history(self):
        times = {"97.0.0": None, "98.0.0": None, "99.0.0": dt(1).isoformat()}
        self.assertEqual(self.issues("crates", "climber", "99.0.0", times), [])

    def test_a_normal_release_is_nothing(self):
        times = {"1.0.0": dt(1).isoformat(), "2.0.0": dt(5).isoformat(), "2.1.0": dt(9).isoformat()}
        self.assertEqual(self.issues("npm", "steady", "2.1.0", times), [])

    def test_no_history_says_nothing(self):
        # a fetch that fails (or the history off) returns {}; a first-release reading must not fire on that
        self.assertEqual(self.issues("npm", "brand-new", "99.0.0", {}), [])

    def test_an_ecosystem_without_history_is_skipped(self):
        self.assertEqual(repo.version_inflation_issues("go", "example.com/x", "99.0.0", None), [])

    def test_a_release_already_suspicious_is_not_asked(self):
        # its MAJOR adds nothing to a SUSPICIOUS verdict: no finding, and the history is not read
        strong = [{"rule": "SC-INSTALL-HOOK", "sev": "CRITICAL", "file": "package.json", "line": 1}]
        self.assertEqual(self.issues("npm", "evil", "99.0.0", {"99.0.0": dt(1).isoformat()}, found=strong), [])
        self.asked.assert_not_called()
        weak = [{"rule": "SC-B64", "sev": "MAJOR", "file": "index.js", "line": 1},
                {"rule": "SC-TRUNCATED", "sev": "CRITICAL", "file": "x", "line": 1}]
        self.assertEqual(len(self.issues("npm", "warn", "99.0.0", {"99.0.0": dt(1).isoformat()}, found=weak)), 1)


def index_line(version, pubtime=None, yanked=False):
    rec = {"name": "kit", "vers": version, "cksum": "0" * 64, "features": {}, "yanked": yanked, "deps": []}
    if pubtime is not None:
        rec["pubtime"] = pubtime
    return json.dumps(rec).encode() + b"\n"


class Served:
    """repo.module_transport over made-up answers, counting the requests."""

    def __init__(self, answers):
        self.answers, self.urls = answers, []

    def __call__(self, url, max_bytes=None, accept=None, timeout=None, check_redirect=None, **_kw):
        self.urls.append(url)
        check_redirect(url)
        if url not in self.answers:
            raise base.FetchError("HTTP 404")
        return self.answers[url]


@mock.patch.dict(os.environ, ON)
class VersionTimesTests(unittest.TestCase):
    """prior.version_times: the history RA-7 reads, extracted from each registry's document."""

    def test_npm_times_drop_created_modified_and_what_is_not_a_time(self):
        doc = {"time": {"created": "2026-09-01T00:00:00Z", "modified": "2026-10-02T00:00:00Z",
                        "1.0.0": "2026-10-01T00:00:00Z", "99.0.0": "2026-10-02T00:00:00Z", "98.0.0": "yesterday"}}
        with mock.patch.object(repo, "_fetch", return_value=json.dumps(doc).encode()):
            times = prior.version_times("npm", "pkg")
        self.assertEqual(times, {"1.0.0": "2026-10-01T00:00:00Z", "99.0.0": "2026-10-02T00:00:00Z"})

    def test_off_is_empty(self):
        with mock.patch.dict(os.environ, {prior.OFF_ENV: "1"}):
            self.assertEqual(prior.version_times("npm", "pkg"), {})

    def test_a_registry_that_does_not_answer_is_empty(self):
        with mock.patch.object(repo, "_fetch", side_effect=base.FetchError("HTTP 503")):
            self.assertEqual(prior.version_times("npm", "pkg"), {})

    def test_a_simple_api_document_of_another_shape_is_empty(self):
        for bad in ({"versions": 5, "files": []}, {"versions": [], "files": 5}, {"versions": ["1"], "files": [5]},
                    {"versions": None, "files": None}, [], "text", 5):
            with self.subTest(bad=bad), mock.patch.object(repo, "_fetch", return_value=json.dumps(bad).encode()):
                self.assertEqual(prior.version_times("pypi", "pkg"), {})
                self.assertEqual(prior._pypi_files(bad), {})

    def test_crates_lines_without_pubtime_are_kept_in_the_index_order(self):
        served = Served({INDEX + crates.index_path("kit"): index_line("1.0.0") + index_line("1.1.0")
                         + index_line("1.2.0", yanked=True) + index_line("99.0.0", "2026-10-01T00:00:00Z")})
        with mock.patch.object(repo, "module_transport", served):
            times = prior.version_times("crates", "kit")
        self.assertEqual(list(times.items()), [("1.0.0", None), ("1.1.0", None), ("99.0.0", "2026-10-01T00:00:00Z")])


@mock.patch.dict(os.environ, ON)
class HistoryTests(unittest.TestCase):
    """prior.History: the package's registry documents one release scan reads, each fetched once."""

    def test_a_document_is_fetched_once_and_a_smaller_budget_is_kept(self):
        doc = {"time": {"1.0.0": "2026-10-01T00:00:00Z"}, "versions": {}}
        raw = json.dumps(doc).encode()
        fetched = []

        def fetch(url, max_bytes=None, timeout=None, accept=None):
            fetched.append((url, max_bytes))
            return raw
        history = prior.History()
        url = "https://registry.npmjs.org/pkg"
        with mock.patch.object(repo, "_fetch", fetch), mock.patch.object(repo, "http_json", side_effect=AssertionError):
            self.assertEqual(history.json(url), doc)
            self.assertEqual(prior.version_times("npm", "pkg", history=history), {"1.0.0": "2026-10-01T00:00:00Z"})
            self.assertEqual(history.feed(url), doc)                        # (SC-NEW-DEPENDENCY's, within its budget)
            with mock.patch.object(repo, "MAX_FEED_BYTES", len(raw) - 1):
                with self.assertRaises(base.TooLarge):                      # (over its own budget, as its fetch says)
                    history.feed(url)
        self.assertEqual(fetched, [(url, prior.MAX_HISTORY_BYTES)])

    def test_a_failure_is_kept_and_too_large_is_asked_again_at_a_larger_budget(self):
        calls = []

        def fetch(url, max_bytes=None, timeout=None, accept=None):
            calls.append(max_bytes)
            if max_bytes < prior.MAX_HISTORY_BYTES:
                raise base.TooLarge("response exceeds 5MB budget")
            return b"{}"
        history = prior.History()
        url = "https://registry.npmjs.org/big"
        with mock.patch.object(repo, "_fetch", fetch), \
                mock.patch.object(repo, "http_json", side_effect=base.TooLarge("response exceeds 5MB budget")):
            with self.assertRaises(base.TooLarge):
                history.feed(url)
            self.assertEqual(history.json(url), {})                         # (asked again, at the history's budget)
        self.assertEqual(calls, [prior.MAX_HISTORY_BYTES])
        gone = prior.History()
        with mock.patch.object(repo, "_fetch", side_effect=base.FetchError("HTTP 503")) as failing:
            for _ in range(2):
                with self.assertRaises(base.FetchError):
                    gone.json(url)
        self.assertEqual(failing.call_count, 1)

    def test_a_crates_index_file_is_read_once_for_the_release(self):
        # SC-NEW-DEPENDENCY's records, SC-NEW-INDICATOR's records and its predecessor's resolution, and
        # SC-VERSION-INFLATION's: one request
        served = Served({INDEX + crates.index_path("kit"): index_line("0.9.0", "2026-09-01T00:00:00Z")
                         + index_line("1.0.0", "2026-10-01T00:00:00Z")})
        history = prior.History()
        module = repo.registry_module("crates")
        with mock.patch.object(repo, "module_transport", served):
            fetch = history.module_fetch(module)
            self.assertIs(history.module_fetch(module), fetch)
            records = module.records("kit", fetch)
            when, best, refs = prior._crates("kit", "1.0.0", None, None, history)
            times = prior.version_times("crates", "kit", history=history)
        self.assertEqual((len(records), best[0], [r["filename"] for r in refs], list(times)),
                         (2, "0.9.0", ["kit-0.9.0.crate"], ["0.9.0", "1.0.0"]))
        self.assertEqual(served.urls, [INDEX + crates.index_path("kit")])


if __name__ == "__main__":
    unittest.main()
