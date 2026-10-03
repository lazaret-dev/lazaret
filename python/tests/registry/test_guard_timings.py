"""`lazaret guard --timings` (0.1.9, P-4): where a guarded install's time goes.

The guard wraps its network requests, its scans (here or in a worker, whose own report is merged
back), and the package manager's runs in `lazaret.scanner.timings` spans; `--timings` prints the
table on stderr and `--json` carries the report. Nothing here needs a package manager, a
registry or the native engine: the scan itself is a stand-in and the server is local."""

import concurrent.futures
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

from lazaret.registry import guard, repo
from lazaret.scanner import timings
from tests.registry.test_guard import _Server, context

FAKE = {"verdict": "CLEAN", "verdictReason": "", "issues": []}


class FakePool:
    """A pool that runs the job here, as a worker would, and answers with a finished Future."""

    def __init__(self):
        self.submitted = []

    def submit(self, fn, *args):
        self.submitted.append(args)
        future = concurrent.futures.Future()
        try:
            future.set_result(fn(*args))
        except BaseException as exc:                        # noqa: BLE001 - what a worker would send back
            future.set_exception(exc)
        return future


class NetworkTests(unittest.TestCase):
    def test_a_fetch_is_a_request_and_a_read(self):
        server = _Server({"/a": (200, {}, b"x" * 1000)})
        self.addCleanup(server.close)
        f = guard.Fetcher(set())
        f.allow(server.url)
        with timings.capture() as t:
            self.assertEqual(f.get(server.url + "/a"), b"x" * 1000)
            self.assertEqual(f.get(server.url + "/a"), b"x" * 1000)
        row = t.report()["phases"]["network"]
        self.assertEqual(row["calls"], 4)
        self.assertEqual((row["by"]["request"]["calls"], row["by"]["read"]["calls"]), (2, 2))

    def test_a_failed_request_is_counted_and_still_raises(self):
        server = _Server({})
        self.addCleanup(server.close)
        f = guard.Fetcher(set())
        f.allow(server.url)
        with timings.capture() as t, self.assertRaises(repo.FetchError):
            f.get(server.url + "/missing")
        self.assertEqual(t.report()["phases"]["network"]["by"]["request"]["calls"], 1)

    def test_nothing_is_kept_without_a_capture(self):
        server = _Server({"/a": (200, {}, b"x")})
        self.addCleanup(server.close)
        f = guard.Fetcher(set())
        f.allow(server.url)
        f.get(server.url + "/a")
        self.assertIsNone(timings.current())


class ScanTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(repo, "_scan_artifact", return_value=dict(FAKE))
        self.scanned = patch.start()
        self.addCleanup(patch.stop)

    def test_a_scan_here_is_a_span(self):
        s = guard.Scanner(None, timeout=10, jobs=1)
        with timings.capture() as t:
            self.assertEqual(s.scan(b"d", "tgz", "npm")["verdict"], "CLEAN")
        self.assertEqual(t.report()["phases"]["scan"]["by"], {"artifact": {"seconds": t.report()["phases"]["scan"]["seconds"],
                                                                           "calls": 1}})

    def test_a_worker_is_asked_for_its_timings_only_when_they_are_kept(self):
        s = guard.Scanner(None, timeout=10, jobs=2)
        s._pool = FakePool()
        s.scan(b"d", "tgz", "npm")
        self.assertEqual(s._pool.submitted[-1][-1], 10)                     # (data, container, kind, timeout): no flag
        with timings.capture():
            answer = s.scan(b"d", "tgz", "npm")
        self.assertEqual(s._pool.submitted[-1][-1], True)
        self.assertNotIn("timings", answer)                                 # merged and taken out, not passed on
        self.assertEqual(set(answer), {"verdict", "reason", "indicators"})

    def test_the_workers_report_is_merged_with_the_wait(self):
        s = guard.Scanner(None, timeout=10, jobs=2)
        s._pool = FakePool()
        with timings.capture() as t:
            s.scan(b"d", "tgz", "npm")
            s.scan(b"d", "tgz", "npm")
        scan = t.report()["phases"]["scan"]["by"]
        self.assertEqual(scan["artifact"]["calls"], 2)                      # the worker's, merged
        self.assertEqual(scan["wait for worker"]["calls"], 2)               # the parent's own

    def test_scan_one_returns_its_report_only_when_asked(self):
        plain = guard._scan_one(b"d", "tgz", "npm", 10)
        self.assertEqual(set(plain), {"verdict", "reason", "indicators"})
        timed = guard._scan_one(b"d", "tgz", "npm", 10, True)
        self.assertEqual(timed["timings"]["phases"]["scan"]["by"]["artifact"]["calls"], 1)
        self.assertGreater(timed["timings"]["wall"], 0)
        self.assertIsNone(timings.current())                                # the worker's capture is closed

    def test_a_timed_scan_inside_a_capture_leaves_that_capture_alone(self):
        with timings.capture() as outer:
            guard._scan_one(b"d", "tgz", "npm", 10, True)
            self.assertIs(timings.current(), outer)
        self.assertNotIn("scan", outer.report()["phases"])                  # the worker kept its own

    def test_a_scan_that_fails_still_closes_its_span(self):
        self.scanned.side_effect = RuntimeError("boom")
        s = guard.Scanner(None, timeout=10, jobs=1)
        with timings.capture() as t, self.assertRaises(guard.ScanError):
            s.scan(b"d", "tgz", "npm")
        self.assertEqual(t.report()["phases"]["scan"]["calls"], 1)


class ToolTests(unittest.TestCase):
    def test_a_package_manager_run_is_a_span_named_for_what_it_did(self):
        with timings.capture() as t:
            guard.run_tool([sys.executable, "-c", "pass"], dict(os.environ), capture=True)
            guard.run_tool([sys.executable, "-c", "pass"], dict(os.environ))
        name = os.path.basename(sys.executable)
        by = t.report()["phases"]["tool"]["by"]
        self.assertEqual({k: v["calls"] for k, v in by.items()}, {f"{name} resolve": 1, f"{name} run": 1})

    def test_a_tool_that_cannot_run_is_still_a_guard_error(self):
        with timings.capture() as t, self.assertRaises(guard.GuardError):
            guard.run_tool(["/no/such/tool"], dict(os.environ))
        self.assertEqual(t.report()["phases"]["tool"]["calls"], 1)


class ReportTests(unittest.TestCase):
    def test_json_carries_the_timings_of_a_run_that_keeps_them(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            ctx = context(json=path)
            with timings.capture() as t, t.run():
                with timings.span("network", "request"):
                    pass
                guard.finish(ctx, installed=False, code=0)
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual(list(doc["timings"]["phases"]), ["network"])
            self.assertEqual(set(doc["timings"]), {"wall", "other", "phases"})

    def test_and_not_otherwise(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.json")
            guard.finish(context(json=path), installed=False, code=0)
            with open(path, encoding="utf-8") as f:
                self.assertNotIn("timings", json.load(f))


class CommandLine(unittest.TestCase):
    def run_main(self, argv):
        err = io.StringIO()
        with mock.patch("sys.stderr", err), mock.patch.dict(os.environ, {"LAZARET_GUARD_CACHE": os.devnull}):
            try:
                code = guard.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, err.getvalue()

    def test_the_option_is_off_by_default_and_a_flag(self):
        self.assertFalse(guard.build_parser().parse_args(["pip", "install", "x"]).timings)
        self.assertTrue(guard.build_parser().parse_args(["--timings", "pip", "install", "x"]).timings)

    def test_the_table_is_printed_on_stderr_after_the_run(self):
        def pretend(ctx, tool, args):
            with timings.span("network", "request"):
                pass
            return 0
        with mock.patch.object(guard, "guard_pip", pretend):
            code, err = self.run_main(["--timings", "pip", "install", "x"])
            quiet_code, quiet = self.run_main(["pip", "install", "x"])
        self.assertEqual((code, quiet_code), (0, 0))
        self.assertIn("timings (seconds; wall ", err)
        self.assertRegex(err, r"\n  network +\d+\.\d\d +\d* ?%?  1 call\n")
        self.assertIn("other", err.splitlines()[-1])
        self.assertNotIn("timings (seconds", quiet)
        self.assertIsNone(timings.current())

    def test_the_exit_code_is_the_runs_and_the_table_follows_a_failure_too(self):
        with mock.patch.object(guard, "guard_pip", lambda ctx, tool, args: 1):
            code, err = self.run_main(["--timings", "pip", "install", "x"])
        self.assertEqual(code, 1)
        self.assertIn("timings (seconds", err)
        with mock.patch.object(guard, "guard_pip", mock.Mock(side_effect=KeyboardInterrupt)):
            code, err = self.run_main(["--timings", "pip", "install", "x"])
        self.assertEqual(code, 130)
        self.assertIn("interrupted", err)
        self.assertIn("timings (seconds", err)

    def test_a_run_that_ends_in_a_usage_error_after_work_still_prints_its_table(self):
        def refuse_late(ctx, tool, args):
            with timings.span("tool", "pip resolve"):
                pass
            return guard.EXIT_USAGE
        with mock.patch.object(guard, "guard_pip", refuse_late):
            code, err = self.run_main(["--timings", "pip", "install", "x"])
        self.assertEqual(code, guard.EXIT_USAGE)
        self.assertIn("pip resolve", err)

    def test_a_usage_error_prints_no_table(self):
        code, err = self.run_main(["--timings", "--min-age", "soon", "npm", "install"])
        self.assertEqual(code, 2)
        self.assertNotIn("timings (seconds", err)


if __name__ == "__main__":
    unittest.main()
