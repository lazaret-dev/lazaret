"""How `guard.Scanner` uses its scan workers (0.1.9, P-7): `--no-isolate`, `--worker-memory`, and what each way a worker
can fail means for the package. The workers themselves are tested in `test_scanpool`; here a stand-in pool says what
happened, and one real worker scans a real archive to show it gives the answer a scan in this process gives."""

import argparse
import io
import unittest
from unittest import mock

from lazaret.registry import guard, repo, scanpool
from lazaret.scanner import engine
from tests.registry._review_support import tarball
from tests.registry.test_guard import context, options


class Workers:
    """A `scanpool.WorkerPool` that answers, or raises, what it is told."""

    def __init__(self, outcome=None):
        self.outcome, self.calls, self.closed = outcome, [], 0

    def run(self, data, container, kind, timeout, timed=False):
        self.calls.append((data, container, kind, timeout, timed))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome if self.outcome is not None else {"verdict": "OK", "reason": "", "indicators": []}

    def close(self):
        self.closed += 1


class WhichWayTests(unittest.TestCase):
    def test_workers_for_which_jobs_and_isolate(self):
        for jobs, isolate, workers in ((1, None, False), (2, None, True), (4, None, True), (1, True, True),
                                       (1, False, False), (4, False, False)):
            with self.subTest(jobs=jobs, isolate=isolate):
                s = guard.Scanner(None, timeout=10, jobs=jobs, isolate=isolate)
                self.addCleanup(s.close)
                pool = s._get_pool()
                self.assertEqual(isinstance(pool, scanpool.WorkerPool), workers)
                self.assertEqual(s.isolate, workers)
                if workers:
                    self.assertEqual((pool.jobs, pool.fn, pool.memory_bytes), (jobs, guard._scan_one,
                                                                               scanpool.DEFAULT_MEMORY_MB * 1024 * 1024))

    def test_the_memory_limit_is_handed_to_the_workers(self):
        s = guard.Scanner(None, timeout=10, jobs=1, isolate=True, memory_mb=321)
        self.addCleanup(s.close)
        self.assertEqual(s._get_pool().memory_bytes, 321 * 1024 * 1024)

    def test_the_defaults(self):
        s = guard.Scanner(None)
        self.assertEqual((s.jobs, s.isolate, s.timeout, s.memory_mb), (1, False, repo.SCAN_TIMEOUT,
                                                                        scanpool.DEFAULT_MEMORY_MB))

    def test_the_pool_is_made_once_and_only_when_a_scan_needs_it(self):
        s = guard.Scanner(None, timeout=10, jobs=2)
        self.assertIsNone(s._pool)                                           # (a run that scans nothing starts nothing)
        self.assertIs(s._get_pool(), s._get_pool())
        s.close()
        self.assertIsNone(s._pool)
        s.close()                                                            # twice is harmless

    def test_a_scan_with_no_isolation_goes_through_this_process_whatever_the_jobs(self):
        s = guard.Scanner(None, timeout=10, jobs=4, isolate=False)
        with mock.patch.object(guard, "_scan_one", return_value={"verdict": "OK", "reason": "", "indicators": []}) as one:
            s.scan(b"data", "tgz", "npm")
        one.assert_called_once_with(b"data", "tgz", "npm", 10)


class FailureTests(unittest.TestCase):
    def scanner(self, outcome):
        s = guard.Scanner(None, timeout=10, jobs=2)
        s._pool = Workers(outcome)
        return s

    def test_the_answer_is_what_the_worker_gave(self):
        answer = {"verdict": "WARN", "reason": "r", "indicators": ["i"]}
        self.assertEqual(self.scanner(answer).scan(b"d", "tgz", "npm"), answer)

    def test_a_lost_worker_is_a_scan_error_with_the_pool_s_words(self):
        with self.assertRaisesRegex(guard.ScanError, "^the scan worker was lost on this archive"):
            self.scanner(scanpool.Died("the scan worker was lost on this archive, also when it ran alone")).scan(
                b"d", "tgz", "npm")

    def test_a_scan_that_hung_is_the_old_message(self):
        with self.assertRaisesRegex(guard.ScanError, "^the scan did not finish$"):
            self.scanner(scanpool.Hung("x")).scan(b"d", "tgz", "npm")

    def test_other_failures_name_their_type_and_nothing_else(self):
        for exc in (ValueError("a path /secret"), MemoryError(), scanpool.ArchiveChanged("x")):
            with self.subTest(type(exc).__name__), self.assertRaisesRegex(
                    guard.ScanError, rf"^the scan failed \({type(exc).__name__}\)$"):
                self.scanner(exc).scan(b"d", "tgz", "npm")

    def test_a_package_whose_scan_fails_is_blocked_as_not_checked(self):
        ctx = context(jobs=2)
        ctx.scanner._pool = Workers(scanpool.Died("the scan worker was lost on this archive"))
        check = guard.Check("npm", "p", "1.0.0", "p-1.0.0.tgz")
        try:
            ctx.scanner.scan(b"d", "tgz", "npm")
        except guard.ScanError as exc:
            ctx.not_checked(check, exc)
        self.assertEqual(check.blocked, ["could not be checked: the scan worker was lost on this archive"])

    def test_workers_that_cannot_start_mean_a_scan_here_and_a_line_about_it_once(self):
        said = []
        s = guard.Scanner(None, timeout=10, jobs=2, note=said.append)
        pool = s._pool = Workers(scanpool.Unavailable("OSError: no processes"))
        with mock.patch.object(guard, "_scan_one", return_value={"verdict": "OK", "reason": "", "indicators": []}) as one:
            for _ in range(3):
                self.assertEqual(s.scan(b"d", "tgz", "npm")["verdict"], "OK")
        self.assertEqual(len(pool.calls), 1)                                 # (asked once, then not again)
        self.assertEqual(one.call_count, 3)
        self.assertEqual(pool.closed, 1)
        self.assertEqual(said, ["lazaret guard: no scan worker could be started; scanning in this process"])
        self.assertIsNone(s._pool)

    def test_the_line_is_said_once_however_often_the_fall_back_is_asked_for(self):
        said = []
        s = guard.Scanner(None, timeout=10, jobs=2, note=said.append)
        s._get_pool()
        for _ in range(3):                                                   # (several threads found it at once)
            s._scan_here()
        self.assertEqual(len(said), 1)
        self.assertIsNone(s._pool)

    def test_no_note_function_is_fine(self):
        s = guard.Scanner(None, timeout=10, jobs=2)
        s._pool = Workers(scanpool.Unavailable("x"))
        with mock.patch.object(guard, "_scan_one", return_value={"verdict": "OK", "reason": "", "indicators": []}):
            self.assertEqual(s.scan(b"d", "tgz", "npm")["verdict"], "OK")

    def test_the_line_goes_to_the_run_s_output(self):
        ctx = context(jobs=2)
        ctx.scanner._pool = Workers(scanpool.Unavailable("x"))
        with mock.patch.object(guard, "_scan_one", return_value={"verdict": "OK", "reason": "", "indicators": []}):
            ctx.scanner.scan(b"d", "tgz", "npm")
        self.assertEqual(ctx.out.getvalue(), "lazaret guard: no scan worker could be started; scanning in this process\n")

    def test_close_closes_the_workers(self):
        s = self.scanner(None)
        pool = s._pool
        s.close()
        self.assertEqual(pool.closed, 1)


class OptionTests(unittest.TestCase):
    def test_the_parser(self):
        base = guard.build_parser().parse_args(["pip", "install", "x"])
        self.assertEqual((base.isolate, base.worker_memory), (True, scanpool.DEFAULT_MEMORY_MB))
        opts = guard.build_parser().parse_args(["--no-isolate", "--worker-memory", "512", "pip", "install", "x"])
        self.assertEqual((opts.isolate, opts.worker_memory), (False, 512))

    def test_the_context_passes_them_on(self):
        ctx = context(isolate=False, worker_memory=123, jobs=4)
        self.assertEqual((ctx.scanner.isolate, ctx.scanner.memory_mb), (False, 123))
        ctx = context(isolate=True, jobs=1)
        self.assertEqual((ctx.scanner.isolate, ctx.scanner.memory_mb), (True, scanpool.DEFAULT_MEMORY_MB))
        ctx = context(jobs=1)                                                # (an options object that predates them)
        self.assertEqual(ctx.scanner.isolate, False)
        self.assertEqual(context(jobs=3).scanner.isolate, True)

    def test_a_negative_limit_is_a_usage_error(self):
        err = io.StringIO()
        with mock.patch("sys.stderr", err):
            code = guard.main(["--worker-memory", "-1", "pip", "install", "x"])
        self.assertEqual(code, guard.EXIT_USAGE)
        self.assertIn("--worker-memory", err.getvalue())

    def test_no_limit_is_a_limit_of_zero(self):
        for value, refused in (("0", False), ("-1", True), ("1", False)):
            with self.subTest(value):
                err = io.StringIO()
                with mock.patch("sys.stderr", err):
                    guard.main(["--worker-memory", value, "pip"])               # (no command: refused further on)
                self.assertEqual("--worker-memory" in err.getvalue(), refused, err.getvalue())

    def test_the_options_are_in_the_help(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out), self.assertRaises(SystemExit):
            guard.build_parser().parse_args(["--help"])
        for name in ("--no-isolate", "--worker-memory"):
            self.assertIn(name, out.getvalue())


@unittest.skipUnless(engine.available(), "the scan needs the native engine")
class RealWorkerTests(unittest.TestCase):
    def test_a_worker_gives_the_answer_a_scan_here_gives(self):
        data = tarball({"package.json": '{"name": "tiny", "version": "1.0.0"}',
                        "index.js": "module.exports = 1;\n"})
        here = guard.Scanner(None, timeout=60, jobs=1, isolate=False)
        isolated = guard.Scanner(None, timeout=60, jobs=1, isolate=True)
        self.addCleanup(isolated.close)
        want = here.scan(data, "tgz", "npm")
        self.assertEqual(isolated.scan(data, "tgz", "npm"), want)
        self.assertEqual(isolated.scan(data, "tgz", "npm"), want)            # (the second one in the same worker)
        self.assertIsInstance(isolated._pool, scanpool.WorkerPool)


if __name__ == "__main__":
    unittest.main()
