"""P-4's call sites: where a registry scan's time goes (`lazaret-registry --timings`, and the guard's workers).

The engine's loader times every call by name (`_native.call_raw`: a batch is named for its first call), the
registry its network (`repo._fetch`) and its archive reading (`repo.iter_archive`, the reader's own seconds,
not the caller's between members). With no capture open, nothing is recorded. The engine is a stand-in here
except in the guard's worker test, which skips without it."""

import contextlib
import io
import os
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

from lazaret.registry import guard, repo
from lazaret.scanner import _native, timings
from tests import _support


def tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo("package/" + name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def captured(fn):
    """Run fn() under a capture: -> (its result, the report)."""
    t = timings.Timings()
    with timings.capture(t), t.run():
        out = fn()
    return out, t.report()


class EngineCallTests(unittest.TestCase):
    def setUp(self):
        self.calls = []

        def fake(lib, name, args, text):
            self.calls.append(name)
            time.sleep(0.002)
            return _native.STATUS_OK, "null"

        patches = [mock.patch.object(_native, "_load", lambda: object()), mock.patch.object(_native, "_call_lib", fake)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def test_each_call_is_a_span_named_for_it(self):
        def work():
            _native.call("cross_file", {}, "x")
            _native.call("batch", {"calls": [["scan_file", {}, "a"], ["scan_file", {}, "b"]]})
            _native.call("batch", {"calls": [["import_time_risk", {}, "a"]]})
            _native.call("batch", {"calls": [["import_time_risk", {}, "b"]]})
        _, report = captured(work)
        engine = report["phases"]["engine"]
        self.assertEqual({n: s["calls"] for n, s in engine["by"].items()},
                         {"cross_file": 1, "batch:scan_file": 1, "batch:import_time_risk": 2})
        self.assertGreater(engine["seconds"], 0.006)
        self.assertEqual(self.calls, ["cross_file", "batch", "batch", "batch"])

    def test_span_names(self):
        self.assertEqual(_native.span_name("batch", {"calls": []}), "batch")
        self.assertEqual(_native.span_name("batch", {"calls": [[7]]}), "batch")
        self.assertEqual(_native.span_name("batch", None), "batch")
        self.assertEqual(_native.span_name("scan_file", {"calls": [["x"]]}), "scan_file")

    def test_nothing_is_recorded_without_a_capture(self):
        self.assertIsNone(timings.current())
        self.assertIsNone(_native.call("cross_file", {}, "x"))        # still answers
        self.assertIs(timings.span("engine", "x"), timings.span("network"))   # the shared no-op span


@mock.patch.dict(os.environ, _support.PYTHON_TRANSPORT)
class RegistryTests(unittest.TestCase):
    def test_a_fetch_is_the_network(self):
        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        opener = mock.Mock()
        opener.open.side_effect = lambda req, timeout=None: Response(b'{"ok": true}')
        with mock.patch.object(repo, "_OPENER", opener):
            data, report = captured(lambda: repo._fetch("https://registry.npmjs.org/left-pad"))
        self.assertEqual(data, b'{"ok": true}')
        self.assertEqual(report["phases"]["network"]["by"]["fetch"]["calls"], 1)

    def test_a_failed_fetch_is_timed_and_still_raises(self):
        def refuse(req, timeout=None):
            raise OSError("connection refused")
        opener = mock.Mock()
        opener.open.side_effect = refuse
        t = timings.Timings()
        with mock.patch.object(repo, "_OPENER", opener), timings.capture(t), t.run():
            with self.assertRaises(repo.FetchError):
                repo._fetch("https://registry.npmjs.org/left-pad")
        self.assertEqual(t.report()["phases"]["network"]["calls"], 1)

    def test_archive_reading_is_the_readers_time_not_the_callers(self):
        data = tgz({"package.json": b'{"name": "x"}', "index.js": b"module.exports = 1;\n", "lib/a.js": b"x\n"})

        def read_slowly():
            names = []
            for m in repo.iter_archive(data, "tgz", "npm"):
                names.append(m[0])
                time.sleep(0.05)                      # the caller's time between members
            return names
        names, report = captured(read_slowly)
        self.assertEqual(sorted(names), ["index.js", "lib/a.js", "package.json"])
        archive = report["phases"]["archive"]
        self.assertEqual(list(archive["by"]), ["iter_archive"])
        self.assertLess(archive["seconds"], 0.1)      # not the 0.15 s the caller slept

    def test_a_reader_left_early_is_closed(self):
        closed = []

        def members(*a):
            try:
                yield repo.Member("a.js", 1, b"x", None, None)
                yield repo.Member("b.js", 1, b"y", None, None)
            finally:
                closed.append(True)
        with mock.patch.object(repo, "_iter_tar", members):
            gen = repo.iter_archive(b"", "tgz", "npm")
            self.assertEqual(next(gen)[0], "a.js")
            gen.close()
        self.assertEqual(closed, [True])

    def test_the_command_line_prints_the_table(self):
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "state.db")
            for argv, wanted in ((["list", "--timings"], True), (["list"], False)):
                with self.subTest(argv=argv), mock.patch.object(sys, "argv", ["lazaret-registry", "--db", db] + argv), \
                        mock.patch.object(repo._engine, "require", lambda: None), \
                        contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                    repo.main()
                self.assertIn("no tracked packages", out.getvalue())
                self.assertEqual("timings (seconds; wall" in err.getvalue(), wanted, err.getvalue())


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class GuardWorkerTests(unittest.TestCase):
    def test_a_workers_report_splits_engine_archive_and_scan(self):
        data = tgz({"package.json": b'{"name": "x", "version": "1.0.0", "main": "index.js"}',
                    "index.js": b"module.exports = (a, b) => a + b;\n"})
        answer = guard._scan_one(data, "tgz", "npm", 60, timed=True)
        phases = answer["timings"]["phases"]
        self.assertTrue({"engine", "archive", "scan"} <= set(phases), phases)
        self.assertTrue(any(name.startswith("batch:") for name in phases["engine"]["by"]), phases["engine"])
        self.assertEqual(answer["verdict"], "OK")


class ProfileScriptsTests(unittest.TestCase):
    def test_the_profile_scripts_do_not_time_the_engine_twice(self):
        from tests import _support
        common = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "profile", "_common.py"),
                                      "profile_common_for_p4")
        real = _native.call_raw
        with common.engine_spans(_native, timings):
            self.assertIs(_native.call_raw, real)          # the loader's own spans are used
        self.assertIs(_native.call_raw, real)


if __name__ == "__main__":
    unittest.main()
