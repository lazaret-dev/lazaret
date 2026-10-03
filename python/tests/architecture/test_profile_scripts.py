"""scripts/profile (0.1.9, P-10): the scheduled performance check, and the profile scripts around it.

`perf_check.py` fetches archives by pinned sha256, times the engine's calls on them, judges the seconds against
budgets and calibrates budgets from reports. Nothing here needs the registries: archives come from a local
server, and the scan is a stand-in that adds engine seconds to `lazaret.scanner.timings` (one test runs the
real engine on a tiny tarball, and skips without it). The workflow file that runs it is checked for the rules
of ci.yml: actions at commit SHAs, `contents: read`, no secrets, no caches."""

import ast
import hashlib
import http.server
import io
import json
import os
import re
import shlex
import socketserver
import sys
import tarfile
import tempfile
import threading
import types
import unittest
from unittest import mock

from tests import _support

PROFILE = os.path.join(_support.REPO_ROOT, "scripts", "profile")
WORKFLOW = os.path.join(_support.REPO_ROOT, ".github", "workflows", "perf.yml")


def load(name):
    if PROFILE not in sys.path:
        sys.path.insert(0, PROFILE)
    return _support.load_script(os.path.join(PROFILE, name + ".py"), "profile_" + name)


perf = load("perf_check")
common = load("_common")


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Server:
    """Serves `files` ({path: bytes}) over http on loopback and counts the requests for each path."""

    def __init__(self, files):
        outer = self
        self.hits = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.hits[self.path] = outer.hits.get(self.path, 0) + 1
                body = files.get(self.path)
                if body is None:
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class Plain(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.server = Plain(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, args=(0.01,), daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def entry(data, name="a.tgz", url="https://example.com/a.tgz", **kw):
    return {"url": url, "filename": name, "sha256": sha(data), "container": "tgz", "artifact": "npm", **kw}


def package(pid="npm:a@1", files=None, budget=None, **kw):
    pkg = {"id": pid, "files": [entry(b"a")] if files is None else files, "budget": {"engine_s": budget}}
    pkg.update(kw)
    return pkg


def config(*packages):
    return {"version": 1, "packages": list(packages)}


class PackagesFileTests(unittest.TestCase):
    def test_the_shipped_file_is_valid_and_pins_the_profiles_packages(self):
        cfg = perf.load_packages()
        ids = [p["id"] for p in cfg["packages"]]
        self.assertEqual(sorted(ids), sorted(["npm:eslint@10.12.0", "npm:express@5.2.1", "npm:next@16.3.8",
                                              "npm:playwright-core@1.63.0", "npm:typescript@7.0.2",
                                              "pypi:botocore@1.43.108", "pypi:litellm@1.103.2",
                                              "pypi:requests@2.34.2"]))
        for p in cfg["packages"]:
            for f in p["files"]:
                self.assertTrue(f["url"].startswith("https://"), f["url"])
                self.assertRegex(f["sha256"], r"^[0-9a-f]{64}$")

    def test_each_package_is_every_archive_a_scan_reads(self):
        by_id = {p["id"]: p for p in perf.load_packages()["packages"]}
        self.assertEqual(len(by_id["pypi:litellm@1.103.2"]["files"]), 8)              # the sdist and seven wheels
        self.assertEqual({f["artifact"] for f in by_id["pypi:requests@2.34.2"]["files"]}, {"sdist", "wheel"})
        self.assertEqual({f["artifact"] for f in by_id["npm:next@16.3.8"]["files"]}, {"npm"})

    def test_what_is_refused(self):
        good = config(package())
        self.assertIs(perf.validate(good), good)
        bad = {
            "a wrong version": {"version": 2, "packages": good["packages"]},
            "no packages": {"version": 1, "packages": []},
            "not an object": [],
            "an id used twice": config(package(), package()),
            "an empty id": config(package(pid="")),
            "no files": config(package(files=[])),
            "a short digest": config(package(files=[{**entry(b"a"), "sha256": "ab"}])),
            "an upper-case digest": config(package(files=[{**entry(b"a"), "sha256": sha(b"a").upper()}])),
            "a plain http url": config(package(files=[entry(b"a", url="http://example.com/a.tgz")])),
            "a file url": config(package(files=[entry(b"a", url="file:///etc/passwd")])),
            "an unknown container": config(package(files=[{**entry(b"a"), "container": "rar"}])),
            "an unknown artifact": config(package(files=[{**entry(b"a"), "artifact": "egg"}])),
            "no filename": config(package(files=[{k: v for k, v in entry(b"a").items() if k != "filename"}])),
            "a true budget": config(package(budget=True)),
            "a zero budget": config(package(budget=0)),
            "a text budget": config(package(budget="2")),
        }
        for what, cfg in bad.items():
            with self.subTest(what), self.assertRaises(perf.ConfigError):
                perf.validate(cfg)
        for ok in (config(package(budget=2)), config(package(budget=0.5)), config(package(budget=None)),
                   config(package(files=[entry(b"a", url=f"http://127.0.0.1:1/a")]))):
            perf.validate(ok)

    def test_select(self):
        cfg = config(package("npm:a@1"), package("npm:b@1"))
        self.assertEqual([p["id"] for p in perf.select(cfg)], ["npm:a@1", "npm:b@1"])
        self.assertEqual([p["id"] for p in perf.select(cfg, ["npm:b@1"])], ["npm:b@1"])
        with self.assertRaisesRegex(perf.ConfigError, "npm:c@1"):
            perf.select(cfg, ["npm:b@1", "npm:c@1"])

    def test_loading_and_saving(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "p.json")
            perf.save_packages(config(package(budget=1.5)), path)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            self.assertTrue(text.endswith("}\n"))
            self.assertEqual(perf.load_packages(path)["packages"][0]["budget"], {"engine_s": 1.5})
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with self.assertRaises(perf.ConfigError):
                perf.load_packages(path)
            with self.assertRaises(perf.ConfigError):
                perf.load_packages(os.path.join(d, "missing.json"))


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.data = os.urandom(5000)
        self.server = Server({"/a.tgz": self.data, "/other.tgz": b"not the pinned bytes"})
        self.addCleanup(self.server.close)
        self.cache = tempfile.mkdtemp(prefix="lazaret-perf-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.cache, ignore_errors=True))

    def pinned(self, path="/a.tgz", data=None):
        return entry(self.data if data is None else data, url=self.server.url + path)

    def test_a_file_is_fetched_hashed_and_kept_under_its_hash(self):
        e = self.pinned()
        path = perf.fetch_file(e, self.cache)
        self.assertEqual(path, os.path.join(self.cache, e["sha256"]))
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), self.data)
        self.assertEqual(os.listdir(self.cache), [e["sha256"]])                       # no .part left behind

    def test_a_cached_file_is_not_fetched_again(self):
        e = self.pinned()
        perf.fetch_file(e, self.cache)
        perf.fetch_file(e, self.cache)
        self.assertEqual(self.server.hits["/a.tgz"], 1)

    def test_a_cached_file_that_is_not_the_pinned_bytes_is_fetched_again(self):
        e = self.pinned()
        with open(os.path.join(self.cache, e["sha256"]), "wb") as fh:
            fh.write(b"swapped")
        path = perf.fetch_file(e, self.cache)
        with open(path, "rb") as fh:
            self.assertEqual(fh.read(), self.data)
        self.assertEqual(self.server.hits["/a.tgz"], 1)

    def test_bytes_that_are_not_the_pinned_ones_are_refused_and_not_kept(self):
        e = self.pinned("/other.tgz", self.data)
        with self.assertRaisesRegex(perf.PinError, "not the pinned ones"):
            perf.fetch_file(e, self.cache)
        self.assertEqual(os.listdir(self.cache), [])

    def test_a_missing_file_a_dead_server_and_a_big_download(self):
        with self.assertRaisesRegex(perf.PinError, "404"):
            perf.fetch_file(self.pinned("/nothing.tgz"), self.cache)
        dead = Server({})
        url = dead.url
        dead.close()
        with self.assertRaises(perf.PinError):
            perf.fetch_file(entry(b"x", url=url + "/a.tgz"), self.cache)
        with mock.patch.object(perf, "MAX_FILE_BYTES", 1000), self.assertRaisesRegex(perf.PinError, "MiB"):
            perf.fetch_file(self.pinned(), self.cache)
        self.assertEqual(os.listdir(self.cache), [])

    def test_only_https_is_fetched_and_nothing_is_asked_for_otherwise(self):
        opener = mock.Mock()
        with self.assertRaisesRegex(perf.PinError, "https"):
            perf.fetch_file(entry(b"x", url="http://example.com/a.tgz"), self.cache, opener)
        with self.assertRaises(perf.PinError):
            perf.fetch_file(entry(b"x", url="ftp://example.com/a.tgz"), self.cache, opener)
        opener.assert_not_called()

    def test_one_file_in_two_packages_is_fetched_once(self):
        e = self.pinned()
        said = []
        paths = perf.fetch_all([package("npm:a@1", [e]), package("npm:b@1", [dict(e)])], self.cache, progress=said.append)
        self.assertEqual(list(paths), [e["sha256"]])
        self.assertEqual(self.server.hits["/a.tgz"], 1)
        self.assertEqual(len(said), 1)


class FakeScan:
    """A stand-in for the registry's scan: it adds engine seconds the way `engine_spans` would, and notes its calls."""

    def __init__(self, seconds, files_scanned=10, verdict="OK"):
        from lazaret.scanner import timings
        self.timings, self.seconds = timings, list(seconds)
        self.files_scanned, self.verdict, self.calls = files_scanned, verdict, []

    def __call__(self, data, container, artifact):
        self.calls.append((data, container, artifact))
        if self.timings.current() is not None:
            self.timings.add("engine", self.seconds[(len(self.calls) - 1) % len(self.seconds)], "scan_file")
        return {"filesScanned": self.files_scanned, "verdict": self.verdict}


class MeasureTests(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.mkdtemp(prefix="lazaret-perf-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.cache, ignore_errors=True))

    def put(self, data):
        with open(os.path.join(self.cache, sha(data)), "wb") as fh:
            fh.write(data)
        return entry(data, name=sha(data)[:6] + ".tgz")

    def test_the_median_the_spread_and_the_counts(self):
        pkg = package(files=[self.put(b"one"), self.put(b"two!")])
        scan = FakeScan([1.0, 1.0, 3.0, 3.0, 2.0, 2.0])
        got = perf.measure(pkg, self.cache, 3, scan)
        self.assertEqual([r["engine_s"] for r in got["runs"]], [2.0, 6.0, 4.0])
        self.assertEqual((got["engine_s"], got["files"], got["bytes"], got["files_scanned"]), (4.0, 2, 7, 20))
        self.assertAlmostEqual(got["spread"], (6.0 - 2.0) / 4.0)
        self.assertEqual(got["runs"][0]["engine_calls"], 2)
        self.assertEqual(got["verdicts"], ["OK", "OK"])
        self.assertGreaterEqual(got["wall_s"], 0.0)

    def test_the_scan_gets_the_pinned_bytes_container_and_kind(self):
        e = {**self.put(b"payload"), "container": "zip", "artifact": "wheel"}
        scan = FakeScan([0.1])
        perf.measure(package(files=[e]), self.cache, 2, scan)
        self.assertEqual(scan.calls, [(b"payload", "zip", "wheel")] * 2)

    def test_nothing_engine_shaped_is_zero_and_not_a_division_by_zero(self):
        scan = lambda data, container, artifact: {"filesScanned": 3, "verdict": "OK"}      # noqa: E731
        got = perf.measure(package(files=[self.put(b"x")]), self.cache, 2, scan)
        self.assertEqual((got["engine_s"], got["spread"]), (0.0, 0.0))

    def test_a_scan_that_fails_stops_the_run_and_closes_the_capture(self):
        from lazaret.scanner import timings

        def boom(data, container, artifact):
            raise RuntimeError("scan failed")
        with self.assertRaises(RuntimeError):
            perf.measure(package(files=[self.put(b"x")]), self.cache, 2, boom)
        self.assertIsNone(timings.current())

    def test_judging(self):
        base = {"engine_s": 2.0, "files_scanned": 10}
        self.assertEqual(perf.judge(package(), dict(base))["status"], "uncalibrated")
        self.assertEqual(perf.judge(package(budget=2.0), dict(base))["status"], "ok")             # at the budget is within it
        self.assertEqual(perf.judge(package(budget=1.99), dict(base))["status"], "over")
        r = perf.judge(package(budget=4.0), dict(base))
        self.assertEqual((r["budget_s"], r["ratio"], r["work_changed"]), (4.0, 0.5, False))
        self.assertIsNone(perf.judge(package(), dict(base))["ratio"])
        same = perf.judge(package(budget=4.0, expect={"files_scanned": 10}), dict(base))
        self.assertFalse(same["work_changed"])
        more = perf.judge(package(budget=4.0, expect={"files_scanned": 11}), dict(base))
        self.assertTrue(more["work_changed"])

    def test_the_smallest_archive_is_scanned_once_first_and_unmeasured(self):
        small, big = self.put(b"s"), self.put(b"b" * 50)
        small["bytes"], big["bytes"] = 1, 50
        cfg = config(package("npm:big@1", [big]), package("npm:small@1", [small]))
        scan = FakeScan([1.0])
        report = perf.run_check(cfg, self.cache, 2, scan)
        self.assertEqual([c[0] for c in scan.calls], [b"s", b"b" * 50, b"b" * 50, b"s", b"s"])      # warm-up, then 2 + 2
        self.assertEqual([p["id"] for p in report["packages"]], ["npm:big@1", "npm:small@1"])
        self.assertEqual([p["engine_s"] for p in report["packages"]], [1.0, 1.0])                  # (the warm-up is not in them)
        self.assertEqual(report["runs"], 2)
        self.assertEqual(report["schema"], 1)
        self.assertRegex(report["when"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_only_names_the_packages_run(self):
        a, b = self.put(b"a"), self.put(b"bb")
        cfg = config(package("npm:a@1", [a]), package("npm:b@1", [b]))
        report = perf.run_check(cfg, self.cache, 1, FakeScan([0.1]), only=["npm:b@1"])
        self.assertEqual([p["id"] for p in report["packages"]], ["npm:b@1"])

    def test_over_budget(self):
        report = {"packages": [{"id": "a", "status": "ok"}, {"id": "b", "status": "over"}, {"id": "c", "status": "uncalibrated"}]}
        self.assertEqual(perf.over_budget(report), ["b"])


class ReportTests(unittest.TestCase):
    def report(self, **rows):
        packages = []
        for pid, seconds in rows.items():
            packages.append({"id": pid, "engine_s": seconds, "files_scanned": 7, "wall_s": seconds * 1.5, "spread": 0.1,
                             "bytes": 2_500_000, "budget_s": None, "status": "uncalibrated", "work_changed": False})
        return {"schema": 1, "runs": 3, "cpus": 4, "python": "3.13.1", "platform": "linux", "packages": packages}

    def test_the_table(self):
        rep = self.report(a=2.0)
        text = perf.render_table(rep)
        self.assertIn("| a | 7 | 2.5 | 2.00 | 3.00 | 10% | - | uncalibrated |", text)
        self.assertIn("Median of 3 runs per package; 4 CPUs; Python 3.13.1 on linux", text)
        self.assertIn("uncalibrated have no budget", text)
        rep["packages"][0].update(budget_s=2.5, status="ok", work_changed=True)
        text = perf.render_table(rep)
        self.assertIn("| 2.5 | ok (work changed) |", text)
        self.assertNotIn("uncalibrated have no budget", text)
        self.assertTrue(text.endswith("\n"))

    def test_calibration_is_the_median_of_the_medians_plus_the_margin_rounded_up(self):
        got = perf.calibrate([self.report(big=10.0), self.report(big=12.0), self.report(big=11.0)], 0.25)
        self.assertEqual(got["big"]["median"], 11.0)
        self.assertEqual(got["big"]["engine_s"], 13.8)                  # 11 * 1.25 = 13.75, up to a tenth
        self.assertEqual((got["big"]["reports"], got["big"]["files_scanned"]), (3, 7))
        self.assertEqual(perf.calibrate([self.report(x=10.0)], 0.5)["x"]["engine_s"], 15.0)         # exact: not pushed up
        self.assertEqual(perf.calibrate([self.report(x=10.0)], 0.0)["x"]["engine_s"], 10.3)         # the slack floor wins

    def test_a_tiny_package_gets_at_least_the_slack_above_its_median(self):
        got = perf.calibrate([self.report(tiny=0.1)], 0.25)["tiny"]["engine_s"]
        self.assertEqual(got, 0.4)                                      # 0.1 + 0.25 = 0.35, up to 0.4
        self.assertEqual(perf.calibrate([self.report(zero=0.0)], 0.25)["zero"]["engine_s"], 0.3)

    def test_packages_are_calibrated_separately_across_reports(self):
        got = perf.calibrate([self.report(a=1.0, b=2.0), self.report(a=3.0)], 0.0)
        self.assertEqual((got["a"]["reports"], got["b"]["reports"]), (2, 1))
        self.assertEqual(got["a"]["median"], 2.0)

    def test_apply_budgets_writes_the_budget_and_what_the_scan_read(self):
        cfg = config(package("a", budget=None, expect={"files_scanned": 1, "note": "kept"}), package("b", budget=9.0))
        changed = perf.apply_budgets(cfg, {"a": {"engine_s": 2.5, "files_scanned": 7}})
        self.assertEqual(changed, ["a"])
        self.assertEqual(cfg["packages"][0]["budget"], {"engine_s": 2.5})
        self.assertEqual(cfg["packages"][0]["expect"], {"files_scanned": 7, "note": "kept"})
        self.assertEqual(cfg["packages"][1]["budget"], {"engine_s": 9.0})
        self.assertNotIn("expect", cfg["packages"][1])


class PinTests(unittest.TestCase):
    class Resolution(tuple):
        artifacts = [{"url": "https://files.example/x-1.0.tar.gz", "container": "tgz", "artifact": "sdist"},
                     {"url": "https://files.example/x-1.0-py3-none-any.whl", "container": "zip", "artifact": "wheel",
                      "filename": "x-1.0-py3-none-any.whl"}]

    def test_a_pypi_release_is_every_artifact_resolved_and_hashed(self):
        blobs = {"https://files.example/x-1.0.tar.gz": b"sdist", "https://files.example/x-1.0-py3-none-any.whl": b"wheel!"}
        cfg = config()
        said = []
        ids = perf.pin(["pypi:x"], cfg, lambda eco, name, version: self.Resolution(("1.0",)), blobs.__getitem__, said.append)
        self.assertEqual(ids, ["pypi:x@1.0"])
        pkg = cfg["packages"][0]
        self.assertEqual((pkg["id"], pkg["ecosystem"], pkg["name"], pkg["version"]), ("pypi:x@1.0", "pypi", "x", "1.0"))
        self.assertEqual(pkg["budget"], {"engine_s": None})
        sdist, wheel = pkg["files"]
        self.assertEqual((sdist["filename"], sdist["sha256"], sdist["bytes"], sdist["artifact"]), ("x-1.0.tar.gz", sha(b"sdist"), 5, "sdist"))
        self.assertEqual((wheel["filename"], wheel["container"], wheel["bytes"]), ("x-1.0-py3-none-any.whl", "zip", 6))
        self.assertEqual(len(said), 2)
        perf.validate(cfg)

    def test_an_npm_release_is_its_one_tarball(self):
        calls = []

        def resolve(eco, name, version):
            calls.append((eco, name, version))
            return ("2.0.0", "https://registry.example/y/-/y-2.0.0.tgz", "tgz", "npm", {})
        cfg = config()
        perf.pin(["npm:y@2.0.0"], cfg, resolve, lambda url: b"tarball")
        self.assertEqual(calls, [("npm", "y", "2.0.0")])
        f = cfg["packages"][0]["files"][0]
        self.assertEqual((f["filename"], f["container"], f["artifact"]), ("y-2.0.0.tgz", "tgz", "npm"))
        perf.validate(cfg)

    def test_a_package_already_there_keeps_its_budget_and_expectations(self):
        old = package("npm:y@2.0.0", [entry(b"old")], budget=3.5, expect={"files_scanned": 9})
        cfg = config(old)
        perf.pin(["npm:y@2.0.0"], cfg, lambda *a: ("2.0.0", "https://r.example/y.tgz", "tgz", "npm", {}), lambda url: b"new")
        self.assertEqual(len(cfg["packages"]), 1)
        pkg = cfg["packages"][0]
        self.assertEqual((pkg["budget"], pkg["expect"]), ({"engine_s": 3.5}, {"files_scanned": 9}))
        self.assertEqual(pkg["files"][0]["sha256"], sha(b"new"))

    def test_a_scoped_name_and_a_bad_spec(self):
        self.assertEqual(common.split_spec("npm:@babel/core@7.0.0"), ("npm", "@babel/core", "7.0.0"))
        self.assertEqual(common.split_spec("npm:@babel/core"), ("npm", "@babel/core", None))
        self.assertEqual(common.split_spec("pypi:requests"), ("pypi", "requests", None))
        for bad in ("requests", "gem:x", "npm:", "npm:@", ":x"):
            with self.subTest(bad), self.assertRaises(ValueError):
                common.split_spec(bad)


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="lazaret-perf-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        self.err = io.StringIO()

    def main(self, *argv):
        out = io.StringIO()
        with mock.patch("sys.stderr", self.err), mock.patch("sys.stdout", out):
            code = perf.main(list(argv))
        return code, out.getvalue()

    def write(self, name, obj):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return path

    def test_calibrate_prints_and_writes(self):
        packages = self.write("p.json", config(package("a", budget=None)))
        report = self.write("r.json", {"packages": [{"id": "a", "engine_s": 2.0, "files_scanned": 4}]})
        code, out = self.main("--packages", packages, "calibrate", report, "--margin", "0.5")
        self.assertEqual(code, 0)
        self.assertIn("a: median 2.00 s over 1 report(s) -> budget 3.0 s (4 files)", out)
        self.assertIsNone(perf.load_packages(packages)["packages"][0]["budget"]["engine_s"])      # nothing written yet
        code, out = self.main("--packages", packages, "calibrate", report, "--write")
        self.assertEqual(code, 0)
        written = perf.load_packages(packages)["packages"][0]
        self.assertEqual((written["budget"]["engine_s"], written["expect"]["files_scanned"]), (2.5, 4))
        self.assertIn("wrote 1 budget(s)", out)

    def test_usage_errors_are_exit_2_and_name_the_problem(self):
        good = self.write("p.json", config(package("a")))
        code, _ = self.main("--packages", good, "fetch", "--only", "nope")
        self.assertEqual(code, 2)
        self.assertIn("nope", self.err.getvalue())
        code, _ = self.main("--packages", os.path.join(self.dir, "missing.json"), "fetch")
        self.assertEqual(code, 2)
        code, _ = self.main("--packages", self.write("bad.json", {"version": 9}), "fetch")
        self.assertEqual(code, 2)
        code, _ = self.main("--packages", good, "calibrate", os.path.join(self.dir, "nothing.json"))
        self.assertEqual(code, 2)
        code, _ = self.main("--packages", good, "run", "--runs", "0")
        self.assertEqual(code, 2)

    def test_fetch_downloads_and_a_wrong_file_is_exit_3(self):
        data = os.urandom(300)
        server = Server({"/a.tgz": data, "/b.tgz": b"changed"})
        self.addCleanup(server.close)
        cache = os.path.join(self.dir, "cache")
        packages = self.write("p.json", config(package("a", [entry(data, url=server.url + "/a.tgz")])))
        self.assertEqual(self.main("--packages", packages, "fetch", "--cache", cache)[0], 0)
        self.assertEqual(os.listdir(cache), [sha(data)])
        moved = self.write("m.json", config(package("a", [entry(data, url=server.url + "/b.tgz")])))
        cache2 = os.path.join(self.dir, "cache2")
        self.assertEqual(self.main("--packages", moved, "fetch", "--cache", cache2)[0], 3)
        self.assertIn("not the pinned ones", self.err.getvalue())

    def test_the_options_the_workflow_uses_are_accepted(self):
        args = perf.build_parser().parse_args(["run", "--cache", "c", "--runs", "3", "--json", "j", "--summary", "s"])
        self.assertEqual((args.cache, args.runs, args.json, args.summary, args.no_fail), ("c", 3, "j", "s", False))
        self.assertEqual(perf.build_parser().parse_args(["fetch", "--cache", "c"]).command, "fetch")


def tarball(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in files.items():
            raw = text.encode("utf-8")
            info = tarfile.TarInfo("package/" + name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def native_engine():
    try:
        common.use_source_tree()
        from lazaret.scanner import engine
        return engine.available()
    except Exception:                                   # noqa: BLE001
        return False


@unittest.skipUnless(native_engine(), "needs the native engine")
class RealEngineTests(unittest.TestCase):
    """The check against the engine itself, on a tiny package served from loopback."""

    def setUp(self):
        self.data = tarball({"package.json": json.dumps({"name": "tiny", "version": "1.0.0", "main": "index.js"}),
                             "index.js": "module.exports = function add(a, b) { return a + b; };\n" * 40})
        self.server = Server({"/tiny.tgz": self.data})
        self.addCleanup(self.server.close)
        self.dir = tempfile.mkdtemp(prefix="lazaret-perf-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        self.packages = os.path.join(self.dir, "p.json")
        self.write(budget=None)

    def write(self, budget, expect=None):
        pkg = package("npm:tiny@1.0.0", [entry(self.data, name="tiny-1.0.0.tgz", url=self.server.url + "/tiny.tgz")], budget=budget)
        if expect is not None:
            pkg["expect"] = expect
        perf.save_packages(config(pkg), self.packages)

    def run_main(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            code = perf.main(["--packages", self.packages, "run", "--cache", os.path.join(self.dir, "cache"),
                              "--runs", "2", "--json", os.path.join(self.dir, "r.json"), *extra])
        return code, out.getvalue(), err.getvalue()

    def report(self):
        with open(os.path.join(self.dir, "r.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_a_real_run_measures_the_engine_and_leaves_it_as_it_found_it(self):
        from lazaret.registry import repo
        from lazaret.scanner import _native
        before, bound = _native.call_raw, repo.USE_RISK_CHARS
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        rep = self.report()
        pkg = rep["packages"][0]
        self.assertGreater(pkg["engine_s"], 0)
        self.assertGreater(pkg["runs"][0]["engine_calls"], 0)
        self.assertGreaterEqual(pkg["files_scanned"], 1)
        self.assertEqual((pkg["status"], pkg["budget_s"]), ("uncalibrated", None))
        self.assertIn("npm:tiny@1.0.0", out)
        self.assertGreaterEqual(rep["threads"], 1)
        self.assertTrue(rep["engine"])
        self.assertIs(_native.call_raw, before)                       # the engine's own function is back
        self.assertEqual(repo.USE_RISK_CHARS, bound)                  # and so is the use-time bound

    def test_over_its_budget_fails_unless_told_not_to(self):
        self.write(budget=1e-9)
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("over budget: npm:tiny@1.0.0", err)
        code, _, err = self.run_main("--no-fail")
        self.assertEqual(code, 0)
        self.assertIn("(--no-fail)", err)
        self.write(budget=1e6)
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("| ok |", out)

    def test_a_different_amount_of_work_is_reported(self):
        self.write(budget=1e6, expect={"files_scanned": 999})
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("ok (work changed)", out)

    def test_the_summary_is_appended(self):
        summary = os.path.join(self.dir, "summary.md")
        with open(summary, "w", encoding="utf-8") as fh:
            fh.write("before\n")
        self.assertEqual(self.run_main("--summary", summary)[0], 0)
        with open(summary, encoding="utf-8") as fh:
            text = fh.read()
        self.assertTrue(text.startswith("before\n### Engine performance\n\n| package |"))

    def test_a_package_that_is_not_the_pinned_bytes_stops_before_anything_is_timed(self):
        self.write(budget=None)
        cfg = perf.load_packages(self.packages)
        cfg["packages"][0]["files"][0]["sha256"] = sha(b"something else")
        perf.save_packages(cfg, self.packages)
        code, out, err = self.run_main()
        self.assertEqual((code, out), (3, ""))
        self.assertIn("not the pinned ones", err)


class CommonTests(unittest.TestCase):
    def test_engine_spans_wraps_every_call_and_restores(self):
        from lazaret.scanner import timings
        seen = []
        native = types.SimpleNamespace(call_raw=lambda name, args=None, text="": seen.append(name) or "ok")
        original = native.call_raw
        t = timings.Timings()
        with timings.capture(t), common.engine_spans(native, timings):
            self.assertEqual(native.call_raw("cross_file"), "ok")
            native.call_raw("batch", {"calls": [["scan_file", {}, "x"]]})
            native.call_raw("batch", {"calls": []})
            native.call_raw("batch", None)
        self.assertIs(native.call_raw, original)
        by = t.report()["phases"]["engine"]["by"]
        self.assertEqual(sorted(by), ["batch", "batch:scan_file", "cross_file"])
        self.assertEqual(by["batch"]["calls"], 2)
        self.assertEqual(seen, ["cross_file", "batch", "batch", "batch"])

    def test_engine_spans_restores_when_the_block_raises(self):
        from lazaret.scanner import timings
        native = types.SimpleNamespace(call_raw=lambda *a, **k: None)
        original = native.call_raw
        with self.assertRaises(KeyError), common.engine_spans(native, timings):
            raise KeyError("x")
        self.assertIs(native.call_raw, original)

    def test_recorded_network_records_replays_and_restores(self):
        calls = []

        def fetch(url, *args, **kwargs):
            calls.append(url)
            return b"from the network " + url.encode()
        repo = types.SimpleNamespace(_fetch=fetch)
        with tempfile.TemporaryDirectory() as d:
            with common.recorded_network(repo, d, record=True, replay=False):                # cold
                self.assertEqual(repo._fetch("u1"), b"from the network u1")
                self.assertEqual(repo._fetch("u1"), b"from the network u1")
            self.assertEqual(calls, ["u1", "u1"])                                            # a cold run never replays
            self.assertIs(repo._fetch, fetch)
            with common.recorded_network(repo, d, record=True, replay=True):                 # warm
                self.assertEqual(repo._fetch("u1"), b"from the network u1")
                self.assertEqual(repo._fetch("u2"), b"from the network u2")                  # not recorded yet: asked, kept
                self.assertEqual(repo._fetch("u1", data=b"post"), b"from the network u1")    # a request body is another key
            self.assertEqual(calls, ["u1", "u1", "u2", "u1"])
            with common.recorded_network(repo, d, record=False, replay=True):
                repo._fetch("u2")
                repo._fetch("u3")
                repo._fetch("u3")                                                            # not kept: asked twice
            self.assertEqual(calls, ["u1", "u1", "u2", "u1", "u3", "u3"])

    def test_the_source_tree_is_put_first_once(self):
        common.use_source_tree()
        common.use_source_tree()
        self.assertEqual(sys.path.count(common.SRC), 1)
        self.assertTrue(os.path.isdir(os.path.join(common.SRC, "lazaret")))


class ScriptTests(unittest.TestCase):
    """The other scripts: usage errors without a registry, and the parts that are plain functions."""

    def run_script(self, name, *argv):
        script = load(name)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            try:
                code = script.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_a_bad_spec_is_a_usage_error_and_nothing_is_fetched(self):
        for name, argv in (("registry_scan", ["requests"]), ("release_overlap", ["requests"]),
                           ("use_time_coverage", ["gem:x"]), ("engine_replay", ["hot", "requests"]),
                           ("thread_scaling", ["requests", "1"])):
            with self.subTest(name):
                code, _, err = self.run_script(name, *argv)
                self.assertEqual(code, 2)
                self.assertIn("not a package spec", err)

    def test_guard_connections_says_how_to_use_it(self):
        code, out, _ = self.run_script("guard_connections", "--help")
        self.assertEqual(code, 0)
        self.assertIn("guard_connections.py [--keepalive]", out)
        code, out, _ = self.run_script("guard_connections")
        self.assertEqual(code, 2)

    def test_the_overlap_of_a_release(self):
        overlap = load("release_overlap").overlap
        totals, by_ext = overlap([("a.py", b"xx"), ("b/a.py", b"xx"), ("c.md", b"yyy"), ("d.bin", b"xx"), ("e.py", b"z")])
        self.assertEqual(totals["all"], [5, 10, 3, 6])                       # xx three times, yyy, z
        self.assertEqual(totals["text"], [4, 8, 3, 6])                       # the .bin is not text-like
        self.assertEqual(by_ext[".py"], [3, 5, 2, 3])
        self.assertEqual(by_ext[".bin"], [1, 2, 0, 0])                       # (seen first as a.py's bytes)
        self.assertEqual(overlap([])[0]["all"], [0, 0, 0, 0])

    def test_every_script_is_standard_library_only_and_names_its_encodings(self):
        allowed = {"argparse", "collections", "contextlib", "hashlib", "http", "io", "json", "math", "os", "random",
                   "resource", "statistics", "subprocess", "sys", "tempfile", "threading", "time", "urllib", "_common",
                   "lazaret"}
        for name in sorted(os.listdir(PROFILE)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(PROFILE, name), encoding="utf-8") as fh:
                text = fh.read()
            for node in ast.walk(ast.parse(text)):
                modules = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                    [node.module] if isinstance(node, ast.ImportFrom) else []
                for module in modules:
                    with self.subTest(script=name, module=module):
                        self.assertIn(module.split(".")[0], allowed)
            if name != "_common.py":
                self.assertIn("configure_stdio()", text, name)


class SCABundleTests(unittest.TestCase):
    """`sca_bundle.py` (P-5): the bundle a scan loads whole, against the indexed one it reads parts of."""

    def setUp(self):
        self.script = load("sca_bundle")
        self.dir = tempfile.mkdtemp(prefix="lz-scabundle-")
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)

    def run_script(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            try:
                code = self.script.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def path(self, name):
        return os.path.join(self.dir, name)

    def test_the_synthetic_bundle_is_the_shape_of_the_real_one_and_the_same_every_time(self):
        doc = self.script.synthetic(40)
        self.assertEqual((doc["bundleVersion"], len(doc["advisories"]), doc["counts"]["advisories"]), (1, 40, 40))
        self.assertEqual(doc, self.script.synthetic(40))
        self.assertNotEqual(doc, self.script.synthetic(40, seed=8))
        adv = doc["advisories"][0]
        self.assertTrue({"cve", "aliases", "severity", "cvss", "refs", "epss", "packages"} <= set(adv))
        self.assertTrue(all(p["exact"] and p["ecosystem"] in ("npm", "pypi") and p["ranges"]
                            for a in doc["advisories"] for p in a["packages"]))

    def test_an_inventory_is_half_names_the_bundle_has_and_half_it_has_not(self):
        doc = self.script.synthetic(200)
        inventory = self.script.inventory_of(doc, 100)
        self.assertEqual(len(inventory), 100)
        known = {(p["ecosystem"], p["name"]) for a in doc["advisories"] for p in a["packages"]}
        self.assertEqual(sum((eco, name) in known for eco, name, _ in inventory), 50)
        self.assertEqual(inventory, self.script.inventory_of(doc, 100))
        self.assertNotEqual(inventory, self.script.inventory_of(doc, 100, seed=4))

    def test_an_inventory_from_a_bundle_with_less_in_it_than_asked_for_is_padded_and_survives_junk(self):
        doc = {"advisories": [{"packages": [{"name": "a", "ecosystem": "npm", "exact": True,
                                             "ranges": [{"fromVersion": "2.0.0"}]},
                                            {"name": "b", "ecosystem": "pypi", "exact": True, "ranges": []},
                                            {"name": "loose", "ecosystem": "npm", "exact": False},
                                            {"name": 5, "ecosystem": "npm", "exact": True}, "junk", None]},
                              "junk", {"packages": "no"}]}
        inventory = self.script.inventory_of(doc, 6)
        self.assertEqual(len(inventory), 6)
        named = sorted(item for item in inventory if not item[1].startswith("no-advisory"))
        self.assertEqual(named, [["npm", "a", "2.0.0"], ["pypi", "b", "1.0.0"]])   # (the loose and the nameless are not used;
        #                                                             a bundle that gives no version gets 1.0.0; four padded)
        self.assertEqual(self.script.inventory_of({}, 3)[0][1][:11], "no-advisory")

    def test_the_hash_of_the_matches_is_of_their_order_and_not_of_the_order_of_a_ranges_keys(self):
        def match(cve, rng):
            return ({"cve": cve}, {"name": "p", "ecosystem": "npm"}, ("npm", "p", "1.0.0", "x"), rng)
        a = [match("A", {"fromVersion": "1", "toVersion": "2"}), match("B", "all versions")]
        same = [match("A", {"toVersion": "2", "fromVersion": "1"}), match("B", "all versions")]
        self.assertEqual(self.script.digest_of(a), self.script.digest_of(same))
        self.assertNotEqual(self.script.digest_of(a), self.script.digest_of(a[::-1]))
        self.assertNotEqual(self.script.digest_of(a), self.script.digest_of(a[:1]))
        self.assertNotEqual(self.script.digest_of(a), self.script.digest_of([a[0], match("B", "other")]))

    def test_the_peak_is_in_megabytes_whatever_the_platform_counts_in(self):
        usage = mock.Mock(ru_maxrss=2048 * 1024)
        with mock.patch.object(self.script.resource, "getrusage", return_value=usage):
            with mock.patch.object(self.script.sys, "platform", "linux"):
                self.assertEqual(self.script.peak_mb(), 2048.0)               # (kilobytes)
            with mock.patch.object(self.script.sys, "platform", "darwin"):
                self.assertEqual(self.script.peak_mb(), 2.1)                  # (bytes)
        with mock.patch.object(self.script, "resource", None):
            self.assertIsNone(self.script.peak_mb())

    def test_gen_inventory_build_and_measure_one_after_another(self):
        bundle, inventory, indexed = self.path("b.json"), self.path("inv.json"), self.path("b.lzx")
        code, out, err = self.run_script("gen", "60", bundle)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("60 advisories", out)
        self.assertEqual(self.run_script("inventory", bundle, inventory, "--deps", "30")[0], 0)
        code, out, _ = self.run_script("build", bundle, indexed)
        built = json.loads(out)
        self.assertEqual((code, built["bytes"], os.path.getsize(indexed)), (0, os.path.getsize(indexed), built["bytes"]))
        results = {}
        for path in (bundle, indexed):
            code, out, _ = self.run_script("measure", path, inventory)
            self.assertEqual(code, 0)
            results[json.loads(out)["format"]] = json.loads(out)
        self.assertEqual(set(results), {"json", "index"})
        self.assertEqual(results["json"]["digest"], results["index"]["digest"])
        self.assertEqual((results["json"]["advisories"], results["json"]["deps"]), (60, 30))
        self.assertGreater(results["json"]["matches"], 0)

    def test_compare_builds_measures_both_and_says_they_agree(self):
        bundle, report, keep = self.path("b.json"), self.path("report.json"), self.path("kept")
        self.run_script("gen", "80", bundle)
        code, out, err = self.run_script("compare", bundle, "--deps", "40", "--runs", "2", "--json", report,
                                         "--keep", keep)
        self.assertEqual((code, err), (0, ""))
        self.assertIn("80 advisories; 40 dependencies matched; best of 2", out)
        self.assertIn("JSON bundle", out)
        self.assertIn("indexed bundle", out)
        self.assertIn("the same matches, in the same order", out)
        with open(report, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertTrue(data["same_answer"])
        self.assertEqual((data["json"]["format"], data["index"]["format"], data["deps"], data["runs"]),
                         ("json", "index", 40, 2))
        self.assertTrue(os.path.exists(os.path.join(keep, "bundle.lzx")))
        self.assertTrue(os.path.exists(os.path.join(keep, "inventory.json")))

    def fake(self, **change):
        record = {"bundle": "x", "bytes": 10 ** 6, "format": "json", "advisories": 5, "deps": 4, "load_s": 1.0,
                  "match_s": 0.5, "matches": 3, "unknown": 0, "peak_mb": 100.0, "digest": "a" * 64}
        return dict(record, **change)

    def test_two_bundles_that_give_different_matches_are_exit_1(self):
        built = {"build_s": 1, "parse_s": 1, "bytes": 5, "peak_mb": 9.0}
        answers = iter([{"deps": 4}, built, self.fake(), self.fake(format="index", digest="b" * 64)])
        with mock.patch.object(self.script, "child", side_effect=lambda *a: next(answers)):
            code, out, _ = self.run_script("compare", self.path("any.json"))
        self.assertEqual(code, 1)
        self.assertIn("DIFFERENT matches", out)

    def test_a_step_that_fails_is_exit_4_and_says_which(self):
        with mock.patch.object(self.script, "child", side_effect=RuntimeError("`build` failed (1): boom")):
            code, _, err = self.run_script("compare", self.path("any.json"))
        self.assertEqual(code, 4)
        self.assertIn("`build` failed", err)

    def test_a_missing_or_damaged_bundle_is_exit_4_not_a_traceback(self):
        for argv in (("inventory", self.path("nowhere.json"), self.path("o.json")),
                     ("build", self.path("nowhere.json"), self.path("o.lzx")),
                     ("measure", self.path("nowhere.json"), self.path("o.json"))):
            with self.subTest(argv[0]):
                self.assertEqual(self.run_script(*argv)[0], 4)
        bad = self.path("bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        self.assertEqual(self.run_script("inventory", bad, self.path("o.json"))[0], 4)

    def test_usage_errors_are_exit_2(self):
        for argv in (("gen", "0", self.path("x.json")), ("compare", "b.json", "--deps", "0"),
                     ("compare", "b.json", "--runs", "0"), ("inventory", "b.json", "o.json", "--deps", "0")):
            with self.subTest(argv):
                self.assertEqual(self.run_script(*argv)[0], 2)
        self.assertEqual(self.run_script()[0], 2)
        self.assertEqual(self.run_script("frob")[0], 2)

    def test_the_child_runs_this_script_and_reads_its_last_line(self):
        done = mock.Mock(returncode=0, stdout="noise\n{\"a\": 1}\n", stderr="")
        with mock.patch.object(self.script.subprocess, "run", return_value=done) as run:
            self.assertEqual(self.script.child("measure", "x", "y"), {"a": 1})
        argv = run.call_args[0][0]
        self.assertEqual((argv[0], os.path.basename(argv[1]), argv[2:]), (sys.executable, "sca_bundle.py",
                                                                           ["measure", "x", "y"]))
        failed = mock.Mock(returncode=3, stdout="", stderr="Traceback ... boom")
        with mock.patch.object(self.script.subprocess, "run", return_value=failed), \
                self.assertRaisesRegex(RuntimeError, r"`measure` failed \(3\): .*boom"):
            self.script.child("measure", "x")


class WorkflowTests(unittest.TestCase):
    """The rules ci.yml states, for the file that runs the check."""

    @classmethod
    def setUpClass(cls):
        with open(WORKFLOW, encoding="utf-8") as fh:
            cls.text = fh.read()

    def test_every_action_is_pinned_to_a_commit(self):
        uses = re.findall(r"^\s*-?\s*uses:\s*(\S+)(.*)$", self.text, flags=re.M)
        self.assertGreaterEqual(len(uses), 3)
        for ref, rest in uses:
            with self.subTest(ref):
                self.assertRegex(ref, r"^[\w./-]+@[0-9a-f]{40}$")
                self.assertRegex(rest, r"#\s*v\d")

    def test_it_runs_on_a_schedule_and_by_hand_and_reads_no_pull_request(self):
        on = self.text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertIn("schedule:", on)
        self.assertIn("workflow_dispatch:", on)
        for trigger in ("pull_request", "push:", "workflow_call", "issue_comment", "workflow_run"):
            self.assertNotIn(trigger, on)

    def test_read_only_no_secrets_no_caches_a_timeout_and_one_run_at_a_time(self):
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n")
        self.assertNotIn("write", re.sub(r"#.*", "", self.text.split("\njobs:", 1)[0].split("permissions:", 1)[1]))
        body = re.sub(r"(?m)#.*$", "", self.text)
        self.assertNotIn("secrets.", body)
        self.assertNotIn("actions/cache", body)
        self.assertNotRegex(body, r"(?m)^\s+cache(-dependency-path)?:")
        self.assertNotIn("id-token", body)
        self.assertRegex(body, r"timeout-minutes:\s*\d+")
        self.assertRegex(body, r"concurrency:\n  group: \S+\n  cancel-in-progress: false")
        self.assertIn("persist-credentials: false", body)

    def test_it_fetches_before_it_times_and_runs_the_script(self):
        fetch, run = self.text.index("perf_check.py fetch"), self.text.index("perf_check.py run")
        self.assertLess(fetch, run)
        self.assertIn("cargo build --release --offline --locked", self.text)
        self.assertLess(self.text.index("cargo build"), fetch)
        self.assertIn('--summary "$GITHUB_STEP_SUMMARY"', re.sub(r"\s+", " ", self.text))

    def command(self, sub):
        """The arguments the workflow gives `perf_check.py <sub>`, split as a shell would."""
        start = self.text.index(f"perf_check.py {sub}") + len("perf_check.py ")
        end = self.text.find("\n      - ", start)
        chunk = re.sub(r"\n\s+(?=--)", " ", self.text[start:end if end != -1 else None]).split("\n")[0]
        return shlex.split(chunk)

    def test_the_options_in_the_workflow_are_the_scripts(self):
        parser = perf.build_parser()
        fetch, run = parser.parse_args(self.command("fetch")), parser.parse_args(self.command("run"))
        self.assertEqual((fetch.command, run.command), ("fetch", "run"))
        self.assertEqual(fetch.cache, run.cache)
        self.assertTrue(run.cache.startswith("$RUNNER_TEMP/"))
        self.assertEqual((run.runs, run.summary, run.no_fail), (3, "$GITHUB_STEP_SUMMARY", False))
        self.assertIn("path: ${{ runner.temp }}/" + os.path.basename(run.json), self.text)      # the report the job uploads


if __name__ == "__main__":
    unittest.main()
