"""The npm package's cross-file follower against the Python package's: the
WebAssembly engine's `cross_file` through js/src/lib/native.js
(crossFileIssues, which the npm --deps checks run) and the platform
library's through engine.cross_file_issues, on the follower's parity corpus
(crossfile_corpus.py: its own cases and the generated stream of Python and
npm packages). One Rust source, so they must find the same
findings in the same order, file, line, severity, message and snippet
alike: what this holds is the npm binding of a call with many texts (each
file encoded on its own, its length counted in code points as the engine
reads it) and the WebAssembly build (no threads).

Skipped where node, the WebAssembly build (npm run build in js/) or the
native library is missing.
"""
import json
import os
import subprocess
import unittest

from lazaret.scanner import _native
from tests import _support
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from lazaret.scanner import engine
from tests.architecture.crossfile_corpus import curated, generated, view

NATIVE_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "native.js")
NPM = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const n = await import(pathToFileURL(process.argv[1]).href);
const { cases, onePackage } = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(cases.map((files) => n.crossFileIssues(files, new Set(), { onePackage })
  .map((i) => [i.file, i.line, i.sev, i.msg, i.snipStart, i.snippet]))));
"""


def npm(cases, one_package=False):
    p = subprocess.run([NPM_READY, "--input-type=module", "-e", NPM, NATIVE_JS],
                       input=json.dumps({"cases": cases, "onePackage": one_package}),
                       capture_output=True, encoding="utf-8", timeout=120)
    if p.returncode:
        raise AssertionError(f"node exited {p.returncode}: {p.stderr[-2000:]}")
    return json.loads(p.stdout)


def native(files, **kwargs):
    """The platform library's findings (engine.cross_file_issues)."""
    return engine.cross_file_issues(files, **kwargs)


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class CrossFileWasmParityTests(unittest.TestCase):
    maxDiff = None

    def test_the_followers_cases_and_the_generated_packages(self):
        cases = [files for _label, files in curated()] + generated(20260928, 700)
        want = [view(native(files)) for files in cases]
        self.assertGreater(sum(map(len, want)), 200)
        got = npm(cases)
        bad = [k for k, (w, g) in enumerate(zip(want, got)) if w != g]
        self.assertEqual(bad[:5], [])
        self.assertEqual(len(got), len(want))

    def test_one_distribution(self):
        cases = generated(7, 60)
        want = [view(native(files, one_package=True)) for files in cases]
        self.assertEqual(npm(cases, one_package=True), want)


if __name__ == "__main__":
    unittest.main()
