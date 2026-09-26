"""Project and --deps scans read source files up to 16,000,000 bytes.

At the old 2,000,000-byte limit, `lazaret --deps` reported SC-TRUNCATED
(CRITICAL, which fails the gate) for ordinary single-file bundles in
node_modules: typescript's lib/typescript.js (9.1 MB) and _tsc.js (6.2 MB),
@babel/standalone's babel.js (5.3 MB). The limit is now 16,000,000 by
default, as in the registry scanner, and --max-source-bytes /
LAZARET_MAX_SOURCE_BYTES change it (the MCP server uses the same value; see
tests/mcp/test_mcp_hardening.py). The npm engine's twin is
js/test/review-source-limit.test.js, and test_js_parity runs both with the
option and the variable.
"""
import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from tests import _support
from tests.scanner.test_review_binary import make_tree, run_cli
from lazaret.scanner import core

B64 = '"Y29uc29sZS5sb2coMSk="'
# 2.4 MB of ordinary bundle, then a decode-and-run on its last line
BUNDLE = "var a = function (b) { return b + 1; };\n" * 60_000 + "eval(atob(%s));\n" % B64


def rules_in(report, name):
    return {i["rule"] for i in report["issues"] if i["file"].replace(os.sep, "/") == name}


class SourceLimitTests(unittest.TestCase):
    def setUp(self):
        self.root = make_tree({"a.js": "var x = 1;\n", "node_modules/big/dist/index.js": BUNDLE,
                               "node_modules/big/package.json": '{"name": "big", "version": "1.0.0"}'})
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_the_default_reads_a_large_bundle(self):
        self.assertEqual(core.SOURCE_SIZE_CAP, 16_000_000)
        p, report = run_cli(self.root, "--deps", "--ci")
        found = rules_in(report, "node_modules/big/dist/index.js")
        self.assertIn("SC-EVAL-DECODE", found)             # scanned to its last line
        self.assertNotIn("SC-TRUNCATED", found)

    def test_the_option_sets_the_limit(self):
        p, report = run_cli(self.root, "--deps", "--max-source-bytes", "2000000")
        (msg,) = [i["msg"] for i in report["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(msg, "File not fully scanned: %s bytes exceeds the 2,000,000-byte file limit."
                         % f"{len(BUNDLE):,}")
        self.assertEqual(p.returncode, 0)
        p, report = run_cli(self.root, "--deps", "--max-source-bytes", "2000000", "--ci")
        self.assertEqual((p.returncode, report["pass"]), (1, False))

    def test_the_environment_sets_the_limit(self):
        env = dict(os.environ, LAZARET_MAX_SOURCE_BYTES="2000000", PYTHONPATH=_support.SRC)
        out = subprocess.run([sys.executable, "-c", "from lazaret.scanner import core; print(core.SOURCE_SIZE_CAP)"],
                             capture_output=True, encoding="utf-8", errors="replace", env=env, timeout=40)
        self.assertEqual(out.stdout.strip(), "2000000", out.stderr[-400:])

    def test_bad_values(self):
        for value in ("0", "-5", "abc", "1e6", ""):
            with self.subTest(value=value):
                p, report = run_cli(self.root, "--max-source-bytes", value)
                self.assertEqual(p.returncode, 2)
                self.assertIn("expected a positive number of bytes", p.stderr)
        for value, want in (("0", 7), ("-5", 7), ("abc", 7), (" 2_000 ", 2000), ("3000000", 3_000_000)):
            with self.subTest(env=value):
                with mock.patch.dict(os.environ, {"LAZARET_MAX_SOURCE_BYTES": value}):
                    self.assertEqual(core._env_int("LAZARET_MAX_SOURCE_BYTES", 7), want)


if __name__ == "__main__":
    unittest.main()
