"""Engine parity on large and converted inputs, split from
test_js_parity.py (0.1.8) so each module runs in well under the suite's
per-module time budget: the source-size limit (a 2.4 MB bundle, five ways,
in both engines) and every fixture converted to Windows line endings. The
comparison is test_js_parity's (EngineParityTests.assert_same). Inert
content; skipped where Node isn't installed.
"""

import collections
import os
import shutil
import tempfile
import unittest

from tests import _support
from tests.architecture import test_js_parity as base      # (the module: its TestCase is not collected here)
from tests.architecture.test_js_parity import NODE, both, issue_key, js_cmd, py_cmd, run_cli


@unittest.skipUnless(NODE, "node is not installed")
class EngineLimitParityTests(unittest.TestCase):
    maxDiff = None
    assert_same = base.EngineParityTests.assert_same

    def test_windows_line_endings_change_nothing(self):
        """Every fixture, converted to CRLF (as a Windows checkout does), must
        give exactly the findings its LF original gives, in both engines. CI
        on Windows first caught this: a bare "# nosec" on a CRLF line was
        ignored by the JS engine."""
        for name in sorted(os.listdir(_support.FIXTURES)):
            src = os.path.join(_support.FIXTURES, name)
            if not os.path.isdir(src):
                continue
            with self.subTest(fixture=name), tempfile.TemporaryDirectory() as tmp:
                lf, crlf = os.path.join(tmp, "lf"), os.path.join(tmp, "crlf")
                shutil.copytree(src, lf)
                shutil.copytree(src, crlf)
                for dirpath, _, files in os.walk(crlf):
                    for fname in files:
                        if fname.endswith((".py", ".js", ".sql", ".json")):
                            path = os.path.join(dirpath, fname)
                            with open(path, "rb") as f:
                                data = f.read().replace(b"\r\n", b"\n")
                            with open(path, "wb") as f:
                                f.write(data.replace(b"\n", b"\r\n"))
                for cmd in (js_cmd, py_cmd):
                    lf_exit, lf_rep, _ = run_cli(cmd(lf))
                    cr_exit, cr_rep, _ = run_cli(cmd(crlf))
                    self.assertEqual(collections.Counter(issue_key(i) for i in cr_rep["issues"]),
                                     collections.Counter(issue_key(i) for i in lf_rep["issues"]),
                                     f"{cmd.__name__}: CRLF changed the findings")
                    self.assertEqual(cr_exit, lf_exit)

    def test_source_limit_agrees(self):
        """Both engines read sources up to 16,000,000 bytes by default, and
        --max-source-bytes / LAZARET_MAX_SOURCE_BYTES change the limit the
        same way (a 2.4 MB bundle with a decode-and-run on its last line)."""
        bundle = "var a = function (b) { return b + 1; };\n" * 60_000 + 'eval(atob("Y29uc29sZS5sb2coMSk="));\n'
        with tempfile.TemporaryDirectory() as root:
            for rel, text in {"a.js": "var x = 1;\n", "node_modules/big/dist/index.js": bundle,
                              "node_modules/big/package.json": '{"name": "big", "version": "1.0.0"}'}.items():
                path = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
            for label, extra, env, want in (
                    ("default", (), None, "SC-EVAL-DECODE"),
                    ("option", ("--max-source-bytes", "2000000"), None, "SC-TRUNCATED"),
                    ("variable", (), {"LAZARET_MAX_SOURCE_BYTES": "2000000"}, "SC-TRUNCATED"),
                    ("option over variable", ("--max-source-bytes", "3000000"),
                     {"LAZARET_MAX_SOURCE_BYTES": "2000000"}, "SC-EVAL-DECODE"),
                    ("bad variable", (), {"LAZARET_MAX_SOURCE_BYTES": "0"}, "SC-EVAL-DECODE")):
                with self.subTest(label=label):
                    js, py = both(root, deps=True, extra=extra, env=env)
                    self.assert_same(js, py, label=f"source limit, {label}")
                    found = {i["rule"] for i in js[1]["issues"]
                             if i["file"].replace("\\", "/") == "node_modules/big/dist/index.js"}
                    self.assertEqual(found, {want})


if __name__ == "__main__":
    unittest.main()
