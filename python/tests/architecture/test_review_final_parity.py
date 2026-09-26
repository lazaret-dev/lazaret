"""Engine parity for the final review's fixes: the Python CLI and the npm CLI
report the same findings (rule, file, line, severity, message), metrics and
exit code on a tree exercising each of them, with and without --deps:

1. dedupe of identical findings and the cap on every non-security rule (a
   one-line file of repeated empty catches, a 1,000-line one, a repeated
   MAJOR Python bug, repeated security findings that are never capped);
2. snippet clipping on long lines with astral characters;
3. SC-EVAL-DECODE through `__import__(…)` / `importlib.import_module(…)`,
   in project mode and in dependency mode (across statements);
4. S-EXEC-JS on method names and definitions vs real sinks;
5. .pth files at the root, in a subdirectory and in a venv's site-packages,
   plus a directory holding only a .pth file (a valid target in both).

The dashboard's side of each is checked in tests/scanner/test_review_*.py.
All content is inert (nothing is executed). Skipped where node is missing.
"""
import collections
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
TIMEOUT = 40

TREE = {
    # 1. dedupe + cap
    "cap/one.js": "try{}catch(e){}" * 20_000,
    "cap/many.js": "try{}catch(e){}\n" * 1000,
    "cap/except.py": "try:\n    f()\nexcept:\n    pass\n" * 250,
    "cap/sec.sql": "DELETE FROM a; DELETE FROM b;\n" * 250,
    "cap/sql_msgs.py": "cur.execute(sql % x); cur.execute(tpl.format(y))\ncur.execute(a % x); cur.execute(b % y)\n",
    # 2. clipping around astral characters on a long line
    "clip/emoji.js": ("const s = '" + "\U0001F600" * 400 + "'; try{}catch(e){} eval(x); "
                      + "try{}catch(e){}" * 300 + "\n"),
    # 3. SC-EVAL-DECODE through inline imports
    "decode/inline.py": ('exec(__import__("base64").b64decode("cHJpbnQoMSk="))\n'
                         "eval(__import__('codecs').decode(s, 'rot13'))\n"
                         "exec(importlib.import_module('zlib').decompress(b))\n"
                         'exec(__import__("os").system("x"))\n'
                         'exec(\n    __import__("base64").b64decode(p))\n'),
    "node_modules/pkg/flow.py": ('p = __import__("base64").b64decode(s)\nq = 1\nexec(p)\n'
                                "d = __import__('codecs').decode(s, 'rot13'); eval(d)\n"),
    "node_modules/pkg/package.json": json.dumps({"name": "pkg", "version": "1.0.0"}),
    # 4. S-EXEC-JS
    "exec/cmd.js": ("class LL extends LS {\n  async exec (args) {\n    return super.exec(args)\n  }\n}\n"
                    "class Pack {\n  async exec (args, { localPrefix } = {}) {\n    await this.#exec(args)\n  }\n"
                    "  async #exec (cmd, args) {\n    return child_process.exec(cmd)\n  }\n}\n"
                    "const { exec } = require('child_process'); exec(x);\nthis.exec(a); cp.exec(b);\n"
                    "const o = { exec(cmd) { return run(cmd) } };\nrequire('child_process').exec(cmd);\n"),
    # 5. .pth files
    "evil.pth": 'import os, base64; exec(base64.b64decode("cHJpbnQoMSk="))\n',
    "sub/boot.pth": b"\xef\xbb\xbfimport sys\r\n./x\r\nimport os; os.system(cmd)\r\n",
    "paths.pth": "./src\n",
    "venv/pyvenv.cfg": "home = /usr\n",
    "venv/lib/python3.11/site-packages/ns.pth": "import _distutils_hack; _distutils_hack.do()\n",
    "venv/lib/python3.11/site-packages/evil.pth": "import zlib; exec(zlib.decompress(b))\n",
}


def write_tree(root, tree):
    for rel, data in tree.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def run_cli(cmd):
    with tempfile.TemporaryDirectory() as out:
        p = subprocess.run(cmd + ["--out-dir", out, "--no-html", "--quiet"], capture_output=True,
                           encoding="utf-8", errors="replace", timeout=TIMEOUT)
        path = os.path.join(out, "lazaret-report.json")
        report = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                report = json.load(f)
        return p.returncode, report, p.stderr


def key(issue):
    return (issue["rule"], str(issue["file"]).replace("\\", "/"), issue["line"], issue["sev"], issue["msg"])


@unittest.skipUnless(NODE, "node is not installed")
class FinalReviewParityTests(unittest.TestCase):
    maxDiff = None

    def both(self, root, extra=()):
        js = run_cli([NODE, JS_BIN, "check", root, *extra])
        py = run_cli([sys.executable, "-m", "lazaret", root, *extra])
        for name, (code, rep, err) in (("npm", js), ("python", py)):
            self.assertIsNotNone(rep, f"{name} engine wrote no report (exit {code}): {err[-500:]}")
        return js, py

    def assert_same(self, js, py, label):
        (js_exit, js_rep, _), (py_exit, py_rep, _) = js, py
        py_issues = [i for i in py_rep["issues"] if not i["rule"].startswith("X-") and i["rule"] != "Q-FLOW-SKIPPED"]
        a, b = collections.Counter(map(key, js_rep["issues"])), collections.Counter(map(key, py_issues))
        self.assertEqual(sorted((a - b).elements()), [], f"{label}: only the npm engine reports")
        self.assertEqual(sorted((b - a).elements()), [], f"{label}: only the Python engine reports")
        self.assertEqual(js_rep["metrics"], py_rep["metrics"], f"{label}: metrics")
        if len(py_issues) == len(py_rep["issues"]):
            for field in ("pass", "conditions", "counts", "ratings"):
                self.assertEqual(js_rep[field], py_rep[field], f"{label}: {field}")
            self.assertEqual(js_exit, py_exit, f"{label}: exit code")

    def test_tree_agrees(self):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, TREE)
            for label, extra in (("default", ()), ("--deps", ("--deps",))):
                with self.subTest(mode=label):
                    js, py = self.both(root, extra)
                    self.assert_same(js, py, label)
                    found = collections.Counter((k[0], k[1]) for k in map(key, js[1]["issues"]))
                    # not vacuous: each fix is exercised
                    self.assertEqual(found[("B-EMPTY-CATCH", "cap/one.js")], 1)
                    self.assertEqual(found[("B-EMPTY-CATCH", "cap/many.js")], 200)
                    self.assertEqual(found[("SQL-DELETE-NOWHERE", "cap/sec.sql")], 250)
                    self.assertEqual(found[("S-SQL-PY", "cap/sql_msgs.py")], 3)
                    self.assertEqual(found[("SC-EVAL-DECODE", "decode/inline.py")], 4)
                    self.assertEqual(found[("S-EXEC-JS", "exec/cmd.js")], 4)
                    self.assertEqual(found[("SC-PTH-EXEC", "evil.pth")], 1)
                    self.assertEqual(found[("SC-PTH-EXEC", "sub/boot.pth")], 2)
                    deps = label == "--deps"
                    self.assertEqual(found[("SC-EVAL-DECODE", "node_modules/pkg/flow.py")], 2 if deps else 0)
                    self.assertEqual(found[("SC-PTH-EXEC", "venv/lib/python3.11/site-packages/evil.pth")],
                                     1 if deps else 0)

    def test_a_directory_with_only_a_pth_file(self):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, {"evil.pth": TREE["evil.pth"]})
            js, py = self.both(root, ("--ci",))
            self.assert_same(js, py, "only evil.pth")
            self.assertEqual((js[0], py[0]), (1, 1))          # scanned, gate failed (was: exit 2)
            self.assertEqual([key(i)[:4] for i in js[1]["issues"]], [("SC-PTH-EXEC", "evil.pth", 1, "CRITICAL")])
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, {"paths.pth": "./src\n"})
            js, py = self.both(root)
            self.assert_same(js, py, "only paths.pth")
            self.assertEqual((js[0], py[0]), (0, 0))


if __name__ == "__main__":
    unittest.main()
