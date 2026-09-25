"""Review item 5 (FIX-SPEC 8): which directories the project walk skips.

* __pycache__ was always skipped, so a malicious unchecked-hash .pyc next to
  benign source (it runs on import, whatever the .py says) passed --ci. Every
  .pyc in __pycache__ is now checked: SC-PYC-UNCHECKED (CRITICAL) for PEP 552
  unchecked-hash bytecode, SC-PYC-ORPHAN (MAJOR) for bytecode with no source.
* Any directory named vendor / venv / .venv was pruned at any depth, so a
  first-party app/vendor/helpers.py with exec(b64decode(...)) PASSED. Those
  names are pruned only when they look like dependency trees now.
* Q-SKIPPED-TREE paths were cwd-relative ('./app/vendor') for a relative
  scan root; they are root-relative.
* dist/ and migrations/ are scanned (item 11: README drift, safe direction).

Bytecode fixtures are header bytes plus marshalled `x = 1`; nothing runs.
"""
import importlib.util
import json
import marshal
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import _support
from lazaret.scanner import core

PY = sys.executable
PAYLOAD = 'import base64\ndef run():\n    exec(base64.b64decode("eCA9IDE="))\n'   # "x = 1"


def pyc(flags):
    body = marshal.dumps(compile("x = 1\n", "m.py", "exec"))
    return importlib.util.MAGIC_NUMBER + flags.to_bytes(4, "little") + b"\x00" * 8 + body


def make_tree(files):
    root = tempfile.mkdtemp(prefix="lz-review-prune-")
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


def run_cli(target, *extra, cwd=None):
    out = tempfile.mkdtemp(prefix="lz-review-out-")
    try:
        p = subprocess.run([PY, _support.CLI, target, "--out-dir", out, "--no-html", *extra],
                           capture_output=True, encoding="utf-8", errors="replace",
                           timeout=40, cwd=cwd)
        report = None
        path = os.path.join(out, "lazaret-report.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
    finally:
        shutil.rmtree(out, ignore_errors=True)
    return p, report


def by_file(res):
    out = {}
    for i in res["issues"]:
        out.setdefault(i["file"].replace(os.sep, "/"), set()).add(i["rule"])
    return out


class Bytecode(unittest.TestCase):
    def test_unchecked_hash_pyc_fails_ci(self):
        root = make_tree({
            "app/__init__.py": "",
            "app/util.py": "def greet():\n    return 'hello'\n",
            "app/__pycache__/util.cpython-311.pyc": pyc(0b01),        # unchecked hash
            "app/__pycache__/__init__.cpython-311.pyc": pyc(0b00),    # timestamp: fine
        })
        self.addCleanup(shutil.rmtree, root, True)
        p, report = run_cli(root, "--ci")
        self.assertEqual(p.returncode, 1, p.stdout[-800:])    # used to PASS
        files = by_file(report)
        self.assertEqual(files["app/__pycache__/util.cpython-311.pyc"], {"SC-PYC-UNCHECKED"})
        self.assertNotIn("app/__pycache__/__init__.cpython-311.pyc", files)
        issue = [i for i in report["issues"] if i["rule"] == "SC-PYC-UNCHECKED"][0]
        self.assertEqual((issue["sev"], issue["type"], issue["line"]), ("CRITICAL", "HOTSPOT", 1))

    def test_checked_hash_and_timestamp_pycs_are_quiet(self):
        root = make_tree({
            "m.py": "x = 1\n",
            "__pycache__/m.cpython-311.pyc": pyc(0b11),              # checked hash
            "__pycache__/m.cpython-310.opt-1.pyc": pyc(0b00),
            "__pycache__/notes.txt": "not bytecode",
            "__pycache__/sub/deep.py": "eval(x)\n",                   # never scanned
        })
        self.addCleanup(shutil.rmtree, root, True)
        res = core.scan_project(root)
        self.assertEqual([i for i in res["issues"] if i["file"].startswith("__pycache__")], [])
        self.assertTrue(res["pass"])

    def test_orphan_pyc(self):
        root = make_tree({
            "a.py": "x = 1\n",
            "pkg/__pycache__/gone.cpython-312.pyc": pyc(0b00),
            "pkg/__pycache__/both.cpython-312.pyc": pyc(0b01),
            "pkg/win.pyw": "x = 1\n",
            "pkg/__pycache__/win.cpython-312.pyc": pyc(0b00),
        })
        self.addCleanup(shutil.rmtree, root, True)
        files = by_file(core.scan_project(root))
        self.assertEqual(files["pkg/__pycache__/gone.cpython-312.pyc"], {"SC-PYC-ORPHAN"})
        self.assertEqual(files["pkg/__pycache__/both.cpython-312.pyc"],
                         {"SC-PYC-ORPHAN", "SC-PYC-UNCHECKED"})
        self.assertNotIn("pkg/__pycache__/win.cpython-312.pyc", files)

    def test_pyc_issue_helper(self):
        self.assertEqual(core.pyc_issues("x.pyc", b"ab\r\n\x01\x00\x00\x00", True)[0]["rule"],
                         "SC-PYC-UNCHECKED")
        self.assertEqual(core.pyc_issues("x.pyc", b"ab\r\n\x03\x00\x00\x00", True), [])
        self.assertEqual(core.pyc_issues("x.pyc", b"ab\n\n\x01\x00\x00\x00", True), [])  # not a pyc
        self.assertEqual(core.pyc_issues("x.pyc", b"ab\r\n", True), [])                  # short


class DependencyTrees(unittest.TestCase):
    def test_first_party_vendor_and_venv_named_dirs_are_scanned(self):
        root = make_tree({
            "app/main.py": "from app.vendor.helpers import run\nrun()\n",
            "app/vendor/helpers.py": PAYLOAD,
            "app/venv/tool.py": "eval(x)\n",
            "app/.venv/t2.py": "eval(y)\n",
            "env/c.py": "eval(z)\n",
        })
        self.addCleanup(shutil.rmtree, root, True)
        p, report = run_cli(root, "--ci")
        self.assertEqual(p.returncode, 1)                      # used to PASS
        files = by_file(report)
        self.assertIn("S-EVAL-PY", files["app/vendor/helpers.py"])
        for f in ("app/venv/tool.py", "app/.venv/t2.py", "env/c.py"):
            self.assertIn("S-EVAL-PY", files[f], f)
        self.assertFalse([i for i in report["issues"] if i["rule"] == "Q-SKIPPED-TREE"])

    def test_real_dependency_trees_are_pruned_and_counted(self):
        root = make_tree({
            "a.py": "x = 1\n",
            "venv/pyvenv.cfg": "home = /usr/bin\n",
            "venv/lib/x.py": "eval(x)\n",
            "sub/.venv/pyvenv.cfg": "",
            "sub/.venv/y.py": "eval(y)\n",
            "go/vendor/modules.txt": "# example.invalid/mod v1\n",
            "go/vendor/m/m.js": "eval(1)\n",
            "php/vendor/autoload.php": "<?php\n",
            "py/vendor/requests-2.0.dist-info/METADATA": "Name: requests\n",
            "py/vendor/r.py": "eval(r)\n",
            "js/vendor/package.json": "{}",
            "node_modules/p/index.js": "eval(p)\n",
            "web/bower_components/q/q.js": "eval(q)\n",
            "lib/site-packages/s.py": "eval(s)\n",
        })
        self.addCleanup(shutil.rmtree, root, True)
        res = core.scan_project(root)
        skipped = sorted(i["file"].replace(os.sep, "/") for i in res["issues"]
                         if i["rule"] == "Q-SKIPPED-TREE")
        self.assertEqual(skipped, ["go/vendor", "js/vendor", "lib/site-packages", "node_modules",
                                   "php/vendor", "py/vendor", "sub/.venv", "venv",
                                   "web/bower_components"])
        self.assertTrue(res["pass"], [i["rule"] for i in res["issues"]])
        tree = [i for i in res["issues"] if i["file"] == "venv"][0]
        self.assertEqual(tree["msg"], "Directory venv was skipped (2 files, 24 bytes unread).")

    def test_deps_mode_marks_dependency_files(self):
        root = make_tree({
            "a.py": "x = 1\n",
            "vendor/modules.txt": "",
            "vendor/dep.py": 'password = "hunter2hunter2"\n',
            "app/vendor/own.py": "x = 1\n",
            "node_modules/p/package.json": json.dumps({"scripts": {"prepare": "node x.js"}}),
        })
        self.addCleanup(shutil.rmtree, root, True)
        files, manifests, _ = core.collect_files(root, [], include_deps=True)
        dep = {f["path"].replace(os.sep, "/"): f["dep"] for f in files}
        self.assertEqual(dep, {"a.py": False, "app/vendor/own.py": False, "vendor/dep.py": True})
        self.assertEqual([m["dep"] for m in manifests], [True])
        res = core.scan_project(root, include_deps=True)
        # an installed dependency's `prepare` never runs: registry hook set
        self.assertFalse([i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"])
        self.assertFalse([i for i in res["issues"] if i["rule"] == "Q-SKIPPED-TREE"])

    def test_explicit_exclude_and_git_always_win(self):
        root = make_tree({"a.py": "x = 1\n", ".git/config": "[core]\n",
                          "node_modules/p/i.js": "eval(p)\n", "gen/g.py": "eval(g)\n"})
        self.addCleanup(shutil.rmtree, root, True)
        res = core.scan_project(root, exclude=["gen", "node_modules"], include_deps=True)
        skipped = sorted(i["file"] for i in res["issues"] if i["rule"] == "Q-SKIPPED-TREE")
        self.assertEqual(skipped, [".git", "gen", "node_modules"])


class RootRelativePaths(unittest.TestCase):
    def test_skipped_tree_paths_are_root_relative(self):
        parent = tempfile.mkdtemp(prefix="lz-review-rel-")
        self.addCleanup(shutil.rmtree, parent, True)
        proj = os.path.join(parent, "proj")
        for rel, text in {"a.py": "x = 1\n", "app/vendor/modules.txt": "",
                          "app/vendor/x.py": "x = 2\n"}.items():
            os.makedirs(os.path.dirname(os.path.join(proj, rel)), exist_ok=True)
            with open(os.path.join(proj, rel), "w", encoding="utf-8") as fh:
                fh.write(text)
        for target, cwd in (("proj", parent), (".", proj), ("./proj/", parent)):
            with self.subTest(target=target):
                p, report = run_cli(target, cwd=cwd)
                self.assertEqual(p.returncode, 0, p.stderr)
                skipped = [i["file"].replace(os.sep, "/") for i in report["issues"]
                           if i["rule"] == "Q-SKIPPED-TREE"]
                self.assertEqual(skipped, ["app/vendor"])


class BuildOutputsAreScanned(unittest.TestCase):
    def test_dist_and_migrations(self):
        root = make_tree({"dist/b.js": "eval(x)\n", "migrations/1.sql": "GRANT ALL ON a TO b;\n",
                          "build/c.py": "eval(y)\n"})
        self.addCleanup(shutil.rmtree, root, True)
        files = by_file(core.scan_project(root))
        self.assertIn("S-EVAL-JS", files["dist/b.js"])
        self.assertIn("SQL-GRANT-ALL", files["migrations/1.sql"])
        self.assertIn("S-EVAL-PY", files["build/c.py"])


if __name__ == "__main__":
    unittest.main()
