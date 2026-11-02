"""--show-secrets: a finding's flagged line unredacted on the terminal, and nowhere else.

Every finding is redacted where it is made (the one redactor: the engine's), so a secret finding's line is a
placeholder on the terminal too. John asked (Oct 15) for a flag that shows the credentials interactively, on project
scans, the commit hook and registry scans: `--show-secrets` keeps each finding's flagged line as it was read, apart
from the result (core.flagged_lines), and the terminal's excerpt prints it. The result, the JSON, HTML and SARIF
reports, the baseline and the registry's store stay redacted. It works only when the output is a terminal: asked for
elsewhere (a pipe, a file, a CI log), a note says the credentials stay redacted.

The credentials are made up and built in pieces (test_fixture_credentials); nothing is contacted.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest

from lazaret.registry import repo
from lazaret.scanner import _native, core, hook

TOKEN = "gh" + "p_" + "a1B2" * 9
LINE = f'const token = "{TOKEN}";'
GIT = shutil.which("git")


class Terminal(io.StringIO):
    def isatty(self):
        return True


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-show-")
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return root


class AskedTests(unittest.TestCase):
    def test_only_on_a_terminal(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertFalse(core.show_secrets_on(False, Terminal()))
            self.assertTrue(core.show_secrets_on(True, Terminal()))
            self.assertEqual(err.getvalue(), "")
            self.assertFalse(core.show_secrets_on(True, io.StringIO()))
        self.assertEqual(err.getvalue().strip(), core.SHOW_SECRETS_NOT_A_TERMINAL)

    def test_flagged_lines(self):
        entries = [{"path": "a.js", "content": "x\r\ny\u2028z", "lang": "js"}, {"path": "b", "content": "p\nq"},
                   {"path": "c", "content": None}]
        issues = [{"file": "a.js", "line": 3}, {"file": "a.js", "line": 4}, {"file": "b", "line": 2},
                  {"file": "c", "line": 1}, {"file": "d", "line": 1}, {"file": "b", "line": 0}, {"file": "b"}]
        self.assertEqual(core.flagged_lines(issues, entries), {("a.js", 3): "z", ("b", 2): "q"})


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ProjectScanTests(unittest.TestCase):
    def setUp(self):
        self.root = tree({"app.js": f"// settings\n{LINE}\n", "package.json": '{"name": "x"}\n'})
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_the_result_stays_redacted(self):
        shown = {}
        res = core.scan_project(self.root, shown=shown)
        found = [i for i in res["issues"] if i["rule"] == "S-TOKEN"]
        self.assertEqual([(i["file"], i["line"]) for i in found], [("app.js", 2)])
        self.assertEqual(shown[("app.js", 2)], LINE)
        self.assertNotIn(TOKEN, json.dumps(res))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            core.print_report(res, False, shown)
        self.assertIn(TOKEN, out.getvalue())                        # the terminal's excerpt, unredacted
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            core.print_report(res, False)
        self.assertNotIn(TOKEN, out.getvalue())

    def run_main(self, *args, terminal):
        out, err = (Terminal() if terminal else io.StringIO()), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                core.main([self.root, "--out-dir", self.root, "--force-overwrite", *args])
            except SystemExit:
                pass
        with open(os.path.join(self.root, "lazaret-report.json"), encoding="utf-8") as fh:
            report = fh.read()
        with open(os.path.join(self.root, "lazaret-report.html"), encoding="utf-8") as fh:
            report += fh.read()
        return out.getvalue(), err.getvalue(), report

    def test_the_cli(self):
        saved = core.REDACT_SECRETS
        self.addCleanup(setattr, core, "REDACT_SECRETS", saved)
        out, err, report = self.run_main("--show-secrets", terminal=True)
        self.assertIn(TOKEN, out)
        self.assertNotIn(TOKEN, report)
        self.assertNotIn(core.SHOW_SECRETS_NOT_A_TERMINAL, err)
        out, err, report = self.run_main("--show-secrets", terminal=False)
        self.assertNotIn(TOKEN, out + report)
        self.assertIn(core.SHOW_SECRETS_NOT_A_TERMINAL, err)
        out, err, report = self.run_main(terminal=True)
        self.assertNotIn(TOKEN, out + report)


@unittest.skipUnless(GIT, "git is not installed")
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class HookTests(unittest.TestCase):
    def test_the_staged_line(self):
        root = tree({"app.js": f"{LINE}\n"})
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        for args in (["init", "-q"], ["config", "user.email", "t@x.invalid"], ["config", "user.name", "t"],
                     ["add", "app.js"]):
            subprocess.run(["git", "-C", root, *args], check=True, capture_output=True)
        for show in (True, False):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = hook.run([], cwd=root, show_secrets=show)
            self.assertEqual(code, core.EXIT_GATE)
            self.assertIn("[S-TOKEN]", out.getvalue())
            self.assertEqual(TOKEN in out.getvalue(), show)


def tgz(files, root="package"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in sorted(files.items()):
            raw = text.encode("utf-8")
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RegistryTests(unittest.TestCase):
    def test_an_archive_member(self):
        data = tgz({"package.json": '{"name": "x", "version": "1.0.0", "main": "index.js"}\n',
                    "index.js": f"module.exports = 1;\n{LINE}\n"})
        shown = {}
        budget = repo.Budget(deadline=time.monotonic() + 60, deadline_detail="the test's budget")
        r = repo._scan_artifact(data, "tgz", "npm", False, budget, shown=shown)
        found = [i for i in r["issues"] if i["rule"] == "S-TOKEN"]
        self.assertEqual(len(found), 1)
        self.assertEqual(shown[(found[0]["file"], found[0]["line"])], LINE)
        self.assertNotIn(TOKEN, json.dumps(r))
        out = io.StringIO()
        res = {"ecosystem": "npm", "name": "x", "version": "1.0.0", "verdict": r["verdict"],
               "verdictReason": r["verdictReason"], "profile": "supply-chain", "filesScanned": r["filesScanned"],
               "archiveBytes": len(data), "sevCounts": {s: 0 for s in core.SEV_ORDER}, "supplyChain": 0,
               "issues": found}
        with contextlib.redirect_stdout(out):
            repo.print_scan(res, shown=shown)
        self.assertIn(TOKEN, out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            repo.print_scan(res)
        self.assertNotIn(TOKEN, out.getvalue())

    def test_the_scan_command_flag(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertFalse(core.show_secrets_on(True, io.StringIO()))
        self.assertIn("--show-secrets", err.getvalue())
        self.assertFalse(repo.SHOW_SECRETS)


if __name__ == "__main__":
    unittest.main()
