"""Review: findings built outside scan_file leaked the file's secrets.

mk_issue redacts a snippet with the patterns AND the file's own entropy
literals (and its PEM blocks) only while scan_file's context is active.
redact_result, the sweep over the whole result, applies the pattern list
alone. So:

* Q-ENCODING / SC-UTF7 (built by encoding_issues while the walk decodes the
  file): a UTF-8-BOM settings.py with `SEED = "q8Zr…"` had that literal
  redacted in its S-ENTROPY snippet and shown raw in the Q-ENCODING one;
* the flow engine's X-* findings copy raw source lines into their snippets:
  the X-CMD snippet showed the same literal in the JSON and the HTML report,
  and key lines of a PEM block whose BEGIN line sat above the snippet.

encoding_issues now builds its findings with the file's own redactor (every
caller: the project walk, the registry and the MCP server), and scan_project
applies each file's literal set and file-wide PEM set to every finding
numbered by that file's scan lines that the engine's scan of it did not
build (redact_file_issues: the flows', the dependency checks'; the engine
redacts its own as mk_issue does). The npm engine and
the dashboard redact their Q-ENCODING / SC-UTF7 findings the same way.
Credentials here are dummies; nothing is executed.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from lazaret.scanner import core
from tests import _support
from tests.scanner import _dashboard_vm as dash

SEED = "q8Zr2LmX0vB7nTg4Wk1pYc9Hs6Jd3Fe5DUMMYVALUE9"
SETTINGS = b"\xef\xbb\xbf# service settings\nSEED = \"" + SEED.encode() + b"\"\nDEBUG_LEVEL = 1\n"
UTF7 = b"# -*- coding: utf-7 -*-\nSEED = \"" + SEED.encode() + b"\"\nx = 1\n"
FLOW = ("import os\nfrom flask import request\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\n"
        "def view():\n    seed = \"" + SEED + "\"\n    run(request.args.get(\"c\"))\n")
PEM_BODY = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"
PEM_FLOW = ("import os\nfrom flask import request\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\n"
            "KEY = \"\"\"-----BEGIN RSA PRIVATE KEY-----\n" + (PEM_BODY + "\n") * 3
            + "-----END RSA PRIVATE KEY-----\"\"\"\nrun(request.args.get(\"c\"))\n")


def write(root, rel, data):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def findings(res, rule):
    return [i for i in res["issues"] if i["rule"] == rule]


class ScanProjectTests(unittest.TestCase):
    def scan(self, tree, **kw):
        with tempfile.TemporaryDirectory() as root:
            for rel, data in tree.items():
                write(root, rel, data)
            return core.scan_project(root, **kw)

    def test_encoding_finding_redacts_the_files_literals(self):
        res = self.scan({"settings.py": SETTINGS})
        (enc,) = findings(res, "Q-ENCODING")
        self.assertEqual(enc["snippet"], ["# service settings", 'SEED = "[redacted]"', "DEBUG_LEVEL = 1"])
        self.assertEqual(len(findings(res, "S-ENTROPY")), 1)
        self.assertNotIn(SEED, json.dumps(res))

    def test_utf7_findings_redact_the_files_literals(self):
        res = self.scan({"u7.py": UTF7})
        self.assertEqual({i["rule"] for i in res["issues"]}, {"Q-ENCODING", "SC-UTF7", "S-ENTROPY"})
        for rule in ("Q-ENCODING", "SC-UTF7"):
            (issue,) = findings(res, rule)
            self.assertEqual(issue["snippet"][1], 'SEED = "[redacted]"', rule)
        self.assertNotIn(SEED, json.dumps(res))

    def test_encoding_issues_helper(self):
        """The registry and the MCP server call encoding_issues directly."""
        text, info = core.decode_source(SETTINGS, "py")
        (enc,) = core.encoding_issues("settings.py", text, info)
        self.assertEqual(enc["snippet"][1], 'SEED = "[redacted]"')

    def test_flow_finding_redacts_the_files_literals(self):
        res = self.scan({"app.py": FLOW})
        (flow,) = findings(res, "X-CMD")
        self.assertEqual(flow["snippet"][1], '    seed = "[redacted]"')
        self.assertNotIn(SEED, json.dumps(res))

    def test_flow_finding_redacts_pem_lines_whose_begin_is_above_the_snippet(self):
        res = self.scan({"app.py": PEM_FLOW})
        (flow,) = findings(res, "X-CMD")
        self.assertEqual(flow["line"], 14)
        self.assertEqual(flow["snippet"], ["[redacted]", "[redacted]", 'run(request.args.get("c"))', ""])
        self.assertNotIn(PEM_BODY, json.dumps(res))

    def test_only_what_the_engine_did_not_redact_is_swept(self):
        """The engine's scan of a file redacts its own findings as mk_issue does (the file's literals, its PEM
        blocks): the sweep takes the findings built outside it alone (the flows', the dependency checks'), as the
        npm package's redactFlowIssues does, and reads no other file again. The result is the same."""
        swept = []
        real = core.redact_file_issues

        def redact_file_issues(issues, files):
            swept.extend(issues)
            return real(issues, files)
        tree = {"app.py": FLOW, "near.py": "import os\nseed = \"" + SEED + "\"\neval(input())\n",
                "settings.py": SETTINGS}
        with mock.patch.object(core, "redact_file_issues", redact_file_issues):
            res = self.scan(tree)
        self.assertEqual(sorted({i["rule"] for i in swept}), ["X-CMD"])
        self.assertIn("S-EVAL-PY", {i["rule"] for i in res["issues"]})
        (ev,) = findings(res, "S-EVAL-PY")
        self.assertEqual(ev["snippet"][1], 'seed = "[redacted]"')            # (redacted by the engine)
        self.assertNotIn(SEED, json.dumps(res))

    def test_nothing_is_redacted_on_request(self):
        res = self.scan({"app.py": FLOW, "settings.py": SETTINGS}, redact_secrets=False)
        self.assertIn(SEED, findings(res, "X-CMD")[0]["snippet"][1])
        self.assertIn(SEED, findings(res, "Q-ENCODING")[0]["snippet"][1])

    def test_lines_their_builder_redacted_are_left_alone(self):
        issue = core.mk_issue({"id": "S-ENTROPY", "name": "n", "type": "HOTSPOT", "sev": "MAJOR", "msg": "m",
                               "why": "w", "fix": "f", "ref": "r"}, "a.py", 1, ['k = "' + SEED + '"', "-----END"])
        before = json.loads(json.dumps(issue))
        core.redact_file_issues([issue], [{"path": "a.py", "lang": "py", "content": 'k = "' + SEED + '"\n-----END'}])
        self.assertEqual(issue, before)
        self.assertTrue(issue["snippet"][0].startswith(core.REDACT_FINGERPRINT))


class ReportTests(unittest.TestCase):
    """The JSON and the HTML report, as the CLI writes them."""

    def test_reports_carry_no_literal(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            write(root, "settings.py", SETTINGS)
            write(root, "app.py", FLOW)
            p = subprocess.run([sys.executable, _support.CLI, root, "--out-dir", out, "--quiet"],
                               capture_output=True, encoding="utf-8", errors="replace", timeout=40)
            self.assertEqual(p.returncode, 0, p.stderr)
            for name in ("lazaret-report.json", "lazaret-report.html"):
                with open(os.path.join(out, name), encoding="utf-8") as f:
                    text = f.read()
                self.assertIn("X-CMD", text)
                self.assertIn("Q-ENCODING", text)
                self.assertNotIn(SEED, text, name)


@dash.requires_node
class DashboardTests(unittest.TestCase):
    def test_uploads_redact_like_the_cli(self):
        uploads = [("settings.py", SETTINGS), ("u7.py", UTF7),
                   ("le.js", b"\xff\xfe" + ('const k = "' + SEED + '";\n').encode("utf-16-le"))]
        (page,) = dash.run([{"op": "uploadScan", "files": [
            {"name": n, "b64": base64.b64encode(d).decode("ascii")} for n, d in uploads]}])
        key = lambda i: json.dumps(i, sort_keys=True, ensure_ascii=False)
        for (name, data), got in zip(uploads, page):
            with self.subTest(file=name):
                lang = core.EXTS[os.path.splitext(name)[1]]
                text, info = core.decode_source(data, lang)
                cli = core.encoding_issues(name, text, info) + core.scan_file(name, text, lang)
                self.assertEqual(sorted(map(key, got)), sorted(map(key, cli)))
                self.assertIn("Q-ENCODING", {i["rule"] for i in got})
                self.assertNotIn(SEED, json.dumps(got))


if __name__ == "__main__":
    unittest.main()
