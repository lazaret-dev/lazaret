"""Review fix: secrets no longer leak through context lines, msg or cmd.

README's L1 claim is that no credential reaches a report. The review found:
  * S-TOKEN on `-----BEGIN RSA PRIVATE KEY-----` redacted the header while the
    next two key lines shipped raw in its snippet;
  * an S-ENTROPY literal, redacted in its own finding, shipped raw in a
    neighbouring finding's snippet;
  * `identified by '…'` (lowercase) leaked through SQL-GRANT-ALL's context;
  * an install hook's GitHub PAT leaked through `msg` (terminal/JSON/HTML/
    SARIF) and the JSON `cmd` field.
Dummy credentials only; token-shaped strings are assembled at runtime.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import _support
from lazaret.scanner import core

KEY_BODY = ["MIIEowIBAAKCAQEAdummydummydummydummydummydummydummydummydumm",
            "VTLwdummydummydummydummydummydummydummydummydummydummydummyAB",
            "LxoSdummydummydummydummydummydummydummydummydummydummydummyCD"]
PEM = ['KEY = """-----BEGIN RSA PRIVATE KEY-----'] + KEY_BODY + ['-----END RSA PRIVATE KEY-----"""']
ENTROPY_LIT = "Zk3q9XvB2mT7pL4wR8sY1nC6hJ0dF5gA"


def pat(prefix):
    return prefix + "_" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def all_text(issues):
    return json.dumps(issues)


class PemBlockTests(unittest.TestCase):
    def test_token_snippet_redacts_the_whole_key(self):
        src = "\n".join(PEM) + "\n"
        issues = core.scan_file("keys.py", src, "py")
        tok = next(i for i in issues if i["rule"] == "S-TOKEN")
        self.assertEqual(tok["snippet"][1:], ["[redacted]"] * 2)
        for body in KEY_BODY:
            self.assertNotIn(body[4:20], all_text(issues))

    def test_neighbour_snippet_redacts_body_and_end(self):
        src = "\n".join(PEM + ["import os; os.system(input())"]) + "\n"
        issues = core.scan_file("keys.py", src, "py")
        cmd = next(i for i in issues if i["rule"] == "S-OSCMD-PY")
        self.assertEqual(cmd["line"], 6)
        self.assertEqual(cmd["snippet"][:2], ["[redacted]"] * 2)   # last body line, END line
        self.assertNotIn(KEY_BODY[2][4:20], all_text(issues))

    def test_unterminated_key_redacted_to_end_of_file(self):
        lines = PEM[:3] + ["x = 1"]
        self.assertEqual(core._pem_block_lines(lines), {1, 2, 3})

    def test_single_line_key_with_escaped_newlines(self):
        line = 'k = "-----BEGIN PRIVATE KEY-----\\nMIIEdummy\\n-----END PRIVATE KEY-----"; x = 1'
        self.assertEqual(core._redact_context_line(line), 'k = "[redacted]"; x = 1')
        self.assertEqual(core._pem_block_lines([line, "next"]), set())

    def test_foreign_snippet_sweep(self):
        res = {"issues": [{"rule": "X-SQL", "line": 5, "snipStart": 1, "msg": "m",
                           "snippet": PEM[:4] + ["run()"]}]}
        core.redact_result(res)
        self.assertEqual(res["issues"][0]["snippet"][1:4], ["[redacted]"] * 3)


class EntropyLiteralTests(unittest.TestCase):
    def test_literal_redacted_in_neighbouring_snippet(self):
        src = 'import os\nbuild_sig = "%s"\nos.system("uptime")\n' % ENTROPY_LIT
        issues = core.scan_file("ent.py", src, "py")
        self.assertIn("S-ENTROPY", {i["rule"] for i in issues})
        self.assertNotIn(ENTROPY_LIT, all_text(issues))
        cmd = next(i for i in issues if i["rule"] == "S-OSCMD-PY")
        self.assertEqual(cmd["snippet"][1], 'build_sig = "[redacted]"')

    def test_literal_redacted_where_it_is_reused(self):
        src = ('SIG = "%s"\nimport os\nos.system("curl -H x:%s example.invalid")\n'
               % (ENTROPY_LIT, ENTROPY_LIT))
        issues = core.scan_file("ent.py", src, "py")
        self.assertNotIn(ENTROPY_LIT, all_text(issues))

    def test_literal_index_substring_match(self):
        lits = core._SecretLiterals(['k = "%s"' % ENTROPY_LIT])
        self.assertEqual(lits.redact("u=x" + ENTROPY_LIT + "yz"), "u=x[redacted]yz")
        self.assertEqual(lits.redact("nothing here"), "nothing here")


class SqlCaseTests(unittest.TestCase):
    def test_lowercase_identified_by(self):
        src = "create user app identified by 'Sup3rS3cretPw!';\ngrant all privileges on appdb.* to app;\n"
        issues = core.scan_file("u.sql", src, "sql")
        self.assertIn("SQL-GRANT-ALL", {i["rule"] for i in issues})
        self.assertNotIn("Sup3rS3cretPw", all_text(issues))


class MessageAndCmdTests(unittest.TestCase):
    def manifest(self, token):
        return json.dumps({"name": "app", "scripts": {
            "prepare": "git clone https://%s@github.com/org/priv.git vendor-priv" % token}},
            indent=2)

    def test_hook_token_redacted_in_msg_and_cmd(self):
        for prefix in ("ghp", "gho", "ghu", "ghs", "ghr"):
            with self.subTest(prefix=prefix):
                token = pat(prefix)
                issues = core.scan_manifest("package.json", self.manifest(token))
                self.assertTrue(issues)
                self.assertNotIn(token, issues[0]["msg"])
                res = core.redact_result({"issues": issues})
                self.assertNotIn(token, all_text(res))
        fine_grained = "github_pat_" + "11ABCDEFG0" * 4
        self.assertEqual(core._redact_context_line(fine_grained), "[redacted]")

    def test_url_userinfo(self):
        self.assertEqual(core._redact_context_line("u = 'https://bob:hunter2@example.invalid/x'"),
                         "u = 'https://[redacted]@example.invalid/x'")

    def test_opt_out_keeps_raw_text(self):
        old = core.REDACT_SECRETS
        core.REDACT_SECRETS = False
        try:
            token = pat("ghp")
            issues = core.scan_manifest("package.json", self.manifest(token))
            self.assertIn(token, issues[0]["msg"])
        finally:
            core.REDACT_SECRETS = old

    def test_cli_reports_and_terminal_are_clean(self):
        tmp = tempfile.mkdtemp(prefix="lz-red-")
        self.addCleanup(shutil.rmtree, tmp, True)
        root, out = os.path.join(tmp, "proj"), os.path.join(tmp, "out")
        os.makedirs(root)
        os.makedirs(out)
        token = pat("ghp")
        with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as fh:
            fh.write(self.manifest(token))
        with open(os.path.join(root, "a.py"), "w", encoding="utf-8") as fh:
            fh.write('import os\nbuild_sig = "%s"\nos.system("uptime")\n' % ENTROPY_LIT)
        p = subprocess.run([sys.executable, _support.CLI, root, "--out-dir", out,
                            "--sarif", os.path.join(out, "r.sarif")],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        texts = [p.stdout, p.stderr]
        for name in ("lazaret-report.json", "lazaret-report.html", "r.sarif"):
            with open(os.path.join(out, name), encoding="utf-8") as fh:
                texts.append(fh.read())
        for t in texts:
            self.assertNotIn(token, t)
            self.assertNotIn(ENTROPY_LIT, t)
        self.assertIn("SC-INSTALL-HOOK", texts[2])


if __name__ == "__main__":
    unittest.main()
