"""The dashboard redacts credentials like the CLI, and its export can't be
mistaken for a CLI report.

Before: "Export report (JSON)" wrote every snippet raw (a pasted AWS key or
password went straight into the file) as lazaret-report.json, the CLI's
default report name, with a different schema. Runs the page's own script in
node:vm (see _dashboard_vm.py). All credentials below are dummies."""

import json
import os
import tempfile
import unittest

from lazaret.scanner import reports
from tests.scanner import _dashboard_vm as dash

AWS = "AKIAIOSFODNN7ABCDEFG"
PASSWORD = "Xk9#mQ2vLp8zR4tW"
LITERAL = "q8Z3vN5mR1tY7wK2pL9xB4cJ6hF0dS"          # flagged by the entropy rule
GH_TOKEN = "gho_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
PEM_BODY = ["MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
            "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK"]
SECRETS = [AWS, PASSWORD, LITERAL, GH_TOKEN, "hunter2", "s3cr3tpw"] + PEM_BODY

PY = "\n".join([
    "import os",
    f'AWS = "{AWS}"',
    f'DB_PASSWORD = "{PASSWORD}"',
    f'token_value = "{LITERAL}"',
    f'client.connect("{LITERAL}")',            # the literal again, where no rule flags it
    "os.system(cmd)",                          # its snippet shows the two lines above
    f'headers = {{"Authorization": "{GH_TOKEN}"}}',
    "os.system(cmd2)",
    'KEY = """-----BEGIN RSA PRIVATE KEY-----',
    PEM_BODY[0],
    PEM_BODY[1],
    '-----END RSA PRIVATE KEY-----"""',
    "eval(user_input)",                        # its snippet shows PEM body lines
    "",
])
SQL = "\n".join([
    "create user app identified by 'hunter2';",
    "grant all privileges on app.* to 'app'@'%';",
    "alter role app with password 's3cr3tpw';",
    "grant select on app.logs to public;",
    "",
])


def leaks(text):
    return [s for s in SECRETS if s in text]


@dash.requires_node
class DashboardRedactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = [{"name": "app.py", "content": PY}, {"name": "users.sql", "content": SQL}]
        cls.result, cls.export = dash.run([{"op": "runScan", "files": files}, {"op": "export"}])

    def issues(self, rule=None, file=None):
        return [i for i in self.result["issues"]
                if (rule is None or i["rule"] == rule) and (file is None or i["file"] == file)]

    def test_nothing_secret_survives_in_the_result(self):
        self.assertTrue(self.issues("S-TOKEN") and self.issues("SQL-CRED") and self.issues("S-ENTROPY"))
        self.assertEqual(leaks(json.dumps(self.result)), [])

    def test_flagged_lines_get_the_cli_placeholder(self):
        for rule in ("S-TOKEN", "S-SECRET", "SQL-CRED", "S-ENTROPY"):
            for issue in self.issues(rule):
                flagged = issue["snippet"][issue["line"] - issue["snipStart"]]
                self.assertRegex(flagged, r"^\[redacted: secret rule %s\] \(\d+ chars\)$" % rule)

    def test_context_lines_pem_blocks_and_repeated_literals(self):
        (cmd,) = [i for i in self.issues("S-OSCMD-PY") if i["line"] == 6]
        self.assertEqual(cmd["snippet"][:2], ['token_value = "[redacted]"',    # the entropy finding's line
                                              'client.connect("[redacted]")'])  # the literal, reused unflagged
        (ev,) = self.issues("S-EVAL-PY")
        self.assertEqual(ev["snippet"][:2], ["[redacted]", "[redacted]"])        # PEM body line + END line
        (cmd2,) = [i for i in self.issues("S-OSCMD-PY") if i["line"] == 8]
        self.assertIn('"Authorization": "[redacted]"', cmd2["snippet"][1])

    def test_sql_credentials_are_matched_case_insensitively(self):
        (grant,) = self.issues("SQL-GRANT-ALL")
        self.assertNotIn("hunter2", "\n".join(grant["snippet"]))
        self.assertIn("create user app [redacted];", grant["snippet"])

    def test_messages_are_swept(self):
        (issue,) = dash.run([{"op": "eval", "expr":
            f'mkIssue({{id:"X-TEST", name:"n", type:"VULN", sev:"MAJOR", msg:"key {AWS} seen",'
            f' why:"", fix:"", ref:""}}, {{name:"a.py", lang:"py"}}, 1, ["x = 1"])'}])
        self.assertEqual(issue["msg"], "key [redacted] seen")

    def test_export_is_redacted_and_distinct_from_cli_reports(self):
        self.assertEqual(self.export["filename"], "lazaret-dashboard-export.json")
        self.assertNotEqual(self.export["filename"], reports.JSON_REPORT_NAME)
        self.assertEqual(leaks(self.export["text"]), [])
        data = json.loads(self.export["text"])
        self.assertEqual(next(iter(data)), "generatedBy")                    # first key, like the CLI's
        self.assertEqual(data["generatedBy"], "lazaret-dashboard-1")
        self.assertNotEqual(data["generatedBy"], reports.ENGINE_VERSION)
        with tempfile.TemporaryDirectory() as d:                             # never "ours" to the CLI
            path = os.path.join(d, reports.JSON_REPORT_NAME)
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.export["text"])
            self.assertFalse(reports.is_our_report(path, "json"))


if __name__ == "__main__":
    unittest.main()
