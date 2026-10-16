"""The dashboard redacts credentials as the CLI does, always, and its export can't be mistaken for a CLI report.

Before: "Export report (JSON)" wrote every snippet raw (a pasted AWS key or password went straight into the file)
as lazaret-report.json, the CLI's default report name, with a different schema. The page redacts every finding
(the CLI's redaction: its findings are the CLI's, test_review_dashboard_parity; what is redacted and how is the
engine's, tests/scanner/test_review_redaction*.py), and exports under its own name and marker. Runs the page in
node:vm (see _dashboard_vm.py). All credentials below are dummies, built in pieces."""

import json
import os
import tempfile
import unittest

from lazaret.scanner import reports
from tests.scanner import _dashboard_vm as dash

AWS = "AKI\x41IOSFODNN7ABCDEFG"
PASSWORD = "Xk9#mQ2vLp8zR4tW"
LITERAL = "q8Z3vN5mR1tY7wK2pL9xB4cJ6hF0dS"          # flagged by the entropy rule
GH_TOKEN = "gho_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
PEM_BODY = ["MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun",
            "VTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK"]
CRATES = "cio" + "Zq8vN3pL0wX7rT2mK9sB4hF6jD1aE5cG"   # crates.io's API token shape (0.1.9, R-4)
SECRETS = [AWS, PASSWORD, LITERAL, GH_TOKEN, CRATES, "hunter2", "s3cr3tpw"] + PEM_BODY

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
    f'cargo_token = "{CRATES}"',               # S-TOKEN, and the next finding's context line
    "os.system(cmd3)",
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
        cls.files = [("app.py", PY), ("users.sql", SQL)]
        cls.result, cls.export = dash.run([dash.scan_request(cls.files), {"op": "export"}])

    def test_the_findings_are_the_clis_and_nothing_secret_survives(self):
        rules = {i["rule"] for i in self.result["issues"]}
        self.assertLessEqual({"S-TOKEN", "SQL-CRED", "S-ENTROPY", "S-SECRET"}, rules)
        self.assertEqual(dash.comparable(self.result, dash.PAGE_ONLY),
                         dash.comparable(dash.cli_result(self.files), dash.CLI_ONLY))
        self.assertEqual(leaks(json.dumps(self.result)), [])
        for issue in self.result["issues"]:
            if issue["rule"] in ("S-TOKEN", "S-SECRET", "SQL-CRED", "S-ENTROPY"):
                flagged = issue["snippet"][issue["line"] - issue["snipStart"]]
                self.assertRegex(flagged, r"^\[redacted: secret rule %s\] \(\d+ chars\)$" % issue["rule"])

    def test_export_is_redacted_and_distinct_from_cli_reports(self):
        self.assertEqual(self.export["filename"], "lazaret-dashboard-export.json")
        self.assertNotEqual(self.export["filename"], reports.JSON_REPORT_NAME)
        self.assertEqual(leaks(self.export["text"]), [])
        data = json.loads(self.export["text"])
        self.assertEqual(next(iter(data)), "generatedBy")                    # first key, like the CLI's
        self.assertEqual(data["generatedBy"], "lazaret-dashboard-2")
        self.assertNotEqual(data["generatedBy"], reports.ENGINE_VERSION)
        self.assertEqual(data, self.result)
        with tempfile.TemporaryDirectory() as d:                             # never "ours" to the CLI
            path = os.path.join(d, reports.JSON_REPORT_NAME)
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.export["text"])
            self.assertFalse(reports.is_our_report(path, "json"))


if __name__ == "__main__":
    unittest.main()
