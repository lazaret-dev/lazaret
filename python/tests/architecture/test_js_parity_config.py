"""Engine parity for config and data files (audit P0): the Python CLI and the
npm CLI read the same files as config, find the same credentials in them and
report the same findings, metrics (configFiles), gate and exit code.

Each line of the S-SECRET tables in tests/scanner/test_config_secrets.py
becomes a file of its own, in the formats a value is written in (.env, YAML,
JSON, a Dockerfile), next to comment, marker and size cases. The expectations
themselves are in that module and js/test/config-secrets.test.js; this holds
the engines to each other. All content is inert (hosts are .invalid, every
credential is made up; the Slack and Discord webhook lines are text, never
contacted). Skipped where node is missing.
"""
import collections
import tempfile
import unittest

from tests.architecture.test_js_parity import DERIVED, NODE, both, derived, issue_key
from tests.architecture.test_js_parity_lexing import write_tree
from tests.scanner.test_config_secrets import PASS, QUIET, REPORTED, TOKEN

TREE = {}
for n, line in enumerate(REPORTED):
    TREE[f"reported/{n:02d}.yaml"] = f"# case {n}\n{line}\n"
for n, line in enumerate(QUIET):
    TREE[f"quiet/{n:02d}.env"] = f"{line}\n"
TREE.update({
    "forms/.env": f"A_PASSWORD={PASS}\nexport B_TOKEN='{PASS}'\n",
    "forms/Dockerfile": f"FROM scratch\nENV C_TOKEN={PASS}\nARG D_TOKEN\n",
    "forms/settings.jsonc": f'{{\n  // a comment\n  "e_password": "{PASS}",\n  "f": 1, // g_password={PASS}\n}}\n',
    "forms/app.properties": f"h.password={PASS}\n! not a comment in this reading\n",
    "forms/prod.tfvars": f'db_password = "{PASS}"\n',
    "forms/.pypirc": f"[pypi]\nusername = __token__\npassword = pypi-{PASS}{PASS}\n",
    "forms/run.sh": f"#!/bin/sh\ncurl -H 'Authorization: token {TOKEN}' https://api.invalid\n",
    "markers/.env": (f"A_TOKEN={PASS}  # nosec\nB_TOKEN={TOKEN}  # lazaret-ignore: S-SECRET\n"
                     f"# lazaret-ignore\nC_PASSWORD={PASS}\nD_PASSWORD={PASS} LABEL=\"# nosec\"\n"
                     f"E_PASSWORD={PASS} ; nosec\n"),
    "comments/app.yaml": f"# password: {PASS}\n  # token: {TOKEN}\nkey: value # api_key: {PASS}\n",
    "unicode/app.yaml": f"password: \"{PASS}é\"\ntoken: \"\U0001F600{PASS}\"\nsecret: {PASS} x\n",
    "crlf/.env": f"A_PASSWORD={PASS}\r\n# B_PASSWORD={PASS}\r\n".encode("utf-8"),
    "bom/app.yaml": b"\xef\xbb\xbf" + f"password: {PASS}\n".encode("utf-8"),
    "utf16/app.yaml": "﻿password: {}\n".format(PASS).encode("utf-16-le"),
    "long/app.yaml": "k: " + "a=" * 200_000 + f"\npassword: {PASS}\n",
})


@unittest.skipUnless(NODE, "node is not installed")
class ConfigParityTests(unittest.TestCase):
    maxDiff = None

    def test_config_tree(self):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, TREE)
            (js_exit, js, js_err), (py_exit, py, py_err) = both(root)
        self.assertIsNotNone(js, f"JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py, f"Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        js_c = collections.Counter(issue_key(i) for i in js["issues"])
        py_c = collections.Counter(issue_key(i) for i in py["issues"])
        self.assertEqual({"only the JS engine reports": sorted((js_c - py_c).elements()),
                          "only the Python engine reports": sorted((py_c - js_c).elements())},
                         {"only the JS engine reports": [], "only the Python engine reports": []},
                         "the engines disagree")
        self.assertEqual(js["metrics"], py["metrics"])
        for field in DERIVED:
            self.assertEqual(derived(js, field), derived(py, field), field)
        self.assertEqual(js_exit, py_exit)
        self.assertEqual(py["metrics"]["configFiles"], len(TREE))
        by_file = collections.defaultdict(set)
        for i in py["issues"]:
            by_file[i["file"].replace("\\", "/")].add((i["rule"], i["line"]))
        for n in range(len(REPORTED)):
            self.assertIn(("S-SECRET", 2), by_file[f"reported/{n:02d}.yaml"], REPORTED[n])
        self.assertEqual({f for f in by_file if f.startswith("quiet/")}, set())
        self.assertEqual(by_file["markers/.env"], {("S-TOKEN", 2), ("S-SECRET", 5), ("S-SECRET", 6)})
        self.assertEqual(by_file["comments/app.yaml"], {("S-TOKEN", 2)})
        self.assertEqual(by_file["crlf/.env"], {("S-SECRET", 1)})
        self.assertIn(("S-SECRET", 1), by_file["bom/app.yaml"])
        self.assertIn(("S-SECRET", 1), by_file["utf16/app.yaml"])
        self.assertIn(("S-SECRET", 2), by_file["long/app.yaml"])


if __name__ == "__main__":
    unittest.main()
