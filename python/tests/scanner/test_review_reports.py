"""Review items 8 and 9: report emitters.

8. SARIF: artifactLocation.uri was the raw path ("my dir/a#1%2.py" verbatim,
   so '#' started a fragment); there was no uriBaseId/originalUriBaseIds; the
   driver claimed version "2.0.0" and informationUri example.invalid. Now:
   percent-encoded relative references against %SRCROOT% (the scan root as a
   file: URI), lazaret.__version__, https://lazaret.dev. The log is checked
   against the SARIF 2.1.0 required fields below (stdlib only: no jsonschema).
9. The HTML report header still said "CodeGuard"; no report output may.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

import lazaret
from tests import _support
from lazaret.scanner import core

PY = sys.executable
LEVELS = {"none", "note", "warning", "error"}
# RFC 3986 URI-reference characters (after percent-encoding)
URI_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*$")


def validate_sarif(test, log):
    """Required structure of a SARIF 2.1.0 log (sarif-schema-2.1.0 'required'
    lists plus the constraints GitHub code scanning enforces)."""
    test.assertEqual(log["version"], "2.1.0")
    test.assertIsInstance(log.get("$schema"), str)
    test.assertIsInstance(log["runs"], list)
    for run in log["runs"]:
        driver = run["tool"]["driver"]
        test.assertIsInstance(driver["name"], str)
        rules = driver.get("rules", [])
        ids = [r["id"] for r in rules]
        test.assertEqual(len(ids), len(set(ids)), "rule ids must be unique")
        for r in rules:
            test.assertIsInstance(r["id"], str)
            for key in ("shortDescription", "fullDescription", "help"):
                if key in r:
                    test.assertIsInstance(r[key]["text"], str)
        bases = run.get("originalUriBaseIds", {})
        for name, loc in bases.items():
            parsed = urllib.parse.urlsplit(loc["uri"])
            test.assertTrue(parsed.scheme, "a base URI must be absolute")
            test.assertTrue(loc["uri"].endswith("/"), "a base URI must end with '/'")
        for res in run["results"]:
            test.assertIsInstance(res["message"]["text"], str)
            test.assertIn(res["level"], LEVELS)
            if "ruleIndex" in res:
                test.assertEqual(ids[res["ruleIndex"]], res["ruleId"])
            test.assertIn(res["ruleId"], ids)
            for loc in res.get("locations", []):
                art = loc["physicalLocation"]["artifactLocation"]
                test.assertRegex(art["uri"], URI_CHARS)
                test.assertNotIn("#", art["uri"])
                for m in re.finditer("%", art["uri"]):
                    test.assertRegex(art["uri"][m.start():m.start() + 3], r"^%[0-9A-F]{2}$")
                if "uriBaseId" in art:
                    test.assertIn(art["uriBaseId"], bases)
                    test.assertFalse(urllib.parse.urlsplit(art["uri"]).scheme)
                region = loc["physicalLocation"].get("region", {})
                if "startLine" in region:
                    test.assertIsInstance(region["startLine"], int)
                    test.assertGreaterEqual(region["startLine"], 1)


def make_tree(files):
    root = tempfile.mkdtemp(prefix="lz-review-rep-")
    for rel, data in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data)
    return root


class Sarif(unittest.TestCase):
    def setUp(self):
        files = {"my dir/a#1%2.py": "eval(input())\n", "ok.py": "x = 1\n",
                 "node_modules/m/i.js": "x\n"}
        if os.name == "posix":              # ':' and '?' are not valid in Windows names
            files.update({"d/ü?.js": "eval(location.hash)\n", "c:x.py": "eval(y)\n"})
        self.root = make_tree(files)
        self.addCleanup(shutil.rmtree, self.root, True)
        self.out = tempfile.mkdtemp(prefix="lz-review-out-")
        self.addCleanup(shutil.rmtree, self.out, True)
        p = subprocess.run([PY, _support.CLI, self.root, "--out-dir", self.out, "--sarif",
                            os.path.join(self.out, "r.sarif")],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr)
        with open(os.path.join(self.out, "r.sarif"), encoding="utf-8") as fh:
            self.log = json.load(fh)

    def test_structure(self):
        validate_sarif(self, self.log)

    def test_driver_identity(self):
        driver = self.log["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["version"], lazaret.__version__)
        self.assertEqual(driver["informationUri"], "https://lazaret.dev")

    def test_uris_are_encoded_and_root_relative(self):
        run = self.log["runs"][0]
        base = run["originalUriBaseIds"]["%SRCROOT%"]["uri"]
        self.assertTrue(base.startswith("file:"))
        if os.name == "posix":
            self.assertEqual(urllib.parse.unquote(urllib.parse.urlsplit(base).path),
                             os.path.abspath(self.root) + "/")
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in run["results"]}
        self.assertIn("my%20dir/a%231%252.py", uris)
        self.assertIn("node_modules", uris)              # Q-SKIPPED-TREE, root-relative
        if os.name == "posix":
            self.assertIn("d/%C3%BC%3F.js", uris)
            self.assertIn("c%3Ax.py", uris)             # never read as a URI scheme
        for r in run["results"]:
            art = r["locations"][0]["physicalLocation"]["artifactLocation"]
            self.assertEqual(art["uriBaseId"], "%SRCROOT%")
            path = urllib.parse.unquote(art["uri"])
            self.assertTrue(os.path.lexists(os.path.join(self.root, path)), path)

    def test_helper(self):
        self.assertEqual(core.sarif_uri("a b/c#d.py"), ("a%20b/c%23d.py", "%SRCROOT%"))
        uri, base = core.sarif_uri(os.path.abspath("x y.py"))
        self.assertTrue(uri.startswith("file:"))
        self.assertIsNone(base)


class Branding(unittest.TestCase):
    def test_no_codeguard_in_any_output(self):
        root = make_tree({"a.py": "eval(x)\n", "b.js": "eval(y)\n", "c.sql": "GRANT ALL ON a TO b;\n",
                          "package.json": json.dumps({"scripts": {"postinstall": "node x.js"}})})
        self.addCleanup(shutil.rmtree, root, True)
        out = tempfile.mkdtemp(prefix="lz-review-out-")
        self.addCleanup(shutil.rmtree, out, True)
        p = subprocess.run([PY, _support.CLI, root, "--out-dir", out, "--sarif",
                            os.path.join(out, "r.sarif")],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr)
        outputs = {"stdout": p.stdout, "stderr": p.stderr}
        for name in os.listdir(out):
            with open(os.path.join(out, name), encoding="utf-8") as fh:
                outputs[name] = fh.read()
        self.assertEqual(set(outputs), {"stdout", "stderr", "lazaret-report.json",
                                        "lazaret-report.html", "r.sarif"})
        for name, text in outputs.items():
            self.assertNotIn("codeguard", text.lower(), name)
            self.assertNotIn("code guard", text.lower(), name)
        self.assertIn('class="logo">Laza<span>ret</span>', outputs["lazaret-report.html"])

    def test_no_codeguard_in_scanner_source(self):
        with open(core.__file__, encoding="utf-8") as fh:
            self.assertNotIn("codeguard", fh.read().lower())


if __name__ == "__main__":
    unittest.main()
