"""Engine parity for the project-scan robustness and report-integrity fixes.

Same comparison as test_js_parity (the helpers are imported from there): both
CLIs scan the same tree and must report the same findings, metrics, ratings,
gate and exit code. These trees are the review's reproductions; where a fix
is about what a snippet shows (redaction), the snippets are compared too.
All content is inert: nothing is executed, hosts are TEST-NET (192.0.2.x) or
.invalid, credentials are dummies. Skipped where Node isn't installed.
"""

import collections
import contextlib
import json
import os
import tempfile
import unittest

from tests.architecture import test_js_parity as parity

SEED = "q8Zr2LmX0vB7nTg4Wk1pYc9Hs6Jd3Fe5DUMMYVALUE9"
PEM_BODY = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"


@contextlib.contextmanager
def tree(files):
    """A temporary directory holding `files` (relative path -> str or bytes)."""
    with tempfile.TemporaryDirectory() as root:
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as f:
                f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        yield root


def snippets(report):
    """Every finding's key with its snippet (the Python-only ones left out)."""
    return collections.Counter(json.dumps([parity.issue_key(i), i["snipStart"], i["snippet"]])
                               for i in report["issues"] if not parity._python_only(i))


@unittest.skipUnless(parity.NODE, "node is not installed")
class CoreParityTests(unittest.TestCase):
    maxDiff = None
    assert_same = parity.EngineParityTests.assert_same

    def test_redaction_of_findings_built_outside_the_file_scan(self):
        files = {
            "settings.py": b"\xef\xbb\xbf# service settings\nSEED = \"" + SEED.encode() + b"\"\nDEBUG_LEVEL = 1\n",
            "u7.py": b"# -*- coding: utf-7 -*-\nSEED = \"" + SEED.encode() + b"\"\nx = 1\n",
            "keys.js": b"\xff\xfe" + ('const k = "-----BEGIN RSA PRIVATE KEY-----\n' + PEM_BODY + "\n" + PEM_BODY
                                      + '\n-----END RSA PRIVATE KEY-----";\n').encode("utf-16-le"),
            "app.py": ("import os\nfrom flask import request\n\n\ndef run(cmd):\n    os.system(cmd)\n\n\n"
                       "def view():\n    seed = \"" + SEED + "\"\n    run(request.args.get(\"c\"))\n"),
        }
        with tree(files) as root:
            js, py = parity.both(root)
            self.assert_same(js, py, label="redaction")
            self.assertEqual(snippets(js[1]), snippets(py[1]))
            for engine, (_, report, _) in (("js", js), ("py", py)):
                self.assertNotIn(SEED, json.dumps(report), engine)
                self.assertNotIn(PEM_BODY, json.dumps(report), engine)
            self.assertIn("X-CMD", {i["rule"] for i in py[1]["issues"]})


if __name__ == "__main__":
    unittest.main()
