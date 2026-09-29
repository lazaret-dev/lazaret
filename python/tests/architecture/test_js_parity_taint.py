"""Engine parity for taint (audit P0): the Python CLI and the npm CLI follow
values into f-strings and template literals, over the lines of a statement and
through augmented assignments, read the same sink arguments, Flask views and
guards, keep a taint where it lives, model the same frameworks (route
parameters, sinks, sanitizers, containers, allowlists) — and so report the
same T-* findings on every case of tests/scanner/test_taint_fstrings.py and
test_taint_frameworks.py, each written as a file of its own, next to
adversarial shapes (unterminated literals, deep brackets, astral characters,
CRLF, very long lines). Skipped where node is missing.
"""
import collections
import tempfile
import unittest

from tests.architecture.test_js_parity import DERIVED, NODE, _python_only, both, derived, issue_key
from tests.architecture.test_js_parity_lexing import write_tree
from tests.scanner.test_taint_fstrings import QUIET, REPORTED
from tests.scanner import test_taint_frameworks as frameworks

TREE = {}
for n, (lang, src, _) in enumerate(REPORTED):
    TREE[f"reported/r{n:02d}.{lang}"] = src
for n, (lang, src) in enumerate(QUIET):
    TREE[f"quiet/q{n:02d}.{lang}"] = src
for n, (lang, src, _) in enumerate(frameworks.REPORTED):
    TREE[f"frameworks/r{n:02d}.{lang}"] = src
for n, (lang, src) in enumerate(frameworks.QUIET):
    TREE[f"frameworks/q{n:02d}.{lang}"] = src
TREE.update({
    "odd/unterminated.py": "import os\nq = input()\nos.system(f'ls {q}\nos.system(\"a\" + q\n",
    "odd/unterminated.js": "const cp = require('child_process');\nconst q = process.argv[2];\ncp.exec(`ls ${q}\n",
    "odd/brackets.py": "import os\nq = input()\nos.system(" + "(" * 40 + "q" + ")" * 40 + ")\n"
                       "subprocess.run(\n" + "    [\n" * 12 + "q\n" + "]\n" * 12 + ")\n",
    "odd/astral.py": "import os\n\U0001F600 = 1\nq = input()  # \U0001F600\nos.system(f'\U0001F600 {q} \U0001F600')\n"
                     "open(f\"/srv/\U0001F600/{q}\")\n",
    "odd/astral.js": "const cp = require('child_process');\nconst q = process.argv[2]; // \U0001F600\n"
                     "cp.exec(`\U0001F600 ${q}`, () => {});\n",
    "odd/crlf.py": b"import os\r\nq = input()\r\nos.system(\r\n    f'ls {q}'\r\n)\r\n",
    "odd/long.py": "import os\nq = input()\nos.system('x' + " + "'a' + " * 3000 + "q)\n"
                   "subprocess.run(\n" + ("    'a' +\n" * 20) + "    q)\n",
    "odd/long.js": "const cp = require('child_process');\nconst q = process.argv[2];\ncp.exec(\n"
                   + ("  'a' +\n" * 20) + "  q);\n",
    "odd/tabs.py": "from flask import request\n@app.route('/a')\ndef a():\n\tq = request.args['q']\n\tif q:\n"
                   "\t\tq = 'x'\n\treturn q\n",
    "odd/decorators.py": "from flask import Flask, request\napp = Flask(__name__)\n@app.route(\n    '/a',\n"
                         "    methods=['GET', 'POST'],\n)\n@login_required\ndef a():\n"
                         "    return '<p>' + request.args['q']\n",
})


@unittest.skipUnless(NODE, "node is not installed")
class TaintParityTests(unittest.TestCase):
    maxDiff = None

    def test_taint_tree(self):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, TREE)
            (js_exit, js, js_err), (py_exit, py, py_err) = both(root)
        self.assertIsNotNone(js, f"JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py, f"Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        # the Python half of the flow engine (X-*, Q-FLOW-* on Python files)
        # is Python-only; where it reports, the derived fields may differ
        py_only = [i for i in py["issues"] if _python_only(i, project=py.get("project"))]
        js_c = collections.Counter(issue_key(i) for i in js["issues"])
        py_c = collections.Counter(issue_key(i) for i in py["issues"]
                                   if not _python_only(i, project=py.get("project")))
        self.assertEqual({"only the JS engine reports": sorted((js_c - py_c).elements()),
                          "only the Python engine reports": sorted((py_c - js_c).elements())},
                         {"only the JS engine reports": [], "only the Python engine reports": []},
                         "the engines disagree")
        self.assertEqual(js["metrics"], py["metrics"])
        if not py_only:
            for field in DERIVED:
                self.assertEqual(derived(js, field), derived(py, field), field)
            self.assertEqual(js_exit, py_exit)
        by_file = collections.defaultdict(set)
        for i in py["issues"]:
            if i["rule"].startswith("T-"):
                by_file[i["file"].replace("\\", "/")].add((i["rule"], i["line"]))
        for n, (lang, _, want) in enumerate(REPORTED):
            self.assertEqual(by_file[f"reported/r{n:02d}.{lang}"], want, n)
        for n, (lang, _, want) in enumerate(frameworks.REPORTED):
            self.assertEqual(by_file[f"frameworks/r{n:02d}.{lang}"], want, n)
        self.assertEqual({f for f in by_file if f.startswith(("quiet/", "frameworks/q"))}, set())


if __name__ == "__main__":
    unittest.main()
