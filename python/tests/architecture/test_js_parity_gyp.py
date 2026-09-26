"""Engine parity for the supply-chain manifest scanners (package.json hooks,
binding.gyp), on inputs from the review of the npm engine's twins. Runs
both CLIs (helpers from test_js_parity) and requires the same findings, and
checks what both report. Skipped where Node isn't installed. All input is
inert: commands are strings that are never run.

* Hook commands are judged with Python regex semantics in both engines: the
  npm engine's patterns were plain JS regexes (ASCII \\w and \\b, JS \\s, ASCII
  case folding), so `baſe64` and `node\\x1c-e` were MAJOR there and CRITICAL
  in core, `éeval` the reverse, and a gyp include-path expansion requiring
  `./données` was CRITICAL there and benign in core.
* binding.gyp: at most GYP_MAX_HOOK_FINDINGS findings per file plus one
  summing up the rest, SC-TRUNCATED when a bound stops the walk, and an
  action reported on the line of its own "action" key.
"""

import os
import tempfile
import unittest

from tests.architecture import test_js_parity as parity

UNICODE_HOOKS = {
    "a/package.json": '{"name": "a", "scripts": {"postinstall": "echo ba\\u017fe64"}}',
    "b/package.json": '{"name": "b", "scripts": {"postinstall": "node\\u001c-e x"}}',
    "c/package.json": '{"name": "c", "scripts": {"postinstall": "echo \\u00e9eval x"}}',
    "native/binding.gyp": ("{'targets': [{'target_name': 'x',\n"
                           " 'include_dirs': [\"<!(node -e \\\"require('./données')\\\")\",\n"
                           "                  \"<!(node -p \\\"require('café').include\\\")\"],\n"
                           " 'actions': [{'action_name': 'gen', 'action': ['sh', 'gen.sh']}]}]}\n"),
    "index.js": "module.exports = 1;\n",
}


def _actions(n):
    rows = ",\n".join("    {'action_name': 'a', 'action': ['t%06d']}" % i for i in range(n))
    return "{'targets': [{'target_name': 'x', 'actions': [\n" + rows + "\n]}]}\n"


GYP_TREE = {
    "many/binding.gyp": _actions(300).replace("['t000250']", "['curl', 'http://192.0.2.1/x']"),
    "expansions/binding.gyp": "{'variables': {'v': '" + "<!(curl -s http://192.0.2.1/x)" * 150 + "'}}\n",
    "lines/binding.gyp": ("{\n 'targets': [{\n  'target_name': 'echo',\n  'sources': ['marker.cc'],\n"
                          "  'actions': [{\n   'action_name': 'gen', 'action': ['echo', 'marker']}]}]}\n"),
    "keys/binding.gyp": ("# c\n{'targets': [{'x': \"\"\"a\\rb\"\"\",\n 'action': ['echo', 'first'],\n"
                         " 'action': ['echo', 'second']},\n {('action'): ['echo', 'third']},\n"
                         " {'act'\n  'ion': ['echo', 'fourth']}]}\n"),
    "json/binding.gyp": ('{\n  "targets": [\n    {\n      "target_name": "echo",\n      "actions": [\n'
                         '        {"action_name": "a",\n         "action": ["echo", "one"]}\n      ]\n    }\n  ]\n}\n'),
    "big/binding.gyp": ("{'targets': [{'actions': [{'action': ['echo', 'marker']}]}],\n 'variables': {'list': ["
                        + "'v', " * 100000 + "]}}\n"),
    "long/binding.gyp": "{'v': '" + "<!(" * 20000 + "curl x'}\n",
    "index.js": "module.exports = 1;\n",
}


def write_tree(root, files):
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


@unittest.skipUnless(parity.NODE, "node is not installed")
class SupplyChainParityTests(unittest.TestCase):
    maxDiff = None

    def scan_both(self, files, label):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, files)
            js, py = parity.both(root)
            parity.EngineParityTests.assert_same(self, js, py, label=label)
            return py[1]["issues"]

    def test_unicode_hook_commands(self):
        issues = self.scan_both(UNICODE_HOOKS, "unicode hook commands")
        hooks = sorted((i["file"].replace("\\", "/"), i["line"], i["sev"]) for i in issues
                       if i["rule"] == "SC-INSTALL-HOOK")
        self.assertEqual(hooks, [("a/package.json", 1, "CRITICAL"), ("b/package.json", 1, "CRITICAL"),
                                 ("c/package.json", 1, "MAJOR"), ("native/binding.gyp", 4, "MAJOR")])

    def test_gyp_caps_truncation_and_lines(self):
        issues = self.scan_both(GYP_TREE, "binding.gyp caps and lines")

        def found(rel, rule="SC-INSTALL-HOOK"):
            return [i for i in issues if i["file"].replace("\\", "/") == rel and i["rule"] == rule]
        many = found("many/binding.gyp")
        self.assertEqual(len(many), 101)
        (summary,) = [i for i in many if i["msg"].startswith("200 more binding.gyp")]
        self.assertEqual((summary["sev"], summary["line"]), ("CRITICAL", 102))
        self.assertEqual(len(found("expansions/binding.gyp")), 101)
        self.assertEqual([i["line"] for i in found("lines/binding.gyp")], [6])
        self.assertEqual(sorted(i["line"] for i in found("keys/binding.gyp")), [4, 5, 6])
        self.assertEqual([i["line"] for i in found("json/binding.gyp")], [7])
        for rel in ("big/binding.gyp", "long/binding.gyp"):
            self.assertEqual(len(found(rel, "SC-TRUNCATED")), 1, rel)


if __name__ == "__main__":
    unittest.main()
