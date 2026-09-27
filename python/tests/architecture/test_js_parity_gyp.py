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
* binding.gyp literals: numbers keep Python's kind and digits (`1.0`,
  `12345678901234567890`, `-0.0` were `1 12345678901234567000 0` in the npm
  engine), `--1` is refused and `1+2j` accepted as ast.literal_eval does, and
  an int past 4300 digits no longer crashes core's scan.
* binding.gyp strings and containers: \\N{...} names, bytes kept apart from
  str (a b'action' key is no action), tuples, sets and non-str keys with
  their Python kinds, and \\r ending a comment or a line as Python's
  tokenizer reads it.
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
                           " 'include_dirs': [\"<!(node -e \\\"require('./donn\u00e9es')\\\")\",\n"
                           "                  \"<!(node -p \\\"require('caf\u00e9').include\\\")\"],\n"
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

NUMBER_TREE = {
    "a/binding.gyp": "{'action': ['echo', 1.0, 12345678901234567890, -0.0]}\n",
    "b/binding.gyp": "{'action': ['echo', 1.e5, 01.5, 0x_1F, 1e400, 9999999999999998.0, 1e16, 1e-5]}\n",
    "c/binding.gyp": "{'action': ['echo', 2j, -2j, 1+2j, 1.5-2.5j, -(1), 0x10+1j]}\n",
    "d/binding.gyp": '{"action": ["echo", 1, -0, 1.0, 2.50, 1E400, ' + "1" * 1200 + "]}\n",
    "e/binding.gyp": "{'action': ['echo', -0x" + "f" * 5000 + "]}\n",
    "binding.gyp": "{'targets': [{'actions': [{'action': ['echo', --1]}]}]}\n",       # root: unparseable
    "f/binding.gyp": "{'action': ['echo', 1+2j+3j]}\n",                                 # nested: nothing
    "index.js": "module.exports = 1;\n",
}

STRING_TREE = {
    "a/binding.gyp": ("{'action': ['caf\\N{LATIN SMALL LETTER E WITH ACUTE}', '\\N{latin small letter a}', "
                      "'x\\N{SP}y', '\\N{KELVIN SIGN}']}\n"),
    "b/binding.gyp": "{'action': ['\\N{LATIN SMALL LETTER C}url', 'x']}\n",
    "c/binding.gyp": "{'action': ['echo', # c\r 'x', '''a\r\nb''', 'a\\\r\nb']}\n",
    "d/binding.gyp": "{'action': ['echo', b'x', b'\\777', (1,), (), set(), {1: 'a', (2,): b'x'}]}\n",
    "e/binding.gyp": "{b'action': ['curl x'], ('action',): ['curl x'], ('<!(curl -s http://192.0.2.1/x)',): 1}\n",
    "f/binding.gyp": "{1: {'action': ['echo', 'one']}, '1': {'action': ['echo', 'two']}}\n",
    "binding.gyp": "{'action': ['echo', b'a' 'b']}\n",                                  # root: unparseable
    "g/binding.gyp": "{'action': ['echo', 'a\rb']}\n",                                   # nested: nothing
    "index.js": "module.exports = 1;\n",
}



def write_tree(root, files):
    for rel, text in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # newline="" writes the bytes as given: these fixtures embed CR and
        # CRLF on purpose, and text mode would turn every \n into \r\n on
        # Windows, corrupting them (the c/binding.gyp finding was then lost).
        with open(path, "w", encoding="utf-8", newline="") as f:
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

    def test_gyp_number_literals(self):
        issues = self.scan_both(NUMBER_TREE, "binding.gyp numbers")
        got = sorted((i["file"].replace("\\", "/"), i["rule"], i.get("cmd")) for i in issues)
        self.assertEqual(got, [
            ("a/binding.gyp", "SC-INSTALL-HOOK", "echo 1.0 12345678901234567890 -0.0"),
            ("b/binding.gyp", "SC-INSTALL-HOOK", "echo 100000.0 1.5 31 inf 9999999999999998.0 1e+16 1e-05"),
            ("binding.gyp", "SC-MANIFEST-UNPARSEABLE", None),
            ("c/binding.gyp", "SC-INSTALL-HOOK", "echo 2j (-0-2j) (1+2j) (1.5-2.5j) -1 (16+1j)"),
            ("d/binding.gyp", "SC-INSTALL-HOOK", "echo 1 0 1.0 2.5 inf inf"),
            ("e/binding.gyp", "SC-INSTALL-HOOK", "echo -0x" + "f" * 5000),
        ])

    def test_gyp_strings_and_containers(self):
        issues = self.scan_both(STRING_TREE, "binding.gyp strings")
        got = sorted((i["file"].replace("\\", "/"), i["rule"], i["sev"], i.get("cmd")) for i in issues)
        self.assertEqual(got, [
            ("a/binding.gyp", "SC-INSTALL-HOOK", "MAJOR",
             "caf\N{LATIN SMALL LETTER E WITH ACUTE} a x y \N{KELVIN SIGN}"),
            ("b/binding.gyp", "SC-INSTALL-HOOK", "CRITICAL", "curl x"),
            ("binding.gyp", "SC-MANIFEST-UNPARSEABLE", "MAJOR", None),
            ("c/binding.gyp", "SC-INSTALL-HOOK", "MAJOR", "echo x a\nb ab"),
            ("d/binding.gyp", "SC-INSTALL-HOOK", "MAJOR", "echo b'x' b'\\xff' (1,) () set() {1: 'a', (2,): b'x'}"),
            ("e/binding.gyp", "SC-INSTALL-HOOK", "CRITICAL", "curl -s http://192.0.2.1/x"),
            ("f/binding.gyp", "SC-INSTALL-HOOK", "MAJOR", "echo one"),
            ("f/binding.gyp", "SC-INSTALL-HOOK", "MAJOR", "echo two"),
        ])


if __name__ == "__main__":
    unittest.main()
