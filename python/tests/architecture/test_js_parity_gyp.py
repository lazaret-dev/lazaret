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


if __name__ == "__main__":
    unittest.main()
