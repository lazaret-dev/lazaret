"""Code that Node runs is scanned, or the scan is INCOMPLETE.

- A main, bin or hook target that was also read as a manifest (a .gyp or
  .gypi file, binding.gyp, pyproject.toml) was kept only as manifest text:
  _text_of() returned None for it without a finding, so `main:
  lib/core.gypi` holding a decode-and-exec payload was OK. It is scanned as
  what it is run as now.

Payloads are the inert DECODE_EXEC_*/EXFIL_JS markers of _review_support.
"""

import unittest

from lazaret.registry import repo
from tests.registry._review_support import (
    DECODE_EXEC_JS, EXFIL_JS, hooks, issues, manifest, scan_npm)


class ManifestNamedAsCodeTests(unittest.TestCase):
    def test_main_that_is_a_gyp_include_or_pyproject(self):
        for target in ("lib/core.gypi", "lib/core.gyp", "pyproject.toml"):
            with self.subTest(target=target):
                res = scan_npm({"package.json": manifest(main=target), target: DECODE_EXEC_JS})
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
                self.assertIn(target, {i["file"] for i in issues(res, "SC-EVAL-DECODE")})

    def test_bin_that_is_a_gyp_file(self):
        res = scan_npm({"package.json": manifest(bin={"x": "tools/x.gyp"}), "tools/x.gyp": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_hook_that_runs_a_gyp_file(self):
        res = scan_npm({"package.json": hooks(postinstall="node lib/setup.gypi"),
                        "lib/setup.gypi": EXFIL_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual(issues(res, "SC-INSTALL-HOOK")[0]["sev"], "CRITICAL")

    def test_a_gyp_include_that_is_only_a_manifest_is_not_code(self):
        res = scan_npm({"package.json": manifest(), "index.js": "module.exports = 1;\n",
                        "lib/core.gypi": "{'variables': {'x': 1}}\n"})
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        self.assertEqual(res["filesScanned"], 1)

    def test_package_json_named_as_main_is_data(self):
        res = scan_npm({"package.json": manifest(main="package.json")})
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
