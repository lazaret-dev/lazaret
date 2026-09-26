"""Code that Node runs is scanned, or the scan is INCOMPLETE.

- A main, bin or hook target that was also read as a manifest (a .gyp or
  .gypi file, binding.gyp, pyproject.toml) was kept only as manifest text:
  _text_of() returned None for it without a finding, so `main:
  lib/core.gypi` holding a decode-and-exec payload was OK. It is scanned as
  what it is run as now.
- _reachable() followed require()/import from the entry points to local
  files but never scanned what it found: index.js doing
  `require('./lib/core.dat')` left core.dat unscanned and the package OK.
  A file reached that way is scanned as JavaScript now (text of any
  extension), or counted as not scanned; an image, font or stylesheet that
  isn't text is a bundler asset (React Native's require('./icon.png')).

Payloads are the inert DECODE_EXEC_*/EXFIL_JS markers of _review_support.
"""

import unittest

from lazaret.registry import repo
from tests.registry._review_support import (
    DECODE_EXEC_JS, EXFIL_JS, hooks, issues, manifest, scan_npm)

PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 13 + b"\x00\x00\x00\x00IEND\xaeB`\x82"
BLOB = bytes((i * 7919) % 256 for i in range(4096))


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


class RequiredFilesTests(unittest.TestCase):
    def test_a_file_main_requires_is_scanned(self):
        res = scan_npm({"package.json": manifest(),
                        "index.js": "module.exports = require('./lib/core.dat');\n",
                        "lib/core.dat": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn("lib/core.dat", {i["file"] for i in issues(res, "SC-EVAL-DECODE")})
        self.assertEqual(res["filesScanned"], 2)

    def test_transitively_and_through_import(self):
        res = scan_npm({"package.json": manifest(main="lib/a.js"),
                        "lib/a.js": "import b from './b';\nexport default b;\n",
                        "lib/b.js": "const c = await import('../data/c.txt');\n",
                        "data/c.txt": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn("data/c.txt", {i["file"] for i in issues(res, "SC-EVAL-DECODE")})

    def test_a_hook_script_that_requires_one(self):
        res = scan_npm({"package.json": hooks(postinstall="node install.js"),
                        "install.js": "require('./lib/setup.bin');\n", "lib/setup.bin": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_one_that_is_not_text_is_incomplete(self):
        res = scan_npm({"package.json": manifest(), "index.js": "require('./lib/core.dat');\n",
                        "lib/core.dat": BLOB})
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertTrue(any("lib/core.dat runs at install/import time but is not text" in i["msg"]
                            for i in issues(res, "SC-TRUNCATED")))

    def test_a_stylesheet_that_is_text_is_scanned(self):
        res = scan_npm({"package.json": manifest(), "index.js": "require('./style.css');\n",
                        "style.css": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_bundler_assets_are_not_code(self):
        res = scan_npm({"package.json": manifest(main="lib/Header.js"),
                        "lib/Header.js": ("const icon = require('../assets/back-icon.png');\n"
                                          "import './Header.css';\nmodule.exports = icon;\n"),
                        "assets/back-icon.png": PNG,
                        "lib/Header.css": ".back { width: 24px; background: url(data:image/png;base64,"
                                          "iVBORw0KGgo=) }\n"})
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        self.assertEqual(res["filesScanned"], 2)          # Header.js and the stylesheet

    def test_json_and_native_addons_are_not_code(self):
        res = scan_npm({"package.json": manifest(),
                        "index.js": "require('./data.json');\nrequire('./build/addon');\n",
                        "data.json": "{}", "build/addon.node": b"\x7fELF\x02\x01\x01" + b"\0" * 64})
        self.assertNotEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
