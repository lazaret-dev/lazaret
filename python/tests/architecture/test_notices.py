"""The notices of the npm package and of the Unicode data (0.1.8).

The npm package's shell tokenizer (js/src/lib/hooks.js, shlexSplit) is a
translation of CPython's shlex, so the package carries CPython's LICENSE
(js/LICENSE-PYTHON, the same file as rust/LICENSE-PYTHON) and a NOTICE that
says what was translated and what changed, and declares Python-2.0.1. The
Unicode 13.0 tables (scanner/_unicode13.py, js/src/lib/unicode13.js, the
dashboard's copy, rust/…/generated/unicode13.rs) and the single-byte codec
tables (js/src/lib/codecs.js and the dashboard's copy) are Unicode data: each
carries the Unicode notice, every package that ships them carries the
Unicode License v3 (LICENSE-UNICODE, one text in python/, js/ and rust/) and
declares Unicode-3.0. (rust/: test_rust_notices.py.)
"""

import hashlib
import json
import os
import unittest

from tests import _support

ROOT = _support.REPO_ROOT
PSF = "Copyright (c) 2001 Python Software Foundation; All Rights Reserved"
UNICODE = "Copyright © 1991-2026 Unicode, Inc."
# The Unicode License v3 as unicode.org gives it (2026's copyright years); replace it only whole.
LICENSE_UNICODE_SHA256 = "e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96"
UNICODE_DATA = ("python/src/lazaret/scanner/_unicode13.py", "js/src/lib/unicode13.js", "js/src/lib/codecs.js",
                "rust/crates/lazaret-engine/src/generated/unicode13.rs")


def read(rel):
    with open(os.path.join(ROOT, *rel.split("/")), encoding="utf-8") as f:
        return f.read()


def raw(rel):
    with open(os.path.join(ROOT, *rel.split("/")), "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


class UnicodeNoticeTests(unittest.TestCase):
    def test_one_license_text_in_every_package(self):
        for rel in ("python/LICENSE-UNICODE", "js/LICENSE-UNICODE", "rust/LICENSE-UNICODE"):
            with self.subTest(rel):
                self.assertEqual(hashlib.sha256(raw(rel)).hexdigest(), LICENSE_UNICODE_SHA256)
                self.assertIn(UNICODE, read(rel))

    def test_the_tables_carry_the_notice(self):
        for rel in UNICODE_DATA:
            with self.subTest(rel):
                head = " ".join(read(rel)[:1500].replace("//", " ").split())     # (the words, across lines)
                self.assertIn(UNICODE, head)
                self.assertIn("Unicode License v3", head)
                self.assertIn("LICENSE-UNICODE", head)
        dashboard = read("python/src/lazaret/web/lazaret.html")
        for section in ("/* ======== lib/unicode13.js ======== */", "/* ======== lib/codecs.js ======== */"):
            with self.subTest(section):
                at = dashboard.index(section)
                self.assertIn(UNICODE, dashboard[at:at + 3000])


class NpmNoticeTests(unittest.TestCase):
    def test_the_shlex_translation_is_declared(self):
        self.assertEqual(raw("js/LICENSE-PYTHON"), raw("rust/LICENSE-PYTHON"))
        hooks = read("js/src/lib/hooks.js")
        self.assertTrue(hooks.startswith("// SPDX-License-Identifier: Apache-2.0 AND Python-2.0.1\n"))
        at = hooks.index("export function shlexSplit(")
        self.assertIn(PSF, hooks[at - 3000:at])
        notice = read("js/NOTICE")
        for part in (PSF, "src/lib/hooks.js", "Lib/shlex.py", "Summary of the changes", UNICODE,
                     "src/lib/unicode13.js", "src/lib/codecs.js", "LICENSE-PYTHON", "LICENSE-UNICODE",
                     "Apache-2.0 AND Python-2.0.1 AND Unicode-3.0"):
            with self.subTest(part):
                self.assertIn(part, notice)

    def test_the_package_ships_and_declares_them(self):
        pkg = json.loads(read("js/package.json"))
        self.assertEqual(pkg["license"], "Apache-2.0 AND Python-2.0.1 AND Unicode-3.0")
        for name in ("LICENSE", "LICENSE-PYTHON", "LICENSE-UNICODE", "NOTICE"):
            with self.subTest(name):
                self.assertIn(name, pkg["files"])
                self.assertTrue(os.path.isfile(os.path.join(ROOT, "js", name)))

    def test_no_other_npm_file_says_it_is_translated_from_cpython(self):
        """A new translation gets the notice too (and a line in js/NOTICE)."""
        import re
        said = re.compile(r"(?i)\b(?:port(?:ed)?|translat\w*)\b[^.\n]{0,80}\b(?:CPython|shlex\.py|_sre|"
                          r"sre_parse|unicodeobject)")
        for root, _dirs, files in os.walk(os.path.join(ROOT, "js", "src")):
            for fn in files:
                if not fn.endswith(".js") or fn == "hooks.js":
                    continue
                with open(os.path.join(root, fn), encoding="utf-8") as f:
                    text = f.read()
                with self.subTest(fn):
                    self.assertIsNone(said.search(text), "says it is translated from CPython: give it the "
                                                         "PSF notice and a line in js/NOTICE")


if __name__ == "__main__":
    unittest.main()
