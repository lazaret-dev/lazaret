"""The native engine's notices: part of it is a Rust translation of CPython
code, distributed under CPython's license.

rust/NOTICE lists what was translated from where, summarizes the changes
(section 3 of the PSF License asks for that) and repeats the originals'
notices; rust/LICENSE-PYTHON is CPython 3.14.0's LICENSE, unchanged. Each
translated file names its source and carries its notices, and the crates and
the platform wheels (python/_build) declare both licenses. A file that comes
to say it is ported from CPython without them fails here.
"""

import hashlib
import os
import re
import unittest

from tests import _support

RUST = os.path.join(_support.REPO_ROOT, "rust")
SRC = os.path.join(RUST, "crates", "lazaret-engine", "src")
# the crates' and the platform wheels' license (with generated/unicode13.rs's Unicode data, 0.1.8) …
EXPRESSION = "Apache-2.0 AND Python-2.0.1 AND Unicode-3.0"
# … and a translated file's
FILE_EXPRESSION = "Apache-2.0 AND Python-2.0.1"
PSF = "Copyright (c) 2001 Python Software Foundation; All Rights Reserved"
# CPython v3.14.0's LICENSE: replace it only with another release's LICENSE, whole.
LICENSE_PYTHON_SHA256 = "b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231"
# file -> the Secret Labs line of what it translates (None: CPython's notice only)
TRANSLATED = {
    "pyre/parser.rs": ["Copyright (c) 1998-2001 by Secret Labs AB.  All rights reserved."],
    "pyre/compiler.rs": ["Copyright (c) 1997-2001 by Secret Labs AB.  All rights reserved."],
    "pyre/constants.rs": ["Copyright (c) 1998-2001 by Secret Labs AB.  All rights reserved."],
    "pyre/matcher.rs": ["Copyright (c) 1997-2001 by Secret Labs AB.  All rights reserved."],
    "pyre/mod.rs": ["Copyright (c) 1998-2001 by Secret Labs AB.  All rights reserved.",
                    "Copyright (c) 1997-2001 by Secret Labs AB.  All rights reserved."],
    "hooks.rs": [],
    "unicode.rs": [],
}
CNRI = ("This version of the SRE library can be redistributed under CNRI's\n"
        "Python 1.6 license.  For any other use, please contact Secret Labs\n"
        "AB (info@pythonware.com).")


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


def header(text):
    """The leading // comment block, without the comment marks."""
    lines = []
    for line in text.splitlines():
        if not line.startswith("//") or line.startswith("//!"):
            break
        lines.append(line[2:].strip())
    return "\n".join(lines)


class NoticeTests(unittest.TestCase):
    def test_license_python_is_cpythons_unchanged(self):
        with open(os.path.join(RUST, "LICENSE-PYTHON"), "rb") as f:
            data = f.read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), LICENSE_PYTHON_SHA256,
                         "rust/LICENSE-PYTHON is CPython 3.14.0's LICENSE file, unchanged")
        text = data.decode("ascii")
        for part in (PSF, "PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2", "CNRI LICENSE AGREEMENT FOR PYTHON 1.6.1"):
            self.assertIn(part, text)

    def test_the_notice_lists_every_translated_file(self):
        notice = read(RUST, "NOTICE")
        self.assertIn(PSF, notice)
        self.assertIn(EXPRESSION, notice)
        listed = set(re.findall(r"crates/lazaret-engine/src/(\S+\.rs)", notice))
        self.assertEqual(listed, set(TRANSLATED) | {"generated/unicode13.rs"})
        for source in ("Lib/re/__init__.py", "Lib/re/_parser.py", "Lib/re/_compiler.py", "Lib/re/_constants.py",
                       "Modules/_sre/sre_lib.h", "Modules/_sre/sre.c", "Objects/unicodeobject.c"):
            with self.subTest(source=source):
                self.assertIn(f"\n{source}", notice)                  # its notices are repeated
        self.assertIn("Summary of the changes", notice)

    def test_each_translated_file_carries_its_notices(self):
        for name, lines in TRANSLATED.items():
            with self.subTest(file=name):
                text = read(SRC, *name.split("/"))
                self.assertTrue(text.startswith(f"// SPDX-License-Identifier: {FILE_EXPRESSION}\n"))
                head = header(text)
                self.assertIn("rust/NOTICE", head)
                self.assertIn("rust/LICENSE-PYTHON", head)
                self.assertIn(PSF, head)
                for line in lines:
                    self.assertIn(line, head)
                if lines:
                    self.assertIn(CNRI, head)

    def test_no_other_file_says_it_is_ported_from_cpython(self):
        """A new translation gets a notice (and a line in rust/NOTICE)."""
        said = re.compile(r"(?i)(?:port(?:ed)?|translat\w*)\b[^.]{0,80}\b(?:CPython|_sre|sre_lib|"
                          r"_parser\.py|_compiler\.py|shlex\.py|unicodeobject)|CPython's \w+\.")
        for crate in ("lazaret-engine", "lazaret-ffi"):
            base = os.path.join(RUST, "crates", crate)
            for root, _dirs, files in os.walk(base):
                for fn in files:
                    if not fn.endswith(".rs"):
                        continue
                    rel = os.path.relpath(os.path.join(root, fn), SRC).replace(os.sep, "/")
                    text = read(root, fn)
                    if rel in TRANSLATED or rel == "generated/unicode13.rs":
                        continue
                    with self.subTest(file=os.path.relpath(os.path.join(root, fn), RUST)):
                        self.assertIsNone(said.search(text), "says it is translated from CPython: give it a "
                                                             "notice header and a line in rust/NOTICE")

    def test_the_crates_and_the_platform_wheels_declare_both_licenses(self):
        cargo = read(RUST, "Cargo.toml")
        self.assertRegex(cargo, rf'(?m)^license = "{re.escape(EXPRESSION)}"$')
        backend = _support.load_script(os.path.join(_support.PY_ROOT, "_build", "lazaret_build.py"),
                                       "lazaret_build_for_notices")
        self.assertEqual(backend.NATIVE_LICENSE_EXPRESSION, EXPRESSION)
        self.assertEqual({k: os.path.realpath(v) for k, v in backend.NATIVE_LICENSE_FILES.items()},
                         {"LICENSE-PYTHON": os.path.realpath(os.path.join(RUST, "LICENSE-PYTHON")),
                          "NOTICE": os.path.realpath(os.path.join(RUST, "NOTICE"))})
        check = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "check_native_library.py"),
                                     "check_native_library_for_notices")
        self.assertEqual(check.NATIVE_LICENSE_EXPRESSION, EXPRESSION)
        self.assertEqual(check.NATIVE_LICENSE_FILES, tuple(backend.NATIVE_LICENSE_FILES))


if __name__ == "__main__":
    unittest.main()
