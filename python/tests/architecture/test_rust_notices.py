"""The native engine's notices: since P-16 the engine is Lazaret's own work,
with Unicode data.

Until then parts of it were Rust translations of CPython code, distributed
under CPython's license: the port of sre (pyre/), the shell tokenizer
(hooks.rs), the Final_Sigma rule (unicode.rs) and re's case-fix table
(generated/unicode13.rs). They are retired. rust/NOTICE says so and lists
no translated file; no engine file carries CPython's license header or says
it is ported from CPython; the crates declare Apache-2.0 AND Unicode-3.0.
So do the packages that carry the engine (the wheels, the sdist, the npm
package): the codec names they hold outside the engine are what Python's
codecs answer to, facts about Python, not CPython's code, so none carries
CPython's license (they did in 0.1.8; js/NOTICE, test_notices.py).
"""

import os
import re
import unittest

from tests import _support

RUST = os.path.join(_support.REPO_ROOT, "rust")
SRC = os.path.join(RUST, "crates", "lazaret-engine", "src")
# the crates' license: Lazaret's, and the Unicode data of generated/unicode13.rs and pyparse/unidata.rs
CRATES = "Apache-2.0 AND Unicode-3.0"
# the packages' (python/_build, scripts/check_native_library.py): the same
PACKAGES = CRATES
PSF = "Copyright (c) 2001 Python Software Foundation; All Rights Reserved"
# the terms of the SRE library's notices, which went with pyre/
CNRI = "For any other use, please contact Secret Labs"


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as f:
        return f.read()


def engine_files():
    for crate in ("lazaret-engine", "lazaret-ffi"):
        base = os.path.join(RUST, "crates", crate)
        for root, _dirs, files in os.walk(base):
            for fn in files:
                if fn.endswith(".rs"):
                    yield os.path.relpath(os.path.join(root, fn), RUST), read(root, fn)


class NoticeTests(unittest.TestCase):
    def test_no_package_carries_cpythons_license(self):
        for rel in ("rust/LICENSE-PYTHON", "js/LICENSE-PYTHON", "python/LICENSE-PYTHON"):
            with self.subTest(rel):
                self.assertFalse(os.path.exists(os.path.join(_support.REPO_ROOT, *rel.split("/"))))
        notice = read(RUST, "NOTICE")
        self.assertNotIn("LICENSE-PYTHON", notice)
        self.assertNotIn("Python-2.0.1", notice)
        self.assertIn(f"Those packages are {PACKAGES} too.", " ".join(notice.split()))

    def test_the_notice_says_the_engine_is_lazarets_own(self):
        notice = read(RUST, "NOTICE")
        self.assertIn("is Lazaret's own work", notice)
        self.assertIn(f"the crates' license is {CRATES}.", " ".join(notice.split()))
        # the retired translations are named as history, not as parts of the engine
        history = notice.split("What was CPython's")[1].split("Unicode data")[0]
        self.assertIn("They are retired", history)
        for name in ("Lib/shlex.py", "Objects/unicodeobject.c", "Lib/re/_casefix.py", "Modules/_sre"):
            with self.subTest(name=name):
                self.assertEqual(notice.count(name), history.count(name))
        # no original's notice, no summary of changes, no SRE terms are left
        self.assertNotIn(PSF, notice)
        self.assertNotIn("Summary of the changes", notice)
        self.assertNotIn("Fredrik Lundh", notice)
        self.assertNotIn(CNRI, notice)
        self.assertIn("generated/unicode13.rs", notice.split("Unicode data")[1])

    def test_no_engine_file_carries_cpythons_license(self):
        for rel, text in engine_files():
            with self.subTest(file=rel):
                self.assertNotIn("Python-2.0.1", text)
                self.assertNotIn(PSF, text)
                self.assertNotIn("LICENSE-PYTHON", text)

    def test_no_engine_file_says_it_is_ported_from_cpython(self):
        """A translation of CPython code would need its notices and its
        license again: write from the documentation and Python's answers."""
        said = re.compile(r"(?i)(?:port(?:ed)?|translat\w*)\b[^.]{0,80}\b(?:CPython|_sre|sre_lib|"
                          r"_parser\.py|_compiler\.py|shlex\.py|unicodeobject)|CPython's \w+\.")
        for rel, text in engine_files():
            with self.subTest(file=rel):
                self.assertIsNone(said.search(text), "says it is translated from CPython")

    def test_the_crates_and_the_packages_declare_their_licenses(self):
        cargo = read(RUST, "Cargo.toml")
        self.assertRegex(cargo, rf'(?m)^license = "{re.escape(CRATES)}"$')
        backend = _support.load_script(os.path.join(_support.PY_ROOT, "_build", "lazaret_build.py"),
                                       "lazaret_build_for_notices")
        self.assertEqual(backend.NATIVE_LICENSE_EXPRESSION, PACKAGES)
        self.assertEqual({k: os.path.realpath(v) for k, v in backend.NATIVE_LICENSE_FILES.items()},
                         {"NOTICE": os.path.realpath(os.path.join(RUST, "NOTICE"))})
        self.assertNotIn("LICENSE-PYTHON", backend.RUST_TOP_FILES)
        check = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "check_native_library.py"),
                                     "check_native_library_for_notices")
        self.assertEqual(check.NATIVE_LICENSE_EXPRESSION, PACKAGES)
        self.assertEqual(check.NATIVE_LICENSE_FILES, tuple(backend.NATIVE_LICENSE_FILES))


if __name__ == "__main__":
    unittest.main()
