"""Review fix: source text is read in Unicode 13.0 on every Python and Node.

Python's re and unicodedata, and Node's regexes and ICU, classify code points
by the Unicode version they were built with. U+10D4A (Unicode 16) is a letter
on Python 3.14 and Node 22 and unassigned on 3.10-3.13, so `\\U00010d4a` +
`eval(x)` in a .py file was S-EVAL-PY on 3.11-3.13 only (\\b before eval), and
a JS `\\u200d` escape was an identifier character in npm and on 3.13+ only.

For the code points Unicode 13.0 (Python 3.10's) assigns, \\w, \\d, \\s and
NFKC are the same on every supported Python and Node (identifier characters
too, but for the four in core._LATER_ID_CONTINUE), so both engines map every
code point Unicode 13.0 leaves unassigned to U+FFFD before scanning a source
file (lazaret.scanner._unicode13, generated with its JS twin by
scripts/make_unicode_tables.py). Later letters are therefore not word
characters anywhere: the scan fails closed on them (they are a SyntaxError on
3.10 in any case). All input is inert.
"""
import os
import unicodedata
import unittest

from tests import _support
from lazaret.scanner import _unicode13, core

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "make_unicode_tables.py")


def rules_at(issues):
    return sorted((i["rule"], i["line"]) for i in issues)


class UnicodeTableTests(unittest.TestCase):
    def test_generated_tables_are_current(self):
        gen = _support.load_script(SCRIPT, "make_unicode_tables")
        self.assertEqual(gen.main(["--check"]), 0, "run python3 scripts/make_unicode_tables.py")

    @unittest.skipUnless(unicodedata.unidata_version == "13.0.0", "needs Unicode 13.0 (Python 3.10)")
    def test_the_table_is_unicode_13(self):
        for cp in range(0x110000):
            want = 0xD800 <= cp <= 0xDFFF or unicodedata.category(chr(cp)) != "Cn"
            if _unicode13.assigned(cp) != want:
                self.fail(f"U+{cp:04X}")

    def test_what_unicode_13_assigns_stays_assigned(self):
        for cp in range(0x110000):
            if _unicode13.assigned(cp) and not 0xD800 <= cp <= 0xDFFF and unicodedata.category(chr(cp)) == "Cn":
                self.fail(f"U+{cp:04X}")


class PinnedScanTests(unittest.TestCase):
    def test_later_letters_are_no_word_characters(self):
        src = "\U00010d4aeval(x)\nexec\U00010d4a(y)\n"
        self.assertEqual(rules_at(core.scan_file("u.py", src, "py")), [("S-EVAL-PY", 1)])

    def test_js_escapes_decode_the_same_everywhere(self):
        src = "a = 1;\n\\u{10D4A}eval(x)\n\\u200deval(y)\n\\u30fbeval(z)\n"
        # line 3's invisible U+200D glued to eval is also a look-alike name (SC-HOMOGLYPH)
        self.assertEqual(rules_at(core.scan_file("u.js", src, "js")),
                         [("S-EVAL-JS", 2), ("S-EVAL-JS", 3), ("S-EVAL-JS", 4), ("SC-HOMOGLYPH", 3)])

    def test_snippets_show_the_replacement_character(self):
        (issue,) = core.scan_file("s.py", "x = eval(y)  # \U0001fae0 \U0001f600\n", "py")
        self.assertEqual(issue["snippet"][0], "x = eval(y)  # � \U0001f600")
        m = core.compute_metrics([{"path": "s.py", "lang": "py", "content": "x = 1  # \U0001fae0\n"}])
        self.assertEqual((m["ncloc"], m["comments"]), (1, 0))


if __name__ == "__main__":
    unittest.main()
