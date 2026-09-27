"""Invisible-character payload (SC-HIDDEN-UNICODE; analyst gap: GlassWorm).

GlassWorm (Oct 2025, 150+ repos across npm and VS Code) hid its payload in a
run of variation selectors and decoded it with a codePointAt map into eval;
tag characters (U+E0000-E007F) smuggle instructions past a reviewer and an AI
alike. A run of two or more such invisible characters in code is
SC-HIDDEN-UNICODE: CRITICAL when the file also runs code from a string (the
GlassWorm shape), else MAJOR. A flag emoji (U+1F3F4 + tag letters + U+E007F)
and a lone emoji variation selector (U+FE0F) are left alone.

The invisible characters are built at run time so this file stays ASCII. The
npm engine's twin: js/test/review-hidden-unicode.test.js.
"""
import unittest

from lazaret.scanner import core


def vs(data):
    """A run of variation selectors, one per byte (U+FE00-FE0F cycling)."""
    return "".join(chr(0xFE00 + (b % 16)) for b in data)


def tag_chars(text):
    """`text` as tag characters (U+E0000 + code point)."""
    return "".join(chr(0xE0000 + ord(c)) for c in text)


def flag_emoji():
    """Scotland's flag: U+1F3F4, the tag letters g b s c t, U+E007F."""
    return chr(0x1F3F4) + "".join(chr(0xE0000 + ord(c)) for c in "gbsct") + chr(0xE007F)


def found(text, lang="js"):
    return [(i["sev"], i["line"], i["msg"]) for i in core.scan_file("x." + lang, text, lang)
            if i["rule"] == "SC-HIDDEN-UNICODE"]


class HiddenUnicodeTests(unittest.TestCase):
    def test_the_glassworm_shape_is_critical(self):
        text = ("const s = v => [...v].map(w => w.codePointAt(0));\n"
                "eval(Buffer.from(s(`" + vs(b"payload") + "`)).toString());\n")
        self.assertEqual(found(text), [(
            "CRITICAL", 2, "A run of 7 invisible variation selectors carries hidden data in the code, "
                           "and the file runs code from a string.")])

    def test_a_bare_carrier_is_major(self):
        self.assertEqual(found("const x = `" + vs(b"hi") + "`;\n"),
                         [("MAJOR", 1, "A run of 2 invisible variation selectors carries hidden data in the code.")])

    def test_tag_characters_smuggle(self):
        # a run of tag characters not after U+1F3F4: a carrier, MAJOR without a sink
        self.assertEqual(found("x = '" + tag_chars("run") + "'\n", "py"),
                         [("MAJOR", 1, "A run of 3 invisible tag characters carries hidden data in the code.")])
        # and CRITICAL with exec in the file
        crit = found("import base64\nexec(base64.b64decode('" + tag_chars("os") + "'))\n", "py")
        self.assertEqual(crit[0][0], "CRITICAL")

    def test_what_is_left_alone(self):
        for text, lang in [
            ("const label = '" + flag_emoji() + "';\n", "js"),         # a flag emoji
            ("x = 'a" + chr(0xFE0F) + "';\n", "js"),                   # a lone emoji variation selector
            ("const re = /[a-z]/;\n", "js"),                           # ASCII only
            ("s = '" + chr(0x0435) + "val'\n", "py"),                  # a Cyrillic letter is not a carrier
        ]:
            with self.subTest(text=text):
                self.assertEqual(found(text, lang), [])

    def test_reported_in_code_points_not_utf16(self):
        # the astral tag/VS-supplement chars are counted as one each (not two)
        run = "".join(chr(0xE0100 + i) for i in range(5))              # 5 astral variation selectors
        (only,) = found("const x = `" + run + "`;\n")
        self.assertIn("run of 5 invisible", only[2])

    def test_it_runs_on_dependencies_and_is_never_suppressed(self):
        text = "eval(s(`" + vs(b"xy") + "`)); // nosec\n"
        self.assertEqual([i["sev"] for i in core.scan_file("x.js", text, "js", dep=True)
                          if i["rule"] == "SC-HIDDEN-UNICODE"], ["CRITICAL"])


if __name__ == "__main__":
    unittest.main()
