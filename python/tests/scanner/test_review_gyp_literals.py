"""binding.gyp literals: core.scan_gyp's results that the npm engine now
reproduces (js/test/review-gyp-literals.test.js asserts the same values;
tests/architecture/test_js_parity_gyp compares the two CLIs).

Review fix in core itself: an action argument that is an int of more than
4300 digits (a long hex literal) made str() raise ValueError out of
scan_gyp, so a hostile binding.gyp crashed the scan instead of being
reported. Such an int is now shown in hex, as the npm engine shows it."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
