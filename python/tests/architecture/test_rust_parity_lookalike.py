"""Engine parity for SC-HOMOGLYPH's look-alike names: the native engine's
lookalike_name (crates/lazaret-engine: scanfile.rs; the npm package runs it
as WebAssembly) against core.lookalike_name, case by case on the curated
lines and the seeded random corpus of names of test_js_parity_lookalike.py
(ASCII letters, every look-alike letter of the table, letters that are not
look-alikes, NFKC compatibility forms, the invisible U+200C / U+200D, digits
and punctuation): the name, what it reads as, the severity, whether another
name of the file reads so, the detail and the column (code points in both).
(Before the npm package ran the native engine, this held its JavaScript twin
to core.) Skipped where the native library is not built.
"""
import unittest

from lazaret.scanner import _native, core
from tests.architecture.test_js_parity_lookalike import WORDS, corpus


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LookalikeParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus()
        calls = [["lookalike_view", {"lang": lang, "words": WORDS}, code] for code, lang in cls.cases]
        cls.results = [r.get("ok", r) for r in _native.call("batch", {"calls": calls})]

    def test_every_case_agrees(self):
        words = frozenset(WORDS)
        diffs = []
        for (code, lang), got in zip(self.cases, self.results):
            want = core.lookalike_name(code, lang, lambda: words)
            if (list(want) if want else None) != got:
                diffs.append((code, lang, want, got))
        self.assertEqual(diffs[:10], [])
        found = [r for r in self.results if r]
        self.assertGreater(sum(1 for r in found if r[2] == "CRITICAL" and not r[3]), 40)    # a target
        self.assertGreater(sum(1 for r in found if r[3]), 30)                                # another name
        self.assertGreater(sum(1 for r in found if r[2] == "MAJOR"), 300)
        self.assertGreater(len(self.results) - len(found), 300)


if __name__ == "__main__":
    unittest.main()
