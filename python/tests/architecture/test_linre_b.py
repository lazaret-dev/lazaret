"""linre against Python's re: the rule pack on texts sampled from each
pattern (half of the patterns; test_linre_c.py runs the other half).

For each pattern linre accepts, _linre_inputs.sample walks its parse tree
with seeded random choices — a branch, a repeat's count near its bounds, a
class's member (a range's ends, the characters re treats specially), a
letter's case under re.I — and mutates some of what it builds, so the texts
match, almost match, or match more than once. search, match, fullmatch,
finditer with every group, sub and split answer alike, at 0 and in windows.
Skipped where the native library is not built.
"""
import random
import unittest

from lazaret.scanner import _native
from tests.architecture import _linre_inputs as inputs


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LinreSampledTests(unittest.TestCase):
    maxDiff = 4000
    PART = 0

    def test_sampled_texts(self):
        rnd = random.Random(20261003 + self.PART)
        n = 0
        for name, src, flags in inputs.accepted(self.PART, 2):
            with self.subTest(pattern=name):
                texts = inputs.sample(src, flags, rnd, 100)
                n += inputs.compare(self, src, flags, texts)
                n += inputs.compare(self, src, flags, texts[:12], pos=1, endpos=6)
                n += inputs.compare(self, src, flags, texts[12:24], pos=rnd.randint(0, 9))
                n += inputs.compare(self, src, flags, texts[24:30], pos=5, endpos=2)
        self.assertGreater(n, 30000)


if __name__ == "__main__":
    unittest.main()
