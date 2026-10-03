"""The engine's Unicode normalization (NFC, NFD, NFKC and NFKD of text
pinned to Unicode 13.0, which the match text and the look-alike rules read)
against Python's unicodedata, on every assigned code point alone and on
random strings of the characters composition turns on. Python's
unicodedata is the oracle here, as Unicode's own algorithm; it is 13.0's
where the suite runs on Python 3.10, and the tables agree for every
assigned 13.0 character on the later ones (scripts/make_rust_tables.py
--check).
"""
import random
import unicodedata
import unittest

from lazaret.scanner import _native, _unicode13


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NormalizationTests(unittest.TestCase):
    """NFC, NFD, NFKC and NFKD of text pinned to Unicode 13.0: every
    assigned code point alone, and random strings of the characters
    composition turns on (combining marks, the pairs' first and second
    characters, Hangul jamo and syllables, compatibility characters)."""

    @classmethod
    def setUpClass(cls):
        cls.cps = [c for c in range(0x110000) if _unicode13.assigned(c) and not 0xD800 <= c <= 0xDFFF]

    def compare(self, form, texts):
        bad = []
        for i in range(0, len(texts), 4000):
            chunk = texts[i:i + 4000]
            answers = _native.call("batch", {"calls": [["normalize", {"form": form}, t] for t in chunk], "threads": 2})
            for t, a in zip(chunk, answers):
                if a.get("ok") != unicodedata.normalize(form, t):
                    bad.append((form, [f"U+{ord(c):04X}" for c in t]))
                    if len(bad) >= 10:
                        return bad
        return bad

    def test_each_code_point(self):
        singles = [chr(c) for c in self.cps]
        for form in ("NFC", "NFD", "NFKC", "NFKD"):
            with self.subTest(form=form):
                self.assertEqual(self.compare(form, singles), [])

    def test_sequences(self):
        rnd = random.Random(15)
        marks = [c for c in self.cps if unicodedata.combining(chr(c))]
        decomposable = [c for c in self.cps if unicodedata.decomposition(chr(c))
                        and not 0xAC00 <= c <= 0xD7A3]
        pairs = [d.split() for d in map(unicodedata.decomposition, map(chr, decomposable))
                 if d and not d.startswith("<") and len(d.split()) == 2]
        firsts = sorted({int(a, 16) for a, _ in pairs})
        seconds = sorted({int(b, 16) for _, b in pairs})
        jamo = list(range(0x1100, 0x1113)) + list(range(0x1161, 0x1176)) + list(range(0x11A7, 0x11C3))
        syllables = [0xAC00, 0xAC01, 0xAC1C, 0xB098, 0xB099, 0xD7A3]
        pools = [marks, decomposable, firsts, seconds, jamo, syllables, [0x61, 0x41, 0x3A3, 0x300, 0x301, 0x323, 0x345]]
        texts = ["".join(chr(rnd.choice(rnd.choice(pools))) for _ in range(rnd.randint(1, 8))) for _ in range(20000)]
        for form in ("NFC", "NFD", "NFKC", "NFKD"):
            with self.subTest(form=form):
                self.assertEqual(self.compare(form, texts), [])


if __name__ == "__main__":
    unittest.main()
