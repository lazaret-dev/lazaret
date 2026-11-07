"""linre against Python's re: hand-written patterns, for what the rule pack
may not exercise.

The pyre parity test's hand-written patterns (each construct re supports
for str patterns: linre runs them or refuses them, saying why), then
linre's own: lookarounds of more than one character (nested, at a window's
ends), anchors under MULTILINE, `.` with and without DOTALL, flags inline
and as arguments, re.I's folds past ASCII (ſ, K, İ, ı, ß, σ/ς/Σ, ǅ),
astral characters and lone surrogates, counted and lazy repeats at their
bounds, empty matches, the last iteration's capture and lastindex, and the
literal scans' corners. Each on the hand-written texts, the edge
characters and texts sampled from the pattern, at 0 and in windows.
Skipped where the native library is not built.
"""
import random
import sys
import unittest

from lazaret.scanner import _native
from tests.architecture import _linre_inputs as inputs
from tests.architecture.test_rust_parity_regex import HANDWRITTEN, HANDWRITTEN_TEXTS

# why linre refuses one of these
REASONS = ("a backreference", "a conditional group", "a repeat whose body can match the empty string",
           "a capturing group inside a positive lookaround", "an atomic group", "a possessive repeat")

LINRE_HANDWRITTEN = [
    # lookarounds of more than one character, nested, of several widths
    (r"(?<=ab)c", ""), (r"(?<!ab)c", ""), (r"a(?=bc)", ""), (r"a(?!bc)", ""), (r"(?<=\d{3})x", ""),
    (r"a(?=b{1,5}c)", ""), (r"x(?![ \t]{0,8}\()", ""), (r"(?<=(?<!b)a)c", ""), (r"a(?=b(?!c))", ""),
    (r"a(?=b|cd|efg)\w*", ""), (r"(?<=ab|cd)e", ""), (r"(?<![\w$.]{2})x\w", ""), (r"(?=a{2,3}b)a+", ""),
    (r"(?<=\s)(?=\S{2,4}\b)\w+", ""), (r"(?:(?<=x)|(?<=yz))w", ""), (r"(?!ab|ba)[ab]{2}", ""),
    (r"\b(?=\w{3}\b)\w+", ""), (r"(?<=^ab)c", "m"), (r"(?<=\n)x|x(?=\n)", ""), (r"(?=(?:ab){1,2}c)\w+", ""),
    # anchors, MULTILINE, DOTALL
    (r"^\w+$", ""), (r"^\w+$", "m"), (r"\A\w|\w\Z", "m"), (r"$\n?", ""), (r"(?m)^$", ""), (r"\b\w", "a"),
    (r"\B\w\B", ""), (r".+", ""), (r".+", "s"), (r"(?s:.)(?-s:.)", ""), (r"a.c", "s"), (r"^", ""),
    # flags inline and as arguments, scoped
    (r"(?i)abc", ""), (r"abc", "i"), (r"(?x) a  b # c", ""), (r"a b", "x"), (r"(?i:a)b", ""), (r"(?-i:a)b", "i"),
    (r"(?a)\w+", ""), (r"\w+", "a"), (r"(?ims)^a.b$", ""), (r"(?i)[^\W\d]+", ""), (r"(?i)\bk\b", ""),
    # re.I past ASCII
    (r"[a-z]+", "i"), (r"ss", "i"), (r"\xdf", "i"), (r"[^k]", "i"), (r"İ", "i"), (r"ı", "i"),
    (r"i", "i"), (r"σ+", "i"), (r"[ς]", "i"), (r"ǅ", "i"), (r"[Ǆ-ǆ]", "i"), (r"K", "i"),
    (r"[k-l]", "i"), (r"[ſ]+", "i"), (r"[^ſ]", "i"), (r"[\x80-ɏ]+", "i"), (r"[\U00010400-\U0001044f]", "i"),
    (r"\U00010400", "i"),
    # astral characters, lone surrogates
    (r"[\ud800-\udfff]+", ""), (r"\W+", ""), (r"[\U0001F600-\U0001F64F]", ""), (r"..", ""), (r"\S\s\S", ""),
    # counted and lazy repeats at their bounds, with groups
    (r"a{3,5}", ""), (r"(?:ab){2,3}", ""), (r"[a-c]{0,2}?b", ""), (r"(a|b){2,4}", ""), (r"(a{1,2}){2}", ""),
    (r"a+?", ""), (r"a{2,4}?", ""), (r"(a+?)(a*)", ""), (r".*?x", ""), (r"(\w{1,3}?)(\w{2})", ""),
    (r"x{0}y", ""), (r"(?:a|bc){0,3}?d", ""), (r"[^x]{2,}?x", ""), (r"(a)?(b)??c", ""),
    # empty matches, groups, lastindex
    (r"a*", ""), (r"x?", ""), (r"(?:)", ""), (r"\b", ""), (r"(a)|(b)", ""), (r"(?P<n>x)?y", ""), (r"((a)|b)+", ""),
    (r"((a)(b)?)+", ""), (r"(a)(?:(b)|c)*", ""), (r"(?:(a)|(b)|(c))+", ""), (r"(a?)b", ""),
    # where the literal scans and the first-character scan decide where to try
    (r"foo|foobar|bar", ""), (r"(?:fs\.)?writeFile", ""), (r"x(?:ab|cd)+y", ""), (r"\bopen\s*\(", ""),
    (r"(?:Foo|bar)baz", "i"), (r"[0-9a-f]{8}-[0-9a-f]{4}", ""), (r"(?<![\w$.])(?:abc|de)\(", ""),
    (r"[=:]\s*[\"']([A-Za-z0-9+/=_\-]{20,})[\"']", ""), (r"\w+@\w+\.com", ""), (r"\s*(?:,|$)", ""),
]
# an astral letter written in a class under re.I, an astral range under
# re.A and re.I: linre answers as Python 3.13 on (and the engine's pyre) do;
# 3.10-3.12 match neither case of the letter, and fold the range
if sys.version_info >= (3, 13):
    LINRE_HANDWRITTEN += [(r"[\U00010400a]", "i"), (r"[^\U00010400]", "i"), (r"[\U00010400-\U00010401]", "ai")]


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LinreHandwrittenTests(unittest.TestCase):
    maxDiff = 4000

    def check(self, src, flags, rnd):
        texts = HANDWRITTEN_TEXTS + inputs.EDGE + inputs.sample(src, flags, rnd, 40)
        inputs.compare(self, src, flags, texts)
        inputs.compare(self, src, flags, texts, pos=2, endpos=5)
        inputs.compare(self, src, flags, texts[:60], pos=5, endpos=2)
        inputs.compare(self, src, flags, texts[:60], pos=1)

    def test_pyre_handwritten(self):
        rnd = random.Random(11)
        ran = 0
        for src, flags in HANDWRITTEN:
            with self.subTest(pattern=src, flags=flags):
                got = _native.call("linre.probe", {"pattern": src, "flags": flags, "texts": [""]})
                if "error" in got:
                    self.assertTrue(got["refused"], got)
                    self.assertTrue(got["error"].startswith(REASONS), got["error"])
                    continue
                self.check(src, flags, rnd)
                ran += 1
        self.assertGreater(ran, 100)

    def test_linre_handwritten(self):
        rnd = random.Random(12)
        for src, flags in LINRE_HANDWRITTEN:
            with self.subTest(pattern=src, flags=flags):
                self.check(src, flags, rnd)

    @unittest.skipUnless(sys.version_info >= (3, 13), "3.10-3.12 match an astral letter's case differently")
    def test_astral_classes_as_re_313(self):
        # where Python versions differ (an astral letter in a class under
        # re.I; an astral range under re.A and re.I), linre answers as 3.13
        # and later do (and as pyre's sre port did, before P-16 retired it)
        letters = ["\U00010400", "\U00010401", "\U00010427", "\U00010428", "\U0001044f", "\U0001F600", "\U0001E900",
                   "\U0001E922", "A", "a", "k", "K", "ſ", "s"]
        texts = ["".join(letters), "".join(reversed(letters))] + letters
        rnd = random.Random(14)
        for _ in range(300):
            items = []
            for _ in range(rnd.randint(1, 3)):
                a, b = sorted(rnd.sample(letters, 2), key=ord)
                items.append(f"{a}-{b}" if rnd.random() < 0.4 else a)
            src = "[" + ("^" if rnd.random() < 0.3 else "") + "".join(items) + "]+"
            flags = rnd.choice(["i", "ai", ""])
            with self.subTest(pattern=src, flags=flags):
                inputs.compare(self, src, flags, texts)

    def test_longer_texts(self):
        # matches far into a text, across the literal scans' and the DFAs'
        # paths (a long gap, then a match; a near miss at every place)
        rnd = random.Random(13)
        for src, flags in LINRE_HANDWRITTEN[::3]:
            with self.subTest(pattern=src, flags=flags):
                pieces = inputs.sample(src, flags, rnd, 30)
                texts = ["".join(rnd.choice(pieces + [" ", "\n", "x" * 40]) for _ in range(60)) for _ in range(6)]
                inputs.compare(self, src, flags, texts)
                inputs.compare(self, src, flags, texts, gate=True)


if __name__ == "__main__":
    unittest.main()
