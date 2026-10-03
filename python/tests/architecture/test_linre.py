"""linre, the native engine's linear-time regex engine (rust/…/src/linre,
docs/RUST_ENGINE.md), against Python's re: the rule pack on the regex corpus.

Every pattern of the pack linre accepts is run by both on the texts the
pyre parity test uses (_rust_regex_corpus.py: the pattern's own words and
the characters patterns treat specially) and on the characters re handles
specially one by one (_linre_inputs.EDGE: ſ, K, İ, U+0085, U+00A0,
U+001C–U+001F, astral characters, lone surrogates), at 0 and in windows
(pos/endpos inside the text, and past each other), with and without a text
gate: search, match, fullmatch, finditer with every group, sub and split
answer alike. Then what linre refuses: the reasons, and linre.check.

The sampled texts are test_linre_b.py's and _c's, the hand-written patterns
_d's, linear time test_linre_linear.py's. Skipped where the native library
is not built.
"""
import random
import unittest

from lazaret.scanner import _native
from tests.architecture import _linre_inputs as inputs
from tests.architecture import _rust_regex_corpus as corpus
from tests.architecture.test_rust_parity_regex import HANDWRITTEN_TEXTS, pack_patterns

# why linre refuses a pattern of the pack (a backreference needs what a group
# matched; an unbounded lookahead costs up to the rest of the text at every
# position; a program over the size limit comes of counted repeats)
REASONS = ("a backreference", "a lookahead of unbounded width", "too large")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LinreCorpusTests(unittest.TestCase):
    maxDiff = 4000

    def test_every_accepted_pack_pattern(self):
        rnd = random.Random(20261001)
        n = 0
        for name, src, flags in inputs.accepted():
            with self.subTest(pattern=name):
                texts = corpus.texts_for(src, rnd, count=120) + HANDWRITTEN_TEXTS[:12] + inputs.EDGE
                n += inputs.compare(self, src, flags, texts)
                n += inputs.compare(self, src, flags, texts[:24], pos=1, endpos=6)
                n += inputs.compare(self, src, flags, texts[:12], pos=5, endpos=2)
        self.assertGreater(n, 90000)

    def test_every_accepted_pack_pattern_with_a_text_gate(self):
        # texts of 256 characters or more get a gate (rust/…/src/textgate.rs):
        # the searches that ask it answer as re does
        rnd = random.Random(20261002)
        n = 0
        for name, src, flags in inputs.accepted():
            with self.subTest(pattern=name):
                words = corpus.texts_for(src, rnd, count=40) + inputs.sample(src, flags, rnd, 8)
                texts = [(" ".join(words[i:i + 8]) + "\n") * 6 for i in range(0, len(words), 8)]
                texts = [t for t in texts if len(t) >= 256] + [("x = 1\n" + " ".join(words)) * 4 + "q" * 300]
                n += inputs.compare(self, src, flags, texts, gate=True)
                n += inputs.compare(self, src, flags, texts, gate=True, pos=7, endpos=290)
        self.assertGreater(n, 5000)

    def test_most_of_the_pack_is_accepted(self):
        checked = inputs.checked()
        self.assertEqual(sorted(checked), sorted(name for name, _, _ in pack_patterns()))
        refused = {name: e["reason"] for name, e in checked.items() if not e["accepted"]}
        self.assertGreater(len(checked) - len(refused), 0.9 * len(checked))
        for name, why in refused.items():
            with self.subTest(pattern=name):
                self.assertNotIn("error", checked[name], f"Python's re compiles {name}")
                self.assertTrue(why.startswith(REASONS), why)

    def test_check(self):
        names = [name for name, _, _ in pack_patterns()][:5] + ["NO_SUCH_PATTERN", "RULES[100000]"]
        got = _native.call("linre.check", {"names": names})
        self.assertEqual([e["name"] for e in got], names)
        for e in got[:5]:
            self.assertEqual(e["flags"], dict((n, f) for n, _, f in pack_patterns())[e["name"]])
            if e["accepted"]:
                self.assertGreater(e["insts"], 0)
                self.assertIn("need", e)
                self.assertIn("lead", e)
            else:
                self.assertTrue(e["reason"])
        for e in got[5:]:
            self.assertEqual((e["accepted"], e["reason"]), (False, "no such pattern in the pack"))

    def test_refusals_are_not_errors(self):
        # a pattern Python's re rejects is an error (refused false); one
        # linre does not run, a refusal with the reason
        for src, refused, why in [
            (r"(['\"])x\1", True, "backreference"),
            (r"a(?=.*b)", True, "lookahead of unbounded width"),
            (r"(?:a{1,2000}){1,2000}", True, "too large"),
            (r"(a)?(?(1)b|c)", True, "conditional"),
            (r"(?:a*)*", True, "empty string"),
            (r"(?=(a))", True, "capturing group inside a positive lookaround"),
            (r"(?<=a+)b", False, "look-behind requires fixed-width pattern"),
            (r"(", False, "missing )"),
            (r"a**", False, "multiple repeat"),
        ]:
            with self.subTest(pattern=src):
                got = _native.call("linre.probe", {"pattern": src, "texts": ["a"]})
                self.assertEqual(got.get("refused"), refused, got)
                self.assertIn(why, got["error"])


if __name__ == "__main__":
    unittest.main()
