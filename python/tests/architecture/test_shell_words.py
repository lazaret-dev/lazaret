"""The engine's reading of a hook command's words (hooks.rs, shlex_split)
against Python's shlex, in the mode the scanners use: posix=True,
punctuation_chars=True, whitespace_split=True, no comment characters.

The engine's tokenizer is written from shlex's documentation (P-16, part 3;
until then it was a translation of Lib/shlex.py), so Python's shlex is the
oracle: the hooks corpus's cases, then seeded random commands made of the
characters its rules name (the quotes, the backslash, `();<>|&`, the four
whitespace characters) and of others that are not whitespace to it. A
command shlex rejects (a quote left open, a backslash at the end) is None
on both sides. Skipped where the native library is not built.
"""
import random
import shlex
import unittest

from lazaret.scanner import _native
from tests.architecture import hooks_corpus

ALPHABET = list(" \t\r\n;|&()<>'\"\\#=-./~*?$`ab") + ["\u00a0", "\u3000", "\x0b", "\x0c", "\x00", "\u00e9",
                                                       "\ud800", "\U0001f600"]


def shlex_words(cmd):
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:
        return None


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ShellWordsTests(unittest.TestCase):
    def same(self, cases):
        differ = [(cmd, got, want) for cmd in cases
                  for got, want in [(_native.call("shlex_split", {}, cmd), shlex_words(cmd))] if got != want]
        self.assertEqual(differ[:5], [], f"{len(differ)} of {len(cases)} commands differ")

    def test_the_hooks_corpus(self):
        cases = hooks_corpus.corpus()
        self.assertGreater(len(cases), 40000)
        self.same(cases)

    def test_random_commands(self):
        rnd = random.Random(20261004)
        self.same(["".join(rnd.choice(ALPHABET) for _ in range(rnd.randint(0, 16))) for _ in range(30000)])

    def test_what_shlex_rejects(self):
        for cmd in ("node 'a.js", 'node "a.js', 'node "a.js\\', "node x.js \\", "'", '"', "\\"):
            with self.subTest(cmd=cmd):
                self.assertIsNone(shlex_words(cmd))
                self.assertIsNone(_native.call("shlex_split", {}, cmd))


if __name__ == "__main__":
    unittest.main()
