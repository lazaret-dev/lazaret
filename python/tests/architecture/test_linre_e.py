"""linre against Python's re on what P-16 added to it.

- Lookaheads of unbounded width (`(?!\\s*\\()`, the rest of an argument
  list or a string): run as written, their walks memoized for a text, and
  swept in one pass when the walks would cost more (looks.rs).
- Lookaheads whose walks meet thousands of sets (what the last dozen
  characters were), which the sweep decides.
- A backreference to a group of one character of a few uncased ones
  (`(["'])…\\1`): one branch per character (hir.rs), the groups kept.

The shapes are linre/tests.rs's, which hold linre to answers recorded from
sre's own matcher; here they meet re itself, on texts made of the pieces
the patterns read, with long runs of one piece now and then (what a walk
crosses), at 0 and in windows. Skipped where the native library is not
built.
"""
import random
import re
import unittest

from lazaret.scanner import _native
from tests.architecture import _linre_inputs as inputs

# (pattern, flags): the pack's lookaheads of unbounded width, and others
UNBOUNDED_LOOKAHEADS = [
    (r"\((?![^()]*\)\s*\{)", ""),
    (r"yaml\.load\s*\((?!(?:(?!yaml\.load)[^)])*(?:SafeLoader|safe_load))", ""),
    (r"a(?=.*b)", ""),
    (r"a(?=.*b)", "s"),
    (r"a(?!\s*\()", ""),
    (r"\w+(?!\s*\()", ""),
    (r"(?<![\w$])[A-Za-z_$][\w$]*(?![\w$])(?!\s*\()", ""),
    (r"""\.(?:type\s*\()\s*["'](?![^"']*(?:html|xml|svg))""", ""),
    (r"x(?=[ab ]*b)", ""),
    (r"(?=[a-z0-9_-]{3,}\.ey[a-z]{2})", ""),
    (r"(\w+)(?=\s*=(?!=))", ""),
    (r"(?:(?!ab)[a-c])*c", ""),
    (r"a(?=(?:[^()]|\([^()]*\))*,\s*\{)", ""),
    (r"EXEC(?:UTE)?\s*\(\s*@?\w+\s*\+|EXECUTE\s+IMMEDIATE\b(?:(?!EXECUTE\s+IMMEDIATE\b)[^;])*\|\|", "i"),
    (r"npm_(?:package|config)_(?![\w]*(?:auth|token))\w*\Z", "i"),
    (r"\bfoo\b(?![ \t]*=[^=])", ""),
    (r"=[ \t]*(?=(?:async[ \t]+)?(?:function\b|\([^()]*\)[ \t]*=>|[A-Za-z_$][\w$]*[ \t]*=>))", ""),
    (r"a(?=b*(?!c+d)e*)", ""),
    (r"(?!x*(?=y*z))\w", ""),
    (r"(?<=a(?=b*c))b", ""),
    (r"(a)(?=(?:b|c)*d)", ""),
    (r"^\s*(?!.*\bx\b)\w+$", "m"),
    (r"(?=.*?\d)(?=.*?[a-z])\w{3,}", ""),
    (r"\b\w+\b(?=(?:\s+\w+){2,}\s*;)", ""),
    (r"(?P<n>[a-c]+)(?!(?:\s|,)*\))", ""),
]
LOOK_PIECES = ["a", "b", "c", "d", "e", "x", "y", "z", "_", "1", "-", " ", "  ", "\t", "\n", "(", ")", "{", "}", ",",
               ";", "=", "==", "=>", "'", '"', ".", "@", "+", "||", "html", "xml", "svg", "safe_load", "SafeLoader",
               "yaml.load(", "EXECUTE", "IMMEDIATE", "exec(", "npm_package_", "npm_config_", "token", "auth", "foo",
               ".ey", ".eyJab", "async", "function", "type(", ".type(", "ſ", "K", "é", "\U00010400"]

# lookaheads that meet thousands of sets, on texts of a's and b's that end
# with a b and 13 a's (the second's body matches from every b)
MANY_SETS = [r"a(?![ab]*a[ab]{12}c)", r"b(?=[ab]*b[ab]{10}a[ab]{2}$)", r"(?![ab]*?a[ab]{11}ac)[ab]"]

# a backreference to a one-character group: the pack's quotes matched
# again, and others; then some linre still refuses
CHAR_BACKREFS = [
    (r"""(["'])([^"'\\\n]*)\1""", ""),
    (r"""\(\s*[rRuU]?(["'])(.*?)\1""", ""),
    (r"""[fFrRbBuU]{0,2}(["'`])([^"'`\n]*)\1\Z""", ""),
    (r"""(?<![\w$.])([A-Za-z_$][\w$]*)\s*\[\s*(["'])([^"'\\\n]*)\2\s*\]""", ""),
    (r"""^\s*([A-Za-z_$][\w$]*)\s*\[\s*(["'])([^"'\\\n]*)\2\s*\]\s*=(?![=>])""", "m"),
    (r"""(?<![\w$.])(?P<obj>[A-Za-z_$][\w$]*)[ \t]*\.[ \t]*emit[ \t]*\([ \t]*(?P<q>['"`])(?P<event>[^'"`\n]{1,20})\2[ \t]*,""",
     ""),
    (r"""(?:\brequire\s*\(\s*|\bfrom\s+)(['"])(\.{1,2}/[^'"\n]+)\1""", ""),
    (r"""(?:(["'])x\1)*y""", ""),
    (r"""(["'])abc\1""", "i"),
    (r"""(['"])(?=\w*\1)""", ""),
    (r"""(?P<q>[-+])\d+(?P=q)""", ""),
    (r"""([ab])x\1""", ""),
    (r"""(['"])(?:a|\1b)+\1""", ""),
    (r"""(a)(["'])\2\1""", ""),
]
STILL_REFUSED = [(r"([ab])x\1", "i"), (r"(\w)x\1", ""), (r"(xa)\1", ""), (r"(?:(a)|b)\1", ""),
                 (r"(?:(a))*\1", ""), (r"(a)?b\1", "")]
BACKREF_PIECES = ['"', "'", "`", "a", "b", "x", "y", "abc", "ABC", "1", "23", "-", "+", " ", "\t", "\n", "(", ")",
                  "[", "]", "{", "}", "${", "=", "==", ".", ",", ";", "r", "f", "\\", "https://", "http://h", "./",
                  "../m", "require(", "from ", "o.emit(", "_", "$", "ſ"]


def text_of(rnd, pieces, most, runs=True):
    """Up to `most` pieces, now and then one repeated (a run a walk crosses)."""
    out = []
    for _ in range(rnd.randint(0, most)):
        piece = rnd.choice(pieces)
        out.append(piece * (rnd.randint(1, 40) if runs and rnd.random() < 1 / 12 else 1))
    return "".join(out)


def random_lookahead(rnd, depth):
    """A random pattern with lookaheads of unbounded width in it (as
    linre/tests.rs's random_lookahead_pattern builds them)."""
    atoms = ["a", "b", "c", "x", ".", r"\w", r"\s", "[ab]", "[^a]", r"[^()]", r"\(", r"\)", " "]
    out = ""
    for _ in range(rnd.randint(1, 3)):
        if depth > 0 and rnd.random() < 1 / 3:
            inner = random_lookahead(rnd, depth - 1)
            out += rnd.choice([f"(?={inner})", f"(?!{inner})", f"(?:{inner}|{random_lookahead(rnd, depth - 1)})",
                               f"(?:{inner})"])
        else:
            out += rnd.choice(atoms)
        out += rnd.choice(["*", "+", "*?", "?", "", ""])
    return out


def runs_it(src, flags):
    """Python's re compiles it, and linre runs it."""
    try:
        re.compile(src, inputs.flag_bits(flags))
    except re.error:
        return False
    got = _native.call("linre.probe", {"pattern": src, "flags": flags, "texts": []})
    return "error" not in got


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LinreP16Tests(unittest.TestCase):
    maxDiff = 4000

    def test_unbounded_lookaheads(self):
        rnd = random.Random(20261004)
        for src, flags in UNBOUNDED_LOOKAHEADS:
            with self.subTest(pattern=src):
                texts = [text_of(rnd, LOOK_PIECES, 8 if k < 150 else 30) for k in range(200)]
                inputs.compare(self, src, flags, texts)
                inputs.compare(self, src, flags, texts[::4], pos=2, endpos=11)
                inputs.compare(self, src, flags, texts[1::4], pos=5)

    def test_random_lookahead_patterns(self):
        rnd = random.Random(4242)
        ran = 0
        for _ in range(600):
            src = f"{random_lookahead(rnd, 1)}(?{rnd.choice('=!')}{random_lookahead(rnd, 2)})"
            if not runs_it(src, ""):
                continue
            ran += 1
            # (short texts with no runs: re's own matcher takes exponential time on a near miss of
            # some of these, which linre's linear time is for, not this comparison)
            texts = [text_of(rnd, ["a", "b", "c", "x", " ", "(", ")", "_", "1", "é"], 8, runs=False) for _ in range(12)]
            inputs.compare(self, src, "", texts)
            inputs.compare(self, src, "", texts[:4], pos=1, endpos=6)
        self.assertGreater(ran, 300)

    def test_lookaheads_of_many_sets(self):
        rnd = random.Random(77)
        for src in MANY_SETS:
            with self.subTest(pattern=src):
                texts = ["".join(rnd.choice("ab") for _ in range(1500)) + "b" + "a" * 13 for _ in range(2)]
                inputs.compare(self, src, "", texts)
                inputs.compare(self, src, "", texts[:1], pos=500, endpos=1200)

    def test_one_character_backreferences(self):
        rnd = random.Random(9)
        for src, flags in CHAR_BACKREFS:
            with self.subTest(pattern=src):
                texts = [text_of(rnd, BACKREF_PIECES, 10 if k < 150 else 30, runs=False) for k in range(200)]
                inputs.compare(self, src, flags, texts)
                inputs.compare(self, src, flags, texts[::5], pos=3)

    def test_other_backreferences_are_still_refused(self):
        for src, flags in STILL_REFUSED:
            with self.subTest(pattern=src):
                got = _native.call("linre.probe", {"pattern": src, "flags": flags, "texts": [""]})
                self.assertTrue(got.get("refused"), got)
                self.assertIn("backreference", got["error"])


if __name__ == "__main__":
    unittest.main()
