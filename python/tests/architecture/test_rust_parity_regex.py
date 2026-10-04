"""The Rust engine's `re` (crates/lazaret-engine/src/pyre) against Python's:
each pattern as the engine runs it (on linre, src/linre, where linre accepts
it) and on pyre's backtracking matcher alone (pyre.probe's "backtracking").

Every pattern of the rule pack — every compiled pattern of
lazaret.scanner.core, with its flags — is compiled by both, and each entry
point is compared on texts built from the pattern's own words and the
characters patterns treat specially (_rust_regex_corpus.py): search, match
and fullmatch (at 0 and at a pos/endpos inside the text), finditer's every
match with every group's span and lastindex, sub with a function, and
split. Then a set of hand-written patterns covers what core's may not:
backreferences, conditionals, empty-match loops, nested repeats with
groups, lookbehind at the start, inline flags, verbose mode, re.I folding.

Skipped where the native library is not built (LAZARET_NATIVE_LIB or the
wheel's lazaret/_native/).
"""
import itertools
import json
import os
import random
import re
import sys
import unittest

from lazaret.scanner import _native
from tests.architecture import _rust_regex_corpus as corpus

PACK = os.path.join(os.path.dirname(__file__), "..", "..", "..", "rust", "crates", "lazaret-engine", "rules",
                    "lazaret-rules.json")
_FLAGS = {"i": re.I, "m": re.M, "s": re.S, "x": re.X, "a": re.A}


def pack_patterns():
    """(name, source, flags) of every pattern in the rule pack, pairs and
    tables included."""
    with open(PACK, encoding="utf-8") as f:
        values = json.load(f)["values"]
    out = []

    def walk(name, v):
        if "re" in v:
            out.append((name, v["re"], v["flags"]))
        elif "list" in v:
            for i, x in enumerate(v["list"]):
                walk(f"{name}[{i}]", x)
        elif "map" in v:
            for k, x in v["map"].items():
                walk(f"{name}[{k!r}]", x)
        elif "items" in v:
            for i, (_, x) in enumerate(v["items"]):
                walk(f"{name}.items[{i}]", x)
    for name, v in sorted(values.items()):
        walk(name, v)
    return out


def flag_bits(letters):
    f = 0
    for c in letters:
        f |= _FLAGS[c]
    return f


def py_probe(rx, texts, pos=0, endpos=None, template=None):
    """What pyre.probe answers, from Python's re."""
    def mv(m):
        if m is None:
            return None
        groups = []
        for g in range(1, rx.groups + 1):
            groups += list(m.span(g))
        return [m.start(), m.end(), -1 if m.lastindex is None else m.lastindex, groups]
    out = []
    for t in texts:
        ep = len(t) if endpos is None else endpos
        r = {"search": mv(rx.search(t, pos, ep)), "match": mv(rx.match(t, pos, ep)),
             "fullmatch": mv(rx.fullmatch(t, pos, ep)),
             "finditer": [mv(m) for m in itertools.islice(rx.finditer(t, pos, ep), 10000)],
             "sub": rx.sub(lambda m: "<" + m.group() + ">", t), "split": rx.split(t)}
        if template is not None:
            r["template"] = rx.sub(template, t)
        out.append(r)
    return {"groups": rx.groups, "results": out}


def compare(testcase, src, flags, texts, gate=False, **kw):
    """Assert that both engines answer alike; returns the number of texts.
    The texts travel as JSON, which reads a high surrogate next to a low one
    as the character they encode: each is compared as JSON leaves it.
    `gate`: each text's searches ask a text gate (rust/…/src/textgate.rs)."""
    texts = [json.loads(json.dumps(t)) for t in texts]
    rx = re.compile(src, flag_bits(flags))
    want = py_probe(rx, texts, **kw)
    args = {"pattern": src, "flags": flags, "texts": texts}
    args.update({k: v for k, v in kw.items() if v is not None})
    if gate:
        args["gate"] = True
    # as the engine runs the pattern (on linre where linre accepts it), and on sre's matcher alone
    for backtracking in (False, True):
        got = _native.call("pyre.probe", dict(args, backtracking=True) if backtracking else args)
        if got != want:
            testcase.assertNotIn("error", got, f"{src!r}: {got.get('error')}")
            for t, a, b in zip(texts, want["results"], got["results"]):
                for key in a:
                    testcase.assertEqual(a[key], b.get(key), f"pattern {src!r} flags {flags!r} {key} on {t!r} {kw} "
                                                             f"(backtracking: {backtracking})")
            testcase.assertEqual(want, got)
    return len(texts)


# Patterns core may not exercise: each construct re supports for str patterns
HANDWRITTEN = [
    (r"(a)\1", ""), (r"(?P<q>['\"]).*?(?P=q)", ""), (r"(a)?(?(1)b|c)", ""), (r"(?:(a)|b)*c", ""),
    (r"(a|)*", ""), (r"(a*)*b", ""), (r"(a*)+?", ""), (r"((a)|b)+", ""), (r"(?:x(y)?)*z", ""),
    (r"(?<=ab)c", ""), (r"(?<!\w)x", ""), (r"(?<=^)x", "m"), (r"^\s*$", "m"), (r"\Aa|b\Z", ""),
    (r"(?i)straße", ""), (r"[a-z]+", "i"), (r"[^\W\d_]+", ""), (r"\bk\b", "i"), (r"[ſ]", "i"),
    (r"[İı]", "i"), (r"[\x00-\x7f]+", "i"), (r"[Ā-ſ]+", "i"), (r"[\U00010400-\U0001044f]", "i"),
    (r"\w+", "a"), (r"\s+", ""), (r"\S+?", ""), (r"\d{2,}", ""), (r".{0,3}x", "s"), (r"a{,2}", ""),
    (r"a{2}b{3,}c{2,4}?", ""), (r"x{", ""), (r"x{2,1a}", ""), (r"(?x) a b  \# c  # comment", ""),
    (r"(?s:.)(.)", ""), (r"(?-i:a)b", "i"),
    (r"(?:ab|a)(?:bc|c)", ""), (r"(a|ab)(c|bcd)(d*)", ""), (r"(?=(a+))a*b\1", ""), (r"(?!)", ""),
    (r"[]a]", ""), (r"[^]a]", ""), (r"[a-]", ""), (r"[\w-]+", ""), (r"[\s\S]", ""), (r"\x41B\U00000043\101", ""),
    (r"$", ""), (r"$", "m"), (r"^", "m"), (r"\b", ""), (r"", ""), (r"(?:)", ""),
    (r"(?P<a>x)(?P<b>y)?", ""), (r"(a)(b)(c)(d)(e)(f)(g)(h)(i)(j)\10", ""), (r"[\d\D]", ""),
    (r"(?m)^(?:[ \t]*#.*\n)+", ""), (r"\\", ""), (r"[\\\]]", ""), (r"(\w+)\s+\1", "i"),
    (r"(?<=\d{2})x", ""), (r"(?<![a-z]{3})y", "i"), (r"(?:a|b|c|d)+", ""), (r"ab|ac|ad", ""),
    (r"foo|foobar", ""), (r"[ab]|[cd]|e", ""), (r"é", "i"), (r"É+", "i"), (r"Σ+", "i"), (r"ς", "i"),
    # where the engine skips a start, an alternative or a backtracking step
    # by the characters what follows can begin with (pyre/first.rs, prog.rs)
    (r"(?:(?<=a)b|(c)|(?=d)d|)e", ""), (r"(?:(?!a)\w|a)+", ""), (r"x(?:\s*y|z?)w", ""),
    (r"(?:\bfoo|(?<![\w])bar)\(", ""), (r"(?:ab|ǆ|ſt)x", "i"), (r"(?:a|b?)c", ""), (r"(?:(a)|(b))\2?c", ""),
    (r"a*(?:b|c)", ""), (r"\w*?(?=x)x", ""), (r"\s*(?:$|;)", ""), (r"a+?(?:b|$)", ""), (r"[a-z]*(?<=c)d", ""),
    (r"x*(?:y*)z", ""), (r"\w+(?:\.\w+)*\(", ""), (r".*?(?:ſ|k)", "i"), (r"a*\b", ""), (r"(?:a*)*b", ""),
    (r"(?:a*b)*c", ""), (r"(?:[ab]*?c|d)+e", ""), (r"(a*)(?:\1|x)y", ""), (r"(?:é|e)*?[ÉE]", "i"),
    (r"(?=ab)a", ""), (r"(?=a|)b?", ""), (r"(?=\w{2})", ""), (r"(?=a*)b", ""), (r"(?=)a", ""),
    (r"(?=(a))\1b", ""), (r"(?:^|x)y", "m"), (r"(?:(?<=a)|^)b", ""), (r"(?:^|(?<=\s))//", ""), (r"(?=[ſ])s", "i"),
    # where a search stops early on text that holds none of the strings every
    # match holds (pyre/literal.rs)
    (r"ngrok|pastebin", "i"), (r"kiss", "i"), (r"st\b", "i"), (r"x(?:ab|cd)+y", ""), (r"(?:ab)+", ""),
    (r"a(?=bc)bc", ""), (r"(?<=ab)cd", ""), (r"(?<!ab)cd", ""), (r"(?:foo|ba(?:r|z))qux", ""), (r"ab|a", ""),
    (r"(?:ab|cd)?ef", ""), (r"ab*cd", ""), (r"a[bc]d", ""), (r"a[bB]D", "i"), (r"(?:ab){2}", ""),
    (r"\b(?:nc|ncat|netcat)\s", ""), (r"x(?:y|)z", ""), (r"ab(?:\w|cd)", ""), (r"(?i)Ab(?:[sS]|c)", ""),
    (r"(a)(?(1)bc|de)fg", ""), (r"\bab\b\w*", "a"), (r"(?>ab|c)d", "") if sys.version_info >= (3, 11) else (r"ab", ""),
    # where a search tries only where a string every match starts with
    # starts (pyre/literal.rs), or where the zero-width tests a match makes
    # before its first character hold (pyre/first.rs)
    (r"(?<![\w$.])foo\(", ""), (r"(?<=[ab])c", ""), (r"(?<![^\n])x=", ""), (r"(?:(?<![^\n])|[;{]|=>)[ \t]*(\w+)=", ""),
    (r"\b(?:open|read)\(", ""), (r"(?:\$\(|`)\s*id\b", ""), (r"HTTPS?Connection|requests|\"https\"", ""),
    (r"(?:Foo|bar)baz", "i"), (r"(?:ab|ǆ)c", "i"), (r"(?=ab)(?:ab|ac)", ""), (r"(?<!x)(?:ab|cd)", ""),
    (r"^\s*(?:ab|cd)", "m"), (r"n(?:c|cat|etcat)\b", ""), (r"(?:\bx|(?<=\.)y)z", ""), (r"(?<=^)ab|(?<![\w])cd", "m"),
]
if sys.version_info >= (3, 11):                 # atomic groups and possessive repeats
    HANDWRITTEN += [(r"(?>a+)b", ""), (r"a++b", ""), (r"a*+", ""), (r"(?:ab|a)*+c", ""), (r"(?>(a)|b)+", "")]
# \B on an empty text: no match on 3.10-3.13, a match on 3.14+ (gh-124130).
# The Rust engine reads it as 3.10-3.13 do; no pattern of core uses \B.
NON_BOUNDARY = (r"\B", "")
HANDWRITTEN_TEXTS = ["", "a", "aa", "ab", "abc", "abab", "aab", "b", "c", "bc", "ac", "abcd", "abbcd", "xyz",
                     "xz", "xyxz", "STRASSE", "Straße", "straſse", "K", "K", "k", "ſ", "s", "S",
                     "İ", "ı", "i", "I", "\U00010400", "\U00010428", "éÉ", "a\nb\n", "\n",
                     "  \n\t\n", "'x'", '"y" "z"', "abcdefghijj", "x{2,1a}", "x{", "a{,2}", "ab # c",
                     "ΣΣσς", "12x", "ab x", "y", "aaab", "x\ny", "foobar", "٣٤", "\x1c\x85", "KİSS", "kıss", "ſt", "ST", "NGROK", "PasteBin", "xabcdy", "abcd",
                     "foobarqux", "bazqux", "ef", "cdef", "abbbcd", "acd", "AbD", "abab", "abcfg", "adefg", "abd", "cd", "nc ", "ncat x", "netcat\t",
                     "net cat", "xz", "xyz", "abx", "abcd", "ABS", "abſ", "aBC",
                     "foo(", ".foo(", "$foo(", "afoo(", "x=1\ny=2", ";a=1", "{b=2", "=>c=3", "a==b", "open(",
                     "reopen(", "$(id)", "` id`", "HTTPSConnection HTTPConnection", "requests", '"https"', "FOOBAZ",
                     "barBaz", "ǅc", "ǆC", "xab", "yab cd", ".yz", "xz", "ncat\n", "xcd"]


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RegexParityTests(unittest.TestCase):
    maxDiff = 4000

    def test_every_pack_pattern(self):
        rnd = random.Random(20260929)
        n = 0
        for name, src, flags in pack_patterns():
            with self.subTest(pattern=name):
                texts = corpus.texts_for(src, rnd, count=120) + HANDWRITTEN_TEXTS[:12]
                n += compare(self, src, flags, texts)
                n += compare(self, src, flags, texts[:20], pos=1, endpos=6)
        self.assertGreater(n, 30000)

    def test_every_pack_pattern_with_a_text_gate(self):
        # the searches of a text read once for its pairs and triples of
        # characters answer as re does (texts of 256 characters or more get
        # a gate; the pattern's own words make them hold what it needs)
        rnd = random.Random(20261001)
        n = 0
        for name, src, flags in pack_patterns():
            with self.subTest(pattern=name):
                words = corpus.texts_for(src, rnd, count=40)
                texts = [(" ".join(words[i:i + 8]) + "\n") * 6 for i in range(0, len(words), 8)]
                texts = [t for t in texts if len(t) >= 256] + [("x = 1\n" + " ".join(words)) * 4 + "q" * 300]
                n += compare(self, src, flags, texts, gate=True)
                n += compare(self, src, flags, texts, gate=True, pos=7, endpos=290)
        self.assertGreater(n, 3000)

    def test_handwritten(self):
        rnd = random.Random(7)
        for src, flags in HANDWRITTEN:
            with self.subTest(pattern=src, flags=flags):
                texts = HANDWRITTEN_TEXTS + corpus.texts_for(src, rnd, count=60, most=8)
                compare(self, src, flags, texts)
                compare(self, src, flags, texts, pos=2, endpos=5)
                compare(self, src, flags, texts, pos=5, endpos=2)

    def test_non_boundary(self):
        texts = [t for t in HANDWRITTEN_TEXTS if t]
        compare(self, *NON_BOUNDARY, texts)
        self.assertIsNone(_native.call("pyre.probe", {"pattern": r"\B", "texts": [""]})["results"][0]["search"])
        self.assertEqual([name for name, src, _ in pack_patterns() if "\\B" in src], [])

    def test_templates(self):
        for src, tpl in [(r"(a)(b)?", r"[\1|\2]"), (r"(?P<n>\w)", r"\g<n>\g<0>\n"), (r"x", r"\\\-"),
                         (r"(a)", r"\101\0\07")]:
            with self.subTest(pattern=src):
                compare(self, src, "", HANDWRITTEN_TEXTS, template=tpl)

    def test_escape(self):
        text = "".join(map(chr, range(0x100))) + " \U0001F600\ud800"
        self.assertEqual(_native.call("pyre.escape", {}, text), re.escape(text))


if __name__ == "__main__":
    unittest.main()
