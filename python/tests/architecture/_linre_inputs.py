"""Inputs and the comparison for the linre tests (test_linre*.py): linre,
the native engine's linear-time regex engine (rust/…/src/linre), against
Python's re. Not a test.

`compare` runs a pattern on texts in both and asserts the same answers:
search, match and fullmatch, finditer's every match with every group's span
and lastindex, sub with a function, and split. `sample` builds texts from a
pattern's own pieces: its parse tree walked with random choices (a branch,
a repeat's count, a class's member, a letter's case), so the text is likely
to match, then mutated, so it is likely to almost match. Repeat counts lean
to the bounds (min, min - 1, max, max + 1); class members to a range's ends
and to the characters re treats specially (`EDGE`).

Characters are drawn only where Unicode 13.0 (the engine's tables) and the
running Python's Unicode agree: from ranges, those whose general category
Unicode 3.2 and this Python give alike.
"""
import json
import re
import unicodedata

from lazaret.scanner import _native
from tests.architecture.test_rust_parity_regex import flag_bits, pack_patterns, py_probe

try:                                                # Python 3.11 on
    from re import _parser as _sre_parse
except ImportError:                                 # 3.10
    import sre_parse as _sre_parse

SURROGATES = [chr(0xD800), chr(0xDBFF), chr(0xDC00), chr(0xDFFF)]
# what re treats specially: the letters re.I folds beyond ASCII (ſ, K, İ, ı,
# ß, Σ, ǅ), the characters \s holds past ASCII (U+001C–U+001F, U+0085, U+00A0,
# U+2028, U+3000), astral letters and symbols, lone surrogates
EDGE = ["ſ", "s", "S", "K", "k", "K", "İ", "ı", "i", "I", "\x85", "\xa0", "\x1c", "\x1d", "\x1e",
        "\x1f", " ", "　", "\U0001F600", "\U00010400", "\U00010428", "\U0001D41A", "\n", "\r\n", "\t",
        "\x0b", "\x0c", "\xdf", "ẞ", "Σ", "σ", "ς", "ǅ", "ǆ", "Ǆ", "\xe9", "\xc9",
        "٣", "﻿", "​", "\x00", "Ⅷ"] + SURROGATES
POOL = [chr(c) for c in range(0x20, 0x7F)] + EDGE
CATEGORY = {
    "CATEGORY_DIGIT": ["0", "1", "5", "9", "٣", "१"],
    "CATEGORY_NOT_DIGIT": ["a", "x", " ", "_", "-", "\xe9", "Ⅷ", "\n", "\U0001F600", chr(0xD800)],
    "CATEGORY_SPACE": [" ", "\t", "\n", "\r", "\x0b", "\x0c", "\x1c", "\x1f", "\x85", "\xa0", " ", "　"],
    "CATEGORY_NOT_SPACE": ["a", "x", "_", "1", ".", "\xe9", "​", "﻿", "\U00010400", chr(0xDC00)],
    "CATEGORY_WORD": ["a", "Z", "_", "0", "\xe9", "\xdf", "Σ", "ſ", "K", "İ", "ı", "٣",
                      "Ⅷ", "\U00010400", "\U0001D41A", "中"],
    "CATEGORY_NOT_WORD": [" ", ".", "-", "$", "(", "\n", "\x85", "\U0001F600", chr(0xD800), "​", "'"],
}
CATEGORY["CATEGORY_LINEBREAK"] = ["\n"]
CATEGORY["CATEGORY_NOT_LINEBREAK"] = ["a", " "]


def stable(ch):
    """Does Unicode 13.0 see `ch` as this Python's Unicode does (as far as
    a general category tells)?"""
    c = ord(ch)
    if c < 0x250 or 0xD800 <= c < 0xE000:
        return True
    cat = unicodedata.category(ch)
    return cat != "Cn" and unicodedata.ucd_3_2_0.category(ch) == cat


def normalized(texts):
    """The texts as JSON carries them (a high surrogate before a low one
    reads back as the character they encode)."""
    return [json.loads(json.dumps(t)) for t in texts]


def compare(testcase, src, flags, texts, gate=False, **kw):
    """Assert that linre answers as re does; returns the number of texts."""
    texts = normalized(texts)
    rx = re.compile(src, flag_bits(flags))
    want = py_probe(rx, texts, **kw)
    args = {"pattern": src, "flags": flags, "texts": texts}
    args.update({k: v for k, v in kw.items() if v is not None})
    if gate:
        args["gate"] = True
    got = _native.call("linre.probe", args)
    if got != want:
        testcase.assertNotIn("error", got, f"{src!r}: {got.get('error')}")
        for t, a, b in zip(texts, want["results"], got["results"]):
            for key in a:
                testcase.assertEqual(a[key], b.get(key), f"pattern {src!r} flags {flags!r} {key} on {t!r} {kw}")
        testcase.assertEqual(want, got)
    return len(texts)


_CHECKED = None


def checked():
    """linre.check for every pattern of the pack: {name: its entry}."""
    global _CHECKED
    if _CHECKED is None:
        _CHECKED = {e["name"]: e for e in _native.call("linre.check", {})}
    return _CHECKED


def accepted(part=None, parts=1):
    """(name, source, flags) of the pack's patterns linre accepts (the
    `part`-th of `parts` shares, by position)."""
    out = [(n, s, f) for n, s, f in pack_patterns() if checked()[n]["accepted"]]
    if part is not None:
        out = out[part::parts]
    return out


def _name(op):
    return getattr(op, "name", str(op))


def _fold(rnd, ch):
    """A case variant of `ch` (as re.I may fold it), or `ch`."""
    if len(ch) != 1:
        return ch
    variants = {ch, ch.lower(), ch.upper()} | {"s": {"ſ", "S"}, "k": {"K", "K"}, "i": {"İ", "I"},
                                               "\xdf": {"ẞ"}, "σ": {"ς", "Σ"}}.get(ch.lower(), set())
    variants = sorted(v for v in variants if len(v) == 1)
    return rnd.choice(variants)


def _count(rnd, lo, hi, loose, one):
    """How many times to repeat: near a bound mostly (`loose`: just past
    one now and then). An unbounded repeat of more than one character
    (`one` false) stays short: re's backtracking takes time exponential in
    its count on a near miss of `(?:[ \\t]+-{1,2}[\\w-]+)*`, which linre's
    linear time is for (test_linre_linear.py), not this comparison."""
    if hi >= _sre_parse.MAXREPEAT:
        picks = [lo, lo, lo + 1, lo + 2, lo + rnd.randint(0, 8)] + ([lo + rnd.randint(0, 40)] if one else [])
    else:
        picks = [lo, lo, hi, rnd.randint(lo, hi), rnd.randint(lo, hi)]
    if loose:
        picks += [max(0, lo - 1)] + ([hi + 1] if hi < _sre_parse.MAXREPEAT else [])
    return min(rnd.choice(picks), lo + 700)


def _member(rnd, items, loose):
    """A character of a class (`loose`: or, now and then, one just outside
    it)."""
    if any(_name(op) == "NEGATE" for op, _ in items) or (loose and rnd.random() < 0.1):
        return rnd.choice(POOL)
    op, av = rnd.choice(items)
    name = _name(op)
    if name == "LITERAL":
        return chr(av)
    if name == "RANGE":
        lo, hi = av
        outside = [max(0, lo - 1), min(0x10FFFF, hi + 1)] if loose else []
        for _ in range(8):
            c = rnd.choice([lo, hi, rnd.randint(lo, hi), rnd.randint(lo, hi)] + outside)
            if stable(chr(c)):
                return chr(c)
        return chr(lo)
    if name == "CATEGORY":
        return rnd.choice(CATEGORY.get(_name(av), POOL))
    return rnd.choice(POOL)


def _walk(rnd, seq, out, groups, icase, budget, loose):
    items = list(seq)
    for k, (op, av) in enumerate(items):
        if len(out) > budget:
            return
        name = _name(op)
        if name == "LITERAL":
            ch = chr(av)
            out.append(_fold(rnd, ch) if icase and rnd.random() < 0.4 else ch)
        elif name == "NOT_LITERAL":
            out.append(rnd.choice([c for c in POOL if c != chr(av)]))
        elif name == "ANY":
            out.append(rnd.choice(POOL + ["\n"]))
        elif name == "IN":
            ch = _member(rnd, av, loose)
            out.append(_fold(rnd, ch) if icase and rnd.random() < 0.3 else ch)
        elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            lo, hi, body = av
            one = len(body) == 1 and _name(body[0][0]) in ("LITERAL", "NOT_LITERAL", "ANY", "IN")
            for _ in range(_count(rnd, lo, hi, loose, one)):
                _walk(rnd, body, out, groups, icase, budget, loose)
                if len(out) > budget:
                    return
        elif name == "SUBPATTERN":
            group, add, dele, body = av[0], av[1], av[2], av[-1]
            inner = (icase or bool(add & re.I)) and not (dele & re.I)
            start = len(out)
            _walk(rnd, body, out, groups, inner, budget, loose)
            if group:
                groups[group] = "".join(out[start:])
        elif name == "ATOMIC_GROUP":
            _walk(rnd, av, out, groups, icase, budget, loose)
        elif name == "BRANCH":
            _walk(rnd, rnd.choice(av[1]), out, groups, icase, budget, loose)
        elif name == "GROUPREF":
            out.append(groups.get(av, ""))
        elif name == "GROUPREF_EXISTS":
            body = av[1] if av[0] in groups else av[2]
            if body is not None:
                _walk(rnd, body, out, groups, icase, budget, loose)
        elif name == "AT":
            at = _name(av)
            if at in ("AT_END", "AT_END_LINE") and rnd.random() < 0.3:
                out.append("\n")
            elif at == "AT_BEGINNING_LINE" and rnd.random() < 0.3:
                out.append("\n")
        elif name == "ASSERT":
            # what a lookbehind wants, before; what a lookahead wants, after
            # (when nothing follows it here: what follows reads it too)
            direction, body = av
            last = k == len(items) - 1
            if rnd.random() < (0.5 if direction < 0 else 0.8 if last else 0.25):
                _walk(rnd, body, out, groups, icase, budget, loose)


def _mutate(rnd, chars):
    for _ in range(rnd.choice([0, 0, 1, 1, 2, 3])):
        k = rnd.randrange(len(chars) + 1)
        what = rnd.random()
        if what < 0.3 and chars:
            del chars[min(k, len(chars) - 1)]
        elif what < 0.6:
            chars.insert(k, rnd.choice(POOL))
        elif what < 0.8 and chars:
            chars[min(k, len(chars) - 1)] = rnd.choice(POOL)
        elif chars:
            i = rnd.randrange(len(chars))
            chars[i:i] = chars[i:i + rnd.randint(1, 6)]
    return chars


def parse(src, flags):
    return _sre_parse.parse(src, flag_bits(flags))


def sample(src, flags, rnd, count, budget=2500):
    """`count` texts from the pattern's pieces: matches, near misses, several
    in a row, and the edge characters around them."""
    tree = parse(src, flags)
    icase = bool(tree.state.flags & re.I)
    out = []
    for _ in range(count):
        chars = []
        for _ in range(rnd.choice([1, 1, 1, 2, 3])):
            if rnd.random() < 0.5:
                chars.extend(rnd.choice(EDGE + POOL) for _ in range(rnd.randint(0, 3)))
            piece = []
            _walk(rnd, tree, piece, {}, icase, budget, rnd.random() < 0.15)
            chars.extend(_mutate(rnd, piece) if rnd.random() < 0.5 else piece)
        if rnd.random() < 0.5:
            chars.extend(rnd.choice(EDGE + POOL) for _ in range(rnd.randint(0, 3)))
        out.append("".join(chars))
    return out
