"""Inputs for the regex parity test (test_rust_parity_regex.py): texts that
reach the scanner's patterns, built from core's own pattern text. Not a test.

Each pattern is run on (a) text made of the literal words its source holds
(`curl`, `require`, `.npmrc` …), joined with the characters the patterns
treat specially — quotes, brackets, operators, every kind of whitespace
Python's `\\s` knows (U+001C, U+0085, U+2028), the letters `re.I` folds
(ſ, K, İ, ı), letters `\\w` holds past ASCII (é, ٣), astral characters,
lone surrogates; (b) the hooks parity corpus's hand-written cases; and
(c) random strings of the same pieces. The seed is fixed, so a failure
reproduces.
"""
import random
import re

SPECIALS = ["\n", "\n", " ", " ", "  ", "\t", "\r", "\r\n", "\x0b", "\x0c", "\x1c", "\x1f", "\x85", "\xa0",
            " ", "　", "'", '"', "`", "\\", "/", ".", ",", ";", ":", "=", "==", "=>", "+", "-", "*",
            "(", ")", "[", "]", "{", "}", "<", ">", "|", "&", "$", "#", "@", "!", "?", "%", "^", "~", "_",
            "0", "1", "9", "a", "A", "z", "Z", "x", "ſ", "K", "İ", "ı", "é", "٣",
            "ß", "Σ", "\U0001F600", "\U0001D41A", "\ud800", "\udc00", "\x00", "\x7f", "﻿",
            "​", "ͅ", "k", "K", "s", "S", "i", "I"]

_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-/]*")


def words_of(src):
    """Literal words in a pattern's source (and their pieces)."""
    out = set()
    for m in _WORD_RE.finditer(src.replace("\\s", " ").replace("\\w", " ").replace("\\d", " ")
                               .replace("\\b", " ").replace("\\n", " ").replace("\\t", " ")):
        w = m.group()
        out.add(w)
        for part in re.split(r"[.\-/]", w):
            if part:
                out.add(part)
    return sorted(out)


def texts_for(src, rnd, count=160, most=10):
    """Random texts of a pattern's words and the special characters."""
    words = words_of(src) or ["x"]
    pieces = words * 3 + SPECIALS
    out = []
    for _ in range(count):
        n = rnd.randint(1, most)
        out.append("".join(rnd.choice(pieces) for _ in range(n)))
    return out
