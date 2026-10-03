"""Smaller pieces of the engine, held to their recorded outputs
(_snapshots.py) on seeded corpora: SC-HEXSTR's names and text written in
escapes (hex_view: \\xNN, \\uNNNN, \\u{N…}, \\UNNNNNNNN and octal, on the
dangerous words and on random pieces), SC-HOMOGLYPH's look-alike names
(lookalike_view: ASCII letters, every look-alike letter of the table,
letters that are not look-alikes, NFKC compatibility forms, the invisible
U+200C / U+200D, digits and punctuation) and SC-OFFSCREEN-CODE (code pushed
past the screen's edge by a run of blanks, and lines that must not count).
"""
import json
import random
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots

HEX_CURATED = [
    'var m = global["\\x72\\x65\\x71\\x75\\x69\\x72\\x65"]("child_process");', 'x = "\\x65val"', 'x = "\\\\x65val"',
    'x = "\\\\\\x65val"', 'u = "https:\\u002F\\u002Fexample.invalid"', 'u = "\\u0068ttps://example.invalid"',
    'w["\\u{65}v\\u0061l"](x)', 's = "\\145val"', 'b = b"\\x00\\x01\\x65val"', 'b = b"\\x00\\x65\\x76\\x61\\x6c"',
    'x = "\\x41PI system"', 'x = "sy\\x73tem"', 'x = "e\\x76al_thing"', 'k = "\\x5f_import__"', 'p = "\\U00000065xec"',
    'x = "\\x65"; y = "val"', "a = '\\x00\\x00\\x00'; b = '\\x65val'", 'x = "\\u00e9val"', 'x = "\\U0001F600\\x65val"',
    'x = "\\UFFFFFFFF\\x65val"', 'x = "\\u{110000}\\x65val"', 'x = `\\x63url -s x`', 'x = "\\x2Fbin\\x2Fsh"',
    'x = "/b\\x69n/sh"', 'x = "\\x70ickle.loads"', 'x = "\U0001F600" + "\\x65val"', 'x = "é\\x65val"',
    'x = "\\x65val" + "\\x65xec"', "\\x65val", '"\\x65val', 'x = ""', 'x = "\\"\\x65val"',
]
HEX_PIECES = ["\\x65", "\\x76", "\\x61", "\\x6c", "\\x45", "\\x72", "\\x71", "\\x69", "\\x00", "\\x7f", "\\x20", "\\x2f", "\\x5f",
          "\\u0065", "\\u0076", "\\u00e9", "\\u002F", "\\ud83d", "\\u{65}", "\\u{1F600}", "\\u{110000}", "\\U00000065",
          "\\U0001F600", "\\145", "\\166", "\\777", "\\", "\\\\", "\\\\\\", "x", "e", "v", "a", "l", "val", "eval", "exec",
          "require", "system", "curl", "https://", "/bin/sh", "import", "_", "0", "9", " ", "é", "\U0001F600", "ſ",
          "\u212a", "İ", "\x1c", '"', '"', "'", "`", "+", ";", "(", ")", "[", "]", "/"]


HEX_WORDS = ["eval", "exec", "execSync", "require", "system", "popen", "spawn", "curl", "wget", "https://",
         "http://", "/bin/sh", "/bin/bash", "__import__", "import", "base64", "atob", "Function", "fromCharCode",
         "marshal", "pickle", "child_process", "subprocess", "powershell", "cmd.exe", "compile", "b64decode", "EVAL"]


def escape(ch, rnd):
    """ch written as one of the escape forms (octal only below 0o1000)."""
    c = ord(ch)
    return rnd.choice([f"\\x{c:02x}", f"\\x{c:02X}", f"\\u{c:04x}", f"\\u{{{c:x}}}", f"\\U{c:08x}", f"\\{c:03o}"])


def hex_corpus(seed=20260927, count=3000):
    rnd = random.Random(seed)
    cases = list(HEX_CURATED)
    for _ in range(count):
        q = rnd.choice(['"', "'", "`"])
        if rnd.random() < 0.6:                      # a dangerous word, some of it escaped
            word = "".join(escape(ch, rnd) if rnd.random() < 0.4 else ch for ch in rnd.choice(HEX_WORDS))
            body = ("".join(rnd.choice(HEX_PIECES) for _ in range(rnd.randint(0, 4))) + word
                    + "".join(rnd.choice(HEX_PIECES) for _ in range(rnd.randint(0, 4))))
        else:
            body = "".join(rnd.choice(HEX_PIECES) for _ in range(rnd.randint(1, 12)))
        cases.append(rnd.choice(["x = ", "w[", "", "f("]) + q + body + q + rnd.choice(["", ";", ")", "](x)"]))
    return [json.loads(json.dumps(c)) for c in cases]


OFF_CURATED = [
    ("});" + " " * 731 + "global['_V']='8-npm20';global['r']=require;(function(){var mGB=''", "js"),
    (")" + " " * 515 + ";from fernet import Fernet;data = Fernet(b'x');exec(data)", "py"),
    ("/* Start point of React module */" + " " * 268 + "const _0x213e5c=_0x43d3;(function(a,b){})", "js"),
    ("    ignation of what errors, if an" + " " * 534 + "y,", "py"),
    ("    note it may not be accurate if" + " " * 189 + "│", "py"),
    (" " * 101 + "cmd_line_options_in,", "py"),
    ("x = '" + " " * 200 + "import os'", "py"),
    ("x = 1  # " + " " * 200 + "import os", "py"),
    ("var s = `" + " " * 200 + "require('x')`", "js"),
    ("// " + " " * 200 + "require('x')", "js"),
    ("/* " + " " * 200 + "require('x')", "js"),
    ("a();" + " " * 149 + "require('x')", "js"),
    ("a();" + " " * 150 + "require('x')", "js"),
    ("a();" + "\t" * 150 + "eval(x)", "js"),
    ("a();" + " " * 150 + "for more details", "js"),
    ("a();" + " " * 150 + "function f() {}", "js"),
    ("a();" + " " * 150 + "class Foo {}", "py"),
    ("a();" + " " * 150 + "def run(): pass", "py"),
    ("x = \"\\\"\"" + " " * 160 + "import os", "py"),
    ("x = \"\\\\\"" + " " * 160 + "import os", "py"),
    ("\U0001F600\U0001F600;" + " " * 170 + "require('\U0001F600')", "js"),
    ("é;" + " " * 170 + "x.y = 1" + "z" * 5000 + "atob(q)", "js"),
]
OFF_BEFORE = ["", "", "a();", "});", ")", "x = 1;", "'", '"', "`", "'a'", '"b"', "`c`", "'\\''", '"\\"', "\\", "#",
          "//", "/*", "*/", "/* c */", "# c", "\U0001F600", "é", " ", "\x1c", "\xa0", "x", " ", "\t"]
OFF_AFTER = ["require('x')", "import os", "from x import y", "exec(z)", "eval(z)", "Function(z)()", "global['r']=require",
         "const a = 1", "let b", "var c;", "function f(", "async function g(", "class K:", "def f():", "x.y = 1",
         "f(x)", "a[0] = 1", "s = 'x'", ";", ",", "(", ")", "{", "}", "[", "]", "y,", "for more", "│", "and so on",
         "child_process", "spawn(", "b64decode(x)", "String.fromCharCode(1)", "atob(x)", "\U0001F600",
         "x" * 80, "__import__('os')", "compile(s)", "execSync('a')"]


def off_corpus(seed=20260929, count=4000):
    rnd = random.Random(seed)
    cases = list(OFF_CURATED)
    for _ in range(count):
        before = "".join(rnd.choice(OFF_BEFORE) for _ in range(rnd.randint(0, 3)))
        blanks = "".join(rnd.choice(" \t") if rnd.random() < 0.1 else " "
                         for _ in range(rnd.choice([16, 100, 149, 150, 151, 200, 731])))
        after = "".join(rnd.choice(OFF_AFTER) for _ in range(rnd.randint(1, 3)))
        cases.append((before + blanks + after + rnd.choice(["", ";", ")", " // x", " # x"]), rnd.choice(["js", "py"])))
    return [json.loads(json.dumps(c)) for c in cases]


# the look-alike table, as the engine's rule pack holds it
_LOOKALIKES, _LOOKALIKE_TARGETS = (_snapshots.pack("_LOOKALIKES", "_LOOKALIKE_TARGETS") if _native.available()
                                   else ({}, []))
WORDS = ["eval", "isAdmin", "value", "data", "a", "ab", "count", "Function", "result", "config"]
CURATED = [
    ("const \\u0435val = eval;", "js"), ("\\u0435val(x)", "js"), ("if (isAdm\\u0456n) {", "js"), ("v\\u0430lue = 1", "py"),
    ("/[\\u0430-\\u044f]/", "js"), ("\\u043f\\u0440\\u0438\\u0432\\u0435\\u0442 = 1", "py"), ("\\uff45val(x)", "js"),
    ("\\uff45val(x)", "py"), ("eva\\u200dl(x)", "js"), ("\\u0435\\u0445\\u0435\\u0441(c)", "py"), ("\\u03b1 = 0.05", "py"),
    ("\\u039f = 1", "py"), ("x = 1", "js"), ("c\\u043eunt += 1", "js"), ("\\U0001d41eval(x)", "js"),
    ("\\u0430\\u0431", "js"), ("1\\u0435", "js"), ("$\\u0435val", "js"), ("\\u0421ount", "js"), ("\\ufb01le", "js"),
]


def unescape(text):
    return text.encode("ascii").decode("unicode-escape")


PIECES = (["e", "v", "a", "l", "i", "s", "A", "d", "m", "n", "c", "o", "u", "t", "x", "_", "$", "0", "7"]
          + list(_LOOKALIKES)
          + [chr(c) for c in (0x043F, 0x0438, 0x0432, 0x0442, 0x044F, 0x0436, 0x03B1, 0x03BD, 0x03C1, 0xFF45, 0xFF56,
                              0x1D41E, 0x200C, 0x200D, 0x00E9, 0x0131, 0x017F, 0x212A)]
          + ["eval", "isAdmin", "value", "exec", "require", " ", " ", "=", "(", ")", ".", ";", "'", "[", "]", "-"])


SPOOF = {}                                              # ASCII letter -> its look-alikes
for fake, real in _LOOKALIKES.items():
    SPOOF.setdefault(real, []).append(fake)
TARGETS = sorted(_LOOKALIKE_TARGETS)
OTHERS = ["isAdmin", "value", "data", "count", "result", "config", "request", "open"]


def spoof(name, rnd):
    """name with some letters swapped for look-alikes (or a compatibility
    form, or an invisible character after them)."""
    out = []
    for ch in name:
        roll = rnd.random()
        if roll < 0.3 and ch in SPOOF:
            out.append(rnd.choice(SPOOF[ch]))
        elif roll < 0.35 and ch.isalpha():
            out.append(chr(ord(ch) - ord("a") + 0xFF41) if ch.islower() else ch)       # fullwidth
        else:
            out.append(ch)
        if rnd.random() < 0.04:
            out.append(rnd.choice([chr(0x200C), chr(0x200D)]))
    return "".join(out)


def corpus(seed=20260928, count=3000):
    rnd = random.Random(seed)
    cases = [(unescape(code), lang) for code, lang in CURATED]
    for _ in range(count):
        if rnd.random() < 0.5:                          # a name with some letters spoofed
            code = ("".join(rnd.choice(PIECES) for _ in range(rnd.randint(0, 3))) + spoof(rnd.choice(TARGETS if rnd.random() < 0.5 else OTHERS), rnd)
                    + "".join(rnd.choice(PIECES) for _ in range(rnd.randint(0, 3))))
        else:
            code = "".join(rnd.choice(PIECES) for _ in range(rnd.randint(1, 10)))
        cases.append((code, rnd.choice(["js", "py"])))
    return cases


def snapshot_sets():
    return {"hex_view": lambda: [("hex_view", {}, c) for c in hex_corpus()],
            "lookalike_view": lambda: [("lookalike_view", {"lang": lang, "words": WORDS}, code)
                                       for code, lang in corpus()],
            "offscreen": lambda: [("offscreen_code", {"lang": lang}, text) for text, lang in off_corpus()]}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class SmallSnapshotTests(unittest.TestCase):
    def answers(self, name):
        answers = _snapshots.run(snapshot_sets()[name]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, name, answers)
        return [a["ok"] for a in answers]

    def test_hex_names(self):
        found = sum(1 for r in self.answers("hex_view") if r[0])
        self.assertGreater(found, 300)                  # the corpus reaches the finding
        self.assertGreater(len(hex_corpus()) - found, 300)     # and its absence

    def test_lookalike_names(self):
        results = self.answers("lookalike_view")
        found = [r for r in results if r]
        self.assertGreater(sum(1 for r in found if r[2] == "CRITICAL" and not r[3]), 40)    # a target
        self.assertGreater(sum(1 for r in found if r[3]), 30)                                # another name
        self.assertGreater(sum(1 for r in found if r[2] == "MAJOR"), 300)
        self.assertGreater(len(results) - len(found), 300)

    def test_offscreen_code(self):
        found = self.answers("offscreen")
        self.assertGreater(sum(1 for f in found if f and f[3]), 300)          # CRITICAL: hidden code that runs code
        self.assertGreater(sum(1 for f in found if f and not f[3]), 300)      # MAJOR
        self.assertGreater(sum(1 for f in found if not f), 300)               # and its absence
        want = [True, True, True, False, False, False, False, False, False, False, False, False, True, True, False,
                True, True, True, True, True, True, True]
        self.assertEqual([f is not None for f in found[:len(OFF_CURATED)]], want)


if __name__ == "__main__":
    unittest.main()
