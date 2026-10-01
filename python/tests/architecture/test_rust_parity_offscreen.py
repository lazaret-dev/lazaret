"""Engine parity for SC-OFFSCREEN-CODE (0.1.8): the native engine's
offscreen_code (crates/lazaret-engine: signs.rs; the npm package runs it as
WebAssembly) against core.offscreen_code, case by case, for JavaScript and
Python lines: curated lines (the samples it was built from, and prose that
must not count) and a seeded random corpus built from blank runs around the
threshold, what may stand before them (code, an open or closed string, a
comment) and what may follow (code, a declaration, prose, a call that runs
code). Columns are code points in both. (Until 0.1.9 this held the npm
engine's JavaScript twin to core.) Skipped where the native library is not
built.

All text is inert: nothing is executed.
"""
import json
import random
import unittest

from lazaret.scanner import _native, core

CURATED = [
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
BEFORE = ["", "", "a();", "});", ")", "x = 1;", "'", '"', "`", "'a'", '"b"', "`c`", "'\\''", '"\\"', "\\", "#",
          "//", "/*", "*/", "/* c */", "# c", "\U0001F600", "é", " ", "\x1c", "\xa0", "x", " ", "\t"]
AFTER = ["require('x')", "import os", "from x import y", "exec(z)", "eval(z)", "Function(z)()", "global['r']=require",
         "const a = 1", "let b", "var c;", "function f(", "async function g(", "class K:", "def f():", "x.y = 1",
         "f(x)", "a[0] = 1", "s = 'x'", ";", ",", "(", ")", "{", "}", "[", "]", "y,", "for more", "│", "and so on",
         "child_process", "spawn(", "b64decode(x)", "String.fromCharCode(1)", "atob(x)", "\U0001F600",
         "x" * 80, "__import__('os')", "compile(s)", "execSync('a')"]


def corpus(seed=20260929, count=4000):
    rnd = random.Random(seed)
    cases = list(CURATED)
    for _ in range(count):
        before = "".join(rnd.choice(BEFORE) for _ in range(rnd.randint(0, 3)))
        blanks = "".join(rnd.choice(" \t") if rnd.random() < 0.1 else " "
                         for _ in range(rnd.choice([16, 100, 149, 150, 151, 200, 731])))
        after = "".join(rnd.choice(AFTER) for _ in range(rnd.randint(1, 3)))
        cases.append((before + blanks + after + rnd.choice(["", ";", ")", " // x", " # x"]), rnd.choice(["js", "py"])))
    return [json.loads(json.dumps(c)) for c in cases]


def core_view(case):
    found = core.offscreen_code(case[0], case[1])
    return list(found) if found else None


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class OffscreenParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus()
        calls = [["offscreen_code", {"lang": lang}, text] for text, lang in cls.cases]
        cls.results = [r.get("ok", r) for r in _native.call("batch", {"calls": calls})]

    def test_every_case_agrees(self):
        diffs = [(c, core_view(c), r) for c, r in zip(self.cases, self.results) if core_view(c) != r]
        self.assertEqual(diffs[:10], [])
        found = [core_view(c) for c in self.cases]
        self.assertGreater(sum(1 for f in found if f and f[3]), 300)          # CRITICAL: hidden code that runs code
        self.assertGreater(sum(1 for f in found if f and not f[3]), 300)      # MAJOR
        self.assertGreater(sum(1 for f in found if not f), 300)               # and its absence

    def test_the_curated_lines(self):
        want = [True, True, True, False, False, False, False, False, False, False, False, False, True, True, False,
                True, True, True, True, True, True, True]
        self.assertEqual([core.offscreen_code(t, lang) is not None for t, lang in CURATED], want)


if __name__ == "__main__":
    unittest.main()
