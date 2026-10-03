"""Engine parity for SC-HOMOGLYPH's look-alike names, on whole files: a
seeded random corpus of JavaScript, TypeScript and Python built from
literals of every kind, comments, regex literals and divisions, escapes and
look-alike names, scanned by core and by the npm engine (its native engine,
as WebAssembly, and its comment layout, the engine's lexers'), whose
SC-HOMOGLYPH findings must agree (the lexers' literal spans and names_code /
namesCode). The dashboard keeps its own comment lexer until it runs the
engine (it reads a template's `${…}` and an f-string's fields as text, and
some of this corpus's regex literals and divisions otherwise), so it is
held to the CLI on the fixtures and the curated inputs of
tests/scanner/test_review_dashboard_parity.py instead. The name corpus here
(curated lines and a seeded random corpus of names built from ASCII letters,
every look-alike letter of the table, letters that are not look-alikes
(Cyrillic, Greek alpha / nu / rho), NFKC compatibility forms (fullwidth,
mathematical bold), the invisible U+200C / U+200D, digits and punctuation)
holds the native engine's lookalike_name to its recorded outputs in
test_snapshot_small.py. The expectations are in
tests/scanner/test_review_lookalike_names.py. Skipped where the npm engine
is not built. Every such character here is written as an escape.
"""
import json
import os
import random
import subprocess
import unittest

from lazaret.scanner import core
from tests import _support
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP

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
          + list(_support.pack("_LOOKALIKES"))
          + [chr(c) for c in (0x043F, 0x0438, 0x0432, 0x0442, 0x044F, 0x0436, 0x03B1, 0x03BD, 0x03C1, 0xFF45, 0xFF56,
                              0x1D41E, 0x200C, 0x200D, 0x00E9, 0x0131, 0x017F, 0x212A)]
          + ["eval", "isAdmin", "value", "exec", "require", " ", " ", "=", "(", ")", ".", ";", "'", "[", "]", "-"])


SPOOF = {}                                              # ASCII letter -> its look-alikes
for fake, real in _support.pack("_LOOKALIKES").items():
    SPOOF.setdefault(real, []).append(fake)
TARGETS = sorted(_support.pack("_LOOKALIKE_TARGETS"))
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


# ---- whole files ----
FILE_PIECES = {
    "any": [" ", " ", " ", "\n", "\n", "=", "(", ")", "{", "}", ";", ",", "+", "/", "x", "a", "2", "value", "eval",
            "'", '"', "\\", "\\'", '\\"', "\\\n", "[", "]", "-", ".test(s)"],
    "js": ["//", "/*", "*/", "/[a-z", "]/", "/x/g", "return /", "`", "${", "=> /", "\\u0435val", "\\u{435}val",
           "\\u017F", "\\uFF10", "\\u0061", "<b>", "</b>", "<a title='", "i++ /", "} /", "const "],
    "py": ["#", '"""', "'''", 'f"', "f'", "rb'", "\\N{", ":", "def f():\n    ", "r'"],
}
FILE_NON_ASCII = ["\u0430", "\u044f", "\u017f", "\u00ba", "\u00aa", "\u0441e", "\uff45", "\u200d", "\u03b1",
                  "\u043f\u0440\u0438", "\ufb03", "\u0410-\u042f"]


def file_corpus(seed=20260926, count=500):
    rnd = random.Random(seed)
    out = []
    for n in range(count):
        name = rnd.choice(["x.js", "x.js", "x.ts", "x.py", "x.py"])
        lang = "py" if name.endswith(".py") else "js"
        pieces = FILE_PIECES["any"] + FILE_PIECES[lang]
        parts = []
        for _ in range(rnd.randint(3, 40)):
            roll = rnd.random()
            if roll < 0.12:
                parts.append(spoof(rnd.choice(TARGETS if rnd.random() < 0.5 else OTHERS), rnd))
            elif roll < 0.2:
                parts.append(rnd.choice(FILE_NON_ASCII))
            else:
                parts.append(rnd.choice(pieces))
        out.append((f"f{n}/{name}", lang, "".join(parts)))
    return out


NPM_FILES = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const { scanFile } = await import(pathToFileURL(process.argv[1]).href);
const files = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(files.map(([path, lang, content]) => scanFile({ path, content, lang })
  .filter((i) => i.rule === "SC-HOMOGLYPH").map((i) => [i.sev, i.line, i.msg]))));
"""


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class WholeFileParityTests(unittest.TestCase):
    maxDiff = None

    def test_core_and_the_npm_engine_agree(self):
        files = file_corpus()
        want = [[[i["sev"], i["line"], i["msg"]] for i in core.scan_file(path, content, lang)
                 if i["rule"] == "SC-HOMOGLYPH"] for path, lang, content in files]
        p = subprocess.run([NPM_READY, "--input-type=module", "-e", NPM_FILES,
                            os.path.join(_support.REPO_ROOT, "js", "src", "index.js")],
                           input=json.dumps(files), capture_output=True, encoding="utf-8", timeout=60)
        if p.returncode:
            raise AssertionError(p.stderr[-2000:])
        npm = json.loads(p.stdout)
        diffs = [(f, w, n) for f, w, n in zip(files, want, npm) if w != n]
        self.assertEqual(diffs[:5], [])
        self.assertGreater(sum(1 for w in want if w), 150)
        self.assertGreater(sum(1 for w in want if not w), 100)


if __name__ == "__main__":
    unittest.main()
