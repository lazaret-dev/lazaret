"""Engine parity for SC-HOMOGLYPH's look-alike names: the npm engine's
lookalikeName (js/src/scanner/scan.js, and the dashboard's copy) against
core.lookalike_name, case by case on curated lines and a seeded random corpus
of names built from ASCII letters, every look-alike letter of the table,
letters that are not look-alikes (Cyrillic, Greek alpha / nu / rho), NFKC
compatibility forms (fullwidth, mathematical bold), the invisible U+200C /
U+200D, digits and punctuation; and the tables themselves. Columns are
compared in code points (the npm engine's are UTF-16 offsets). Then whole
files: a seeded random corpus of JavaScript, TypeScript and Python built from
literals of every kind, comments, regex literals and divisions, escapes and
look-alike names, scanned by core, the npm engine and the dashboard, whose
SC-HOMOGLYPH findings must agree (the lexer's literal spans and
names_code / namesCode). The expectations are in
tests/scanner/test_review_lookalike_names.py. Skipped where node is missing.
Every such character here is written as an escape.
"""
import json
import os
import random
import shutil
import subprocess
import unittest

from lazaret.scanner import core
from tests import _support
from tests.scanner import _dashboard_vm as dash

NODE = shutil.which("node")
SCAN_JS = os.path.join(_support.REPO_ROOT, "js", "src", "scanner", "scan.js")
NPM = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const s = await import(pathToFileURL(process.argv[1]).href);
const { cases, words } = JSON.parse(readFileSync(0, "utf8"));
const known = new Set(words);
const cp = (t, i) => [...t.slice(0, i)].length;
process.stdout.write(JSON.stringify({
  tables: { lookalikes: Object.fromEntries(s.LOOKALIKES), targets: [...s.LOOKALIKE_TARGETS].sort(), nameRun: s.NAME_RUN_SRC },
  results: cases.map(([code, lang]) => {
    const r = s.lookalikeName(code, lang, () => known);
    return r && [...r.slice(0, 5), cp(code, r[5])];
  }),
}));
"""
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
          + list(core._LOOKALIKES)
          + [chr(c) for c in (0x043F, 0x0438, 0x0432, 0x0442, 0x044F, 0x0436, 0x03B1, 0x03BD, 0x03C1, 0xFF45, 0xFF56,
                              0x1D41E, 0x200C, 0x200D, 0x00E9, 0x0131, 0x017F, 0x212A)]
          + ["eval", "isAdmin", "value", "exec", "require", " ", " ", "=", "(", ")", ".", ";", "'", "[", "]", "-"])


SPOOF = {}                                              # ASCII letter -> its look-alikes
for fake, real in core._LOOKALIKES.items():
    SPOOF.setdefault(real, []).append(fake)
TARGETS = sorted(core._LOOKALIKE_TARGETS)
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


@unittest.skipUnless(NODE, "node is not installed")
class WholeFileParityTests(unittest.TestCase):
    maxDiff = None

    def test_core_the_npm_engine_and_the_dashboard_agree(self):
        files = file_corpus()
        want = [[[i["sev"], i["line"], i["msg"]] for i in core.scan_file(path, content, lang)
                 if i["rule"] == "SC-HOMOGLYPH"] for path, lang, content in files]
        p = subprocess.run([NODE, "--input-type=module", "-e", NPM_FILES,
                            os.path.join(_support.REPO_ROOT, "js", "src", "index.js")],
                           input=json.dumps(files), capture_output=True, encoding="utf-8", timeout=60)
        if p.returncode:
            raise AssertionError(p.stderr[-2000:])
        npm = json.loads(p.stdout)
        page = [[[i["sev"], i["line"], i["msg"]] for i in issues if i["rule"] == "SC-HOMOGLYPH"]
                for issues in dash.run([{"op": "scanFile", "file": {"name": path, "lang": lang, "content": content}}
                                        for path, lang, content in files], timeout=60)]
        diffs = [(f, w, n, g) for f, w, n, g in zip(files, want, npm, page) if not w == n == g]
        self.assertEqual(diffs[:5], [])
        self.assertGreater(sum(1 for w in want if w), 150)
        self.assertGreater(sum(1 for w in want if not w), 100)


@unittest.skipUnless(NODE, "node is not installed")
class LookalikeParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus()
        p = subprocess.run([NODE, "--input-type=module", "-e", NPM, SCAN_JS],
                           input=json.dumps({"cases": cls.cases, "words": WORDS}),
                           capture_output=True, encoding="utf-8", timeout=60)
        if p.returncode:
            raise AssertionError(p.stderr[-2000:])
        out = json.loads(p.stdout)
        cls.tables, cls.results = out["tables"], out["results"]

    def test_every_case_agrees(self):
        words = frozenset(WORDS)
        diffs = []
        for (code, lang), got in zip(self.cases, self.results):
            want = core.lookalike_name(code, lang, lambda: words)
            if (list(want) if want else None) != got:
                diffs.append((code, lang, want, got))
        self.assertEqual(diffs[:10], [])
        found = [r for r in self.results if r]
        self.assertGreater(sum(1 for r in found if r[2] == "CRITICAL" and not r[3]), 40)    # a target
        self.assertGreater(sum(1 for r in found if r[3]), 30)                                # another name
        self.assertGreater(sum(1 for r in found if r[2] == "MAJOR"), 300)
        self.assertGreater(len(self.results) - len(found), 300)

    def test_the_tables_are_cores(self):
        self.assertEqual(self.tables["lookalikes"], core._LOOKALIKES)
        self.assertEqual(self.tables["targets"], sorted(core._LOOKALIKE_TARGETS))
        self.assertEqual(self.tables["nameRun"], core._NAME_RUN_RE.pattern)


if __name__ == "__main__":
    unittest.main()
