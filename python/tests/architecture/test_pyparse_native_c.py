"""The native engine's Python parser against Python 3.13's `ast.parse` (see
test_pyparse_native.py) on what it reads with Unicode 15.1, Python 3.13's
version, rather than the engine's 13.0 (rust/crates/lazaret-engine/src/
pyparse/unidata.rs, written by scripts/make_pyparse_tables.py):

* the tables are those Python 3.13's unicodedata gives (the script's
  `--check`);
* every character an identifier may start or go on with (str.isidentifier()
  in Python 3.13), each in a name, and 3,000 seeded characters it may not
  hold: the same trees (names normalized to NFKC as Python normalizes them),
  the same refusals;
* every character name unicodedata gives, every alias, in a `\\N{…}` escape
  (and a seeded sample of them in lowercase): the same strings.

Inert text only: nothing is executed. Skipped where Python 3.13 or the
native library is missing.
"""
import json
import os
import random
import subprocess
import unittest

from lazaret.scanner import _native
from tests import _support
from tests.architecture import pyparse_oracle as oracle

# run by python3.13: the identifier characters and the names, as JSON
UNICODE = r'''
import json, sys, unicodedata
chars = [c for c in range(0x80, 0x110000) if not 0xD800 <= c < 0xE000]
start = [c for c in chars if chr(c).isidentifier()]
cont = [c for c in chars if ("a" + chr(c)).isidentifier()]
names = [n for n in (unicodedata.name(chr(c), None) for c in range(0x110000)) if n]
sys.stdout.write(json.dumps({"version": unicodedata.unidata_version, "start": start, "continue": cont, "names": names}))
'''


def chunks(lines, n):
    return ["".join(lines[i:i + n]) for i in range(0, len(lines), n)]


@unittest.skipUnless(oracle.PYTHON313, oracle.SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NativePythonParseUnicodeTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        p = subprocess.run([oracle.PYTHON313, "-c", UNICODE], capture_output=True, timeout=40)
        cls.data = json.loads(p.stdout.decode("ascii"))

    def same(self, sources):
        want = oracle.oracle(sources)
        self.assertEqual(oracle.differences(sources, answers=want), [])
        return want

    def test_the_tables_are_python_313s(self):
        script = os.path.join(_support.REPO_ROOT, "scripts", "make_pyparse_tables.py")
        p = subprocess.run([oracle.PYTHON313, script, "--check"], capture_output=True, encoding="utf-8",
                           errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.data["version"], "15.1.0")

    def test_every_identifier_character(self):
        start, cont = self.data["start"], self.data["continue"]
        self.assertGreater(len(start), 130_000)
        sources = chunks([chr(c) + "\n" for c in start], 20_000) + chunks(["a" + chr(c) + "\n" for c in cont], 20_000)
        want = self.same(sources)
        self.assertFalse([w[:200] for w in want if oracle.is_error(w)])
        # characters no identifier holds, each alone: refused by both
        allowed = set(cont)
        rng = random.Random(20261001)
        others = [c for c in (rng.randrange(0x80, 0x110000) for _ in range(20_000))
                  if c not in allowed and not 0xD800 <= c < 0xE000][:3000]
        want = self.same(["a" + chr(c) + "\n" for c in others])
        self.assertEqual([chr(c) for c, w in zip(others, want) if not oracle.is_error(w)], [])

    def test_every_character_name(self):
        names = self.data["names"]
        self.assertGreater(len(names), 138_000)
        rng = random.Random(20261001)
        lower = [n.lower() for n in rng.sample(names, 5000)]
        sources = chunks(["'\\N{%s}'\n" % n for n in names + lower], 6000)
        want = self.same(sources)
        self.assertFalse([w[:200] for w in want if oracle.is_error(w)])

    def test_every_alias(self):
        script = os.path.join(_support.REPO_ROOT, "scripts", "make_pyparse_tables.py")
        with open(script, encoding="utf-8") as f:
            text = f.read()
        # (the aliases the script lists: `code;alias`, `|` or a line break between)
        block = text.split('ALIASES = """', 1)[1].split('"""', 1)[0]
        aliases = [a.split(";", 1)[1] for a in block.replace("\n", "|").split("|") if ";" in a]
        self.assertGreater(len(aliases), 200)
        vs = ["VS%d" % k for k in range(1, 257)]
        sources = chunks(["'\\N{%s}'\n" % a for a in aliases + vs] + ["'\\N{%s}'\n" % a.lower() for a in aliases], 500)
        want = self.same(sources)
        self.assertFalse([w[:200] for w in want if oracle.is_error(w)])
        # a named sequence is no character: refused by both
        want = self.same(["'\\N{LATIN CAPITAL LETTER A WITH MACRON AND GRAVE}'", "'\\N{KEYCAP NUMBER SIGN}'"])
        self.assertTrue(all(oracle.is_error(w) for w in want))


if __name__ == "__main__":
    unittest.main()
