"""The engine's lexers (rust/crates/lazaret-engine/src/lex/: the `lex.tokens`
and `lex.structure` calls) held to the parsers and to Python's tokenizer:

* JavaScript: every literal the engine's JavaScript parser (`js_parse`)
  finds — a string, a regular expression, a template's text, JSX text — is a
  token of the lexer's reading in the file's dialect, span for span, and in
  a JavaScript file the lexer finds no other (a TypeScript file's types,
  which the parser skips, may hold more); on the inputs the parser's own
  tests read (curated snippets, the repository's JavaScript, seeded
  generated projects, token soups and mutations of real files).
* Python: every string and comment Python 3.13's tokenize finds is the
  lexer's, span for span (an f-string from its start to its end, its
  pieces between), and the lexer finds no other, on the repository's own
  Python, pyparse's curated cases and seeded generated programs (none of
  which holds a t-string, which the lexer reads as Python 3.14 does).
* The structure the detectors read: what both readings of a text agree on
  (JavaScript with JSX and without, Python as 3.12 and as 3.11 read it).
* Both lexers are total: on any text, every character in at most one
  token, in order (seeded soups of the characters that matter).

The JavaScript oracle is the engine's own parser (held to jsparse.py's trees
by test_jsparse_native*.py); the Python one is a python3.13 subprocess (the
suite runs on Python 3.10 to 3.14), skipped where there is none. Inert text
only: nothing is executed. Skipped where the native library is not built.
"""
import json
import random
import subprocess
import unittest

from lazaret.scanner import _native, jsparse
from tests.architecture import jsgen
from tests.architecture import jsparse_cases as jcases
from tests.architecture import pyparse_cases as pcases
from tests.architecture import pyparse_oracle
from tests.architecture import test_js_parity_parse as twin

PYTHON313 = pyparse_oracle.PYTHON313

# the literal kinds both sides name, a JSX attribute's string a string
LITERAL = {"str": "str", "jsx_str": "str", "regex": "regex", "template": "template", "jsx_text": "jsx_text"}

# tokenize run by python3.13: a JSON list of sources on stdin; for each, null
# where tokenize refuses it, else its strings, f-string starts and ends and
# comments as [kind, start, end] in code points
TOKENIZER = r'''
import io, json, sys, tokenize
out = []
for src in json.load(sys.stdin):
    starts, at = [], 0
    for line in src.split("\n"):
        starts.append(at)
        at += len(line) + 1
    pos = lambda rc: starts[rc[0] - 1] + rc[1]
    toks = []
    try:
        for t in tokenize.generate_tokens(io.StringIO(src).readline):
            if t.type == tokenize.STRING:
                toks.append(["str", pos(t.start), pos(t.end)])
            elif t.type == tokenize.COMMENT:
                toks.append(["comment", pos(t.start), pos(t.end)])
            elif t.type == tokenize.FSTRING_START:
                toks.append(["fstart", pos(t.start), pos(t.end)])
            elif t.type == tokenize.FSTRING_END:
                toks.append(["fend", pos(t.start), pos(t.end)])
    except (SyntaxError, tokenize.TokenError):
        toks = None
    out.append(toks)
json.dump(out, sys.stdout)
'''


def tokens(text, lang, jsx=True):
    return _native.call("lex.tokens", {"lang": lang, "jsx": jsx}, text)


def tree_literals(tree):
    """(kind, start, end) of every literal node of a js_parse tree."""
    out, stack = set(), [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
            continue
        if not isinstance(node, dict):
            continue
        t = node.get("type")
        if t == "Literal" and node.get("kind") in ("string", "regex"):
            out.add(("str" if node["kind"] == "string" else "regex", node["start"], node["end"]))
        elif t == "TemplateElement":
            out.add(("template", node["start"], node["end"]))
        elif t == "JSXText":
            out.add(("jsx_text", node["start"], node["end"]))
        stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
    return out


def js_differences(items, limit=5):
    """[(path, missing, extra)] where the lexer's literals and the parser's
    differ (in a TypeScript file only what the lexer misses counts), and the
    number of files and literals compared."""
    found, files, literals = [], 0, 0
    for path, src in items:
        ts, jsx = jsparse.dialect(path)
        status, answer = jcases.native_raw("js_parse_file", {"path": path, "spans": True}, src)
        tree = json.loads(answer)
        if status != 0 or "error" in tree:
            continue
        want = tree_literals(tree)
        got = {(LITERAL[k], a, b) for k, a, b in tokens(src, "js", jsx) if k in LITERAL}
        missing, extra = want - got, set() if ts else got - want
        files += 1
        literals += len(want)
        if (missing or extra) and len(found) < limit:
            show = lambda s: sorted((k, src[a:b][:40]) for k, a, b in s)[:3]  # noqa: E731
            found.append((path, show(missing), show(extra)))
    return found, files, literals


def py_oracle(sources):
    """python3.13's tokenize on each source (see TOKENIZER)."""
    run = subprocess.run([PYTHON313, "-c", TOKENIZER], input=json.dumps(sources).encode("ascii"), capture_output=True,
                         timeout=40, check=True)
    return json.loads(run.stdout.decode("ascii"))


def py_differences(sources, limit=5):
    """[(index, source, what differs)] where the lexer's strings, f-strings
    and comments are not tokenize's, and the number of sources compared (a
    source with a CR, a form feed or a NUL is left out: tokenize's lines and
    the lexer's are counted differently there)."""
    keep = [i for i, s in enumerate(sources) if "\r" not in s and "\f" not in s and "\0" not in s]
    found, compared = [], 0
    for i, want in zip(keep, py_oracle([sources[i] for i in keep])):
        src = sources[i]
        if want is None:
            continue
        compared += 1
        got = tokens(src, "py")
        diff = []
        for kind in ("str", "comment"):
            w = [(a, b) for k, a, b in want if k == kind]
            g = [(a, b) for k, a, b in got if k == kind]
            if w != g:
                diff.append((kind, sorted(set(w) ^ set(g))[:3]))
        pieces = [(a, b) for k, a, b in got if k == "template"]
        fstarts = sorted(a for k, a, _ in want if k == "fstart")
        fends = sorted(b for k, _, b in want if k == "fend")
        if sorted(a for a, _ in pieces if a in fstarts) != fstarts or sorted(b for _, b in pieces if b in fends) != fends:
            diff.append(("f-strings", fstarts[:3], fends[:3], pieces[:6]))
        # every piece is in an f-string: after a start, before its end
        spans = list(zip(fstarts, fends)) if len(fstarts) == len(fends) else []
        if spans and any(not any(s <= a and b <= e for s, e in spans) for a, b in pieces):
            diff.append(("piece outside an f-string", pieces[:6]))
        if diff and len(found) < limit:
            found.append((i, json.dumps(src)[:160], diff))
    return found, compared


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class JavaScriptLexerTests(unittest.TestCase):
    maxDiff = None

    def same(self, items, files, literals):
        found, n, k = js_differences(items)
        self.assertEqual(found, [])
        self.assertGreaterEqual(n, files)
        self.assertGreaterEqual(k, literals)

    def test_snippets(self):
        self.same(twin.items_of(twin.SNIPPETS), 40, 30)

    def test_own_sources(self):
        self.same(twin.own_sources(), 100, 10_000)

    def test_generated_projects(self):
        self.same([(f["path"], f["content"]) for files in jsgen.projects(20261002, 40) for f in files], 100, 5_000)

    def test_soups_and_mutations(self):
        # (most do not parse: the ones that do are compared)
        self.same(twin.soups(20261002, 800) + twin.mutations(twin.own_sources(), 20261002, 200), 50, 1_000)

    def test_typescript_types_are_read_too(self):
        # the parser skips a type; its strings are strings all the same
        src = "type U = 'a' | `b${C}`; declare module 'm' { }\nlet x = 'y'"
        kinds = [(k, src[a:b]) for k, a, b in tokens(src, "js", False) if k in LITERAL]
        self.assertEqual(kinds, [("str", "'a'"), ("template", "`b${"), ("template", "}`"), ("str", "'m'"),
                                 ("str", "'y'")])


@unittest.skipUnless(PYTHON313, pyparse_oracle.SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class PythonLexerTests(unittest.TestCase):
    maxDiff = None

    def same(self, sources, compared):
        found, n = py_differences(sources)
        self.assertEqual(found, [])
        self.assertGreaterEqual(n, compared)

    def test_own_sources(self):
        self.same(pcases.own_sources(), 300)

    def test_curated_cases(self):
        self.same(pcases.STATEMENTS + pcases.EXPRESSIONS + pcases.MATCH + pcases.ERRORS, 100)

    def test_generated_programs(self):
        self.same(pcases.programs(20261002, 300), 250)

    def test_fstrings_and_their_holes(self):
        self.same(['f"{x!r:>{w}} {{y}}"\n', "f'''a\n{b # c\n}'''\n", 'f"{f"{1}"}"  # n\n', "rb'\\'' 'x'\n",
                   "x = f'{a}' f\"{b}\" 'c'  # d\n", "f'{x:{y}.{z}}' # e\n"], 6)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class StructureTests(unittest.TestCase):
    maxDiff = None

    def structure(self, src, lang, jsx=True):
        st = _native.call("lex.structure", {"lang": lang, "jsx": jsx}, src)
        return {k: [src[a:b] for a, b in v] for k, v in st.items()}

    def test_javascript(self):
        st = self.structure("a = `x ${ y /* c */ } z` // d\nb = <i>'</i>; c = '\\''", "js")
        self.assertEqual(st["comments"], ["/* c */", "// d"])
        # (the JSX text's apostrophe: the plain reading pairs it with a quote,
        # so neither its text nor the string after it is a literal of both)
        self.assertEqual(st["literals"][:2], ["`x ${", "} z`"])
        self.assertEqual(self.structure("c = '\\''", "js", False)["strings"], ["'\\''"])

    def test_python(self):
        st = self.structure('x = f"{a + "#"}"  # c\ns = """\n# no\n"""\n', "py")
        self.assertEqual(st["comments"], ["# c"])
        self.assertEqual(st["strings"], ['"""\n# no\n"""'])
        self.assertEqual(st["literals"], ['f"', '"', '"""\n# no\n"""'])

    def test_other_languages(self):
        with self.assertRaises(_native.NativeError):
            _native.call("lex.structure", {"lang": "sh"}, "x")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class TotalTests(unittest.TestCase):
    ALPHABET = list("`'\"/\\*{}()[]<>!-#$=:;,.?+\n\r\t  abcfrtx01_") + [" ", "${", "</", "/*", "*/", "<!--", "-->",
                                                                           "'''", '"""', "f'", 'f"', "#!", "{{", "}}"]

    def test_every_character_once_on_soups(self):
        rng = random.Random(20261002)
        for _ in range(2000):
            src = "".join(rng.choice(self.ALPHABET) for _ in range(rng.randint(0, 60)))
            for lang, jsx in (("js", False), ("js", True), ("py", True)):
                at = 0
                for kind, a, b in tokens(src, lang, jsx):
                    self.assertTrue(at <= a <= b <= len(src), (src, lang, jsx, kind, a, b))
                    at = b
                _native.call("lex.structure", {"lang": lang, "jsx": jsx}, src)


if __name__ == "__main__":
    unittest.main()
