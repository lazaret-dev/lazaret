"""FP-HOMOGLYPH-ORDINAL: an ordinal indicator after a letter or digit in display text is not a look-alike name.

The false positive: John's fp-tally over 261 GitHub scans (Oct 21) found SC-HOMOGLYPH (MAJOR, WARN) on
doomvault/src/library/LocalLibrary.tsx:581: "'Nº' reads as 'No' but is spelled with U+00BA for 'o'". "Nº" is the
usual way to write "number" in Spanish, Portuguese and Italian, here in a label: JSX text. A file that may hold JSX is
read with JSX and without, and only what both readings hold as literals is left out of names; JSX text is code to the
reading without JSX, so `<span>Nº {n}</span>` was read as a name. A look-alike matters where a name is resolved or
trusted. Now an ordinal (digits or one ASCII letter, then one ordinal indicator, U+00AA ª or U+00BA º, with no
identifier character before or after it: `1º`, `2ª`, `Nº`), not itself a look-alike of a dangerous name, is not one
where the file's JSX reading holds it as display text, by the lexer and by the parser (JSX text, a JSX attribute's
string, a string, a template's text), in a file that does not parse as JavaScript without JSX (scanfile.rs:
ordinal_display_runs, jsx_display_spans). Every other look-alike in display text (a Cyrillic а in `pаypal`, `evªl`),
and an ordinal in an identifier, an import, a command or a file JavaScript reads without JSX, is read as before.

The review of Oct 27 (H1): `of <b> evªl("1")` and `obj.return <b> evªl("1")` are valid JavaScript, two comparisons,
that the lexer's JSX reading took for an element (it read `of` and a keyword-named property as a word an expression
follows); the commit made them quiet. Its four rulings are tested here: only ordinals are exempt (`evªl` never is),
the lexer reads `of` and a property's name as operands, a file that parses without JSX has no display text, and a
look-alike of a dangerous name (CRITICAL) is never lowered. Strings and comments both readings agree on were never
read for names. Files built here, inert: nothing is run.
"""
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import core
from tests.registry._review_support import scan_npm

PKG = '{"name": "x", "version": "1.0.0", "main": "index.js"}\n'
TALLY = """import React from "react";

export function LocalLibrary({ items }) {
  return (
    <ul>
      {items.map((item, index) => (
        <li key={item.id}>
          <span className="n">Nº {index + 1}</span> {item.title}
        </li>
      ))}
    </ul>
  );
}
"""


def homoglyphs(path, text):
    return [(i["line"], i["sev"]) for i in core.scan_file(path, text, "js") if i["rule"] == "SC-HOMOGLYPH"]


def scan(files, **kw):
    root = tempfile.mkdtemp(prefix="lz-hg-")
    try:
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(data)
        return core.scan_project(root, **kw)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def found(res):
    return sorted((i["file"].replace(os.sep, "/"), i["line"], i["sev"]) for i in res["issues"] if i["rule"] == "SC-HOMOGLYPH")


class TheFalsePositive(unittest.TestCase):
    def test_the_tally_case(self):
        self.assertEqual(homoglyphs("src/library/LocalLibrary.tsx", TALLY), [])
        res = scan({"package.json": PKG, "src/library/LocalLibrary.tsx": TALLY})
        self.assertEqual(found(res), [])
        self.assertTrue(res["pass"])
        self.assertEqual(res["supplyChain"], 0)

    def test_ordinals_in_display_text(self):
        for path, text in (
                ("a.jsx", "export const A = () => <p>1º lugar, 2ª vez, Nº 7, nº 8</p>;\n"),
                ("b.js", "export const B = () => <p>Mª José, Nº {n}</p>;\n"),
                ("c.tsx", "export const C = () => <p>it's Nº {n}</p>;\n"),
                ("d.tsx", 'export const D = () => <p title="Nº">\n  Nº de pedido\n</p>;\n'),
                ("e.tsx", "export const E = () => <p>{'Nº'} {`Nº ${n}`} {/* Nº */}</p>;\n"),
                ("f.ts", 'export const label = "Nº de pedido"; // Nº\n')):
            with self.subTest(path=path):
                self.assertEqual(homoglyphs(path, text), [])


class StillLookAlikes(unittest.TestCase):
    def test_in_names_and_elsewhere(self):
        for path, text, want in (
                # an ordinal in an identifier, declared and used, in TypeScript and in a JSX expression
                ("h.ts", "const Nº = 1;\nexport const y = Nº + 1;\n", [(1, "MAJOR"), (2, "MAJOR")]),
                ("i.tsx", "const Nº = 1;\nexport const L = () => <p>{Nº}</p>;\n", [(1, "MAJOR"), (2, "MAJOR")]),
                ("j.js", "const evªl = eval;\nevªl('1');\n", [(1, "CRITICAL"), (2, "CRITICAL")]),
                # another look-alike in JSX text; an ordinal that follows no letter or digit
                ("k.tsx", "export const K = () => <a>Visit pаypal</a>;\n", [(1, "MAJOR")]),
                ("m.tsx", "export const M = () => <p>ºeval x</p>;\n", [(1, "MAJOR")]),
                # a display ordinal first on the line does not hide a look-alike name after it
                ("n.tsx", "export const N = () => <p>Nº {isАdmin}</p>;\nconst isAdmin = 1;\n", [(1, "CRITICAL")]),
                # a Cyrillic letter in a name
                ("o.js", "const isАdmin = true;\nexport const isAdmin = false;\n", [(1, "CRITICAL")]),
                # a name that holds an ordinal is not one, in JSX text too (ruling 1): evªl reads as eval
                ("g.tsx", "export const G = () => <p>evªl</p>;\n", [(1, "CRITICAL")]),
                ("p.jsx", "export const P = () => <p>aºb nºs</p>;\n", [(1, "MAJOR")])):
            with self.subTest(path=path):
                self.assertEqual(homoglyphs(path, text), want)

    def test_a_python_name_is_its_nfkc_form(self):
        # (Python reads `Nº` as `No`: the same name, not a look-alike — as before)
        self.assertEqual([i for i in core.scan_file("a.py", "Nº = 1\nprint(Nº)\n", "py") if i["rule"] == "SC-HOMOGLYPH"], [])


SHAPES = {
    # the review's two shapes (valid JavaScript: two comparisons each), and the control it kept
    "of": 'const of=1,b=2;\nof <b> evªl("1");\n',
    "property": 'const obj={return:1},b=2;\nobj.return <b> evªl("1");\n',
    "control": 'const a=1,b=2;\na <b> evªl("1");\n',
}
EXTS = ("js", "mjs", "cjs", "jsx", "tsx")
LABEL = "export const L = () => <p>Nº 1, 1º lugar, 2ª vez</p>;\n"


class TheReviewOfOct27(unittest.TestCase):
    """H1 and the four rulings, in every extension the review read and on every route."""

    def test_the_shapes_stay_critical(self):
        for name, text in SHAPES.items():
            for ext in EXTS + ("ts",):
                with self.subTest(name=name, ext=ext):
                    self.assertEqual(homoglyphs(f"x.{ext}", text), [(2, "CRITICAL")])

    def test_an_ordinal_a_comparison_holds_is_a_name(self):
        # (the file parses as JavaScript without JSX: no display text, ruling 3)
        for ext in EXTS:
            with self.subTest(ext=ext):
                self.assertEqual(homoglyphs(f"x.{ext}", "const of=1,b=2;\nof <b> Nº;\n"), [(2, "MAJOR")])
                self.assertEqual(homoglyphs(f"x.{ext}", "const o={return:1},b=2;\no.return <b> Nº;\n"), [(2, "MAJOR")])
                # beside real JSX: the parser reads the comparison, so it is still a name
                self.assertEqual(homoglyphs(f"x.{ext}", LABEL + "const of=1,b=2;\nof <b> Nº;\n"), [(3, "MAJOR")])

    def test_contextual_words_and_keyword_properties(self):
        for w in ("of", "yield", "await", "async", "get", "set", "let", "static", "as", "from", "target", "meta", "type"):
            for ext in ("js", "cjs", "jsx"):
                with self.subTest(word=w, ext=ext):
                    self.assertEqual(homoglyphs(f"x.{ext}", f'var {w}=1,b=2;\n{w} <b> evªl("1");\n'), [(2, "CRITICAL")])
                    self.assertEqual(homoglyphs(f"x.{ext}", f"var {w}=1,b=2;\n{w} <b> Nº;\n"), [(2, "MAJOR")])
        for w in ("return", "typeof", "in", "of", "new", "delete", "void", "case", "yield", "await", "default", "do", "if"):
            for dot in (".", "?."):
                with self.subTest(word=w, dot=dot):
                    self.assertEqual(homoglyphs("x.js", f'const o={{}},b=2;\no{dot}{w} <b> evªl("1");\n'), [(2, "CRITICAL")])

    def test_labels_stay_quiet(self):
        for ext in EXTS:
            with self.subTest(ext=ext):
                self.assertEqual(homoglyphs(f"x.{ext}", LABEL), [])
        self.assertEqual(homoglyphs("src/library/LocalLibrary.tsx", TALLY), [])

    def test_the_routes(self):
        files = {"package.json": PKG, "index.js": SHAPES["of"], "lib/p.mjs": SHAPES["property"], "ui/L.tsx": LABEL}
        want = [("index.js", 2, "CRITICAL"), ("lib/p.mjs", 2, "CRITICAL")]
        res = scan(files)
        self.assertEqual(found(res), want)
        self.assertFalse(res["pass"])
        res = scan({"package.json": PKG, "index.js": "1;\n", "node_modules/x/package.json": PKG,
                    **{f"node_modules/x/{k}": v for k, v in files.items() if k != "package.json"}}, include_deps=True)
        self.assertEqual(found(res), [(f"node_modules/x/{f}", line, sev) for f, line, sev in want])
        res = scan_npm(files)
        self.assertEqual(sorted((i["file"], i["line"], i["sev"]) for i in res["issues"] if i["rule"] == "SC-HOMOGLYPH"), want)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


class Routes(unittest.TestCase):
    def test_deps(self):
        res = scan({"package.json": PKG, "index.js": "1;\n",
                    "node_modules/ui/package.json": '{"name": "ui", "version": "1.0.0"}\n',
                    "node_modules/ui/LocalLibrary.jsx": TALLY,
                    "node_modules/ui/bad.js": "const evªl = eval;\nevªl('1');\n"}, include_deps=True)
        self.assertEqual(found(res), [("node_modules/ui/bad.js", 1, "CRITICAL"), ("node_modules/ui/bad.js", 2, "CRITICAL")])

    def test_registry(self):
        res = scan_npm({"package.json": PKG, "index.js": "1;\n", "LocalLibrary.jsx": TALLY})
        self.assertEqual([i for i in res["issues"] if i["rule"] == "SC-HOMOGLYPH"], [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        res = scan_npm({"package.json": PKG, "index.js": "const Nº = 1;\nmodule.exports = Nº;\n"})
        self.assertEqual([(i["file"], i["line"]) for i in res["issues"] if i["rule"] == "SC-HOMOGLYPH"],
                         [("index.js", 1), ("index.js", 2)])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
