"""scripts/rsparse (0.1.9, R-2): the tools that hold the engine's Rust item reader to `rustc`.

The tests never run the engine, and run `rustc` in one place only, where it is there. They check the Python halves: `diff.py`
sorts every difference into the right words and fails exactly when it should, `rustc_items.py` reads `rustc`'s tree dump as it
must (on a dump kept here), `mutate.py` makes the same mutants for the same seed, writes a list of what it made and leaves out
what it should; and they read the scripts for what they must stay: no connection, no program but `rustc`."""

import contextlib
import io
import os
import random
import re
import shutil
import sys
import tempfile
import threading
import unittest

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "rsparse")
diff = _support.load_script(os.path.join(SCRIPT, "diff.py"), "rsparse_diff_script")
mutate = _support.load_script(os.path.join(SCRIPT, "mutate.py"), "rsparse_mutate_script")
items = _support.load_script(os.path.join(SCRIPT, "rustc_items.py"), "rsparse_rustc_items_script")

#: `rustc -Zunpretty=ast-tree` for the file `pub fn f() {}` (rustc 1.97), as `tiny.rs`
TINY = 'Crate {\n    id: NodeId(4294967040),\n    attrs: [],\n    items: [\n        Item {\n            attrs: [],\n            id: NodeId(4294967040),\n            span: tiny.rs:1:1: 1:14 (#0),\n            vis: Visibility {\n                kind: Public,\n                span: tiny.rs:1:1: 1:4 (#0),\n                tokens: None,\n            },\n            kind: Fn(\n                Fn {\n                    defaultness: Implicit,\n                    ident: f#0,\n                    generics: Generics {\n                        params: [],\n                        where_clause: WhereClause {\n                            has_where_token: false,\n                            predicates: [],\n                            span: tiny.rs:1:11: 1:11 (#0),\n                        },\n                        span: tiny.rs:1:9: 1:9 (#0),\n                    },\n                    sig: FnSig {\n                        header: FnHeader {\n                            constness: No,\n                            coroutine_kind: None,\n                            safety: Default,\n                            ext: None,\n                        },\n                        decl: FnDecl {\n                            inputs: [],\n                            output: Default(\n                                tiny.rs:1:11: 1:11 (#0),\n                            ),\n                        },\n                        span: tiny.rs:1:1: 1:11 (#0),\n                    },\n                    contract: None,\n                    define_opaque: None,\n                    body: Some(\n                        Block {\n                            stmts: [],\n                            id: NodeId(4294967040),\n                            rules: Default,\n                            span: tiny.rs:1:12: 1:14 (#0),\n                            tokens: None,\n                        },\n                    ),\n                    eii_impls: [],\n                },\n            ),\n            tokens: None,\n        },\n    ],\n    spans: ModSpans {\n        inner_span: tiny.rs:1:1: 1:14 (#0),\n        inject_use_span: no-location (#0),\n    },\n    is_placeholder: false,\n}'

BASE = [
    "item 0 Mod m 0 40 pub - - - - -",
    "item 1 Fn f 10 38 inherited 0 u - - -",
    "item 2 Use - 41 60 inherited - - - - -",
    "use 2 a::b as c",
    "crate allow",
]


def lines(*changes):
    """BASE with each (index, text) put in place of the line there."""
    out = list(BASE)
    for k, text in changes:
        out[k] = text
    return out


class DiffTests(unittest.TestCase):
    def test_the_same_items_are_no_difference(self):
        self.assertEqual(diff.compare(BASE, list(BASE)), [])

    def test_an_item_one_side_lacks_is_missing_or_extra(self):
        fewer = ["item 0 Mod m 0 40 pub - - - - -", "item 1 Use - 41 60 inherited - - - - -", "use 1 a::b as c", "crate allow"]
        got = diff.compare(BASE, fewer)
        self.assertIn("missing Fn f 10-38", got)
        got = diff.compare(fewer, BASE)
        self.assertIn("extra Fn f 10-38", got)

    def test_an_item_that_starts_or_ends_elsewhere_is_a_different_item(self):
        got = diff.compare(BASE, lines((1, "item 1 Fn f 10 39 inherited 0 u - - -")))
        self.assertIn("missing Fn f 10-38", got)
        self.assertIn("extra Fn f 10-39", got)

    def test_each_field_is_compared(self):
        for field, change, word in (("name", "item 1 Fn g 10 38 inherited 0 u - - -", "name"),
                                    ("vis", "item 1 Fn f 10 38 pub 0 u - - -", "vis"),
                                    ("flags", "item 1 Fn f 10 38 inherited 0 ua - - -", "flags"),
                                    ("abi", "item 1 Fn f 10 38 inherited 0 u \"C\" - -", "abi"),
                                    ("attrs", "item 1 Fn f 10 38 inherited 0 u - derive -", "attrs"),
                                    ("inner", "item 1 Fn f 10 38 inherited 0 u - - allow", "inner")):
            with self.subTest(field):
                got = diff.compare(BASE, lines((1, change)))
                self.assertEqual(len(got), 1, got)
                self.assertIn(f": {word}: rustc ", got[0])

    def test_the_parent_is_compared_by_position_not_by_number(self):
        got = diff.compare(BASE, lines((1, "item 1 Fn f 10 38 inherited - u - - -")))
        self.assertEqual(len(got), 1)
        self.assertIn("parent: rustc (", got[0])
        # the same parent under another number is the same
        other = ["item 0 Use - 41 60 inherited - - - - -", "item 1 Mod m 0 40 pub - - - - -", "item 2 Fn f 10 38 inherited 1 u - - -", "use 0 a::b as c", "crate allow"]
        self.assertEqual(diff.compare(BASE, other), ["items are the same but not in the same order"])

    def test_the_order_of_items_matters_when_nothing_else_differs(self):
        swapped = [BASE[0], BASE[2].replace("item 2", "item 1"), BASE[1].replace("item 1", "item 2"), "use 1 a::b as c", "crate allow"]
        got = diff.compare(BASE, swapped)
        self.assertTrue(any("parent" in g for g in got) or got == ["items are the same but not in the same order"], got)

    def test_the_use_leaves_are_compared_by_the_item_that_holds_them(self):
        got = diff.compare(BASE, lines((3, "use 2 a::b")))
        self.assertEqual(len(got), 1)
        self.assertIn("use 41-60: rustc ['a::b as c'], ours ['a::b']", got[0])
        got = diff.compare(BASE, [l for l in BASE if not l.startswith("use ")])
        self.assertEqual(len(got), 1)

    def test_the_crates_attributes_are_compared(self):
        got = diff.compare(BASE, lines((4, "crate allow,deny")))
        self.assertEqual(got, ["crate attributes: rustc 'allow', ours 'allow,deny'"])
        got = diff.compare(BASE, BASE[:4])
        self.assertEqual(len(got), 1)
        self.assertEqual(diff.compare(BASE[:4], BASE[:4]), [])

    def test_problems_in_a_file_rustc_takes_are_a_difference_only_when_nothing_else_is(self):
        self.assertEqual(diff.compare(BASE, BASE + ["problems 2"]), ["ours reports 2 problems in a file rustc accepts"])
        got = diff.compare(BASE, lines((1, "item 1 Fn g 10 38 inherited 0 u - - -")) + ["problems 2"])
        self.assertEqual(len(got), 1)
        self.assertNotIn("problems", got[0])

    def test_the_lines_are_read_into_fields(self):
        parsed, uses, crate, problems = diff.parse_lines(["item 3 Fn f 10 38 pub 0 tu \"C\" derive,cfg allow", "item 4 Mod - 1 2 inherited - - - - -", "use 3 a::b", "crate x", "problems 4"])
        self.assertEqual(parsed[0], dict(n=3, kind="Fn", name="f", start=10, end=38, vis="pub", parent=0, flags="ut", abi="C", attrs="derive,cfg", inner="allow"))
        self.assertEqual((parsed[1]["parent"], parsed[1]["flags"], parsed[1]["abi"]), (None, "", "-"))
        self.assertEqual((uses, crate, problems), ([(3, "a::b")], "x", 4))

    def test_the_abi_is_the_string_without_its_quotes_or_prefix(self):
        for text, want in (("-", "-"), ("\"C\"", "C"), ("r\"C\"", "C"), ("r#\"C\"#", "C"), ("\"system\"", "system")):
            self.assertEqual(diff.norm_abi(text), want)

    def test_an_abi_is_the_string_it_holds_whichever_way_each_side_wrote_it(self):
        # ours is the source's text (escapes as written, a raw string as it is, whitespace and % as %XX); rustc's is the
        # string in Debug form (the DEL character is `\u{7f}`, a backslash is `\\`), written the same way
        for ours, rustc, want in (("\"\\x7f\"", "\"\\u{7f}\"", "\x7f"), ("\"\x7f\"", "\"\\u{7f}\"", "\x7f"),
                                  ("\"C%20x\"", "\"C%20x\"", "C x"), ("\"a%25b\"", "\"a%25b\"", "a%b"),
                                  ("r\"a\\b\"", "\"a\\\\b\"", "a\\b"), ("r#\"a\\n\"#", "\"a\\\\n\"", "a\\n"),
                                  ("\"a\\nb\"", "\"a\\nb\"", "a\nb"), ("\"x\\%0A%20%20y\"", "\"xy\"", "xy"),
                                  ("\"\\u{e9}\"", "\"\u00e9\"", "\u00e9"), ("\"%C3%A9\"", "\"%C3%A9\"", "\u00e9")):
            with self.subTest(ours):
                self.assertEqual(diff.norm_abi(ours), want)
                self.assertEqual(diff.norm_abi(rustc, rustc=True), want)

    def test_a_string_literals_escapes_are_read_as_rust_reads_them(self):
        for text, want in (("a", "a"), ("\\n\\r\\t\\0\\\\\\\"\\'", "\n\r\t\0\\\"'"), ("\\x41\\x7f", "A\x7f"), ("\\u{41}\\u{1_F600}", "A\U0001f600"),
                           ("a\\\n   b", "ab"), ("a\\\r\n\tb", "ab"), ("\\q", "\\q"), ("\\x80", "\\x80"), ("\\u{110000}", "\\u{110000}"),
                           ("\\u{}", "\\u{}"), ("\\", "\\"), ("\\\\n", "\\n")):
            with self.subTest(text):
                self.assertEqual(diff.unescape(text), want)

    def test_a_word_of_a_line_has_no_space_no_line_break_and_no_bare_percent(self):
        for text in ("C", "C x", "a\nb", "\t", "%", "\x7f\u2028\u00a0", "\u00e9\u4e16", ""):
            with self.subTest(text):
                got = items.word(text)
                self.assertIsNone(re.search(r"\s", got), got)
                self.assertEqual(diff.unpercent(got), text)
        self.assertEqual(items.word("C x%"), "C%20x%25")
        self.assertEqual(items.word("\u00e9"), "\u00e9")
        self.assertEqual(items.word("\x7f"), "%7F")
        self.assertEqual(items.word("\u2028"), "%E2%80%A8")

    def test_the_two_ways_of_writing_one_abi_are_no_difference_and_another_abi_is(self):
        ours = lines((1, "item 1 Fn f 10 38 inherited 0 u \"\x7f\" - -"))
        theirs = lines((1, "item 1 Fn f 10 38 inherited 0 u \"%7F\" - -"))
        self.assertEqual(diff.compare(theirs, ours), [])
        other = lines((1, "item 1 Fn f 10 38 inherited 0 u \"%7E\" - -"))
        self.assertEqual(len(diff.compare(other, ours)), 1)
        spaced = lines((1, "item 1 Fn f 10 38 inherited 0 u \"C%20x\" - -"))
        self.assertEqual(diff.compare(spaced, spaced), [])

    def test_the_edition_is_the_manifests(self):
        with tempfile.TemporaryDirectory() as tmp:
            def crate(name, manifest):
                folder = os.path.join(tmp, name, "src")
                os.makedirs(folder)
                if manifest is not None:
                    with open(os.path.join(tmp, name, "Cargo.toml"), "w", encoding="utf-8") as fh:
                        fh.write(manifest)
                path = os.path.join(folder, "lib.rs")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("")
                return path

            self.assertEqual(diff.edition_for(crate("a", '[package]\nname = "a"\nedition = "2018"\n')), "2018")
            self.assertEqual(diff.edition_for(crate("b", '[package]\nname = "b"\n')), "2015", "no edition: Cargo's 2015")
            self.assertEqual(diff.edition_for(crate("c", '[package]\nname = "c"\nedition.workspace = true\n')), "2021")
            self.assertEqual(diff.edition_for(crate("d", '[package]\nname = "d"\n[dependencies.x]\nedition = "2024"\n')), "2024", "(the first key that says it)")
            self.assertEqual(diff.edition_for(crate("e", None)), "2021", "no manifest at all")

    def test_the_files_are_the_rs_files_below_the_directories_without_target_and_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("b.rs", "a.rs", "x.txt", "sub/c.rs", "target/d.rs", ".git/e.rs", "sub/target/f.rs"):
                path = os.path.join(tmp, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write("")
            got = [os.path.relpath(p, tmp).replace(os.sep, "/") for p in diff.find_files([tmp])]
            self.assertEqual(got, ["a.rs", "b.rs", "sub/c.rs"])
            self.assertEqual(diff.find_files([os.path.join(tmp, "b.rs")]), [os.path.join(tmp, "b.rs")])


class RustcItemsTests(unittest.TestCase):
    def test_a_name_is_read_without_its_hygiene_mark_and_without_the_raw_prefix(self):
        for text, want in (("name#0", "name"), ("r#type#0", "type"), ("a_b#12", "a_b"), ("{{root}}#0", "{{root}}")):
            self.assertEqual(items.ident(items.N(text)), want)
        self.assertIsNone(items.ident(items.N("x", args=[])))
        self.assertIsNone(items.ident("plain"))
        self.assertIsNone(items.ident(items.N("noMark")))

    def test_the_debug_text_is_read_into_values(self):
        root = items.parse_debug('Crate { id: NodeId(1), attrs: [], items: [Item { x: 5, y: "s, } ]" }, Two], z: (1, a) }')
        self.assertEqual(root.name, "Crate")
        self.assertEqual(root.fields["id"].args[0].name, "1")
        self.assertEqual(root.fields["items"][0].fields["y"], '"s, } ]"')
        self.assertEqual(root.fields["items"][1].name, "Two")
        self.assertEqual(len(root.fields["z"]), 2)

    def test_a_spans_file_name_may_hold_brackets_and_parentheses(self):
        for name in ("a.rs", "into_bytes_enum.repr(u8).expected.rs", "x[1].rs", "{x}.rs"):
            root = items.parse_debug("Item { span: %s:3:4: 3:9 (#0), id: NodeId(1) }" % name)
            self.assertIsInstance(root.fields["span"], items.Span)
            self.assertTrue(root.fields["span"].startswith(name))

    def test_what_is_not_debug_text_is_an_error(self):
        with self.assertRaises(ValueError):
            items.parse_debug("Crate { id }")
        with self.assertRaises(ValueError):
            items.parse_debug('Crate { id: "unterminated }')

    def test_the_items_of_a_crate_are_rendered_with_their_spans_in_code_points(self):
        root = items.parse_debug(TINY)
        self.assertEqual(items.render("tiny.rs", "pub fn f() {}\n", root), ["item 0 Fn f 0 13 pub - - - - -"])
        self.assertEqual(items.crate_attrs(root), [])

    @unittest.skipUnless(shutil.which("rustc"), "rustc is not installed")
    def test_rustc_gives_the_same_dump_and_refuses_what_it_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            good, bad = os.path.join(tmp, "good.rs"), os.path.join(tmp, "bad.rs")
            with open(good, "w", encoding="utf-8") as fh:
                fh.write("pub fn f() {}\n")
            with open(bad, "w", encoding="utf-8") as fh:
                fh.write("fn (\n")
            got, err = items.items_for_file(good)
            if got is None and "-Z" in (err or ""):
                self.skipTest("this rustc will not print its tree")
            self.assertEqual((got, err), (["item 0 Fn f 0 13 pub - - - - -"], None))
            got, err = items.items_for_file(bad)
            self.assertIsNone(got)
            self.assertTrue(err.startswith("error"), err)


class MutateTests(unittest.TestCase):
    SOURCE = "use std::io;\n\nfn f(a: i32) -> i32 {\n    let x = a + 1;\n    x\n}\n\nstatic Y: [i32; 3] = [1, 2, 3];\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.write("a.rs", self.SOURCE)
        self.write("b.rs", self.SOURCE.replace("f(", "g("))
        self.write("notes.txt", "not rust")
        self.write("big.rs", "static X: u8 = 1;\n" * 5000)
        with open(os.path.join(self.root, "bad.rs"), "wb") as fh:
            fh.write(b"fn f() {}\n\xff\xfe\n")
        with open(os.path.join(self.root, "list.txt"), "w", encoding="utf-8") as fh:
            fh.write("a.rs\nb.rs\nnotes.txt\nbig.rs\nbad.rs\nmissing.rs\n")

    def write(self, name, text):
        with open(os.path.join(self.root, name), "w", encoding="utf-8") as fh:
            fh.write(text)

    def make(self, out, *extra):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            status = mutate.main([os.path.join(self.root, "list.txt"), os.path.join(self.root, out), "--root", self.root] + list(extra))
        return status, buffer.getvalue()

    def files(self, out):
        with open(os.path.join(self.root, out, "list.txt"), encoding="utf-8") as fh:
            names = fh.read().split()
        contents = []
        for name in names:
            with open(name, encoding="utf-8", newline="") as fh:
                contents.append(fh.read())
        return names, contents

    def test_it_writes_the_mutants_and_a_list_of_them(self):
        status, text = self.make("m1", "--count", "40", "--max-size", "2000")
        self.assertEqual(status, 0)
        names, contents = self.files("m1")
        self.assertEqual(len(names), 40)
        self.assertEqual([os.path.basename(n) for n in names[:3]], ["m00000.rs", "m00001.rs", "m00002.rs"])
        self.assertIn("40 mutants of 2 files", text, "a text file, a file past --max-size, one that is not UTF-8 and one that is missing are left out")
        self.assertGreater(len(set(contents)), 20)
        self.assertTrue(any(c != self.SOURCE and c != self.SOURCE.replace("f(", "g(") for c in contents))

    def test_the_same_seed_gives_the_same_files(self):
        self.make("m1", "--count", "50", "--seed", "5", "--max-size", "2000")
        self.make("m2", "--count", "50", "--seed", "5", "--max-size", "2000")
        self.make("m3", "--count", "50", "--seed", "6", "--max-size", "2000")
        self.assertEqual(self.files("m1")[1], self.files("m2")[1])
        self.assertNotEqual(self.files("m1")[1], self.files("m3")[1])

    def test_the_defaults_are_a_thousand_mutants_of_seed_one_from_files_up_to_20000_bytes(self):
        status, text = self.make("m1")
        self.assertEqual(len(self.files("m1")[0]), 1000)
        self.assertIn("1000 mutants of 2 files", text, "a.rs and b.rs; big.rs is past 20,000 bytes")
        self.make("m2", "--count", "1000", "--seed", "1", "--max-size", "20000")
        self.assertEqual(self.files("m1")[1], self.files("m2")[1])
        # the size limit is inclusive
        for name, size in (("edge.rs", 20000), ("over.rs", 20001)):
            with open(os.path.join(self.root, name), "wb") as fh:
                fh.write(b"fn f() {}\n" + b"//" + b"x" * (size - 13) + b"\n")
            self.assertEqual(os.path.getsize(os.path.join(self.root, name)), size)
        with open(os.path.join(self.root, "list.txt"), "w", encoding="utf-8") as fh:
            fh.write("edge.rs\n")
        self.assertIn("2 mutants of 1 files", self.make("m3", "--count", "2")[1])
        with open(os.path.join(self.root, "list.txt"), "w", encoding="utf-8") as fh:
            fh.write("over.rs\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.make("m4", "--count", "2")[0], 2)

    def test_it_writes_into_a_directory_that_exists(self):
        os.makedirs(os.path.join(self.root, "there"))
        self.assertEqual(self.make("there", "--count", "3", "--max-size", "2000")[0], 0)
        self.assertEqual(len(self.files("there")[0]), 3)

    def test_no_source_files_is_an_error(self):
        with open(os.path.join(self.root, "list.txt"), "w", encoding="utf-8") as fh:
            fh.write("notes.txt\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.make("m1")[0], 2)
        self.assertIn("no source files", err.getvalue())

    def test_every_kind_of_change_is_made(self):
        # the nine kinds are picked by a number the generator draws; over many files each one has changed something
        seen = set()
        for seed in range(300):
            rnd = random.Random(seed)
            text = mutate.mutate(self.SOURCE, rnd)
            self.assertIsInstance(text, str)
            if text == self.SOURCE:
                continue
            if len(text) < len(self.SOURCE) - 8:
                seen.add("deleted")
            if any(ch in text for ch in mutate.ODD if ch not in self.SOURCE):
                seen.add("odd character")
            if any(w in text for w in ("dyn", "union", "macro_rules", "unsafe", "where", "gen", "try")):
                seen.add("word")
            if any(l in text for l in ("0b2", "1__0", "\"unterminated", "r#\"raw", "'ab'", "/*")):
                seen.add("literal")
            if text.count("\n") != self.SOURCE.count("\n"):
                seen.add("lines")
        self.assertEqual(seen, {"deleted", "odd character", "word", "literal", "lines"})

    def test_the_odd_characters_and_words_are_the_ones_the_reader_must_care_about(self):
        for ch in ("\x00", "\ufeff", "\r", "\u202e"):
            self.assertIn(ch, mutate.ODD)
        for lit in ("\"\\", "r#\"raw", "/*", "0b2", "0o8", "1_", "'ab'", "'static", "/// doc", "//! doc"):
            self.assertIn(lit, mutate.LITERALS)
        for word in ("union", "auto", "default", "macro_rules", "safe", "gen", "try", "async", "dyn", "r#type"):
            self.assertIn(word, mutate.WORDS)

    def test_a_short_text_does_not_stop_it(self):
        for text in ("", "p", "a\nb"):
            for seed in range(30):
                self.assertIsInstance(mutate.mutate(text, random.Random(seed)), str)


class Scripted:
    """Stands for random.Random: answers each call with the next value it was given and keeps what was asked."""

    def __init__(self, *values):
        self.values = list(values)
        self.asked = []

    def _next(self, name, *args):
        self.asked.append((name,) + args)
        return self.values.pop(0)

    def choice(self, seq):
        return self._next("choice", seq)

    def randrange(self, *args):
        return self._next("randrange", *args)

    def randint(self, *args):
        return self._next("randint", *args)

    def random(self):
        return self._next("random")


class MutateKindTests(unittest.TestCase):
    """Each of the nine changes, made on a text with the draws that pick it."""

    def one(self, text, kind, *draws):
        rnd = Scripted(1, kind, *draws)
        out = mutate.mutate(text, rnd)
        self.assertEqual(rnd.values, [], "every draw is used")
        self.assertEqual(rnd.asked[0], ("choice", [1, 1, 1, 2, 2, 3]))
        self.assertEqual(rnd.asked[1], ("randrange", 9))
        self.assertEqual(rnd.asked[2], ("randrange", len(text)))
        return out, rnd.asked[3:]

    def test_a_span_is_deleted(self):
        out, asked = self.one("abcdefgh", 0, 2, 3)
        self.assertEqual(out, "ab" + "fgh")
        self.assertEqual(asked, [("randint", 1, 6)])

    def test_a_word_is_put_in(self):
        out, asked = self.one("abcd", 1, 2, "fn")
        self.assertEqual(out, "ab fn cd")
        self.assertEqual(asked, [("choice", mutate.WORDS)])

    def test_punctuation_is_put_in(self):
        out, asked = self.one("abcd", 2, 1, "..=")
        self.assertEqual(out, "a..=bcd")
        self.assertEqual(asked, [("choice", mutate.PUNCT)])

    def test_a_literal_is_put_in(self):
        out, asked = self.one("abcd", 3, 4, "0b2")
        self.assertEqual(out, "abcd 0b2 ")
        self.assertEqual(asked, [("choice", mutate.LITERALS)])

    def test_a_character_is_replaced(self):
        out, asked = self.one("abcd", 4, 1, "\x00")
        self.assertEqual(out, "a\x00cd")
        self.assertEqual(asked, [("choice", mutate.PUNCT + mutate.ODD)])
        out, _ = self.one("abcd", 4, 3, "+")
        self.assertEqual(out, "abc+")

    def test_a_line_is_deleted(self):
        # (the draws are the character the change starts at, which this one does not use, and the line)
        out, asked = self.one("a\nb\nc\nd", 5, 0, 1)
        self.assertEqual(out, "a\nc\nd")
        self.assertEqual(asked, [("randrange", 3)], "the last line is not chosen")
        out, _ = self.one("a\nb\nc\nd", 5, 3, 2)
        self.assertEqual(out, "a\nb\nd")

    def test_a_line_is_copied_or_swapped(self):
        out, asked = self.one("a\nb\nc", 6, 0, 1, 0.2)
        self.assertEqual(out, "a\nb\nb\nc", "copied below 0.5")
        self.assertEqual(asked, [("randrange", 2), ("random",)])
        out, _ = self.one("a\nb\nc", 6, 0, 1, 0.5)
        self.assertEqual(out, "a\nc\nb", "swapped from 0.5")
        out, _ = self.one("a\nb\nc", 6, 0, 0, 0.9)
        self.assertEqual(out, "b\na\nc")

    def test_lines_are_changed_only_in_a_text_of_three(self):
        # (a text of two lines has nothing to delete, copy or swap that is not its last: nothing is drawn)
        for kind in (5, 6):
            rnd = Scripted(1, kind, 1)
            self.assertEqual(mutate.mutate("a\nb", rnd), "a\nb")
            self.assertEqual(rnd.values, [])
            rnd = Scripted(1, kind, 1)
            self.assertEqual(mutate.mutate("a", rnd), "a")

    def test_the_text_is_cut_short(self):
        out, asked = self.one("abcdef", 7, 3)
        self.assertEqual((out, asked), ("abc", []))
        out, _ = self.one("abcdef", 7, 0)
        self.assertEqual(out, "")

    def test_an_odd_character_is_put_in(self):
        out, asked = self.one("abcd", 8, 2, "\ufeff")
        self.assertEqual(out, "ab\ufeffcd")
        self.assertEqual(asked, [("choice", mutate.ODD)])

    def test_up_to_three_changes_and_none_in_an_empty_text(self):
        rnd = Scripted(3, 7, 4, 7, 2, 7, 1)
        self.assertEqual(mutate.mutate("abcdefgh", rnd), "a")
        self.assertEqual(rnd.values, [])
        rnd = Scripted(3)
        self.assertEqual(mutate.mutate("", rnd), "")
        rnd = Scripted(3, 7, 0)
        self.assertEqual(mutate.mutate("abc", rnd), "", "once the text is empty, the rest are not made")
        self.assertEqual(rnd.values, [])


class RustSourceTests(unittest.TestCase):
    """The scripts are read, not run: they must stay tools that open no connection and run no program but `rustc`."""

    def source(self, name):
        with open(os.path.join(SCRIPT, name), encoding="utf-8") as fh:
            return fh.read()

    def test_they_import_the_standard_library_only(self):
        allowed = {"argparse", "collections", "concurrent", "os", "random", "re", "subprocess", "sys", "threading"}
        for name in ("diff.py", "mutate.py", "rustc_items.py"):
            for module in re.findall(r"^(?:import|from) ([A-Za-z_][A-Za-z_0-9]*)", self.source(name), re.M):
                self.assertTrue(module in allowed or module == "rustc_items", (name, module))

    def test_they_open_no_connection(self):
        for name in ("diff.py", "mutate.py", "rustc_items.py"):
            text = self.source(name)
            for word in ("socket", "urllib", "http", "requests", "ftplib"):
                self.assertNotIn(word, text, (name, word))

    def test_the_oracle_leaves_the_process_as_it_was(self):
        """The tests load rustc_items.py into the process every test shares (CI runs one `unittest discover`). A
        recursion limit it raised when loaded, or a thread stack size it left after reading a file, was every later
        test's: tomllib then read TOML nested 200,000 deep that a test expects refused, and the JSON reader went
        through answers nested 70,000 deep until the stack ran out (Windows, Python 3.10)."""
        self.assertIsNone(re.search(r"^(?:sys\.setrecursionlimit|threading\.stack_size)\(", self.source("rustc_items.py"), re.M))
        limit, size = sys.getrecursionlimit(), threading.stack_size()
        seen = []
        items.deep(lambda: seen.append(sys.getrecursionlimit()))
        self.assertEqual(seen, [max(limit, items.DEEP_RECURSION)])
        self.assertEqual((sys.getrecursionlimit(), threading.stack_size()), (limit, size))

    def test_the_only_programs_they_run_are_rustc_and_the_dump(self):
        self.assertEqual(re.findall(r'subprocess\.run\(\["([^"]+)"', self.source("rustc_items.py")), ["rustc"])
        self.assertIn('"-Zunpretty=ast-tree"', self.source("rustc_items.py"))
        self.assertIn('RUSTC_BOOTSTRAP="1"', self.source("rustc_items.py"))
        self.assertEqual(len(re.findall(r"subprocess\.run\(", self.source("diff.py"))), 1)
        self.assertNotIn("subprocess", self.source("mutate.py"))

    def test_the_dump_lines_are_the_ones_the_engine_writes(self):
        engine = os.path.join(_support.REPO_ROOT, "rust", "crates", "lazaret-engine", "src", "rsparse", "out.rs")
        if not os.path.exists(engine):
            self.skipTest("the engine's sources are not here")
        with open(engine, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn('"item {} {} {} {} {} {} {} {} {} {} {}"', text)
        self.assertIn('"use {} {}{}"', text)
        self.assertIn('"crate {}"', text)


if __name__ == "__main__":
    unittest.main()
