"""scripts/goparse (0.1.9, G-2): the tools that hold the engine's Go parser to `go/parser`.

The tests never run Go or the engine. They check the Python halves: `diff.py` sorts every file into the right case and
fails exactly when it should, and `mutate.py` makes the same mutants for the same seed, writes a list of what it made and leaves
out what it should; and they read `astdump.go` for what it must stay: a program of Go's own parser that opens no connection."""

import contextlib
import io
import os
import random
import re
import tempfile
import unittest

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "goparse")
diff = _support.load_script(os.path.join(SCRIPT, "diff.py"), "goparse_diff_script")
mutate = _support.load_script(os.path.join(SCRIPT, "mutate.py"), "goparse_mutate_script")

TREE = ["File 0 20", "Ident 8 9", "GenDecl 11 20"]


def run_diff(oracle, mine, *extra):
    """The text of one comparison and its exit status."""
    with tempfile.TemporaryDirectory() as tmp:
        paths = []
        for name, text in (("oracle.txt", oracle), ("mine.txt", mine)):
            path = os.path.join(tmp, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            paths.append(path)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = diff.main(paths + list(extra))
        return out.getvalue(), status


def section(path, *lines):
    return "".join(["== %s\n" % path] + ["%s\n" % line for line in lines])


class DiffTests(unittest.TestCase):
    def count(self, text, label):
        match = re.search(r"^\s*(\d+)  %s$" % re.escape(label), text, re.M)
        self.assertIsNotNone(match, label + "\n" + text)
        return int(match.group(1))

    def test_the_same_trees_and_the_same_refusals_agree(self):
        text, status = run_diff(section("a.go", *TREE) + section("b.go", "!! x.go:2:1: expected 'package'"),
                                section("a.go", *TREE) + section("b.go", "!! expected 'package', found 'func' at 0"))
        self.assertEqual(status, 0, text)
        self.assertEqual(self.count(text, "same tree"), 1)
        self.assertEqual(self.count(text, "both refuse"), 1, "the messages are not compared: the two say it differently")

    def test_a_file_only_go_parser_refuses_is_a_difference(self):
        text, status = run_diff(section("a.go", "!! x.go:1:1: bad"), section("a.go", *TREE))
        self.assertEqual(status, 1)
        self.assertEqual(self.count(text, "only go/parser refuses"), 1)
        self.assertIn("a.go: go/parser: !! x.go:1:1: bad; Lazaret accepts", text)

    def test_a_file_only_lazaret_refuses_is_a_difference(self):
        text, status = run_diff(section("a.go", *TREE), section("a.go", "!! expected operand (at '}') at 26"))
        self.assertEqual(status, 1)
        self.assertEqual(self.count(text, "only Lazaret refuses"), 1)

    def test_a_different_tree_is_a_difference_and_says_where(self):
        text, status = run_diff(section("a.go", *TREE), section("a.go", "File 0 20", "Ident 8 10", "GenDecl 11 20"))
        self.assertEqual(status, 1)
        self.assertEqual(self.count(text, "different trees"), 1)
        self.assertIn("node 1: go/parser 'Ident 8 9', Lazaret 'Ident 8 10' (3 and 3 nodes)", text)

    def test_a_tree_with_a_node_more_or_less_is_a_difference(self):
        text, status = run_diff(section("a.go", *TREE), section("a.go", *TREE[:2]))
        self.assertEqual(status, 1)
        self.assertIn("node 2: go/parser 'GenDecl 11 20', Lazaret None (3 and 2 nodes)", text)

    def test_a_file_one_side_lacks_is_a_difference(self):
        text, status = run_diff(section("a.go", *TREE), section("a.go", *TREE) + section("b.go", *TREE))
        self.assertEqual(status, 1)
        self.assertEqual(self.count(text, "missing from one side"), 1)
        self.assertIn("b.go: missing from the oracle", text)
        text, _ = run_diff(section("a.go", *TREE) + section("b.go", *TREE), section("a.go", *TREE))
        self.assertIn("b.go: missing from Lazaret's output", text)

    def test_a_file_too_deep_for_lazaret_is_a_limit_not_a_difference(self):
        text, status = run_diff(section("a.go", *TREE), section("a.go", "!! exceeded max nesting depth (at '(') at 700"))
        self.assertEqual(status, 0, text)
        self.assertEqual(self.count(text, "too deep for Lazaret (a limit, not a difference)"), 1)
        # but not when go/parser refuses it too, nor when Lazaret says something else
        text, _ = run_diff(section("a.go", "!! x"), section("a.go", "!! exceeded max nesting depth (at '(') at 7"))
        self.assertEqual(self.count(text, "both refuse"), 1)
        text, status = run_diff(section("a.go", *TREE), section("a.go", "!! expected ')' at 7"))
        self.assertEqual(status, 1)

    def test_show_bounds_the_descriptions(self):
        both = "".join(section("f%02d.go" % i, *TREE) for i in range(30))
        mine = "".join(section("f%02d.go" % i, "File 0 1") for i in range(30))
        text, status = run_diff(both, mine, "--show", "3")
        self.assertEqual(status, 1)
        self.assertEqual(self.count(text, "different trees"), 30)
        self.assertEqual(len(re.findall(r"^  f\d\d\.go:", text, re.M)), 3)
        self.assertIn("… and 27 more", text)

    def test_an_empty_file_is_a_tree_of_no_nodes_not_a_refusal(self):
        text, status = run_diff(section("a.go"), section("a.go"))
        self.assertEqual(status, 0)
        self.assertEqual(self.count(text, "same tree"), 1)

    def test_no_output_is_no_files(self):
        text, status = run_diff("", "")
        self.assertEqual(status, 0)
        for label in ("same tree", "both refuse", "different trees", "missing from one side"):
            self.assertEqual(self.count(text, label), 0)

    def test_the_default_shows_ten_and_a_full_list_has_no_more_line(self):
        both = "".join(section("f%02d.go" % i, *TREE) for i in range(30))
        mine = "".join(section("f%02d.go" % i, "File 0 1") for i in range(30))
        text, _ = run_diff(both, mine)
        self.assertEqual(len(re.findall(r"^  f\d\d\.go:", text, re.M)), 10)
        self.assertIn("… and 20 more", text)
        text, _ = run_diff(both, mine, "--show", "30")
        self.assertEqual(len(re.findall(r"^  f\d\d\.go:", text, re.M)), 30)
        self.assertNotIn("more", text)

    def test_a_tree_with_a_node_less_in_the_oracle_is_a_difference_too(self):
        text, status = run_diff(section("a.go", *TREE[:2]), section("a.go", *TREE))
        self.assertEqual(status, 1)
        self.assertIn("node 2: go/parser None, Lazaret 'GenDecl 11 20' (2 and 3 nodes)", text)

    def test_the_last_file_is_read(self):
        # (no trailing newline, and the last section is the only one)
        text, status = run_diff("== a.go\nFile 0 1", "== a.go\nFile 0 1")
        self.assertEqual((status, self.count(text, "same tree")), (0, 1))


class MutateTests(unittest.TestCase):
    SOURCE = "package p\n\nimport \"os\"\n\nfunc f(a int) int {\n\tx := a + 1\n\treturn x\n}\n\nvar y = []int{1, 2, 3}\n"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.write("a.go", self.SOURCE)
        self.write("b.go", self.SOURCE.replace("f(", "g("))
        self.write("notes.txt", "not go")
        self.write("big.go", "package p\n" + "var x = 1\n" * 5000)
        with open(os.path.join(self.root, "bad.go"), "wb") as fh:
            fh.write(b"package p\n\xff\xfe\n")
        with open(os.path.join(self.root, "list.txt"), "w", encoding="utf-8") as fh:
            fh.write("a.go\nb.go\nnotes.txt\nbig.go\nbad.go\nmissing.go\n")

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
        self.assertEqual([os.path.basename(n) for n in names[:3]], ["m00000.go", "m00001.go", "m00002.go"])
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
        self.assertIn("1000 mutants of 2 files", text, "a.go and b.go; big.go is past 20,000 bytes")
        self.make("m2", "--count", "1000", "--seed", "1", "--max-size", "20000")
        self.assertEqual(self.files("m1")[1], self.files("m2")[1])
        # the size limit is inclusive
        for name, size in (("edge.go", 20000), ("over.go", 20001)):
            with open(os.path.join(self.root, name), "wb") as fh:
                fh.write(b"package p\n" + b"//" + b"x" * (size - 13) + b"\n")
            self.assertEqual(os.path.getsize(os.path.join(self.root, name)), size)
        with open(os.path.join(self.root, "list.txt"), "w", encoding="utf-8") as fh:
            fh.write("edge.go\n")
        self.assertIn("2 mutants of 1 files", self.make("m3", "--count", "2")[1])
        with open(os.path.join(self.root, "list.txt"), "w", encoding="utf-8") as fh:
            fh.write("over.go\n")
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
            if any(w in text for w in ("chan", "select", "fallthrough", "goto", "defer")):
                seen.add("word")
            if any(l in text for l in ("0b2", "1__0", "\"unterminated", "`raw", "'ab'", "/*")):
                seen.add("literal")
            if text.count("\n") != self.SOURCE.count("\n"):
                seen.add("lines")
        self.assertEqual(seen, {"deleted", "odd character", "word", "literal", "lines"})

    def test_the_odd_characters_are_the_ones_the_parser_must_care_about(self):
        for ch in ("\x00", "﻿", "\r", " "):
            self.assertIn(ch, mutate.ODD)
        for lit in ("\"\\", "`raw", "/*", "0b2", "0o8", "1_", "'ab'", "08"):
            self.assertIn(lit, mutate.LITERALS)

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
        out, asked = self.one("abcd", 1, 2, "func")
        self.assertEqual(out, "ab func cd")
        self.assertEqual(asked, [("choice", mutate.WORDS)])

    def test_punctuation_is_put_in(self):
        out, asked = self.one("abcd", 2, 1, "&^=")
        self.assertEqual(out, "a&^=bcd")
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


class GoSourceTests(unittest.TestCase):
    """`astdump.go` is read, not run: it must stay a program of Go's own parser that opens no connection."""

    def setUp(self):
        with open(os.path.join(SCRIPT, "astdump.go"), encoding="utf-8") as fh:
            self.source = fh.read()

    def test_it_imports_the_standard_library_only(self):
        block = re.search(r"import \((.*?)\n\)", self.source, re.S).group(1)
        found = re.findall(r'"([^"]+)"', block)
        self.assertIn("go/parser", found)
        self.assertIn("go/ast", found)
        for path in found:
            self.assertNotIn(".", path.split("/")[0], path)

    def test_it_opens_no_connection_and_runs_no_program(self):
        for word in ("os/exec", "net.", "http.", "syscall", "unsafe", "os.Remove", "os.Setenv", "os.WriteFile", "os.Create"):
            self.assertNotIn(word, self.source, word)

    def test_it_parses_as_the_engine_does(self):
        # the flag that leaves out the resolution of identifiers (the engine builds no scopes), and the carriage returns
        # made spaces (the reason is in the program)
        self.assertIn("parser.SkipObjectResolution", self.source)
        self.assertIn("'\\r'", self.source)

    def test_it_prints_what_diff_py_reads(self):
        self.assertIn('"== %s\\n"', self.source)
        self.assertIn('"!! %v\\n"', self.source)
        self.assertIn('"%s %d %d\\n"', self.source)


if __name__ == "__main__":
    unittest.main()
