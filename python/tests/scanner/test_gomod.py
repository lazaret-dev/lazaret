"""scanner/gomod.py: the go.mod reader the Go auditor and the dependency inventory share.

Expected values for `replace`, `go` and `require` below are the answers of `modfile.Parse` (golang.org/x/mod v0.22.0, asked
through scripts/gooracle) for the same text, where Go accepts it. `scripts/gooracle/gooracle.py diff` holds the reader to
Go's on thousands of generated files; these tests need no Go. The lexer and the `require` rules are also exercised through
`registry/ecosystems/golang.py` (tests/registry/test_golang.py)."""

import unittest
from unittest import mock

from lazaret.scanner import gomod


def parse(text):
    return gomod.parse("module m\n" + text)


class ReplaceTests(unittest.TestCase):
    def test_the_forms_go_accepts(self):
        for text, want in (
                ("replace a.example/x => ./local\n", [("a.example/x", "", "./local", "")]),
                ("replace a.example/x v1.0.0 => ../local\n", [("a.example/x", "v1.0.0", "../local", "")]),
                ("replace a.example/x => b.example/y v1.2.3\n", [("a.example/x", "", "b.example/y", "v1.2.3")]),
                ("replace a.example/x v1.0.0 => b.example/y v1.2.3\n", [("a.example/x", "v1.0.0", "b.example/y", "v1.2.3")]),
                ("replace a.example/x => b.example/y v1\n", [("a.example/x", "", "b.example/y", "v1.0.0")]),      # (a version is read as CanonicalVersion)
                ("replace a.example/x v1 => b.example/y v1.2.3\n", [("a.example/x", "v1.0.0", "b.example/y", "v1.2.3")]),
                ("replace a.example/x => .\n", [("a.example/x", "", ".", "")]),
                ("replace a.example/x => ..\n", [("a.example/x", "", "..", "")]),
                ("replace a.example/x => /abs\n", [("a.example/x", "", "/abs", "")]),
                ('replace "a.example/x" v1.0.0 => "b.example/y" v1.2.3\n', [("a.example/x", "v1.0.0", "b.example/y", "v1.2.3")]),
                ("replace a.example/x => b.example/y v1.2.3 // note\n", [("a.example/x", "", "b.example/y", "v1.2.3")]),
                ("replace (\n\ta.example/x => ./l\n\tb.example/y v1.0.0 => c.example/z v2.0.0+incompatible\n)\n",
                 [("a.example/x", "", "./l", ""), ("b.example/y", "v1.0.0", "c.example/z", "v2.0.0+incompatible")]),
                ("replace (\n)\n", [])):
            with self.subTest(text=text):
                self.assertEqual(parse(text)["replace"], want)

    def test_the_forms_go_refuses_are_dropped(self):
        for text in ("replace a.example/x=>b.example/y v1.2.3\n",                  # (no space around the arrow)
                     "replace a.example/x =>b.example/y v1.2.3\n",
                     "replace a.example/x => b.example/y\n",                       # (a module needs a version)
                     "replace a.example/x => l\n",
                     "replace a.example/x => ./l v1.0.0\n",                        # (a directory cannot have one)
                     "replace a.example/x v1.0.0 => ../l v1.0.0\n", "replace a.example/x => . v1.0.0\n", "replace a.example/x => /l v1.0.0\n",
                     "replace a.example/x v1.0.0 b.example/y v1.2.3\n",            # (no arrow)
                     "replace a.example/x => b.example/y v1.2.3 extra\n",
                     "replace a.example/x => ./l v1.0.0 extra\n", "replace a.example/x => ./l extra extra\n",      # (too many words, a directory too)
                     "replace a.example/x v1.0.0 => ./l extra extra\n", "replace a.example/x v1.0.0 => ./l v1.0.0 extra\n",
                     "replace a.example/x v1.0.0 => b.example/y v1.2.3 extra\n",
                     "replace a.example/x v1.x => b.example/y v1.2.3\n",           # (not a version)
                     "replace a.example/x => b.example/y latest\n",
                     "replace\n", "replace =>\n", 'replace "a => b\n', "replace (\n", "replace ( a.example/x => ./l\n"):
            with self.subTest(text=text):
                self.assertEqual(parse(text)["replace"], [])

    def test_the_arrow_is_a_word_of_its_own_at_the_second_or_third_place(self):
        self.assertEqual(parse("replace a b => c d\n")["replace"], [])                          # (b is not a version)
        self.assertEqual(parse("replace a v1.0.0 => ./c\n")["replace"], [("a", "v1.0.0", "./c", "")])
        self.assertEqual(parse("replace a => => ./c\n")["replace"], [])
        self.assertEqual(parse("replace => => ./c\n")["replace"], [("=>", "", "./c", "")])                  # (the first word is the module, whatever it is)

    def test_a_bad_line_does_not_stop_the_reading(self):
        text = "replace a b c\nrequire x.example/y v1.0.0\nreplace a.example/x => ./l\nreplace\n"
        got = parse(text)
        self.assertEqual(got["require"], [("x.example/y", "v1.0.0", False)])
        self.assertEqual(got["replace"], [("a.example/x", "", "./l", "")])

    def test_a_replace_is_a_replace_only_at_the_start_of_a_line_or_in_its_block(self):
        self.assertEqual(parse("require (\n\treplace a.example/x => ./l\n)\n")["replace"], [])
        self.assertEqual(parse("exclude (\n\ta.example/x => ./l\n)\n")["replace"], [])
        self.assertEqual(parse("replace (\n\ta.example/x => ./l\n)\nrequire a.example/y v1.0.0\n")["require"],
                         [("a.example/y", "v1.0.0", False)])

    def test_a_word_that_could_not_be_read_drops_the_line(self):
        for text in ('replace "a\\q" => ./l\n', 'replace a.example/x => "./l\\q"\n', 'replace a.example/x => "b\\q" v1.0.0\n',
                     'replace a.example/x "v1\\q" => ./l\n', 'replace a.example/x v1.0.0 => b.example/y "v1\\q"\n',
                     'replace a.example/x => b.example/y "v1.0.0\n'):
            with self.subTest(text=text):
                self.assertEqual(parse(text)["replace"], [])
        self.assertEqual(parse('replace a.example/x => ./l\nreplace "a\\q" => ./l\n')["replace"], [("a.example/x", "", "./l", "")])

    def test_the_reader_of_versions_is_given_text_only(self):
        seen = []

        def canonical(version):
            seen.append(version)
            if not isinstance(version, str):
                raise AssertionError(version)
            return version
        gomod.parse('module m\nreplace "a\\q" v1 => b v2\nreplace a v1 => b "c\\q"\nrequire x "v\\q"\nreplace a "v\\q" => ./l\n',
                    canonical=canonical)
        self.assertEqual(seen, [])

    def test_the_number_is_bounded(self):
        self.assertEqual(gomod.MAX_REPLACES, 20_000)
        text = "".join("replace a.example/x%d => ./l\n" % i for i in range(gomod.MAX_REPLACES + 1))
        self.assertEqual(len(parse(text)["replace"]), gomod.MAX_REPLACES)
        text = "".join("replace a.example/x%d => ./l\n" % i for i in range(10))
        with mock.patch.object(gomod, "MAX_REPLACES", 4):
            self.assertEqual([r[0] for r in parse(text)["replace"]], ["a.example/x0", "a.example/x1", "a.example/x2", "a.example/x3"])
        self.assertEqual(len(parse(text)["replace"]), 10)


class GoDirectiveTests(unittest.TestCase):
    def test_the_first_go_line_is_the_go_version(self):
        for text, want in (("go 1.16\n", "1.16"), ("go 1.21.3\n", "1.21.3"), ("go 1.22rc1\n", "1.22rc1"), ("", None),
                           ("go\n", None), ("go 1.21 1.22\n", None), ("go 1.16\ngo 1.21\n", "1.16"), ("go (\n1.17\n)\n", None),
                           ("go 1.x\n", None), ("go v1.21\n", None), ("go 1\n", None), ("go 0.9\n", None), ("go 1.21beta2\n", "1.21beta2")):
            with self.subTest(text=text):
                self.assertEqual(parse(text)["go"], want)

    def test_a_version_at_least_1_17(self):
        for text, want in (("1.16", False), ("1.17", True), ("1.17.0", True), ("1.21.3", True), ("1.22rc1", True), ("1.21beta2", True),
                           ("1.9", False), ("1.0", False), ("1.16.9", False), ("2.0", True), ("10.0", True), ("1.100", True),
                           ("1." + "9" * 5000, True), ("9" * 5000 + ".0", True), ("1.17" + "0", True), ("1.1", False),
                           ("0.99999", False), ("1", False), ("v1.21", False), ("", False), (None, False), (5, False), ("1.x", False),
                           ("01.20", False), ("1.021", False), ("1.21.03", False), ("1.21rc", False), ("1.21.3.4", False),
                           ("1.21 ", False), ("1.2\u0663", False), ("1.21\n", False)):
            with self.subTest(text=text[:20] if isinstance(text, str) else text):
                self.assertEqual(gomod.go_at_least(text, 1, 17), want)

    def test_any_floor(self):
        self.assertTrue(gomod.go_at_least("1.21", 1, 21))
        self.assertFalse(gomod.go_at_least("1.20.9", 1, 21))
        self.assertTrue(gomod.go_at_least("2.0", 1, 21))
        self.assertFalse(gomod.go_at_least("1.21", 2, 0))
        self.assertTrue(gomod.go_at_least("2.0", 2, 0))
        self.assertTrue(gomod.go_at_least("1.100", 1, 99))
        self.assertFalse(gomod.go_at_least("1.99", 1, 100))


class DirectoryTests(unittest.TestCase):
    def test_is_directory_path_is_gos(self):
        for text, want in (("", False), (".", True), ("..", True), ("./x", True), ("../x", True), (".\\x", True), ("..\\x", True),
                           ("/x", True), ("\\x", True), ("C:", True), ("c:x", True), ("Z:\\x", True), ("1:x", False), (":", False),
                           ("a:", True), ("x.example/y", False), ("...", False), (".x", False), ("..x", False), ("~/x", False),
                           ("\u00e9:", False), ("x", False), ("a", False)):
            with self.subTest(text=text):
                self.assertEqual(gomod.is_directory_path(text), want)


class VersionTests(unittest.TestCase):
    def test_a_version_is_read_as_canonical_version_reads_it(self):
        for text, want in (("v1", "v1.0.0"), ("v1.2", "v1.2.0"), ("v1.2.3", "v1.2.3"), ("v1.2.3+meta", "v1.2.3"),
                           ("v1.2.3+incompatible", "v1.2.3+incompatible"), ("v1.2.3-rc.1+x", "v1.2.3-rc.1"),
                           ("v0.0.0-20190101000000-abcdefabcdef", "v0.0.0-20190101000000-abcdefabcdef"),
                           ("v1-pre", ""), ("v1+b", ""), ("1.2.3", ""), ("latest", ""), ("", ""), ("v01.2.3", ""), ("v1.2.3-01", ""),
                           ("v1.2.3-", ""), ("v" + "1" * 200, ""), (None, ""), (5, "")):
            with self.subTest(text=text):
                self.assertEqual(gomod.canonical_version(text), want)
        self.assertEqual(gomod.canonical_version("v" + "1" * (gomod.MAX_VERSION - 1)), "v" + "1" * (gomod.MAX_VERSION - 1) + ".0.0")
        self.assertEqual(gomod.canonical_version("v" + "1" * gomod.MAX_VERSION), "")
        self.assertEqual(gomod.canonical_version("v1." + "1" * (gomod.MAX_VERSION - 3)), "v1." + "1" * (gomod.MAX_VERSION - 3) + ".0")
        self.assertEqual(gomod.canonical_version("v1." + "1" * (gomod.MAX_VERSION - 2)), "")

    def test_a_require_with_a_version_that_is_not_one_is_dropped(self):
        got = parse("require a.example/x latest\nrequire a.example/y v1\nrequire a.example/z 1.0.0\n")
        self.assertEqual(got["require"], [("a.example/y", "v1.0.0", False)])

    def test_the_reader_of_versions_can_be_another(self):
        got = gomod.parse("module m\nrequire a.example/x whatever\nreplace a => b 5\n", canonical=lambda v: v.upper())
        self.assertEqual(got["require"], [("a.example/x", "WHATEVER", False)])
        self.assertEqual(got["replace"], [("a", "", "b", "5")])


class WhatIsReadTests(unittest.TestCase):
    def test_not_text_is_nothing(self):
        for value in (None, 5, b"module m", [], {}):
            self.assertEqual(gomod.parse(value), {"module": None, "go": None, "require": [], "replace": [], "use": [],
                                                  "unversioned": [], "dropped": 0})

    def test_the_module_line(self):
        self.assertEqual(gomod.parse("module a.example/m\n")["module"], "a.example/m")
        self.assertEqual(gomod.parse('module "a.example/m"\n')["module"], "a.example/m")
        self.assertEqual(gomod.parse("module (\n\ta.example/m\n)\n")["module"], "a.example/m")
        self.assertEqual(gomod.parse("module a.example/one\nmodule a.example/two\n")["module"], "a.example/one")
        self.assertIsNone(gomod.parse("module a b\n")["module"])

    def test_requires_and_indirect(self):
        text = ("module m\nrequire a.example/x v1.0.0\nrequire (\n\ta.example/y v1.1.0 // indirect\n\ta.example/z v1.2.0 // indirect; more\n"
                "\ta.example/w v1.3.0 // indirectly\n)\n")
        self.assertEqual(gomod.parse(text)["require"], [("a.example/x", "v1.0.0", False), ("a.example/y", "v1.1.0", True),
                                                        ("a.example/z", "v1.2.0", True), ("a.example/w", "v1.3.0", False)])

    def test_what_is_not_read(self):
        text = ("module m\nexclude a.example/x v1.0.0\nretract v1.0.0\ntoolchain go1.22.1\ngodebug x=y\nunknown thing\n"
                "tool a.example/t\nrequire a.example/y v1.0.0\n")
        self.assertEqual(gomod.parse(text), {"module": "m", "go": None, "require": [("a.example/y", "v1.0.0", False)], "replace": [],
                                             "use": [], "unversioned": [], "dropped": 0})

    def test_the_text_is_cut_at_the_limit(self):
        text = "module m\n" + " " * gomod.MAX_GOMOD + "\nrequire a.example/x v1.0.0\n"
        self.assertEqual(gomod.parse(text)["require"], [])
        small = "module m\nrequire a.example/x v1.0.0\n"
        with mock.patch.object(gomod, "MAX_GOMOD", len(small) - 2):                    # (cut inside the version)
            self.assertEqual(gomod.parse(small)["require"], [])
        for limit in (len(small) - 1, len(small)):
            with mock.patch.object(gomod, "MAX_GOMOD", limit):
                self.assertEqual(len(gomod.parse(small)["require"]), 1)

    def test_hostile_text_is_read_in_linear_time_and_never_raises(self):
        for text in ("\x00" * 10000, "(" * 100000, '"' * 100000, "`" * 100000, "require (" * 20000, "\\" * 100000,
                     "module " + "a" * 1_000_000, "replace " + "a => " * 50000 + "./l\n", "\ufeffmodule m\n", "module m\r\n" * 5000,
                     "require a.example/x v1.0.0 //" + "/" * 100000, "// " * 100000, "\ud800\n", "require a \udcff\n"):
            with self.subTest(text=text[:20]):
                gomod.parse(text)

    def test_the_number_of_requirements_is_bounded(self):
        text = "".join("require a.example/x%d v1.0.0\n" % i for i in range(10))
        with mock.patch.object(gomod, "MAX_REQUIRES", 3):
            self.assertEqual(len(gomod.parse(text)["require"]), 3)

    def test_what_is_not_read_is_counted_and_a_long_version_is_no_version(self):
        """(the Go/Rust review's SCA-3: a requirement Go reads, with a version over MAX_VERSION characters or a path in an
        escape this reader did not read, was dropped and nothing said so)"""
        long_version = "v1.0.0-" + "a" * 94
        text = ("go 1.22\nrequire evil.example/x " + long_version + "\nrequire \"evil.example\\x2fy\" v1.0.0\n"
                "require \"evil.example/z\" v1.0.0 // indirect\nrequire good.example/w v1.0.0\nrequire bad.example/q latest\n"
                "require a.example/no\nreplace a.example/x => b.example/y \"v1\\q\"\n")
        got = gomod.parse(text)
        self.assertEqual(got["require"], [("evil.example/y", "v1.0.0", False), ("evil.example/z", "v1.0.0", True),
                                          ("good.example/w", "v1.0.0", False)])
        self.assertEqual((got["unversioned"], got["dropped"]), ([("evil.example/x", False)], 3))
        with mock.patch.object(gomod, "MAX_REQUIRES", 2):
            got = gomod.parse("".join("require a.example/x%d v1.0.0\n" % i for i in range(5)))
            self.assertEqual((len(got["require"]), got["dropped"]), (2, 3))

    def test_a_go_work_names_its_modules(self):
        got = gomod.parse('go 1.22\n\nuse ./a\nuse (\n\t./b\n\t"./c d"\n\t../out\n)\nuse x y\nreplace a.example/x => ./x\n')
        self.assertEqual(got["use"], ["./a", "./b", "./c d", "../out"])
        self.assertEqual((got["replace"], got["dropped"]), ([("a.example/x", "", "./x", "")], 1))

    def test_the_constants_are_gos(self):
        self.assertEqual((gomod.MAX_GOMOD, gomod.MAX_VERSION), (16 * 1024 * 1024, 100))


if __name__ == "__main__":
    unittest.main()
