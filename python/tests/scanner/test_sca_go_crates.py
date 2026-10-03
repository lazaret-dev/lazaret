"""lazaret-sca for Go modules and Rust crates (0.1.9).

What a project's Go and Rust files put in the inventory, and how the inventory is held to the OSV Go and crates.io
advisories:

* go.mod: every `require`, with the `replace` lines applied (a version of the same module, another module, or a
  directory that is the project's own code); go.sum only for a module whose go.mod is from before Go 1.17 (it does not
  list what the build needs); vendor/modules.txt; a path Go could not fetch (`stdlib`) is no module.
* Cargo.lock: a crate from a registry at the version locked, one from git with no version, a path or workspace crate
  not at all. Cargo.toml: `=x.y.z` is a version, any other requirement is a range (no version), a path dependency is the
  project's own.
* matching: a Go module or a crate is matched only by an exact bundle entry of its own ecosystem and name, ordered as
  SemVer orders them; a bundle made before these ecosystems were in it is not a clear (a gate condition).

The expected values of go.mod come from reading Go's rules (golang.org/x/mod), which `scripts/gooracle` holds the reader
to on thousands of generated files (tests/scanner/test_gomod.py); the fixtures here are inert text (example.invalid, made-up
CVE ids)."""

import contextlib
import datetime
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from lazaret.scanner import gomod, sca, sca_index


def write(root, rel, text):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class Project(unittest.TestCase):
    """A project directory the test writes files into."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="lz-gocrates-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.warn = sca._Warnings()

    def put(self, rel, text):
        return write(self.root, rel, text)

    def go(self):
        return list(sca.scan_go(self.root, self.warn))

    def crates(self):
        return list(sca.scan_crates(self.root, self.warn))


# ---------------------------------------------------------------------------
# Versions and names
# ---------------------------------------------------------------------------

class VersionAndNameTests(unittest.TestCase):
    def test_the_ecosystems(self):
        self.assertEqual(sca.ECOSYSTEMS, ("npm", "pypi", "go", "crates"))
        self.assertEqual(sca.EXACT_ONLY, ("go", "crates"))

    def test_go_and_crates_versions_are_semver_and_nothing_else(self):
        for eco in ("go", "crates"):
            with self.subTest(ecosystem=eco):
                self.assertIsNotNone(sca.version_key("v1.2.3" if eco == "go" else "1.2.3", eco))
                self.assertIsNone(sca.version_key("1.0.post1", eco))                  # (PEP 440, which npm and PyPI also read)
                self.assertIsNone(sca.version_key("1!2.0", eco))
                self.assertIsNone(sca.version_key("2.0rc1", eco))
                self.assertIsNone(sca.version_key("*", eco))
                self.assertIsNone(sca.version_key("", eco))
        self.assertIsNotNone(sca.version_key("1.0.post1", "pypi"))
        self.assertIsNotNone(sca.version_key("2.0rc1", "pypi"))

    def test_go_versions_order_as_go_orders_them(self):
        order = ["v0.0.0-20190101000000-aaaaaaaaaaaa", "v0.0.0-20200101000000-aaaaaaaaaaaa", "v0.0.0", "v1.0.0-rc.1", "v1.0.0",
                 "v1.0.1-0.20200101000000-bbbbbbbbbbbb", "v1.0.1", "v1.2.0", "v1.10.0", "v2.0.0+incompatible", "v2.0.1"]
        for lo, hi in zip(order, order[1:]):
            with self.subTest(lo=lo, hi=hi):
                self.assertEqual(sca.compare_versions(lo, hi, "go"), -1)
                self.assertEqual(sca.compare_versions(hi, lo, "go"), 1)

    def test_incompatible_and_the_v_prefix_are_not_part_of_the_order(self):
        self.assertEqual(sca.compare_versions("v2.0.0+incompatible", "v2.0.0", "go"), 0)
        self.assertEqual(sca.compare_versions("v2.0.0", "2.0.0", "go"), 0)             # (OSV writes the version without the v)
        self.assertEqual(sca.compare_versions("v1.2", "1.2.0", "go"), 0)

    def test_crate_versions(self):
        order = ["0.0.0-0", "0.1.0-alpha.1", "0.1.0-alpha.2", "0.1.0", "0.2.0-0", "0.2.0", "0.2.23", "1.0.0-rc.1+build", "1.0.0"]
        for lo, hi in zip(order, order[1:]):
            with self.subTest(lo=lo, hi=hi):
                self.assertLessEqual(sca.compare_versions(lo, hi, "crates"), 0)
        self.assertEqual(sca.compare_versions("0.2.0-0", "0.2.0", "crates"), -1)
        self.assertEqual(sca.compare_versions("1.0.0+a", "1.0.0+b", "crates"), 0)

    def test_a_go_module_path_is_as_written(self):
        self.assertEqual(sca.normalize_pkg("github.com/Foo/Bar", "go"), "github.com/Foo/Bar")
        self.assertNotEqual(sca.normalize_pkg("github.com/Foo/Bar", "go"), sca.normalize_pkg("github.com/foo/bar", "go"))
        self.assertNotEqual(sca.normalize_pkg("github.com/a/foo-bar", "go"), sca.normalize_pkg("github.com/a/foo.bar", "go"))
        self.assertNotEqual(sca.normalize_pkg("github.com/a/foo_bar", "go"), sca.normalize_pkg("github.com/a/foo-bar", "go"))
        self.assertEqual(sca.exact_name_key(" github.com/Foo/Bar ", "go"), "github.com/Foo/Bar")
        self.assertEqual(sca.name_variants("github.com/Foo/Bar", "go"), {"github.com/Foo/Bar"})
        self.assertEqual(sca.normalize_pkg("python-foo", "go"), "python-foo")           # (no PyPI aliases)
        self.assertEqual(sca.normalize_pkg("@scope/name", "go"), "@scope/name")

    def test_a_crate_name_folds_case_and_underscores(self):
        for name in ("Serde_Json", "serde-json", "SERDE_JSON", " serde_json "):
            self.assertEqual(sca.exact_name_key(name, "crates"), "serde-json")
            self.assertEqual(sca.normalize_pkg(name, "crates"), "serde-json")
        self.assertEqual(sca.name_variants("Serde_Json", "crates"), {"serde-json"})
        self.assertEqual(sca.exact_name_key("a.b", "crates"), "a.b")                 # (a dot is not a hyphen, as in PEP 503)
        self.assertEqual(sca.normalize_pkg("A.b", "crates"), "a.b")
        self.assertEqual(sca.normalize_pkg("@a/b", "crates"), "@a/b")                # (no npm scopes)
        self.assertEqual(sca.normalize_pkg("python-foo", "npm"), "python-foo")        # (the PyPI aliases are PyPI's)
        self.assertEqual(sca.normalize_pkg("foo-python", "npm"), "foo-python")
        self.assertEqual(sca.name_variants("", "go"), set())
        self.assertEqual(sca.name_variants(None, "crates"), set())
        self.assertEqual(sca.exact_name_key("a--b", "crates"), "a--b")
        self.assertEqual(sca.normalize_pkg("a--b", "crates"), "a--b")                # (`a-b` is another crate)
        self.assertEqual(sca.normalize_pkg("A__b", "crates"), "a--b")
        self.assertEqual(sca.normalize_pkg("a b", "crates"), "a b")
        self.assertEqual(sca.normalize_pkg("python-foo", "crates"), "python-foo")        # (no PyPI aliases)
        self.assertEqual(sca.normalize_pkg("py-foo-python", "crates"), "py-foo-python")
        self.assertEqual(sca.exact_name_key("Lodash_X", "npm"), "Lodash_X")           # (the others are as they were)
        self.assertEqual(sca.exact_name_key("Zope.Interface", "pypi"), "zope-interface")

    def test_the_fix_hint_of_a_go_module_has_the_v_a_module_is_required_at(self):
        pkg = {"ranges": [{"fromVersion": "0", "toVersion": "1.2.3", "toInclusive": False}]}
        self.assertEqual(sca.fix_hint({}, pkg, "go"), "Upgrade to >= v1.2.3")
        self.assertEqual(sca.fix_hint({}, pkg, "crates"), "Upgrade to >= 1.2.3")
        self.assertEqual(sca.fix_hint({}, pkg, "npm"), "Upgrade to >= 1.2.3")
        pkg = {"ranges": [{"toVersion": "v1.2.3", "toInclusive": False}]}
        self.assertEqual(sca.fix_hint({}, pkg, "go"), "Upgrade to >= v1.2.3")
        pkg = {"ranges": [{"toVersion": "0.0.0-20220906165146-f3363e06e74c", "toInclusive": False}]}
        self.assertEqual(sca.fix_hint({}, pkg, "go"), "Upgrade to >= v0.0.0-20220906165146-f3363e06e74c")

    def test_the_fix_hint_is_the_highest_exclusive_bound_that_can_be_compared(self):
        pkg = {"ranges": ["bad", {"toVersion": "1.5.0", "toInclusive": False}, {"toVersion": "latest", "toInclusive": False},
                          {"toVersion": "1.9.0", "toInclusive": False}, {"toVersion": "9.0.0", "toInclusive": True},
                          {"toVersion": "1.2.3", "toInclusive": False}, {"toVersion": "*", "toInclusive": False}]}
        for eco, want in (("go", "Upgrade to >= v1.9.0"), ("crates", "Upgrade to >= 1.9.0")):
            self.assertEqual(sca.fix_hint({}, pkg, eco), want)
        self.assertEqual(sca.fix_hint({}, {"ranges": [{"toVersion": "latest", "toInclusive": False}]}, "go"),
                         "See the advisory references for patched versions")
        self.assertEqual(sca.fix_hint({}, {"ranges": None}, "go"), "See the advisory references for patched versions")


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

GO_MOD = """module example.com/app

go 1.21

require (
	github.com/gin-gonic/gin v1.9.0
	golang.org/x/net v0.0.0-20220906165146-f3363e06e74c // indirect
	github.com/Example/Lib/v2 v2.3.0+incompatible
)

require gopkg.in/yaml.v3 v3.0.1
"""


class GoModTests(Project):
    def test_every_requirement_direct_or_indirect(self):
        self.put("go.mod", GO_MOD)
        self.assertEqual(self.go(), [
            ("go", "github.com/gin-gonic/gin", "v1.9.0", "go.mod"),
            ("go", "golang.org/x/net", "v0.0.0-20220906165146-f3363e06e74c", "go.mod"),
            ("go", "github.com/Example/Lib/v2", "v2.3.0+incompatible", "go.mod"),
            ("go", "gopkg.in/yaml.v3", "v3.0.1", "go.mod")])
        self.assertEqual(self.warn.lines(), [])

    def test_a_version_is_read_as_go_reads_it(self):
        self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1\nrequire a.example/y v1.2.3+meta\nrequire a.example/z latest\n"
                           "require a.example/w 1.2.3\n")
        self.assertEqual([(n, v) for _e, n, v, _w in self.go()], [("a.example/x", "v1.0.0"), ("a.example/y", "v1.2.3")])

    def test_what_names_nothing_is_not_read(self):
        self.put("go.mod", "module a.example/m\ngo 1.21\ntoolchain go1.22.1\nexclude a.example/x v1.0.0\nretract v0.9.0\n"
                           "godebug x=y\ntool a.example/t\nrequire a.example/y v1.0.0\n")
        self.assertEqual(self.go(), [("go", "a.example/y", "v1.0.0", "go.mod")])

    def test_a_replacement_by_a_version_of_the_same_module(self):
        self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\nreplace a.example/x v1.0.0 => a.example/x v1.0.4\n")
        self.assertEqual(self.go(), [("go", "a.example/x", "v1.0.4", "go.mod (replaces a.example/x)")])

    def test_a_replacement_by_another_module_keeps_the_original_with_no_version(self):
        """A fork may be vulnerable or may not: the module required is reported as unknown, not as clear."""
        self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\nreplace a.example/x => b.example/fork v1.0.1\n")
        self.assertEqual(self.go(), [("go", "b.example/fork", "v1.0.1", "go.mod (replaces a.example/x)"),
                                     ("go", "a.example/x", "", "go.mod (replaced by b.example/fork)")])

    def test_a_replacement_by_a_directory_is_the_projects_own_code(self):
        for line in ("replace a.example/x => ./x", "replace a.example/x v1.0.0 => ../x", "replace a.example/x => /abs/x",
                     "replace a.example/x => ."):
            with self.subTest(line=line):
                self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\nrequire a.example/y v1.0.0\n" + line + "\n")
                self.assertEqual(self.go(), [("go", "a.example/y", "v1.0.0", "go.mod")])

    def test_a_replacement_for_one_version_does_not_touch_another(self):
        self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\nrequire a.example/x v1.1.0\n"
                           "replace a.example/x v1.0.0 => ./local\n")
        self.assertEqual(self.go(), [("go", "a.example/x", "v1.1.0", "go.mod")])

    def test_a_replacement_for_a_version_wins_over_one_for_all_in_either_order(self):
        for first, second in (("replace a.example/x => ./local", "replace a.example/x v1.0.0 => b.example/y v2.0.0"),
                              ("replace a.example/x v1.0.0 => b.example/y v2.0.0", "replace a.example/x => ./local")):
            with self.subTest(first=first):
                self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\nrequire a.example/x v1.1.0\n%s\n%s\n" % (first, second))
                got = {(n, v) for _e, n, v, _w in self.go()}
                self.assertEqual(got, {("b.example/y", "v2.0.0"), ("a.example/x", "")})      # (v1.1.0: the directory; v1.0.0: the fork)

    def test_the_first_of_two_replacements_for_one_version_is_the_one(self):
        self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\nreplace a.example/x => b.example/one v1.0.0\n"
                           "replace a.example/x => b.example/two v1.0.0\n")
        self.assertEqual([n for _e, n, _v, _w in self.go()], ["b.example/one", "a.example/x"])
        self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\nreplace a.example/x v1.0.0 => b.example/one v1.0.0\n"
                           "replace a.example/x v1.0.0 => b.example/two v1.0.0\n")
        self.assertEqual([n for _e, n, _v, _w in self.go()], ["b.example/one", "a.example/x"])

    def test_a_replacement_of_a_module_not_required_does_nothing(self):
        self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\nreplace a.example/other => b.example/y v1.0.0\n")
        self.assertEqual(self.go(), [("go", "a.example/x", "v1.0.0", "go.mod")])

    def test_a_path_without_a_dot_is_no_module(self):
        """OSV names the standard library `stdlib` and the go command `toolchain`: a go.mod that says so is not a
        dependency on them."""
        self.put("go.mod", "module m\ngo 1.21\nrequire stdlib v1.0.0\nrequire toolchain v1.21.0\nrequire std/x v1.0.0\n"
                           "require a.example/x v1.0.0\nrequire example v0.0.0\nreplace example => b.example/y v1.0.0\n")
        self.assertEqual([(n, v) for _e, n, v, _w in self.go()], [("a.example/x", "v1.0.0"), ("b.example/y", "v1.0.0")])
        self.assertEqual(self.warn.lines(), ["4 Go module path(s) without a dot in the first element (not inventoried)"])

    def test_a_path_with_a_dot_in_a_later_element_only_is_no_module(self):
        self.put("go.mod", "module m\ngo 1.21\nrequire std/a.b v1.0.0\nrequire a.example/b.c/d v1.0.0\n")
        self.assertEqual([n for _e, n, _v, _w in self.go()], ["a.example/b.c/d"])

    def test_a_go_mod_of_a_hostile_size_is_cut(self):
        self.put("go.mod", "module m\ngo 1.21\n" + "".join("require a.example/x%d v1.0.0\n" % i for i in range(10)))
        with mock.patch.object(gomod, "MAX_REQUIRES", 3):
            self.assertEqual(len(self.go()), 3)

    def test_the_limits_are_these(self):
        self.assertEqual((sca.MAX_GO_SUM_LINES, sca.MAX_GO_MODULES), (1_000_000, 200_000))

    def test_nothing_in_a_directory_without_go_files(self):
        self.assertEqual(self.go(), [])
        self.assertEqual(sca.scan_go(os.path.join(self.root, "missing")), [])
        self.assertEqual(self.warn.lines(), [])


class GoSumTests(Project):
    SUM = ("a.example/x v1.0.0 h1:AAAA=\n"
           "a.example/x v1.0.0/go.mod h1:BBBB=\n"
           "a.example/x v1.2.0 h1:CCCC=\n"
           "a.example/x v1.10.0/go.mod h1:DDDD=\n"
           "a.example/x v1.9.0 h1:EEEE=\n"
           "b.example/y v0.1.0/go.mod h1:FFFF=\n"
           "c.example/z v2.0.0+incompatible h1:GGGG=\n"
           "d.example/w v1 h1:HHHH=\n"
           "e.example/v latest h1:IIII=\n"
           "f.example/u v1.0.0 sha256:JJJJ=\n"
           "short line\n"
           "g.example/t v1.0.0 h1:KKKK= extra\n"
           "\n")

    def test_a_module_before_1_17_reads_go_sum_for_the_modules_it_does_not_list(self):
        for go_line in ("go 1.16\n", "go 1.12\n", "", "go 1.x\n", "go 1.0\n"):
            with self.subTest(go=go_line):
                self.put("go.mod", "module m\n" + go_line + "require a.example/x v1.0.0\n")
                self.put("go.sum", self.SUM)
                self.assertEqual(self.go(), [
                    ("go", "a.example/x", "v1.0.0", "go.mod"),
                    ("go", "a.example/x", "v1.9.0", "go.sum"),             # (v1.9.0 is the highest with a zip hash)
                    ("go", "c.example/z", "v2.0.0+incompatible", "go.sum"),
                    ("go", "d.example/w", "v1.0.0", "go.sum")])

    def test_a_module_from_1_17_does_not_read_go_sum(self):
        for go_line in ("go 1.17\n", "go 1.21.3\n", "go 1.22rc1\n", "go 2.0\n"):
            with self.subTest(go=go_line):
                self.put("go.mod", "module m\n" + go_line + "require a.example/x v1.0.0\n")
                self.put("go.sum", self.SUM)
                self.assertEqual(self.go(), [("go", "a.example/x", "v1.0.0", "go.mod")])

    def test_go_sum_without_a_go_mod(self):
        self.put("go.sum", self.SUM)
        self.assertEqual([(n, v) for _e, n, v, _w in self.go()],
                         [("a.example/x", "v1.9.0"), ("c.example/z", "v2.0.0+incompatible"), ("d.example/w", "v1.0.0")])

    def test_a_go_mod_that_cannot_be_read_leaves_go_sum_to_be(self):
        os.makedirs(os.path.join(self.root, "target"))
        self.put("target/go.mod", "module m\ngo 1.21\nrequire a.example/x v1.0.0\n")
        os.symlink("target/go.mod", os.path.join(self.root, "go.mod"))
        self.put("go.sum", self.SUM)
        self.assertEqual(len(self.go()), 3)
        self.assertEqual(self.warn.lines(), ["1 unreadable go.mod file(s)"])

    def test_go_sum_that_cannot_be_read_is_counted(self):
        os.makedirs(os.path.join(self.root, "go.sum"))
        self.assertEqual(self.go(), [])
        self.assertEqual(self.warn.lines(), ["1 unreadable go.sum file(s)"])

    def test_the_highest_version_is_the_semver_highest(self):
        self.put("go.sum", "a.example/x v1.10.0 h1:A=\na.example/x v1.9.0 h1:B=\na.example/x v1.10.0-rc.1 h1:C=\n"
                           "a.example/x v1.2.0 h1:D=\n")
        self.assertEqual([v for _e, _n, v, _w in self.go()], ["v1.10.0"])
        self.put("go.sum", "a.example/x v0.0.0-20200101000000-aaaaaaaaaaaa h1:A=\na.example/x v0.0.0-20210101000000-bbbbbbbbbbbb h1:B=\n"
                           "a.example/x v0.0.0-20190101000000-cccccccccccc h1:C=\n")
        self.assertEqual([v for _e, _n, v, _w in self.go()], ["v0.0.0-20210101000000-bbbbbbbbbbbb"])

    def test_the_number_of_lines_and_of_modules_is_bounded(self):
        text = "".join("a.example/x%d v1.0.0 h1:A=\n" % i for i in range(10))
        self.put("go.sum", text)
        with mock.patch.object(sca, "MAX_GO_SUM_LINES", 4):
            self.assertEqual(len(self.go()), 4)
        with mock.patch.object(sca, "MAX_GO_MODULES", 3):
            self.assertEqual(len(self.go()), 3)
        with mock.patch.object(sca, "MAX_GO_MODULES", 3):             # (a module already held is still raised)
            self.put("go.sum", "a.example/a v1.0.0 h1:A=\na.example/b v1.0.0 h1:A=\na.example/c v1.0.0 h1:A=\n"
                               "a.example/d v1.0.0 h1:A=\na.example/a v1.5.0 h1:B=\n")
            self.assertEqual([(n, v) for _e, n, v, _w in self.go()], [("a.example/a", "v1.5.0"), ("a.example/b", "v1.0.0"),
                                                                      ("a.example/c", "v1.0.0")])

    def test_go_sum_names_without_a_dot_are_no_modules(self):
        self.put("go.sum", "stdlib v1.0.0 h1:A=\na.example/x v1.0.0 h1:A=\n")
        self.assertEqual([n for _e, n, _v, _w in self.go()], ["a.example/x"])
        self.assertEqual(self.warn.lines(), ["1 Go module path(s) without a dot in the first element (not inventoried)"])


class GoVendorTests(Project):
    MODULES = ("# a.example/x v1.2.3\n"
               "## explicit; go 1.16\n"
               "a.example/x\n"
               "a.example/x/sub\n"
               "# b.example/y v1.0.0 => b.example/y v1.0.2\n"
               "b.example/y\n"
               "# c.example/z v0.1.0 => ./local/z\n"
               "c.example/z\n"
               "# d.example/w v2.0.0 => e.example/fork v2.0.1\n"
               "e.example/fork\n"
               "# f.example/v => g.example/u v1.0.0\n"
               "# h.example/t latest\n"
               "# i.example/s v1.0.0 => i.example/s v1.0.0 extra\n"
               "# j.example/r v1.0.0 => j.example/r bad\n"
               "#k.example/q v1.0.0\n"
               "## not a module line v1.0.0\n"
               "# l.example/p v1\n")

    def test_the_modules_that_are_built(self):
        self.put("vendor/modules.txt", self.MODULES)
        self.assertEqual(self.go(), [
            ("go", "a.example/x", "v1.2.3", "vendor/modules.txt"),
            ("go", "b.example/y", "v1.0.2", "vendor/modules.txt (replaces b.example/y)"),
            ("go", "e.example/fork", "v2.0.1", "vendor/modules.txt (replaces d.example/w)"),
            ("go", "d.example/w", "", "vendor/modules.txt (replaced by e.example/fork)"),
            ("go", "l.example/p", "v1.0.0", "vendor/modules.txt")])

    def test_a_vendor_directory_that_is_a_link_is_not_followed(self):
        os.makedirs(os.path.join(self.root, "elsewhere"))
        self.put("elsewhere/modules.txt", self.MODULES)
        os.symlink("elsewhere", os.path.join(self.root, "vendor"))
        self.assertEqual(self.go(), [])
        self.assertEqual(self.warn.lines(), [])

    def test_a_modules_txt_that_is_a_link_is_counted(self):
        self.put("elsewhere/modules.txt", self.MODULES)
        os.makedirs(os.path.join(self.root, "vendor"))
        os.symlink("../elsewhere/modules.txt", os.path.join(self.root, "vendor", "modules.txt"))
        self.assertEqual(self.go(), [])
        self.assertEqual(self.warn.lines(), ["1 unreadable modules.txt file(s)"])

    def test_the_same_module_in_go_mod_and_in_vendor_is_one(self):
        self.put("go.mod", "module m\ngo 1.21\nrequire a.example/x v1.2.3\n")
        self.put("vendor/modules.txt", "# a.example/x v1.2.3\n## explicit; go 1.21\na.example/x\n")
        self.assertEqual(sca.scan_all(self.root), [("go", "a.example/x", "v1.2.3", "go.mod")])

    def test_the_number_of_lines_is_bounded(self):
        self.put("vendor/modules.txt", "".join("# a.example/x%d v1.0.0\n" % i for i in range(10)))
        with mock.patch.object(sca, "MAX_GO_SUM_LINES", 4):
            self.assertEqual(len(self.go()), 4)

    def test_a_path_without_a_dot_is_no_module(self):
        self.put("vendor/modules.txt", "# stdlib v1.0.0\n# a.example/x v1.0.0\n")
        self.assertEqual([n for _e, n, _v, _w in self.go()], ["a.example/x"])


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

CARGO_LOCK = """# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "app"
version = "0.1.0"
dependencies = [
 "serde",
 "time",
]

[[package]]
name = "Serde_Json"
version = "1.0.152"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "0000000000000000000000000000000000000000000000000000000000000000"

[[package]]
name = "time"
version = "0.2.22"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "sparse-crate"
version = "2.0.0"
source = "sparse+https://index.crates.io/"

[[package]]
name = "private"
version = "1.0.0"
source = "registry+https://crates.example.invalid/index"

[[package]]
name = "fork"
version = "0.3.0"
source = "git+https://example.invalid/fork?branch=main#0123456789abcdef0123456789abcdef01234567"

[[package]]
name = "odd"
version = "0.3.0"
source = "something-else+https://example.invalid/odd"

[[package]]
name = "pathdep"
version = "0.1.0"
"""


class CargoLockTests(Project):
    def test_the_crates_that_are_locked(self):
        self.put("Cargo.lock", CARGO_LOCK)
        self.assertEqual(self.crates(), [
            ("crates", "Serde_Json", "1.0.152", "Cargo.lock"),
            ("crates", "time", "0.2.22", "Cargo.lock"),
            ("crates", "sparse-crate", "2.0.0", "Cargo.lock"),
            ("crates", "private", "1.0.0", "Cargo.lock"),
            ("crates", "fork", "", "Cargo.lock (git source)"),
            ("crates", "odd", "", "Cargo.lock (other source)")])
        self.assertEqual(self.warn.lines(), [])

    def test_a_workspace_member_and_a_path_crate_are_the_projects_own(self):
        self.put("Cargo.lock", CARGO_LOCK)
        names = [n for _e, n, _v, _w in self.crates()]
        self.assertNotIn("app", names)
        self.assertNotIn("pathdep", names)
        self.put("Cargo.lock", '[[package]]\nname = "x"\nversion = "1.0.0"\nsource = ""\n')
        self.assertEqual(self.crates(), [])

    def test_the_old_lock_format_with_a_root_table(self):
        self.put("Cargo.lock", '[root]\nname = "app"\nversion = "0.1.0"\ndependencies = ["time 0.2.22 (registry+https://github.com/'
                               'rust-lang/crates.io-index)"]\n\n[[package]]\nname = "time"\nversion = "0.2.22"\nsource = '
                               '"registry+https://github.com/rust-lang/crates.io-index"\n\n[metadata]\n"checksum time 0.2.22 (registry+'
                               'https://github.com/rust-lang/crates.io-index)" = "00"\n')
        self.assertEqual(self.crates(), [("crates", "time", "0.2.22", "Cargo.lock")])

    def test_a_version_that_is_not_text_is_no_version(self):
        self.put("Cargo.lock", '[[package]]\nname = "x"\nversion = 5\nsource = "registry+https://example.invalid/"\n\n'
                               '[[package]]\nname = "y"\nsource = "registry+https://example.invalid/"\n\n'
                               '[[package]]\nname = "z"\nversion = " 1.0.0 "\nsource = "registry+https://example.invalid/"\n')
        self.assertEqual([(n, v) for _e, n, v, _w in self.crates()], [("x", ""), ("y", ""), ("z", "1.0.0")])

    def test_entries_that_are_not_packages_are_counted(self):
        self.put("Cargo.lock", '[[package]]\nname = 5\n\n[[package]]\nversion = "1.0.0"\n\n[[package]]\nname = "x"\nversion = "1.0.0"\n'
                               'source = "registry+https://example.invalid/"\n')
        self.assertEqual([n for _e, n, _v, _w in self.crates()], ["x"])
        self.assertEqual(self.warn.lines(), ["2 malformed Cargo.lock entries"])

    def test_a_lock_that_is_not_toml_is_counted(self):
        self.put("Cargo.lock", "[[package\nname = ")
        self.assertEqual(self.crates(), [])
        self.assertEqual(self.warn.lines(), ["1 unparseable Cargo.lock file(s)"])

    def test_a_lock_that_cannot_be_read_is_counted(self):
        os.makedirs(os.path.join(self.root, "Cargo.lock"))
        self.assertEqual(self.crates(), [])
        self.assertEqual(self.warn.lines(), ["1 unreadable Cargo.lock file(s)"])

    def test_packages_that_are_not_a_list_are_counted(self):
        self.put("Cargo.lock", 'package = 5\n')
        self.assertEqual(self.crates(), [])
        self.assertEqual(self.warn.lines(), ["1 malformed Cargo.lock file(s)"])


CARGO_TOML = """[package]
name = "app"
version = "0.1.0"

[dependencies]
serde = "1.0"
exact = "=1.2.3"
exactpre = "=1.2.3-rc.1+build"
spaced = "= 1.2.3 "
partial = "=1.2"
tilde = "~1.2.3"
star = "*"
renamed = { package = "real-name", version = "0.4" }
exact_table = { version = "=2.0.0", features = ["a"] }
fromgit = { git = "https://example.invalid/x", branch = "main" }
fromgit_renamed = { package = "git-real", git = "https://example.invalid/y" }
local = { path = "../local", version = "1.0" }
ws = { workspace = true }
nover = {}
badver = { version = 5 }
badpackage = { package = 5, version = "=0.5.0" }

[dev-dependencies]
dev-crate = "=0.9.0"

[build-dependencies.build-crate]
version = "=0.8.0"

[target.'cfg(unix)'.dependencies]
unix-crate = "=3.0.0"

[workspace.dependencies]
shared = "=4.0.0"
"""


class CargoTomlTests(Project):
    def entries(self):
        return sorted((n, v, w) for _e, n, v, w in self.crates())

    def test_the_dependencies_a_manifest_names(self):
        self.put("Cargo.toml", CARGO_TOML)
        self.assertEqual(self.entries(), sorted([
            ("serde", "", "Cargo.toml(dependencies) range: 1.0"),
            ("exact", "1.2.3", "Cargo.toml(dependencies)"),
            ("exactpre", "1.2.3-rc.1+build", "Cargo.toml(dependencies)"),
            ("spaced", "1.2.3", "Cargo.toml(dependencies)"),
            ("partial", "", "Cargo.toml(dependencies) range: =1.2"),
            ("tilde", "", "Cargo.toml(dependencies) range: ~1.2.3"),
            ("star", "", "Cargo.toml(dependencies) range: *"),
            ("real-name", "", "Cargo.toml(dependencies) range: 0.4"),
            ("exact_table", "2.0.0", "Cargo.toml(dependencies)"),
            ("fromgit", "", "Cargo.toml(dependencies) git"),
            ("git-real", "", "Cargo.toml(dependencies) git"),
            ("nover", "", "Cargo.toml(dependencies) no version"),
            ("badver", "", "Cargo.toml(dependencies) no version"),
            ("badpackage", "0.5.0", "Cargo.toml(dependencies)"),
            ("dev-crate", "0.9.0", "Cargo.toml(dev-dependencies)"),
            ("build-crate", "0.8.0", "Cargo.toml(build-dependencies)"),
            ("unix-crate", "3.0.0", "Cargo.toml(target.dependencies)"),
            ("shared", "4.0.0", "Cargo.toml(workspace.dependencies)")]))
        self.assertEqual(self.warn.lines(), [])

    def test_a_path_dependency_and_a_workspace_one_are_not_named(self):
        self.put("Cargo.toml", CARGO_TOML)
        names = {n for n, _v, _w in self.entries()}
        self.assertTrue({"local", "ws"}.isdisjoint(names))

    def test_the_older_spellings_of_the_tables(self):
        self.put("Cargo.toml", '[dev_dependencies]\na = "=1.0.0"\n[build_dependencies]\nb = "=2.0.0"\n')
        self.assertEqual(self.entries(), [("a", "1.0.0", "Cargo.toml(dev_dependencies)"), ("b", "2.0.0", "Cargo.toml(build_dependencies)")])

    def test_a_table_that_is_not_one_names_nothing(self):
        for text in ('dependencies = 5\n', 'dependencies = ["a"]\n', '[workspace]\ndependencies = "x"\n', 'workspace = 5\n',
                     'target = 5\n', '[target]\nx = 5\n', '[target.a]\ndependencies = 5\n', '[dependencies]\n"" = "1"\n'):
            with self.subTest(text=text):
                self.put("Cargo.toml", text)
                self.assertEqual(self.crates(), [])
                self.assertEqual(self.warn.lines(), [])

    def test_a_dependency_that_is_not_text_or_a_table_names_nothing_it_can_check(self):
        self.put("Cargo.toml", '[dependencies]\na = 5\nb = ["1.0"]\nc = true\n')
        self.assertEqual(self.entries(), [("a", "", "Cargo.toml(dependencies) no version"), ("b", "", "Cargo.toml(dependencies) no version"),
                                          ("c", "", "Cargo.toml(dependencies) no version")])

    def test_a_requirement_is_cut_in_the_note(self):
        self.put("Cargo.toml", '[dependencies]\na = "' + ">=1.0, " * 20 + '<2"\n')
        (_n, v, w), = self.entries()
        self.assertEqual(v, "")
        self.assertEqual(w, "Cargo.toml(dependencies) range: " + (">=1.0, " * 20)[:40])

    def test_only_a_version_that_is_three_numbers_is_exact(self):
        for req, want in (("=1.2.3", "1.2.3"), ("=0.0.0", "0.0.0"), ("=  1.2.3", "1.2.3"), ("=1.2.3-alpha.1", "1.2.3-alpha.1"),
                          ("=1.2.3+b.1", "1.2.3+b.1"), ("=1.2.3-a+b", "1.2.3-a+b"), ("=1.2", ""), ("=1", ""), ("1.2.3", ""),
                          ("==1.2.3", ""), ("=1.2.3, <2", ""), ("=1.2.3.4", ""), ("= 1.2.3 x", ""), ("=v1.2.3", ""), ("=1.2.x", ""),
                          ("=1.2.3-", ""), ("=1.2.3 \n", "1.2.3"), ("", "")):
            with self.subTest(req=req):
                self.put("Cargo.toml", '[dependencies]\na = {version = %s}\n' % json.dumps(req))
                (_n, v, _w), = self.entries()
                self.assertEqual(v, want)

    def test_a_manifest_that_is_not_toml_is_counted(self):
        self.put("Cargo.toml", "[dependencies\na = ")
        self.assertEqual(self.crates(), [])
        self.assertEqual(self.warn.lines(), ["1 unparseable Cargo.toml file(s)"])

    def test_a_manifest_that_cannot_be_read_is_counted(self):
        os.makedirs(os.path.join(self.root, "Cargo.toml"))
        self.assertEqual(self.crates(), [])
        self.assertEqual(self.warn.lines(), ["1 unreadable Cargo.toml file(s)"])

    def test_the_number_of_target_tables_is_bounded(self):
        text = "".join("[target.'cfg(a%d)'.dependencies]\nc%d = \"=1.0.0\"\n" % (i, i) for i in range(205))
        self.put("Cargo.toml", text)
        self.assertEqual(len(self.crates()), 200)

    def test_the_lock_makes_a_range_in_the_manifest_redundant(self):
        self.put("Cargo.toml", '[dependencies]\ntime = "0.2"\nserde = "1"\n')
        self.put("Cargo.lock", '[[package]]\nname = "time"\nversion = "0.2.22"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        got = sca.scan_all(self.root)
        self.assertEqual([(n, v) for _e, n, v, _w in got], [("time", "0.2.22"), ("serde", "")])    # (serde has no lock: unknown)

    def test_the_lock_and_the_manifest_with_the_name_the_other_way(self):
        self.put("Cargo.toml", '[dependencies]\nserde_json = "=1.0.152"\n')
        self.put("Cargo.lock", '[[package]]\nname = "serde-json"\nversion = "1.0.152"\nsource = "registry+https://example.invalid/"\n')
        self.assertEqual(len(sca.scan_all(self.root)), 1)                       # (crates.io holds one of the two spellings)


class WithoutTomllib:
    """Python 3.10 has no tomllib: the same tests with the subset reader (`sca.toml_subset_loads`) that stands in."""

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(sca, "_tomllib", return_value=None)
        patcher.start()
        self.addCleanup(patcher.stop)


class CargoLockWithoutTomllibTests(WithoutTomllib, CargoLockTests):
    pass


class CargoTomlWithoutTomllibTests(WithoutTomllib, CargoTomlTests):
    pass


class TomlReadersAgreeTests(unittest.TestCase):
    def test_the_two_readers_read_cargo_files_alike(self):
        lib = sca._tomllib()
        if lib is None:
            self.skipTest("no tomllib")
        for text in (CARGO_LOCK, CARGO_TOML):
            self.assertEqual(sca.toml_subset_loads(text), lib.loads(text))


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def package(name, eco, *ranges, exact=True):
    return {"name": name, "ecosystem": eco, "exact": exact, "ranges": list(ranges)}


def below(version, start=None):
    r = {"toVersion": version, "toInclusive": False}
    if start:
        r.update(fromVersion=start, fromInclusive=True)
    return r


def advisory(cve, *packages, **more):
    return dict({"cve": cve, "title": "synthetic " + cve, "packages": list(packages)}, **more)


def bundle(*advisories, sources=("osv:npm", "osv:pypi", "osv:go", "osv:crates", "cisa-kev")):
    return sca.CveBundle({"bundleVersion": 1, "generatedAt": now(), "sources": list(sources), "advisories": list(advisories)})


class MatchTests(unittest.TestCase):
    NET = advisory("CVE-2099-3001", package("golang.org/x/net", "go", below("0.0.0-20990101000000-aaaaaaaaaaaa")))
    TIME = advisory("CVE-2099-4001", package("time", "crates", below("0.2.0", "0.0.0-0"), below("0.2.23", "0.2.1-0")))

    def verdicts(self, b, *deps):
        matches, unknown = sca.match_inventory([d + ("f",) for d in deps], b)
        return sorted((m[0]["cve"], m[2][1], m[2][2]) for m in matches), sorted((u[1]["cve"], u[0][1], u[0][2]) for u in unknown)

    def test_a_go_module_in_the_affected_range(self):
        b = bundle(self.NET)
        for version, hit in (("v0.0.0-20980101000000-bbbbbbbbbbbb", True), ("v0.0.0-20990101000000-aaaaaaaaaaaa", False),
                             ("v0.0.0-20990201000000-cccccccccccc", False), ("v0.1.0", False), ("v0.0.0", False)):
            with self.subTest(version=version):
                matches, unknown = self.verdicts(b, ("go", "golang.org/x/net", version))
                self.assertEqual(matches, [("CVE-2099-3001", "golang.org/x/net", version)] if hit else [])
                self.assertEqual(unknown, [])

    def test_a_crate_in_the_affected_range(self):
        b = bundle(self.TIME)
        for version, hit in (("0.1.45", True), ("0.2.0-alpha.1", True), ("0.2.0", False), ("0.2.22", True), ("0.2.23", False),
                             ("0.3.0", False)):
            with self.subTest(version=version):
                matches, unknown = self.verdicts(b, ("crates", "time", version))
                self.assertEqual(matches, [("CVE-2099-4001", "time", version)] if hit else [])
                self.assertEqual(unknown, [])

    def test_a_dependency_with_no_version_is_unknown_not_clear(self):
        b = bundle(self.NET, self.TIME)
        matches, unknown = self.verdicts(b, ("go", "golang.org/x/net", ""), ("crates", "time", ""))
        self.assertEqual(matches, [])
        self.assertEqual(unknown, [("CVE-2099-3001", "golang.org/x/net", ""), ("CVE-2099-4001", "time", "")])

    def test_the_reason_an_advisory_cannot_decide_is_told(self):
        b = bundle(advisory("CVE-2099-1", package("a.example/x", "go", below("2.0.0"))),
                   advisory("CVE-2099-2", package("a.example/y", "go")),
                   advisory("CVE-2099-3", {"name": "a.example/z", "ecosystem": "go", "exact": True, "ranges": "bad"}),
                   advisory("CVE-2099-4", package("c", "crates", below("2.0.0"))))
        _matches, unknown = sca.match_inventory([("go", "a.example/x", "", "f"), ("go", "a.example/y", "v1.0.0", "f"),
                                                 ("go", "a.example/z", "v1.0.0", "f"), ("go", "a.example/x", "v1.x", "f"),
                                                 ("crates", "c", "", "f")], b)
        reasons = {(u[1]["cve"], u[0][2]): u[3] for u in unknown}
        self.assertIn("no concrete version", reasons[("CVE-2099-1", "")])
        self.assertIn("no affected-version ranges", reasons[("CVE-2099-2", "v1.0.0")])
        self.assertIn("malformed", reasons[("CVE-2099-3", "v1.0.0")])
        self.assertIn("cannot be compared", reasons[("CVE-2099-1", "v1.x")])
        self.assertIn("no concrete version", reasons[("CVE-2099-4", "")])
        self.assertEqual(len(reasons), 5)

    def test_one_advisory_naming_a_dependency_three_ways_is_one_result_the_worst_of_them(self):
        clear, unknown, affected = package("a.example/x", "go", below("0.5.0")), package("a.example/x", "go"), package("a.example/x", "go", {})
        unknown["ranges"] = []
        for order in ((clear, unknown, affected), (affected, unknown, clear), (unknown, clear, affected), (clear, affected, unknown)):
            with self.subTest(order=[order.index(p) for p in (clear, unknown, affected)]):
                matches, unk = sca.match_inventory([("go", "a.example/x", "v1.0.0", "f")], bundle(advisory("CVE-2099-1", *order)))
                self.assertEqual(([m[0]["cve"] for m in matches], unk), (["CVE-2099-1"], []))
        for order in ((clear, unknown), (unknown, clear)):
            matches, unk = sca.match_inventory([("go", "a.example/x", "v1.0.0", "f")], bundle(advisory("CVE-2099-1", *order)))
            self.assertEqual((matches, [u[1]["cve"] for u in unk]), ([], ["CVE-2099-1"]))
        matches, unk = sca.match_inventory([("go", "a.example/x", "v1.0.0", "f")], bundle(advisory("CVE-2099-1", clear)))
        self.assertEqual((matches, unk), ([], []))

    def test_advisory_entries_of_the_wrong_shape_are_counted_and_skipped(self):
        warn = sca._Warnings()
        self.assertIsNone(sca.normalize_advisory("x", warn, 1))
        self.assertIsNone(sca.normalize_advisory(["x"], warn, 2))
        self.assertEqual(warn.lines(), ["2 malformed advisory entries skipped"])
        warn = sca._Warnings()
        adv = sca.normalize_advisory({"cve": "CVE-2099-1", "cvss": "high", "epss": None, "epssPercentile": [1]}, warn, 1)
        self.assertEqual((adv["cvss"], adv["epss"], adv["epssPercentile"]), (None, None, None))
        self.assertEqual(warn.lines(), ["1 non-numeric cvss values ignored", "1 non-numeric epssPercentile values ignored"])
        warn = sca._Warnings()
        self.assertEqual(sca.normalize_advisory({"cve": "CVE-2099-1"}, warn, 1)["packages"], [])
        self.assertEqual(sca.normalize_advisory({"cve": "CVE-2099-1", "packages": None}, warn, 1)["packages"], [])
        self.assertEqual(warn.lines(), [])
        self.assertEqual(sca.normalize_advisory({"cve": "CVE-2099-1", "packages": "x"}, warn, 1)["packages"], [])
        self.assertEqual(warn.lines(), ["1 advisories with a malformed 'packages' list skipped"])
        warn = sca._Warnings()
        adv = sca.normalize_advisory({"cve": "CVE-2099-1", "packages": [
            {"name": "a", "ecosystem": "go", "exact": True}, {"name": "b", "ecosystem": "go", "exact": True, "ranges": ["x"]},
            {"name": " ", "ecosystem": "go"}, {"ecosystem": "go"}, "c"]}, warn, 1)
        self.assertEqual([(p["name"], p["ranges"]) for p in adv["packages"]], [("a", []), ("b", None)])
        self.assertEqual(warn.lines(), ["3 malformed advisory package entries skipped",
                                        "1 malformed affected-version ranges (verdict: unknown)"])

    def test_an_advisory_without_a_usable_id_is_numbered(self):
        warn = sca._Warnings()
        for raw in ({"cve": 5, "packages": []}, {"id": "", "packages": []}, {"packages": []}, {"cve": None, "id": ["x"]}):
            with self.subTest(raw=raw):
                self.assertEqual(sca.normalize_advisory(raw, warn, 7)["cve"], "advisory#7")
        self.assertEqual(warn.lines(), ["4 advisory entries without a 'cve' id (kept as 'advisory#N')"])
        self.assertEqual(sca.normalize_advisory({"id": "GO-2099-1", "packages": []}, warn, 7)["cve"], "GO-2099-1")

    def test_a_version_that_is_not_semver_is_unknown(self):
        b = bundle(self.NET, self.TIME)
        matches, unknown = self.verdicts(b, ("go", "golang.org/x/net", "latest"), ("crates", "time", "0.2.22-dev.x y"))
        self.assertEqual(matches, [])
        self.assertEqual([u[:2] for u in unknown], [("CVE-2099-3001", "golang.org/x/net"), ("CVE-2099-4001", "time")])

    def test_a_malicious_module_is_affected_at_any_version(self):
        b = bundle(advisory("MAL-2099-1", package("evil.example/x", "go", {}), malicious=True))
        matches, unknown = self.verdicts(b, ("go", "evil.example/x", "v1.0.0"), ("go", "evil.example/x", ""))
        self.assertEqual(matches, [("MAL-2099-1", "evil.example/x", ""), ("MAL-2099-1", "evil.example/x", "v1.0.0")])

    def test_the_name_is_the_identity(self):
        b = bundle(advisory("CVE-2099-1", package("github.com/Example/Lib", "go", {})),
                   advisory("CVE-2099-2", package("Some_Crate", "crates", {})))
        for dep, hit in ((("go", "github.com/Example/Lib", "v1.0.0"), True), (("go", "github.com/example/lib", "v1.0.0"), False),
                         (("go", "github.com/Example/Lib/v2", "v1.0.0"), False), (("go", "github.com/Example/Lib ", "v1.0.0"), True),
                         (("crates", "some-crate", "1.0.0"), True), (("crates", "SOME_CRATE", "1.0.0"), True),
                         (("crates", "some.crate", "1.0.0"), False), (("crates", "somecrate", "1.0.0"), False)):
            with self.subTest(dep=dep):
                self.assertEqual(bool(self.verdicts(b, dep)[0]), hit)

    def test_the_ecosystems_do_not_meet(self):
        """A crate called `lodash`, a Go module called `requests`, an npm package called `time`: each has its own
        namespace; none is under another's advisory, by an exact entry or by a loose one."""
        exact = bundle(advisory("CVE-2099-1", package("lodash", "npm", {})), advisory("CVE-2099-2", package("requests", "pypi", {})),
                       advisory("CVE-2099-3", package("time", "crates", {})), advisory("CVE-2099-4", package("a.example/x", "go", {})))
        for dep in (("crates", "lodash", "1.0.0"), ("crates", "requests", "1.0.0"), ("go", "lodash", "v1.0.0"),
                    ("go", "time", "v1.0.0"), ("npm", "time", "1.0.0"), ("pypi", "time", "1.0.0"), ("npm", "a.example/x", "1.0.0"),
                    ("crates", "a.example/x", "1.0.0")):
            with self.subTest(dep=dep):
                self.assertEqual(self.verdicts(exact, dep), ([], []))
        self.assertEqual([m[1] for m in self.verdicts(exact, ("npm", "lodash", "1.0.0"))[0]], ["lodash"])         # (and they still do)

    def test_a_loose_entry_is_never_matched_to_a_module_or_a_crate(self):
        loose = bundle(advisory("CVE-2099-1", package("ws", "npm", {}, exact=False)),
                       advisory("CVE-2099-2", package("net", "go", {}, exact=False)),
                       advisory("CVE-2099-3", package("tokio", "crates", {}, exact=False)))
        for dep in (("crates", "ws", "1.0.0"), ("go", "ws", "v1.0.0"), ("go", "net", "v1.0.0"), ("crates", "net", "1.0.0"),
                    ("go", "tokio", "v1.0.0"), ("crates", "tokio", "1.0.0")):
            with self.subTest(dep=dep):
                self.assertEqual(self.verdicts(loose, dep), ([], []))
        self.assertEqual(len(self.verdicts(loose, ("npm", "ws", "1.0.0"))[0]), 1)             # (the npm package is, as it was)
        self.assertEqual(len(self.verdicts(loose, ("pypi", "net", "1.0.0"))[0]), 1)           # (a loose entry's ecosystem is a hint)

    def test_a_lookup_without_an_ecosystem_finds_every_ecosystems_exact_entry(self):
        b = bundle(advisory("CVE-2099-1", package("x", "npm", {})), advisory("CVE-2099-2", package("x", "go", {})),
                   advisory("CVE-2099-3", package("x", "crates", {})), advisory("CVE-2099-4", package("x", "pypi", {})))
        self.assertEqual([a["cve"] for a, _p in b.advisories_for("x")], ["CVE-2099-1", "CVE-2099-2", "CVE-2099-3", "CVE-2099-4"])
        self.assertEqual([a["cve"] for a, _p in b.advisories_for("x", "go")], ["CVE-2099-2"])
        self.assertEqual([a["cve"] for a, _p in b.advisories_for("x", "crates")], ["CVE-2099-3"])
        self.assertEqual([a["cve"] for a, _p in b.advisories_for("x", "maven")], ["CVE-2099-1", "CVE-2099-2", "CVE-2099-3", "CVE-2099-4"])

    def test_an_entry_of_these_ecosystems_is_an_exact_one(self):
        b = bundle(advisory("CVE-2099-1", package("a.example/x", "go", below("2.0.0")), {"name": "c", "ecosystem": "crates", "exact": True,
                                                                                         "ranges": "bad"}))
        self.assertEqual(b.warnings.lines(), ["1 malformed affected-version ranges (verdict: unknown)"])
        self.assertEqual(len(b.advisories_for("a.example/x", "go")), 1)
        self.assertEqual(len(b.advisories_for("c", "crates")), 1)

    def test_an_exact_entry_without_an_ecosystem_i_know_is_still_loose(self):
        b = bundle(advisory("CVE-2099-1", {"name": "x", "ecosystem": "cargo", "exact": True, "ranges": [{}]}))
        self.assertEqual(b.warnings.lines(), ["1 exact package entries without a known ecosystem (matched by name)"])
        self.assertEqual(len(b.advisories_for("x", "npm")), 1)
        self.assertEqual(b.advisories_for("x", "crates"), [])             # (a crate is matched by an exact entry of crates only)

    def test_the_indexed_bundle_answers_as_the_json_one_does(self):
        doc = {"bundleVersion": 1, "generatedAt": now(), "sources": ["osv:go", "osv:crates"], "advisories": [
            self.NET, self.TIME, advisory("CVE-2099-5", package("github.com/Example/Lib", "go", {})),
            advisory("CVE-2099-6", package("Some_Crate", "crates", {}), package("some-crate", "npm", {})),
            advisory("CVE-2099-7", package("ws", "npm", {}, exact=False)),
            advisory("CVE-2099-8", package("x", "pypi", {}), package("x", "go", {}), package("x", "crates", {}))]}
        plain = sca.CveBundle(doc)
        path = os.path.join(tempfile.mkdtemp(prefix="lz-gocrates-idx-"), "cve-bundle.idx")
        self.addCleanup(shutil.rmtree, os.path.dirname(path), True)
        with open(path, "wb") as fh:
            sca_index.dump_index(doc, fh)
        indexed = sca.CveBundle.load(path)
        self.addCleanup(indexed.close)
        for name, eco in (("golang.org/x/net", "go"), ("time", "crates"), ("github.com/Example/Lib", "go"), ("github.com/example/lib", "go"),
                          ("some_crate", "crates"), ("SOME-CRATE", "crates"), ("some-crate", "npm"), ("ws", "crates"), ("ws", "go"),
                          ("ws", "npm"), ("ws", None), ("x", None), ("x", "go"), ("x", "crates"), ("x", "pypi"), ("x", "npm"), ("none", "go")):
            with self.subTest(name=name, eco=eco):
                want = [(a["cve"], p["name"], p["ecosystem"]) for a, p in plain.advisories_for(name, eco)]
                got = [(a["cve"], p["name"], p["ecosystem"]) for a, p in indexed.advisories_for(name, eco)]
                self.assertEqual(got, want)
        self.assertEqual(len(plain.advisories_for("x", "go")), 1)
        self.assertEqual(plain.advisories_for("ws", "go"), [])


# ---------------------------------------------------------------------------
# The gate, the report and the command
# ---------------------------------------------------------------------------

class ResultTests(unittest.TestCase):
    def result(self, b, inventory, issues=()):
        stats = {"npm": 0, "pypi": 0}
        for eco in sca.EXACT_ONLY:
            n = sum(1 for d in inventory if d[0] == eco)
            if n:
                stats[eco] = n
        return sca.build_sca_result("/p", b, list(issues), inventory, stats)

    def conditions(self, res):
        return {c["label"]: c["ok"] for c in res["conditions"]}

    def test_a_bundle_that_never_read_go_is_no_clear_for_a_go_project(self):
        inv = [("go", "a.example/x", "v1.0.0", "go.mod")]
        res = self.result(bundle(sources=("osv:npm", "osv:pypi", "cisa-kev")), inv)
        self.assertEqual(self.conditions(res)["CVE bundle covers the Go dependencies found"], False)
        self.assertFalse(res["pass"])
        res = self.result(bundle(sources=("osv:npm", "osv:pypi", "osv:go", "cisa-kev")), inv)
        self.assertEqual(self.conditions(res)["CVE bundle covers the Go dependencies found"], True)
        self.assertTrue(res["pass"])

    def test_the_same_for_crates_and_for_both(self):
        inv = [("crates", "time", "0.2.22", "Cargo.lock")]
        res = self.result(bundle(sources=("osv:npm", "osv:pypi", "osv:go")), inv)
        self.assertEqual(self.conditions(res)["CVE bundle covers the Rust dependencies found"], False)
        inv += [("go", "a.example/x", "v1.0.0", "go.mod")]
        res = self.result(bundle(sources=("osv:go",)), inv)
        self.assertEqual(self.conditions(res)["CVE bundle covers the Go and Rust dependencies found"], False)
        res = self.result(bundle(sources=("osv:crates",)), inv)
        self.assertEqual(self.conditions(res)["CVE bundle covers the Go and Rust dependencies found"], False)
        res = self.result(bundle(sources=("osv:crates", "osv:go")), inv)
        self.assertEqual(self.conditions(res)["CVE bundle covers the Go and Rust dependencies found"], True)

    def test_a_project_without_go_or_rust_has_no_such_condition(self):
        inv = [("npm", "lodash", "4.17.21", "package-lock.json")]
        res = self.result(bundle(sources=("osv:npm",)), inv)
        self.assertEqual(len(res["conditions"]), 7)
        self.assertFalse(any("covers" in c["label"] for c in res["conditions"]))
        self.assertNotIn("goDeps", res["metrics"])
        self.assertNotIn("cratesDeps", res["metrics"])

    def test_the_metrics_count_what_is_there(self):
        inv = [("go", "a.example/x", "v1.0.0", "go.mod"), ("go", "a.example/y", "v1.0.0", "go.mod"), ("crates", "time", "0.2.22", "Cargo.lock")]
        res = self.result(bundle(), inv)
        self.assertEqual((res["metrics"]["goDeps"], res["metrics"]["cratesDeps"]), (2, 1))
        self.assertEqual((res["metrics"]["npmDeps"], res["metrics"]["pypiDeps"]), (0, 0))
        self.assertEqual(res["inventoryStats"], {"npm": 0, "pypi": 0, "go": 2, "crates": 1})
        self.assertEqual([i["ecosystem"] for i in res["inventory"]], ["go", "go", "crates"])
        res = self.result(bundle(), inv[:2])
        self.assertNotIn("cratesDeps", res["metrics"])

    def test_the_condition_wants_the_source_of_each_ecosystem_found(self):
        inv = [("go", "a.example/x", "v1.0.0", "go.mod")]
        for sources, ok in ((("osv:go",), True), (("osv:Go",), False), (("go",), False), (("osv:go ",), False), (("osv:crates",), False), ((), False)):
            with self.subTest(sources=sources):
                res = self.result(bundle(sources=sources), inv)
                self.assertEqual(self.conditions(res)["CVE bundle covers the Go dependencies found"], ok)


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lz-gocrates-cmd-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "project")
        write(self.root, "go.mod", "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgolang.org/x/net v0.0.0-20220906165146-f3363e06e74c\n"
                                   "\tgithub.com/Example/Lib/v2 v2.4.0\n)\n")
        write(self.root, "Cargo.lock", CARGO_LOCK)
        self.doc = {"bundleVersion": 1, "generatedAt": now(), "sources": ["osv:npm", "osv:pypi", "osv:go", "osv:crates", "cisa-kev"],
                    "advisories": [
                        advisory("CVE-2099-3001", package("golang.org/x/net", "go", below("0.0.0-20990101000000-aaaaaaaaaaaa")),
                                 cvss=7.5, severity="high"),
                        advisory("GO-2099-0002", package("github.com/Example/Lib/v2", "go", below("2.3.1", "2.0.0"))),
                        advisory("CVE-2099-4001", package("time", "crates", below("0.2.0", "0.0.0-0"), below("0.2.23", "0.2.1-0")),
                                 knownExploited=True),
                        advisory("RUSTSEC-2099-0003", package("Serde_Json", "crates", below("1.0.200")))]}
        self.bundle = os.path.join(self.tmp, "cve-bundle.json")
        self.run_args = [self.root, "--bundle", self.bundle, "--no-json"]

    def write_bundle(self, doc=None):
        with open(self.bundle, "w", encoding="utf-8") as fh:
            json.dump(doc or self.doc, fh)

    def run_cli(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = sca.main(self.run_args + list(extra))
        return rc, out.getvalue(), err.getvalue()

    def test_the_inventory_line_names_go_and_crates_when_there_are_some(self):
        self.write_bundle()
        rc, out, _err = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertIn("  inventory: 0 npm · 0 pypi · 2 go · 6 crates modules\n", out)

    def test_the_inventory_line_is_as_it_was_without_them(self):
        write(self.tmp, "plain/package.json", json.dumps({"dependencies": {"lodash": "4.17.21"}}))
        self.write_bundle()
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            sca.main([os.path.join(self.tmp, "plain"), "--bundle", self.bundle, "--no-json"])
        self.assertIn("  inventory: 1 npm · 0 pypi modules\n", out.getvalue())

    def test_what_is_found(self):
        self.write_bundle()
        report = os.path.join(self.tmp, "report.json")
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            rc = sca.main([self.root, "--bundle", self.bundle, "--json", report, "-q"])
        self.assertEqual(rc, 0, err.getvalue())
        with open(report, encoding="utf-8") as fh:
            res = json.load(fh)
        found = sorted((i["detail"]["cve"], i["rule"], i["sev"], i["detail"]["package"], i["detail"]["installed"], i["detail"]["ecosystem"])
                       for i in res["issues"])
        self.assertEqual(found, [                                           # (Example/Lib/v2 v2.4.0 is past its fix: silent)
            ("CVE-2099-3001", "SCA-CVE", "MAJOR", "golang.org/x/net", "v0.0.0-20220906165146-f3363e06e74c", "go"),
            ("CVE-2099-4001", "SCA-CVE-KEV", "BLOCKER", "time", "0.2.22", "crates"),
            ("RUSTSEC-2099-0003", "SCA-CVE", "MINOR", "Serde_Json", "1.0.152", "crates")])
        self.assertIn("Upgrade to >= v0.0.0-20990101000000-aaaaaaaaaaaa",
                      [i["fix"] for i in res["issues"] if i["detail"]["package"] == "golang.org/x/net"])
        self.assertEqual(res["inventoryStats"], {"npm": 0, "pypi": 0, "go": 2, "crates": 6})

    def test_a_bundle_without_the_ecosystems_fails_the_gate_with_ci(self):
        doc = dict(self.doc, sources=["osv:npm", "osv:pypi", "cisa-kev"], advisories=[
            advisory("CVE-2099-9", package("lodash", "npm", below("4.17.12")))])
        self.write_bundle(doc)
        rc, out, _err = self.run_cli("--ci")
        self.assertEqual(rc, 1)
        self.assertIn("✗ CVE bundle covers the Go and Rust dependencies found", out)

    def test_a_clear_scan_of_a_covered_project_passes(self):
        doc = dict(self.doc, advisories=[advisory("CVE-2099-9", package("lodash", "npm", below("4.17.12")))])
        self.write_bundle(doc)
        rc, out, _err = self.run_cli("--ci")
        self.assertEqual(rc, 0, out)
        self.assertIn("✓ CVE bundle covers the Go and Rust dependencies found", out)

    def test_inventory_only_lists_them(self):
        self.write_bundle()
        rc, out, _err = self.run_cli("--inventory-only")
        self.assertEqual(rc, 0)
        self.assertIn("crates Serde_Json", out)
        self.assertIn("go    golang.org/x/net", out)


if __name__ == "__main__":
    unittest.main()
