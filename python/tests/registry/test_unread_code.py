"""N-1: a Go module's or a crate's code is not read yet, and the verdict says so.

Lazaret has no Go or Rust detectors yet (G-1, R-1): `guard go` and `guard
cargo` check a module's or a crate's checksum, age and archive, and read its
other files, but not what its .go or .rs code does. A clean verdict would
say more than the scan knows, so such an artifact is INCOMPLETE, never OK:
one SC-UNREAD-CODE finding says how many files were not read and what that
code is (init functions, package initializers, cgo; a build script,
procedural macros). Test code the build never compiles does not count. A
strong indicator still makes it SUSPICIOUS; npm and PyPI artifacts are
unchanged. Inert content.
"""
import io
import tarfile
import time
import unittest
import zipfile

from lazaret.registry import repo
from lazaret.scanner import _native

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 600


def gomod_zip(files, root="example.test/m@v1.0.0"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in sorted(files.items()):
            zf.writestr(f"{root}/{name}", data)
    return buf.getvalue()


def crate_tgz(files, root="good-1.0.0"):
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


class WhichFilesTests(unittest.TestCase):
    def test_go(self):
        # (paths as iter_archive gives them: the first part of the module's path dropped)
        for rel, want in (("m@v1.0.0/m.go", True), ("m@v1.0.0/sub/x.go", True), ("pkg/errors@v0.9.1/errors.go", True),
                          ("m@v1.0.0/m_test.go", False), ("m@v1.0.0/testdata/x.go", False),
                          ("m@v1.0.0/_tools/x.go", False), ("m@v1.0.0/.x/y.go", False),
                          ("m@v1.0.0/go.mod", False), ("m@v1.0.0/x.c", False)):
            with self.subTest(rel=rel):
                self.assertEqual(repo._unread_code("gomod", rel), want)

    def test_rust(self):
        # (paths as iter_archive gives them: below the crate's "<name>-<version>" root)
        for rel, want in (("src/lib.rs", True), ("build.rs", True), ("src/tests/x.rs", True), ("tests/t.rs", False),
                          ("benches/b.rs", False), ("examples/e.rs", False), ("Cargo.toml", False),
                          ("tests.rs", True)):
            with self.subTest(rel=rel):
                self.assertEqual(repo._unread_code("crate", rel), want)

    def test_other_artifacts(self):
        for kind in ("npm", "sdist", "wheel"):
            self.assertFalse(repo._unread_code(kind, "package/native/x.go"))
            self.assertFalse(repo._unread_code(kind, "pkg-1.0/src/lib.rs"))


class VerdictTests(unittest.TestCase):
    def test_reasons(self):
        go = repo._unread_code_issue("gomod", ["m@v1.0.0/a.go", "m@v1.0.0/b.go"])
        self.assertEqual((go["rule"], go["sev"], go["file"]), ("SC-UNREAD-CODE", "MAJOR", "m@v1.0.0/a.go"))
        self.assertTrue(go["msg"].startswith("2 Go files not read (a.go, b.go): Lazaret has no Go detectors yet"))
        self.assertEqual(repo.decide_verdict([go], 0)[:2],
                         ("INCOMPLETE", "scan incomplete: its Go code not read (Lazaret has no Go detectors yet), "
                                        "so the package can't be cleared"))
        rs = repo._unread_code_issue("crate", ["build.rs"])
        self.assertIn("1 Rust file not read (build.rs)", rs["msg"])
        self.assertEqual(repo.decide_verdict([rs], 1)[1],
                         "scan incomplete: 1 part not fully scanned, and its Rust code not read (Lazaret has no Rust "
                         "detectors yet), so the package can't be cleared")

    def test_a_strong_indicator_still_decides(self):
        go = repo._unread_code_issue("gomod", ["m@v1.0.0/a.go"])
        strong = {"rule": "SC-BINARY", "sev": "CRITICAL", "file": "x"}
        self.assertEqual(repo.decide_verdict([go, strong], 0)[0], "SUSPICIOUS")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ArtifactTests(unittest.TestCase):
    def test_a_go_module_with_code(self):
        res = scan(gomod_zip({"go.mod": "module example.test/m\n", "m.go": "package m\n\nfunc init() {}\n",
                              "m_test.go": "package m\n"}), "zip", "gomod")
        self.assertEqual(res["verdict"], "INCOMPLETE")
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-UNREAD-CODE"]
        self.assertIn("1 Go file not read (m.go)", issue["msg"])

    def test_a_go_module_without_code_that_runs(self):
        res = scan(gomod_zip({"go.mod": "module example.test/m\n", "m_test.go": "package m\n",
                              "testdata/x.go": "package x\n"}), "zip", "gomod")
        self.assertEqual((res["verdict"], [i for i in res["issues"] if i["rule"] == "SC-UNREAD-CODE"]), ("OK", []))

    def test_a_crate(self):
        res = scan(crate_tgz({"Cargo.toml": "[package]\nname = \"good\"\n", "src/lib.rs": "pub fn f() {}\n",
                              "build.rs": "fn main() {}\n", "tests/t.rs": "#[test] fn t() {}\n"}), "tgz", "crate")
        self.assertEqual(res["verdict"], "INCOMPLETE")
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-UNREAD-CODE"]
        self.assertIn("2 Rust files not read (build.rs, src/lib.rs)", issue["msg"])

    def test_a_crate_with_a_strong_indicator(self):
        res = scan(crate_tgz({"Cargo.toml": "[package]\nname = \"evil\"\n", "src/lib.rs": "pub fn f() {}\n",
                              "helper.py": ELF}), "tgz", "crate")
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_an_npm_package_with_go_files_is_unchanged(self):
        data = crate_tgz({"package.json": '{"name": "x", "version": "1.0.0"}', "index.js": "module.exports = 1;\n",
                          "native/x.go": "package x\n"}, root="package")
        res = scan(data, "tgz", "npm")
        self.assertEqual((res["verdict"], [i for i in res["issues"] if i["rule"] == "SC-UNREAD-CODE"]), ("OK", []))


if __name__ == "__main__":
    unittest.main()
