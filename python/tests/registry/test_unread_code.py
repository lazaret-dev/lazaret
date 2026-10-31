"""N-1: code in a language nothing reads is said, and the verdict says so.

Until Part C (0.1.9), a Go module's .go files and a crate's .rs files were
such code: `guard go` and `guard cargo` checked a module's or a crate's
checksum, age and archive, and read its other files, but not what its code
does, so such an artifact was INCOMPLETE, never OK, with one SC-UNREAD-CODE
finding. The Go and Rust readers read that code now
(tests/registry/test_package_code.py), so no artifact's code is left
unread; the mechanism stays, data-driven (UNREAD_CODE), for a language with
no reader: one finding says how many files were not read, the verdict is
INCOMPLETE, and a strong indicator still decides. Inert content.
"""
import io
import tarfile
import time
import unittest
from unittest import mock

from lazaret.registry import repo
from lazaret.scanner import _native

ELF = b"\x7fELF\x02\x01\x01\x00" + b"\0" * 600


def tgz(files, root="good-1.0.0"):
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
    def test_go_and_rust_are_read_now(self):
        self.assertEqual(repo.UNREAD_CODE, {})
        self.assertEqual({k: v[0] for k, v in repo.PACKAGE_CODE.items()}, {"gomod": "go", "crate": "rs"})
        for kind, rel in (("gomod", "m@v1.0.0/m.go"), ("crate", "src/lib.rs"), ("npm", "native/x.go")):
            self.assertFalse(repo._unread_code(kind, rel))

    def test_a_language_with_no_reader(self):
        with mock.patch.dict(repo.UNREAD_CODE, {"crate": ("Zig", ".zig")}):
            for rel, want in (("src/main.zig", True), ("tests/t.zig", False), ("src/x_test.go", False),
                              ("src/lib.rs", False)):
                with self.subTest(rel=rel):
                    self.assertEqual(repo._unread_code("crate", rel), want)


class VerdictTests(unittest.TestCase):
    def test_reasons(self):
        with mock.patch.dict(repo.UNREAD_CODE, {"crate": ("Zig", ".zig")}):
            two = repo._unread_code_issue("crate", ["src/a.zig", "src/b.zig"])
            one = repo._unread_code_issue("crate", ["build.zig"])
        self.assertEqual((two["rule"], two["sev"], two["file"]), ("SC-UNREAD-CODE", "MAJOR", "src/a.zig"))
        self.assertTrue(two["msg"].startswith("2 Zig files not read (src/a.zig, src/b.zig): Lazaret has no Zig detectors"))
        self.assertEqual(repo.decide_verdict([two], 0)[:2],
                         ("INCOMPLETE", "scan incomplete: its Zig code not read (Lazaret has no Zig detectors yet), "
                                        "so the package can't be cleared"))
        self.assertIn("1 Zig file not read (build.zig)", one["msg"])
        self.assertEqual(repo.decide_verdict([one], 1)[1],
                         "scan incomplete: 1 part not fully scanned, and its Zig code not read (Lazaret has no Zig "
                         "detectors yet), so the package can't be cleared")

    def test_a_strong_indicator_still_decides(self):
        with mock.patch.dict(repo.UNREAD_CODE, {"crate": ("Zig", ".zig")}):
            issue = repo._unread_code_issue("crate", ["src/a.zig"])
        strong = {"rule": "SC-BINARY", "sev": "CRITICAL", "file": "x"}
        self.assertEqual(repo.decide_verdict([issue, strong], 0)[0], "SUSPICIOUS")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ArtifactTests(unittest.TestCase):
    def test_code_with_no_reader(self):
        with mock.patch.dict(repo.UNREAD_CODE, {"crate": ("Zig", ".zig")}):
            res = scan(tgz({"Cargo.toml": "[package]\nname = \"good\"\n", "src/lib.rs": "pub fn f() {}\n",
                            "src/main.zig": "pub fn main() void {}\n", "tests/t.zig": "test {}\n"}), "tgz", "crate")
        self.assertEqual(res["verdict"], "INCOMPLETE")
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-UNREAD-CODE"]
        self.assertIn("1 Zig file not read (src/main.zig)", issue["msg"])

    def test_a_crate_with_a_strong_indicator(self):
        res = scan(tgz({"Cargo.toml": "[package]\nname = \"evil\"\n", "src/lib.rs": "pub fn f() {}\n", "helper.py": ELF}),
                   "tgz", "crate")
        self.assertEqual(res["verdict"], "SUSPICIOUS")


if __name__ == "__main__":
    unittest.main()
