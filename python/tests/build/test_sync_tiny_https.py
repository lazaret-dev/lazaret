"""scripts/sync_tiny_https.py (NET-1): a drop of tiny_https taken into rust/crates/tiny_https as it was handed over,
and the copy checked against the hashes recorded then. Synthetic drops in temporary folders; the real copy's check is
`test_the_repositorys_copy_is_the_drop`."""

import contextlib
import io
import os
import pathlib
import tarfile
import tempfile
import unittest
from unittest import mock

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "sync_tiny_https.py")
MANIFEST = ('[package]\nname = "tiny_https"\nversion = "0.2.0"\nedition = "2021"\n\n[dependencies]\n\n'
            '[features]\ndefault = ["net"]\nnet = []\n\n[lints.rust]\n# a comment kept\nunexpected_cfgs = "warn"\n\n'
            '# the release profile\n[profile.release]\nopt-level = 3\n\n[profile.test]\nopt-level = 2\n')
DROP = {"Cargo.toml": MANIFEST, "LICENSE": "Apache License\n", "README.md": "# tiny_https\n", "BACKLOG.md": "b\n",
        "SECURITY_REVIEW.md": "# Security review brief\n", "SECURITY.md": "not taken\n",
        "Cargo.lock": "lock\n", "src/lib.rs": "pub fn f() {}\n", "src/quic/vectors.txt": "1 2\n",
        "tests/data/cert.pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "tests/data/pkg.tgz": "tgz", "tests/t.rs": "#[test] fn t() {}\n", "examples/e.rs": "fn main() {}\n",
        "fuzz/corpus/x": "fuzz input\n", "tools/gen.py": "print(1)\n", "target/debug/x": "built\n",
        "src/__pycache__/x.pyc": "x"}


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.s = _support.load_script(SCRIPT, "sync_tiny_https")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = pathlib.Path(self._tmp.name)
        self.dest = self.root / "dest"
        patcher = mock.patch.object(self.s, "DEST", self.dest)
        patcher.start()
        self.addCleanup(patcher.stop)

    def main(self, args):
        """The script's main, its messages kept off the test's output."""
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return self.s.main(args)

    def drop(self, files=None, name="drop"):
        folder = self.root / name
        for rel, text in (DROP if files is None else files).items():
            (folder / rel).parent.mkdir(parents=True, exist_ok=True)
            (folder / rel).write_text(text, encoding="utf-8", newline="\n")
        return folder

    def taken(self):
        return sorted(p.relative_to(self.dest).as_posix() for p in self.dest.rglob("*") if p.is_file())

    def test_what_is_taken_and_what_is_left_out(self):
        self.assertEqual(self.main([str(self.drop())]), 0)
        self.assertEqual(self.taken(), [".gitattributes", ".gitignore", "BACKLOG.md", "Cargo.toml", "LAZARET.md",
                                        "LICENSE", "README.md", "SECURITY_REVIEW.md", "examples/e.rs", "src/lib.rs",
                                        "src/quic/vectors.txt", "tests/data/cert.pem", "tests/data/pkg.tgz", "tests/t.rs",
                                        "vendored.sha256"])
        manifest = (self.dest / "Cargo.toml").read_text(encoding="utf-8")
        self.assertNotIn("[profile", manifest)
        self.assertNotIn("the release profile", manifest)
        self.assertIn("# a comment kept\nunexpected_cfgs", manifest)
        self.assertIn('[features]\ndefault = ["net"]', manifest)
        self.assertIn("* -text", (self.dest / ".gitattributes").read_text(encoding="utf-8"))
        self.assertIn("!*.pem\n!*.tgz\n", (self.dest / ".gitignore").read_text(encoding="utf-8"))
        notes = (self.dest / "LAZARET.md").read_text(encoding="utf-8")
        self.assertIn("tiny_https 0.2.0", notes)
        self.assertEqual(len((self.dest / "vendored.sha256").read_text(encoding="utf-8").splitlines()), 11)

    def test_a_tarball_with_one_top_folder(self):
        folder = self.drop()
        tgz = self.root / "drop.tgz"
        with tarfile.open(tgz, "w:gz") as tf:
            tf.add(folder, arcname="tiny_https")
        self.assertEqual(self.main([str(tgz)]), 0)
        self.assertIn("src/lib.rs", self.taken())
        self.assertIn("drop.tgz", (self.dest / "LAZARET.md").read_text(encoding="utf-8"))

    def test_verify_finds_a_change_an_addition_and_a_loss(self):
        self.main([str(self.drop())])
        self.assertEqual(self.s.verify(), [])
        (self.dest / "src" / "lib.rs").write_text("pub fn f() { /* edited */ }\n", encoding="utf-8")
        (self.dest / "src" / "extra.rs").write_text("\n", encoding="utf-8")
        (self.dest / "tests" / "t.rs").unlink()
        problems = self.s.verify()
        self.assertEqual(len(problems), 3, problems)
        self.assertTrue(any("src/lib.rs: changed" in p for p in problems))
        self.assertTrue(any("src/extra.rs: not part of the drop" in p for p in problems))
        self.assertTrue(any("tests/t.rs: missing" in p for p in problems))
        self.assertEqual(self.main(["--verify"]), 1)

    def test_what_stops_a_drop(self):
        cases = {
            "a key file": {**DROP, "tests/data/server.key": "k"},
            "an .env": {**DROP, "examples/.env": "TOKEN=x"},
            "a private key": {**DROP, "tests/data/leaf.pem": "-----BEGIN PRIVATE KEY-----\n" + "A" * 64 + "\n-----END PRIVATE KEY-----\n"},
            "a dependency": {**DROP, "Cargo.toml": MANIFEST.replace("[dependencies]\n", '[dependencies]\nregex = "1"\n')},
            "another package": {**DROP, "Cargo.toml": MANIFEST.replace('"tiny_https"', '"other"')},
            "no lib.rs": {k: v for k, v in DROP.items() if k != "src/lib.rs"},
        }
        for what, files in cases.items():
            with self.subTest(what=what):
                self.assertEqual(self.main([str(self.drop(files, name=what.replace(" ", "_")))]), 1)
                self.assertFalse(self.dest.exists(), "nothing written")

    def test_a_tarball_that_reaches_outside_is_refused(self):
        for name, member in (("dotdot", "tiny_https/../evil.rs"), ("absolute", "/tiny_https/src/lib.rs")):
            with self.subTest(name=name):
                tgz = self.root / f"{name}.tgz"
                with tarfile.open(tgz, "w:gz") as tf:
                    for rel, text in (("tiny_https/Cargo.toml", MANIFEST), ("tiny_https/src/lib.rs", "x"),
                                      ("tiny_https/LICENSE", "l"), (member, "x")):
                        data = text.encode()
                        info = tarfile.TarInfo(rel)
                        info.size = len(data)
                        tf.addfile(info, io.BytesIO(data))
                self.assertEqual(self.main([str(tgz)]), 1)
        tgz = self.root / "link.tgz"
        with tarfile.open(tgz, "w:gz") as tf:
            for rel, text in (("tiny_https/Cargo.toml", MANIFEST), ("tiny_https/LICENSE", "l")):
                info = tarfile.TarInfo(rel)
                info.size = len(text)
                tf.addfile(info, io.BytesIO(text.encode()))
            link = tarfile.TarInfo("tiny_https/src/lib.rs")
            link.type, link.linkname = tarfile.SYMTYPE, "/etc/passwd"
            tf.addfile(link)
        self.assertEqual(self.main([str(tgz)]), 1)

    def test_the_repositorys_copy_is_the_drop(self):
        real = _support.load_script(SCRIPT, "sync_tiny_https_real")
        self.assertEqual(real.verify(), [])


if __name__ == "__main__":
    unittest.main()
