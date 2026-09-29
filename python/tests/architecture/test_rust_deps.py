"""The Rust workspace depends on nothing outside itself
(scripts/check_rust_deps.py): its Cargo.lock lists only the workspace's
crates, from no registry, and each crate's dependencies are paths to other
members. Synthetic manifests show what the check refuses."""
import os
import pathlib
import tempfile
import unittest

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "check_rust_deps.py")


class RustDepsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = _support.load_script(SCRIPT, "check_rust_deps")

    def test_the_workspace_has_no_external_crates(self):
        names = self.s.members()
        self.assertEqual(sorted(names), ["lazaret-engine", "lazaret-ffi"])
        self.assertEqual(self.s.lock_problems(names), [])
        for name, directory in names.items():
            self.assertEqual(self.s.manifest_problems(name, directory, names), [], name)

    def test_what_is_refused(self):
        names = {"lazaret-engine": None, "lazaret-ffi": None}
        with tempfile.TemporaryDirectory() as d:
            lock = pathlib.Path(d, "Cargo.lock")
            lock.write_text('version = 3\n\n[[package]]\nname = "lazaret-engine"\nversion = "0.1.8"\n\n'
                            '[[package]]\nname = "memchr"\nversion = "2.7.4"\n'
                            'source = "registry+https://github.com/rust-lang/crates.io-index"\n', encoding="utf-8")
            self.assertEqual(self.s.lock_problems(names, lock), [
                "Cargo.lock: package memchr is not a workspace member",
                "Cargo.lock: package memchr comes from \"registry+https://github.com/rust-lang/crates.io-index\""])
            pathlib.Path(d, "Cargo.toml").write_text(
                '[package]\nname = "lazaret-ffi"\n\n[dependencies]\nlazaret-engine = { path = "../lazaret-engine" }\n'
                'regex = "1"\n\n[dev-dependencies]\nproptest = { git = "https://example.invalid/p" }\n\n'
                '[target.\'cfg(unix)\'.build-dependencies]\ncc = "1"\n', encoding="utf-8")
            problems = self.s.manifest_problems("lazaret-ffi", pathlib.Path(d), names)
            self.assertEqual([p.split(" = ")[0] for p in problems],
                             ["lazaret-ffi: dependencies regex", "lazaret-ffi: dev-dependencies proptest",
                              "lazaret-ffi: build-dependencies cc"])


if __name__ == "__main__":
    unittest.main()
