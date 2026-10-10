"""The Rust workspace depends on nothing outside itself
(scripts/check_rust_deps.py): its Cargo.lock lists only the workspace's
crates, from no registry, and each crate's dependencies are paths to other
members. Synthetic manifests show what the check refuses. It also holds the
line between the engine and the network (NET-1): pratique's pure part
through lazaret-verify, its sockets through lazaret-net, which only the
native library links."""
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
        self.assertEqual(sorted(names), ["lazaret-engine", "lazaret-ffi", "lazaret-net", "lazaret-verify", "pratique"])
        self.assertEqual(self.s.lock_problems(names), [])
        for name, directory in names.items():
            self.assertEqual(self.s.manifest_problems(name, directory, names), [], name)
        self.assertEqual(self.s.purity_problems(names), [])

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


    def test_the_engine_never_links_the_network(self):
        def crates(**manifests):
            d = tempfile.mkdtemp()
            self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
            out = {}
            for name, deps in manifests.items():
                folder = pathlib.Path(d, name)
                folder.mkdir()
                folder.joinpath("Cargo.toml").write_text(f'[package]\nname = "{name}"\n\n{deps}', encoding="utf-8")
                out[name] = folder
            return out

        native = "[target.'cfg(not(target_arch = \"wasm32\"))'.dependencies]"
        good = crates(**{"lazaret-verify": '[dependencies]\npratique = { path = "../pratique", default-features = false }\n',
                         "lazaret-net": '[dependencies]\npratique = { path = "../pratique" }\n',
                         "lazaret-ffi": f'[dependencies]\nlazaret-engine = {{ path = "../lazaret-engine" }}\n\n'
                                        f'{native}\nlazaret-net = {{ path = "../lazaret-net" }}\n',
                         "lazaret-engine": '[dependencies]\nlazaret-verify = { path = "../lazaret-verify" }\n'})
        self.assertEqual(self.s.purity_problems(good), [])
        bad = crates(**{"lazaret-verify": '[dependencies]\npratique = { path = "../pratique" }\n',
                        "lazaret-engine": '[dependencies]\nlazaret-net = { path = "../lazaret-net" }\n'
                                          'pratique = { path = "../pratique", default-features = false }\n',
                        "lazaret-ffi": '[dependencies]\nlazaret-net = { path = "../lazaret-net" }\n'})
        problems = self.s.purity_problems(bad)
        self.assertEqual(len(problems), 4, problems)
        self.assertTrue(any(p.startswith("lazaret-verify: pratique without default-features") for p in problems))
        self.assertTrue(any(p.startswith("lazaret-engine: [dependencies] lazaret-net") for p in problems))
        self.assertTrue(any(p.startswith("lazaret-engine: [dependencies] pratique") for p in problems))
        self.assertTrue(any(p.startswith("lazaret-ffi: [dependencies] lazaret-net") for p in problems),
                        "the network for every target, WebAssembly included")


if __name__ == "__main__":
    unittest.main()
