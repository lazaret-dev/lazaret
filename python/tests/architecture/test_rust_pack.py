"""The native engine's rule pack, rust/crates/lazaret-engine/rules/
lazaret-rules.json: since the Rust-first refactor it is the source of the
engine's patterns, sets, limits and finding texts (it was extracted from
lazaret.scanner.core, which no longer holds them). scripts/make_rust_tables.py
--check holds it: in its canonical form, naming the registry's rule set,
every pattern compiling with Python's re (the syntax the engine reads), and
equal to the values core still keeps for the Python side (the reasons the
registry ranks, the limits the walk applies), which CI runs on Linux, macOS
and Windows. Here the same checks run, and the values core keeps are shown
to move neither with the operating system nor with the release: core is
imported in a child process with every os.O_* flag and errno number changed
(and O_BINARY added, as on Windows), and with the package's version changed.
"""

import json
import os
import subprocess
import sys
import unittest

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "make_rust_tables.py")
PACK = os.path.join(_support.REPO_ROOT, "rust", "crates", "lazaret-engine", "rules", "lazaret-rules.json")

CHILD = r"""
import errno, importlib.util, json, os, sys
sys.path.insert(0, sys.argv[2])
if sys.argv[1] == "release":
    import lazaret
    lazaret.__version__ = "99.0.0"          # (core reads it when it is imported, below)
if sys.argv[1] == "other":
    for name in dir(os):
        if name.startswith("O_") and isinstance(getattr(os, name), int):
            setattr(os, name, getattr(os, name) ^ 0x5A5A0000)
    if not hasattr(os, "O_BINARY"):
        os.O_BINARY = 0x8000
    for name in dir(errno):
        if name.isupper() and isinstance(getattr(errno, name), int):
            setattr(errno, name, getattr(errno, name) + 1000)
spec = importlib.util.spec_from_file_location("make_rust_tables", sys.argv[3])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with open(mod.PACK_OUT, encoding="utf-8") as f:
    print(json.dumps(mod.check_pack(f.read())))
"""


def problems(which):
    env = {k: v for k, v in os.environ.items() if not k.startswith("LAZARET_") or k == "LAZARET_NATIVE_LIB"}
    p = subprocess.run([sys.executable, "-c", CHILD, which, _support.SRC, SCRIPT], capture_output=True,
                       encoding="utf-8", errors="replace", env=env, timeout=40)
    if p.returncode:
        raise AssertionError(p.stderr[-2000:])
    return json.loads(p.stdout)


class RulePackTests(unittest.TestCase):
    def test_the_pack_passes_its_checks(self):
        self.assertEqual(problems("here"), [])

    def test_no_value_core_keeps_moves_with_the_operating_system(self):
        self.assertEqual(problems("other"), [], "a value core and the pack both hold depends on the OS")

    def test_no_value_core_keeps_moves_with_the_release(self):
        self.assertEqual(problems("release"), [], "a value core and the pack both hold changes with the version")

    def test_the_pack_names_the_registrys_rule_set(self):
        """The pack says which rule set it holds (the registry's ENGINE_VERSION,
        which a verdict records): a bump of ENGINE_VERSION changes the pack's
        rule_set with it."""
        from lazaret.registry.repo import ENGINE_VERSION
        with open(PACK, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["rule_set"], ENGINE_VERSION)


if __name__ == "__main__":
    unittest.main()
