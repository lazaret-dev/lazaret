"""The native engine's rule pack is the same on every platform.

scripts/make_rust_tables.py extracts every module-level value of core into
rust/crates/lazaret-engine/rules/lazaret-rules.json, and CI runs its --check
on Linux, macOS and Windows. A value core computes from the operating
system's constants would be written as this machine's number and then fail
the check everywhere else: `_OPEN_FLAGS` (os.O_NOFOLLOW | os.O_NONBLOCK …)
did, on 0.1.8's first macOS and Windows runs. Here core is imported, in a
child process, once as it is and once with every os.O_* flag and errno
number changed (and O_BINARY added, as on Windows); any pack value that
moves must be left out of the pack (make_rust_tables.PLATFORM_VALUES) or
computed another way."""

import json
import os
import subprocess
import sys
import unittest

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "make_rust_tables.py")

CHILD = r"""
import errno, importlib.util, json, os, sys
if sys.argv[1] == "other":
    for name in dir(os):
        if name.startswith("O_") and isinstance(getattr(os, name), int):
            setattr(os, name, getattr(os, name) ^ 0x5A5A0000)
    if not hasattr(os, "O_BINARY"):
        os.O_BINARY = 0x8000
    for name in dir(errno):
        if name.isupper() and isinstance(getattr(errno, name), int):
            setattr(errno, name, getattr(errno, name) + 1000)
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location("make_rust_tables", sys.argv[3])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print(json.dumps({"values": mod.pack_data()["values"], "skipped": sorted(mod.PLATFORM_VALUES)}))
"""


def pack(which):
    env = {k: v for k, v in os.environ.items() if not k.startswith("LAZARET_")}
    p = subprocess.run([sys.executable, "-c", CHILD, which, _support.SRC, SCRIPT], capture_output=True,
                       encoding="utf-8", errors="replace", env=env, timeout=40)
    if p.returncode:
        raise AssertionError(p.stderr[-2000:])
    return json.loads(p.stdout)


class RulePackPortabilityTests(unittest.TestCase):
    def test_no_value_moves_with_the_operating_system(self):
        here, other = pack("here"), pack("other")
        moved = sorted(k for k in set(here["values"]) | set(other["values"])
                       if here["values"].get(k) != other["values"].get(k))
        self.assertEqual(moved, [], "these core values depend on the OS: add them to "
                                    "make_rust_tables.PLATFORM_VALUES (the engine must not read them)")

    def test_the_left_out_values_are_not_in_the_pack(self):
        here = pack("here")
        with open(os.path.join(_support.REPO_ROOT, "rust", "crates", "lazaret-engine", "rules",
                               "lazaret-rules.json"), encoding="utf-8") as f:
            shipped = json.load(f)["values"]
        for name in here["skipped"]:
            with self.subTest(name):
                self.assertFalse(name in here["values"], f"{name} is extracted")
                self.assertFalse(name in shipped, f"{name} is in the shipped pack: rerun "
                                                  f"scripts/make_rust_tables.py")


if __name__ == "__main__":
    unittest.main()
