"""The received-code detector's shared data spec (received_spec.json).

Name sets, character sets and limits are authored once in
python/src/lazaret/scanner/received_spec.json and synced into the npm package
at js/src/lib/received-spec.json by scripts/sync-received-spec.py, so a needle
or a limit is edited in one place. These tests hold the two copies together
and hold the loaded values to what core actually uses:

  * the two JSON files are byte-identical (the sync is current), and
  * every set / limit core exposes matches the spec it came from.

The Python↔JavaScript engine comparison (that both compile the same patterns
and agree on every input) is tests/architecture/test_js_parity_hooks.py.
"""
import json
import os
import unittest

from lazaret.scanner import core
from tests import _support

REPO = _support.REPO_ROOT
SOURCE = os.path.join(REPO, "python", "src", "lazaret", "scanner", "received_spec.json")
COPY = os.path.join(REPO, "js", "src", "lib", "received-spec.json")


class ReceivedSpecTests(unittest.TestCase):
    def test_the_two_copies_are_byte_identical(self):
        with open(SOURCE, "rb") as f:
            source = f.read()
        with open(COPY, "rb") as f:
            copy = f.read()
        self.assertEqual(source, copy,
                         "js/src/lib/received-spec.json is stale; run scripts/sync-received-spec.py")

    def test_the_spec_is_valid_and_shaped(self):
        with open(SOURCE, encoding="utf-8") as f:
            spec = json.load(f)
        self.assertEqual(set(spec) - {"$comment"},
                         {"arrays", "charstrings", "limits", "patterns", "alternatives"})
        for name, value in spec["arrays"].items():
            self.assertTrue(value and all(isinstance(x, str) for x in value), name)
        for name, value in spec["charstrings"].items():
            self.assertTrue(value and isinstance(value, str), name)
        for name, value in spec["limits"].items():
            self.assertIsInstance(value, int, name)
        for name, p in spec["patterns"].items():
            self.assertEqual(set(p) - {"note"}, {"src", "flags"}, name)
            self.assertTrue(p["src"] and isinstance(p["src"], str), name)
            self.assertIsInstance(p["flags"], str, name)
            self.assertLessEqual(set(p["flags"]), set("ims"), name)
        for name, g in spec["alternatives"].items():
            self.assertEqual(set(g) - {"note", "tail", "extends"}, {"pairs"}, name)
            self.assertTrue(g["pairs"], name)
            for pair in g["pairs"]:
                self.assertEqual(len(pair), 2, name)
                self.assertTrue(all(isinstance(x, str) for x in pair), name)
            if "extends" in g:
                self.assertIn(g["extends"], spec["alternatives"], name)
            if "tail" in g:
                self.assertIsInstance(g["tail"], str, name)

    def test_core_uses_the_spec_values(self):
        with open(SOURCE, encoding="utf-8") as f:
            spec = json.load(f)
        a = spec["arrays"]
        self.assertEqual(list(core._DL_NEEDLES), a["_DL_NEEDLES"])
        self.assertEqual(list(core._DL_RUN_NEEDLES), a["_DL_RUN_NEEDLES"])
        self.assertEqual(list(core._DL_DESERIAL_NEEDLES), a["_DL_DESERIAL_NEEDLES"])
        self.assertEqual(list(core._DL_IMPORT_NEEDLES), a["_DL_IMPORT_NEEDLES"])
        self.assertEqual(list(core._DL_ALIAS_NEEDLES), a["_DL_ALIAS_NEEDLES"])
        self.assertEqual(list(core._DL_FILE_WRITE_NEEDLES), a["_DL_FILE_WRITE_NEEDLES"])
        self.assertEqual(list(core._DL_PATHRUN_NEEDLES), a["_DL_PATHRUN_NEEDLES"])
        self.assertEqual(sorted(core._DL_PY_NET_MODULES), sorted(a["_DL_PY_NET_MODULES"]))
        self.assertEqual(sorted(core._DL_NOT_NAMES), sorted(a["_DL_NOT_NAMES"]))
        self.assertEqual(list(core._DL_DEFINING), a["_DL_DEFINING"])
        self.assertEqual(core._DL_PREFIX_CHARS, frozenset(spec["charstrings"]["_DL_PREFIX_CHARS"]))
        self.assertEqual(core._DL_CALLEE_CHARS, frozenset(spec["charstrings"]["_DL_CALLEE_CHARS"]))
        for name, value in spec["limits"].items():
            self.assertEqual(getattr(core, name), value, name)
        # SINK is derived, not stored
        self.assertEqual(list(core._DL_SINK_NEEDLES),
                         a["_DL_RUN_NEEDLES"] + a["_DL_DESERIAL_NEEDLES"] + a["_DL_IMPORT_NEEDLES"])
        # core compiles each plain pattern's source verbatim from the spec (the
        # composed group patterns are held to core by test_js_parity_hooks)
        for name, p in spec["patterns"].items():
            self.assertEqual(getattr(core, name).pattern, p["src"], name)


if __name__ == "__main__":
    unittest.main()
