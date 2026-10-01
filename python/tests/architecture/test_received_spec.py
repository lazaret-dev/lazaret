"""The received-code detector's shared data spec (received_spec.json).

Name sets, character sets, limits and pattern pieces are authored once in
python/src/lazaret/scanner/received_spec.json, which core loads; the native
engine reads core's values from its rule pack (make_rust_tables.py), and
the npm package runs the native engine (0.1.8; through 0.1.7 it carried a
copy of the spec, js/src/lib/received-spec.json). These tests hold the spec's
shape and hold what core uses to the spec it came from; the parity tests
(test_rust_parity_signs) hold the engines to each other on every input.
"""
import json
import os
import unittest

from lazaret.scanner import core
from tests import _support

REPO = _support.REPO_ROOT
SOURCE = os.path.join(REPO, "python", "src", "lazaret", "scanner", "received_spec.json")


class ReceivedSpecTests(unittest.TestCase):
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
        self.assertEqual(core._DL_RUNNERS, frozenset(a["_DL_RUNNERS"]))
        self.assertEqual(core._DL_PREFIX_CHARS, frozenset(spec["charstrings"]["_DL_PREFIX_CHARS"]))
        self.assertEqual(core._DL_CALLEE_CHARS, frozenset(spec["charstrings"]["_DL_CALLEE_CHARS"]))
        for name, value in spec["limits"].items():
            self.assertEqual(getattr(core, name), value, name)
        # SINK is derived, not stored
        self.assertEqual(list(core._DL_SINK_NEEDLES),
                         a["_DL_RUN_NEEDLES"] + a["_DL_DESERIAL_NEEDLES"] + a["_DL_IMPORT_NEEDLES"])
        # core compiles each plain pattern's source verbatim from the spec
        for name, p in spec["patterns"].items():
            self.assertEqual(getattr(core, name).pattern, p["src"], name)


if __name__ == "__main__":
    unittest.main()
