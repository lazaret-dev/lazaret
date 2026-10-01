"""The engine's per-file scans, held to their recorded outputs
(_snapshots.py): scan_file in dependency mode (registry, guard and --deps
scans: the pattern rules and their families, secrets redacted), scan_rules
(project mode's rules part) and what the families read of each line
(file_context: the comment layout, match text and names), on the scan_file
corpus (scanfile_corpus.py) and the repository's test fixtures. The corpus
reaches every family in each of its variants, and project mode's rules of
each kind.
"""
import os
import unittest

from lazaret.scanner import _native, core
from tests import _support
from tests.architecture import _snapshots
from tests.architecture.scanfile_corpus import corpus

FAMILIES = ("S-SECRET", "S-TOKEN", "SC-EVAL-DECODE", "SC-PACKER", "SC-EVAL-DECODER", "SC-MARSHAL", "SC-HEXSTR",
            "SC-HOMOGLYPH", "SC-HIDDEN-UNICODE", "SC-CHARCODE", "SC-B64", "SC-OFFSCREEN-CODE", "S-ENTROPY",
            "SC-OBF-IDENT", "SC-SELF-PUBLISH")
# each variant a family can take, reached by the corpus: (rule, severity, a piece of the message)
VARIANTS = (("SC-HEXSTR", "CRITICAL", "hide readable text"), ("SC-HEXSTR", "MAJOR", "hide readable text"),
            ("SC-HEXSTR", "CRITICAL", "hide a name"), ("SC-HOMOGLYPH", "CRITICAL", "another name in this file"),
            ("SC-HOMOGLYPH", "CRITICAL", "reads as"), ("SC-HOMOGLYPH", "MAJOR", "reads as"),
            ("SC-HOMOGLYPH", "CRITICAL", "invisible"), ("SC-HIDDEN-UNICODE", "CRITICAL", "runs code"),
            ("SC-HIDDEN-UNICODE", "MAJOR", "tag characters"), ("SC-HIDDEN-UNICODE", "MAJOR", "variation selectors"),
            ("SC-OFFSCREEN-CODE", "CRITICAL", "blanks"), ("SC-OFFSCREEN-CODE", "MAJOR", "blanks"),
            ("SC-EVAL-DECODE", "BLOCKER", "assigned at line"), ("SC-EVAL-DECODE", "BLOCKER", "in the same call"))
# project mode: what only it reads, and rules of each kind it must reach
PROJECT_ONLY = ("Q-LONGLINE", "SC-PIPE-SHELL", "B-EMPTY-CATCH", "B-EXCEPT-PASS")
REACHED = PROJECT_ONLY + ("B-EQEQ", "Q-TODO", "S-BIDI", "S-EVAL-PY", "S-TOKEN", "SC-EVAL-DECODE", "SC-HEXSTR",
                          "S-ENTROPY")
MAX_FILE = 300_000                     # characters of a fixture read


def lang_of(path):
    return core.EXTS.get(os.path.splitext(path)[1].lower())


def call_args(path):
    return {"lang": lang_of(path), "dep": True, "jsx": core.jsx_reading(path), "neumaier": True}


def fixtures():
    """(path, text) of the repository's test fixtures that are source files."""
    out = []
    base = os.path.join(_support.PY_ROOT, "tests", "fixtures")
    for root, dirs, files in os.walk(base):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(root, name)
            if not lang_of(path):
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            if len(text) <= MAX_FILE:
                out.append((os.path.relpath(path, _support.REPO_ROOT).replace(os.sep, "/"), text))
    return out


def snapshot_sets():
    def files():
        return corpus() + fixtures()

    def context():
        return corpus(seed=7, scale=1)[::2] + fixtures()
    return {"scan_file": lambda: [("scan_file", call_args(p), t) for p, t in files()],
            "scan_rules": lambda: [("scan_rules", call_args(p), t) for p, t in files()],
            "file_context": lambda: [("file_context", call_args(p), t) for p, t in context()]}


def findings(answers):
    """Each answer's findings as (rule, severity, message)."""
    return [[(a[0], a[3], a[4]) for a in r["ok"]] for r in answers if "ok" in r]


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ScanFileSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.answers = _snapshots.run(snapshot_sets()["scan_file"]())

    def test_the_outputs_are_the_recorded_ones(self):
        self.assertFalse([a for a in self.answers if "ok" not in a][:5])
        _snapshots.check(self, "scan_file", self.answers)

    def test_every_family_is_reached(self):
        """The corpus makes the engine find each family, in each of its variants."""
        found = [f for issues in findings(self.answers) for f in issues]
        for family in FAMILIES:
            with self.subTest(family=family):
                self.assertTrue(any(rule == family for rule, _s, _m in found), family)
        for rule, sev, piece in VARIANTS:
            with self.subTest(rule=rule, sev=sev, msg=piece):
                self.assertTrue(any(r == rule and s == sev and piece in m for r, s, m in found))
        # and redaction: a secret on a flagged line and in the lines around one
        self.assertTrue(any("[redacted" in line for r in self.answers if "ok" in r for a in r["ok"] for line in a[9]))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ScanRulesSnapshotTests(unittest.TestCase):
    def test_the_outputs_are_the_recorded_ones(self):
        answers = _snapshots.run(snapshot_sets()["scan_rules"]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, "scan_rules", answers)
        found = {rule for issues in findings(answers) for rule, _s, _m in issues}
        for rule in REACHED:
            with self.subTest(rule=rule):
                self.assertIn(rule, found)
        self.assertGreaterEqual(len(found), 40)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class FileContextSnapshotTests(unittest.TestCase):
    def test_the_outputs_are_the_recorded_ones(self):
        answers = _snapshots.run(snapshot_sets()["file_context"]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, "file_context", answers)


if __name__ == "__main__":
    unittest.main()
