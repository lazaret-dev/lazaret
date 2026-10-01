"""Engine parity for scan_file in project mode, as far as the native engine
reads it (0.1.9): the native engine's scan_rules (crates/lazaret-engine:
scanfile.rs) against core.scan_rules — the pattern rules of every line
(quality, bug and security rules alike, with Q-LONGLINE and SC-PIPE-SHELL
in their places), the supply-chain and credential families, the file-level
ones and the whole-text rules, finding for finding (rule, texts, line,
snippet clipped and redacted) and in core's order, before the passes that
follow them (the SQL statements without WHERE, taint, the SQL-sink pass,
the function metrics), the suppression markers and the cap. The npm package
runs the native engine as WebAssembly and does the rest itself.

The files are those of the dependency-mode test (test_rust_parity_scanfile:
the scan_file corpus, this repository's sources and fixtures, a sample of
the standard library), read as your own. Skipped where the native library
is not built.
"""
import unittest

from lazaret.scanner import _native, core
from tests.architecture.scanfile_corpus import corpus
from tests.architecture.test_rust_parity_scanfile import as_issues, jsonable, lang_of, real_files, run_both

# what only project mode reads, and rules of each kind it must reach
PROJECT_ONLY = ("Q-LONGLINE", "SC-PIPE-SHELL", "B-EMPTY-CATCH", "B-EXCEPT-PASS")
REACHED = PROJECT_ONLY + ("B-EQEQ", "Q-TODO", "S-BIDI", "S-EVAL-PY", "S-TOKEN", "SC-EVAL-DECODE", "SC-HEXSTR",
                          "S-ENTROPY")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RustProjectRulesParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus() + real_files()
        cls.want, box = run_both("scan_rules", cls.cases, lambda path, text: jsonable(
            core.scan_rules(path, text, lang_of(path))))
        cls.error = box.get("error")
        cls.got = [jsonable(as_issues(path, a["ok"])) if "ok" in a else a
                   for (path, _text), a in zip(cls.cases, box.get("answers", []))]

    def test_every_file_is_answered(self):
        self.assertIsNone(self.error)
        self.assertEqual(len(self.got), len(self.cases))
        unanswered = [(path, g) for (path, _t), g in zip(self.cases, self.got) if not isinstance(g, list)]
        self.assertEqual(unanswered[:5], [])

    def test_each_rule_agrees(self):
        rules = sorted({i["rule"] for issues in self.want for i in issues}
                       | {i["rule"] for issues in self.got if isinstance(issues, list) for i in issues})
        for rule in rules:
            with self.subTest(rule=rule):
                found = []
                for (path, text), want, got in zip(self.cases, self.want, self.got):
                    if not isinstance(got, list):
                        continue
                    w = [i for i in want if i["rule"] == rule]
                    g = [i for i in got if i["rule"] == rule]
                    if w != g:
                        k = next((k for k, (a, b) in enumerate(zip(w, g)) if a != b), min(len(w), len(g)))
                        found.append((path, text[:300], w[k:k + 1], g[k:k + 1]))
                        if len(found) >= 3:
                            break
                self.assertEqual(found, [])

    def test_the_findings_come_in_cores_order(self):
        for (path, _t), want, got in zip(self.cases, self.want, self.got):
            if isinstance(got, list) and got != want:
                self.fail(f"{path}: {[i['rule'] for i in want]} != {[i['rule'] for i in got]}")

    def test_the_files_reach_each_kind_of_rule(self):
        found = {i["rule"] for issues in self.want for i in issues}
        for rule in REACHED:
            with self.subTest(rule=rule):
                self.assertIn(rule, found)
        self.assertGreaterEqual(len(found), 40)


if __name__ == "__main__":
    unittest.main()
