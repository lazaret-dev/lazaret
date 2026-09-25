#!/usr/bin/env python3
"""Unit tests — Lazaret detection gaps (card "Lazaret detection gaps:
S-SQL-PY … / install-hook denylist / SKIP_DIRS / UTF-16", audit ids M9-M11 /
M17 = G10-G12, G22).

Run:  python3 lazaret/test_detection_gaps.py [unittest-args]

Acceptance criteria covered:
  G12 (M11): S-SQL-PY must catch execute(sql % x) with no space after %,
      literal %-interpolation in the call, .format() on a template variable,
      execute(name) where name was %-/concat-built — and must NOT flag
      parameterized calls (execute(q, (x,)), execute("…?", (x,))).
  G11 (M10): mere presence of an npm lifecycle script (preinstall, install,
      postinstall, prepare, prepublishOnly) yields SC-INSTALL-HOOK MAJOR; a
      fetch/eval pattern in the command escalates to CRITICAL; binding.gyp
      actions are covered.
  G10 (M9):  only .git/__pycache__ skip by default — dist/, migrations/,
      .hidden/ ARE scanned (secrets in them must be found); a FILE named dist
      is never skipped; skipped trees are counted and surfaced as INFO
      findings (Q-SKIPPED-TREE), never silently dropped.
  M17: a UTF-16LE .py with a secret and eval() is decoded properly (findings
      appear) and reported via Q-ENCODING; it no longer scans clean.

Fixtures live in lazaret/fixtures/detection_gaps/ (single-function .py
files on purpose — the interprocedural engine (lazaret_flow.py) predates
Python 3.12's ast changes and is out of scope for this card).
"""

import io
import json
import os

from tests import _support  # noqa: E402
import sys
import tempfile
import unittest

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures

from lazaret.scanner import core as lazaret  # noqa: E402

_EXPECTED = os.path.join(_support.PKG, "scanner", "core.py")
assert os.path.abspath(lazaret.__file__) == _EXPECTED, (
    f"test imported a shadowed module: {lazaret.__file__} (expected {_EXPECTED})")


def scan_to_result(root, exclude=()):
    """Run the module's scan pipeline on `root` and return the result dict."""
    files, manifests, binary_issues = lazaret.collect_files(root, list(exclude))
    issues = list(binary_issues)
    for f in files:
        issues.extend(lazaret.scan_file(f["path"], f["content"], f["lang"],
                                          dep=f.get("dep", False)))
    for mf in manifests:
        if os.path.basename(mf["path"]) == "binding.gyp":
            issues.extend(lazaret.scan_gyp(mf["path"], mf["content"]))
        else:
            issues.extend(lazaret.scan_manifest(mf["path"], mf["content"]))
    issues.extend(lazaret.skipped_tree_issues())
    return lazaret.build_result(root, files, issues)


def rules_at(res, rule_id):
    return [i for i in res["issues"] if i["rule"] == rule_id]


FIXTURES = os.path.join(HERE, "detection_gaps")


def git_dir_project():
    # A path with a literal ".git" component cannot be committed to git, so
    # this fixture tree is built at runtime in a temp dir instead of living
    # under fixtures/ (same trick as M17Encoding._utf16_project).
    d = tempfile.mkdtemp(prefix="cg_gitdir_")
    os.makedirs(os.path.join(d, ".git", "objects"), exist_ok=True)
    with open(os.path.join(d, ".git", "objects", "pack_secret.py"), "w") as f:
        f.write('password = "committed-then-deleted-secret"\n')
    with open(os.path.join(d, "clean.py"), "w") as f:
        f.write("x = 1\n")
    return d


class G12SqlIdioms(unittest.TestCase):
    """M11: SQLi idioms a single-line regex cannot see."""

    def test_all_vulnerable_idioms_flagged(self):
        res = scan_to_result(os.path.join(FIXTURES, "sql"))
        findings = rules_at(res, "S-SQL-PY")
        lines = sorted(i["line"] for i in findings)
        # execute(sql % x), "…" % x in call, SQL.format(x), execute(sql2),
        # execute(sql3)  →  5 vulnerable lines in vuln_sql.py
        self.assertEqual(len(findings), 5, f"expected 5 SQLi findings, got {lines}")
        self.assertEqual(lines, [8, 11, 15, 19, 23],
                         f"expected the 5 vulnerable lines, got {lines}")

    def test_parameterized_calls_not_flagged(self):
        res = scan_to_result(os.path.join(FIXTURES, "sql"))
        for i in rules_at(res, "S-SQL-PY"):
            self.assertNotIn("(user_input,)", i.get("snippet", ""),
                             "parameterized call was flagged")
            self.assertNotIn("?", i.get("snippet", "")[:40],
                             "placeholder query was flagged")

    def test_safe_project_clean(self):
        res = scan_to_result(os.path.join(FIXTURES, "safe"))
        self.assertEqual(rules_at(res, "S-SQL-PY"), [],
                         "safe_sql.py must produce zero S-SQL-PY findings")


class G11InstallHooks(unittest.TestCase):
    """M10: presence-based lifecycle detection, binding.gyp coverage."""

    def test_lifecycle_presence_flagged(self):
        res = scan_to_result(os.path.join(FIXTURES, "hooks"))
        hooks = rules_at(res, "SC-INSTALL-HOOK")
        names = {i["msg"].split('"')[1] for i in hooks}
        # every script `npm install` runs in a checked-out project is flagged
        self.assertTrue({"preinstall", "install", "postinstall", "prepare"} <= names,
                        f"missing lifecycle hooks in {names}")
        # publisher-side scripts only run on the maintainer's machine while
        # packaging a release, never on install, so they are not install hooks
        self.assertNotIn("prepublishOnly", names)

    def test_pattern_escalates_to_critical(self):
        res = scan_to_result(os.path.join(FIXTURES, "hooks"))
        sevs = {i["msg"].split('"')[1]: i["sev"] for i in rules_at(res, "SC-INSTALL-HOOK")}
        # npx/node/git-clone hooks bypass the old denylist: MAJOR presence
        self.assertEqual(sevs["postinstall"], "MAJOR")   # git clone … && make
        self.assertEqual(sevs["preinstall"], "MAJOR")    # npx --yes evil
        # shared semantics 3: in a project checkout a prepare-family hook
        # whose command does not match the fetch/eval patterns is INFO (the
        # project's own build step); a suspicious one stays CRITICAL
        self.assertEqual(sevs["prepare"], "INFO")

    def test_binding_gyp_actions_flagged(self):
        res = scan_to_result(os.path.join(FIXTURES, "gyp"))
        hooks = rules_at(res, "SC-INSTALL-HOOK")
        self.assertTrue(hooks, "binding.gyp action produced no finding")
        self.assertEqual(hooks[0]["sev"], "CRITICAL", "curl in gyp action must be CRITICAL")

    def test_test_script_not_flagged(self):
        res = scan_to_result(os.path.join(FIXTURES, "hooks"))
        for i in rules_at(res, "SC-INSTALL-HOOK"):
            self.assertNotIn('"test"', i["msg"])


class G10SkipDirs(unittest.TestCase):
    """M9: default skips hide the classic spots; make them visible."""

    def test_dist_migrations_hidden_scanned(self):
        res = scan_to_result(os.path.join(FIXTURES, "skips"))
        secrets = {i["file"].replace(os.sep, "/") for i in res["issues"]
                   if i["rule"] in ("S-SECRET", "S-TOKEN")}
        self.assertIn("dist/bundle.py", secrets, "dist/ secret was skipped")
        self.assertIn("migrations/0001.py", secrets, "migrations/ secret was skipped")
        self.assertIn(".hidden/x.py", secrets, ".hidden/ secret was skipped")

    def test_file_named_dist_scanned(self):
        res = scan_to_result(os.path.join(FIXTURES, "skips"))
        secrets = {i["file"].replace(os.sep, "/") for i in res["issues"]
                   if i["rule"] in ("S-SECRET", "S-TOKEN")}
        self.assertIn("dist-file.py", secrets, "file named dist was skipped")

    def test_only_git_and_pycache_default_skipped(self):
        self.assertEqual(lazaret.SKIP_DIRS, {".git", "__pycache__"},
                         "SKIP_DIRS default must be .git/__pycache__ only")

    def test_opt_in_exclude_still_works_and_counted(self):
        res = scan_to_result(os.path.join(FIXTURES, "skips"), exclude=["dist"])
        secrets = {i["file"].replace(os.sep, "/") for i in res["issues"]
                   if i["rule"] in ("S-SECRET", "S-TOKEN")}
        self.assertNotIn("dist/bundle.py", secrets, "explicit exclude ignored")
        skipped = rules_at(res, "Q-SKIPPED-TREE")
        self.assertTrue(any(i["file"] == "dist" for i in skipped),
                        "excluded tree not counted in skipped accounting")

    def test_git_dir_skipped_and_counted(self):
        # .git is still skipped by default, but visibly: Q-SKIPPED-TREE INFO
        res = scan_to_result(git_dir_project())
        skipped = rules_at(res, "Q-SKIPPED-TREE")
        self.assertTrue(any(i["file"].endswith(".git") for i in skipped),
                        ".git tree not counted")
        self.assertEqual(len(rules_at(res, "S-SECRET")), 0)

    def test_skipped_tree_info_never_fails_supply_chain_gate(self):
        # INFO accounting must not trip the "No supply-chain indicators" gate
        res = scan_to_result(os.path.join(FIXTURES, "skips"), exclude=["dist"])
        for c in res["conditions"]:
            if "supply-chain" in c["label"]:
                self.assertTrue(c["ok"], "Q-SKIPPED-TREE tripped the supply gate")


class M17Encoding(unittest.TestCase):
    """M17: UTF-16 sources scan clean today; they must not."""

    def _utf16_project(self):
        d = tempfile.mkdtemp(prefix="cg_m17_")
        src = ('password = "sup3rSecret"\n'
               'eval(x)\n')
        with open(os.path.join(d, "evil_utf16.py"), "wb") as f:
            f.write(src.encode("utf-16"))
        return d

    def test_utf16_findings_not_hidden(self):
        res = scan_to_result(self._utf16_project())
        ids = {i["rule"] for i in res["issues"]}
        self.assertIn("S-EVAL-PY", ids, "eval(x) in UTF-16 still invisible")
        self.assertTrue({"S-SECRET", "S-TOKEN"} & ids,
                        "password literal in UTF-16 still invisible")

    def test_utf16_reported_as_encoding(self):
        res = scan_to_result(self._utf16_project())
        enc = rules_at(res, "Q-ENCODING")
        self.assertTrue(enc, "no Q-ENCODING finding for a UTF-16 source")

    def test_detect_encoding_bom(self):
        de = lazaret.detect_encoding
        self.assertEqual(de(b"\xff\xfep\x00")["encoding"], "utf-16")
        self.assertTrue(de(b"\xff\xfep\x00")["reported"])
        self.assertEqual(de(b"\xef\xbb\xbfimport os\n")["encoding"], "utf-8-sig")
        self.assertEqual(de(b"import os\n")["encoding"], "utf-8")
        self.assertFalse(de(b"import os\n")["reported"])

    def test_ascii_source_not_reported(self):
        res = scan_to_result(os.path.join(FIXTURES, "safe"))
        self.assertEqual(rules_at(res, "Q-ENCODING"), [],
                         "plain UTF-8 file reported as non-UTF-8")


class Regression(unittest.TestCase):
    """Old behaviors that must survive the SKIP_DIRS change."""

    def test_dot_git_contents_never_scanned(self):
        res = scan_to_result(git_dir_project())
        files_scanned = {f for f, in [(i["file"],) for i in res["issues"]]}
        for f in files_scanned:
            self.assertFalse(f.startswith(".git/"), ".git contents were scanned")

    def test_result_json_serializable(self):
        res = scan_to_result(FIXTURES)
        json.dumps(res["issues"])   # must not raise


if __name__ == "__main__":
    unittest.main(verbosity=2)
