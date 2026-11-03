"""Scan-all lists a repository's own workflow hygiene as INFO (SCANALL-HYGIENE, 0.1.9; John's decision of Oct 21:
"INFO in scan-all only"). lazaret.registry.ghdiscover's result(scan_all=True), for the repositories scan-all queued.

SC-WORKFLOW-UNPINNED, -PERMISSIONS, -CACHE and -OIDC-INSTALL are the owner's configuration, not a sign that a new
repository is hostile: in scan-all they are stored and reported as INFO, each message saying so and what a project
scan grades it, and set no verdict (below CRITICAL they never did: core.HARDENING_RULES). Covered: hygiene alone is
OK; a real indicator beside it gives that indicator's verdict (SC-WORKFLOW-SECRETS, a hostile repository's);
SC-WORKFLOW-PR-CHECKOUT is still SUSPICIOUS; --ci, the candidates and `list` follow the verdict; the run's report
says what was listed as INFO; and the same repository elsewhere is graded as before: a filter's candidate in the same
run, `lazaret-registry scan github:`, `lazaret scan github:` (its report and its gate). GitHub and GH Archive are
test_ghdiscover's and test_ghdiscover_archive's fakes; every workflow is inert text, nothing is fetched or run.
"""
import contextlib
import datetime
import io
import json
import os
import sys
import unittest
from unittest import mock

from lazaret.registry import ghdiscover, ghevents, repo, sourcescan
from lazaret.scanner import core, engine
from tests.registry.test_ghdiscover import ENV, HOSTILE, SHA, FakeGitHub
from tests.registry.test_ghdiscover_archive import HOUR, ArchiveCase, FakeArchive, push
from tests.registry.test_sources import Net, gh_answers
from tests.registry.test_sourcescan import Dir

UTC = datetime.timezone.utc
FOUR = ("SC-WORKFLOW-CACHE", "SC-WORKFLOW-OIDC-INSTALL", "SC-WORKFLOW-PERMISSIONS", "SC-WORKFLOW-UNPINNED")

#: a repository whose workflows have every one of the four (six findings), and nothing else
HYGIENE = {
    "README.md": "# a tool\n",
    ".github/workflows/release.yml": (           # an action at a branch (MAJOR), GitHub's at a tag (MINOR), a cache in
        "on: release\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    permissions:\n      id-token: write\n"
        "    steps:\n      - uses: some/thing@main\n      - uses: actions/cache@v4\n        with:\n          path: x\n"
        "      - run: npm ci\n"),                # a release (MAJOR), an install that can ask an OIDC token (MAJOR)
    ".github/workflows/build.yml": (             # no permissions (MINOR), GitHub's action at a tag (MINOR)
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
        "      - run: make\n"),
}


def native(path):
    """A path of the repository as the scans report it: root-relative, with this system's separator (core.py: "Paths
    are root-relative (os.sep separators)"), a backslash on Windows."""
    return path.replace("/", os.sep)


#: what a project scan grades them (and so do a filter's candidate and `scan github:`)
GRADES = [(native(".github/workflows/build.yml"), 2, "SC-WORKFLOW-PERMISSIONS", "MINOR"),
          (native(".github/workflows/build.yml"), 6, "SC-WORKFLOW-UNPINNED", "MINOR"),
          (native(".github/workflows/release.yml"), 8, "SC-WORKFLOW-UNPINNED", "MAJOR"),
          (native(".github/workflows/release.yml"), 9, "SC-WORKFLOW-CACHE", "MAJOR"),
          (native(".github/workflows/release.yml"), 9, "SC-WORKFLOW-UNPINNED", "MINOR"),
          (native(".github/workflows/release.yml"), 12, "SC-WORKFLOW-OIDC-INSTALL", "MAJOR")]
LISTED = {"SC-WORKFLOW-CACHE": 1, "SC-WORKFLOW-OIDC-INSTALL": 1, "SC-WORKFLOW-PERMISSIONS": 1,
          "SC-WORKFLOW-UNPINNED": 3}
SAID = ("6 workflow hygiene findings listed as INFO, as the owner's configuration (SC-WORKFLOW-CACHE 1, "
        "SC-WORKFLOW-OIDC-INSTALL 1, SC-WORKFLOW-PERMISSIONS 1, SC-WORKFLOW-UNPINNED 3)")
#: a weaker indicator that is not hygiene: every secret handed to a job's environment (MAJOR)
SECRETS = {".github/workflows/env.yml": (
    "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - run: make\n        env:\n          ALL: ${{ toJSON(secrets) }}\n")}
#: a pull_request_target job that checks out the pull request's code (CRITICAL), GitHub's checkout at a tag (MINOR)
PR_CHECKOUT = {".github/workflows/pr.yml": (
    "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    "      - run: npm test\n")}


def graded(issues, rules=FOUR):
    """(file, line, rule, severity) of the findings of `rules`, in that order."""
    return sorted((i["file"], i["line"], i["rule"], i["sev"]) for i in issues if i["rule"] in rules)


def by_rule(res, rule):
    return [i for i in res["issues"] if i["rule"] == rule]


class ScanAllCase(ArchiveCase):
    def scan_all(self, queued, ready=None, **kw):
        """The repositories in `queued` pushed (scan-all queues them), those in `ready` a filter's candidates with
        content; one scan-all run scans them all -> {name: result}."""
        self.store.save_discovery_cursor("github-scan-all", 900)
        names = {901 + k: name for k, name in enumerate(queued)}
        archive = FakeArchive({"2026-10-14-11": [push(k, v, HOUR + datetime.timedelta(minutes=k - 900))
                                                 for k, v in names.items()]})
        for k, name in enumerate(ready or {}):
            self.store.add_github_candidate(800 + k, name, None, False, ["look-alike: made up"],
                                            "2026-10-14T09:00:00+00:00", "ready", None)
        gh = FakeGitHub(files={**queued, **(ready or {})})
        out = self.run_gh(gh, events=archive, scan_all=True, **kw)
        self.assertEqual(out["errors"], [])
        return {r["name"]: r for r in out["scans"]}


class ScanAllTests(ScanAllCase):
    def test_hygiene_alone_is_ok_and_listed_as_info(self):
        res = self.scan_all({"u/tool": HYGIENE})["u/tool"]
        self.assertEqual((res["verdict"], res["verdictReason"]), ("OK", "no supply-chain indicators; " + SAID))
        self.assertEqual(graded(res["issues"]), sorted((f, n, r, "INFO") for f, n, r, _ in GRADES))
        for issue in by_rule(res, "SC-WORKFLOW-OIDC-INSTALL") + by_rule(res, "SC-WORKFLOW-PERMISSIONS"):
            sev = "MAJOR" if issue["rule"] == "SC-WORKFLOW-OIDC-INSTALL" else "MINOR"
            self.assertTrue(issue["msg"].endswith(
                f" (scan-all: the owner's workflow configuration, {sev} in a project scan: listed, not counted)"),
                issue["msg"])
        self.assertEqual(res["hygieneInfo"], LISTED)
        self.assertEqual((res["sevCounts"]["MAJOR"], res["sevCounts"]["MINOR"], res["supplyChain"]), (0, 0, 0))
        self.assertEqual(res["issues"], sorted(res["issues"], key=lambda i: core.SEV_ORDER[i["sev"]]))
        # stored so: the candidate's verdict, the scan's findings and counts
        cand = self.candidates()["u/tool"]
        self.assertEqual((cand["state"], cand["verdict"]), ("scanned", "OK"))
        rep = self.store.report("github", "u/tool")
        self.assertEqual((rep["verdict"], graded(rep["issues"])), ("OK", graded(res["issues"])))
        self.assertTrue(all("(scan-all: the owner's workflow configuration" in i["msg"]
                            for i in rep["issues"] if i["rule"] in FOUR))
        majors = self.store.conn.execute("SELECT majors FROM scans").fetchall()
        self.assertEqual(majors, [(0,)])

    def test_a_real_indicator_beside_it_gives_that_indicators_verdict(self):
        scans = self.scan_all({"u/secrets": {**HYGIENE, **SECRETS}, "u/hostile": {**HYGIENE, **HOSTILE},
                               "u/plain": HOSTILE})
        res = scans["u/secrets"]
        self.assertEqual((res["verdict"], res["verdictReason"]),
                         ("WARN", "1 weaker supply-chain indicator to review; " + SAID))
        self.assertEqual([i["sev"] for i in by_rule(res, "SC-WORKFLOW-SECRETS")], ["MAJOR"])    # not hygiene: counted
        self.assertEqual((res["strongIndicators"], res["weakIndicators"]), (0, 1))
        hostile, plain = scans["u/hostile"], scans["u/plain"]
        self.assertEqual((hostile["verdict"], plain["verdict"]), ("SUSPICIOUS", "SUSPICIOUS"))
        self.assertEqual((hostile["strongIndicators"], hostile["weakIndicators"]),
                         (plain["strongIndicators"], plain["weakIndicators"]))     # what the hygiene adds: nothing
        mixed = dict(LISTED)                                    # (the hostile workflow sets no permissions either)
        for rule, n in plain["hygieneInfo"].items():
            mixed[rule] = mixed.get(rule, 0) + n
        self.assertEqual(hostile["hygieneInfo"], mixed)
        self.assertTrue(hostile["verdictReason"].endswith("; " + ghdiscover.hygiene_said(mixed)),
                        hostile["verdictReason"])
        self.assertEqual({i["sev"] for i in hostile["issues"] if i["rule"] in FOUR}, {"INFO"})

    def test_a_pull_request_target_checkout_is_still_suspicious(self):
        res = self.scan_all({"u/pr": {**HYGIENE, **PR_CHECKOUT}})["u/pr"]
        self.assertEqual((res["verdict"], res["strongIndicators"]), ("SUSPICIOUS", 1))
        self.assertEqual([(i["file"], i["sev"]) for i in by_rule(res, "SC-WORKFLOW-PR-CHECKOUT")],
                         [(native(".github/workflows/pr.yml"), "CRITICAL")])
        self.assertEqual(res["issues"][0]["rule"], "SC-WORKFLOW-PR-CHECKOUT")
        self.assertEqual(res["hygieneInfo"], {**LISTED, "SC-WORKFLOW-UNPINNED": 4})     # pr.yml's checkout@v4 too
        self.assertEqual(self.candidates()["u/pr"]["verdict"], "SUSPICIOUS")

    def test_a_filters_candidate_in_the_same_run_is_graded_as_before(self):
        scans = self.scan_all({"u/tool": HYGIENE}, ready={"shopsprint/tool": HYGIENE})
        mine, theirs = scans["u/tool"], scans["shopsprint/tool"]
        self.assertEqual(graded(theirs["issues"]), sorted(GRADES))
        self.assertFalse(any("scan-all:" in i["msg"] for i in theirs["issues"]))
        self.assertEqual((theirs["verdict"], theirs["verdictReason"], theirs["hygieneInfo"]),
                         ("OK", "no supply-chain indicators", {}))
        self.assertEqual(mine["verdict"], theirs["verdict"])                       # the verdict, either way
        self.assertEqual((mine["strongIndicators"], mine["weakIndicators"], mine["supplyChain"]),
                         (theirs["strongIndicators"], theirs["weakIndicators"], theirs["supplyChain"]))

    def test_a_scan_all_repository_checked_by_rest_is_scan_alls_too(self):
        # (a listing item without a node ID: a REST content check makes it ready, its filter scan-all's)
        self.store.add_github_candidate(950, "u/nonode", None, False, [ghdiscover.ALL_NO_NODE],
                                        "2026-10-14T09:00:00+00:00", "ready", None)
        out = self.run_gh(FakeGitHub(files={"u/nonode": HYGIENE}), scan=True)
        (res,) = out["scans"]
        self.assertEqual((res["verdict"], res["hygieneInfo"]), ("OK", LISTED))


class WhatIsListedTests(unittest.TestCase):
    def issue(self, rule, sev, line=1):
        return {"rule": rule, "sev": sev, "file": ".github/workflows/w.yml", "line": line, "msg": "a finding. "}

    def test_exactly_the_four_rules_below_critical(self):
        self.assertEqual(ghdiscover.SCAN_ALL_HYGIENE_RULES, frozenset(FOUR))
        issues = [self.issue("SC-WORKFLOW-UNPINNED", "CRITICAL"), self.issue("SC-WORKFLOW-PIPE-SHELL", "MAJOR"),
                  self.issue("SC-WORKFLOW-SECRETS", "MAJOR"), self.issue("SC-WORKFLOW-PR-CHECKOUT", "CRITICAL"),
                  self.issue("SC-GITLAB-IMAGE", "MAJOR"), self.issue("SC-AGENT-CONFIG", "MAJOR"),
                  self.issue("SC-WORKFLOW-CACHE", "INFO"), self.issue("SC-WORKFLOW-PERMISSIONS", "MINOR", 2),
                  self.issue("SC-WORKFLOW-OIDC-INSTALL", "MAJOR", 3)]
        before = [dict(i) for i in issues]
        self.assertEqual(ghdiscover._hygiene_listed(issues),
                         {"SC-WORKFLOW-OIDC-INSTALL": 1, "SC-WORKFLOW-PERMISSIONS": 1})
        self.assertEqual([(i["rule"], i["sev"]) for i in issues],
                         [("SC-WORKFLOW-UNPINNED", "CRITICAL"), ("SC-WORKFLOW-PR-CHECKOUT", "CRITICAL"),
                          ("SC-WORKFLOW-PIPE-SHELL", "MAJOR"), ("SC-WORKFLOW-SECRETS", "MAJOR"),
                          ("SC-GITLAB-IMAGE", "MAJOR"), ("SC-AGENT-CONFIG", "MAJOR"), ("SC-WORKFLOW-CACHE", "INFO"),
                          ("SC-WORKFLOW-PERMISSIONS", "INFO"), ("SC-WORKFLOW-OIDC-INSTALL", "INFO")])
        self.assertEqual([i["msg"] for i in issues if i["sev"] == "INFO"],
                         ["a finding. ", "a finding. (scan-all: the owner's workflow configuration, MINOR in a project "
                          "scan: listed, not counted)", "a finding. (scan-all: the owner's workflow configuration, "
                          "MAJOR in a project scan: listed, not counted)"])
        untouched = [i for i in issues if i["rule"] not in ("SC-WORKFLOW-PERMISSIONS", "SC-WORKFLOW-OIDC-INSTALL")]
        self.assertEqual(sorted(map(str, untouched)), sorted(str(i) for i in before
                                                             if i["rule"] not in ("SC-WORKFLOW-PERMISSIONS",
                                                                                  "SC-WORKFLOW-OIDC-INSTALL")))
        self.assertEqual(ghdiscover._hygiene_listed([self.issue("SC-WORKFLOW-SECRETS", "MAJOR")]), {})

    def test_no_verdict_changes(self):
        # the four are CI hardening checks, which the registry's GitHub verdict counts only at CRITICAL: made INFO
        # below it, they set no verdict they set before
        self.assertLessEqual(ghdiscover.SCAN_ALL_HYGIENE_RULES, core.HARDENING_RULES)
        for rule in ("SC-WORKFLOW-PR-CHECKOUT", "SC-WORKFLOW-SECRETS", "SC-WORKFLOW-PIPE-SHELL",
                     "SC-WORKFLOW-BACKDOOR", "SC-WORKFLOW-EXFIL"):
            self.assertNotIn(rule, ghdiscover.SCAN_ALL_HYGIENE_RULES)


class CommandLineTests(ScanAllCase):
    def cli(self, *argv, gh, archive=None):
        out, err = io.StringIO(), io.StringIO()

        def both(url, *a, **kw):
            return (archive if archive is not None and "gharchive" in url else gh)(url, *a, **kw)
        with mock.patch.object(sys, "argv", ["lazaret-registry", *argv, "--db", self.db]), \
                mock.patch.dict(os.environ, ENV), mock.patch.object(ghdiscover.sources, "_http", both), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def run_cli(self, files):
        self.store.save_discovery_cursor("github", 1001, datetime.datetime.now(UTC))
        self.store.save_discovery_cursor("github-scan-all", 1000)
        archive = FakeArchive({ghevents.hour_name(datetime.datetime.now(UTC) - datetime.timedelta(hours=1)):
                               [push(1001, "u1/tool")]})
        return self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all", "--ci",
                        gh=FakeGitHub([], files={"u1/tool": files}), archive=archive)

    def test_hygiene_alone_passes_ci_in_one_line_that_says_so(self):
        code, out, _err = self.run_cli(HYGIENE)
        self.assertEqual(code, 0, out)
        self.assertRegex(out, r"  .* OK .* github:u1/tool@0123456789ab  3 files, [^\n]*; 6 workflow hygiene findings "
                              r"listed as INFO, as the owner's configuration\n")
        self.assertEqual(self.candidates()["u1/tool"]["verdict"], "OK")
        code, out, _err = self.cli("list", gh=FakeGitHub())
        self.assertIn("Every new repository (--github-scan-all): scanned 1\n", out)
        self.assertNotIn("scanned   github:u1/tool", out)              # (`list` names the scans not OK)
        self.assertRegex(out, r"github:u1/tool +\S+ +0123456789abcdef\w+ OK ")

    def test_a_suspicious_one_fails_ci_and_its_report_says_what_was_listed(self):
        code, out, _err = self.run_cli({**HYGIENE, **PR_CHECKOUT})
        self.assertEqual(code, 1, out)
        self.assertIn("SUSPICIOUS", out)
        self.assertIn("1 strong supply-chain indicator; " + SAID.replace("6 workflow", "7 workflow")
                      .replace("UNPINNED 3", "UNPINNED 4"), out)
        self.assertIn("[SC-WORKFLOW-PR-CHECKOUT]", out)
        self.assertIn("INFO     [SC-WORKFLOW-UNPINNED]", out)
        code, out, _err = self.cli("list", gh=FakeGitHub())
        self.assertRegex(out, r"scanned   github:u1/tool\s+SUSPICIOUS")


class ElsewhereTests(Dir):
    """The same repository through `lazaret-registry scan github:` and `lazaret scan github:`: graded as before."""

    def test_the_registrys_scan_of_a_repository(self):
        db = os.path.join(self.tmp, "state.db")
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["lazaret-registry", "scan", "github:some/repo", "--ci", "--db", db]), \
                mock.patch.object(ghdiscover.sources, "_http", FakeGitHub(files={"some/repo": HYGIENE})), \
                mock.patch.dict(os.environ, ENV), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        self.assertEqual(code, 0, out.getvalue())
        store = repo.Store(db)
        self.addCleanup(store.close)
        rep = store.report("github", "some/repo")
        self.assertEqual((rep["version"], rep["verdict"]), (SHA, "OK"))
        self.assertEqual(graded(rep["issues"]), sorted(GRADES))
        self.assertNotIn("scan-all:", out.getvalue())

    @unittest.skipUnless(engine.available(), "the scan needs the native engine")
    def test_lazaret_scan_github(self):
        net = Net(gh_answers(files={p: t.encode() for p, t in HYGIENE.items()}))
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sourcescan.main(["github:o/r@v1", "--ci", "-q", "--json", "r.json", "--no-html"], env={}, http=net)
        self.assertEqual(code, 0, out.getvalue() + err.getvalue())        # the gate counts them only at CRITICAL
        with open("r.json", encoding="utf-8") as f:
            report = json.load(f)
        self.assertEqual(graded(report["issues"]), sorted(GRADES))
        self.assertFalse(any("scan-all:" in i["msg"] for i in report["issues"]))
        self.assertEqual(report["supplyChain"], 0)


if __name__ == "__main__":
    unittest.main()
