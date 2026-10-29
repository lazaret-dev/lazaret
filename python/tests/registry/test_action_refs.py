"""An action's commit outside its repository's branches, and a moved tag (0.1.9, RA-4): registry/actionrefs.py and
its use by the action scan (registry/actions.py).

The May 2026 shape: every tag of actions-cool/issues-helper was moved to an imposter commit put in through an
attacker's fork (GitHub serves a fork's commit under the parent's name). The checks run against the in-memory GitHub
of the action scan's tests (`_actions_support.FakeGitHub`, the network seam of sources.Client: repositories with a
commit graph, branches, tags and commits that exist only in a fork; GitHub's compare API answered from the graph);
nothing is fetched. Covered: a fork's commit, pinned or tagged, is CRITICAL (compare `diverged` or 404 for every
branch); a release branch's commit and the default branch's are not; the compare budget (a repository with many
branches stops at it, and the check is incomplete, not CRITICAL), the call budget, the rate limit, an API error,
offline and no token; the answers kept per (repository, commit); a moved tag MAJOR, CRITICAL when it moved to a fork's
commit, in the pin book and in the registry's database (SQLite, and Postgres's wire statements); the switch
LAZARET_NO_ACTION_BRANCHES; the command's --db. And a pin that names an annotated tag's object (the RA-4 follow-up,
vercel/next.js's `actions/github-script@d746ffe…`): its commit checked in its place, nested objects, an impostor's tag
object, the question asked only where the default branch does not hold the pin, a failing or refused question
incomplete, and the comment compared with the object's name. And a commit no branch holds that only one of the
repository's own version tags holds (FP-IMPOSTOR-TAG, mmastrac/mmm-matrix@3edd85c…, the tag v1.0.5): MAJOR the first
time the tag is seen at it and recorded, a note once the pin book held it there before the run, CRITICAL as before
when no exact version tag holds it, when the tag was seen elsewhere, or when the tags could not all be read.
"""

import io
import json
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from lazaret.registry import actionrefs, actions, repo, sources
from lazaret.registry.sources import SourceError
from tests.registry import _actions_support as fx
from tests.registry.test_actions import api_calls, release_repo, workflow
from tests.registry.test_review_store_reconnect import FakeConn, pg_store

TOKEN = "ghp_NotARealTokenJustTestText1234567890"


def compares(gh):
    return [u for u in gh.calls if "/compare/" in u]


def tag_lists(gh):
    """The calls listing a repository's tags (FP-IMPOSTOR-TAG), one a page."""
    return [u for u in gh.calls if "/tags?" in u]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-action-refs-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.book_path = os.path.join(self.tmp, "pins.json")

    def auditor(self, *repos, limit=None, env=None, pins=None, **kw):
        self.gh = fx.FakeGitHub(*repos, limit=limit)
        return actions.Auditor(env={} if env is None else env, http=self.gh, pins=pins, **kw)

    def audit(self, text, *repos, **kw):
        self.aud = self.auditor(*repos, **kw)
        return self.aud.audit(actions.uses_of(text))

    @staticmethod
    def rules(rep):
        return [(actions.rule(f.kind, f.detail)["id"], actions.rule(f.kind, f.detail)["sev"]) for f in rep.findings]


class ForkCommitTests(Base):
    def test_a_forks_commit_diverged_from_every_branch_is_critical(self):
        r = release_repo()
        evil = r.commit(r.shas[0], fork=True, files={"action.yml": fx.action_yml()})     # off an old commit
        rep = self.audit(workflow(f"o/act@{evil}"), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        msg = actions.rule("impostor", rep.findings[0].detail)["msg"]
        self.assertEqual(msg, f"o/act@{evil}: the commit is not in o/act's branches: a commit from a fork, reached "
                              f"through the repository's name (each of its 2 branches was compared).")
        # every branch compared (diverged each time), then the commit itself looked up before it is called one
        self.assertEqual([u.split("/compare/")[1].split("...")[0] for u in compares(self.gh)], ["main", "releases/v1"])
        self.assertIn(f"{fx.API}/repos/o/act/commits/{evil}", self.gh.calls)
        self.assertEqual(rep.branches, {})
        self.assertTrue(rep.complete)

    def test_an_orphan_forks_commit_is_critical_when_every_compare_is_a_404(self):
        r = release_repo()
        evil = r.commit(fork=True, files={"action.yml": fx.action_yml()})                 # no common history
        rep = self.audit(workflow(f"o/act@{evil}"), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual(len(compares(self.gh)), 2)

    def test_every_tag_moved_to_a_forks_commit(self):
        # the actions-cool shape: the floating tag and the release tags all moved onto the imposter (FP-IMPOSTOR-TAG:
        # two or more version tags at one commit no branch holds stay CRITICAL, on a first sighting too)
        r = release_repo(tags=("v2", "v2.0.0", "v2.1.0"))
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        r.tag("v2", evil)
        r.tag("v2.0.0", evil)
        r.tag("v2.1.0", evil, annotated=True)
        rep = self.audit(workflow("o/act@v2", "o/act@v2.1.0", f"o/act@{r.shas[1]}"), r)
        self.assertEqual([(f.uses, f.kind) for f in rep.findings], [("o/act@v2", "impostor"),
                                                                      ("o/act@v2.1.0", "impostor")])
        self.assertEqual({actions.rule(f.kind, f.detail)["sev"] for f in rep.findings}, {"CRITICAL"})
        self.assertIn(f"o/act@v2.1.0 points to the commit {evil}: the commit is not in o/act's branches",
                      actions.rule("impostor", rep.findings[1].detail)["msg"])
        self.assertEqual(rep.branches, {f"o/act@{r.shas[1]}": "main"})     # the pin of the real history is clean
        # one branch check of the imposter for both tags (kept per repository and commit)
        self.assertEqual(len([u for u in compares(self.gh) if u.endswith(f"...{evil}?per_page=1")]), 2)
        # the version tags found are named (the annotated and the lightweight one), from one tag listing
        self.assertEqual([(f.detail["version_tags"], f.detail["version_tag_count"]) for f in rep.findings],
                         [(["v2.0.0", "v2.1.0"], 2)] * 2)
        self.assertIn(("o/act@v2", f"2 version tags of o/act point to {evil[:12]}, v2.0.0, v2.1.0: the shape of tags "
                                   f"moved onto one commit, not a release commit kept by its tag: {STANDS}"),
                      rep.notes)
        self.assertEqual(len(tag_lists(self.gh)), 1)

    def test_a_release_branchs_commit_is_not_an_imposter(self):
        r = release_repo()
        backport = r.commit(r.shas[1], files={"action.yml": fx.action_yml()})
        r.commit(backport, branch="release/v2")               # backport is behind release/v2's head, not on main
        for i in range(4):
            r.commit(r.shas[0], branch=f"a-topic-{i}")         # sorts before release/v2 by name
        r.tag("v2.0.1", backport)
        rep = self.audit(workflow(f"o/act@{backport}", "o/act@v2.0.1"), r)
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.branches, {f"o/act@{backport}": "release/v2", "o/act@v2.0.1": "release/v2"})
        self.assertEqual([u.split("/compare/")[1].split("...")[0] for u in compares(self.gh)], ["main", "release/v2"])
        self.assertFalse([u for u in self.gh.calls if "/commits/" in u])       # (looked up only before a finding)
        self.assertTrue(rep.complete)

    def test_a_commit_of_the_default_branch_costs_two_calls(self):
        r = release_repo()
        aud = self.auditor(r)
        answer = aud.branches.check("o", "act", r.shas[0])
        self.assertEqual((answer.state, answer.where, answer.compared), ("in", "main", ["main"]))
        self.assertEqual([u.split("?")[0] for u in api_calls(self.gh)],
                         [f"{fx.API}/repos/o/act", f"{fx.API}/repos/o/act/compare/main...{r.shas[0]}"])

    def test_a_branch_head_needs_no_compare_and_a_branch_ref_no_check(self):
        r = release_repo()
        side = r.commit(r.shas[1], branch="feature")
        aud = self.auditor(r)
        self.assertEqual(aud.branches.check("o", "act", side).where, "feature")
        self.assertEqual(len(compares(self.gh)), 1)            # main only; feature's head is the commit
        rep = self.audit(workflow("o/act@feature"), r)
        self.assertEqual((rep.findings, compares(self.gh)), ([], []))

    def test_a_commit_github_does_not_have_is_a_note(self):
        r = release_repo()
        rep = self.audit(workflow("o/act@" + "0" * 40), r)
        self.assertEqual((rep.findings, rep.incomplete), ([], []))
        self.assertIn("is not a commit of o/act", rep.notes[0][1])


class BudgetTests(Base):
    def many_branches(self, n=20):
        r = release_repo()
        for i in range(n):
            r.commit(r.shas[1], branch=f"topic-{i:02d}")
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        return r, evil

    def test_many_branches_stop_at_the_budget_and_the_check_is_incomplete(self):
        r, evil = self.many_branches()
        rep = self.audit(workflow(f"o/act@{evil}"), r)
        self.assertEqual(rep.findings, [])                     # not CRITICAL
        self.assertEqual(len(compares(self.gh)), actionrefs.MAX_COMPARES)
        self.assertFalse([u for u in self.gh.calls if f"/commits/{evil}" in u])
        # the repository, whether the pin is a tag object (404: main did not hold it), its branches, the compares and
        # action.yml: nothing more for the branch check
        self.assertEqual(len(api_calls(self.gh)), 3 + actionrefs.MAX_COMPARES + 1)
        self.assertIn(f"{fx.API}/repos/o/act/git/tags/{evil}", self.gh.calls)
        self.assertEqual([u for u, _ in rep.incomplete], [f"o/act@{evil}"])
        self.assertIn(f"whether {evil[:12]} is in o/act's branches is not settled: 9 of its 22 branches were compared",
                      rep.incomplete[0][1])
        self.assertFalse(rep.complete)
        self.assertIn("code", rep.actions[f"o/act@{evil}"])  # the action's code is still read

    def test_the_budget_is_a_constant_of_the_helper(self):
        r, evil = self.many_branches(4)
        with mock.patch.object(actionrefs, "MAX_COMPARES", 3):
            rep = self.audit(workflow(f"o/act@{evil}"), r)
        self.assertEqual(len(compares(self.gh)), 3)
        self.assertIn("3 of its 6 branches were compared (3 compares a commit at most), 3 were not",
                      rep.incomplete[0][1])
        rep = self.audit(workflow(f"o/act@{evil}"), r)        # 1 + 5: within the budget, so it is said
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])

    def test_more_branches_than_a_page_lists(self):
        r, evil = self.many_branches(actionrefs.BRANCH_PAGE + 5)
        with mock.patch.object(actionrefs, "MAX_COMPARES", 1000):
            rep = self.audit(workflow(f"o/act@{evil}"), r, max_calls=1000)
        self.assertEqual(rep.findings, [])
        self.assertIn(f"it has more than the {actionrefs.BRANCH_PAGE} branches one page lists", rep.incomplete[0][1])

    def test_a_branch_name_that_cannot_go_in_a_url(self):
        r = release_repo()
        r.branches["odd..name"] = r.shas[0]
        evil = r.commit(r.shas[2], fork=True)
        rep = self.audit(workflow(f"o/act@{evil}"), r)
        self.assertEqual(rep.findings, [])
        self.assertIn("1 branch name(s) cannot be put in a URL", rep.incomplete[0][1])
        self.assertFalse([u for u in self.gh.calls if "odd" in u])

    def test_the_runs_call_budget_spent_in_the_middle_is_incomplete(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        rep = self.audit(workflow(f"o/act@{evil}", "o/act@v1"), r, max_calls=3)
        self.assertEqual(rep.findings, [])
        self.assertEqual(len(api_calls(self.gh)), 3)           # the repository, main, git/tags: then no more
        self.assertEqual([u for u, _ in rep.incomplete], [f"o/act@{evil}", "o/act@v1"])
        self.assertIn("was not checked: the budget of 3 API calls is spent", rep.incomplete[0][1])
        self.assertIn("not checked: the budget of 3 API calls is spent", rep.incomplete[1][1])


class OnlineTests(Base):
    def test_the_rate_limit_in_the_branch_check_is_incomplete_and_a_moved_tag_still_said(self):
        r = release_repo()
        book = actions.PinBook(self.book_path)
        self.audit(workflow("o/act@v1.0.0"), r, pins=book)
        r.tag("v1.0.0", r.shas[2])
        # the second run: the tag (1), the repository (2), then the compare is refused
        rep = self.audit(workflow("o/act@v1.0.0"), r, pins=actions.PinBook(self.book_path), limit=2)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-MOVED", "MAJOR")])
        self.assertEqual(len(rep.incomplete), 1)
        self.assertIn("is in o/act's branches was not checked", rep.incomplete[0][1])
        self.assertIn("rate limit reached", rep.incomplete[0][1])
        self.assertFalse([u for u in self.gh.calls if "/contents/" in u or "codeload" in u])

    def test_an_api_error_in_a_compare_is_incomplete_and_the_code_is_still_read(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        gh = fx.FakeGitHub(r)
        gh.broken["/compare/"] = 502
        rep = actions.Auditor(env={}, http=gh).audit(actions.uses_of(workflow(f"o/act@{evil}")))
        self.assertEqual(rep.findings, [])
        self.assertIn("could not be settled", rep.incomplete[0][1])
        self.assertIn("HTTP 502", rep.incomplete[0][1])
        self.assertEqual(rep.actions[f"o/act@{evil}"]["code"]["verdict"], "OK")

    def test_offline(self):
        def offline(url, headers, max_bytes, hosts, auth_host, **kw):
            raise SourceError(f"{kw.get('what', url)}: network error (timeout)")
        r = release_repo()
        for value in (f"o/act@{r.shas[1]}", "o/act@v1.0.0"):
            rep = actions.Auditor(env={}, http=offline).audit(actions.uses_of(workflow(value)))
            self.assertEqual(rep.findings, [], value)
            self.assertTrue(rep.incomplete, value)
            self.assertTrue(all("network error" in why for _u, why in rep.incomplete), value)

    def test_without_a_token(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True)
        aud = self.auditor(r)
        rep = aud.audit(actions.uses_of(workflow(f"o/act@{evil}")))
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual(aud.max_calls, actions.CALLS_ANONYMOUS)
        self.assertFalse([h for _u, h in self.gh.headers if "Authorization" in h])
        aud = self.auditor(r, env={"GITHUB_TOKEN": TOKEN})
        rep = aud.audit(actions.uses_of(workflow(f"o/act@{evil}")))
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertTrue(all(h.get("Authorization") == f"Bearer {TOKEN}" for u, h in self.gh.headers
                            if u.startswith(fx.API)))

    def test_the_switch_turns_the_check_off_and_says_so(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True)
        rep = self.audit(workflow(f"o/act@{evil}"), r, env={actionrefs.OFF_ENV: "1"})
        self.assertEqual((rep.findings, compares(self.gh)), ([], []))
        self.assertIn("was not checked (LAZARET_NO_ACTION_BRANCHES is set)", rep.notes[-1][1])
        self.assertFalse(actionrefs.enabled({actionrefs.OFF_ENV: "1"}))
        self.assertTrue(actionrefs.enabled({}) and actionrefs.enabled(None))
        # the test suite's own default (tests/__init__.py): an Auditor of the process environment has it off
        self.assertEqual(os.environ.get(actionrefs.OFF_ENV), "1")


class CacheTests(Base):
    def test_one_branch_check_per_repository_and_commit(self):
        r = fx.Repo("o/mono")
        c = r.commit(files={"a/action.yml": fx.action_yml(), "b/action.yml": fx.action_yml()})
        r.commit(c, branch="main")
        r.branches["releases/v1"] = c
        evil = r.commit(c, fork=True, files={"a/action.yml": fx.action_yml(), "b/action.yml": fx.action_yml()})
        r.tag("v1.0.0", evil)
        rep = self.audit(workflow(f"o/mono/a@{evil}", f"o/mono/b@{evil}", "o/mono/a@v1.0.0", f"O/Mono/b@{evil}"), r)
        # (v1.0.0 points to the commit, seen there for the first time: MAJOR, FP-IMPOSTOR-TAG; one tag listing)
        self.assertEqual([f.kind for f in rep.findings], ["tag-only"] * 4)
        self.assertEqual(len(tag_lists(self.gh)), 1)
        self.assertEqual(self.aud.branches.compares, 2)       # main and releases/v1, once for the four
        self.assertEqual(list(self.aud.branches._answers), [("o", "mono", evil)])
        self.assertEqual(len(self.gh.calls), len(set(self.gh.calls)))

    def test_the_helper_keeps_its_answers_and_its_errors(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True)
        gh = fx.FakeGitHub(r)
        asked = []

        def get(path, what, missing=False):
            asked.append(path)
            try:
                return json.loads(gh(fx.API + path, {}, 1 << 20, set(), "api.github.com", what=what))
            except SourceError as exc:
                if missing and exc.status in (404, 422):
                    return None
                raise

        b = actionrefs.Branches(get)
        first = b.check("o", "act", evil)
        n = len(asked)
        self.assertEqual(b.check("O", "ACT", evil.upper()), first)
        self.assertEqual((first.state, len(asked)), ("out", n))
        gh.broken["/compare/"] = 500
        b = actionrefs.Branches(get)
        with self.assertRaises(SourceError):
            b.check("o", "act", r.shas[1])
        n = len(asked)
        with self.assertRaises(SourceError):
            b.check("o", "act", r.shas[1])
        self.assertEqual(len(asked), n)

    def test_a_repository_that_cannot_be_seen_is_raised(self):
        b = actionrefs.Branches(lambda path, what, missing=False: None)
        with self.assertRaises(SourceError) as cm:
            b.check("o", "gone", "1" * 40)
        self.assertEqual(cm.exception.status, 404)
        # in the scan: the action is not checked, and nothing more is asked about it
        rep = self.audit(workflow("o/gone@" + "1" * 40))
        self.assertEqual(self.gh.calls, [f"{fx.API}/repos/o/gone"])
        self.assertEqual((rep.findings, rep.notes, [u for u, _ in rep.incomplete]), ([], [], ["o/gone@" + "1" * 40]))
        self.assertIn("not found", rep.incomplete[0][1])

    def test_branch_rank(self):
        names = ["zeta", "master", "v1", "release/v2", "a-topic", "main", "releases/v3", "2.x"]
        self.assertEqual(sorted(names, key=actionrefs.branch_rank),
                         ["2.x", "release/v2", "releases/v3", "v1", "main", "master", "a-topic", "zeta"])


def tagged_repo(topics=28):
    """The shape of vercel/next.js's `actions/github-script@d746ffe…` (John's run of Oct 18): the release v9.0.0 is an
    annotated tag, the workflow pins its tag object, and the commit it tags (r.shas[1]) is on main. With 28 topic
    branches the repository has 30, more than the compare budget reaches. -> (the repository, the tag object)."""
    r = release_repo(tags=())
    for i in range(topics):
        r.commit(r.shas[1], branch=f"topic-{i:02d}")
    obj = r.tag_object("v9.0.0", r.shas[1])
    r.tag("v9.0.0", obj)
    return r, obj


def tag_calls(gh):
    return [u for u in gh.calls if "/git/tags/" in u]


class TagObjectTests(Base):
    """A pin that names an annotated tag's object, which GitHub Actions runs as the commit it tags (the RA-4
    follow-up)."""

    def test_a_pinned_tag_object_is_its_commit_on_main(self):
        r, obj = tagged_repo()
        c = r.shas[1]
        u, direct = f"o/act@{obj}", f"o/act@{c}"
        rep = self.audit(workflow(u, direct, comments={u: "v9.0.0"}), r)
        self.assertEqual((rep.findings, rep.incomplete), ([], []))
        self.assertEqual(rep.resolved, {u: c, direct: c})
        self.assertEqual(rep.branches, {u: "main", direct: "main"})
        self.assertEqual(rep.tag_objects, {u: {"tag": "v9.0.0", "object": obj, "commit": c}})
        self.assertEqual(rep.notes, [(u, f"pinned to the tag object v9.0.0 ({obj}) of the commit {c}: the runner runs "
                                         f"that commit, and it is the one checked")])
        # the code read is the commit's: its archive accepted (it names the commit), fetched once for both lines
        self.assertEqual((rep.actions[u]["code"]["commit"], rep.actions[u]["code"]["verdict"]), (c, "OK"))
        self.assertEqual([x for x in self.gh.calls if "codeload" in x],
                         [f"https://codeload.github.com/o/act/tar.gz/{c}"])
        # the repository; main and the pin (404: no compare takes a tag object); the tag object; main and its commit;
        # the comment's tag (its object already asked); action.yml. No branch listing, no budget spent
        self.assertEqual([x.split("?")[0] for x in api_calls(self.gh)],
                         [f"{fx.API}/repos/o/act", f"{fx.API}/repos/o/act/compare/main...{obj}",
                          f"{fx.API}/repos/o/act/git/tags/{obj}", f"{fx.API}/repos/o/act/compare/main...{c}",
                          f"{fx.API}/repos/o/act/git/ref/tags/v9.0.0", f"{fx.API}/repos/o/act/contents/action.yml"])
        self.assertEqual(self.aud.api_calls(), 6)                 # each one counted in the run's budget
        self.assertIn(f"{fx.API}/repos/o/act/git/tags/{obj}", rep.calls)          # and in the report's

    def test_nested_tag_objects_are_followed(self):
        r = release_repo(tags=())
        inner = r.tag_object("v2.0.0", r.shas[0])
        outer = r.tag_object("v2.0.0-signed", inner, kind="tag")
        u = f"o/act@{outer}"
        rep = self.audit(workflow(u, u), r)                    # on two lines: said once
        self.assertEqual((rep.findings, rep.incomplete), ([], []))
        self.assertEqual(rep.resolved, {u: r.shas[0]})
        self.assertEqual(rep.tag_objects[u], {"tag": "v2.0.0-signed", "object": outer, "commit": r.shas[0]})
        self.assertEqual(len(rep.notes), 1)
        self.assertIn("through 2 tag objects", rep.notes[0][1])
        self.assertEqual(len(tag_calls(self.gh)), 2)
        # MAX_TAG_DEPTH tag objects in a row and one more, or a tag of a tree: not known, so incomplete, never a pass
        deep = r.shas[0]
        for i in range(actionrefs.MAX_TAG_DEPTH + 1):
            deep = r.tag_object(f"deep-{i}", deep, kind="commit" if i == 0 else "tag")
        tree = r.tag_object("a-tree", "ab" * 20, kind="tree")
        rep = self.audit(workflow(f"o/act@{deep}", f"o/act@{tree}"), r)
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.tag_objects, {})
        whys = dict((x, []) for x, _ in rep.incomplete)
        for x, why in rep.incomplete:
            whys[x].append(why)
        self.assertIn(f"more than {actionrefs.MAX_TAG_DEPTH} tag objects in a row", whys[f"o/act@{deep}"][0])
        self.assertIn("could not be settled", whys[f"o/act@{deep}"][0])
        self.assertIn("it tags a tree, not a commit", whys[f"o/act@{tree}"][0])
        self.assertEqual(len([u for u in tag_calls(self.gh) if deep in u]), 1)
        self.assertEqual(len(tag_calls(self.gh)), actionrefs.MAX_TAG_DEPTH + 1)
        # neither resolves to anything, and neither is said to have no action.yml (a reusable workflow ...)
        self.assertEqual(rep.resolved, {})
        self.assertFalse([n for _u, n in rep.notes if "no action.yml" in n])
        # a nested tag object answered for another SHA than the one asked about: not followed
        inner = r.tag_object("v4.0.0", r.shas[0])
        outer = r.tag_object("v4.0.0-signed", inner, kind="tag")
        answer = fx.FakeGitHub.answer

        def wrong(gh, repo_, rest, query, what):
            if rest == f"/git/tags/{inner}":
                return gh.js({"sha": outer, "tag": "v4.0.0", "object": {"type": "commit", "sha": r.shas[0]}})
            return answer(gh, repo_, rest, query, what)
        with mock.patch.object(fx.FakeGitHub, "answer", wrong):
            rep = self.audit(workflow(f"o/act@{outer}"), r)
        self.assertEqual((rep.findings, rep.resolved, rep.tag_objects), ([], {}, {}))
        self.assertIn(f"unexpected answer for the tag object {inner[:12]} it tags", rep.incomplete[0][1])

    def test_a_tag_object_of_a_commit_on_no_branch_is_an_impostor(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        obj = r.tag_object("v9.0.0", evil)                     # a fork's tag object, reached through the parent's name
        u = f"o/act@{obj}"
        rep = self.audit(workflow(u), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        d = rep.findings[0].detail
        self.assertEqual((d["sha"], d["ref"], d["tag_object"], d["tag"]), (evil, obj, "v9.0.0", False))
        self.assertEqual(actions.rule("impostor", d)["msg"],
                         f"o/act@{obj}, the tag object v9.0.0, points to the commit {evil}: the commit is not in "
                         f"o/act's branches: a commit from a fork, reached through the repository's name (each of its "
                         f"2 branches was compared).")
        self.assertEqual(rep.tag_objects[u]["commit"], evil)
        self.assertTrue(rep.complete)
        # the repository's own tag, which the pin book saw on main, moved onto that object: the same, through the
        # tag's own resolution
        r.tag("v9.0.0", r.shas[1])
        self.assertEqual(self.audit(workflow("o/act@v9.0.0"), r, pins=actions.PinBook(self.book_path)).findings, [])
        r.tag("v9.0.0", obj)
        rep = self.audit(workflow("o/act@v9.0.0"), r, pins=actions.PinBook(self.book_path))
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL"), ("SC-ACTION-TAG-MOVED", "CRITICAL")])
        # FP-IMPOSTOR-TAG: with no pin book the tag is seen there for the first time, and it holds the commit: MAJOR
        rep = self.audit(workflow("o/act@v9.0.0"), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])

    def test_a_commit_is_asked_about_only_when_the_default_branch_does_not_hold_it(self):
        r = release_repo()
        backport = r.commit(r.shas[1], files={"action.yml": fx.action_yml()})
        r.commit(backport, branch="release/v2")
        rep = self.audit(workflow(f"o/act@{r.shas[0]}", f"o/act@{backport}"), r)
        self.assertEqual((rep.findings, rep.incomplete, rep.tag_objects), ([], [], {}))
        self.assertEqual(rep.branches, {f"o/act@{r.shas[0]}": "main", f"o/act@{backport}": "release/v2"})
        # 404 for the backport, before the branches are listed; nothing for the commit main holds
        self.assertEqual(tag_calls(self.gh), [f"{fx.API}/repos/o/act/git/tags/{backport}"])
        self.assertEqual([x.split("/compare/")[1].split("?")[0] for x in self.gh.calls if "/compare/" in x],
                         [f"main...{r.shas[0]}", f"main...{backport}", f"release/v2...{backport}"])
        self.assertEqual(rep.resolved, {f"o/act@{r.shas[0]}": r.shas[0], f"o/act@{backport}": backport})

    def test_a_question_github_does_not_answer_leaves_a_tag_object_incomplete(self):
        for state in ("on main", "a fork's commit"):
            r, obj = tagged_repo(topics=0)
            if state == "a fork's commit":
                obj = r.tag_object("v9.0.1", r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()}))
            aud = self.auditor(r)
            self.gh.broken["/git/tags/"] = 502
            u = f"o/act@{obj}"
            rep = aud.audit(actions.uses_of(workflow(u, comments={u: "v9.0.1"})))
            # checked as a commit: no branch holds it and GitHub shows no such commit, so it is not known: incomplete
            self.assertEqual((rep.findings, rep.tag_objects, rep.resolved), ([], {}, {}), state)
            self.assertEqual([x for x, _ in rep.incomplete], [u], state)
            self.assertIn(f"GitHub does not show {obj[:12]} as a commit of o/act, and whether it is a tag object could "
                          f"not be asked: looking up the tag object {obj[:12]} of o/act: HTTP 502",
                          rep.incomplete[0][1])
            self.assertEqual(len(tag_calls(self.gh)), 1, state)                                 # asked once
        # the branch check off: asked on its own, and said; the code is still read at the pin, which is incomplete
        r, obj = tagged_repo(topics=0)
        aud = self.auditor(r, env={actionrefs.OFF_ENV: "1"})
        self.gh.broken["/git/tags/"] = 502
        rep = aud.audit(actions.uses_of(workflow(f"o/act@{obj}")))
        self.assertEqual((rep.findings, rep.resolved), ([], {}))
        self.assertIn(f"whether {obj[:12]} is a commit or a tag object of o/act could not be settled",
                      rep.incomplete[0][1])
        # the rate limit on it: not checked
        rep = self.audit(workflow(f"o/act@{obj}"), r, limit=2)
        self.assertEqual((rep.findings, rep.resolved), ([], {}))
        self.assertIn("was not checked", rep.incomplete[0][1])
        self.assertIn("rate limit reached", rep.incomplete[0][1])

    def test_a_question_github_does_not_answer_leaves_a_commit_checked_as_before(self):
        # git/tags answering 422 or 5xx for a commit: the check goes on as before the question was asked
        answer = fx.FakeGitHub.answer
        for status in (422, 503):
            def refused(gh, repo_, rest, query, what, status=status):
                if rest.startswith("/git/tags/"):
                    raise fx.fail(status, what)
                return answer(gh, repo_, rest, query, what)
            with mock.patch.object(fx.FakeGitHub, "answer", refused):
                r = release_repo()
                evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
                backport = r.commit(r.shas[1], files={"action.yml": fx.action_yml()})
                r.commit(backport, branch="release/v2")
                rep = self.audit(workflow(f"o/act@{evil}", f"o/act@{backport}"), r)
                # a fork's commit is CRITICAL as before, with a note that the question was not answered
                self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], status)
                self.assertEqual(rep.findings[0].uses, f"o/act@{evil}")
                self.assertTrue(rep.complete, status)
                self.assertEqual([u for u, _ in rep.notes], [f"o/act@{evil}"], status)
                self.assertIn(f"whether {evil[:12]} is a tag object of o/act could not be asked", rep.notes[0][1])
                self.assertIn(f"HTTP {status}", rep.notes[0][1])
                self.assertEqual(rep.branches, {f"o/act@{backport}": "release/v2"})      # a branch holds it: a commit
                self.assertEqual(rep.resolved, {f"o/act@{evil}": evil, f"o/act@{backport}": backport})
                # with too many branches to settle: incomplete, as before
                for i in range(actionrefs.MAX_COMPARES):
                    r.commit(r.shas[1], branch=f"topic-{i:02d}")
                rep = self.audit(workflow(f"o/act@{evil}"), r)
                self.assertEqual(rep.findings, [], status)
                self.assertIn("is not settled: 9 of its", rep.incomplete[0][1])
                self.assertEqual(rep.resolved, {})
        # and a commit GitHub shows as another commit (as it may a tag object it did not say was one): not CRITICAL
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})

        def peeled(gh, repo_, rest, query, what):
            if rest.startswith("/git/tags/"):
                raise fx.fail(500, what)
            if rest == f"/commits/{evil}":
                return gh.js({"sha": r.shas[2], "parents": []})
            return answer(gh, repo_, rest, query, what)
        with mock.patch.object(fx.FakeGitHub, "answer", peeled):
            rep = self.audit(workflow(f"o/act@{evil}"), r)
        self.assertEqual(rep.findings, [])
        self.assertIn(f"GitHub shows it as the commit {r.shas[2][:12]}", rep.incomplete[0][1])

    def test_a_refused_question_leaves_every_later_use_not_checked(self):
        # the branch check off: the budget or the rate limit refuses the first pin's question; the second pin's,
        # in another repository, is not asked, and both say they were not checked
        for kw in ({"max_calls": 0}, {"limit": 0}):
            r1, r2 = release_repo("o/act"), release_repo("p/other")
            u1, u2 = f"o/act@{r1.shas[1]}", f"p/other@{r2.shas[1]}"
            rep = self.audit(workflow(u1, u2), r1, r2, env={actionrefs.OFF_ENV: "1"}, **kw)
            self.assertEqual([u for u, _ in rep.incomplete], [u1, u2], kw)
            self.assertTrue(all(why.startswith("not checked: ") for _u, why in rep.incomplete), kw)
            self.assertEqual((rep.findings, rep.resolved, rep.actions), ([], {}, {}), kw)
            self.assertLessEqual(len(api_calls(self.gh)), 1, kw)

    def test_after_a_stop_a_use_the_run_could_answer_is_still_said_not_checked(self):
        mono = fx.Repo("o/mono")
        c = mono.commit(files={"a/action.yml": fx.action_yml(), "b/action.yml": fx.action_yml()})
        mono.commit(c, branch="main")
        r = release_repo()
        # o/mono/a: the repository, main and a/action.yml (3 calls); o/act's first call is refused, which its branch
        # check says; o/mono/b resolves from what the run has, but its action.yml would be refused: not checked
        a, other, b = f"o/mono/a@{c}", f"o/act@{r.shas[1]}", f"o/mono/b@{c}"
        rep = self.audit(workflow(a, other, b), mono, r, max_calls=3)
        self.assertEqual([u for u, _ in rep.incomplete], [other, b])
        self.assertIn("was not checked: the budget of 3 API calls is spent", rep.incomplete[0][1])
        self.assertEqual(rep.incomplete[1][1], "not checked: the budget of 3 API calls is spent; GITHUB_TOKEN "
                                               "(read-only) raises it")
        self.assertIn("o/mono/a@" + c, rep.actions)
        self.assertNotIn("o/mono/b@" + c, rep.actions)

    def test_the_question_is_a_call_of_the_runs_budget(self):
        r, obj = tagged_repo(topics=0)
        u = f"o/act@{obj}"
        rep = self.audit(workflow(u), r, max_calls=2)          # the repository and main: the question is refused
        self.assertEqual(rep.findings, [])
        self.assertEqual(len(api_calls(self.gh)), 2)
        self.assertEqual(tag_calls(self.gh), [])
        self.assertIn("is in o/act's branches was not checked: the budget of 2 API calls is spent",
                      rep.incomplete[0][1])
        self.assertEqual(len(rep.incomplete), 1)                # said once
        rep = self.audit(workflow(u), r, max_calls=3)          # answered, then main with its commit refused
        self.assertEqual(rep.findings, [])
        self.assertEqual(tag_calls(self.gh), [f"{fx.API}/repos/o/act/git/tags/{obj}"])
        self.assertEqual(len(api_calls(self.gh)), 3)
        self.assertEqual(rep.resolved, {u: r.shas[1]})           # what was learned is kept
        self.assertEqual([x for x, _ in rep.incomplete], [u])
        self.assertIn("the budget of 3 API calls is spent", rep.incomplete[0][1])

    def test_the_comment_is_compared_with_the_tag_objects_name(self):
        r, obj = tagged_repo(topics=0)
        c = r.shas[1]
        u = f"o/act@{obj}"
        rep = self.audit(workflow(u, comments={u: "v9.0.0"}), r, pins=actions.PinBook(self.book_path))
        self.assertEqual((rep.findings, rep.incomplete), ([], []))
        # the pin book records the tag at its commit, not at its object: the tag itself is then not called moved
        self.assertEqual(actions.PinBook(self.book_path).entries["o/act@v9.0.0"]["sha"], c)
        self.assertEqual(self.audit(workflow("o/act@v9.0.0"), r, pins=actions.PinBook(self.book_path)).findings, [])
        # the tag object of another name: the mismatch
        other = r.tag_object("v8.0.0", c)
        u = f"o/act@{other}"
        rep = self.audit(workflow(u, comments={u: "v9.0.0"}), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-PIN-MISMATCH", "MAJOR")])
        d = rep.findings[0].detail
        self.assertEqual((d["tag"], d["tag_sha"], d["pin"], d["pin_tag"], d["pin_commit"]), ("v9.0.0", c, other,
                                                                                             "v8.0.0", c))
        self.assertEqual(actions.rule("pin-mismatch", d)["msg"],
                         f"o/act is pinned to the tag object v8.0.0 ({other[:12]}, of the commit {c[:12]}) with the "
                         f"comment v9.0.0, but the tag object's name is v8.0.0, and v9.0.0 points to {c[:12]}.")
        # a tag object of the comment's name whose tag is at another commit now
        stray = r.tag_object("v9.0.0", r.shas[0])
        u = f"o/act@{stray}"
        rep = self.audit(workflow(u, comments={u: "v9.0.0"}), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-PIN-MISMATCH", "MAJOR")])
        self.assertEqual(actions.rule("pin-mismatch", rep.findings[0].detail)["msg"],
                         f"o/act is pinned to the tag object v9.0.0 ({stray[:12]}, of the commit {r.shas[0][:12]}) "
                         f"with the comment v9.0.0, but v9.0.0 points to {c[:12]}.")

    def test_a_mismatch_is_said_of_a_commit_and_not_of_a_pin_not_known(self):
        r = release_repo()
        u = f"o/act@{r.shas[0]}"                                # on main: a commit, asked nothing
        rep = self.audit(workflow(u, comments={u: "v1.0.0"}), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-PIN-MISMATCH", "MAJOR")])
        self.assertNotIn("pin_tag", rep.findings[0].detail)
        self.assertEqual(tag_calls(self.gh), [])
        u = f"o/act@{r.shas[1]}"
        self.assertEqual(self.audit(workflow(u, comments={u: "v1.0.0"}), r).findings, [])
        self.assertEqual(tag_calls(self.gh), [])
        # the branch check off and the question failing: no mismatch is said, the use is incomplete
        aud = self.auditor(r, env={actionrefs.OFF_ENV: "1"})
        self.gh.broken["/git/tags/"] = 502
        u = f"o/act@{r.shas[0]}"
        rep = aud.audit(actions.uses_of(workflow(u, comments={u: "v1.0.0"})))
        self.assertEqual(rep.findings, [])
        self.assertEqual([x for x, _ in rep.incomplete], [u])
        self.assertIn(f"whether {r.shas[0][:12]} is a commit or a tag object of o/act could not be settled",
                      rep.incomplete[0][1])

    def test_with_the_branch_check_off_the_pin_is_still_its_commit(self):
        r, obj = tagged_repo(topics=0)
        u = f"o/act@{obj}"
        rep = self.audit(workflow(u), r, env={actionrefs.OFF_ENV: "1"})
        self.assertEqual((rep.findings, rep.incomplete, compares(self.gh)), ([], [], []))
        self.assertEqual(rep.resolved, {u: r.shas[1]})
        self.assertEqual(rep.actions[u]["code"]["commit"], r.shas[1])
        self.assertEqual(tag_calls(self.gh), [f"{fx.API}/repos/o/act/git/tags/{obj}"])

    def test_the_helper_answers_none_for_a_commit_and_keeps_its_answers(self):
        r, obj = tagged_repo(topics=0)
        aud = self.auditor(r)
        self.assertIsNone(aud.branches.tag_object("o", "act", r.shas[1]))
        got = aud.branches.tag_object("O", "Act", obj.upper())
        self.assertEqual(got, actionrefs.TagObject(obj, "v9.0.0", r.shas[1], 1))
        self.assertEqual(aud.branches.tag_object("o", "act", obj), got)
        self.assertEqual(len(tag_calls(self.gh)), 2)
        answer = aud.branches.check("o", "act", obj, pinned=True)
        self.assertEqual((answer.state, answer.where, answer.tag_object), ("in", "main", got))
        self.assertEqual(aud.branches.check("o", "act", r.shas[1]).tag_object, None)
        self.assertEqual(len(tag_calls(self.gh)), 2)


T1 = 1_792_000_000          # fixed clocks (2026-10-14): each later run an hour on
T2 = T1 + 3600
T3 = T2 + 3600
T4 = T3 + 3600
T5 = T4 + 3600
MMM_BRANCHES = ["main", "build-fix", "cli", "index", "types"]
YML = {"action.yml": fx.action_yml()}


def mmm_repo(annotated=False):
    """The shape of mmastrac/mmm-matrix@3edd85c… (John's run of Oct 18 over vercel/next.js's workflows): a release
    commit tagged v1.0.5 (a lightweight tag) and merged into none of the repository's 5 branches (main, build-fix,
    cli, index, types); its other tags (v1.0.0 … v1.2.0, the floating v1) at commits of main. -> (the repository, the
    release commit)."""
    r = fx.Repo("o/mmm")
    c1 = r.commit(files=YML)
    c2 = r.commit(c1, files=YML)
    c3 = r.commit(c2, branch="main", files=YML)
    for name in MMM_BRANCHES[1:]:
        r.commit(c1, branch=name)
    rel = r.commit(c2, files=YML)                       # tagged, never merged
    for tag, c in (("v1.0.0", c1), ("v1.0.4", c2), ("v1.1.0", c3), ("v1.2.0", c3), ("v1", c3)):
        r.tag(tag, c)
    r.tag("v1.0.5", rel, annotated=annotated)
    r.shas = (c1, c2, c3)
    return r, rel


def held_note(rel, first, branches=5):
    return (f"only the tag v1.0.5 of o/mmm holds {rel[:12]}, none of its {branches} branches: a release commit kept "
            f"by its tag, seen at it since {actionrefs.iso(first)}")


STANDS = "the commit is reported as in none of the branches"


def mark(sha, t):
    """SC-ACTION-TAG-ONLY's mark on a record (FP-IMPOSTOR-TAG): the commit it was given at, and when."""
    return {"sha": sha, "at": actionrefs.iso(t) if isinstance(t, (int, float)) else t}


class TagOnlyTests(Base):
    """A commit no branch holds that one of the repository's own exact version tags points to (FP-IMPOSTOR-TAG)."""

    def book(self):
        return actions.PinBook(self.book_path)

    def books(self):
        """The two kinds of pin book, each a maker of a new one over the same records: the file, the database."""
        path = os.path.join(self.tmp, "registry.db")

        def store_book():
            store = repo.Store(path)
            self.addCleanup(store.close)
            return actionrefs.StoreBook(store)
        return (("file", self.book), ("db", store_book))

    def test_a_release_commit_only_its_tag_holds(self):
        # the mmm-matrix shape: a SHA pin, 5 branches none holding it, the commits endpoint shows it, git/tags is 404
        # (a commit, not a tag object), and the tags list v1.0.5 at it
        for kind, book in self.books():
            r, rel = mmm_repo()
            u = f"o/mmm@{rel}"
            rep = self.audit(workflow(u), r, pins=book(), now=lambda: T1)
            self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")], kind)
            d = rep.findings[0].detail
            self.assertEqual(d, {"sha": rel, "ref": rel, "tag": "v1.0.5", "branches": 5, "compared": MMM_BRANCHES,
                                 "recorded": True, "owner": "o", "repo": "mmm", "via": []}, kind)
            rule = actions.rule("tag-only", d)
            self.assertEqual(rule["msg"], f"o/mmm@{rel}: the commit is in none of o/mmm's branches (each of its 5 "
                                          f"branches was compared: main, build-fix, cli, index, types), but the "
                                          f"repository's own version tag v1.0.5, and no other, points to it: as far "
                                          f"as the tags show, a release commit tagged and never merged, so it is not "
                                          f"known to be a fork's; but a tag can be moved by whoever can push to the "
                                          f"repository. A later run with the pin book says whether the tag stayed at "
                                          f"it.")
            self.assertNotIn("not a commit from a fork", rule["msg"] + rule["why"])
            self.assertEqual((rule["name"], rule["type"]), ("Action's commit is held only by a tag, not a branch",
                                                            "HOTSPOT"))
            self.assertIn("a tag can be moved by whoever can push to the repository", rule["why"])
            # a pin is kept if it is the release meant; it is not told to pin what it pins
            self.assertTrue(rule["fix"].startswith("Read the action's code at this commit before the workflow runs "
                                                   "it; keep the pin if it is the release you meant."))
            self.assertNotIn("pin that commit by its SHA", rule["fix"])
            self.assertIn("a later run says whether it stayed", rule["fix"])
            self.assertTrue(rep.complete, kind)
            self.assertEqual((rep.notes, rep.resolved, rep.branches), ([], {u: rel}, {}), kind)
            # asked: the commit itself (before it is called anything), git/tags (404), and, every branch compared,
            # one listing of the tags
            calls = [x.split("?")[0] for x in api_calls(self.gh)]
            self.assertLess(calls.index(f"{fx.API}/repos/o/mmm/commits/{rel}"),
                            calls.index(f"{fx.API}/repos/o/mmm/tags"))
            self.assertEqual(tag_calls(self.gh), [f"{fx.API}/repos/o/mmm/git/tags/{rel}"])
            self.assertEqual(tag_lists(self.gh), [f"{fx.API}/repos/o/mmm/tags?per_page=100"])
            self.assertEqual(len(compares(self.gh)), 5)
            self.assertIn(f"{fx.API}/repos/o/mmm/tags", rep.calls)
            self.assertEqual(rep.actions[u]["code"]["commit"], rel)             # the action's code is still read
            # recorded in the pin book at the commit, with SC-ACTION-TAG-ONLY's mark
            self.assertEqual(book().record("o/mmm@v1.0.5"),
                             {"sha": rel, "first": actionrefs.iso(T1), "last": actionrefs.iso(T1),
                              "tag_only": mark(rel, T1)}, kind)
            # a second run (a new Auditor, the same pin book, an hour later): a note, no finding, complete
            rep = self.audit(workflow(u), r, pins=book(), now=lambda: T2)
            self.assertEqual((rep.findings, rep.incomplete), ([], []), kind)
            self.assertTrue(rep.complete, kind)
            self.assertEqual(rep.notes, [(u, held_note(rel, T1))], kind)
            self.assertEqual(len(tag_lists(self.gh)), 1, kind)
            self.assertEqual(book().record("o/mmm@v1.0.5")["last"], actionrefs.iso(T2), kind)
            self.assertEqual(json.loads(json.dumps(rep.to_json()))["notes"], [[u, held_note(rel, T1)]], kind)

    def test_a_tag_the_pin_book_saw_at_another_commit_stays_critical(self):
        r, rel = mmm_repo()
        u = f"o/mmm@{rel}"
        r.tag("v1.0.5", r.shas[1])                       # seen first at a commit of main
        self.assertEqual(self.audit(workflow("o/mmm@v1.0.5"), r, pins=self.book(), now=lambda: T1).findings, [])
        r.tag("v1.0.5", rel)
        for now in (T2, T3):                              # and on each later run: nothing demoted
            rep = self.audit(workflow(u), r, pins=self.book(), now=lambda t=now: t)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], now)
            self.assertEqual(rep.notes, [(u, f"the version tag v1.0.5 of o/mmm points to {rel[:12]}, but the pin book "
                                             f"first saw it at {r.shas[1][:12]} ({actionrefs.iso(T1)}): it moved: "
                                             f"{STANDS}")], now)
            self.assertTrue(rep.complete, now)
        # the record keeps the commit it was first seen at, and says where the tag went
        entry = self.book().entries["o/mmm@v1.0.5"]
        self.assertEqual((entry["sha"], entry["first"], entry["moved"]["to"]), (r.shas[1], actionrefs.iso(T1), rel))
        # the use named by the tag: the move, CRITICAL as before, and no listing asked (nothing it could change)
        rep = self.audit(workflow("o/mmm@v1.0.5"), r, pins=self.book(), now=lambda: T3)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL"), ("SC-ACTION-TAG-MOVED", "CRITICAL")])
        self.assertEqual(tag_lists(self.gh), [])

    def test_a_move_not_accepted_stays_critical_and_is_kept(self):
        r, rel = mmm_repo()
        u = f"o/mmm@{rel}"
        at = actionrefs.iso(T1 + 60)
        flagged = {"sha": rel, "first": actionrefs.iso(T1), "last": at, "moved": {"to": r.shas[2], "at": at}}
        with open(self.book_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "tags": {"o/mmm@v1.0.5": flagged}}, f)
        why = f"the pin book saw it at {r.shas[2][:12]} since ({at}), a move not accepted"
        for now in (T2, T3):
            rep = self.audit(workflow(u), r, pins=self.book(), now=lambda t=now: t)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], now)
            self.assertEqual(rep.notes, [(u, f"the version tag v1.0.5 of o/mmm points to {rel[:12]}, but {why}: "
                                             f"{STANDS}")], now)
        self.assertEqual(self.book().entries["o/mmm@v1.0.5"]["moved"]["to"], r.shas[2])     # not cleared
        # with the use named by the tag after it, whose own sighting at its first commit clears the move (as before):
        # neither is demoted, the record as it was before the run is what counts
        rep = self.audit(workflow(u, "o/mmm@v1.0.5"), r, pins=self.book(), now=lambda: T3)
        self.assertEqual([(f.uses, actions.rule(f.kind, f.detail)["sev"]) for f in rep.findings],
                         [(u, "CRITICAL"), ("o/mmm@v1.0.5", "CRITICAL")])
        self.assertEqual([x for x, n in rep.notes if why in n], [u, "o/mmm@v1.0.5"])

    def test_accept_moved_never_lowers_a_commit_a_tag_was_moved_onto(self):
        # v1.0.5 seen on main, then moved onto a fork's commit; one run accepts the move; the runs after it (in the
        # pin book file and in the database alike)
        for kind, book in self.books():
            r, rel = mmm_repo()
            r.tag("v1.0.5", r.shas[1])
            self.assertEqual(self.audit(workflow("o/mmm@v1.0.5"), r, pins=book(), now=lambda: T1).findings, [], kind)
            evil = r.commit(r.shas[2], fork=True, files=YML)
            r.tag("v1.0.5", evil)
            u = f"o/mmm@{evil}"
            text = workflow("o/mmm@v1.0.5", u)
            rep = self.audit(text, r, pins=book(), now=lambda: T2)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL"), ("SC-ACTION-TAG-MOVED", "CRITICAL"),
                                               ("SC-ACTION-IMPOSTOR", "CRITICAL")], kind)
            # the run that accepts the move: SC-ACTION-TAG-MOVED is silenced, SC-ACTION-IMPOSTOR is not ...
            rep = self.audit(text, r, pins=book(), now=lambda: T3, accept_moved=True)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")] * 2, kind)
            # ... the record is at the commit accepted and keeps the one the tag moved from ...
            self.assertEqual(book().record("o/mmm@v1.0.5"),
                             {"sha": evil, "first": actionrefs.iso(T3), "last": actionrefs.iso(T3),
                              "moved_from": {"sha": r.shas[1], "at": actionrefs.iso(T3)}}, kind)
            # ... and each later run says the commit is one a tag was moved onto, never a release kept by its tag
            onto = (f"the version tag v1.0.5 of o/mmm points to {evil[:12]}, but it was moved onto it (from "
                    f"{r.shas[1][:12]}, accepted {actionrefs.iso(T3)}): accepting a move does not make it a release "
                    f"commit kept by its tag: {STANDS}")
            for now in (T4, T5):
                rep = self.audit(text, r, pins=book(), now=lambda t=now: t)
                self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")] * 2, (kind, now))
                self.assertEqual(rep.notes, [("o/mmm@v1.0.5", onto), (u, onto)], (kind, now))
            self.assertEqual(book().record("o/mmm@v1.0.5")["moved_from"]["sha"], r.shas[1], kind)   # kept by sightings
        # the same for a move onto a commit of the repository's own that no branch holds
        r, rel = mmm_repo()
        r.tag("v1.0.5", r.shas[1])
        self.audit(workflow("o/mmm@v1.0.5"), r, pins=actions.PinBook(self.book_path + "2"), now=lambda: T1)
        r.tag("v1.0.5", rel)
        self.audit(workflow(f"o/mmm@{rel}"), r, pins=actions.PinBook(self.book_path + "2"), now=lambda: T2,
                   accept_moved=True)
        rep = self.audit(workflow(f"o/mmm@{rel}"), r, pins=actions.PinBook(self.book_path + "2"), now=lambda: T3)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertIn("but it was moved onto it (from", rep.notes[0][1])
        # and it never lowers a commit no version tag holds
        evil = r.commit(r.shas[2], fork=True, files=YML)
        rep = self.audit(workflow(f"o/mmm@{evil}"), r, pins=self.book(), now=lambda: T3, accept_moved=True)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])

    def test_an_accepting_run_that_names_the_tag(self):
        # the use named by the tag accepts the move before the pin's check: the record as it was before the command
        # is the one read (it moved), not the one the accept just wrote
        for pin in (False, True):
            book = os.path.join(self.tmp, f"accept-{pin}.json")
            r, rel = mmm_repo()
            r.tag("v1.0.5", r.shas[1])
            self.audit(workflow("o/mmm@v1.0.5"), r, pins=actions.PinBook(book), now=lambda: T1)
            r.tag("v1.0.5", rel)
            uses = ("o/mmm@v1.0.5", f"o/mmm@{rel}") if pin else ("o/mmm@v1.0.5",)
            rep = self.audit(workflow(*uses), r, pins=actions.PinBook(book), now=lambda: T2, accept_moved=True)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")] * len(uses), uses)
            moved = (f"the version tag v1.0.5 of o/mmm points to {rel[:12]}, but the pin book first saw it at "
                     f"{r.shas[1][:12]} ({actionrefs.iso(T1)}): it moved: {STANDS}")
            self.assertEqual(rep.notes, [(u, moved) for u in uses], uses)
            rep = self.audit(workflow(*uses), r, pins=actions.PinBook(book), now=lambda: T3)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")] * len(uses), uses)
            self.assertTrue(all("but it was moved onto it (from" in n for _u, n in rep.notes), uses)

    def test_only_a_floating_tag_or_another_name_at_the_commit_is_critical(self):
        r, rel = mmm_repo()
        del r.tags["v1.0.5"]
        u = f"o/mmm@{rel}"
        for name in ("v1", "latest", "v1.0", "nightly", "release-1.0.5", "V1.0.5"):
            r.tag(name, rel)
            rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T1)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], name)
            self.assertEqual((rep.notes, rep.incomplete), ([], []), name)          # exactly as before
            self.assertEqual(len(tag_lists(self.gh)), 1, name)
        self.assertEqual(self.book().entries, {})                                   # nothing recorded

    def test_two_version_tags_at_one_commit_stay_critical(self):
        # the shape of tags moved onto one commit (actions-cool), not a release commit kept by its tag: a lightweight
        # and an annotated version tag both count
        r, rel = mmm_repo()
        r.tag("v1.0.6", rel, annotated=True)
        u = f"o/mmm@{rel}"
        note = (f"2 version tags of o/mmm point to {rel[:12]}, v1.0.5, v1.0.6: the shape of tags moved onto one "
                f"commit, not a release commit kept by its tag: {STANDS}")
        for pins in (self.book(), None):                 # first sighting, and no pin book
            rep = self.audit(workflow(u), r, pins=pins, now=lambda: T1)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], pins)
            d = rep.findings[0].detail
            self.assertEqual((d["version_tags"], d["version_tag_count"], d["tag"]), (["v1.0.5", "v1.0.6"], 2, False))
            self.assertTrue(actions.rule("impostor", d)["msg"].endswith(
                "(each of its 5 branches was compared). 2 version tags of the repository point to it (v1.0.5, "
                "v1.0.6): the shape of tags moved onto one commit."))
            self.assertEqual(rep.notes, [(u, note)], pins)
            self.assertTrue(rep.complete, pins)
        self.assertEqual(self.book().entries, {})        # neither tag recorded: nothing to demote later
        # the pin book having seen both there before the run: still CRITICAL, no note that it was kept by its tag
        first = actionrefs.iso(T1)
        with open(self.book_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "tags": {f"o/mmm@{t}": {"sha": rel, "first": first, "last": first,
                                                             "tag_only": mark(rel, T1)}
                                              for t in ("v1.0.5", "v1.0.6")}}, f)
        for value in (u, "o/mmm@v1.0.5"):
            rep = self.audit(workflow(value), r, pins=self.book(), now=lambda: T2)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], value)
            self.assertEqual(rep.notes, [(value, note)], value)
        # many: the detail names the first 10 by version (v2.0.10 after v2.0.9) and counts them all
        r, rel = mmm_repo()
        for i in range(12):
            r.tag(f"v2.0.{i}", rel)
        rep = self.audit(workflow(u), r)
        d = rep.findings[0].detail
        self.assertEqual((d["version_tags"], d["version_tag_count"]),
                         (["v1.0.5"] + [f"v2.0.{i}" for i in range(9)], 13))
        self.assertIn("13 version tags of o/mmm point to", rep.notes[0][1])
        self.assertIn("v1.0.5 … v2.0.8 (and 3 more): the shape of tags moved onto one commit", rep.notes[0][1])

    def test_a_floating_tag_beside_the_version_tag_does_not_count(self):
        r, rel = mmm_repo()
        r.tag("v1", rel)
        r.tag("latest", rel)
        u = f"o/mmm@{rel}"
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T1)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        self.assertEqual(rep.findings[0].detail["tag"], "v1.0.5")
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T2)
        self.assertEqual((rep.findings, rep.notes), ([], [(u, held_note(rel, T1))]))

    def test_one_match_on_a_full_page_with_pages_left_is_critical(self):
        # only the tags read count: one version tag found on a full page, with more not read, may have a second
        r, rel = mmm_repo()
        for i in range(actionrefs.TAG_PAGE - len(r.tags)):
            r.tag(f"x-{i:04d}", r.shas[0])
        u = f"o/mmm@{rel}"
        with mock.patch.object(actionrefs, "TAG_PAGES", 1):
            rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T1)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual(rep.notes, [(u, f"the version tag v1.0.5 of o/mmm points to {rel[:12]}, but not every tag "
                                         f"was read (100 in 1 page of 100, and it has more), so another version tag "
                                         f"may point to it as well: {STANDS}")])
        self.assertEqual(len(tag_lists(self.gh)), 1)
        self.assertEqual(self.book().entries, {})
        # with the page after it read (empty): every tag read, MAJOR
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T1)
        self.assertEqual((self.rules(rep), len(tag_lists(self.gh))), ([("SC-ACTION-TAG-ONLY", "MAJOR")], 2))

    def test_an_annotated_tag_at_the_commit(self):
        r, rel = mmm_repo(annotated=True)
        u = f"o/mmm@{rel}"
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T1)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        self.assertEqual(rep.findings[0].detail["tag"], "v1.0.5")
        # the listing gives the commit the tag's object tags: no call for the object
        self.assertEqual(tag_calls(self.gh), [f"{fx.API}/repos/o/mmm/git/tags/{rel}"])
        self.assertEqual(len(tag_lists(self.gh)), 1)
        self.assertEqual(rep.tag_objects, {})
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T2)
        self.assertEqual((rep.findings, rep.notes), ([], [(u, held_note(rel, T1))]))

    def test_a_tag_listing_that_fails_leaves_the_impostor(self):
        r, rel = mmm_repo()
        u = f"o/mmm@{rel}"
        aud = self.auditor(r, pins=self.book(), now=lambda: T1)
        self.gh.broken["/o/mmm/tags"] = 500
        rep = aud.audit(actions.uses_of(workflow(u)))
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual(rep.notes, [(u, f"whether a version tag of o/mmm points to {rel[:12]} could not be asked "
                                         f"(listing the tags of o/mmm: HTTP 500): {STANDS}")])
        self.assertTrue(rep.complete)
        self.assertEqual(self.book().entries, {})
        # an answer that cannot be read, or one that is not a list: the same
        answer = fx.FakeGitHub.answer
        for body in (b"not json", b"{}", b'{"message": "Not Found"}'):
            def bad(gh, repo_, rest, query, what, body=body):
                return body if rest == "/tags" else answer(gh, repo_, rest, query, what)
            with mock.patch.object(fx.FakeGitHub, "answer", bad):
                rep = self.audit(workflow(u), r)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], body)
            self.assertEqual(len(rep.notes), 1, body)
            self.assertTrue(rep.notes[0][1].startswith(f"whether a version tag of o/mmm points to {rel[:12]} could not "
                                                       f"be asked ("), body)
            self.assertIn("listing the tags of o/mmm", rep.notes[0][1])
            self.assertTrue(rep.complete, body)

    def test_a_refused_tag_listing_leaves_the_impostor_and_stops_the_run(self):
        r, rel = mmm_repo()
        u, later = f"o/mmm@{rel}", "o/mmm@v1.1.0"
        # the repository, main, git/tags, the branches, 4 compares, the commit: 9 calls, then the listing is refused
        for kw, why in (({"max_calls": 9}, "the budget of 9 API calls is spent"), ({"limit": 9}, "rate limit reached")):
            rep = self.audit(workflow(u, later), r, pins=self.book(), **kw)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], kw)
            self.assertEqual(len(rep.notes), 1, kw)
            self.assertIn(f"whether a version tag of o/mmm points to {rel[:12]} was not asked (", rep.notes[0][1])
            self.assertIn(why, rep.notes[0][1])
            # the run stops as on any refusal: the use's action.yml and code are not read, the later use not checked
            self.assertEqual([x for x, _ in rep.incomplete], [u, later], kw)
            self.assertTrue(all(w.startswith("not checked: ") and why in w for _x, w in rep.incomplete), kw)
            self.assertFalse(rep.complete, kw)
            self.assertEqual(rep.actions, {}, kw)
            self.assertFalse([x for x in self.gh.calls if "/contents/" in x or "codeload" in x], kw)
            self.assertEqual(len(api_calls(self.gh)), 9 if "max_calls" in kw else 10, kw)
        self.assertEqual(self.book().entries, {})

    def test_more_tags_than_the_pages_read(self):
        r, rel = mmm_repo()
        for i in range(actionrefs.TAG_PAGES * actionrefs.TAG_PAGE + 20):
            r.tag(f"build-{i:04d}", r.shas[0])          # listed (by name) before v1.0.5
        u = f"o/mmm@{rel}"
        rep = self.audit(workflow(u), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual(rep.notes, [(u, f"none of the 300 tags of o/mmm read (3 pages of 100) is a version tag at "
                                         f"{rel[:12]}, and it has more, which were not read: {STANDS}")])
        self.assertTrue(rep.complete)
        self.assertEqual([x.split("?")[1] for x in tag_lists(self.gh)],
                         ["per_page=100", "per_page=100&page=2", "per_page=100&page=3"])
        # the cap is the helper's constant: one page more reaches the tag
        with mock.patch.object(actionrefs, "TAG_PAGES", 4):
            rep = self.audit(workflow(u), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        self.assertEqual(len(tag_lists(self.gh)), 4)
        # one version tag at the commit on page 1, the 3 pages all full: a second may be among those not read, so
        # CRITICAL, with a note that not every tag was read
        r, rel = mmm_repo()
        for i in range(400):
            r.tag(f"x-{i:04d}", r.shas[0])              # listed after v1.0.5
        rep = self.audit(workflow(f"o/mmm@{rel}"), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual(rep.notes, [(f"o/mmm@{rel}", f"the version tag v1.0.5 of o/mmm points to {rel[:12]}, but not "
                                                      f"every tag was read (300 in 3 pages of 100, and it has more), "
                                                      f"so another version tag may point to it as well: {STANDS}")])
        self.assertEqual((rep.findings[0].detail["version_tags"], rep.findings[0].detail["version_tag_count"]),
                         (["v1.0.5"], 1))
        self.assertEqual(len(tag_lists(self.gh)), 3)
        # every tag read (the last page read not full): the one match is enough
        with mock.patch.object(actionrefs, "TAG_PAGES", 5):
            rep = self.audit(workflow(f"o/mmm@{rel}"), r)
        self.assertEqual((self.rules(rep), len(tag_lists(self.gh))), ([("SC-ACTION-TAG-ONLY", "MAJOR")], 5))
        # exactly a page of tags: the next page is read and found empty
        r, rel = mmm_repo()
        for i in range(actionrefs.TAG_PAGE - len(r.tags)):
            r.tag(f"build-{i:04d}", r.shas[0])
        rep = self.audit(workflow(f"o/mmm@{rel}"), r)
        self.assertEqual((self.rules(rep), len(tag_lists(self.gh))), ([("SC-ACTION-TAG-ONLY", "MAJOR")], 2))

    def test_a_use_named_by_the_tag(self):
        r, rel = mmm_repo()
        u = "o/mmm@v1.0.5"
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T1)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        d = rep.findings[0].detail
        self.assertEqual((d["ref"], d["sha"], d["tag"], d["recorded"]), ("v1.0.5", rel, "v1.0.5", True))
        self.assertTrue(actions.rule("tag-only", d)["msg"].startswith(
            f"o/mmm@v1.0.5 points to the commit {rel}: the commit is in none of o/mmm's branches (each of its 5"))
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T2)
        self.assertEqual((rep.findings, rep.incomplete, rep.notes), ([], [], [(u, held_note(rel, T1))]))
        # a floating tag at the commit: what is checked is the commit that runs, and v1.0.5 holds it
        r.tag("v1", rel)
        rep = self.audit(workflow("o/mmm@v1"), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        self.assertEqual((rep.findings[0].detail["ref"], rep.findings[0].detail["tag"]), ("v1", "v1.0.5"))
        rep = self.audit(workflow("o/mmm@v1"), r, pins=self.book(), now=lambda: T3)
        self.assertEqual((rep.findings, rep.notes), ([], [("o/mmm@v1", held_note(rel, T1))]))
        # the tag moved onto a fork's commit: CRITICAL as now, and no listing asked
        evil = r.commit(r.shas[2], fork=True, files=YML)
        r.tag("v1.0.5", evil)
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T3)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL"), ("SC-ACTION-TAG-MOVED", "CRITICAL")])
        self.assertEqual(tag_lists(self.gh), [])

    def test_a_pinned_tag_object_whose_commit_only_its_tag_holds(self):
        r, rel = mmm_repo()
        obj = r.tag_object("v1.0.5", rel)
        r.tag("v1.0.5", obj)
        u = f"o/mmm@{obj}"
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T1)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        d = rep.findings[0].detail
        self.assertEqual((d["sha"], d["ref"], d["tag"], d["tag_object"]), (rel, obj, "v1.0.5", "v1.0.5"))
        self.assertTrue(actions.rule("tag-only", d)["msg"].startswith(
            f"o/mmm@{obj}, the tag object v1.0.5, points to the commit {rel}: the commit is in none of o/mmm's "
            f"branches"))
        self.assertEqual(rep.tag_objects, {u: {"tag": "v1.0.5", "object": obj, "commit": rel}})
        self.assertEqual(len(tag_lists(self.gh)), 1)
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T2)
        self.assertEqual(rep.findings, [])
        self.assertIn((u, held_note(rel, T1)), rep.notes)

    def test_no_listing_unless_every_branch_was_compared_and_none_holds_it(self):
        r, rel = mmm_repo()
        backport = r.commit(r.shas[1], files=YML)
        r.commit(backport, branch="release/v1")
        rep = self.audit(workflow(f"o/mmm@{r.shas[1]}", "o/mmm@v1.1.0", f"o/mmm@{backport}", "o/mmm@" + "0" * 40), r)
        self.assertEqual((rep.findings, rep.incomplete), ([], []))
        self.assertEqual(rep.branches, {f"o/mmm@{r.shas[1]}": "main", "o/mmm@v1.1.0": "main",
                                        f"o/mmm@{backport}": "release/v1"})
        self.assertEqual(tag_lists(self.gh), [])          # held by a branch, or no such commit: no listing
        # the branch check off, or not settled (more branches than the compare budget): no listing either
        rep = self.audit(workflow(f"o/mmm@{rel}"), r, env={actionrefs.OFF_ENV: "1"})
        self.assertEqual((rep.findings, tag_lists(self.gh)), ([], []))
        for i in range(actionrefs.MAX_COMPARES):
            r.commit(r.shas[0], branch=f"topic-{i:02d}")
        rep = self.audit(workflow(f"o/mmm@{rel}"), r)
        self.assertEqual((rep.findings, tag_lists(self.gh)), ([], []))
        self.assertIn("is not settled", rep.incomplete[0][1])

    def test_one_listing_for_a_repository(self):
        r, rel = mmm_repo()
        rel2 = r.commit(rel, files=YML)
        r.tag("v1.0.6", rel2)
        evil = r.commit(r.shas[2], fork=True, files=YML)
        uses = (f"o/mmm@{rel}", f"o/mmm@{rel2}", f"o/mmm@{evil}", "o/mmm@v1.0.6")
        rep = self.audit(workflow(*uses), r)
        self.assertEqual([(f.uses, f.kind) for f in rep.findings],
                         list(zip(uses, ("tag-only", "tag-only", "impostor", "tag-only"))))
        self.assertEqual([f.detail.get("tag") for f in rep.findings], ["v1.0.5", "v1.0.6", False, "v1.0.6"])
        self.assertEqual(len(tag_lists(self.gh)), 1)
        self.assertEqual(len(self.gh.calls), len(set(self.gh.calls)))      # nothing asked twice

    def test_a_record_made_in_the_run_demotes_nothing(self):
        # three uses resolved apart (a pin, the tag, the floating tag moved there: no `_done` answer shared), the
        # first of which records and marks the tag; the other two read the record as it was before the run
        r, rel = mmm_repo()
        r.tag("v1", rel)
        u = f"o/mmm@{rel}"
        clock = iter(range(T1, T1 + 1000, 5))            # a clock that moves on during the run
        uses = (u, "o/mmm@v1.0.5", "o/mmm@v1")
        rep = self.audit(workflow(*uses), r, pins=self.book(), now=lambda: next(clock))
        self.assertEqual(rep.checked, 3)
        self.assertEqual(sorted(self.aud._done), [("o", "mmm", rel), ("o", "mmm", "v1"), ("o", "mmm", "v1.0.5")])
        self.assertEqual([(f.uses, f.line, actions.rule(f.kind, f.detail)["sev"]) for f in rep.findings],
                         [(u, 7, "MAJOR"), ("o/mmm@v1.0.5", 8, "MAJOR"), ("o/mmm@v1", 9, "MAJOR")])
        self.assertEqual({f.kind for f in rep.findings}, {"tag-only"})
        self.assertEqual(rep.notes, [])
        entry = self.book().entries["o/mmm@v1.0.5"]
        self.assertEqual(entry["tag_only"], mark(rel, entry["first"]))   # marked by the first use's MAJOR
        self.assertGreater(entry["first"], actionrefs.iso(T1))         # (after the run's start)
        self.assertEqual(len(tag_lists(self.gh)), 1)

    def test_a_record_another_check_wrote_gives_the_major_first(self):
        # a run the commit stays CRITICAL in records the tag (the use named by it; a pin's `# v1.0.5` comment) but
        # never marks it: the next run where it is the one version tag at the commit is MAJOR, and the note comes
        # only after that
        def three_runs(name, text, first_run):
            book = lambda: actions.PinBook(os.path.join(self.tmp, name))        # noqa: E731
            r, rel = first_run()
            self.assertEqual({sev for _i, sev in self.rules(self.audit(text(rel), r, pins=book(), now=lambda: T1))},
                             {"CRITICAL"}, name)
            entry = book().entries["o/mmm@v1.0.5"]
            self.assertEqual((entry["sha"], "tag_only" in entry), (rel, False), name)     # recorded, not marked
            r, rel = mmm_repo()                         # v1.0.5 the one version tag at it, every tag read
            rep = self.audit(text(rel), r, pins=book(), now=lambda: T2)
            self.assertEqual({rule for rule in self.rules(rep)}, {("SC-ACTION-TAG-ONLY", "MAJOR")}, name)
            self.assertEqual(rep.notes, [], name)
            self.assertEqual(book().entries["o/mmm@v1.0.5"]["tag_only"], mark(rel, T2), name)
            rep = self.audit(text(rel), r, pins=book(), now=lambda: T3)
            self.assertEqual(rep.findings, [], name)
            self.assertTrue(rep.notes and all(n == held_note(rel, T1) for _u, n in rep.notes), name)

        def two_tags():
            r, rel = mmm_repo()
            r.tag("v1.0.6", rel)
            return r, rel

        def named(rel):
            return workflow("o/mmm@v1.0.5", f"o/mmm@{rel}")

        def commented(rel):
            return workflow(f"o/mmm@{rel}", comments={f"o/mmm@{rel}": "v1.0.5"})
        three_runs("two-tags.json", named, two_tags)
        three_runs("comment.json", commented, two_tags)
        # the listing failing in the first run (the tag's own sighting records it)
        path = os.path.join(self.tmp, "failed.json")
        r, rel = mmm_repo()
        aud = self.auditor(r, pins=actions.PinBook(path), now=lambda: T1)
        self.gh.broken["/o/mmm/tags"] = 500
        rep = aud.audit(actions.uses_of(named(rel)))
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")] * 2)
        self.assertNotIn("tag_only", actions.PinBook(path).entries["o/mmm@v1.0.5"])
        rep = self.audit(named(rel), r, pins=actions.PinBook(path), now=lambda: T2)
        self.assertEqual((self.rules(rep), rep.notes), ([("SC-ACTION-TAG-ONLY", "MAJOR")] * 2, []))

    def test_a_mark_from_a_run_that_began_before_it_was_made_is_not_held(self):
        # two Auditors over one database: B starts, A records and marks the tag, then B reads A's record; a mark
        # made after B's start is not one from before B began (MAJOR), as a third run, after both, gives the note
        path = os.path.join(self.tmp, "shared.db")
        r, rel = mmm_repo()
        u = f"o/mmm@{rel}"
        stores = [repo.Store(path), repo.Store(path)]
        for s in stores:
            self.addCleanup(s.close)
        late = actions.Auditor(env={}, http=fx.FakeGitHub(r), pins=actionrefs.StoreBook(stores[1]),
                               now=lambda: T1 + 10, code=False)
        rep = self.audit(workflow(u), r, pins=actionrefs.StoreBook(stores[0]), now=lambda: T1 + 20, code=False)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        rep = late.audit(actions.uses_of(workflow(u)))
        self.assertEqual((self.rules(rep), rep.notes), ([("SC-ACTION-TAG-ONLY", "MAJOR")], []))
        rep = self.audit(workflow(u), r, pins=actionrefs.StoreBook(stores[1]), now=lambda: T1 + 30, code=False)
        self.assertEqual((rep.findings, rep.notes), ([], [(u, held_note(rel, T1 + 20))]))

    def test_a_mark_that_is_not_the_scans_time_is_not_held(self):
        r, rel = mmm_repo()
        u = f"o/mmm@{rel}"
        # (a time not in the scan's form, a mark that names no commit, the earlier form of a mark: a time alone)
        for bad in (mark(rel, "2020-01-01"), mark(rel, "2020-01-01 00:00:00"), mark(rel, "2020-01-01T00:00:00"),
                    {"sha": rel, "at": 1_700_000_000}, {"at": actionrefs.iso(T1)}, mark(None, T1),
                    mark("x" * 40, T1), actionrefs.iso(T1), ""):
            with open(self.book_path, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "tags": {"o/mmm@v1.0.5": {"sha": rel, "first": actionrefs.iso(T1),
                                                                   "last": actionrefs.iso(T1), "tag_only": bad}}}, f)
            rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T2)
            self.assertEqual((self.rules(rep), rep.notes), ([("SC-ACTION-TAG-ONLY", "MAJOR")], []), bad)
            self.assertEqual(self.book().entries["o/mmm@v1.0.5"]["tag_only"], mark(rel, T2), bad)   # replaced

    def test_a_mark_at_another_commit_is_a_move_no_accept_recorded(self):
        # the new code marks v1.0.5 at the release commit; the tag is moved onto a fork's commit and an older version
        # accepts the move: its database update (the upsert before FP-IMPOSTOR-TAG, of its own columns) moves the row
        # onto the fork's commit and leaves the mark, with no moved_from. That commit stays CRITICAL, run after run
        r, rel = mmm_repo()
        evil = r.commit(r.shas[2], fork=True, files=YML)
        text = workflow("o/mmm@v1.0.5", f"o/mmm@{evil}")
        onto = (f"the version tag v1.0.5 of o/mmm points to {evil[:12]}, but it was moved onto it from {rel[:12]}, "
                f"where SC-ACTION-TAG-ONLY was given ({actionrefs.iso(T1)}), by an accept that kept no record of the "
                f"move (an older version's): accepting a move does not make it a release commit kept by its tag: "
                f"{STANDS}")
        path = os.path.join(self.tmp, "mixed.db")
        with repo.Store(path) as store:
            self.assertEqual(self.rules(self.audit(workflow(f"o/mmm@{rel}"), r, pins=actionrefs.StoreBook(store),
                                                   now=lambda: T1)), [("SC-ACTION-TAG-ONLY", "MAJOR")])
            stamp = actionrefs.iso(T2)
            store.conn.execute(
                "INSERT INTO action_tags (repo,tag,sha,first_seen,last_seen,moved_to,moved_at) VALUES (?,?,?,?,?,?,?) "
                "ON CONFLICT (repo,tag) DO UPDATE SET sha=excluded.sha, first_seen=excluded.first_seen, "
                "last_seen=excluded.last_seen, moved_to=excluded.moved_to, moved_at=excluded.moved_at",
                ("o/mmm", "v1.0.5", evil, stamp, stamp, None, None))
            store.conn.commit()
            self.assertEqual(store.action_tag("o/mmm", "v1.0.5")["tag_only"], mark(rel, T1))
        r.tag("v1.0.5", evil)
        for now in (T3, T4):
            with repo.Store(path) as store:
                rep = self.audit(text, r, pins=actionrefs.StoreBook(store), now=lambda t=now: t)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")] * 2, now)
            self.assertEqual(rep.notes, [("o/mmm@v1.0.5", onto), (f"o/mmm@{evil}", onto)], now)
        with repo.Store(path) as store:
            self.assertEqual(store.action_tag("o/mmm", "v1.0.5")["tag_only"], mark(rel, T1))     # kept: still so
        # the same record in the pin book file
        with open(self.book_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "tags": {"o/mmm@v1.0.5": {"sha": evil, "first": stamp, "last": stamp,
                                                               "tag_only": mark(rel, T1)}}}, f)
        for now in (T3, T4):
            rep = self.audit(text, r, pins=self.book(), now=lambda t=now: t)
            self.assertEqual((self.rules(rep), rep.notes), ([("SC-ACTION-IMPOSTOR", "CRITICAL")] * 2,
                                                            [("o/mmm@v1.0.5", onto), (f"o/mmm@{evil}", onto)]), now)
        # a mark at the record's commit, given there before the run: the note, as ever
        with open(self.book_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "tags": {"o/mmm@v1.0.5": {"sha": rel, "first": stamp, "last": stamp,
                                                               "tag_only": mark(rel, T2)}}}, f)
        r.tag("v1.0.5", rel)
        rep = self.audit(workflow(f"o/mmm@{rel}"), r, pins=self.book(), now=lambda: T3)
        self.assertEqual((rep.findings, rep.notes), ([], [(f"o/mmm@{rel}", held_note(rel, T2))]))

    def test_a_flagged_record_with_the_use_named_by_the_tag_first(self):
        # the record is marked and flagged moved; the use named by the tag comes first, and its own sighting at the
        # first commit clears the flag: the record as it was before the run (flagged) is what counts
        r, rel = mmm_repo()
        at = actionrefs.iso(T1 + 60)
        for uses in (("o/mmm@v1.0.5",), ("o/mmm@v1.0.5", f"o/mmm@{rel}")):
            with open(self.book_path, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "tags": {"o/mmm@v1.0.5": {
                    "sha": rel, "first": actionrefs.iso(T1), "last": at, "tag_only": mark(rel, T1),
                    "moved": {"to": r.shas[2], "at": at}}}}, f)
            rep = self.audit(workflow(*uses), r, pins=self.book(), now=lambda: T2)
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")] * len(uses), uses)
            self.assertTrue(all(f"saw it at {r.shas[2][:12]} since ({at}), a move not accepted" in n
                                for _u, n in rep.notes), uses)

    def test_an_accepting_run_marks_a_first_sighting(self):
        # --accept-moved with nothing moved: the one tag's first sighting is the MAJOR, marked as in any other run
        for kind, book in self.books():
            r, rel = mmm_repo()
            u = f"o/mmm@{rel}"
            rep = self.audit(workflow(u), r, pins=book(), now=lambda: T1, accept_moved=True)
            self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")], kind)
            self.assertEqual(book().record("o/mmm@v1.0.5")["tag_only"], mark(rel, T1), kind)
            rep = self.audit(workflow(u), r, pins=book(), now=lambda: T2)
            self.assertEqual((rep.findings, rep.notes), ([], [(u, held_note(rel, T1))]), kind)

    def test_an_accepting_run_does_not_say_the_move_is_not_accepted(self):
        # a marked record flagged moved, the tag back at its first commit; the run that accepts: CRITICAL, without
        # "a move not accepted"; the accepted record has its mark kept, so the next run is the note
        r, rel = mmm_repo()
        at = actionrefs.iso(T1 + 60)
        with open(self.book_path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "tags": {"o/mmm@v1.0.5": {
                "sha": rel, "first": actionrefs.iso(T1), "last": at, "moved": {"to": r.shas[2], "at": at}}}}, f)
        u = f"o/mmm@{rel}"
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T2, accept_moved=True)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual(rep.notes, [(u, f"the version tag v1.0.5 of o/mmm points to {rel[:12]}, but the pin book saw "
                                         f"it at {r.shas[2][:12]} since ({at}): {STANDS}")])
        self.assertNotIn("moved", self.book().entries["o/mmm@v1.0.5"])
        # (the accepted record has no mark: MAJOR next, then the note)
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T3)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        rep = self.audit(workflow(u), r, pins=self.book(), now=lambda: T4)
        self.assertEqual((rep.findings, rep.notes), ([], [(u, held_note(rel, T2))]))

    def test_the_run_a_commands_files_share(self):
        # one Run for every file's Auditor (as the command makes): its start, so that a mark another process makes
        # between two files is after it ...
        r, rel = mmm_repo()
        u = f"o/mmm@{rel}"
        run = actions.Run()
        first = actions.Auditor(env={}, http=fx.FakeGitHub(r), pins=self.book(), now=lambda: T1, code=False, run=run)
        self.assertEqual(first.audit(actions.uses_of(workflow("o/mmm@v1.1.0"))).findings, [])
        other = self.book()
        other.see("o/mmm@v1.0.5", rel, T1 + 5, tag_only=True)
        other.save()
        later = actions.Auditor(env={}, http=fx.FakeGitHub(r), pins=self.book(), now=lambda: T1 + 10, code=False,
                                run=run)
        rep = later.audit(actions.uses_of(workflow(u)))
        self.assertEqual((self.rules(rep), rep.notes), ([("SC-ACTION-TAG-ONLY", "MAJOR")], []))
        # ... and the records as they were before it: the first file's comment check (its branch check failing, no
        # listing asked) sees the tag back at its first commit, which clears the flag; the second file still reads
        # the record flagged
        path = os.path.join(self.tmp, "flagged.json")
        at = actionrefs.iso(T1 + 60)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"version": 1, "tags": {"o/mmm@v1.0.5": {
                "sha": rel, "first": actionrefs.iso(T1), "last": at, "tag_only": mark(rel, T1),
                "moved": {"to": r.shas[2], "at": at}}}}, f)
        run, book = actions.Run(), actions.PinBook(path)
        broken = fx.FakeGitHub(r)
        broken.broken["/compare/"] = 502
        rep = actions.Auditor(env={}, http=broken, pins=book, now=lambda: T2, code=False, run=run).audit(
            actions.uses_of(workflow(u, comments={u: "v1.0.5"})))
        self.assertEqual(rep.findings, [])
        self.assertIn("could not be settled", rep.incomplete[0][1])
        self.assertNotIn("moved", book.entries["o/mmm@v1.0.5"])        # (the comment check's sighting cleared it)
        rep = actions.Auditor(env={}, http=fx.FakeGitHub(r), pins=book, now=lambda: T2, code=False, run=run).audit(
            actions.uses_of(workflow(u)))
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertIn("a move not accepted", rep.notes[0][1])

    def test_a_refusal_from_the_listing_always_stops_the_run(self):
        r, rel = mmm_repo()
        aud = self.auditor(r)

        def refused(owner, repo_):
            raise actions._Stop("refused")
        aud.branches.tags = refused
        rep = aud.audit(actions.uses_of(workflow(f"o/mmm@{rel}", "o/mmm@v1.1.0")))
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual(rep.incomplete, [(f"o/mmm@{rel}", "not checked: refused"), ("o/mmm@v1.1.0",
                                                                                     "not checked: refused")])

    def test_uses_naming_the_repository_in_another_case_share_one_listing(self):
        r, rel = mmm_repo()
        rep = self.audit(workflow(f"O/MMM@{rel}", "o/Mmm@v1.0.5"), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")] * 2)
        self.assertEqual(rep.checked, 2)                 # (two resolutions, not one answer kept)
        self.assertEqual(len(tag_lists(self.gh)), 1)

    def test_a_pin_book_that_fails_leaves_the_impostor(self):
        class Broken:
            def action_tag(self, repo_, tag):
                raise sqlite3.OperationalError("database is locked")

            def save_action_tag(self, repo_, tag, entry):
                raise sqlite3.OperationalError("database is locked")
        r, rel = mmm_repo()
        note = (f"the version tag v1.0.5 of o/mmm points to {rel[:12]}, but its record in the pin book could not be "
                f"read or kept")
        for u in (f"o/mmm@{rel}", "o/mmm@v1.0.5"):
            rep = self.audit(workflow(u), r, pins=actionrefs.StoreBook(Broken()))
            self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")], u)
            whys = [w for _x, w in rep.incomplete]
            self.assertIn("the tag v1.0.5 of o/mmm could not be read from the registry's database (OperationalError: "
                          "database is locked)", whys)
            self.assertEqual(len([w for w in whys if "could not be recorded in the registry's database" in w]), 1, u)
            self.assertEqual(rep.notes, [(u, f"{note}: {STANDS}")], u)

        # the record as it was before the run could not be read, though the sighting after it was kept (a flaky
        # connection): whether the tag moved is not known
        class FirstReadFails:
            def __init__(self):
                self.rows, self.reads = {}, 0

            def action_tag(self, repo_, tag):
                self.reads += 1
                if self.reads == 1:
                    raise sqlite3.OperationalError("disk I/O error")
                row = self.rows.get((repo_, tag))
                return json.loads(json.dumps(row)) if row is not None else None

            def save_action_tag(self, repo_, tag, entry):
                self.rows[(repo_, tag)] = json.loads(json.dumps(entry))
        flaky = FirstReadFails()
        rep = self.audit(workflow(f"o/mmm@{rel}"), r, pins=actionrefs.StoreBook(flaky), now=lambda: T1)
        self.assertEqual(self.rules(rep), [("SC-ACTION-IMPOSTOR", "CRITICAL")])
        self.assertEqual([w for _x, w in rep.incomplete], ["the tag v1.0.5 of o/mmm could not be read from the "
                                                           "registry's database (OperationalError: disk I/O error)"])
        self.assertEqual(rep.notes, [(f"o/mmm@{rel}", f"{note}: {STANDS}")])
        # the sighting it kept has no mark: the next run is the MAJOR, not the note
        self.assertNotIn("tag_only", flaky.rows[("o/mmm", "v1.0.5")])
        rep = self.audit(workflow(f"o/mmm@{rel}"), r, pins=actionrefs.StoreBook(flaky), now=lambda: T2)
        self.assertEqual((self.rules(rep), rep.notes), ([("SC-ACTION-TAG-ONLY", "MAJOR")], []))

    def test_without_a_pin_book(self):
        r, rel = mmm_repo()
        rep = self.audit(workflow(f"o/mmm@{rel}"), r)
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-ONLY", "MAJOR")])
        rule = actions.rule("tag-only", rep.findings[0].detail)
        self.assertFalse(rep.findings[0].detail["recorded"])
        self.assertTrue(rule["msg"].endswith("Without a pin book, whether the tag stays at it is not known."))
        self.assertIn("(without --no-pins)", rule["fix"])
        self.assertTrue(rep.complete)


def moved_repo():
    r = release_repo()
    r.tag("v1.0.0", r.shas[1])
    return r


class MovedTagTests(Base):
    def run_twice(self, book_of, move_to):
        """A first scan sees v1.0.0 at r.shas[1]; then the tag is moved to `move_to(r)`, and scanned again."""
        r = moved_repo()
        text = workflow("o/act@v1.0.0")
        self.assertEqual(self.audit(text, r, pins=book_of()).findings, [])
        r.tag("v1.0.0", move_to(r))
        return r, self.audit(text, r, pins=book_of())

    def check_moves(self, book_of):
        """A tag moved to a commit of the default branch, then (in the same book) one moved to a fork's commit:
        -> the fork's commit, which the tag's move was accepted to at the end."""
        r, rep = self.run_twice(book_of, lambda r: r.shas[2])
        self.assertEqual(self.rules(rep), [("SC-ACTION-TAG-MOVED", "MAJOR")])
        self.assertTrue(actions.rule("tag-moved", rep.findings[0].detail)["msg"].endswith(
            f"points to {r.shas[2][:12]} now."))
        evil = []

        def to_a_forks_commit(r):
            evil.append(r.commit(r.shas[2], fork=True))
            return evil[0]

        r, rep = self.run_twice(book_of, to_a_forks_commit)
        self.assertEqual(sorted(self.rules(rep)),
                         [("SC-ACTION-IMPOSTOR", "CRITICAL"), ("SC-ACTION-TAG-MOVED", "CRITICAL")])
        moved = next(f for f in rep.findings if f.kind == "tag-moved")
        self.assertEqual((moved.detail["was"], moved.detail["now"], moved.detail["fork"]), (r.shas[1], evil[0], True))
        self.assertIn("which is in none of its branches: a commit from a fork, reached through the repository's name",
                      actions.rule("tag-moved", moved.detail)["msg"])
        # the alert stays until the move is accepted
        text = workflow("o/act@v1.0.0")
        self.assertIn("tag-moved", [f.kind for f in self.audit(text, r, pins=book_of()).findings])
        self.audit(text, r, pins=book_of(), accept_moved=True)
        self.assertNotIn("tag-moved", [f.kind for f in self.audit(text, r, pins=book_of()).findings])
        return evil[0]

    def test_in_the_pin_book(self):
        self.check_moves(lambda: actions.PinBook(self.book_path))

    def test_in_the_registrys_database(self):
        path = os.path.join(self.tmp, "registry.db")
        stores = []

        def book():
            stores.append(repo.Store(path))
            self.addCleanup(stores[-1].close)
            return actionrefs.StoreBook(stores[-1])

        evil = self.check_moves(book)
        with repo.Store(path) as store:
            self.assertIsNone(store.action_tag("o/act", "v9.9.9"))
            rows = store.conn.execute("SELECT repo, tag, sha, moved_to FROM action_tags").fetchall()
        self.assertEqual(rows, [("o/act", "v1.0.0", evil, None)])       # the move accepted: nothing left moved

    def test_a_floating_tag_is_not_recorded(self):
        path = os.path.join(self.tmp, "registry.db")
        with repo.Store(path) as store:
            r = release_repo()
            self.audit(workflow("o/act@v1"), r, pins=actionrefs.StoreBook(store))
            self.assertEqual(store.conn.execute("SELECT COUNT(*) FROM action_tags").fetchone()[0], 0)

    def test_a_database_that_fails_leaves_the_tag_unchecked(self):
        class Broken:
            def action_tag(self, repo_, tag):
                raise sqlite3.OperationalError("database is locked")

            def save_action_tag(self, repo_, tag, entry):
                raise sqlite3.OperationalError("database is locked")
        r = moved_repo()
        rep = self.audit(workflow("o/act@v1.0.0"), r, pins=actionrefs.StoreBook(Broken()))
        self.assertEqual(rep.findings, [])
        self.assertEqual([u for u, _ in rep.incomplete], ["o/act@v1.0.0"])
        self.assertIn("could not be recorded in the registry's database (OperationalError: database is locked)",
                      rep.incomplete[0][1])
        self.assertEqual(rep.branches, {"o/act@v1.0.0": "main"})            # the branch check still ran
        # a pin's comment tag is recorded too: the same failure is said for it
        u = f"o/act@{r.shas[1]}"
        rep = self.audit(workflow(u, comments={u: "v1.0.0"}), r, pins=actionrefs.StoreBook(Broken()))
        self.assertEqual((rep.findings, [x for x, _ in rep.incomplete]), ([], [u]))
        self.assertIn("could not be recorded", rep.incomplete[0][1])

    def test_sighting(self):
        entry, was = actionrefs.sighting(None, "a" * 40, 100)
        self.assertEqual((entry, was), ({"sha": "a" * 40, "first": "1970-01-01T00:01:40Z",
                                         "last": "1970-01-01T00:01:40Z"}, None))
        entry, was = actionrefs.sighting(entry, "b" * 40, 200)
        self.assertEqual((entry["sha"], entry["moved"]["to"], was["sha"]), ("a" * 40, "b" * 40, "a" * 40))
        entry, was = actionrefs.sighting(entry, "a" * 40, 300)
        self.assertEqual((sorted(entry), was), (["first", "last", "sha"], None))
        # FP-IMPOSTOR-TAG: SC-ACTION-TAG-ONLY's sighting marks the record once; other sightings keep the mark, and a
        # sighting elsewhere adds none
        entry, _ = actionrefs.sighting(entry, "a" * 40, 400, tag_only=True)
        self.assertEqual(entry["tag_only"], mark("a" * 40, 400))
        entry, _ = actionrefs.sighting(entry, "a" * 40, 500, tag_only=True)
        entry, _ = actionrefs.sighting(entry, "a" * 40, 600)
        self.assertEqual(entry["tag_only"], mark("a" * 40, 400))
        self.assertEqual(actionrefs.mark_of(entry), ("a" * 40, "1970-01-01T00:06:40Z"))
        moved, was = actionrefs.sighting(entry, "b" * 40, 700, tag_only=True)
        self.assertEqual((moved["sha"], moved["tag_only"], was["sha"]), ("a" * 40, mark("a" * 40, 400), "a" * 40))
        # a mark at another commit than the record's is replaced by SC-ACTION-TAG-ONLY's sighting only, kept by
        # any other
        odd = dict(entry, tag_only=mark("c" * 40, 100))
        self.assertEqual(actionrefs.sighting(odd, "a" * 40, 800)[0]["tag_only"], mark("c" * 40, 100))
        self.assertEqual(actionrefs.sighting(odd, "a" * 40, 800, tag_only=True)[0]["tag_only"], mark("a" * 40, 800))
        self.assertEqual(actionrefs.mark_of(odd), ("c" * 40, "1970-01-01T00:01:40Z"))
        for bad in ("1970-01-01T00:06:40Z", {"sha": "a" * 40}, {"at": "1970-01-01T00:06:40Z"}, None, 3):
            self.assertEqual(actionrefs.mark_of(dict(entry, tag_only=bad)), (None, None), bad)
        # an accept at another commit starts again there and keeps where the tag moved from; at the same commit,
        # the marks are kept
        acc = actionrefs.accepted(moved, "b" * 40, 800)
        self.assertEqual(acc, {"sha": "b" * 40, "first": "1970-01-01T00:13:20Z", "last": "1970-01-01T00:13:20Z",
                               "moved_from": {"sha": "a" * 40, "at": "1970-01-01T00:13:20Z"}})
        self.assertEqual(actionrefs.accepted(acc, "b" * 40, 900)["moved_from"], acc["moved_from"])
        self.assertEqual(actionrefs.accepted(entry, "a" * 40, 900)["tag_only"], mark("a" * 40, 400))
        self.assertEqual(actionrefs.accepted(None, "a" * 40, 900), {"sha": "a" * 40, "first": "1970-01-01T00:15:00Z",
                                                                    "last": "1970-01-01T00:15:00Z"})
        # and a sighting at the same commit keeps moved_from
        self.assertEqual(actionrefs.sighting(acc, "b" * 40, 950)[0]["moved_from"], acc["moved_from"])


class TagConn(FakeConn):
    """The Store's fake Postgres connection, the action_tags statements run on SQLite ($n as ?n)."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.db = sqlite3.connect(":memory:")
        self.sent = []

    def execute_script(self, sql):
        super().execute_script(sql)
        self.script = sql
        for statement in sql.split(";"):
            # (the ALTERs give an older table FP-IMPOSTOR-TAG's columns, which this new table has: SQLite has no
            # ADD COLUMN IF NOT EXISTS)
            if "action_tags" in statement and not statement.strip().startswith("ALTER"):
                self.db.execute(statement)

    def _run(self, op, sql, args):
        self._op(op)
        self.sent.append((sql, args))
        return self.db.execute(re.sub(r"\$(\d+)", r"?\1", sql), args)

    def fetchrow(self, sql, *args):
        if "action_tags" not in sql:
            return super().fetchrow(sql, *args)
        return self._run("fetchrow", sql, args).fetchone()

    def execute(self, sql, *args):
        if "action_tags" not in sql:
            return super().execute(sql, *args)
        self._run("INSERT", sql, args)


class PostgresTagTests(unittest.TestCase):
    def test_round_trip_on_the_wire_statements(self):
        conn = TagConn()
        store = pg_store(conn)
        self.assertIsNone(store.action_tag("o/act", "v1.0.0"))
        store.save_action_tag("o/act", "v1.0.0", {"sha": "a" * 40, "first": "t1", "last": "t1"})
        store.save_action_tag("o/act", "v1.0.0", {"sha": "a" * 40, "first": "t1", "last": "t2",
                                                  "moved": {"to": "b" * 40, "at": "t2"}})
        self.assertEqual(store.action_tag("o/act", "v1.0.0"), {"sha": "a" * 40, "first": "t1", "last": "t2",
                                                               "moved": {"to": "b" * 40, "at": "t2"}})
        insert = next(s for s, _ in conn.sent if s.startswith("INSERT"))
        self.assertIn("VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (repo,tag) DO UPDATE", insert)
        select = next(s for s, _ in conn.sent if s.startswith("SELECT"))
        self.assertIn("WHERE repo=$1 AND tag=$2", select)
        # FP-IMPOSTOR-TAG's marks round-trip, and an older table is given their columns
        entry = {"sha": "c" * 40, "first": "t3", "last": "t3", "tag_only": {"sha": "c" * 40, "at": "t3"},
                 "moved_from": {"sha": "a" * 40, "at": "t3"}}
        store.save_action_tag("o/act", "v1.0.0", entry)
        self.assertEqual(store.action_tag("o/act", "v1.0.0"), entry)
        for column in repo.ACTION_TAG_ADDED:
            self.assertIn(f"ALTER TABLE action_tags ADD COLUMN IF NOT EXISTS {column} TEXT", conn.script)

    def test_an_older_sqlite_table_is_given_the_new_columns(self):
        path = os.path.join(tempfile.mkdtemp(prefix="lazaret-action-tags-"), "old.db")
        self.addCleanup(shutil.rmtree, os.path.dirname(path), ignore_errors=True)
        old = sqlite3.connect(path)
        old.execute("CREATE TABLE action_tags (repo TEXT NOT NULL, tag TEXT NOT NULL, sha TEXT NOT NULL, first_seen "
                    "TEXT NOT NULL, last_seen TEXT NOT NULL, moved_to TEXT, moved_at TEXT, PRIMARY KEY (repo, tag))")
        old.execute("INSERT INTO action_tags VALUES ('o/act', 'v1.0.0', ?, 't1', 't1', NULL, NULL)", ("a" * 40,))
        old.commit()
        old.close()
        with repo.Store(path) as store:
            self.assertEqual(store.action_tag("o/act", "v1.0.0"), {"sha": "a" * 40, "first": "t1", "last": "t1"})
            store.save_action_tag("o/act", "v1.0.0", {"sha": "a" * 40, "first": "t1", "last": "t2",
                                                      "tag_only": {"sha": "a" * 40, "at": "t2"}})
            self.assertEqual(store.action_tag("o/act", "v1.0.0")["tag_only"], {"sha": "a" * 40, "at": "t2"})
        with open(os.path.join(os.path.dirname(repo.__file__), "schema.sql"), encoding="utf-8") as f:
            sql = f.read()
        for column in repo.ACTION_TAG_ADDED:
            self.assertIn(f"ALTER TABLE action_tags ADD COLUMN IF NOT EXISTS {column} TEXT;", sql)

    def test_two_processes_giving_an_older_table_the_columns_at_once(self):
        # another process adds the columns between this one's look at the table and its ALTER: its "duplicate column
        # name" is passed once the table, read again, has the column; any other error is still raised
        path = os.path.join(tempfile.mkdtemp(prefix="lazaret-action-tags-"), "old.db")
        self.addCleanup(shutil.rmtree, os.path.dirname(path), ignore_errors=True)
        conn = sqlite3.connect(path)
        self.addCleanup(conn.close)
        conn.execute("CREATE TABLE action_tags (repo TEXT NOT NULL, tag TEXT NOT NULL, sha TEXT NOT NULL, first_seen "
                     "TEXT NOT NULL, last_seen TEXT NOT NULL, moved_to TEXT, moved_at TEXT, PRIMARY KEY (repo, tag))")
        conn.commit()

        class Racing:
            """A cursor whose first look at the table is from before the other process added the columns."""

            def __init__(self, cur, fail=None, race=True):
                self.cur, self.looks, self.fail, self.race = cur, 0, fail, race

            def execute(self, sql, *args):
                if sql.startswith("PRAGMA table_info("):
                    self.looks += 1
                    rows = list(self.cur.execute(sql, *args))
                    if self.looks == 1 and self.race:
                        other = sqlite3.connect(path)
                        for column in repo.ACTION_TAG_ADDED:
                            other.execute(f"ALTER TABLE action_tags ADD COLUMN {column} TEXT")
                        other.commit()
                        other.close()
                    return rows
                if self.fail is not None and sql.startswith("ALTER"):
                    raise self.fail
                return self.cur.execute(sql, *args)
        racing = Racing(conn.cursor())
        repo._sqlite_add_columns(racing, "action_tags", repo.ACTION_TAG_ADDED)
        self.assertEqual(racing.looks, 2)                # (looked again after the first duplicate column)
        self.assertEqual([row[1] for row in conn.execute("PRAGMA table_info(action_tags)")][7:],
                         list(repo.ACTION_TAG_ADDED))
        # and a Store opened then reads and writes the marks
        with repo.Store(path) as store:
            store.save_action_tag("o/act", "v1.0.0", {"sha": "a" * 40, "first": "t1", "last": "t1",
                                                      "tag_only": {"sha": "a" * 40, "at": "t1"}})
            self.assertEqual(store.action_tag("o/act", "v1.0.0")["tag_only"], {"sha": "a" * 40, "at": "t1"})
        # a duplicate column the table does not have after all, and any other error: raised
        for fail in (sqlite3.OperationalError("duplicate column name: nope"), sqlite3.OperationalError("disk I/O")):
            with self.assertRaises(sqlite3.OperationalError):
                repo._sqlite_add_columns(Racing(conn.cursor(), fail, race=False), "action_tags", ("nope",))


class CommandTests(Base):
    def run_main(self, argv, *repos, clock=None):
        """The command over `repos`; `clock` (FP-IMPOSTOR-TAG): each file's Auditor reads it as its time."""
        self.gh = gh = fx.FakeGitHub(*repos)
        out, err = io.StringIO(), io.StringIO()
        env = {"GITHUB_TOKEN": "", actionrefs.OFF_ENV: "", "LAZARET_ACTIONS_PINS": self.book_path}
        audit_text = actions.audit_text
        timed = (lambda text, **kw: audit_text(text, now=clock, **kw)) if clock is not None else audit_text
        with mock.patch.object(sources, "_http", gh), mock.patch.dict(os.environ, env), \
                mock.patch.object(actions, "audit_text", timed), redirect_stdout(out), redirect_stderr(err):
            code = actions.main(argv)
        return code, out.getvalue(), err.getvalue()

    def files(self, *texts):
        paths = []
        for i, text in enumerate(texts):
            paths.append(os.path.join(self.tmp, f"wf{i}.yml"))
            with open(paths[-1], "w", encoding="utf-8") as f:
                f.write(text)
        return paths

    @staticmethod
    def outcomes(out):
        return [([ru["id"] + " " + ru["sev"] for ru in doc["rules"]], [n for _u, n in doc["notes"]], doc["complete"])
                for doc in json.loads(out)]

    def test_the_files_of_one_command_are_one_run(self):
        # FP-IMPOSTOR-TAG: one command over two workflow files that both use the release commit only its tag holds;
        # a record the first file's audit makes is not one an earlier command left, so the second is MAJOR too
        r, rel = mmm_repo()
        db = os.path.join(self.tmp, "registry.db")
        for book, first in ((["--pins", self.book_path], f"o/mmm@{rel}"), (["--db", db], f"o/mmm@{rel}"),
                            (["--pins", self.book_path + "2"], "o/mmm@v1.0.5")):
            a, b = self.files(workflow(first), workflow(f"o/mmm@{rel}"))
            ticks = iter(range(T1, T1 + 100000, 2))         # the clock moves on 2 s each time it is read
            code, out, _ = self.run_main(["--no-code", *book, a, b], r, clock=lambda: next(ticks))
            self.assertEqual((code, self.outcomes(out)), (1, [(["SC-ACTION-TAG-ONLY MAJOR"], [], True)] * 2), book)
            self.assertEqual(len(tag_lists(self.gh)), 1, book)       # one listing for the command's two files
            # the next command, an hour on: the mark the first one made, so both files give the note
            ticks = iter(range(T2, T2 + 100000, 2))
            code, out, _ = self.run_main(["--no-code", *book, a, b], r, clock=lambda: next(ticks))
            self.assertEqual(code, 0, book)
            self.assertEqual([(rules, done) for rules, _n, done in self.outcomes(out)], [([], True)] * 2, book)
            held = (f"only the tag v1.0.5 of o/mmm holds {rel[:12]}, none of its 5 branches: a release commit kept "
                    f"by its tag, seen at it since 2026-10-14T")
            self.assertTrue(all(len(n) == 1 and n[0].startswith(held) for _r, n, _d in self.outcomes(out)), book)

    def test_accepting_in_one_file_lowers_no_other(self):
        # --accept-moved over two files: the first names the moved tag, the second pins its commit
        r, rel = mmm_repo()
        r.tag("v1.0.5", r.shas[1])
        a, b = self.files(workflow("o/mmm@v1.0.5"), workflow(f"o/mmm@{rel}"))
        self.assertEqual(self.run_main(["--no-code", a], r, clock=lambda: T1)[0], 0)
        r.tag("v1.0.5", rel)
        ticks = iter(range(T2, T2 + 100000, 2))
        code, out, _ = self.run_main(["--no-code", "--accept-moved", a, b], r, clock=lambda: next(ticks))
        self.assertEqual(code, 1)
        self.assertEqual([rules for rules, _n, _d in self.outcomes(out)], [["SC-ACTION-IMPOSTOR CRITICAL"]] * 2)
        self.assertTrue(all("but the pin book first saw it at" in n[0] for _r, n, _d in self.outcomes(out)))

    def test_a_tag_that_moves_during_the_command_stays_critical(self):
        # the first file names v1.0.5 at a commit of main (recorded there, no listing); the tag is moved onto the
        # release commit no branch holds before the second file pins it: a move within the command, CRITICAL
        r, rel = mmm_repo()
        r.tag("v1.0.5", r.shas[1])
        a, b = self.files(workflow("o/mmm@v1.0.5"), workflow(f"o/mmm@{rel}"))
        audit_text, seen = actions.audit_text, []
        ticks = iter(range(T1, T1 + 100000, 2))

        def moving(text, **kw):
            seen.append(text)
            if len(seen) == 2:
                r.tag("v1.0.5", rel)
            return audit_text(text, now=lambda: next(ticks), **kw)
        with mock.patch.object(actions, "audit_text", moving):
            code, out, _ = self.run_main(["--no-code", a, b], r)
        got = self.outcomes(out)
        self.assertEqual((code, got[0][0], got[1][0]), (1, [], ["SC-ACTION-IMPOSTOR CRITICAL"]))
        self.assertTrue(got[1][1][0].startswith(f"the version tag v1.0.5 of o/mmm points to {rel[:12]}, but the pin "
                                                f"book first saw it at {r.shas[1][:12]} (2026-10-14T"))

    def test_a_refused_first_file_lowers_no_other(self):
        # --max-calls 12 (each file's own budget): the first file's use named by v1.0.5 is resolved and recorded,
        # then refused; the second file pins the same commit: MAJOR, not the note
        r, rel = mmm_repo()
        others, uses = [], []
        for i in range(3):
            o = fx.Repo(f"o/x{i}")
            uses.append(f"o/x{i}@{o.commit(branch='main', files=YML)}")
            others.append(o)
        a, b = self.files(workflow(*uses, "o/mmm@v1.0.5"), workflow(f"o/mmm@{rel}"))
        ticks = iter(range(T1, T1 + 100000, 2))
        code, out, _ = self.run_main(["--no-code", "--max-calls", "12", a, b], r, *others, clock=lambda: next(ticks))
        got = self.outcomes(out)
        self.assertEqual((got[0][0], got[0][2]), ([], False))
        self.assertEqual((got[1][0], got[1][1]), (["SC-ACTION-TAG-ONLY MAJOR"], []))
        self.assertEqual(code, 3)        # (an incomplete file before a MAJOR one exits 3: older than FP-IMPOSTOR-TAG)

    def test_the_db_option(self):
        r = moved_repo()
        wf = os.path.join(self.tmp, "ci.yml")
        with open(wf, "w", encoding="utf-8") as f:
            f.write(workflow("o/act@v1.0.0"))
        db = os.path.join(self.tmp, "registry.db")
        self.assertEqual(self.run_main(["--db", db, wf], r)[0], 0)
        r.tag("v1.0.0", r.shas[2])
        code, out, _ = self.run_main(["--db", db, wf], r)
        self.assertEqual((code, [ru["id"] + " " + ru["sev"] for ru in json.loads(out)[0]["rules"]]),
                         (1, ["SC-ACTION-TAG-MOVED MAJOR"]))
        self.assertEqual(self.run_main(["--db", db, "--accept-moved", wf], r)[0], 0)
        self.assertEqual(self.run_main(["--db", db, wf], r)[0], 0)
        self.assertFalse(os.path.exists(self.book_path))           # the database, not the pin book
        for argv in (["--db", db, "--pins", self.book_path, wf], ["--no-pins", "--db", db, wf], ["--db"]):
            code, _, err = self.run_main(argv, r)
            self.assertEqual(code, 2, argv)
            self.assertIn("usage:", err)
        code, _, err = self.run_main(["--db", self.tmp, wf], r)                 # a folder: not a database
        self.assertEqual(code, 2)
        self.assertIn("error: --db:", err)

    def test_an_imposter_exits_1_and_an_unsettled_check_3(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        wf = os.path.join(self.tmp, "ci.yml")
        with open(wf, "w", encoding="utf-8") as f:
            f.write(workflow(f"o/act@{evil}"))
        code, out, _ = self.run_main(["--no-pins", wf], r)
        doc = json.loads(out)[0]
        self.assertEqual((code, doc["rules"][0]["id"], doc["rules"][0]["sev"]), (1, "SC-ACTION-IMPOSTOR", "CRITICAL"))
        for i in range(actionrefs.MAX_COMPARES):
            r.commit(r.shas[1], branch=f"topic-{i:02d}")
        code, out, _ = self.run_main(["--no-pins", wf], r)
        doc = json.loads(out)[0]
        self.assertEqual((code, doc["rules"], doc["complete"]), (3, [], False))

    def test_a_commit_only_a_version_tag_holds_exits_1(self):
        r, rel = mmm_repo()
        wf = os.path.join(self.tmp, "ci.yml")
        with open(wf, "w", encoding="utf-8") as f:
            f.write(workflow(f"o/mmm@{rel}"))
        code, out, _ = self.run_main(["--no-pins", wf], r)
        doc = json.loads(out)[0]
        self.assertEqual((code, [(f["kind"], ru["id"], ru["sev"]) for f, ru in zip(doc["findings"], doc["rules"])]),
                         (1, [("tag-only", "SC-ACTION-TAG-ONLY", "MAJOR")]))
        self.assertEqual((doc["findings"][0]["detail"]["tag"], doc["complete"]), ("v1.0.5", True))


if __name__ == "__main__":
    unittest.main()
