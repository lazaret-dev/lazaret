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
LAZARET_NO_ACTION_BRANCHES; the command's --db.
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
        # the actions-cool shape: the floating tag and the release tag both moved onto the imposter
        r = release_repo(tags=("v2", "v2.1.0"))
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        r.tag("v2", evil)
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
        # the repository, its branches, the compares and action.yml: nothing more for the branch check
        self.assertEqual(len(api_calls(self.gh)), 2 + actionrefs.MAX_COMPARES + 1)
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
        self.assertEqual(len(api_calls(self.gh)), 3)           # the repository, main, the branches: then no more
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
        self.assertEqual([f.kind for f in rep.findings], ["impostor"] * 4)
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


class TagConn(FakeConn):
    """The Store's fake Postgres connection, the action_tags statements run on SQLite ($n as ?n)."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.db = sqlite3.connect(":memory:")
        self.sent = []

    def execute_script(self, sql):
        super().execute_script(sql)
        for statement in sql.split(";"):
            if "action_tags" in statement:
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
        self.assertIn("VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (repo,tag) DO UPDATE", insert)
        select = next(s for s, _ in conn.sent if s.startswith("SELECT"))
        self.assertIn("WHERE repo=$1 AND tag=$2", select)


class CommandTests(Base):
    def run_main(self, argv, *repos):
        gh = fx.FakeGitHub(*repos)
        out, err = io.StringIO(), io.StringIO()
        env = {"GITHUB_TOKEN": "", actionrefs.OFF_ENV: "", "LAZARET_ACTIONS_PINS": self.book_path}
        with mock.patch.object(sources, "_http", gh), mock.patch.dict(os.environ, env), \
                redirect_stdout(out), redirect_stderr(err):
            code = actions.main(argv)
        return code, out.getvalue(), err.getvalue()

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


if __name__ == "__main__":
    unittest.main()
