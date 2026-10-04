"""GitHub Actions at their pinned commits (0.1.9, S-2 online half): lazaret.registry.actions.

The checks run against an in-memory GitHub (`_actions_support.FakeGitHub`): a pin
that is in no branch or tag of the repository (an impostor commit from a fork), a
version tag that moved, a tag off the branches, a pin whose comment names another
commit, an action.yml that runs an unpinned image or unpinned steps; and what is
not checked is said (the rate limit, the call budget, a ref that is an expression).
"""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

from lazaret.registry import actions, sources
from lazaret.scanner import ghworkflow
from tests.registry import _actions_support as fx

DIGEST = "sha256:" + "ab" * 32


def release_repo(name="o/act", tags=("v1.0.0", "v1")):
    """A repository with a main branch of three commits, tagged, and a release branch."""
    r = fx.Repo(name)
    yml = {"action.yml": fx.action_yml()}
    c1 = r.commit(files=yml)
    c2 = r.commit(c1, files=yml)
    c3 = r.commit(c2, branch="main", files=yml)
    r.branches["releases/v1"] = c2
    for t in tags:
        r.tag(t, c2)
    r.shas = (c1, c2, c3)
    return r


def workflow(*uses, comments=None):
    """A workflow with a step for each `uses:` value (and its comment)."""
    comments = comments or {}
    steps = "".join(f"      - uses: {u}{('  # ' + comments[u]) if u in comments else ''}\n" for u in uses)
    return f"on: push\npermissions: {{}}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n{steps}"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-actions-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.book_path = os.path.join(self.tmp, "pins.json")

    def audit(self, text, *repos, limit=None, pins=False, **kw):
        self.gh = fx.FakeGitHub(*repos, limit=limit)
        book = actions.PinBook(self.book_path) if pins else None
        return actions.audit_text(text, env={}, http=self.gh, pins=book, **kw)

    def kinds(self, rep):
        return [(f.kind, f.line) for f in rep.findings]


class PinnedTests(Base):
    def test_a_release_commit_is_quiet_and_costs_two_calls(self):
        r = release_repo()
        rep = self.audit(workflow(f"o/act@{r.shas[1]}"), r)
        self.assertEqual(rep.findings, [])
        self.assertTrue(rep.complete)
        self.assertEqual(rep.checked, 1)
        self.assertEqual(len(self.gh.calls), 2)                 # the tags (a tip matches), then action.yml
        self.assertEqual(rep.resolved, {f"o/act@{r.shas[1]}": r.shas[1]})

    def test_a_commit_of_the_default_branch_that_is_not_tagged(self):
        r = release_repo()
        rep = self.audit(workflow(f"o/act@{r.shas[2]}"), r)
        self.assertEqual(rep.findings, [])

    def test_a_commit_only_on_a_release_branch_is_not_an_impostor(self):
        r = release_repo()
        side = r.commit(r.shas[1], branch="releases/v2")       # a backport: not in main's history, not a tag
        rep = self.audit(workflow(f"o/act@{side}"), r)
        self.assertEqual(rep.findings, [])

    def test_an_impostor_commit_from_a_fork(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        rep = self.audit(workflow(f"o/act@{evil}"), r)
        self.assertEqual(self.kinds(rep), [("impostor", 7)])
        d = rep.findings[0].detail
        self.assertEqual((d["sha"], d["complete"], d["owner"], d["repo"]), (evil, True, "o", "act"))
        rule = actions.rule("impostor", d)
        self.assertEqual((rule["id"], rule["sev"]), ("SC-ACTION-IMPOSTOR", "CRITICAL"))
        self.assertIn(evil[:12], rule["msg"])
        self.assertIn("impostor commit", rule["msg"])

    def test_an_impostor_is_a_maybe_when_not_every_branch_was_looked_at(self):
        r = release_repo()
        for i in range(12):
            r.commit(r.shas[1], branch=f"topic-{i:02d}")
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        rep = self.audit(workflow(f"o/act@{evil}"), r)
        self.assertEqual(self.kinds(rep), [("impostor", 7)])
        self.assertFalse(rep.findings[0].detail["complete"])
        rule = actions.rule("impostor", rep.findings[0].detail)
        self.assertEqual(rule["sev"], "MAJOR")
        self.assertIn("may be an impostor", rule["msg"])
        # the default branch and the release branches are looked at first, then at most MAX_BRANCHES in all
        compared = [u for u in self.gh.calls if "/compare/" in u]
        self.assertEqual(len(compared), 1 + actions.MAX_BRANCHES)
        self.assertIn("/compare/main...", compared[0])

    def test_release_branches_are_looked_at_before_the_others(self):
        r = release_repo()
        for i in range(12):
            r.commit(r.shas[0], branch=f"a-topic-{i:02d}")      # sorts before releases/ and v1
        backport = r.commit(r.shas[1], branch="releases/v2")
        rep = self.audit(workflow(f"o/act@{backport}"), r)
        self.assertEqual(rep.findings, [])

    def test_two_pins_of_one_repository_list_its_tags_once(self):
        r = release_repo()
        rep = self.audit(workflow(f"o/act@{r.shas[1]}", f"o/act@{r.shas[2]}", f"o/act@{r.shas[0]}"), r)
        self.assertEqual(rep.findings, [])
        self.assertEqual(self.gh.calls.count("https://api.github.com/repos/o/act/tags?per_page=100"), 1)
        self.assertEqual(len(self.gh.calls), len(set(self.gh.calls)))

    def test_a_commit_that_does_not_exist_is_a_note_not_a_finding(self):
        r = release_repo()
        rep = self.audit(workflow("o/act@" + "0" * 40), r)
        self.assertEqual(rep.findings, [])
        self.assertEqual(len(rep.notes), 1)
        self.assertIn("is not a commit of o/act", rep.notes[0][1])

    def test_a_repository_that_is_not_there(self):
        rep = self.audit(workflow("nobody/nothing@" + "1" * 40))
        self.assertEqual(rep.findings, [])
        self.assertEqual([u for u, _ in rep.incomplete], ["nobody/nothing@" + "1" * 40])     # not checked, so not cleared
        self.assertFalse(rep.complete)


class TagTests(Base):
    def test_a_tag_is_resolved_and_a_floating_tag_is_quiet(self):
        r = release_repo()
        rep = self.audit(workflow("o/act@v1"), r)
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.resolved, {"o/act@v1": r.shas[1]})

    def test_an_annotated_tag_is_followed_to_its_commit(self):
        r = release_repo(tags=())
        r.tag("v2.0.0", r.shas[1], annotated=True)
        rep = self.audit(workflow("o/act@v2.0.0"), r)
        self.assertEqual(rep.resolved, {"o/act@v2.0.0": r.shas[1]})
        self.assertEqual(rep.findings, [])

    def test_a_branch_is_resolved_and_has_no_signals(self):
        r = release_repo()
        rep = self.audit(workflow("o/act@main", "o/act@releases/v1"), r)
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.resolved, {"o/act@main": r.shas[2], "o/act@releases/v1": r.shas[1]})

    def test_a_ref_that_is_nothing(self):
        r = release_repo()
        rep = self.audit(workflow("o/act@v9.9.9"), r)
        self.assertEqual(rep.resolved, {})
        self.assertIn("is neither a tag nor a branch", rep.notes[0][1])

    def test_a_tag_off_the_branches(self):
        r = release_repo()
        stray = r.commit(r.shas[0], fork=True, files={"action.yml": fx.action_yml()})
        r.tag("v3.0.0", stray)
        rep = self.audit(workflow("o/act@v3.0.0"), r)
        self.assertEqual(self.kinds(rep), [("off-branch", 7)])
        d = rep.findings[0].detail
        self.assertEqual((d["tag"], d["sha"], d["complete"]), ("v3.0.0", stray, True))
        self.assertEqual(actions.rule("off-branch", d)["sev"], "MAJOR")
        self.assertIn(stray, actions.rule("off-branch", d)["fix"])

    def test_a_tag_on_a_release_branch_is_fine(self):
        r = release_repo()
        rel = r.commit(r.shas[1], branch="releases/v2")
        r.tag("v2.0.0", rel)
        rep = self.audit(workflow("o/act@v2.0.0"), r)
        self.assertEqual(rep.findings, [])


class MovedTagTests(Base):
    def test_a_version_tag_that_moved(self):
        r = release_repo()
        text = workflow("o/act@v1.0.0")
        self.assertEqual(self.audit(text, r, pins=True).findings, [])          # first seen
        self.assertEqual(self.audit(text, r, pins=True).findings, [])          # and the same again
        was = r.tag_commit("v1.0.0")
        r.tag("v1.0.0", r.shas[2])                                              # moved to the newest commit
        rep = self.audit(text, r, pins=True)
        self.assertEqual(self.kinds(rep), [("tag-moved", 7)])
        d = rep.findings[0].detail
        self.assertEqual((d["tag"], d["was"], d["now"]), ("v1.0.0", was, r.shas[2]))
        self.assertRegex(d["first"], r"^\d{4}-\d\d-\d\dT")
        rule = actions.rule("tag-moved", d)
        self.assertEqual((rule["id"], rule["sev"]), ("SC-ACTION-TAG-MOVED", "CRITICAL"))
        self.assertIn(was[:12], rule["msg"])
        # the alert stays until the move is accepted
        self.assertEqual(self.kinds(self.audit(text, r, pins=True)), [("tag-moved", 7)])
        self.assertEqual(self.audit(text, r, pins=True, accept_moved=True).findings, [])
        self.assertEqual(self.audit(text, r, pins=True).findings, [])

    def test_a_floating_tag_may_move(self):
        r = release_repo()
        text = workflow("o/act@v1")
        self.audit(text, r, pins=True)
        r.tag("v1", r.shas[2])
        self.assertEqual(self.audit(text, r, pins=True).findings, [])

    def test_without_a_pin_book_nothing_is_found_moved(self):
        r = release_repo()
        text = workflow("o/act@v1.0.0")
        self.audit(text, r)
        r.tag("v1.0.0", r.shas[2])
        self.assertEqual(self.audit(text, r).findings, [])
        self.assertFalse(os.path.exists(self.book_path))

    def test_the_book_is_kept_between_runs_and_names_repositories_in_any_case(self):
        r = release_repo()
        self.audit(workflow("O/ACT@v1.0.0"), r, pins=True)
        with open(self.book_path, encoding="utf-8") as f:
            book = json.load(f)
        self.assertEqual(book["version"], 1)
        self.assertEqual(list(book["tags"]), ["o/act@v1.0.0"])
        self.assertEqual(book["tags"]["o/act@v1.0.0"]["sha"], r.shas[1])


class PinBookTests(Base):
    def write(self, text):
        with open(self.book_path, "w", encoding="utf-8") as f:
            f.write(text)

    def test_what_cannot_be_read_is_started_again(self):
        for text in ("", "not json", "[]", '{"version": 2, "tags": {}}', '{"version": 1, "tags": []}', "{" * 5000):
            self.write(text)
            book = actions.PinBook(self.book_path)
            self.assertEqual(book.entries, {}, text[:20])
            self.assertTrue(book.problem, text[:20])
        self.write('{"version": 1, "tags": {"a/b@v1.0.0": {"sha": "%s", "first": "x", "last": "y"}, "bad": 3, '
                   '"c/d@v1.0.0": {"sha": "nope", "first": "x", "last": "y"}}}' % ("a" * 40))
        book = actions.PinBook(self.book_path)
        self.assertEqual(list(book.entries), ["a/b@v1.0.0"])
        self.assertIsNone(book.problem)

    def test_a_path_that_is_not_a_file_is_never_written(self):
        book = actions.PinBook(self.tmp)                        # a folder
        self.assertIsNone(book.path)
        book.see("a/b@v1.0.0", "a" * 40, 0)
        book.save()
        self.assertEqual(os.listdir(self.tmp), [])

    def test_a_path_that_cannot_be_written_costs_nothing(self):
        book = actions.PinBook(os.path.join(self.book_path, "inside", "pins.json"))
        os.makedirs(self.book_path)                              # makes the book's folder impossible
        book.see("a/b@v1.0.0", "a" * 40, 0)
        book.save()                                              # no exception

    def test_sightings(self):
        book = actions.PinBook(self.book_path)
        self.assertIsNone(book.see("a/b@v1.0.0", "a" * 40, 100))
        self.assertIsNone(book.see("a/b@v1.0.0", "a" * 40, 200))
        was = book.see("a/b@v1.0.0", "b" * 40, 300)
        self.assertEqual((was["sha"], was["first"]), ("a" * 40, "1970-01-01T00:01:40Z"))
        self.assertEqual(book.entries["a/b@v1.0.0"]["sha"], "a" * 40)       # the first sighting stays
        self.assertEqual(book.entries["a/b@v1.0.0"]["moved"]["to"], "b" * 40)
        book.accept("a/b@v1.0.0", "b" * 40, 400)
        self.assertNotIn("moved", book.entries["a/b@v1.0.0"])
        self.assertIsNone(book.see("a/b@v1.0.0", "b" * 40, 500))

    def test_the_book_is_capped_and_the_least_recent_are_dropped(self):
        with mock.patch.object(actions, "PIN_ENTRIES", 3):
            book = actions.PinBook(self.book_path)
            for i in range(6):
                book.see(f"a/b@v1.0.{i}", "a" * 40, i * 1000)
            book.save()
            self.assertEqual(sorted(actions.PinBook(self.book_path).entries), ["a/b@v1.0.3", "a/b@v1.0.4", "a/b@v1.0.5"])


class CommentTests(Base):
    def test_a_pin_that_matches_its_comment(self):
        r = release_repo()
        sha = r.shas[1]
        for comment in ("v1.0.0", "v1.0.0 (latest)", "tag=v1.0.0", "ratchet:o/act@v1.0.0"):
            u = f"o/act@{sha}"
            self.assertEqual(self.audit(workflow(u, comments={u: comment}), r).findings, [], comment)

    def test_a_pin_whose_tag_points_elsewhere(self):
        r = release_repo()
        u = f"o/act@{r.shas[0]}"
        rep = self.audit(workflow(u, comments={u: "v1.0.0"}), r)
        self.assertEqual(self.kinds(rep), [("pin-mismatch", 7)])
        d = rep.findings[0].detail
        self.assertEqual((d["tag"], d["tag_sha"], d["pin"]), ("v1.0.0", r.shas[1], r.shas[0]))
        self.assertIn("points to " + r.shas[1][:12], actions.rule("pin-mismatch", d)["msg"])

    def test_a_pin_whose_tag_is_not_there(self):
        r = release_repo()
        u = f"o/act@{r.shas[1]}"
        rep = self.audit(workflow(u, comments={u: "v7.7.7"}), r)
        d = rep.findings[0].detail
        self.assertIsNone(d["tag_sha"])
        self.assertIn("is not a tag of the repository", actions.rule("pin-mismatch", d)["msg"])

    def test_a_floating_or_no_comment_says_nothing(self):
        r = release_repo()
        sha = r.shas[0]                                          # not what v1 points to: floating tags move
        for comment in ("v1", "latest", "the checkout step", "see https://example.invalid/#x"):
            u = f"o/act@{sha}"
            rep = self.audit(workflow(u, comments={u: comment}), r)
            self.assertEqual(rep.findings, [], comment)
        self.assertEqual(self.audit(workflow(f"o/act@{sha}"), r).findings, [])

    def test_the_comment_is_read_from_the_uses_line_only(self):
        text = "on: push\njobs:\n  a:\n    steps:\n      # v7.7.7\n      - uses: o/act@" + "1" * 40 + "\n"
        self.assertEqual(actions.uses_of(text), [(6, "o/act@" + "1" * 40, "")])
        text = "on: push\njobs:\n  a:\n    steps:\n      - uses: 'o/act@" + "1" * 40 + "' # v1.2.3\n"
        self.assertEqual(actions.uses_of(text)[0][2], "v1.2.3")


class NotCheckedTests(Base):
    def test_what_cannot_be_looked_up_is_said_and_costs_no_call(self):
        r = release_repo()
        values = ["o/act@${{ matrix.v }}", "o/act", "o/act@", "o/act/../../x@v1", "o/act@v1?x=1",
                  "o/act@a..b", "-bad/act@v1", "o/" + "a" * 101 + "@v1", "o/act/sub//dir@v1"]
        rep = self.audit(workflow(*values), r)
        self.assertEqual(self.gh.calls, [])
        self.assertEqual(rep.findings, [])
        self.assertEqual(len(rep.incomplete), len(values))
        self.assertFalse(rep.complete)

    def test_local_paths_and_images_need_nothing(self):
        rep = self.audit(workflow("./local", "./.github/actions/x", f"docker://alpine@{DIGEST}", "docker://alpine:3"))
        self.assertEqual(self.gh.calls, [])
        self.assertTrue(rep.complete)
        self.assertEqual(rep.checked, 0)

    def test_only_the_api_host_is_asked_and_names_are_quoted(self):
        r = release_repo()
        self.audit(workflow("o/act@releases/v1", "o/act/sub@v1"), r)
        for url in self.gh.calls:
            self.assertTrue(url.startswith("https://api.github.com/repos/o/act"), url)

    def test_the_rate_limit_stops_the_run_and_leaves_the_rest_unchecked(self):
        a, b = release_repo("o/a"), release_repo("o/b")
        rep = self.audit(workflow(f"o/a@{a.shas[1]}", f"o/b@{b.shas[1]}", "o/b@v1"), a, b, limit=2)
        self.assertEqual(len(self.gh.calls), 3)                  # nothing is asked after the answer that said stop
        self.assertEqual(rep.findings, [])
        self.assertEqual([u for u, _ in rep.incomplete], [f"o/b@{b.shas[1]}", "o/b@v1"])
        self.assertIn("rate limit reached", rep.incomplete[0][1])
        self.assertFalse(rep.complete)

    def test_the_call_budget(self):
        a = release_repo("o/a")
        rep = self.audit(workflow("o/a@v1", "o/a@main"), a, max_calls=1)
        self.assertEqual(len(self.gh.calls), 1)
        self.assertEqual(len(rep.incomplete), 2)
        self.assertIn("budget of 1 API calls is spent", rep.incomplete[0][1])
        self.assertIn("GITHUB_TOKEN", rep.incomplete[0][1])      # no token: it says what raises the limit

    def test_the_default_budgets(self):
        self.assertEqual(actions.Auditor(env={}, http=fx.FakeGitHub()).max_calls, actions.CALLS_ANONYMOUS)
        self.assertEqual(actions.Auditor(env={"GITHUB_TOKEN": "ghp_NotARealTokenJustTestText1234567890"},
                                         http=fx.FakeGitHub()).max_calls, actions.CALLS_TOKEN)

    def test_a_failure_is_asked_once_and_the_others_go_on(self):
        a = release_repo("o/a")
        rep = self.audit(workflow("gone/x@v1", "gone/x@v1", f"o/a@{a.shas[1]}"), a)
        self.assertEqual(self.gh.calls.count("https://api.github.com/repos/gone/x/git/ref/tags/v1"), 1)
        self.assertEqual(rep.findings, [])
        self.assertEqual(rep.checked, 2)

    def test_a_server_error_is_asked_once_for_an_action_used_twice(self):
        a = release_repo("o/a")
        gh = fx.FakeGitHub(a)
        gh.broken["/repos/o/a/git/ref/tags/v1"] = 500
        rep = actions.audit_text(workflow("o/a@v1", "o/a@v1"), env={}, http=gh)
        self.assertEqual(gh.calls.count("https://api.github.com/repos/o/a/git/ref/tags/v1"), 1)
        self.assertEqual([u for u, _ in rep.incomplete], ["o/a@v1", "o/a@v1"])

    def test_a_token_goes_to_the_api_only_and_is_in_no_report(self):
        token = "ghp_NotARealTokenJustTestText1234567890"
        r = release_repo()
        gh = fx.FakeGitHub(r)
        rep = actions.audit_text(workflow(f"o/act@{r.shas[1]}"), env={"GITHUB_TOKEN": token}, http=gh)
        self.assertTrue(all(h.get("Authorization") == f"Bearer {token}" for _, h in gh.headers))
        self.assertNotIn(token, json.dumps(rep.to_json()))
        with self.assertRaises(sources.SourceError):
            actions.audit_text(workflow("o/act@v1"), env={"GITHUB_TOKEN": "bad token\n"}, http=gh)

    def test_one_action_on_two_lines_is_asked_about_once(self):
        r = release_repo()
        u = f"o/act@{r.shas[1]}"
        rep = self.audit(workflow(u, "o/act@v1", u), r)
        self.assertEqual(rep.checked, 2)
        self.assertEqual(len(self.gh.calls), len(set(self.gh.calls)))        # no URL asked twice


class ActionYmlTests(Base):
    def repo_with(self, yml, name="o/act"):
        r = fx.Repo(name)
        c = r.commit(files={"action.yml": yml})
        r.commit(c, branch="main")
        r.tag("v1.0.0", c)
        r.sha = c
        return r

    def test_a_docker_action_with_an_image_that_is_not_pinned(self):
        r = self.repo_with(fx.action_yml("docker", image="docker://ghcr.io/o/img:1.2"))
        rep = self.audit(workflow(f"o/act@{r.sha}"), r)
        self.assertEqual(self.kinds(rep), [("docker-unpinned", 7)])
        self.assertEqual(rep.findings[0].detail["image"], "docker://ghcr.io/o/img:1.2")
        self.assertEqual(actions.rule("docker-unpinned", rep.findings[0].detail)["id"], "SC-ACTION-DOCKER-UNPINNED")

    def test_a_docker_action_with_a_digest_or_a_dockerfile(self):
        r = self.repo_with(fx.action_yml("docker", image=f"docker://ghcr.io/o/img@{DIGEST}"))
        self.assertEqual(self.audit(workflow(f"o/act@{r.sha}"), r).findings, [])
        r = self.repo_with(fx.action_yml("docker", image="Dockerfile"))
        rep = self.audit(workflow(f"o/act@{r.sha}"), r)
        self.assertEqual(rep.findings, [])
        self.assertIn("builds its image from Dockerfile", rep.notes[0][1])

    def test_a_node_action_reports_what_runs(self):
        r = self.repo_with(fx.action_yml("node20", main="dist/index.js", pre="dist/pre.js", post="dist/post.js"))
        rep = self.audit(workflow(f"o/act@{r.sha}"), r)
        self.assertEqual(rep.actions[f"o/act@{r.sha}"], {"using": "node20", "pre": True, "post": True})
        self.assertEqual(rep.findings, [])

    def test_a_composite_action_with_an_unpinned_step(self):
        inner = release_repo("o/inner")
        r = self.repo_with(fx.action_yml("composite", steps=["o/inner@v1.0.0", "actions/checkout@v4", "./local",
                                                              f"o/inner@{inner.shas[1]}"]))
        rep = self.audit(workflow(f"o/act@{r.sha}"), r, inner)
        kinds = [(f.kind, f.detail.get("nested")) for f in rep.findings]
        self.assertEqual(kinds, [("nested-unpinned", "o/inner@v1.0.0"), ("nested-unpinned", "actions/checkout@v4")])
        self.assertEqual({f.line for f in rep.findings}, {7})
        rules = {f.detail["nested"]: actions.rule(f.kind, f.detail) for f in rep.findings}
        self.assertEqual(rules["o/inner@v1.0.0"]["sev"], "MAJOR")
        self.assertEqual(rules["actions/checkout@v4"]["sev"], "MINOR")        # GitHub's own, at a version tag
        self.assertIn(f"{r.sha[:0]}o/act", rules["o/inner@v1.0.0"]["msg"])
        # what it uses was looked at as well: o/inner@v1.0.0 resolved
        self.assertEqual(rep.resolved["o/inner@v1.0.0"], inner.shas[1])

    def test_a_nested_impostor_is_found_and_says_through_what(self):
        inner = release_repo("o/inner")
        evil = inner.commit(inner.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        r = self.repo_with(fx.action_yml("composite", steps=[f"o/inner@{evil}"]))
        rep = self.audit(workflow(f"o/act@{r.sha}"), r, inner)
        self.assertEqual(self.kinds(rep), [("impostor", 7)])
        d = rep.findings[0].detail
        self.assertEqual(d["via"], [f"o/act@{r.sha}"])
        self.assertIn(f"(through o/act@{r.sha})", actions.rule("impostor", d)["msg"])

    def test_composites_that_nest_are_followed_two_levels_and_a_loop_ends(self):
        a, b, c = fx.Repo("o/a"), fx.Repo("o/b"), fx.Repo("o/c")
        for repo, nxt in ((a, "o/b"), (b, "o/c"), (c, "o/a")):                  # a -> b -> c -> a
            sha = repo.commit(files={"action.yml": fx.action_yml("composite", steps=[nxt + "@v1"])})
            repo.commit(sha, branch="main")
            repo.tag("v1", sha)
        rep = self.audit(workflow("o/a@v1"), a, b, c)
        self.assertEqual(rep.checked, 3)
        self.assertLess(len(self.gh.calls), 40)
        self.assertEqual({f.kind for f in rep.findings}, {"nested-unpinned"})

    def test_an_action_in_a_subdirectory_and_one_without_an_action_yml(self):
        r = fx.Repo("o/mono")
        c = r.commit(files={"build/action.yaml": fx.action_yml("docker", image="docker://x:1")})
        r.commit(c, branch="main")
        rep = self.audit(workflow(f"o/mono/build@{c}", f"o/mono/missing@{c}"), r)
        self.assertEqual([f.kind for f in rep.findings], ["docker-unpinned"])
        self.assertIn("no action.yml or action.yaml", rep.notes[0][1])

    def test_a_reusable_workflow_gets_the_ref_signals_and_no_action_yml(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True)
        text = f"on: push\njobs:\n  call:\n    uses: o/act/.github/workflows/w.yml@{evil}\n"
        rep = self.audit(text, r)
        self.assertEqual(self.kinds(rep), [("impostor", 4)])
        self.assertFalse([u for u in self.gh.calls if "/contents/" in u])


class RuleTests(unittest.TestCase):
    D = {"owner": "o", "repo": "r", "via": []}
    CASES = {
        "impostor": {"sha": "a" * 40, "complete": True},
        "tag-moved": {"tag": "v1.0.0", "was": "a" * 40, "now": "b" * 40, "first": "2026-10-03T00:00:00Z"},
        "off-branch": {"tag": "v1.0.0", "sha": "a" * 40, "complete": False},
        "pin-mismatch": {"tag": "v1.0.0", "tag_sha": "b" * 40, "pin": "a" * 40},
        "docker-unpinned": {"image": "docker://x:1"},
        "nested-unpinned": {"nested": "a/b@v1", "kind": "action", "first": False, "tag": True},
    }

    def test_each_rule_has_what_mk_issue_takes(self):
        ids = set()
        for kind, detail in self.CASES.items():
            rule = actions.rule(kind, dict(self.D, **detail))
            self.assertEqual(sorted(rule), ["fix", "id", "msg", "name", "ref", "sev", "type", "why"], kind)
            self.assertTrue(rule["id"].startswith("SC-ACTION-"), kind)
            self.assertEqual(rule["type"], "HOTSPOT")
            self.assertIn(rule["sev"], ("MINOR", "MAJOR", "CRITICAL"))
            self.assertTrue(all(isinstance(rule[k], str) and rule[k] for k in ("msg", "why", "fix", "name", "ref")), kind)
            ids.add(rule["id"])
        self.assertEqual(len(ids), 6)


class CommandTests(Base):
    def run_main(self, argv, *repos, limit=None):
        gh = fx.FakeGitHub(*repos, limit=limit)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sources, "_http", gh), mock.patch.dict(os.environ, {"GITHUB_TOKEN": ""}), \
                redirect_stdout(out), redirect_stderr(err):
            code = actions.main(argv)
        return code, out.getvalue(), err.getvalue(), gh

    def write(self, text, name="ci.yml"):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_usage(self):
        for argv in ([], ["--nope", "x"], ["--max-calls"], ["--max-calls", "x", "f"], ["--pins"]):
            code, out, err, _ = self.run_main(argv)
            self.assertEqual(code, 2, argv)
            self.assertIn("usage:", err)
        code, _, err, _ = self.run_main([os.path.join(self.tmp, "none.yml")])
        self.assertEqual(code, 2)
        self.assertIn("none.yml", err)

    def test_exit_codes_and_the_json(self):
        r = release_repo()
        evil = r.commit(r.shas[2], fork=True, files={"action.yml": fx.action_yml()})
        clean = self.write(workflow(f"o/act@{r.shas[1]}"), "clean.yml")
        bad = self.write(workflow(f"o/act@{evil}"), "bad.yml")
        unknown = self.write(workflow("o/act@${{ x }}"), "unknown.yml")
        code, out, _, _ = self.run_main(["--no-pins", clean], r)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)[0]["file"], clean)
        code, out, _, _ = self.run_main(["--no-pins", bad], r)
        self.assertEqual(code, 1)
        doc = json.loads(out)[0]
        self.assertEqual(doc["findings"][0]["kind"], "impostor")
        self.assertEqual(doc["rules"][0]["id"], "SC-ACTION-IMPOSTOR")
        code, out, _, _ = self.run_main(["--no-pins", unknown], r)
        self.assertEqual(code, 3)
        self.assertFalse(json.loads(out)[0]["complete"])

    def test_the_pin_book_option(self):
        r = release_repo()
        wf = self.write(workflow("o/act@v1.0.0"))
        book = os.path.join(self.tmp, "book.json")
        self.assertEqual(self.run_main(["--pins", book, wf], r)[0], 0)
        r.tag("v1.0.0", r.shas[2])
        self.assertEqual(self.run_main(["--pins", book, wf], r)[0], 1)
        self.assertEqual(self.run_main(["--pins", book, "--accept-moved", wf], r)[0], 0)
        self.assertEqual(self.run_main(["--pins", book, wf], r)[0], 0)

    def test_the_budget_option(self):
        r = release_repo()
        wf = self.write(workflow("o/act@v1", "o/act@main"))
        code, out, _, gh = self.run_main(["--no-pins", "--max-calls", "1", wf], r)
        self.assertEqual((code, len(gh.calls)), (3, 1))


class UsesTests(unittest.TestCase):
    def test_ghworkflow_uses_and_parse_uses(self):
        text = ("on: push\njobs:\n  call:\n    uses: o/r/.github/workflows/w.yml@v1\n  b:\n    runs-on: x\n"
                "    steps:\n      - uses: a/b@v1\n        with:\n          uses: not-a-step\n      - run: echo uses\n")
        self.assertEqual(ghworkflow.uses(text), [(4, "o/r/.github/workflows/w.yml@v1"), (8, "a/b@v1")])
        self.assertEqual(ghworkflow.parse_uses("a/b/c@v1"), ("action", "a/b/c", "v1", False))
        self.assertEqual(ghworkflow.parse_uses("./x"), None)
        self.assertEqual(ghworkflow.parse_uses("docker://a:1")[0], "docker")

    def test_parse_use(self):
        use, why = actions.parse_use(3, "Owner/Repo/sub/dir@" + "AB" * 20, "v1.0.0")
        self.assertIsNone(why)
        self.assertEqual((use.owner, use.repo, use.path, use.ref, use.pinned, use.comment),
                         ("Owner", "Repo", "sub/dir", "ab" * 20, True, "v1.0.0"))
        self.assertEqual(actions.parse_use(1, "./x"), (None, None))
        self.assertEqual(actions.parse_use(1, "docker://a:1"), (None, None))
        self.assertEqual(actions.parse_use(1, "o/r/.github/workflows/w.yml@v1")[0].kind, "workflow")


if __name__ == "__main__":
    unittest.main()
