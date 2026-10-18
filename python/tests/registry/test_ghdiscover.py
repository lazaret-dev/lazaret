"""Finding new public GitHub repositories and scanning the likely-hostile ones (GH-NEW-REPOS:
lazaret.registry.ghdiscover, `lazaret-registry discover --ecosystem github --resume`).

GitHub is a fake throughout (the network seam of sources.Client): pages of `/repositories`, `/repos/{owner}/{repo}`
answers, archives built in memory. The repositories that look hostile are made of the repository's existing inert
test fixtures (the project-hook tests' file of five `_0x` names, test_hook's workflow and install hook, all with
.invalid hosts); nothing is fetched or run. Covered: the first run's search for the newest repository; resuming across
runs and after a run stopped mid-listing; the run's call budget and GitHub's rate limit; each filter (a look-alike
such as shopsprint/decimal, a copy with the original's description, campaign markers in any case and separator,
your own patterns); a campaign repository never downloaded; the content checks' backoff and the candidates dropped
(empty, gone, made private); the verdict leaving out CI hardening below CRITICAL; an incomplete checkout INCOMPLETE;
the CLI (--resume, the token, --ci, list, report, scan github:…); the candidates table on Postgres's wire statements.
"""

import contextlib
import datetime
import io
import json
import os
import re
import sqlite3
import tempfile
import unittest
from unittest import mock

from lazaret.registry import ghdiscover, lookalike, repo, sources
from lazaret.registry.sources import SourceError
from tests.registry.test_review_store_reconnect import FakeConn, pg_store
from tests.registry.test_sources import TOKEN, make_archive
from tests.scanner.test_hook import HOOK_DOWNLOADS, WORKFLOW
from tests.scanner.test_review_project_hooks import OBF

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 10, 14, 12, 0, tzinfo=UTC)
ENV = {"GITHUB_TOKEN": TOKEN}
SHA = "0123456789abcdef0123456789abcdef01234567"
API = "https://api.github.com"


def at(hours):
    return NOW + datetime.timedelta(hours=hours)


def item(rid, full, description=None, fork=False):
    owner, name = full.split("/")
    return {"id": rid, "node_id": node_id(rid), "full_name": full, "name": name, "owner": {"login": owner},
            "description": description, "fork": fork, "private": False}


def node_id(rid):
    """A listed repository's node ID, in GitHub's shape (made up)."""
    return f"R_kgDO{rid:08d}"


def failure(text, status):
    err = SourceError(text)
    err.status = status
    return err


#: a repository's files: hostile shapes made of the inert fixtures, a benign one, one only hardening flags
HOSTILE = {
    "package.json": json.dumps({"name": "app", "version": "1.0.0", "scripts": {"preinstall": "node lib/setup.mjs"}}),
    "lib/setup.mjs": OBF,
    ".vscode/tasks.json": json.dumps({"version": "2.0.0", "tasks": [
        {"label": "dev", "command": "node lib/setup.mjs", "runOptions": {"runOn": "folderOpen"}}]}),
    ".github/workflows/ci.yml": WORKFLOW,
    "tools/package.json": HOOK_DOWNLOADS,
}
BENIGN = {"README.md": "# a tool\n", "src/main.py": "def main():\n    return 1\n"}
UNPINNED = {"README.md": "# a tool\n", ".github/workflows/ci.yml": (
    "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
    "      - uses: actions/checkout@v4\n      - run: echo hi\n")}


def rules(res, sev=None):
    """The rules of a scan's findings (of one severity)."""
    return {i["rule"] for i in res["issues"] if sev is None or i["sev"] == sev}


class FakeGitHub:
    """The network seam: GitHub's listing, repositories and archives, and its GraphQL API (GH-SCAN-GQL: a POST of
    `nodes(ids:)`); every URL asked for is kept, and every GraphQL call's node IDs (`posts`)."""

    def __init__(self, repos=(), info=None, files=None, page=100, remaining=None, truncated=(), code=()):
        self.repos = sorted(repos, key=lambda r: r["id"])
        self.info = dict(info or {})          # full_name -> /repos answer, or an HTTP status
        self.files = dict(files or {})        # full_name -> {path: text}: what a scan fetches
        self.page, self.remaining, self.truncated = page, remaining, set(truncated)
        self.fail, self.seen, self.pages = {}, [], {}     # pages: since -> a page served as it is
        self.code = set(code)                 # GraphQL: the repository IDs that have code (the others are empty)
        self.nodes = {}                       # node ID -> the node GraphQL answers with (None: null), over the default
        self.answers = []                     # the next GraphQL calls' answers, in turn: a document, bytes or an error
        self.posts, self.bodies, self.points = [], [], 5000

    def __call__(self, url, headers, max_bytes, hosts, auth_host, reply_headers=None, method="GET", data=None,
                 **kw):
        self.seen.append(url)
        if method == "POST":
            return self._graphql(url, headers, data, hosts, reply_headers)
        self._count(reply_headers)
        if url in self.fail:
            raise self.fail[url]
        m = re.fullmatch(re.escape(API) + r"/repositories\?since=(\d+)", url)
        if m:
            return self._listing(int(m.group(1)))
        m = re.fullmatch(re.escape(API) + r"/repos/([^/]+/[^/]+)(/.*)?", url)
        if m and not m.group(2):
            return self._repository(m.group(1))
        if m and m.group(1) in self.files:
            body = self._content(m.group(1), m.group(2))
            if body is not None:
                return body
        raise SourceError(f"no answer for {url}")

    def node(self, rid):
        """The node GraphQL answers for a listed repository: empty, or with code when `code` has it (a fork made at
        11:59 and pushed to at 12:30)."""
        listed = next(r for r in self.repos if r["id"] == rid)
        has = rid in self.code
        return {"databaseId": rid, "nameWithOwner": listed["full_name"], "isEmpty": not has,
                "isFork": bool(listed.get("fork")), "isPrivate": False, "createdAt": "2026-10-14T11:59:00Z",
                "pushedAt": "2026-10-14T12:30:00Z" if has else None, "diskUsage": 12 if has else 0}

    def _graphql(self, url, headers, data, hosts, reply_headers):
        if url != f"{API}/graphql" or hosts != {"api.github.com"}:
            raise SourceError(f"no answer for a POST to {url}")
        doc = json.loads(data)
        self.bodies.append((doc, dict(headers)))
        ids = doc["variables"]["ids"]
        self.posts.append(ids)
        if self.answers:
            ans = self.answers.pop(0)
            if isinstance(ans, tuple):                  # (an answer, and the headers it comes with)
                ans, more = ans
                if reply_headers is not None:
                    reply_headers.update(more)
            if isinstance(ans, Exception):
                raise ans
            return ans if isinstance(ans, bytes) else json.dumps(ans).encode()
        by_node = {r.get("node_id"): r["id"] for r in self.repos}
        nodes = [self.nodes[n] if n in self.nodes else self.node(by_node[n]) if n in by_node else None for n in ids]
        errors = [{"type": "NOT_FOUND", "path": ["nodes", i], "message": f"Could not resolve to a node with the "
                   f"global id of '{n}'"} for i, n in enumerate(ids) if nodes[i] is None]
        self.points -= 1
        if reply_headers is not None:
            reply_headers.update({"x-ratelimit-remaining": str(self.points), "x-ratelimit-resource": "graphql"})
        answer = {"data": {"nodes": nodes, "rateLimit": {"cost": 1, "remaining": self.points,
                                                         "resetAt": "2026-10-14T13:00:00Z"}}}
        if errors:
            answer["errors"] = errors
        return json.dumps(answer).encode()

    def _count(self, reply_headers):
        if self.remaining is None:
            return
        self.remaining -= 1
        if reply_headers is not None:
            reply_headers["x-ratelimit-remaining"] = str(self.remaining)

    def _listing(self, since):
        if since in self.pages:
            return json.dumps(self.pages[since]).encode()
        return json.dumps([r for r in self.repos if r["id"] > since][:self.page]).encode()

    def _repository(self, full):
        ans = self.info.get(full, 404)
        if isinstance(ans, int):
            raise failure(f"checking: HTTP {ans}", ans)
        return json.dumps(ans).encode()

    def _content(self, full, rest):
        files = {p: t.encode() for p, t in self.files[full].items()}
        if rest == "/commits/HEAD":
            return SHA.encode()
        if rest == f"/tarball/{SHA}":
            return make_archive(SHA, files)
        if rest == f"/git/trees/{SHA}?recursive=1":
            return json.dumps({"sha": SHA, "truncated": full in self.truncated,
                               "tree": [{"path": p, "type": "blob", "mode": "100644"} for p in files]}).encode()
        return None

    def asked(self, text):
        return [u for u in self.seen if text in u]


class Case(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.db = os.path.join(d.name, "state.db")
        self.store = repo.Store(self.db)
        self.addCleanup(self.store.close)

    def run_gh(self, gh, when=NOW, **kw):
        kw.setdefault("filters", ghdiscover.Filters())
        return ghdiscover.run(self.store, env=ENV, http=gh, now=when, **kw)

    def candidates(self):
        return {c["full_name"]: c for c in self.store.github_candidates()}


class ListingTests(Case):
    def test_the_first_run_finds_the_newest_repository_and_lists_nothing(self):
        gh = FakeGitHub([item(1_100_000_000 + k, f"o{k}/r{k}") for k in range(1, 251)])
        out = self.run_gh(gh)
        self.assertTrue(out["first"])
        self.assertEqual(out["cursor"], 1_100_000_250)
        self.assertEqual(self.store.discovery_cursor("github")[0], "1100000250")
        self.assertEqual((out["listed"], out["stopped"]), (0, None))
        self.assertLess(len(gh.seen), 40)                          # a search, not a walk
        self.assertEqual(self.store.github_candidates(), [])

    def test_a_first_run_without_the_budget_for_the_search_stores_nothing(self):
        out = self.run_gh(FakeGitHub([item(1_100_000_001, "o/r")]), max_calls=3)
        self.assertIsNone(self.store.discovery_cursor("github"))
        self.assertIn("before the newest repository was found", out["stopped"])

    def test_a_resumed_run_lists_every_new_repository_and_keeps_the_candidates(self):
        self.store.save_discovery_cursor("github", 1000, NOW)
        repos = [item(1000 + k, f"user{k}/project{k}", "a project") for k in range(1, 251)]
        repos[10] = item(1011, "shopsprint/decimal", "decimals")
        repos[20] = item(1021, "victim/SHAI_hulud")
        repos[30] = item(1031, "victim2/random-name", "sha1 hulud: the SECOND coming")
        gh = FakeGitHub(repos + [item(900, "old/one")])
        out = self.run_gh(gh)
        self.assertEqual((out["listed"], out["pages"], out["caughtUp"], out["cursor"]), (250, 3, True, 1250))
        self.assertEqual(self.store.discovery_cursor("github")[0], "1250")
        kept = self.candidates()
        self.assertEqual(sorted(kept), ["shopsprint/decimal", "victim/SHAI_hulud", "victim2/random-name"])
        look = kept["shopsprint/decimal"]
        self.assertEqual((look["state"], look["next_check"]), ("waiting", "2026-10-14T13:00:00+00:00"))
        self.assertIn('look-alike: its owner \'shopsprint\' is one change from "shopspring"', look["filters"][0])
        self.assertEqual({kept[n]["state"] for n in ("victim/SHAI_hulud", "victim2/random-name")}, {"reported"})
        self.assertEqual([(f, url) for f, _m, url in out["campaigns"]],
                         [("victim/SHAI_hulud", "https://github.com/victim/SHAI_hulud"),
                          ("victim2/random-name", "https://github.com/victim2/random-name")])
        self.assertEqual(out["matches"], {"campaign marker": 2, "look-alike": 1})

    def test_a_campaign_repository_is_never_downloaded(self):
        self.store.save_discovery_cursor("github", 1000, NOW)
        gh = FakeGitHub([item(1001, "victim/shai-hulud")], info={"victim/shai-hulud": {"size": 10}},
                        files={"victim/shai-hulud": BENIGN})
        for when in (NOW, at(1), at(2), at(80)):
            self.run_gh(gh, when=when, scan=True)
        self.assertEqual(gh.asked("victim"), [])                   # not checked, not fetched, ever
        self.assertEqual(self.candidates()["victim/shai-hulud"]["state"], "reported")

    def test_the_budget_stops_the_listing_and_the_next_run_goes_on(self):
        self.store.save_discovery_cursor("github", 0, NOW)
        gh = FakeGitHub([item(k, f"user{k}/project{k}") for k in range(1, 351)])
        first = self.run_gh(gh, max_calls=2)
        self.assertEqual((first["listed"], first["cursor"], first["caughtUp"]), (200, 200, False))
        self.assertIn("--max-calls", first["stopped"])
        second = self.run_gh(gh, max_calls=10)
        self.assertEqual((second["listed"], second["cursor"], second["caughtUp"]), (150, 350, True))

    def test_an_item_that_is_not_a_repository_is_left_out(self):
        self.store.save_discovery_cursor("github", 1000, NOW)
        odd = [item(1001, "shopsprint/decimal"), {**item(1002, "a/b"), "full_name": "shopsprint/../x"},
               {**item(1003, "a/b"), "full_name": "shopsprint/d?x=1"}, {**item(1004, "a/b"), "id": "1004"},
               {**item(1005, "a/b"), "full_name": "a/b@main"}, "text", {**item(1006, "a/b"), "full_name": "-bad/x"}]
        gh = FakeGitHub()
        gh.pages[1000] = odd
        out = self.run_gh(gh)
        self.assertEqual((out["listed"], sorted(self.candidates())), (1, ["shopsprint/decimal"]))

    def test_a_page_listed_again_changes_no_candidate(self):
        self.store.save_discovery_cursor("github", 1000, NOW)
        gh = FakeGitHub([item(1001, "shopsprint/decimal")])
        self.run_gh(gh)
        self.store.update_github_candidate(1001, state="ready", size=5)
        self.store.save_discovery_cursor("github", 1000, NOW)      # (a run that stopped before its cursor)
        self.run_gh(gh, when=at(0.5))
        cand = self.candidates()["shopsprint/decimal"]
        self.assertEqual((cand["state"], cand["size"]), ("ready", 5))

    def test_the_rate_limit_stops_the_run(self):
        self.store.save_discovery_cursor("github", 0, NOW)
        gh = FakeGitHub([item(k, f"user{k}/p{k}") for k in range(1, 1001)], remaining=ghdiscover.RATE_FLOOR + 2)
        out = self.run_gh(gh)
        self.assertEqual(out["pages"], 2)
        self.assertIn("rate limit is nearly spent (25 requests left", out["stopped"])
        self.assertEqual(self.store.discovery_cursor("github")[0], "200")

    def test_a_rate_limit_answer_stops_the_run_and_keeps_the_cursor(self):
        self.store.save_discovery_cursor("github", 0, NOW)
        gh = FakeGitHub([item(k, f"user{k}/p{k}") for k in range(1, 301)])
        gh.fail[f"{API}/repositories?since=100"] = failure("listing new repositories: rate limit reached, wait "
                                                           "until 13:00 UTC", 403)
        out = self.run_gh(gh)
        self.assertIn("rate limit reached", out["stopped"])
        self.assertEqual((out["errors"], self.store.discovery_cursor("github")[0]), ([], "100"))

    def test_another_error_is_one(self):
        self.store.save_discovery_cursor("github", 0, NOW)
        gh = FakeGitHub([item(1, "a/b")])
        gh.fail[f"{API}/repositories?since=0"] = failure("listing new repositories: the token was refused "
                                                         "(HTTP 401)", 401)
        out = self.run_gh(gh)
        self.assertEqual(len(out["errors"]), 1)
        self.assertIn("HTTP 401", out["stopped"])

    def test_no_token_no_run(self):
        with self.assertRaisesRegex(ghdiscover.DiscoveryError, "needs GITHUB_TOKEN"):
            ghdiscover.run(self.store, env={}, http=FakeGitHub(), now=NOW)


class FilterTests(unittest.TestCase):
    def match(self, rid, full, description=None, fork=False, **kw):
        return ghdiscover.Filters(**kw).match(item(rid, full, description, fork))

    def test_look_alikes(self):
        self.assertTrue(self.match(1, "boltdb-go/bolt")[0])
        self.assertTrue(self.match(1, "spf31/cobra", fork=True)[0])        # a fork is no excuse
        for full in ("shopspring/decimal", "spf13/cobra", "someone/decimal", "rs/zerolog2"):
            with self.subTest(full=full):
                self.assertEqual(self.match(1, full), ([], None))

    def test_campaign_markers_fold_case_and_separators(self):
        for full, desc in (("a/Shai-Hulud", None), ("a/shai_hulud", None), ("a/SHAIHULUD", None),
                           ("a/x", "Shai-Hulud Migration"), ("a/x", "shai hulud  migration!"),
                           ("a/x", "Sha1-Hulud: The Second Coming.")):
            with self.subTest(full=full, desc=desc):
                found, marker = self.match(1, full, desc)
                self.assertTrue(marker and found[0].startswith("campaign marker: "))
        for full, desc in (("a/shai-hulud-scanner", None), ("a/x", "Detects Shai-Hulud")):
            with self.subTest(full=full, desc=desc):
                self.assertIsNone(self.match(1, full, desc)[1])

    def test_a_copy_with_the_originals_description(self):
        tables = (lookalike._load()["github"][0], {"decimal": [("shopspring", "Arbitrary-precision decimals")]})
        self.assertEqual(self.match(1, "someone/decimal", "arbitrary-precision  DECIMALS", tables=tables)[0],
                         ["copy: shopspring/decimal's name and description under another owner"])
        for desc, fork in (("Arbitrary-precision decimals", True), ("my decimals", False), (None, False)):
            with self.subTest(desc=desc, fork=fork):
                self.assertEqual(self.match(1, "someone/decimal", desc, fork, tables=tables)[0], [])

    def test_your_own_patterns(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "f.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"include": {"full_name": ["(?i)wallet"], "description": ["airdrop"]},
                           "exclude": {"full_name": ["^trusted-org/"]}}, f)
            patterns = ghdiscover.load_patterns(path)
        self.assertEqual(self.match(1, "x/my-Wallet", patterns=patterns)[0],
                         ["pattern: full_name matches '(?i)wallet'"])
        self.assertEqual(self.match(1, "x/y", "free airdrop", patterns=patterns)[0],
                         ["pattern: description matches 'airdrop'"])
        self.assertEqual(self.match(1, "trusted-org/wallet", patterns=patterns), ([], None))
        self.assertTrue(self.match(1, "trusted-org/shai-hulud", patterns=patterns)[1])   # never excluded

    def test_a_patterns_file_that_is_not_one(self):
        with tempfile.TemporaryDirectory() as d:
            for doc in ({"include": {"owner": ["x"]}}, {"include": {"full_name": ["("]}}, ["x"],
                        {"include": {"full_name": "x"}}, {"other": {}}):
                with self.subTest(doc=doc):
                    path = os.path.join(d, "f.json")
                    with open(path, "w", encoding="utf-8") as f:
                        json.dump(doc, f)
                    with self.assertRaises(ghdiscover.DiscoveryError):
                        ghdiscover.load_patterns(path)
            with self.assertRaises(ghdiscover.DiscoveryError):
                ghdiscover.load_patterns(os.path.join(d, "missing.json"))


class ContentTests(Case):
    def keep(self, *fulls):
        self.store.save_discovery_cursor("github", 1000, NOW)
        repos = [item(1001 + k, full) for k, full in enumerate(fulls)]
        patterns = {"include": {"full_name": [re.compile("^cand")]}}
        self.run_gh(FakeGitHub(repos), filters=ghdiscover.Filters(patterns=patterns))
        return {c["full_name"]: c["repo_id"] for c in self.store.github_candidates()}

    def test_an_empty_repository_is_checked_on_the_schedule_and_dropped(self):
        self.keep("cand/empty")
        gh = FakeGitHub(info={"cand/empty": {"size": 0, "default_branch": "main"}})
        self.run_gh(gh, when=at(0.5))
        self.assertEqual(gh.asked("/repos/"), [])                      # nothing due yet
        for hours, due in ((1, "2026-10-14T18:00:00+00:00"), (6, "2026-10-15T12:00:00+00:00"),
                           (24, "2026-10-17T12:00:00+00:00")):
            self.run_gh(gh, when=at(hours))
            cand = self.candidates()["cand/empty"]
            self.assertEqual((cand["state"], cand["next_check"]), ("waiting", due))
        self.run_gh(gh, when=at(72))
        cand = self.candidates()["cand/empty"]
        self.assertEqual((cand["state"], cand["checks"], cand["last_error"]),
                         ("dropped", 4, "still empty 72 hours after it was listed"))
        self.assertEqual(len(gh.asked("/repos/cand/empty")), 4)

    def test_gone_private_and_ready(self):
        self.keep("cand/gone", "cand/private", "cand/full")
        gh = FakeGitHub(info={"cand/private": {"size": 9, "private": True},
                              "cand/full": {"size": 12, "default_branch": "main",
                                            "pushed_at": "2026-10-14T12:20:00Z"}})
        out = self.run_gh(gh, when=at(1))
        kept = self.candidates()
        self.assertEqual({n: (c["state"], c["last_error"]) for n, c in kept.items()},
                         {"cand/gone": ("dropped", "gone or made private"),
                          "cand/private": ("dropped", "made private"), "cand/full": ("ready", None)})
        self.assertEqual(out["checked"], {"dropped": 2, "ready": 1})
        self.assertEqual((kept["cand/full"]["size"], kept["cand/full"]["default_branch"]), (12, "main"))

    def scan_all(self):
        """Four candidates with content: one run checks them (ready, not scanned), the next scans them."""
        files = {"cand/hostile": HOSTILE, "cand/benign": BENIGN, "cand/unpinned": UNPINNED, "cand/partial": BENIGN}
        self.keep(*files)
        gh = FakeGitHub(info={full: {"size": 5} for full in files}, files=files, truncated={"cand/partial"})
        self.run_gh(gh, when=at(1))
        self.assertEqual(gh.asked("/tarball/"), [])
        return {r["name"]: r for r in self.run_gh(gh, when=at(1.5), scan=True)["scans"]}

    def test_scan_stores_the_result_and_the_verdict(self):
        verdicts = {name: r["verdict"] for name, r in self.scan_all().items()}
        self.assertEqual(verdicts, {"cand/hostile": "SUSPICIOUS", "cand/benign": "OK", "cand/unpinned": "OK",
                                    "cand/partial": "INCOMPLETE"})
        kept = self.candidates()
        self.assertEqual({n: (c["state"], c["verdict"], c["commit_sha"]) for n, c in kept.items()},
                         {n: ("scanned", v, SHA) for n, v in verdicts.items()})
        rep = self.store.report("github", "cand/hostile")
        self.assertEqual((rep["version"], rep["verdict"], rep["profile"]), (SHA, "SUSPICIOUS", "project"))

    def test_scan_counts_what_a_project_scan_counts(self):
        scans = self.scan_all()
        self.assertIn("SC-WORKFLOW-UNPINNED", rules(scans["cand/unpinned"]))     # reported, not counted
        self.assertTrue({"SC-INSTALL-HOOK", "SC-AUTORUN"} <= rules(scans["cand/hostile"], "CRITICAL"))
        self.assertIn("not read whole", scans["cand/partial"]["verdictReason"])

    def test_a_scan_that_fails_leaves_the_candidate_ready(self):
        self.keep("cand/broken")
        gh = FakeGitHub(info={"cand/broken": {"size": 5}})
        out = self.run_gh(gh, when=at(1), scan=True)
        self.assertEqual(len(out["errors"]), 1)
        cand = self.candidates()["cand/broken"]
        self.assertEqual(cand["state"], "ready")
        self.assertIn("no answer for", cand["last_error"])


class CliTests(Case):
    def cli(self, *argv, gh=None, env=ENV):
        gh = gh or FakeGitHub()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sources, "_http", gh))
            stack.enter_context(mock.patch.dict(os.environ, env, clear=False))
            if "GITHUB_TOKEN" not in env:
                stack.enter_context(mock.patch.dict(os.environ, {"GITHUB_TOKEN": ""}))
            stack.enter_context(mock.patch("sys.argv", ["lazaret-registry", *argv, "--db", self.db]))
            out = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            err = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_github_needs_resume_and_a_token(self):
        code, _out, err = self.cli("discover", "--ecosystem", "github")
        self.assertIn("use discover --ecosystem github --resume", str(code) + err)
        code, _out, err = self.cli("discover", "--ecosystem", "github", "--resume", env={})
        self.assertIn("needs GITHUB_TOKEN", str(code) + err)

    def test_ci_fails_on_a_campaign_repository_and_list_shows_the_candidates(self):
        self.store.save_discovery_cursor("github", 1000, NOW)
        gh = FakeGitHub([item(1001, "victim/shai-hulud"), item(1002, "shopsprint/decimal")])
        code, out, _err = self.cli("discover", "--ecosystem", "github", "--resume", "--ci", gh=gh)
        self.assertEqual(code, 1)
        self.assertIn("CAMPAIGN", out)
        self.assertIn("github:victim/shai-hulud", out)
        self.assertIn("(not downloaded)", out)
        code, out, _err = self.cli("list")
        self.assertEqual(code, 0)
        self.assertIn("GitHub candidates: reported 1, waiting 1", out)
        self.assertIn("a campaign repository: not downloaded", out)

    def test_a_quiet_run_passes_ci(self):
        self.store.save_discovery_cursor("github", 1000, NOW)
        code, out, _err = self.cli("discover", "--ecosystem", "github", "--resume", "--ci",
                                   gh=FakeGitHub([item(1001, "user/project")]))
        self.assertEqual(code, 0)
        self.assertIn("listed 1 new repositories in 1 page(s), up to ID 1001; caught up", out)

    def test_scan_and_report_a_repository(self):
        gh = FakeGitHub(files={"some/repo": HOSTILE})
        code, out, _err = self.cli("scan", "github:some/repo", "--ci", gh=gh)
        self.assertEqual(code, 1)
        self.assertIn("SUSPICIOUS", out)
        code, out, _err = self.cli("report", "github:some/repo")
        self.assertEqual(code, 0)
        self.assertIn(f"github:some/repo@{SHA} — SUSPICIOUS (profile project", out)
        code, _out, err = self.cli("report", "github:not a repo")
        self.assertIn("github: expected owner/repo", str(code) + err)


class NamesTests(unittest.TestCase):
    """popular_names.json's "github" section and scripts/update-popular-names.py --github, on small files."""

    def setUp(self):
        from tests import _support
        self.script = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "update-popular-names.py"),
                                            "update_popular_names_for_gh_tests")

    def test_repositories_from_npm_and_pypi(self):
        npm = self.script.npm_github_repo
        for field, want in (("git+https://github.com/Facebook/React.git", "facebook/react"),
                            ("github:sindresorhus/ky", "sindresorhus/ky"), ("chalk/chalk", "chalk/chalk"),
                            ({"type": "git", "url": "git@github.com:microsoft/TypeScript.git"}, "microsoft/typescript"),
                            ("https://github.com/babel/babel/tree/main/packages/babel-core", "babel/babel"),
                            ("gitlab:a/b", None), ("https://github.com/sponsors/x", None), (None, None), (5, None)):
            with self.subTest(field=field):
                self.assertEqual(npm(field), want)
        pypi = self.script.pypi_github_repo
        self.assertEqual(pypi({"project_urls": {"Funding": "https://github.com/sponsors/x", "Docs": "https://x.io",
                                                "Source": "https://github.com/psf/requests"}}), "psf/requests")
        self.assertEqual(pypi({"project_urls": {"Tracker": "https://github.com/a/b/issues"}}), "a/b")
        self.assertEqual(pypi({"project_urls": None, "home_page": "https://github.com/pallets/flask/"}), "pallets/flask")
        self.assertIsNone(pypi({"project_urls": {"Docs": "https://x.io"}, "home_page": ""}))

    def test_the_section(self):
        with tempfile.TemporaryDirectory() as d:
            rows = {"npm.jsonl": [{"rank": 1, "name": "b", "repository": "github:o/b"},
                                  {"rank": 0, "name": "a", "repository": "git+https://github.com/O/A.git"},
                                  {"rank": 2, "name": "c", "error": "HTTPError"}],
                    "pypi.jsonl": [{"rank": 0, "name": "p", "project_urls": {"Source": "https://github.com/o/a"}},
                                   {"rank": 1, "name": "q", "home_page": "https://github.com/x/q"}],
                    "stars.jsonl": [{"rank": 0, "full_name": "big/thing", "description": "  The   thing "}]}
            for name, items in rows.items():
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    f.write("".join(json.dumps(r) + "\n" for r in items))
            sec = self.script.github_section(d)["github"]
        self.assertEqual(sec["targets"], ["o/a", "big/thing", "o/b", "x/q"])
        self.assertEqual(sec["descriptions"], {"big/thing": "The thing"})
        self.assertIn("npm.jsonl", sec["source"])

    def test_the_shipped_section(self):
        with open(lookalike.__file__.replace("lookalike.py", "popular_names.json"), encoding="utf-8") as f:
            sec = json.load(f)["github"]
        self.assertTrue(sec["source"] and sec["license"])
        self.assertGreater(len(sec["targets"]), 3000)
        self.assertEqual(len(set(sec["targets"])), len(sec["targets"]))
        self.assertTrue(all(t == t.lower() and t.count("/") == 1 for t in sec["targets"]))
        self.assertIn("facebook/react", sec["targets"])
        tables, _copies = lookalike._load()["github"]
        self.assertIn("github.com/facebook/react", tables[0])
        self.assertTrue(lookalike.github_lookalike("faceb00k/react") or lookalike.github_lookalike("facebok/react"))


class CandidateConn(FakeConn):
    """The Store's fake Postgres connection, the github_candidates statements run on SQLite ($n as ?n)."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.db = sqlite3.connect(":memory:")
        self.sent = []

    def execute_script(self, sql):
        super().execute_script(sql)
        for statement in sql.split(";"):
            if "github_candidates" in statement and "ADD COLUMN IF NOT EXISTS" not in statement:   # (Postgres's)
                self.db.execute(statement)

    def _run(self, op, sql, args):
        self._op(op)
        self.sent.append((sql, args))
        return self.db.execute(re.sub(r"\$(\d+)", r"?\1", sql), args)

    def fetch(self, sql, *args):
        if "github_candidates" not in sql:
            return super().fetch(sql, *args)
        return self._run("fetch", sql, args).fetchall()

    def execute(self, sql, *args):
        if "github_candidates" not in sql:
            return super().execute(sql, *args)
        self._run("INSERT" if sql.startswith("INSERT") else "UPDATE", sql, args)


class PostgresCandidateTests(unittest.TestCase):
    def test_round_trip(self):
        conn = CandidateConn()
        store = pg_store(conn)
        store.add_github_candidate(7, "a/b", "desc", False, ["look-alike: x"], "2026-10-14T12:00:00+00:00", "waiting",
                                   "2026-10-14T13:00:00+00:00")
        store.add_github_candidate(7, "a/b", None, True, [], "2026-10-15T00:00:00+00:00", "reported", None)
        store.update_github_candidate(7, checks=1, size=3)
        self.assertEqual(store.github_candidates(states=("waiting",), due_by="2026-10-14T12:30:00+00:00"), [])
        (cand,) = store.github_candidates(states=("waiting", "ready"), due_by="2026-10-14T13:00:00+00:00")
        self.assertEqual((cand["full_name"], cand["filters"], cand["checks"], cand["size"], cand["fork"]),
                         ("a/b", ["look-alike: x"], 1, 3, 0))
        insert = next(s for s, _ in conn.sent if s.startswith("INSERT"))
        self.assertIn("VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (repo_id) DO NOTHING", insert)
        update, args = next(x for x in conn.sent if x[0].startswith("UPDATE"))
        self.assertIn("SET checks=$1, size=$2, updated_at=$3 WHERE repo_id=$4", update)
        self.assertEqual(args[:2] + args[3:], (1, 3, 7))
        select = [s for s, _ in conn.sent if s.startswith("SELECT")][-1]
        self.assertIn("WHERE state IN ($1,$2) AND next_check IS NOT NULL AND next_check <= $3", select)


if __name__ == "__main__":
    unittest.main()
