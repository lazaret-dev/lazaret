"""Scan-all learns which new repositories got code from GitHub's GraphQL API (GH-SCAN-GQL, 0.1.9:
lazaret.registry.ghdiscover's `_Asker` and `read_nodes`, sources.Client.post and `_post`, the store's github_listed).

GitHub is test_ghdiscover's FakeGitHub throughout, whose GraphQL answers `nodes(ids:)` from its listing (a
repository empty unless `code` has it, `nodes` to answer otherwise, `answers` for fixed answers or errors in turn);
GH Archive is test_ghdiscover_archive's FakeArchive, empty unless a test gives it an hour. The POST's own rules are
tested against the native transport's seam (nativenet.request, a stand-in) and, on urllib's transport, against
loopback servers: test_fetch_deadline's ScriptServer (answers from scripts of bytes and pauses) and a server here
that records what it was sent. Nothing reaches the network; names and IDs are made up. Covered: a listing page's one
call and what its answer does; the asks again at CHECK_HOURS, newest first, 100 a call, and the drop after
PENDING_HOURS; failing closed (HTTP errors, an HTML or non-JSON body, errors for some nodes and data for others, a
node's fields missing or another repository's, an error of the whole query, a partial answer, a body over the
budget); the rate limits (the points' floor, a 403 with no points left, a 429, RATE_LIMITED) and the next run
resuming; --max-graphql-calls; campaign and excluded repositories never asked about, forks, a rename; the POST (the
token to api.github.com alone, no redirect followed, the total deadline, the byte budget); the table's migration on
SQLite and its statements on Postgres; GH Archive's events as before; the CLI's lines."""

import contextlib
import datetime
import http.server
import io
import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests import _support  # noqa: F401
from lazaret import pg
from lazaret.registry import ghdiscover, repo, sources
from lazaret.registry.sources import SourceError
from tests.registry.test_fetch_deadline import ALLOWANCE, ROUTES, ScriptServer, head
from tests.registry.test_ghdiscover import (API, ENV, NOW, Case, CandidateConn, FakeGitHub, at, failure, item,
                                            node_id)
from tests.registry.test_ghdiscover_archive import FakeArchive, public, push
from tests.registry.test_review_store_reconnect import pg_store
from tests.registry.test_sources import TOKEN

WHAT = "asking GitHub's GraphQL API about 3 new repositories"


def repos(first, n, **kw):
    return [item(first + k, f"user{first + k}/project", **kw) for k in range(n)]


class GqlCase(Case):
    def setUp(self):
        super().setUp()
        self.store.save_discovery_cursor("github", 1000, NOW)
        self.store.save_discovery_cursor("github-scan-all", 1000)

    def scan_all(self, gh, when=NOW, events=None, **kw):
        kw.setdefault("filters", ghdiscover.Filters())
        kw.setdefault("max_scans", 0)
        return ghdiscover.run(self.store, env=ENV, http=gh, now=when, archive_http=events or FakeArchive(),
                              scan_all=True, **kw)

    def listed(self):
        return {r["repo_id"]: r for r in self.store.github_listed()}

    def queued(self):
        return {c["repo_id"]: c for c in self.store.github_candidates(states=("queued",))}


class FirstAskTests(GqlCase):
    def test_a_listing_page_is_one_call_and_its_answer_queues_keeps_and_drops(self):
        gh = FakeGitHub(repos(1001, 100), code={1010, 1020, 1030})
        gh.nodes[node_id(1050)] = gh.nodes[node_id(1060)] = None        # (null, NOT_FOUND: deleted since)
        out = self.scan_all(gh)
        self.assertEqual(gh.posts, [[node_id(k) for k in range(1001, 1101)]])
        doc, headers = gh.bodies[0]
        self.assertEqual((sorted(doc), doc["query"], sorted(doc["variables"])),
                         (["query", "variables"], ghdiscover.GRAPHQL_QUERY, ["ids"]))   # (node IDs alone)
        self.assertEqual(headers["Authorization"], f"Bearer {TOKEN}")
        queued = self.queued()
        self.assertEqual(sorted(queued), [1010, 1020, 1030])
        self.assertEqual({c["filters"][0] for c in queued.values()}, {ghdiscover.ALL_GRAPHQL})
        listed = self.listed()
        self.assertEqual(sorted(listed), sorted(set(range(1001, 1101)) - {1010, 1020, 1030, 1050, 1060}))
        self.assertEqual({(r["state"], r["next_check"], r["checks"], r["node_id"] == node_id(r["repo_id"]))
                          for r in listed.values()}, {("empty", "2026-10-14T13:00:00+00:00", 1, True)})
        self.assertEqual(self.store.github_candidate_states([1050, 1060]), {})          # gone: in neither
        g = out["graphql"]
        self.assertEqual((g["listed"], g["asked"], g["calls"], g["code"], g["empty"], g["gone"], g["unanswered"]),
                         (100, 100, 1, 3, 95, 2, 0))
        self.assertEqual((g["points"], g["stopped"], g["kept"], g["waiting"]), (4999, None, 95, 0))
        self.assertEqual(out["listed"], 100)

    def test_a_page_listed_again_is_not_asked_about_again(self):
        gh = FakeGitHub(repos(1001, 3))
        self.scan_all(gh)
        self.store.save_discovery_cursor("github", 1000, NOW)             # (a run that stopped before its cursor)
        self.scan_all(gh, when=at(0.25))
        self.assertEqual(len(gh.posts), 1)
        self.assertEqual({r["checks"] for r in self.listed().values()}, {1})

    def test_nothing_is_asked_before_scan_all_has_a_start(self):
        self.store.conn.execute("DELETE FROM discovery_cursors")            # (the very first run: no cursor yet)
        self.store.conn.commit()
        gh = FakeGitHub(repos(1001, 3))
        out = self.scan_all(gh)
        self.assertEqual((out["first"], out["graphql"], gh.posts), (True, None, []))


class AgainTests(GqlCase):
    def test_a_later_run_asks_the_due_ones_again_oldest_first_within_their_share_100_a_call(self):
        gh = FakeGitHub(repos(1001, 250))
        self.scan_all(gh)
        self.assertEqual([len(p) for p in gh.posts], [100, 100, 50])    # (a call for each page)
        gh.posts.clear()
        self.scan_all(gh, when=at(0.5))
        self.assertEqual(gh.posts, [])                                    # (nothing due yet)
        gh.code.add(1100)
        out = self.scan_all(gh, when=at(1))
        self.assertEqual([len(p) for p in gh.posts], [100, 100, 50])
        # (the due share of 4,000 calls holds them all: oldest listed first, then repository ID)
        self.assertEqual(sum(gh.posts, []), [node_id(k) for k in range(1001, 1251)])
        self.assertEqual(sorted(self.queued()), [1100])
        self.assertEqual({(r["state"], r["next_check"], r["checks"]) for r in self.listed().values()},
                         {("empty", "2026-10-14T18:00:00+00:00", 2)})
        g = out["graphql"]
        self.assertEqual((g["fresh"], g["again"], g["code"], g["empty"]), (0, 250, 1, 249))

    def test_still_empty_after_the_last_check_is_dropped_and_counted(self):
        gh = FakeGitHub(repos(1001, 2))
        self.scan_all(gh)
        for hours, due in ((1, "2026-10-14T18:00:00+00:00"), (6, "2026-10-15T12:00:00+00:00"),
                           (24, "2026-10-17T12:00:00+00:00")):
            self.scan_all(gh, when=at(hours))
            self.assertEqual({r["next_check"] for r in self.listed().values()}, {due})
        gh.code.add(1002)
        out = self.scan_all(gh, when=at(72))
        self.assertEqual((self.listed(), sorted(self.queued())), ({}, [1002]))
        self.assertEqual((out["graphql"]["expired"], out["graphql"]["code"]), (1, 1))
        self.assertEqual(len(gh.posts), 5)

    def test_a_run_long_after_asks_at_the_next_check_still_to_come(self):
        gh = FakeGitHub(repos(1001, 1))
        self.scan_all(gh)
        self.scan_all(gh, when=at(30))                                   # (runs missed the 1 and 6 hours' asks)
        self.assertEqual([(r["next_check"], r["checks"]) for r in self.listed().values()],
                         [("2026-10-17T12:00:00+00:00", 2)])

    def test_one_never_answered_is_never_dropped_for_its_age(self):
        # (the coordinator's rule, the review of Oct 18: dropped for age only when its last scheduled ask said no
        # code; an outage, errors or the budget leave it waiting, however long)
        gh = FakeGitHub(repos(1001, 1), code={1001})
        gh.answers = [failure("x: HTTP 502 from https://api.github.com/graphql", 502)] * 50
        self.scan_all(gh)
        for hours in (1, 6, 24, 72, 80, 200):
            out = self.scan_all(gh, when=at(hours))
            self.assertEqual([(r["state"], r["checks"]) for r in self.listed().values()], [("unasked", 0)])
        self.assertEqual((out["graphql"]["aged"], out["graphql"]["expired"]), (1, 0))
        gh.answers.clear()
        out = self.scan_all(gh, when=at(201))
        self.assertEqual((self.listed(), sorted(self.queued())), ({}, [1001]))     # (answered at last: code)

    def test_one_first_answered_after_its_last_slot_and_empty_is_dropped(self):
        gh = FakeGitHub(repos(1001, 1))
        gh.answers = [failure("x: HTTP 502 from https://api.github.com/graphql", 502)]
        self.scan_all(gh)
        out = self.scan_all(gh, when=at(80))                           # (its last scheduled ask, answered: empty)
        self.assertEqual((self.listed(), out["graphql"]["expired"]), ({}, 1))

    def test_fresh_pages_do_not_starve_the_oldest_due(self):
        # (the review's probe c: rows near their last check, with code, against fresh pages and a tight budget)
        old = repos(1001, 200)
        gh = FakeGitHub(old)
        self.scan_all(gh)
        for hours in (1, 6, 24):
            self.scan_all(gh, when=at(hours))
        gh.code |= {r["id"] for r in old}
        gh.repos = sorted(gh.repos + repos(5001, 300), key=lambda r: r["id"])
        self.store.save_discovery_cursor("github", 1200, NOW)
        self.scan_all(gh, when=at(70), max_graphql_calls=0)                # (listed at 70 h, never asked)
        gh.posts.clear()
        out = self.scan_all(gh, when=at(79), max_graphql_calls=4)
        # (a quarter of 4 calls: the 100 oldest, oldest first; then newest first: the 300 listed at 70 hours)
        self.assertEqual(gh.posts[0], [node_id(k) for k in range(1001, 1101)])
        self.assertEqual(sum(gh.posts[1:], []), [node_id(k) for k in range(5300, 5000, -1)])
        self.assertEqual(sorted(self.queued()), list(range(1001, 1101)))
        g = out["graphql"]
        self.assertEqual((g["aged"], g["expired"], g["kept"]), (100, 0, 400))   # (the other 100 old ones wait)
        self.scan_all(gh, when=at(80))
        self.assertEqual(sorted(self.queued()), list(range(1001, 1201)))

    def test_the_set_waiting_keeps_the_newest(self):
        gh = FakeGitHub(repos(1001, 8))
        with mock.patch.object(ghdiscover, "LISTED_MAX", 5):
            out = self.scan_all(gh)
        self.assertEqual((sorted(self.listed()), out["graphql"]["over"]), ([1004, 1005, 1006, 1007, 1008], 3))


class FailClosedTests(GqlCase):
    """No answer GitHub's GraphQL API gives that is not understood drops a repository or takes it as empty."""

    def assert_kept_unasked(self, answer, ids=(1001, 1002, 1003), unanswered=3):
        gh = FakeGitHub(repos(1001, 3))
        gh.answers = [answer, answer]                       # (the second for the control call, when one is made)
        with mock.patch.object(ghdiscover, "GRAPHQL_SPLIT_DEPTH", 0):     # (the answer read alone: no halves asked)
            out = self.scan_all(gh)
        gh.answers.clear()
        listed = self.listed()
        self.assertEqual(sorted(listed), sorted(ids))
        for rid in ids:
            self.assertEqual((listed[rid]["state"], listed[rid]["checks"], listed[rid]["next_check"],
                              listed[rid]["fails"]), ("unasked", 0, "2026-10-14T12:00:00+00:00", 0))
            self.assertTrue(listed[rid]["last_error"])
        self.assertEqual(self.store.github_candidates(), [])
        self.assertEqual(out["graphql"]["unanswered"], unanswered)
        self.assertEqual(out["graphql"]["waiting"], len(ids))
        later = self.scan_all(gh, when=at(0.25))                          # (the next run asks them again)
        self.assertEqual(gh.posts[-1], [node_id(rid) for rid in sorted(ids)])
        self.assertEqual({r["state"] for r in self.listed().values()}, {"empty"})
        return out, later

    def test_http_errors(self):
        for status in (500, 502, 401):
            with self.subTest(status=status):
                self.setUp()
                out, _ = self.assert_kept_unasked(failure(f"{WHAT}: HTTP {status} from {API}/graphql", status))
                self.assertEqual((out["graphql"]["failed"], out["graphql"]["stopped"], out["stopped"]), (1, None, None))

    def test_a_body_that_is_html_or_not_json(self):
        for body in (b"<html><body><h1>502 Bad Gateway</h1></body></html>", b"", b"{\"data\": ", b"[" * 100_000):
            with self.subTest(body=body[:20]):
                self.setUp()
                out, _ = self.assert_kept_unasked(body)
                self.assertIn("JSON", out["graphql"]["error"])

    def test_a_body_over_the_budget(self):
        out, _ = self.assert_kept_unasked(SourceError(f"{WHAT}: response exceeds the 1024 KB budget"))
        self.assertIn("exceeds", out["graphql"]["error"])

    def test_errors_for_some_nodes_and_data_for_others(self):
        gh = FakeGitHub(repos(1001, 6), code={1001})
        nodes = [gh.node(1001), None, {**gh.node(1003), "isEmpty": None}, gh.node(1004), None,
                 {**gh.node(1006), "databaseId": 4242}]
        del nodes[3]["isEmpty"]
        answer = {"data": {"nodes": nodes, "rateLimit": {"cost": 1, "remaining": 4000, "resetAt": "x"}},
                  "errors": [{"type": "FORBIDDEN", "path": ["nodes", 1], "message": "Resource not accessible"},
                             {"type": "NOT_FOUND", "path": ["nodes", 4], "message": "Could not resolve"}]}
        gh.answers = [answer]
        out = self.scan_all(gh)
        listed = self.listed()
        self.assertEqual(sorted(self.queued()), [1001])                  # (its data: code)
        self.assertEqual(sorted(listed), [1002, 1003, 1004, 1006])       # (1005: null and NOT_FOUND, gone)
        self.assertEqual({rid: r["state"] for rid, r in listed.items()},
                         {1002: "unasked", 1003: "unasked", 1004: "unasked", 1006: "unasked"})
        self.assertIn("FORBIDDEN", listed[1002]["last_error"])
        self.assertIn("another repository's", listed[1006]["last_error"])
        g = out["graphql"]
        self.assertEqual((g["code"], g["gone"], g["unanswered"], g["empty"], g["points"]), (1, 1, 4, 0, 4000))

    def test_an_error_of_the_whole_query_leaves_every_null_unanswered(self):
        # (nulls with an error that names no node are not gone: fail closed)
        self.assert_kept_unasked({"data": {"nodes": [None, None, None]},
                                  "errors": [{"message": "Something went wrong while executing your query."}]})

    def test_answers_not_as_asked(self):
        gh = FakeGitHub(repos(1001, 3))
        node = gh.node(1001)
        for answer in ({"data": {"nodes": [node]}}, {"data": None}, {"data": {"nodes": "x"}}, [node], "x",
                       {"data": {"nodes": [node, node, node]}, "errors": "x"},
                       {"data": {"nodes": [None, None, None]}, "errors": [{"type": "NOT_FOUND", "path": ["nodes", 7]}]},
                       {"data": {"nodes": [None, None, None]}, "errors": [{"type": "NOT_FOUND", "path": ["x", 0]}]},
                       {"data": {"nodes": [None, None, None]},
                        "errors": [{"type": "NOT_FOUND", "path": ["nodes", True]}]},
                       {"data": {"nodes": [None, None, None]}, "errors": ["NOT_FOUND"]}):
            with self.subTest(answer=str(answer)[:80]):
                self.setUp()
                self.assert_kept_unasked(answer)

    def test_a_node_whose_fields_are_not_the_ones_asked_for(self):
        gh = FakeGitHub(repos(1001, 1))
        good = gh.node(1001)
        bad = [{**good, "databaseId": True}, {**good, "databaseId": "1001"}, {**good, "isEmpty": "false"},
               {**good, "isPrivate": None}, {**good, "createdAt": "yesterday"}, {**good, "pushedAt": 5},
               {**good, "diskUsage": -1}, {**good, "nameWithOwner": "../x"}, {**good, "nameWithOwner": None}, {}, 7]
        rows = [{"repo_id": 1001}]
        for node in bad:
            with self.subTest(node=node):
                verdicts, _rate, limited = ghdiscover.read_nodes({"data": {"nodes": [node]}}, rows)
                self.assertEqual((verdicts[0][0], limited), ("unanswered", None))
        self.assertEqual(ghdiscover.read_nodes({"data": {"nodes": [good]}}, rows)[0], [("empty", None)])
        verdicts = ghdiscover.read_nodes({"data": {"nodes": [{**good, "isPrivate": True, "isEmpty": False}]}}, rows)[0]
        self.assertEqual(verdicts, [("gone", "made private")])
        named = {"data": {"nodes": [good]}, "errors": [{"type": "NOT_FOUND", "path": ["nodes", 0]}]}
        self.assertEqual(ghdiscover.read_nodes(named, rows)[0][0][0], "unanswered")    # (an error for a node with data)

    def test_failed_calls_stop_the_graphql_part_after_a_few(self):
        gh = FakeGitHub(repos(1001, 400))
        gh.answers = [failure(f"x: HTTP 500 from {API}/graphql", 500)] * 10
        out = self.scan_all(gh)
        g = out["graphql"]
        self.assertEqual((len(gh.posts), g["failed"]), (ghdiscover.GRAPHQL_FAILURES, ghdiscover.GRAPHQL_FAILURES))
        self.assertIn("3 GraphQL calls failed", g["stopped"])
        self.assertEqual((out["listed"], out["caughtUp"], out["stopped"]), (400, True, None))   # (the listing goes on)
        self.assertEqual(({r["state"] for r in self.listed().values()}, g["waiting"]), ({"unasked"}, 400))


class RateLimitTests(GqlCase):
    def test_the_points_floor_stops_the_graphql_part_and_the_next_run_resumes(self):
        gh = FakeGitHub(repos(1001, 400))
        gh.points = ghdiscover.GRAPHQL_RATE_FLOOR + 2
        out = self.scan_all(gh)
        g = out["graphql"]
        self.assertEqual(len(gh.posts), 2)                                  # (the second answer is at the floor)
        self.assertEqual(g["stopped"], "GitHub's GraphQL rate limit is nearly spent (100 points left, until 13:00 UTC)")
        self.assertEqual((g["empty"], g["waiting"], out["caughtUp"], out["stopped"]), (200, 200, True, None))
        gh.points = 5000
        later = self.scan_all(gh, when=at(0.25))
        self.assertEqual(sum(gh.posts[2:], []), [node_id(k) for k in range(1201, 1401)])     # (oldest first)
        self.assertEqual((later["graphql"]["empty"], later["graphql"]["waiting"]), (200, 0))

    def test_a_403_with_no_points_left_stops_the_graphql_part_alone(self):
        gh = FakeGitHub(repos(1001, 300))
        refused = failure(f"{WHAT}: rate limit reached, wait until 13:00 UTC", 403)
        gh.answers = [(refused, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1791000000"})]
        out = self.scan_all(gh)
        self.assertEqual(len(gh.posts), 1)
        self.assertIn("rate limit reached", out["graphql"]["stopped"])
        self.assertEqual((out["stopped"], out["caughtUp"], out["graphql"]["waiting"]), (None, True, 300))
        self.scan_all(gh, when=at(0.25))
        self.assertEqual([len(p) for p in gh.posts[1:]], [100, 100, 100])

    def test_a_secondary_limit_stops_the_run_as_rest_does(self):
        for status, headers in ((429, {"retry-after": "60"}),
                                (403, {"retry-after": "60", "x-ratelimit-remaining": "40"}),
                                (403, {"x-ratelimit-remaining": "4000"})):
            with self.subTest(status=status, headers=headers):
                self.setUp()
                gh = FakeGitHub(repos(1001, 300))
                gh.answers = [(failure(f"{WHAT}: rate limit reached, wait for 60 seconds", status), headers)]
                out = self.scan_all(gh)
                self.assertIn("GraphQL API refused a call", out["stopped"])
                self.assertEqual((out["pages"], self.store.discovery_cursor("github")[0]), (1, "1100"))
                self.assertEqual(out["errors"], [])
                later = self.scan_all(gh, when=at(0.25))
                self.assertEqual((later["cursor"], later["caughtUp"]), (1300, True))
                self.assertEqual({r["state"] for r in self.listed().values()}, {"empty"})

    def test_rate_limited_in_the_answer_stops_the_graphql_part(self):
        gh = FakeGitHub(repos(1001, 200))
        gh.answers = [({"data": None, "errors": [{"type": "RATE_LIMITED", "message": "API rate limit exceeded for "
                                                  "user ID 1."}]}, {"x-ratelimit-remaining": "0"})]
        out = self.scan_all(gh)
        self.assertEqual(len(gh.posts), 1)
        self.assertIn("rate limited (API rate limit exceeded", out["graphql"]["stopped"])
        self.assertEqual((out["stopped"], out["graphql"]["unanswered"], out["graphql"]["waiting"]), (None, 100, 200))
        later = self.scan_all(gh, when=at(0.25))
        self.assertEqual((later["graphql"]["again"], later["graphql"]["empty"]), (200, 200))

    def test_rate_limited_comes_before_any_other_error(self):
        doc = {"errors": [{"message": "boom"}, {"type": "RATE_LIMITED", "message": "slow down"}]}
        verdicts, _rate, limited = ghdiscover.read_nodes(doc, [{"repo_id": 1}])
        self.assertEqual(verdicts, [("unanswered", "rate limited")])
        self.assertTrue(limited.endswith("rate limited (slow down)"), limited)


class BudgetTests(GqlCase):
    def test_the_run_stops_asking_at_its_budget_and_says_how_many_are_left(self):
        gh = FakeGitHub(repos(1001, 500))
        out = self.scan_all(gh, max_graphql_calls=2)
        g = out["graphql"]
        self.assertEqual((len(gh.posts), g["calls"], g["waiting"], g["kept"]), (2, 2, 300, 500))
        self.assertEqual(g["stopped"], "the run's budget of 2 GraphQL calls (--max-graphql-calls) was spent")
        self.assertEqual((out["caughtUp"], out["stopped"]), (True, None))      # (REST's --max-calls is apart)
        self.scan_all(gh, when=at(0.25))
        self.assertEqual(sum(gh.posts[2:], []), [node_id(k) for k in range(1201, 1501)])

    def test_no_calls_at_all(self):
        gh = FakeGitHub(repos(1001, 5))
        out = self.scan_all(gh, max_graphql_calls=0)
        self.assertEqual((gh.posts, out["graphql"]["waiting"]), ([], 5))


class WhoIsAskedTests(GqlCase):
    def test_campaign_excluded_and_filter_candidates_are_never_asked_about(self):
        patterns = {"exclude": {"full_name": [re.compile("^trusted-org/")]}, "include": {}}
        gh = FakeGitHub([item(1001, "victim/shai-hulud"), item(1002, "trusted-org/tool"),
                         item(1003, "shopsprint/decimal"), item(1004, "u/plain")], code={1001, 1002, 1003, 1004})
        out = self.scan_all(gh, filters=ghdiscover.Filters(patterns=patterns))
        self.assertEqual(gh.posts, [[node_id(1004)]])
        states = {c["repo_id"]: c["state"] for c in self.store.github_candidates()}
        self.assertEqual(states, {1001: "reported", 1002: "excluded", 1003: "waiting", 1004: "queued"})
        self.assertEqual(gh.asked("victim"), [])
        self.assertEqual(out["graphql"]["code"], 1)

    def test_a_fork_is_queued_once_it_was_pushed_to_after_it_was_made(self):
        gh = FakeGitHub([item(1001, "u/fork-pushed", fork=True), item(1002, "u/fork-untouched", fork=True),
                         item(1003, "u/fork-no-push", fork=True)], code={1001})
        gh.nodes[node_id(1002)] = {**gh.node(1002), "isEmpty": False, "pushedAt": "2026-09-01T00:00:00Z"}
        gh.nodes[node_id(1003)] = {**gh.node(1003), "isEmpty": False, "pushedAt": None}
        out = self.scan_all(gh)
        self.assertEqual(sorted(self.queued()), [1001])
        self.assertEqual({rid: (r["state"], r["checks"]) for rid, r in self.listed().items()},
                         {1002: ("fork", 1), 1003: ("fork", 1)})
        self.assertEqual(out["graphql"]["forks"], 2)
        gh.nodes[node_id(1002)] = {**gh.nodes[node_id(1002)], "pushedAt": "2026-10-14T12:40:00Z"}   # (pushed to)
        self.scan_all(gh, when=at(1))
        self.assertEqual(sorted(self.queued()), [1001, 1002])
        self.assertEqual(sorted(self.listed()), [1003])

    def test_a_push_gh_archive_sees_to_an_untouched_fork_queues_it_as_before(self):
        gh = FakeGitHub([item(1001, "u/fork", fork=True)])
        gh.nodes[node_id(1001)] = {**gh.node(1001), "isEmpty": False, "pushedAt": "2026-09-01T00:00:00Z"}
        self.scan_all(gh)
        archive = FakeArchive({"2026-10-14-12": [push(1001, "u/fork", at(0.5))]})
        self.scan_all(gh, when=at(1.5), events=archive)
        self.assertEqual(self.queued()[1001]["filters"], [ghdiscover.ALL_PUSHED])
        self.assertEqual((self.listed(), len(gh.posts)), ({}, 1))          # (not asked again: GH Archive's now)

    def test_a_repository_renamed_to_a_campaign_marker_is_reported_never_downloaded(self):
        gh = FakeGitHub([item(1001, "u/innocent")], code={1001}, files={"u/shai-hulud": {}})
        gh.nodes[node_id(1001)] = {**gh.node(1001), "nameWithOwner": "u/shai-hulud"}
        out = self.scan_all(gh, max_scans=10)
        self.assertEqual([(c["full_name"], c["state"]) for c in self.store.github_candidates()],
                         [("u/shai-hulud", "reported")])
        self.assertEqual([f for f, _m, _u in out["campaigns"]], ["u/shai-hulud"])
        self.scan_all(gh, when=at(1), max_scans=10)
        self.assertEqual(gh.asked("/repos/u/"), [])

    def test_one_queued_is_scanned_by_the_name_graphql_gives(self):
        from tests.registry.test_ghdiscover import BENIGN
        gh = FakeGitHub([item(1001, "u/old-name")], code={1001}, files={"u/new-name": BENIGN})
        gh.nodes[node_id(1001)] = {**gh.node(1001), "nameWithOwner": "u/new-name"}
        self.scan_all(gh)
        out = self.scan_all(gh, when=at(0.25), max_scans=5)
        self.assertEqual([r["name"] for r in out["scans"]], ["u/new-name"])

    def test_a_listing_item_without_a_node_id_goes_to_the_rest_content_checks(self):
        gh = FakeGitHub([{**item(1001, "u/a"), "node_id": None}, {**item(1002, "u/b"), "node_id": "R_ x"},
                         item(1003, "u/c")], info={"u/a": {"size": 3}, "u/b": {"size": 0}})
        out = self.scan_all(gh)
        self.assertEqual((gh.posts, out["graphql"]["noNode"]), ([[node_id(1003)]], 2))
        cands = {c["repo_id"]: c for c in self.store.github_candidates()}
        self.assertEqual({rid: (c["state"], c["filters"], c["next_check"]) for rid, c in cands.items()},
                         {rid: ("waiting", [ghdiscover.ALL_NO_NODE], "2026-10-14T13:00:00+00:00")
                          for rid in (1001, 1002)})
        self.scan_all(gh, when=at(1))                                       # (REST's check: one has content)
        self.assertEqual({c["repo_id"]: c["state"] for c in self.store.github_candidates()},
                         {1001: "ready", 1002: "waiting"})


class ArchiveAsBeforeTests(GqlCase):
    def test_gh_archive_still_queues_the_public_and_the_pushed(self):
        gh = FakeGitHub(repos(1001, 2))
        self.scan_all(gh)
        archive = FakeArchive({"2026-10-14-12": [push(1001, "user1001/project", at(0.5)),
                                                 public(77, "old/now-public", at(0.5))]})
        out = self.scan_all(gh, when=at(1.5), events=archive)
        queued = self.queued()
        self.assertEqual({rid: c["filters"][0] for rid, c in queued.items()},
                         {1001: ghdiscover.ALL_PUSHED, 77: ghdiscover.ALL_PUBLIC})
        self.assertEqual(gh.posts[-1], [node_id(1002)])                     # (1001 is GH Archive's: not asked)
        self.assertEqual(sorted(self.listed()), [1002])
        self.assertEqual((out["archive"]["pushed"], out["archive"]["public"]), (1, 1))


class ReviewTests(GqlCase):
    """The independent review of Oct 18 (GH-SCAN-GQL, NEEDS FIXES): each finding, and the mutations no test caught."""

    def read(self, *nodes, rid=1001, **doc):
        return [v[0] for v in ghdiscover.read_nodes({"data": {"nodes": list(nodes)}, **doc}, [{"repo_id": rid}])[0]]

    def test_a_node_without_a_field_asked_for_is_unanswered(self):
        # (HIGH: a fork whose answer lacked pushedAt was taken as never pushed, and expired after 72 hours)
        gh = FakeGitHub([item(1001, "u/forky", fork=True)])
        node = {**gh.node(1001), "isEmpty": False}
        del node["pushedAt"]
        gh.nodes[node_id(1001)] = node
        for hours in (0, 1, 6, 24, 72, 80):
            out = self.scan_all(gh, when=at(hours))
        self.assertEqual([(r["state"], r["checks"]) for r in self.listed().values()], [("unasked", 0)])
        self.assertEqual((out["graphql"]["expired"], self.store.github_candidates()), (0, []))
        for field in ghdiscover.NODE_FIELDS:
            with self.subTest(field=field):
                node = gh.node(1001)
                del node[field]
                self.assertEqual(self.read(node), ["unanswered"])

    def test_a_fork_pushed_when_it_was_made_has_no_push_of_its_own(self):
        gh = FakeGitHub([item(1001, "u/f", fork=True)])
        fork = {**gh.node(1001), "isEmpty": False, "createdAt": "2026-10-14T11:59:00Z"}
        for pushed, verdict in (("2026-10-14T11:59:00Z", "fork"), ("2026-10-14T13:59:00+02:00", "fork"),
                                ("2026-10-14T11:59:01Z", "code"), ("2026-10-14T11:58:59Z", "fork"), (None, "fork")):
            with self.subTest(pushed=pushed):
                self.assertEqual(self.read({**fork, "pushedAt": pushed}), [verdict])

    def test_a_null_node_is_gone_only_when_not_found_names_it(self):
        self.assertEqual(self.read(None), ["unanswered"])
        self.assertEqual(self.read(None, errors=[{"type": "NOT_FOUND", "path": ["nodes", 0]}]), ["gone"])
        self.assertEqual(self.read(None, errors=[{"type": "NOT_FOUND", "path": ["nodes", 0]},
                                                 {"type": "FORBIDDEN", "path": ["nodes", 0]}]), ["unanswered"])
        gh = FakeGitHub(repos(1001, 2), code={1001, 1002})
        gh.answers = [{"data": {"nodes": [None, gh.node(1002)]}}]
        out = self.scan_all(gh)
        self.assertEqual((out["graphql"]["gone"], sorted(self.listed()), sorted(self.queued())), (0, [1001], [1002]))

    def test_a_nodes_list_longer_than_asked_is_not_read(self):
        node = FakeGitHub(repos(1001, 1)).node(1001)
        self.assertEqual(self.read(node, {**node, "databaseId": 1002}), ["unanswered"])

    def test_an_error_naming_no_node_leaves_every_answered_node_unanswered(self):
        # (mutations M8 and M9: an error of the whole query, or one naming a node past the list, passed over)
        node = FakeGitHub(repos(1001, 1), code={1001}).node(1001)
        for error in ({"message": "timeout"}, {"type": "X", "path": ["nodes"]}, {"type": "X", "path": ["nodes", 1]},
                      {"type": "X", "path": ["nodes", -1]}, {"type": "X", "path": ["nodes", 10 ** 100]}):
            with self.subTest(error=error):
                self.assertEqual(self.read(node, errors=[error]), ["unanswered"])
        self.assertEqual(self.read(node), ["code"])

    def test_a_repository_found_with_code_is_never_lost_on_its_way_to_the_queue(self):
        # (mutation M17: the waiting row deleted before the candidate was written; a store error between lost it)
        gh = FakeGitHub(repos(1001, 1), code={1001})
        with mock.patch.object(self.store, "add_github_candidates", side_effect=sqlite3.OperationalError("disk")):
            with self.assertRaises(sqlite3.OperationalError):
                self.scan_all(gh)
        self.assertEqual(list(self.listed()), [1001])
        self.scan_all(gh, when=at(0.25))
        self.assertEqual((self.listed(), sorted(self.queued())), ({}, [1001]))

    def test_only_repositories_newer_than_scan_alls_start_are_asked_about(self):
        # (mutation M22: the start itself taken as new)
        self.store.save_discovery_cursor("github-scan-all", 1003)
        gh = FakeGitHub(repos(1001, 6))
        self.scan_all(gh)
        self.assertEqual(gh.posts, [[node_id(k) for k in (1004, 1005, 1006)]])

    def test_a_secondary_limit_answered_200_stops_the_run(self):
        # (MEDIUM 1: the review's p9 made 30 of 30 calls)
        message = "You have exceeded a secondary rate limit. Please wait a few minutes before you try again."
        for answer, headers in (({"data": None, "errors": [{"message": message}]}, {}),
                                ({"data": None, "errors": [{"message": message}]}, {"retry-after": "60"}),
                                (None, {"retry-after": "60"})):
            with self.subTest(answer=answer, headers=headers):
                self.setUp()
                gh = FakeGitHub(repos(1001, 3000))
                gh.answers = [(answer or {"data": {"nodes": [gh.node(k) for k in range(1001, 1101)]}}, headers)]
                out = self.scan_all(gh)
                self.assertEqual((len(gh.posts), out["pages"]), (1, 1))
                self.assertIn("secondary rate limit", out["stopped"])
                self.assertEqual(out["graphql"]["stopped"], out["stopped"])
                self.assertEqual(self.store.discovery_cursor("github")[0], "1100")
                states = {r["state"] for r in self.listed().values()}
                # (the data read when there was some)
                self.assertEqual(states, {"empty"} if answer is None else {"unasked"})

    def test_a_rate_limit_said_in_an_errors_extensions_or_message_stops_the_graphql_part(self):
        for error in ({"message": "x", "extensions": {"code": "RATE_LIMITED"}},
                      {"message": "API rate limit exceeded for user ID 1."}):
            with self.subTest(error=error):
                self.setUp()
                gh = FakeGitHub(repos(1001, 300))
                gh.answers = [{"data": None, "errors": [error]}]
                out = self.scan_all(gh)
                self.assertEqual((len(gh.posts), out["stopped"], out["caughtUp"]), (1, None, True))
                self.assertIn("rate limited", out["graphql"]["stopped"])
                self.assertEqual(out["graphql"]["waiting"], 300)

    def test_a_late_find_is_queued_as_new_and_not_the_first_skipped(self):
        # (MEDIUM 3: it was queued under its listing time, and pruned first by the queue's bound; the re-review's
        # ruling: as of its push, 12:30, held to [its creation, now]; the others' 12:30 is after their run's now)
        gh = FakeGitHub(repos(1001, 4), code={1002, 1003, 1004})
        with mock.patch.object(ghdiscover, "QUEUE_MAX", 3):
            self.scan_all(gh)                                         # (three queued as of 12:00, 1001 empty)
            gh.code.add(1001)
            out = self.scan_all(gh, when=at(1))
        queued = self.queued()
        self.assertEqual(sorted(queued), [1001, 1003, 1004])
        self.assertEqual((queued[1001]["listed_at"], out["queue"]["skipped"]), ("2026-10-14T12:30:00+00:00", 1))
        self.assertEqual({queued[k]["listed_at"] for k in (1003, 1004)}, {"2026-10-14T12:00:00+00:00"})

    def test_the_queue_bound_holds_after_the_listings_asks(self):
        # (mutation M26: the bound applied before the listing alone)
        gh = FakeGitHub(repos(1001, 10), code=set(range(1001, 1011)))
        with mock.patch.object(ghdiscover, "QUEUE_MAX", 4):
            out = self.scan_all(gh)
        self.assertEqual((sorted(self.queued()), out["queue"]["left"], out["queue"]["skipped"]),
                         ([1007, 1008, 1009, 1010], 4, 6))

    def test_dates_and_headers_not_understood_never_end_a_run(self):
        # (MEDIUM 6: OverflowError and ValueError escaped run())
        gh = FakeGitHub(repos(1001, 4), code={1001, 1002, 1003, 1004})
        gh.nodes[node_id(1001)] = {**gh.node(1001), "pushedAt": "9999-12-31T23:59:59-23:59"}
        gh.nodes[node_id(1002)] = {**gh.node(1002), "createdAt": "0001-01-01T00:00:00+23:59"}
        body = {"data": {"nodes": [gh.nodes[node_id(1001)], gh.nodes[node_id(1002)], gh.node(1003), gh.node(1004)],
                         "rateLimit": {"cost": 1, "remaining": 4000, "resetAt": "0001-01-01T00:00:00+05:00"}}}
        gh.answers = [(body, {"x-ratelimit-reset": "999999999999", "x-ratelimit-remaining": "\u00b2"})]
        out = self.scan_all(gh)
        g = out["graphql"]
        self.assertEqual((g["code"], g["unanswered"], g["points"], g["reset"], g["stopped"]), (2, 2, 4000, None, None))
        self.assertEqual(sorted(self.listed()), [1001, 1002])
        for headers in ({"x-ratelimit-remaining": "\u00b2"},
                        {"x-ratelimit-remaining": "3", "x-ratelimit-reset": "9" * 30},
                        {"x-ratelimit-remaining": "-1"},
                        {"x-ratelimit-remaining": "3", "x-ratelimit-reset": "\u00b2"}):
            with self.subTest(headers=headers):
                budget = ghdiscover.Budget(10)
                budget.read(headers)                                  # (REST's: the same pattern, fixed)
                self.assertEqual(budget.stopped is not None, headers["x-ratelimit-remaining"] == "3")
                text = sources._explain(403, {"x-ratelimit-remaining": "0", **{k: v for k, v in headers.items()
                                                                              if k.endswith("reset")}},
                                        f"{API}/x", "w", True, "github")
                self.assertIn("rate limit reached", text)

    def test_answers_of_which_nothing_could_be_read_stop_the_graphql_part_after_a_few_batches(self):
        # (the re-review: whole-call failures in a row count, not each row's; each batch is asked in halves and
        # quarters first, 7 calls, with no control call possible (nothing answered about yet, no other row due),
        # and none of its rows is backed off: GitHub's failure, not theirs)
        gh = FakeGitHub(repos(1001, 500))
        gh.answers = [{"data": None, "errors": [{"message": "Something went wrong"}]}] * 100
        out = self.scan_all(gh)
        g = out["graphql"]
        self.assertEqual([len(p) for p in gh.posts], [100, 50, 50, 25, 25, 25, 25] * ghdiscover.GRAPHQL_FAILURES)
        self.assertEqual((g["failed"], g["unreadable"], g["isolated"], g["unanswered"]), (0, 21, 0, 300))
        self.assertTrue(g["stopped"].startswith("3 batches in a row of which nothing could be read"), g["stopped"])
        self.assertEqual({(r["state"], r["next_check"], r["fails"]) for r in self.listed().values()},
                         {("unasked", "2026-10-14T12:00:00+00:00", 0)})
        self.assertEqual((out["stopped"], out["caughtUp"]), (None, True))     # (the listing goes on)

    def test_the_graphql_part_has_a_wall_clock_bound(self):
        # (each call takes a second of the run's clock: the fakes answer at once, and Windows' monotonic clock moves
        # in steps of some 16 ms, so there a call took no time and three were made before the 1e-9 s were spent)
        gh = FakeGitHub(repos(1001, 300))
        clock, post = [0.0], gh._graphql

        def timed(*a):
            clock[0] += 1
            return post(*a)
        gh._graphql = timed
        with mock.patch.object(ghdiscover, "GRAPHQL_RUN_SECONDS", 1e-9), \
                mock.patch.object(ghdiscover, "_clock", lambda: clock[0]):
            out = self.scan_all(gh)
        self.assertEqual(len(gh.posts), 1)
        self.assertEqual(out["graphql"]["stopped"], "the GraphQL part's 1e-09 seconds for a run were spent")
        self.assertGreater(out["graphql"]["seconds"], 0)

    def test_the_lower_of_the_points_counts_and_the_headers_reset_time(self):
        # (mutations M15, M15b: the higher taken, the header ignored; M35: X-RateLimit-Reset ignored)
        gh = FakeGitHub(repos(1001, 300))
        body = {"data": {"nodes": [gh.node(k) for k in range(1001, 1101)]}}
        body["data"]["rateLimit"] = {"cost": 1, "remaining": 4000, "resetAt": None}
        gh.answers = [(body, {"x-ratelimit-remaining": "50", "x-ratelimit-reset": "1791000000"})]
        out = self.scan_all(gh)
        reset = datetime.datetime.fromtimestamp(1791000000, datetime.timezone.utc)
        self.assertEqual((out["graphql"]["points"], len(gh.posts)), (50, 1))
        self.assertEqual(out["graphql"]["stopped"],
                         f"GitHub's GraphQL rate limit is nearly spent (50 points left, until {reset:%H:%M} UTC)")

    def test_the_newest_first_walk_reads_down_to_where_the_oldest_first_one_read(self):
        # (mutations N3, N31: the newest-first walk not bounded, or bounded at the last row asked, not the last read)
        gh = FakeGitHub(repos(1001, 1500))
        self.scan_all(gh, max_graphql_calls=0)
        for rid in range(1991, 2001):                     # (the first page's last rows: GH Archive queued them since)
            self.store.add_github_candidate(rid, f"user{rid}/project", None, False, [ghdiscover.ALL_PUSHED],
                                            "2026-10-14T12:00:00+00:00", "queued", None)
        reads, read = [], self.store.github_listed

        def recording(**kw):
            reads.append(kw)
            return read(**kw)
        with mock.patch.object(self.store, "github_listed", recording):
            self.scan_all(gh, when=at(0.25), max_graphql_calls=40)          # (a share of 10: the first page)
        newest = [kw for kw in reads if not kw.get("oldest_first") and kw.get("due_by")]
        self.assertEqual({kw["after"] for kw in newest}, {("2026-10-14T12:00:00+00:00", 2000)})
        self.assertEqual(len(gh.posts), 15)                         # (990 oldest first, then 500 newest first)

    def test_the_newest_first_asks_stop_where_the_oldest_first_ones_did(self):
        # (mutation N10: a row the oldest-first share left unanswered asked again by the newest-first walk)
        gh = FakeGitHub(repos(1001, 300))
        self.scan_all(gh, max_graphql_calls=0)
        gh.answers = [failure(f"x: HTTP 500 from {API}/graphql", 500)]
        out = self.scan_all(gh, when=at(0.25), max_graphql_calls=8)          # (a share of 2: 1001-1100, 1101-1200)
        self.assertEqual([p[0] for p in gh.posts], [node_id(1001), node_id(1101), node_id(1300)])
        self.assertEqual((out["graphql"]["unanswered"], out["graphql"]["waiting"]), (100, 100))

    def test_a_reset_time_no_clock_holds_is_left_out(self):
        # (mutation N22: time.gmtime's OverflowError or OSError, which a platform's clock may raise)
        with mock.patch.object(sources.time, "gmtime", side_effect=OverflowError("timestamp out of range")):
            text = sources._explain(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "999999999999"},
                                    f"{API}/x", "w", True, "github")
        self.assertEqual(text, "w: rate limit reached, wait")

    def test_rests_own_limit_stops_rest_alone(self):
        # (the third review: GraphQL spends none of REST's calls; mutation M28 was the other way, before it)
        gh = FakeGitHub(repos(1001, 300), remaining=ghdiscover.RATE_FLOOR + 1)
        out = self.scan_all(gh)
        self.assertIn("rate limit is nearly spent", out["stopped"])
        self.assertEqual((out["pages"], [len(p) for p in gh.posts], out["graphql"]["waiting"]), (1, [100], 0))

    def scans_refused(self, limits, status=403):
        """p15's shape: 200 listed, one queued; the next run's scan refused for a rate limit with `limits`."""
        gh = FakeGitHub(repos(1001, 200), code={1001})
        self.scan_all(gh)
        refused = failure("fetching: rate limit reached, wait until 13:00 UTC", status)
        refused.limits = limits

        def refusing(url, *a, method="GET", **kw):
            if method == "GET" and "/repos/user1001/project" in url:
                raise refused
            return gh(url, *a, method=method, **kw)
        gh.posts.clear()
        return gh, self.scan_all(refusing, when=at(1), max_scans=5)

    def test_a_rest_limit_in_the_scans_leaves_the_asks_going(self):
        # (the third review's p15: the asks after the scans were skipped, 199 left due)
        for limits, status in ((None, 403), ({"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1791000000"}, 403),
                               ({"x-ratelimit-remaining": "0"}, 429)):
            with self.subTest(limits=limits, status=status):
                self.setUp()
                gh, out = self.scans_refused(limits, status)
                self.assertIn("rate limit reached", out["stopped"])
                self.assertEqual((out["pages"], out["cursor"]), (0, None))     # (no listing after it, as before)
                self.assertEqual(([len(p) for p in gh.posts], out["graphql"]["waiting"]), ([100, 99], 0))

    def test_a_secondary_limit_in_the_scans_stops_the_asks_too(self):
        for limits, status in (({"retry-after": "60"}, 403), ({"x-ratelimit-remaining": "4000"}, 429), (None, 429)):
            with self.subTest(limits=limits, status=status):
                self.setUp()
                gh, out = self.scans_refused(limits, status)
                self.assertEqual((gh.posts, out["graphql"]["calls"], out["graphql"]["waiting"]), ([], 0, 199))

    def test_an_error_out_of_the_checks_stops_rests_part_not_the_asks(self):
        # (mutation U13: the scans went on after an error that is no rate limit; none gets out of the checks now,
        # each kept on its candidate, so this one is made up)
        gh = FakeGitHub(repos(1001, 100))
        self.scan_all(gh)
        self.store.add_github_candidate(9, "a/ready", None, False, ["x"], "2026-10-14T10:00:00+00:00", "ready", None)
        self.store.add_github_candidate(8, "a/wait", None, False, ["x"], "2026-10-14T10:00:00+00:00", "waiting",
                                        "2026-10-14T11:00:00+00:00")
        gh.posts.clear()
        with mock.patch.object(ghdiscover, "check", mock.Mock(side_effect=SourceError("checking: something else"))):
            out = self.scan_all(gh, when=at(1), max_scans=5)
        self.assertEqual(out["stopped"], "GitHub answered with an error: checking: something else")
        self.assertEqual((out["scans"], out["pages"], out["cursor"]), ([], 0, None))
        self.assertIsNone(self.store.github_candidates(states=("ready",))[0]["last_error"])     # (not scanned)
        self.assertEqual(([len(p) for p in gh.posts], out["graphql"]["empty"]), ([100], 100))  # (asked as due)

    def test_which_rest_refusal_graphql_shares(self):
        # (sources._explain says "rate limit" for a 429, or a 403 with a Retry-After or no requests left)
        for status, limits, shared in ((403, None, False), (403, {"x-ratelimit-remaining": "0"}, False),
                                       (403, {"x-ratelimit-remaining": "0", "retry-after": "9"}, True),
                                       (403, {"retry-after": "9"}, True), (429, None, True), (429, {}, True),
                                       (429, {"x-ratelimit-remaining": "12"}, True),
                                       (429, {"x-ratelimit-remaining": "0"}, False),
                                       (429, {"x-ratelimit-remaining": "²"}, True)):
            with self.subTest(status=status, limits=limits):
                budget, exc = ghdiscover.Budget(10), failure("x: rate limit reached, wait", status)
                exc.limits = limits
                self.assertTrue(budget.refused(exc))
                self.assertEqual((budget.stopped, budget.shared is not None), ("x: rate limit reached, wait", shared))

    def test_graphql_calls_are_not_charged_to_max_calls(self):
        # (mutation M34: a GraphQL call spent from REST's --max-calls)
        gh = FakeGitHub(repos(1001, 300))
        out = self.scan_all(gh, max_calls=4)                            # (three pages and the empty one: four)
        self.assertEqual((out["pages"], out["caughtUp"], len(gh.posts), out["stopped"]), (3, True, 3, None))


WHOLE = {"data": None, "errors": [{"message": "Something went wrong while executing your query."}]}


class PoisonGitHub(FakeGitHub):
    """FakeGitHub failing the whole query of any call that asks about one of `poison` (repository IDs), and
    answering a FORBIDDEN error, not the node, for one of `forbid`; `answers` first, as FakeGitHub's."""

    def __init__(self, *a, poison=(), forbid=(), **kw):
        super().__init__(*a, **kw)
        self.poison, self.forbid = {node_id(r) for r in poison}, {node_id(r) for r in forbid}

    def _graphql(self, url, headers, data, hosts, reply_headers):
        ids = json.loads(data)["variables"]["ids"]
        if self.answers or not self.poison.intersection(ids):
            answer = super()._graphql(url, headers, data, hosts, reply_headers)
            if self.answers or not self.forbid.intersection(ids):
                return answer
            doc = json.loads(answer)
            for i, n in enumerate(ids):
                if n in self.forbid:
                    doc["data"]["nodes"][i] = None
                    doc.setdefault("errors", []).append({"type": "FORBIDDEN", "path": ["nodes", i]})
            return json.dumps(doc).encode()
        self.posts.append(ids)
        self.bodies.append(None)
        return json.dumps(WHOLE).encode()


class IsolationTests(GqlCase):
    """The re-review's p12 (MEDIUM): a batch of which nothing could be read, for a row GitHub cannot answer about,
    is asked in halves; that row is backed off, never dropped for it, and the rest answered; only failures of the
    call and batches in a row of which nothing could be read, not even in halves and quarters, stop the asking."""

    def rows(self):
        return self.listed()

    def test_poison_rows_are_backed_off_and_the_rest_answered_run_after_run(self):
        # (p12's shapes: 1 and 3 batches of 100 at the old end, each with one row whose node fails the whole query)
        for batches in (1, 3):
            with self.subTest(batches=batches):
                self.setUp()
                poison = [1001 + 100 * b for b in range(batches)]
                gh = PoisonGitHub(repos(1001, 100 * batches), poison=poison)
                nid, waits, seen = 1001 + 100 * batches, [], []
                for run in range(5):
                    if run:
                        new = repos(nid, 300)
                        nid += 300
                        gh.repos += new
                        gh.code |= {r["id"] for r in new[::3]}
                    out = self.scan_all(gh, when=at(run))
                    g, listed = out["graphql"], self.listed()
                    self.assertEqual((g["failed"], g["stopped"], g["waiting"]), (0, None, 0))
                    self.assertEqual(g["code"], 100 if run else 0)
                    self.assertEqual({listed[p]["state"] for p in poison}, {"unasked"})
                    waits.append({(listed[p]["fails"], listed[p]["next_check"]) for p in poison})
                    seen.append(g["isolated"])
                    healthy = [r for rid, r in listed.items() if rid < 1001 + 100 * batches and rid not in poison]
                    self.assertEqual({r["state"] for r in healthy}, {"empty"})          # (all answered)
                    self.assertEqual(len(healthy), 99 * batches)
                # (asked at 0, 1 and 3 hours: backed off 1, 2 and 4 hours)
                self.assertEqual(waits, [{(1, "2026-10-14T13:00:00+00:00")}, {(2, "2026-10-14T15:00:00+00:00")},
                                         {(2, "2026-10-14T15:00:00+00:00")}, {(3, "2026-10-14T19:00:00+00:00")},
                                         {(3, "2026-10-14T19:00:00+00:00")}])
                self.assertEqual(seen, [batches, batches, 0, batches, 0])
                self.assertIn("alone", self.listed()[poison[0]]["last_error"])

    def test_a_poison_row_is_never_dropped_for_it_and_its_wait_stops_growing(self):
        gh = PoisonGitHub(repos(1001, 100), poison=[1050])
        nid, waits = 2001, []
        for hours in (0, 1, 3, 7, 15, 31, 63, 127, 199, 271):
            gh.repos += repos(nid, 10)                          # (a page GitHub answers, each run)
            nid += 10
            self.scan_all(gh, when=at(hours))
            row = self.listed()[1050]
            waits.append((row["fails"], datetime.datetime.fromisoformat(row["next_check"]) - at(hours)))
        self.assertEqual([f for f, _ in waits], list(range(1, 11)))
        self.assertEqual([w.total_seconds() / 3600 for _, w in waits], [1, 2, 4, 8, 16, 32, 64, 72, 72, 72])
        self.assertNotIn(1001, self.listed())                     # (the others: no code by their last ask, dropped)

    def test_a_poison_row_is_found_in_7_levels_of_halves_and_costs_a_few_calls(self):
        gh = PoisonGitHub(repos(1001, 100), poison=[1077])
        out = self.scan_all(gh)
        self.assertEqual([len(p) for p in gh.posts], [100, 50, 50, 25, 25, 13, 12, 7, 6, 4, 3, 2, 2, 1, 1])
        self.assertEqual([1077 in [int(i[6:]) for i in p] for p in gh.posts],
                         [True, False, True, False, True, True, False, True, False, True, False, True, False,
                          False, True])                             # (the half with it asked in halves, level by level)
        g = out["graphql"]
        self.assertEqual((g["calls"], g["isolated"], g["unanswered"], g["unreadable"], g["empty"]), (15, 1, 1, 8, 99))
        row = self.listed()[1077]
        self.assertEqual((row["state"], row["checks"], row["fails"], row["next_check"]),
                         ("unasked", 0, 1, "2026-10-14T13:00:00+00:00"))

    def test_the_halves_are_asked_within_the_runs_calls(self):
        gh = PoisonGitHub(repos(1001, 100), poison=[1001])
        out = self.scan_all(gh, max_graphql_calls=5)
        self.assertEqual([len(p) for p in gh.posts], [100, 50, 50, 25, 25])
        self.assertIn("budget of 5 GraphQL calls", out["graphql"]["stopped"])
        listed = self.listed()
        self.assertEqual({(listed[r]["state"], listed[r]["fails"]) for r in range(1001, 1026)}, {("unasked", 0)})
        self.assertEqual({listed[r]["state"] for r in range(1026, 1101)}, {"empty"})
        self.scan_all(gh, when=at(0.25))                                  # (the next run finds it)
        self.assertEqual((self.listed()[1001]["fails"], self.listed()[1002]["state"]), (1, "empty"))

    def test_more_poison_rows_than_quarters_wait_for_github_to_answer_others(self):
        # (each quarter fails: GitHub's failure, or a row in each; with no control call possible yet, GitHub's
        # answer to the next page tells which)
        poison = [1001, 1030, 1060, 1090]
        gh = PoisonGitHub(repos(1001, 200), poison=poison)
        out = self.scan_all(gh)
        self.assertEqual([len(p) for p in gh.posts[:9]], [100, 50, 50, 25, 25, 25, 25, 100, 13])
        listed, g = self.listed(), out["graphql"]
        self.assertEqual({(listed[p]["state"], listed[p]["fails"]) for p in poison}, {("unasked", 1)})
        self.assertEqual({listed[r]["state"] for r in listed if r not in poison}, {"empty"})
        self.assertEqual(len(listed), 200)
        self.assertEqual((g["isolated"], g["unanswered"], g["stopped"], g["failed"]), (4, 4, None, 0))

    def test_github_failing_for_a_moment_backs_nothing_off(self):
        gh = PoisonGitHub(repos(1001, 300))
        gh.answers = [WHOLE] * 7                                    # (the first batch, its halves and quarters)
        out = self.scan_all(gh)
        listed, g = self.listed(), out["graphql"]
        self.assertEqual({(r["state"], r["fails"]) for r in listed.values()}, {("empty", 0)})
        self.assertEqual((g["isolated"], g["unanswered"], g["empty"], g["stopped"]), (0, 0, 300, None))

    def test_github_failing_every_call_backs_nothing_off_and_the_next_run_asks_again(self):
        gh = PoisonGitHub(repos(1001, 500))
        gh.answers = [WHOLE] * 21                           # (3 batches of 7 calls: no control call possible)
        out = self.scan_all(gh)
        self.assertEqual((len(gh.posts), out["graphql"]["isolated"], out["graphql"]["failed"]), (21, 0, 0))
        self.assertEqual({(r["state"], r["fails"]) for r in self.listed().values()}, {("unasked", 0)})
        self.scan_all(gh, when=at(0.25))
        self.assertEqual({r["state"] for r in self.listed().values()}, {"empty"})

    def test_github_failing_every_call_backs_off_none_of_a_small_batch_either(self):
        for n in (1, 2, 3):
            with self.subTest(rows=n):
                self.setUp()
                gh = PoisonGitHub(repos(1001, n))
                gh.answers = [WHOLE] * 10
                out = self.scan_all(gh)
                self.assertEqual({r["fails"] for r in self.listed().values()}, {0})
                self.assertEqual((out["graphql"]["isolated"], out["graphql"]["unanswered"]), (0, n))

    def test_an_answer_ends_the_streak_of_batches_whose_control_calls_failed(self):
        # (the third review's T10: GitHub failing every call while the listing reads its pages 1, 2, 4 and 5, and
        # answering while it reads 3 and 6: pages 1 and 2 cannot be told apart (nothing answered about yet), 4 and 5
        # are, by a control call that fails too; each streak of 2 ended by an answer, none reaching 3)
        class Flaky(FakeGitHub):
            down = False

            def _listing(self, since):
                self.down = (since - 1000) // 100 in (0, 1, 3, 4)
                return super()._listing(since)

            def _graphql(self, url, headers, data, hosts, reply_headers):
                if self.down:
                    self.posts.append(json.loads(data)["variables"]["ids"])
                    return json.dumps(WHOLE).encode()
                return super()._graphql(url, headers, data, hosts, reply_headers)
        gh = Flaky(repos(1001, 600))
        g = self.scan_all(gh)["graphql"]
        self.assertEqual((g["stopped"], g["empty"], g["isolated"]), (None, 600, 0))
        controls = [p for p in gh.posts if len(p) == 1]
        # (pages 4 and 5: the last answered, page 2's last row, its quarters isolated on after page 3's answer)
        self.assertEqual(controls, [[node_id(1200)], [node_id(1200)]])

    def test_an_answer_ends_the_streak_of_batches_nothing_of_which_could_be_read(self):
        # (batches 1, 2, 4 and 5 with a row GitHub cannot answer about in each quarter: no half or quarter of them
        # can be read; 3 and 6 are answered, which tells their rows apart and ends the streak)
        poison = [1001 + 100 * b + q for b in (0, 1, 3, 4) for q in (0, 25, 50, 75)]
        gh = PoisonGitHub(repos(1001, 600), poison=poison)
        out = self.scan_all(gh)
        listed, g = self.listed(), out["graphql"]
        self.assertEqual((g["stopped"], g["isolated"], g["unanswered"]), (None, 16, 16))
        self.assertEqual({(listed[p]["state"], listed[p]["fails"]) for p in poison}, {("unasked", 1)})
        self.assertEqual({listed[r]["state"] for r in listed if r not in poison}, {"empty"})

    def test_dense_poison_batches_in_a_row_do_not_stop_the_asking(self):
        # (the third review's p12b: three oldest batches with a row GitHub cannot answer about in every quarter were
        # three batches nothing of which could be read, nor of their halves and quarters: 21 calls, stopped, nothing
        # else asked, run after run. A control call about repositories that exist tells them from GitHub failing;
        # the very first run has none to ask about, and stops as on an outage (the fourth review: a call about no
        # repository proves nothing); from the next on they are found)
        poison = [1001 + k for k in range(0, 300, 25)]
        gh = PoisonGitHub(repos(1001, 300), poison=poison)
        gh.code |= set(range(1001, 1301)) - set(poison)
        g = self.scan_all(gh)["graphql"]
        self.assertTrue(g["stopped"].startswith("3 batches in a row"), g["stopped"])
        self.assertEqual((g["calls"], g["code"], g["isolated"]), (21, 0, 0))
        self.assertEqual({r["fails"] for r in self.listed().values()}, {0})
        nid, code = 1301, []
        for run in range(1, 5):
            new = repos(nid, 300)
            nid += 300
            gh.repos += new
            gh.code |= {r["id"] for r in new}
            g = self.scan_all(gh, when=at(run))["graphql"]
            self.assertEqual(g["stopped"], None)
            code.append(g["code"])
        self.assertEqual((sum(code), code[2:]), (288 + 1200, [300, 300]))     # (all found by the third run)
        self.assertEqual(sorted(self.listed()), poison)                 # (waiting, never dropped)
        self.assertEqual({self.listed()[p]["state"] for p in poison}, {"unasked"})
        self.assertTrue(all(self.listed()[p]["fails"] >= 1 for p in poison))

    def test_the_control_call_names_a_repository_github_answered_about(self):
        # (the fourth review's p16: GitHub answering `nodes(ids: [])` while it failed every query that names a
        # repository made the control call blame the rows: 360 to 760 calls, healthy rows backed off. A control
        # call now names a repository GitHub answered about, its answer only read)
        gh = PoisonGitHub(repos(1001, 100))
        self.scan_all(gh)                                                  # (100 answered: empty)
        poison = [1101 + k for k in range(0, 100, 25)]
        gh.repos += repos(1101, 100)
        gh.poison = {node_id(p) for p in poison}
        gh.posts.clear()
        out = self.scan_all(gh, when=at(0.25))                            # (nothing due: the new page alone)
        self.assertEqual(gh.posts[7], [node_id(1100)])            # (none answered this run: the newest found empty)
        listed, g = self.listed(), out["graphql"]
        self.assertEqual((listed[1100]["checks"], listed[1100]["next_check"]), (1, "2026-10-14T13:00:00+00:00"))
        self.assertEqual((g["stopped"], g["isolated"], g["empty"]), (None, 4, 96))
        self.assertNotIn([], gh.posts)

    def test_the_control_call_names_one_github_answered_about_this_run(self):
        # (the first page's repositories all had code: queued, none left waiting to name; the second page has a row
        # GitHub cannot answer about in each quarter)
        poison = [1101 + k for k in range(0, 100, 25)]
        gh = PoisonGitHub(repos(1001, 200), poison=poison, code=range(1001, 1101))
        out = self.scan_all(gh)
        self.assertEqual(gh.posts[8], [node_id(1100)])
        g = out["graphql"]
        self.assertEqual((g["isolated"], g["code"], g["stopped"]), (4, 100, None))
        self.assertEqual(sorted(self.listed()), sorted(set(range(1101, 1201))))

    def test_github_failing_every_query_that_names_a_repository_is_githubs_failure(self):
        # (p16's shapes: rows due, answered by an earlier run, and a fresh page; or the fresh page alone)
        for due, fresh, calls in ((300, 300, 24), (0, 300, 21), (300, 0, 24)):
            with self.subTest(due=due, fresh=fresh):
                self.setUp()
                gh = PoisonGitHub(repos(1001, due))
                if due:
                    self.scan_all(gh)
                gh.repos += repos(5001, fresh)
                self.store.save_discovery_cursor("github", 1000 + due, NOW)
                gh.poison = {r["node_id"] for r in gh.repos}              # (every query naming one fails)
                gh.posts.clear()
                g = self.scan_all(gh, when=at(1))["graphql"]
                self.assertEqual((g["calls"], g["isolated"]), (calls, 0))
                self.assertTrue(g["stopped"].startswith("3 batches in a row"), g["stopped"])
                self.assertNotIn([], gh.posts)
                self.assertEqual({r["fails"] for r in self.listed().values()}, {0})

    def test_the_control_call_asks_the_newest_due_rows_not_asked_yet(self):
        poison = [1001, 1026, 1051, 1076]
        gh = PoisonGitHub(repos(1001, 400), poison=poison)
        self.scan_all(gh, max_graphql_calls=0)                            # (all 400 due, none asked)
        out = self.scan_all(gh, when=at(0.25))
        self.assertEqual([len(p) for p in gh.posts[:7]], [100, 50, 50, 25, 25, 25, 25])
        self.assertEqual(gh.posts[7], [node_id(k) for k in range(1400, 1300, -1)])     # (the control: answered)
        g, listed = out["graphql"], self.listed()
        self.assertEqual((g["stopped"], g["isolated"], g["empty"], g["again"]), (None, 4, 396, 400))
        self.assertEqual({listed[p]["fails"] for p in poison}, {1})

    def test_a_resumed_isolation_backs_off_its_single_rows(self):
        # (the third review's T18: the rows of a batch of two, each failing alone, wait for an answer elsewhere;
        # the next page's gives one, and they are backed off then)
        gh = PoisonGitHub(repos(1001, 4), poison=[1001, 1002], page=2)
        out = self.scan_all(gh)
        self.assertEqual([len(p) for p in gh.posts[:4]], [2, 1, 1, 2])      # (no control possible: the next page)
        listed = self.listed()
        self.assertEqual({listed[k]["fails"] for k in (1001, 1002)}, {1})
        self.assertEqual({listed[k]["fails"] for k in (1003, 1004)}, {0})
        self.assertEqual((out["graphql"]["isolated"], out["graphql"]["stopped"]), (2, None))

    def test_failures_of_the_call_are_not_split_nor_backed_off(self):
        # (a 503 here, where it was a 502: since GH-SCAN-GQL-SPEED a 502 or 504 is GitHub's own time limit for a call,
        # and its batch is asked again in halves: test_ghdiscover_concurrency's TimeLimitTests)
        gh = PoisonGitHub(repos(1001, 300))
        gh.answers = [failure(f"x: HTTP 503 from {API}/graphql", 503), WHOLE, WHOLE,
                      failure(f"x: HTTP 500 from {API}/graphql", 500)]
        out = self.scan_all(gh)
        self.assertEqual([len(p) for p in gh.posts], [100, 100, 50, 50, 100])
        self.assertEqual((out["graphql"]["failed"], out["graphql"]["isolated"]), (2, 0))
        self.assertEqual({(r["state"], r["fails"]) for r in self.listed().values() if r["repo_id"] <= 1200},
                         {("unasked", 0)})

    def test_a_row_githubs_error_names_is_backed_off_its_wait_growing_and_reset_once_answered(self):
        gh = PoisonGitHub(repos(1001, 3), forbid=[1002])
        for hours, wait in ((0, "2026-10-14T13:00:00+00:00"), (1, "2026-10-14T15:00:00+00:00"),
                            (3, "2026-10-14T19:00:00+00:00")):
            out = self.scan_all(gh, when=at(hours))
            row = self.listed()[1002]
            self.assertEqual((row["state"], row["next_check"]), ("unasked", wait))
            self.assertIn("FORBIDDEN", row["last_error"])
        self.assertEqual((row["fails"], out["graphql"]["unanswered"], out["graphql"]["isolated"]), (3, 1, 0))
        gh.forbid.clear()
        self.scan_all(gh, when=at(7))
        row = self.listed()[1002]
        self.assertEqual((row["state"], row["fails"], row["checks"], row["next_check"], row["last_error"]),
                         ("empty", 0, 1, "2026-10-15T12:00:00+00:00", None))


class TimedGitHub(FakeGitHub):
    """FakeGitHub whose repositories were each made and pushed to at a time of their own (`times`: repo_id ->
    (createdAt, pushedAt), the push answered once `code` has it)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.times = {}

    def node(self, rid):
        node = super().node(rid)
        if rid in self.times:
            made, pushed = self.times[rid]
            node.update(createdAt=made, pushedAt=pushed if rid in self.code else None)
        return node


def iso_z(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class PushTimeTests(GqlCase):
    """The re-review's p10 (MEDIUM): what the listing finds with code (fresh) and what an ask finds later (late)
    queue as of when their code arrived, and the scans take them by that."""

    def test_the_time_a_find_is_queued_as(self):
        now = at(1)
        for pushed, created, want in (("2026-10-14T12:30:00Z", "2026-10-14T11:00:00Z", "2026-10-14T12:30:00+00:00"),
                                      ("2026-10-14T10:00:00Z", "2026-10-14T11:00:00Z", "2026-10-14T11:00:00+00:00"),
                                      ("2026-10-14T14:00:00Z", "2026-10-14T11:00:00Z", "2026-10-14T13:00:00+00:00"),
                                      (None, "2026-10-14T11:00:00Z", "2026-10-14T13:00:00+00:00"),
                                      ("x", "2026-10-14T11:00:00Z", "2026-10-14T13:00:00+00:00"),
                                      ("2026-10-14T10:00:00Z", None, "2026-10-14T10:00:00+00:00")):
            with self.subTest(pushed=pushed, created=created):
                self.assertEqual(ghdiscover._code_time({"pushed_at": pushed, "created_at": created}, now), want)

    def test_fresh_and_late_finds_are_scanned_by_push_time_neither_starved(self):
        # (p10's shape with push times as GitHub's: each hour 30 repositories made and pushed to (fresh: listed
        # with code) and 30 made empty, pushed to in the hour after (late: found by the next run's ask); 10 scans
        # a run, a queue of 40; a scan fails at once here, its candidate dropped with its error)
        gh, origin, tried, nid = TimedGitHub([]), {}, [], 1001
        with mock.patch.object(ghdiscover, "QUEUE_MAX", 40):
            for run in range(8):
                gh.code |= {i for i, o in origin.items() if o == "late"}          # (the run before's late ones)
                for k in range(30):
                    made = at(run - 1) + datetime.timedelta(minutes=2 * k)
                    gh.repos += [item(nid, f"f{nid}/p"), item(nid + 1, f"l{nid + 1}/p")]
                    gh.times[nid] = (iso_z(made), iso_z(made + datetime.timedelta(minutes=1)))
                    gh.times[nid + 1] = (iso_z(made), iso_z(at(run) + datetime.timedelta(minutes=2 * k, seconds=90)))
                    gh.code.add(nid)
                    origin[nid], origin[nid + 1] = "fresh", "late"
                    nid += 2
                before = {c["repo_id"] for c in self.store.github_candidates(states=("dropped",))}
                self.scan_all(gh, when=at(run), max_scans=10)
                now = {c["repo_id"] for c in self.store.github_candidates(states=("dropped",)) if c["last_error"]}
                tried.append(sorted(origin[i] for i in now - before))
        # (run 0 has nothing queued yet, run 1 only the fresh of run 0; from then on the 10 pushed last of the hour
        # before, which alternate: late, fresh, late …)
        self.assertEqual([t.count("fresh") for t in tried], [0, 10, 5, 5, 5, 5, 5, 5])
        self.assertEqual([t.count("late") for t in tried], [0, 0, 5, 5, 5, 5, 5, 5])

    def test_a_late_find_waits_for_the_next_runs_scans_as_a_fresh_one_does(self):
        gh = FakeGitHub(repos(1001, 2))
        self.scan_all(gh)                                                  # (both listed empty)
        gh.code.add(1001)
        gh.repos += repos(1003, 1)
        gh.code.add(1003)
        out = self.scan_all(gh, when=at(1), max_scans=10)
        self.assertEqual((out["scans"], sorted(self.queued())), ([], [1001, 1003]))     # (both queued after the scans)


def timed_node(rid, created, pushed):
    """A node GraphQL answers for `rid`, made at `created` and with code pushed at `pushed` (None: still empty)."""
    return {"databaseId": rid, "nameWithOwner": f"user{rid}/project", "isEmpty": pushed is None, "isFork": False,
            "isPrivate": False, "createdAt": iso_z(created), "pushedAt": iso_z(pushed) if pushed else None,
            "diskUsage": 5 if pushed else 0}


class LateShareTests(GqlCase):
    """John's decision of Oct 20: a late find (code found at an ask LATE_HOURS or more after the listing: the 6, 24
    and 72 hours' asks) has LATE_SCAN_SHARE of the queue's scans, rounded up, the first found first; the rest go
    newest push first, and a share not used goes to the other. A scan fails at once here (FakeGitHub has no files):
    its candidate is dropped with its error, which counts it as tried."""

    def tried(self):
        return {c["repo_id"] for c in self.store.github_candidates(states=("dropped",)) if c["last_error"]}

    def queue(self, fresh, late):
        """`fresh` queued finds pushed at 11:00 + k minutes, `late` ones pushed at 06:00 + k minutes and found in
        turn from 09:00 (their late_at); repository IDs from 2001 and 3001."""
        rows = [(2001 + k, f"user{2001 + k}/project", None, False, [ghdiscover.ALL_GRAPHQL],
                 f"2026-10-14T11:{k:02d}:00+00:00", "queued", None) for k in range(fresh)]
        rows += [(3001 + k, f"user{3001 + k}/project", None, False, [ghdiscover.ALL_GRAPHQL],
                  f"2026-10-14T06:{k:02d}:00+00:00", "queued", None, f"2026-10-14T09:{k:02d}:00+00:00")
                 for k in range(late)]
        self.store.add_github_candidates(rows)

    def test_a_find_at_the_6_hours_ask_or_later_is_late(self):
        gh = FakeGitHub(repos(1001, 3))
        self.scan_all(gh)
        gh.code.add(1001)
        one = self.scan_all(gh, when=at(1))                              # (the 1 hour's ask: not late)
        gh.code.add(1002)
        six = self.scan_all(gh, when=at(6))                              # (the 6 hours' ask: late)
        queued = self.queued()
        self.assertEqual((queued[1001]["late_at"], queued[1002]["late_at"]), (None, "2026-10-14T18:00:00+00:00"))
        self.assertEqual((one["graphql"]["late"], six["graphql"]["late"]), (0, 1))

    def test_late_finds_have_a_quarter_of_the_scans_the_first_found_first(self):
        for fresh, late, want_late, want_fresh in (
                (20, 5, [3001, 3002, 3003], list(range(2020, 2013, -1))),     # (3 of 10, then 7 newest)
                (20, 1, [3001], list(range(2020, 2011, -1))),                 # (a share not used: the newest)
                (2, 10, [3001, 3002, 3003] + list(range(3010, 3005, -1)), [2002, 2001]),  # (and the other way)
                (20, 0, [], list(range(2020, 2010, -1)))):                    # (no late find: as before)
            with self.subTest(fresh=fresh, late=late):
                self.setUp()
                self.queue(fresh, late)
                out = self.scan_all(FakeGitHub(), when=at(0.25), max_scans=10)
                tried = self.tried()
                self.assertEqual(sorted(tried), sorted(want_late + want_fresh))
                self.assertEqual(out["queue"]["lateScanned"], len(want_late))
                self.assertEqual(out["queue"]["lateLeft"], late - len(want_late))

    def test_the_late_share_is_of_the_scans_the_ready_ones_leave(self):
        self.queue(20, 5)
        self.store.add_github_candidate(9, "a/ready", None, False, ["x"], "2026-10-14T10:00:00+00:00", "ready", None)
        out = self.scan_all(FakeGitHub(), when=at(0.25), max_scans=5)
        # (the ready one first, kept ready after its failure; a quarter of the 4 left, rounded up, then 3 newest)
        self.assertTrue(self.store.github_candidates(states=("ready",))[0]["last_error"])
        self.assertEqual((sorted(self.tried()), out["queue"]["lateScanned"]), ([2018, 2019, 2020, 3001], 1))

    def test_late_finds_are_scanned_every_run_and_bounded_apart(self):
        # (p10b's shape, the third review: each hour 30 repositories made and pushed to, listed with code, and 10
        # made empty and pushed to 2 to 3 hours after, found at the 6 hours' ask; 10 scans a run, a queue of 40.
        # Before, a late find's push lost the newest-push-first queue to every hour's: none was ever scanned)
        gh, nid, late_ids, scanned, counts = FakeGitHub([]), 1001, set(), [], []
        pushes = {}
        with mock.patch.object(ghdiscover, "QUEUE_MAX", 40):
            for run in range(12):
                t = at(run)
                for rid, (made, when) in list(pushes.items()):
                    if when <= t:
                        gh.nodes[node_id(rid)] = timed_node(rid, made, when)
                        del pushes[rid]
                for k in range(40):
                    made = t - datetime.timedelta(minutes=50 - k)
                    gh.repos.append(item(nid, f"user{nid}/project"))
                    if k < 30:
                        gh.nodes[node_id(nid)] = timed_node(nid, made, made + datetime.timedelta(minutes=1))
                    else:
                        late_ids.add(nid)
                        gh.nodes[node_id(nid)] = timed_node(nid, made, None)
                        pushes[nid] = (made, t + datetime.timedelta(hours=2, minutes=6 * (k - 30)))
                    nid += 1
                before = self.tried()
                out = self.scan_all(gh, when=t, max_scans=10)
                now = self.tried() - before
                scanned.append((len(now - late_ids), len(now & late_ids)))
                counts.append((out["queue"]["lateScanned"], out["graphql"]["late"]))
        # (the late finds of run 0's listing are found at run 6 and scanned from run 7 on: 3 of 10 a run)
        self.assertEqual(scanned, [(0, 0)] + [(10, 0)] * 6 + [(7, 3)] * 5)
        self.assertEqual([c[0] for c in counts], [0] * 7 + [3] * 5)
        self.assertEqual([c[1] for c in counts], [0] * 6 + [10] * 6)
        # (the bounds: 40 newest pushes, 40 late finds found last; the last run's 45th to 41st late find skipped)
        self.assertEqual((out["queue"]["left"], out["queue"]["lateLeft"]), (80, 40))
        self.assertEqual((out["queue"]["skipped"] - out["queue"]["lateSkipped"], out["queue"]["lateSkipped"]), (23, 5))

    def test_the_late_finds_kept_are_the_last_found(self):
        # (found in the other order than pushed: the bound goes by when they were found; mutation U10)
        self.store.add_github_candidates([
            (3001 + k, f"user{3001 + k}/project", None, False, [ghdiscover.ALL_GRAPHQL],
             f"2026-10-14T06:{k:02d}:00+00:00", "queued", None, f"2026-10-14T09:{7 - k:02d}:00+00:00")
            for k in range(8)])
        with mock.patch.object(ghdiscover, "QUEUE_MAX", 5):
            out = self.scan_all(FakeGitHub(), when=at(0.25), max_scans=0)
        self.assertEqual(sorted(self.queued()), [3001, 3002, 3003, 3004, 3005])
        self.assertEqual((out["queue"]["skipped"], out["queue"]["lateSkipped"], out["queue"]["lateLeft"]), (3, 3, 5))


class RunSecondsTests(GqlCase):
    def test_the_oldest_first_share_is_a_quarter_of_the_seconds_as_of_the_calls(self):
        # (the re-review's LOW: the 900 seconds split as the calls are; here every call takes 50 seconds)
        gh = FakeGitHub(repos(1001, 3000))
        self.scan_all(gh, max_graphql_calls=0)
        clock, post = [0.0], gh._graphql

        def slow(*a):
            clock[0] += 50
            return post(*a)
        gh._graphql = slow
        # (GitHub's CPU-time limit's pacing aside here: test_ghdiscover_concurrency's PacingTests)
        with mock.patch.object(ghdiscover, "_clock", lambda: clock[0]), \
                mock.patch.object(ghdiscover, "GRAPHQL_CPU_PER_MINUTE", 1e9):
            out = self.scan_all(gh, when=at(0.25))
        # (225 seconds: 5 calls of the oldest, oldest first; then the newest first until the 900 are spent)
        batches = [(p[0], p[-1], len(p)) for p in gh.posts]               # (compared so: a failure's diff is short)
        self.assertEqual(batches, [(node_id(1001 + 100 * k), node_id(1100 + 100 * k), 100) for k in range(5)]
                         + [(node_id(4000 - 100 * k), node_id(3901 - 100 * k), 100) for k in range(13)])
        g = out["graphql"]
        self.assertEqual((g["calls"], g["seconds"], g["stopped"]),
                         (18, 900.0, "the GraphQL part's 900 seconds for a run were spent"))


class DeadlockTests(unittest.TestCase):
    """MEDIUM 4: two runs at once on one Postgres database deadlocked (40P01 escaped run())."""

    def conn(self, fail_on, sqlstate="40P01", times=1):
        class Rolling(ListedConn):
            left = times

            def execute(self, sql, *args):
                if sql.startswith(fail_on) and self.left:
                    self.left -= 1
                    raise pg.TransactionRollbackError({"S": "ERROR", "C": sqlstate, "M": "deadlock detected"})
                return super().execute(sql, *args)
        return Rolling()

    def test_a_batch_rolled_back_for_a_deadlock_or_a_serialization_failure_is_done_again(self):
        for fail_on, sqlstate in (("UPDATE github_listed", "40P01"), ("INSERT INTO github_candidates", "40001"),
                                  ("INSERT INTO github_listed", "40P01")):
            with self.subTest(fail_on=fail_on, sqlstate=sqlstate):
                conn = self.conn(fail_on, sqlstate)
                store = pg_store(conn)
                with mock.patch.object(repo.time, "sleep", lambda s: None):
                    store.add_github_listed([(9, "R_9", "u/a", None, False, "t", "unasked", "t"),
                                             (7, "R_7", "u/b", None, False, "t", "unasked", "t")])
                    store.save_github_listed(updates=[(9, "empty", "n", 1, None), (7, "empty", "n", 1, None)])
                    store.add_github_candidates([(9, "u/a", None, False, ["x"], "t", "queued", None),
                                                 (7, "u/b", None, False, ["x"], "t", "queued", None)])
                self.assertEqual({r["repo_id"]: r["state"] for r in store.github_listed()}, {9: "empty", 7: "empty"})
                self.assertEqual(sorted(c["repo_id"] for c in store.github_candidates()), [7, 9])
                inserted = [args[0] for s, args in conn.sent if s.startswith("INSERT INTO github_candidates")]
                self.assertEqual(inserted[-2:], [7, 9])                     # (in repo_id order)

    def test_retries_are_bounded_and_other_errors_are_not_retried(self):
        for sqlstate, tries in (("40P01", repo.PG_ROLLBACK_TRIES), ("40003", 1)):
            with self.subTest(sqlstate=sqlstate):
                conn = self.conn("UPDATE github_listed", sqlstate, times=99)
                store = pg_store(conn)
                with mock.patch.object(repo.time, "sleep", lambda s: None), \
                        self.assertRaises(pg.TransactionRollbackError):
                    store.save_github_listed(updates=[(9, "empty", "n", 1, None)])
                self.assertEqual(99 - conn.left, tries)


class PostTests(unittest.TestCase):
    """sources.Client.post and _post: the token, the hosts, redirects, the deadline, the budget."""

    def test_only_https_to_the_api_host(self):
        calls = []
        c = sources.Client("github", token=TOKEN, http=lambda *a, **kw: calls.append((a, kw)) or b"{}")
        for url in ("http://api.github.com/graphql", "https://codeload.github.com/graphql",
                    "https://raw.githubusercontent.com/graphql", "https://evil.example/graphql",
                    "https://api.github.com.evil.example/graphql", "https://user@api.github.com@evil.example/x"):
            with self.subTest(url=url), self.assertRaises(SourceError):
                c.post(url, "w", b"{}")
        self.assertEqual(calls, [])
        c.post(f"{API}/graphql", "w", b'{"query": "q"}')
        (url, headers, max_bytes, hosts, auth_host), kw = calls[0]
        self.assertEqual((url, hosts, auth_host, max_bytes), (f"{API}/graphql", {"api.github.com"}, "api.github.com",
                                                              sources.POST_BYTES))
        self.assertEqual((headers["Authorization"], headers["Content-Type"]), (f"Bearer {TOKEN}", "application/json"))
        self.assertEqual((kw["method"], kw["data"], kw["seconds"]), ("POST", b'{"query": "q"}', sources.POST_SECONDS))
        self.assertNotIn(TOKEN, " ".join(c.calls))

    def test_on_the_native_transport_the_token_is_a_credential_no_redirect_and_a_total_deadline(self):
        asked = []

        def request(url, **kw):
            asked.append((url, kw))
            return sources._net.Reply(200, "HTTP/2", [("x-ratelimit-remaining", "4999")], url, b'{"data": {}}')
        got = {}
        with mock.patch.object(sources._net, "chosen", lambda url: True), \
                mock.patch.object(sources._net, "request", request):
            body = sources.Client("github", token=TOKEN).post(f"{API}/graphql", "w", b"{}", seconds=7,
                                                              reply_headers=got)
        self.assertEqual((body, got), (b'{"data": {}}', {"x-ratelimit-remaining": "4999"}))
        url, kw = asked[0]
        self.assertEqual((kw["method"], kw["data"], kw["max_redirects"], kw["total_timeout"], kw["hosts"]),
                         ("POST", b"{}", 0, 7, ["api.github.com"]))
        self.assertNotIn("Authorization", dict(kw["headers"]))
        self.assertEqual(kw["credentials"], [sources._net.Credential("api.github.com", "/", "Authorization",
                                                                     f"Bearer {TOKEN}")])

    def test_on_the_native_transport_a_redirect_an_error_and_the_budget(self):
        def answering(outcome):
            def request(url, **kw):
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
            return request
        cases = ((sources._net.NetError("http", "too many redirects (limit 0)"), "a POST does not follow", None),
                 (sources._net.NetError("too-large", "response body exceeds"), "exceeds the 1024 KB budget", None),
                 (sources._net.NetError("timeout", "total timeout"), "network error (timeout", None),
                 (sources._net.Reply(302, "HTTP/2", [("location", "https://evil.example/")], "u", b""), "HTTP 302",
                  302),
                 (sources._net.Reply(403, "HTTP/2", [("x-ratelimit-remaining", "0")], "u", b""), "rate limit", 403))
        for outcome, text, status in cases:
            with self.subTest(outcome=outcome), mock.patch.object(sources._net, "chosen", lambda url: True), \
                    mock.patch.object(sources._net, "request", answering(outcome)):
                with self.assertRaises(SourceError) as caught:
                    sources.Client("github", token=TOKEN).post(f"{API}/graphql", "w", b"{}")
                self.assertIn(text, str(caught.exception))
                self.assertEqual(caught.exception.status, status)
                self.assertNotIn(TOKEN, str(caught.exception))

    def test_an_error_answer_keeps_its_rate_limit_headers_alone(self):
        # (the third review: a REST refusal's headers tell GitHub's hourly limit from a secondary one, Budget.shared)
        reply = sources._net.Reply(403, "HTTP/2", [("Retry-After", "60"), ("X-RateLimit-Remaining", "4999"),
                                                   ("Set-Cookie", "s=1"), ("X-RateLimit-Reset", "1" * 50)], "u", b"")
        with mock.patch.object(sources._net, "chosen", lambda url: True), \
                mock.patch.object(sources._net, "request", lambda url, **kw: reply):
            for call in (lambda c: c.get(f"{API}/repos/a/b", "w"), lambda c: c.post(f"{API}/graphql", "w", b"{}")):
                with self.assertRaises(SourceError) as caught:
                    call(sources.Client("github", token=TOKEN))
                self.assertEqual(caught.exception.limits, {"retry-after": "60", "x-ratelimit-remaining": "4999",
                                                           "x-ratelimit-reset": "1" * 40})
        self.assertIsNone(SourceError("x").limits)


NO_LENGTH = object()


class Recorder:
    """An HTTP server on 127.0.0.1 that keeps each request (method, path, headers, body) and answers `status` with
    `body` (and `headers`; `length`, the Content-Length it says, the body's own by default, or none with NO_LENGTH:
    the body ends when the connection does). It reads each request whole before it answers, so that closing the
    connection never resets it."""

    def __init__(self, status=200, body=b'{"data": {}}', headers=(), length=None):
        self.seen = []
        rec = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                rec.seen.append(("POST", self.path, dict(self.headers), self.rfile.read(n)))
                self.send_response(status)
                for k, v in headers:
                    self.send_header(k, v)
                if length is not NO_LENGTH:
                    self.send_header("Content-Length", str(len(body) if length is None else length))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST

            def log_message(self, *args):
                pass
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class UrllibPostTests(unittest.TestCase):
    """_post on urllib's transport (the native one not chosen), against loopback servers."""

    @classmethod
    def setUpClass(cls):
        cls.scripts = ScriptServer({**ROUTES, "/moved": [(head(302, [("Location", "/fast")], length=0), 0)],
                                    "/limited": [(head(403, [("x-ratelimit-remaining", "0"),
                                                             ("x-ratelimit-reset", "1791000000")], length=0), 0)]})

    @classmethod
    def tearDownClass(cls):
        cls.scripts.close()

    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(sources._net, "chosen", lambda url: False))
        stack.enter_context(mock.patch.dict(os.environ))
        for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
            os.environ.pop(name, None)

    def post(self, url, seconds=5.0, max_bytes=sources.POST_BYTES, reply_headers=None):
        host = url.split("/")[2]
        return sources._post(url, {"User-Agent": "t", "Authorization": f"Bearer {TOKEN}",
                                   "Content-Type": "application/json"}, b'{"query": "q"}', max_bytes, {host}, host,
                             what="w", has_token=True, reply_headers=reply_headers, seconds=seconds)

    def test_the_request_is_a_post_of_the_body_with_the_token(self):
        rec = Recorder(headers=[("X-RateLimit-Remaining", "4999")])
        self.addCleanup(rec.close)
        got = {}
        self.assertEqual(self.post(rec.url + "/graphql", reply_headers=got), b'{"data": {}}')
        method, path, headers, body = rec.seen[0]
        self.assertEqual((method, path, body, headers["Authorization"]), ("POST", "/graphql", b'{"query": "q"}',
                                                                          f"Bearer {TOKEN}"))
        self.assertEqual(got["x-ratelimit-remaining"], "4999")

    def test_no_redirect_is_followed(self):
        target = Recorder()
        self.addCleanup(target.close)
        moved = Recorder(status=307, body=b"", headers=[("Location", target.url + "/graphql")])
        self.addCleanup(moved.close)
        with self.assertRaises(SourceError) as caught:
            self.post(moved.url + "/graphql")
        self.assertEqual((caught.exception.status, target.seen), (307, []))
        before = self.scripts.connections
        with self.assertRaises(SourceError) as caught:
            self.post(self.scripts.url + "/moved")
        self.assertEqual((caught.exception.status, self.scripts.connections - before), (302, 1))

    def test_an_error_keeps_its_status_and_headers(self):
        got = {}
        with self.assertRaises(SourceError) as caught:
            self.post(self.scripts.url + "/limited", reply_headers=got)
        self.assertEqual((caught.exception.status, got["x-ratelimit-remaining"]), (403, "0"))
        self.assertEqual(caught.exception.limits["x-ratelimit-remaining"], "0")       # (the rate-limit headers kept)
        self.assertIn("rate limit reached", str(caught.exception))
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_the_total_deadline_holds(self):
        # (each script lasts 4 s or more: a body dripped, headers dripped, a server that says nothing)
        for path in ("/body", "/head", "/mute", "/chunked"):
            with self.subTest(path=path):
                started = time.monotonic()
                with self.assertRaises(SourceError) as caught:
                    self.post(self.scripts.url + path, seconds=0.2)
                took = time.monotonic() - started
                self.assertEqual(str(caught.exception), "w: no answer within 0.2 s")
                self.assertLess(took, 0.2 + ALLOWANCE, f"{took:.3f} s")

    def test_the_byte_budget(self):
        unsaid = Recorder(body=b"x" * (300 * 1024), length=NO_LENGTH)
        self.addCleanup(unsaid.close)
        for url in (self.scripts.url + "/fast", unsaid.url + "/graphql"):
            with self.subTest(url=url), self.assertRaises(SourceError) as caught:
                self.post(url, max_bytes=1024)
            self.assertIn("exceeds the 1 KB budget", str(caught.exception))

    def test_a_body_over_the_budget_with_no_length_said(self):
        # (mutation S6: the budget held loosely; /no-length sends 300 KiB and no Content-Length)
        unsaid = Recorder(body=b"x" * (300 * 1024), length=NO_LENGTH)
        self.addCleanup(unsaid.close)
        with self.assertRaises(SourceError) as caught:
            self.post(unsaid.url + "/graphql", max_bytes=200 * 1024)
        self.assertIn("exceeds the 200 KB budget", str(caught.exception))
        self.assertEqual(self.post(unsaid.url + "/graphql", max_bytes=300 * 1024), b"x" * (300 * 1024))

    def test_a_length_said_over_the_budget_is_refused_before_the_body(self):
        # (mutation S7: /huge says 10**12 bytes, sends 10 and stalls 5 s)
        started = time.monotonic()
        with self.assertRaises(SourceError) as caught:
            self.post(self.scripts.url + "/huge", seconds=3.0)
        self.assertIn("exceeds the 1024 KB budget", str(caught.exception))
        self.assertLess(time.monotonic() - started, 2.0)

    def test_a_body_cut_short(self):
        short = Recorder(body=b"0123456789", length=100)
        self.addCleanup(short.close)
        with self.assertRaises(SourceError) as caught:
            self.post(short.url + "/graphql")
        self.assertIn("ended after 10 of its 100 bytes", str(caught.exception))


class ListedConn(CandidateConn):
    """The fake Postgres connection, github_listed's statements run on SQLite too."""

    def execute_script(self, sql):
        super().execute_script(sql)
        self.script = sql
        for statement in sql.split(";"):
            if "github_listed" in statement and "ADD COLUMN IF NOT EXISTS" not in statement:   # (Postgres's alone)
                self.db.execute(statement)

    def fetch(self, sql, *args):
        if "github_listed" in sql:
            if sql.endswith(" FOR UPDATE"):                 # (SQLite has no row locks: the statement is recorded)
                self.locked = getattr(self, "locked", []) + [list(args)]
                sql = sql[:-len(" FOR UPDATE")]
            return self._run("fetch", sql, args).fetchall()
        return super().fetch(sql, *args)

    def execute(self, sql, *args):
        if "github_listed" in sql:
            self._run(sql.split()[0], sql, args)
            return
        return super().execute(sql, *args)


class StoreTests(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.dir = d.name

    def older(self, name="old.db"):
        """A database as one made before GH-SCAN-GQL: no github_listed, a candidate in it."""
        path = os.path.join(self.dir, name)
        with repo.Store(path) as store:
            store.conn.execute("DROP INDEX idx_github_listed_listed")
            store.conn.execute("DROP TABLE github_listed")
            store.conn.commit()
            store.add_github_candidate(7, "a/b", None, False, ["x"], "2026-10-14T12:00:00+00:00", "queued", None)
        with contextlib.closing(sqlite3.connect(path)) as conn:
            names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
        self.assertNotIn("github_listed", names)
        return path

    def test_an_older_database_opens_and_works_and_opening_twice_changes_nothing(self):
        path = self.older()
        rows = [(1001, "R_1", "u/a", "d", False, "2026-10-14T12:00:00+00:00", "unasked", "2026-10-14T12:00:00+00:00"),
                (1002, "R_2", "u/b", None, True, "2026-10-14T12:00:00+00:00", "unasked", "2026-10-14T12:00:00+00:00")]
        with repo.Store(path) as store:
            store.add_github_listed(rows)
            self.assertEqual(len(store.github_candidates()), 1)
        with repo.Store(path) as store:
            self.assertEqual([r["repo_id"] for r in store.github_listed()], [1002, 1001])
            store.add_github_listed([(1001, "R_9", "u/z", None, False, "2026-10-15T00:00:00+00:00", "empty", "x")])
            self.assertEqual(store.github_listed(limit=1)[0]["node_id"], "R_2")
            self.assertEqual(store.github_listed_known([1001, 5]), {1001})
        with contextlib.closing(sqlite3.connect(path)) as conn:
            indexes = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        self.assertIn("idx_github_listed_listed", indexes)

    def test_a_table_made_before_fails_gets_it(self):
        # (the third review's p14: a github_listed of the first versions, without `fails`, raised "no such column")
        path = os.path.join(self.dir, "draft.db")
        with contextlib.closing(sqlite3.connect(path)) as conn:
            conn.execute(repo._listed_table().replace(" fails INTEGER NOT NULL DEFAULT 0,", ""))
            conn.execute("INSERT INTO github_listed VALUES (1, 'R_1', 'u/a', NULL, 0, '2026-10-14T12:00:00+00:00', "
                         "'unasked', '2026-10-14T12:00:00+00:00', 0, NULL, 'x')")
            conn.commit()
            self.assertNotIn("fails", {r[1] for r in conn.execute("PRAGMA table_info(github_listed)")})
        for _ in range(2):
            with repo.Store(path) as store:
                (row,) = store.github_listed()
                self.assertEqual((row["repo_id"], row["fails"]), (1, 0))
        with repo.Store(path) as store:
            store.save_github_listed([(1, "unasked", "2026-10-14T13:00:00+00:00", 0, "e", 1)])
            self.assertEqual(store.github_listed()[0]["fails"], 1)

    def test_a_candidates_table_made_before_late_at_gets_it(self):
        path = os.path.join(self.dir, "cands.db")
        with contextlib.closing(sqlite3.connect(path)) as conn:
            conn.execute(repo._candidate_table().replace(", late_at TEXT", ""))
            conn.execute("INSERT INTO github_candidates (repo_id, full_name, fork, filters, listed_at, state, checks, "
                         "updated_at) VALUES (7, 'a/b', 0, '[]', '2026-10-14T12:00:00+00:00', 'queued', 0, 'x')")
            conn.commit()
            self.assertNotIn("late_at", {r[1] for r in conn.execute("PRAGMA table_info(github_candidates)")})
        for _ in range(2):
            with repo.Store(path) as store:
                self.assertEqual([(c["repo_id"], c["late_at"]) for c in store.github_candidates()], [(7, None)])
        with repo.Store(path) as store:
            store.add_github_candidates([(8, "a/c", None, False, [], "2026-10-14T06:00:00+00:00", "queued", None,
                                          "2026-10-14T12:00:00+00:00")])
            self.assertEqual([c["repo_id"] for c in store.github_candidates(late=True)], [8])
            self.assertEqual([c["repo_id"] for c in store.github_candidates(late=False)], [7])

    def test_two_openers_of_an_older_database_at_once(self):
        path = self.older("race.db")
        errors, start = [], threading.Barrier(4)

        def open_it():
            try:
                start.wait()
                repo.Store(path).close()
            except Exception as exc:                                            # noqa: BLE001
                errors.append(exc)
        threads = [threading.Thread(target=open_it) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(errors, [])
        with repo.Store(path) as store:
            self.assertEqual(store.github_listed_counts(), {})

    def test_the_queries(self):
        with repo.Store(os.path.join(self.dir, "q.db")) as store:
            self.assert_queries(store)

    def assert_queries(self, store):
        t0, t1 = "2026-10-14T12:00:00+00:00", "2026-10-14T13:00:00+00:00"
        store.add_github_listed([(k, f"R_{k}", f"u/r{k}", None, False, t0 if k < 4 else t1, "empty",
                                  t1 if k % 2 else "2026-10-14T18:00:00+00:00") for k in range(1, 7)])
        self.assertEqual([r["repo_id"] for r in store.github_listed()], [6, 5, 4, 3, 2, 1])
        self.assertEqual([r["repo_id"] for r in store.github_listed(due_by=t1)], [5, 3, 1])
        self.assertEqual([r["repo_id"] for r in store.github_listed(before=(t1, 5), limit=3)], [4, 3, 2])
        self.assertEqual([r["repo_id"] for r in store.github_listed(oldest_first=True)], [1, 2, 3, 4, 5, 6])
        self.assertEqual([r["repo_id"] for r in store.github_listed(due_by=t1, after=(t0, 1), oldest_first=True)],
                         [3, 5])
        self.assertEqual([r["repo_id"] for r in store.github_listed(before=(t1, 6), after=(t0, 2))], [5, 4, 3])
        self.assertEqual(store.github_listed_counts(listed_before=t1), {"empty": 3})
        store.save_github_listed(updates=[(6, "empty", t1, 1, None), (3, "fork", "2026-10-15T12:00:00+00:00", 2, "e"),
                                          (5, "empty", t1, 9, None)], deletes=[5, 99])
        self.assertEqual(store.github_listed_counts(), {"empty": 4, "fork": 1})
        self.assertEqual(store.github_listed_counts(due_by=t1), {"empty": 2})
        row = next(r for r in store.github_listed() if r["repo_id"] == 3)
        self.assertEqual((row["state"], row["checks"], row["last_error"]), ("fork", 2, "e"))
        self.assertEqual(store.prune_github_listed(keep=3), 2)
        self.assertEqual([r["repo_id"] for r in store.github_listed()], [6, 4, 3])
        self.assertEqual(store.prune_github_listed(before=t1), 1)
        self.assertEqual([r["repo_id"] for r in store.github_listed()], [6, 4])

    def test_postgres_statements(self):
        conn = ListedConn()
        store = pg_store(conn)
        self.assertIn("CREATE TABLE IF NOT EXISTS github_listed (repo_id BIGINT PRIMARY KEY", conn.script)
        self.assertIn("CREATE INDEX IF NOT EXISTS idx_github_listed_listed ON github_listed(listed_at, repo_id)",
                      conn.script)
        self.assertIn("ALTER TABLE github_listed ADD COLUMN IF NOT EXISTS fails INTEGER NOT NULL DEFAULT 0",
                      conn.script)
        self.assertIn("ALTER TABLE github_candidates ADD COLUMN IF NOT EXISTS late_at TEXT", conn.script)
        self.assert_queries(store)
        sent = [s for s, _ in conn.sent]
        self.assertTrue(any("WHERE next_check <= $1 ORDER BY listed_at DESC, repo_id DESC" in s for s in sent))
        # (a row-value comparison, which the index on (listed_at, repo_id) serves as a range)
        self.assertTrue(any("WHERE (listed_at, repo_id) < ($1, $2) ORDER BY" in s for s in sent))
        self.assertTrue(any(s.endswith("WHERE next_check <= $1 AND (listed_at, repo_id) > ($2, $3) ORDER BY listed_at, "
                                       "repo_id") for s in sent))
        self.assertTrue(any("WHERE (listed_at, repo_id) < ($1, $2) AND (listed_at, repo_id) > ($3, $4)" in s
                            for s in sent))
        self.assertTrue(any(s.startswith("UPDATE github_listed SET state=$1, next_check=$2, checks=$3, fails=$4, "
                                         "last_error=$5, updated_at=$6 WHERE repo_id=$7") for s in sent))
        # (the batch: its rows locked first, in repo_id order; its updates in that order, the deleted left out)
        self.assertIn([3, 5, 6, 99], conn.locked)
        updates = [args[-1] for s, args in conn.sent if s.startswith("UPDATE github_listed")]
        self.assertEqual(updates, [3, 6])
        self.assertTrue(any("VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (repo_id) DO NOTHING" in s
                            for s in sent if "github_listed" in s))

    def test_schema_sql_has_the_table_its_index_and_its_grant(self):
        path = os.path.join(os.path.dirname(repo.__file__), "schema.sql")
        with open(path, encoding="utf-8") as f:
            sql = f.read()
        body = re.search(r"CREATE TABLE IF NOT EXISTS github_listed \((.*?)\n\);", sql, re.S).group(1)
        columns = [line.split()[0] for line in body.splitlines() if line.strip() and not line.strip().startswith("--")]
        self.assertEqual(tuple(columns), repo.LISTED_COLUMNS)
        self.assertIn("CREATE INDEX IF NOT EXISTS idx_github_listed_listed ON github_listed(listed_at, repo_id);", sql)
        self.assertIn("ALTER TABLE github_listed ADD COLUMN IF NOT EXISTS fails INTEGER NOT NULL DEFAULT 0;", sql)
        self.assertIn("ALTER TABLE github_candidates ADD COLUMN IF NOT EXISTS late_at TEXT;", sql)
        body = re.search(r"CREATE TABLE IF NOT EXISTS github_candidates \((.*?)\n\);", sql, re.S).group(1)
        columns = [line.split()[0] for line in body.splitlines() if line.strip() and not line.strip().startswith("--")]
        self.assertEqual(tuple(columns), repo.CANDIDATE_COLUMNS)
        self.assertIn("GRANT SELECT, INSERT, UPDATE, DELETE ON github_listed TO lazaret_app;", sql)


class CommandLineTests(GqlCase):
    def cli(self, *argv, gh=None):
        gh = gh or FakeGitHub()
        archive = FakeArchive()

        def both(url, *a, **kw):
            return (archive if "gharchive" in url else gh)(url, *a, **kw)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["lazaret-registry", *argv, "--db", self.db]), \
                mock.patch.dict(os.environ, ENV), mock.patch.object(sources, "_http", both), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_a_run_says_what_graphql_said_and_list_counts_what_waits(self):
        gh = FakeGitHub(repos(1001, 250), code={1001, 1002})
        gh.nodes[node_id(1003)] = None
        code, out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all",
                                  "--max-scans", "0", "--max-graphql-calls", "2", gh=gh)
        self.assertEqual(code, 0, err)
        self.assertIn("  GraphQL: asked about 200 new repositories in 2 call(s) (200 just listed, 0 again): 2 had code "
                      "(queued), 197 empty, 0 forks with no push of their own, 1 gone, 0 not answered; 4,998 points "
                      "left (until 13:00 UTC)", out)
        self.assertIn("  GraphQL: 247 listed repositories wait for code (asked again 1, 6, 24 and 72 hours after they "
                      "were listed)", out)
        self.assertIn("  GraphQL: stopped: the run's budget of 2 GraphQL calls (--max-graphql-calls) was spent; "
                      "50 wait to be asked (the next run asks them)", out)
        self.assertIn("warning: github discovery's GraphQL part stopped early: the run's budget of 2 GraphQL "
                      "calls", err)
        code, out, _err = self.cli("list")
        self.assertIn("Every new repository (--github-scan-all): queued 2; waiting for code (asked of GitHub's "
                      "GraphQL API): empty 197, unasked 50", out)

    def test_the_option_goes_with_github_discovery_and_takes_a_count(self):
        code, _out, err = self.cli("discover", "--max-graphql-calls", "3")
        self.assertEqual(code, 2)
        self.assertIn("--max-graphql-calls: these go with discover --ecosystem github --resume", err)
        code, _out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all",
                                   "--max-graphql-calls", "-1")
        self.assertIn("--max-graphql-calls takes a number of calls, 0 or more", str(code) + err)
        code, _out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--max-graphql-calls", "3")
        self.assertEqual(code, 2)
        self.assertIn("--max-graphql-calls goes with --github-scan-all", err)

    def test_evictions_and_items_without_a_node_id_are_said_on_stderr(self):
        gh = FakeGitHub(repos(1001, 8) + [{**item(1009, "u/no-node"), "node_id": None}])
        with mock.patch.object(ghdiscover, "LISTED_MAX", 5):
            code, out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all",
                                      "--max-scans", "0", gh=gh)
        self.assertEqual(code, 0, err)
        self.assertIn("warning: github discovery evicted 3 listed repositories still waiting for code: the set keeps "
                      "the newest 5", err)
        self.assertIn("warning: GitHub listed 1 new repositories without a node ID", err)
        self.assertIn("dropped 3 over the bound (the newest 5 are kept)", out)
        self.assertIn("  GraphQL: 1 listed without a node ID, so not asked: their content is checked by REST", out)

    def test_a_run_says_how_many_calls_could_not_be_read_and_who_waits_for_it(self):
        gh = PoisonGitHub(repos(1001, 100), poison=[1050])
        code, out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all",
                                  "--max-scans", "0", gh=gh)
        self.assertEqual(code, 0, err)
        self.assertIn("  GraphQL: 7 call(s) of which nothing could be read (an error of the whole query, or an answer "
                      "not as asked), their repositories asked again in halves; 1 repositories GitHub could not "
                      "answer about wait to be asked again (1, 2, 4 ... hours on, at most 72)", out)
        self.assertIn("99 empty, 0 forks with no push of their own, 0 gone, 1 not answered", out)

    def test_a_run_says_how_many_late_finds_were_scanned_and_wait(self):
        LateShareTests.queue(self, 20, 5)
        code, out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all", "--scan",
                                  "--max-scans", "10")
        self.assertEqual(code, 1, err)                          # (FakeGitHub has no files: each scan fails)
        self.assertIn("  scanned 0 this run (3 of them late finds: code found 6 hours or more after the listing, which "
                      "have 25% of the queue's scans); 15 left in the queue (2 late finds)", out)

    def test_the_help_names_the_option(self):
        code, out, _err = self.cli("--help")
        self.assertEqual(code, 0)
        self.assertIn("--max-graphql-calls 1000", out)
        self.assertIn("asks GitHub's GraphQL API which new repositories got code", " ".join(out.split()))


if __name__ == "__main__":
    unittest.main()
