"""Scan-all's GraphQL calls paced to GitHub's CPU-time limit and made several at once (GH-SCAN-GQL-SPEED, 0.1.9:
ghdiscover's `_Calls` and `_Asker`, --graphql-concurrency, --graphql-seconds).

GitHub is test_ghdiscover's FakeGitHub (and test_ghdiscover_graphql's PoisonGitHub) behind `Held`: each GraphQL call
waits on its own thread until the run, about to wait for an answer, lets one go, once every call it started is
waiting; `pick` chooses which (the first started, the last, one at random from a seed), or each call takes so many
seconds on a fake clock and the first to end goes, so that calls overlap and end in any order, and what a run sees is
the same each time the tests run. Nothing sleeps: the pacing waits on the fake clock, and a wait that would hang fails
the test after WAIT seconds instead. Covered: one at a time by default, at most eight and the GraphQL seconds 1 to
3,600; the pacing (eight at once of calls of 3.5 s keep under 50 s of calls in any minute, some 14 calls a minute;
fast calls have eight in flight; one at a time is paced too, its waits counted towards the GraphQL seconds, the due
share a quarter of them; the report); N calls in flight at once and never more, the first alone; the listing going on
while its pages are asked about; the answers ending in any order storing what one at a time stores (and the calls
started in its order), over runs with code, forks, gone, GitHub's errors for some rows, rows that fail the whole query
and control calls; the wall clock and the due share's seconds on a fake clock, not the sum of the calls' times; the
call budget and the points' floor with calls in flight; a secondary limit and a failure of the call mid-flight (no new
call, the answers in flight stored once each, the window reopened by a call started since); failures in flight
together counted as one; isolation and control calls one at a time; GitHub's own time limit for a call (502, 504)
asked again in halves, at one and at eight calls at once; the database written from the run's thread alone, on SQLite
and on Postgres's statements (and on a live Postgres: test_ghdiscover_concurrency_pg); no call's thread left after a
run, an error of the store or of the seam; the POST from eight threads at once on each transport, against a local
HTTPS server, a connection each; the options and the run's report. Names and IDs are made up; nothing reaches the
network."""

import collections
import contextlib
import http.server
import io
import json
import os
import random
import re
import sqlite3
import ssl
import sys
import tempfile
import threading
import unittest
from unittest import mock

from tests import _support  # noqa: F401
from lazaret.registry import ghdiscover, repo, sources
from tests.registry.test_ghdiscover import API, ENV, NOW, FakeGitHub, at, failure, item, node_id
from tests.registry.test_ghdiscover_archive import FakeArchive
from tests.registry.test_ghdiscover_at_eight import answered_in_turn
from tests.registry.test_ghdiscover_graphql import GqlCase, ListedConn, PoisonGitHub, repos
from tests.registry.test_review_store_reconnect import pg_store

#: seconds a test waits for a call to come or to be let go before it fails (never reached when all is well)
WAIT = 10.0
WIDTH = ghdiscover.GRAPHQL_CONCURRENCY_MAX


def first(held):
    return held[0]


def last(held):
    return held[-1]


def at_random(seed):
    rng = random.Random(seed)
    return lambda held: rng.choice(held)


#: a call let go: its ticket (its number in the run), its node IDs, the calls in flight then (it among them, every one
#: held) and the calls started by then
Released = collections.namedtuple("Released", "ticket ids flying started")


class Held:
    """The network seam with GitHub's GraphQL answers held: a POST waits on its thread until `let_go` lets it go to
    `gh`; REST's calls go to `gh` at once (on the run's thread). `released` keeps each call let go (`Released`), in
    that order; `clock`, a list, is moved on by `step` seconds each time. With `seconds`, each call takes that long
    on `clock` from when it came (or as long as `seconds(node IDs)` says): the one that ends first is let go, the clock
    moved to its end (`ends`: each call's end and response time)."""

    def __init__(self, gh, pick=first, clock=None, step=0.0, seconds=None):
        self.gh, self.pick, self.clock, self.step, self.seconds = gh, pick, clock, step, seconds
        self.cond = threading.Condition()
        self.held, self.released, self.threads, self.most, self.started = [], [], set(), 0, 0
        self.came, self.took, self.ends = {}, {}, []

    def __call__(self, url, *a, method="GET", **kw):
        if method != "POST":
            return self.gh(url, *a, method=method, **kw)
        me = threading.current_thread()
        ticket = int(me.name.rsplit("-", 1)[1])          # (ghdiscover names a call's thread by its number in the run)
        go = threading.Event()
        with self.cond:
            self.threads.add(me.name)
            self.held.append((ticket, json.loads(kw["data"])["variables"]["ids"], go))
            self.most, self.started = max(self.most, len(self.held)), max(self.started, ticket)
            self.came[ticket] = self.clock[0] if self.clock is not None else None
            if self.seconds is not None:
                ids = self.held[-1][1]
                self.took[ticket] = self.seconds(ids) if callable(self.seconds) else self.seconds
            self.cond.notify_all()
        if not go.wait(WAIT):
            raise AssertionError(f"GraphQL call {ticket} was never let go")
        return self.gh(url, *a, method=method, **kw)

    def let_go(self, started, every=False):
        """Once the `started` calls in flight are all held: one of them let go (`pick`), or `every` one."""
        with self.cond:
            if not self.cond.wait_for(lambda: len(self.held) >= started, WAIT):
                raise AssertionError(f"{started} GraphQL calls in flight, {len(self.held)} came")
            held = sorted(self.held, key=lambda h: h[0])
            if every:
                chosen = held
            elif self.seconds is not None:
                chosen = [min(held, key=lambda h: (self.came[h[0]] + self.took[h[0]], h[0]))]
                self.clock[0] = max(self.clock[0], self.came[chosen[0][0]] + self.took[chosen[0][0]])
                self.ends.append((self.clock[0], self.clock[0] - self.came[chosen[0][0]]))
            else:
                chosen = [self.pick(held)]
            for h in chosen:
                self.held.remove(h)
                self.released.append(Released(h[0], h[1], len(held), self.started))
        if self.clock is not None and self.seconds is None:
            self.clock[0] += self.step
        for h in chosen:
            h[2].set()

    def tickets(self):
        return [r.ticket for r in self.released]

    def starts(self):
        """The node IDs of each call, in the order the calls were started."""
        return [r.ids for r in sorted(self.released)]


@contextlib.contextmanager
def holding(held):
    """ghdiscover's calls answered through `held`: when the run would wait for one (`_Calls.next` blocking with none
    ended), one is let go; when it ends them after an error (`_Calls.close`), every one."""
    nxt, close = ghdiscover._Calls.next, ghdiscover._Calls.close

    def next_(pool, block):
        if block and pool.threads and pool.done.empty():
            held.let_go(len(pool.threads))
        return nxt(pool, block)

    def close_(pool):
        if pool.threads:
            held.let_go(len(pool.threads) - pool.done.qsize(), every=True)
        return close(pool)
    with mock.patch.object(ghdiscover._Calls, "next", next_), mock.patch.object(ghdiscover._Calls, "close", close_):
        yield held


def call_threads():
    return [t.name for t in threading.enumerate() if t.name.startswith("lazaret-graphql-")]


class Timing(FakeGitHub):
    """FakeGitHub that ends a GraphQL call of more than `most` node IDs at its own time limit (`status`: 502 or 504),
    as GitHub's GraphQL API ends a call over 10 seconds."""

    def __init__(self, *a, most=60, status=502, **kw):
        super().__init__(*a, **kw)
        self.most, self.status = most, status

    def _graphql(self, url, headers, data, hosts, reply_headers):
        ids = json.loads(data)["variables"]["ids"]
        if len(ids) > self.most:
            self.posts.append(ids)
            raise failure(f"asking: HTTP {self.status} from {API}/graphql", self.status)
        return super()._graphql(url, headers, data, hosts, reply_headers)


class Failing(FakeGitHub):
    """FakeGitHub answering a GraphQL call that asks about one of `at` (repository IDs), or every call after the
    first `fine` ones, with `answer`: an error raised, or (a document, its headers)."""

    def __init__(self, *a, at=(), fine=None, answer=None, **kw):
        super().__init__(*a, **kw)
        self.at, self.fine, self.answer, self.calls = {node_id(r) for r in at}, fine, answer, 0

    def _graphql(self, url, headers, data, hosts, reply_headers):
        ids = json.loads(data)["variables"]["ids"]
        self.calls += 1
        if self.at.intersection(ids) or (self.fine is not None and self.calls > self.fine):
            self.posts.append(ids)
            if isinstance(self.answer, Exception):
                raise self.answer
            doc, more = self.answer
            reply_headers.update(more)
            return json.dumps(doc).encode()
        return super()._graphql(url, headers, data, hosts, reply_headers)


#: what one at a time and calls at once must store and say alike (not the points, the last error's text, the seconds
#: or how many were at once, which the order of the answers moves)
SAME = ("listed", "asked", "fresh", "again", "calls", "code", "empty", "forks", "gone", "unanswered", "isolated",
        "late", "campaigns", "excluded", "expired", "aged", "over", "noNode", "failed", "unreadable", "timeouts",
        "stopped", "waiting", "kept")


class ConcurrencyCase(GqlCase):
    def held_run(self, gh, pick=first, clock=None, step=0.0, store=None, seconds=None, **kw):
        """A scan-all run at WIDTH calls at once, its calls held (`Held`) -> (the run's result, the Held)."""
        held = Held(gh, pick, clock, step, seconds)
        kw.setdefault("filters", ghdiscover.Filters())
        kw.setdefault("max_scans", 0)
        kw.setdefault("when", NOW)
        when = kw.pop("when")
        with holding(held):
            out = ghdiscover.run(self.store if store is None else store, env=ENV, http=held, now=when,
                                 archive_http=FakeArchive(), scan_all=True, graphql_concurrency=WIDTH, **kw)
        self.assertEqual(call_threads(), [])                        # (none left once the run returns)
        return out, held

    def due(self, n, cls=FakeGitHub, **kw):
        """`n` repositories listed from 1001 on and none asked: all due at at(0.25). -> the fake (`cls`, made with
        `kw`), which made no GraphQL call yet."""
        gh = cls(repos(1001, n), **kw)
        self.scan_all(gh, max_graphql_calls=0, graphql_concurrency=1)
        return gh

    def stored(self):
        """What github_listed and github_candidates hold, every column that a run writes."""
        listed = sorted((r["repo_id"], r["state"], r["next_check"], r["checks"], r["fails"], r["last_error"])
                        for r in self.store.github_listed())
        cands = sorted((c["repo_id"], c["full_name"], c["state"], c["listed_at"], c["late_at"], tuple(c["filters"]))
                       for c in self.store.github_candidates())
        return listed, cands


class InFlightTests(ConcurrencyCase):
    def test_n_calls_in_flight_at_once_the_first_alone_and_never_more(self):
        gh = self.due(2000)
        out, held = self.held_run(gh, when=at(0.25))
        g = out["graphql"]
        self.assertEqual((g["calls"], g["atOnce"], held.most, g["concurrency"]), (20, WIDTH, WIDTH, WIDTH))
        # (the first alone until its answer is read, then eight at once; the last ones end as none starts)
        self.assertEqual([r.flying for r in held.released], [1] + [WIDTH] * 12 + list(range(WIDTH - 1, 0, -1)))
        self.assertEqual(held.tickets(), list(range(1, 21)))
        # (started oldest first, the due share holding them all; on threads of their own, not the run's)
        self.assertEqual(sum(held.starts(), []), [node_id(k) for k in range(1001, 3001)])
        self.assertEqual(held.threads, {f"lazaret-graphql-{k}" for k in range(1, 21)})
        self.assertEqual((g["asked"], g["again"], g["empty"], g["waiting"], g["stopped"]), (2000, 2000, 2000, 0, None))
        self.assertEqual({(r["state"], r["checks"]) for r in self.listed().values()}, {("empty", 1)})

    def test_the_listing_goes_on_while_its_pages_are_asked_about(self):
        gh = FakeGitHub(repos(1001, 1500), code=range(1001, 2501, 7))
        pages = []
        held = Held(gh)
        let_go = held.let_go

        def noting(started, every=False):
            pages.append(len(gh.asked("/repositories?since=")))
            return let_go(started, every)
        held.let_go = noting
        with holding(held):
            out = self.scan_all(held, graphql_concurrency=WIDTH)
        g = out["graphql"]
        self.assertEqual((out["pages"], out["caughtUp"], g["calls"], g["fresh"], g["atOnce"]),
                         (15, True, 15, 1500, WIDTH))
        # (page 1's call answered alone; then the listing read on: pages 2 to 9 asked about at once, and page 10
        # read while they were in flight; then a page more for each call that ended)
        self.assertEqual(pages[:4], [1, 10, 11, 12])
        self.assertEqual(sum(held.starts(), []), [node_id(k) for k in range(1001, 2501)])
        self.assertEqual(sorted(self.queued()), list(range(1001, 2501, 7)))

    def test_by_default_one_at_a_time_and_no_thread(self):
        gh = FakeGitHub(repos(1001, 300))
        with mock.patch.object(ghdiscover, "_spawn", side_effect=AssertionError("a thread at a concurrency of 1")):
            out = self.scan_all(gh)
        self.assertEqual((out["graphql"]["calls"], out["graphql"]["concurrency"], out["graphql"]["atOnce"]), (3, 1, 1))
        self.assertEqual((ghdiscover.DEFAULT_GRAPHQL_CONCURRENCY, WIDTH, out["graphql"]["runSeconds"]), (1, 8, 900))

    def test_the_concurrency_is_one_to_eight_and_the_seconds_one_to_3600(self):
        for bad in (0, -1, 9, True, 2.5, "8"):
            with self.subTest(concurrency=bad), self.assertRaises(ghdiscover.DiscoveryError) as caught:
                self.scan_all(FakeGitHub(), graphql_concurrency=bad)
            self.assertIn("--graphql-concurrency takes a number of calls at once, 1 to 8", str(caught.exception))
        for bad in (0, 0.5, -1, 3601, True, "900"):
            with self.subTest(seconds=bad), self.assertRaises(ghdiscover.DiscoveryError) as caught:
                self.scan_all(FakeGitHub(), graphql_seconds=bad)
            self.assertIn("--graphql-seconds takes a number of seconds, 1 to 3600", str(caught.exception))
        out = self.scan_all(FakeGitHub(repos(1001, 1)), graphql_concurrency=8, graphql_seconds=3600)
        self.assertEqual((out["graphql"]["concurrency"], out["graphql"]["runSeconds"]), (8, 3600))


class OrderTests(ConcurrencyCase):
    """The answers end in any order, and what is asked and stored is what one at a time asks and stores."""

    PICKS = (("first", first), ("last", last), ("random 1", at_random(1)), ("random 2", at_random(2)),
             ("random 3", at_random(3)))

    def replay(self, run):
        """Three runs: a listing with code, forks (one pushed to), one gone, GitHub's errors for two rows, a row that
        fails the whole query and a page with such a row in every quarter (no control call possible yet); an hour
        later, more listed and due rows with code now, and a due batch with such a row in every quarter (control
        calls); six hours on, late finds. -> what was stored and said after each."""
        poison = [1250, 1601, 1626, 1651, 1676, 1907, 1932, 1957, 1982]
        gh = PoisonGitHub(repos(1001, 700) + [item(1701 + k, f"u{k}/fork", fork=True) for k in range(4)],
                          poison=poison, forbid=[1111, 1555], code=set(range(1001, 1701, 9)) | {1701})
        gh.nodes[node_id(1020)] = None                                      # (gone: null, NOT_FOUND)
        gh.nodes[node_id(1702)] = {**gh.node(1702), "isEmpty": False, "pushedAt": "2026-10-14T11:59:00Z"}
        seen = []
        for when, new in ((NOW, None), (at(1), repos(1901, 300)), (at(6), None)):
            if new:
                gh.repos += new
                gh.code |= set(range(1002, 1701, 13)) | {r["id"] for r in new[::5]}
            if when == at(6):
                gh.code |= set(range(1003, 1701, 17))
            out = run(gh, when)
            seen.append((self.stored(), {k: out["graphql"][k] for k in SAME}))
        return seen

    def test_answers_ending_in_any_order_store_what_one_at_a_time_stores(self):
        one = self.replay(lambda gh, when: self.scan_all(gh, when=when, graphql_concurrency=1))
        self.assertTrue(one[0][1]["isolated"] and one[1][1]["isolated"] and one[2][1]["late"], one)
        for name, pick in self.PICKS:
            with self.subTest(pick=name):
                self.setUp()
                ats = []

                def held(gh, when):
                    out, h = self.held_run(gh, pick=pick, when=when)
                    ats.append(out["graphql"]["atOnce"])
                    return out
                self.assertEqual(self.replay(held), one)
                self.assertGreater(max(ats), WIDTH // 2)                  # (calls overlapped)

    def test_the_due_asks_start_in_their_order_whatever_order_they_end_in(self):
        # (a quarter of 8 calls oldest listed first, the rest newest first: started so, ended last first)
        gh = self.due(600)
        self.scan_all(gh, when=at(0.25), max_graphql_calls=8, graphql_concurrency=1)
        one = gh.posts
        self.assertEqual([p[0] for p in one], [node_id(k) for k in (1001, 1101, 1600, 1500, 1400, 1300)])
        self.setUp()
        gh = self.due(600)
        _out, held = self.held_run(gh, pick=last, when=at(0.25), max_graphql_calls=8)
        self.assertEqual(held.starts(), one)
        self.assertNotEqual(held.tickets(), sorted(held.tickets()))        # (they ended in another order)


class LimitTests(ConcurrencyCase):
    def test_the_wall_clock_bounds_the_graphql_part_not_the_sum_of_its_calls(self):
        # (each time the run waits for an answer 10 seconds pass; 90 seconds for the part, --graphql-seconds: a
        # quarter, 22.5, for the oldest first. The sum of the calls' times would have stopped it after its fourth call.
        # GitHub's CPU-time limit's pacing aside here: PacingTests)
        gh = self.due(3000)
        clock = [0.0]
        with mock.patch.object(ghdiscover, "_clock", lambda: clock[0]), \
                mock.patch.object(ghdiscover, "GRAPHQL_CPU_PER_MINUTE", 1e9):
            out, held = self.held_run(gh, when=at(0.25), clock=clock, step=10.0, graphql_seconds=90)
        g = out["graphql"]
        self.assertEqual((g["calls"], g["seconds"], g["stopped"]),
                         (16, 160.0, "the GraphQL part's 90 seconds for a run were spent"))
        starts = held.starts()
        # (oldest first while the share's 22.5 seconds lasted: 10 calls started by 20 s; then newest first to 90 s)
        self.assertEqual([s[0] for s in starts], [node_id(1001 + 100 * k) for k in range(10)]
                         + [node_id(4000 - 100 * k) for k in range(6)])
        # (the six calls in flight at 90 seconds still answered and stored)
        self.assertEqual(sum(1 for r in self.listed().values() if r["state"] == "empty"), 1600)
        self.assertEqual((g["asked"], g["waiting"]), (1600, 1400))

    def test_one_at_a_time_while_github_says_no_points_left(self):
        # (the margin for the calls in flight cannot be kept: answers without rateLimit or X-RateLimit-Remaining)
        class NoPoints(FakeGitHub):
            def _graphql(self, url, headers, data, hosts, reply_headers):
                doc = json.loads(super()._graphql(url, headers, data, hosts, reply_headers))
                del doc["data"]["rateLimit"]
                reply_headers.pop("x-ratelimit-remaining", None)
                return json.dumps(doc).encode()
        gh = self.due(1000, NoPoints)
        out, held = self.held_run(gh, when=at(0.25))
        g = out["graphql"]
        self.assertEqual((g["calls"], g["atOnce"], held.most, g["points"], g["empty"]), (10, 1, 1, None, 1000))

    def test_the_call_budget_counts_the_calls_in_flight(self):
        gh = self.due(2000)
        out, held = self.held_run(gh, when=at(0.25), max_graphql_calls=5)
        g = out["graphql"]
        self.assertEqual((g["calls"], g["atOnce"], held.most, len(held.released)), (5, 4, 4, 5))
        self.assertEqual(g["stopped"], "the run's budget of 5 GraphQL calls (--max-graphql-calls) was spent")
        self.assertEqual((g["empty"], g["waiting"]), (500, 1500))

    def test_the_points_floor_keeps_a_call_for_each_in_flight(self):
        # (106 points: the first answer says 105, and five more may be in flight; GitHub never falls under the floor)
        floor = ghdiscover.GRAPHQL_RATE_FLOOR
        gh = self.due(2000)
        gh.points = floor + 6
        out, held = self.held_run(gh, when=at(0.25))
        g = out["graphql"]
        self.assertEqual((g["calls"], g["atOnce"], gh.points, g["points"]), (6, 5, floor, floor))
        self.assertTrue(g["stopped"].startswith(f"GitHub's GraphQL rate limit is nearly spent ({floor} points left"))
        self.setUp()
        gh2 = self.due(2000)
        gh2.points = floor + 6
        one = self.scan_all(gh2, when=at(0.25), graphql_concurrency=1)["graphql"]
        self.assertEqual((one["calls"], one["empty"]), (6, g["empty"]))


class MidFlightTests(ConcurrencyCase):
    def applied(self):
        """Every row id save_github_listed stored, as many times as it did."""
        ids, save = collections.Counter(), self.store.save_github_listed

        def counting(updates=(), deletes=()):
            ids.update(u[0] for u in updates)
            ids.update(deletes)
            return save(updates, deletes)
        return ids, mock.patch.object(self.store, "save_github_listed", counting)

    def test_a_secondary_limit_mid_flight_stops_new_calls_and_stores_the_answers_in_flight_once(self):
        limited = failure("asking: rate limit reached, wait for 60 seconds", 429)
        limited.limits = {"retry-after": "60"}
        for answer in (limited, ({"data": None, "errors": [{"message": "You have exceeded a secondary rate limit."}]},
                                 {})):
            with self.subTest(answer=str(answer)[:40]):
                self.setUp()
                gh = self.due(2000, Failing, at=[1201], answer=answer)
                ids, patch = self.applied()
                with patch:
                    out, held = self.held_run(gh, when=at(0.25))
                g = out["graphql"]
                if isinstance(answer, tuple):
                    self.assertIn("secondary rate limit", out["stopped"])
                    self.assertEqual(g["stopped"], out["stopped"])
                else:
                    self.assertIn("refused a call", out["stopped"])
                    self.assertIn("refused the call", g["stopped"])
                # (call 3 met it while 4 to 10 were in flight: those answered and stored, none started after, and
                # the listing not read)
                self.assertEqual((g["calls"], held.tickets(), out["pages"]), (10, list(range(1, 11)), 0))
                listed = self.listed()
                self.assertEqual({(listed[k]["state"], listed[k]["checks"]) for k in range(1001, 2001)
                                  if not 1201 <= k <= 1300}, {("empty", 1)})
                self.assertEqual({(listed[k]["state"], listed[k]["checks"]) for k in range(1201, 1301)},
                                 {("unasked", 0)})
                self.assertEqual({listed[k]["state"] for k in range(2001, 3001)}, {"unasked"})   # (never asked)
                self.assertEqual(set(ids.values()), {1})                 # (nothing stored twice)
                self.assertEqual(set(ids), set(range(1001, 2001)))

    def test_a_secondary_limit_met_while_the_listing_reads_stops_it_before_its_next_page(self):
        # (page 2's call meets one while page 3, all of it excluded, so asked about in no call, is read: the listing
        # reads the calls that ended before each page, and stops there rather than read pages 4 to 6)
        class Late(FakeGitHub):
            go = threading.Event()

            def __call__(self, url, *a, method="GET", **kw):
                answer = super().__call__(url, *a, method=method, **kw)
                if method == "GET" and url.endswith("since=1200"):
                    self.go.set()                                  # (page 3: page 2's call ends while it is read)
                    for thread in threading.enumerate():
                        if thread.name == "lazaret-graphql-2":
                            thread.join(WAIT)
                return answer

            def _graphql(self, url, headers, data, hosts, reply_headers):
                if node_id(1101) in json.loads(data)["variables"]["ids"]:
                    if not self.go.wait(WAIT):
                        raise AssertionError("page 3 was never read")
                    limited = failure("asking: rate limit reached, wait for 60 seconds", 429)
                    limited.limits = {"retry-after": "60"}
                    raise limited
                return super()._graphql(url, headers, data, hosts, reply_headers)
        gh = Late(repos(1001, 200) + [item(1201 + k, f"skip{k}/p") for k in range(400)])
        patterns = {"exclude": {"full_name": [re.compile("^skip")]}, "include": {}}
        out = self.scan_all(gh, graphql_concurrency=WIDTH, filters=ghdiscover.Filters(patterns=patterns))
        self.assertEqual((out["pages"], out["cursor"], out["caughtUp"]), (3, 1300, False))
        self.assertIn("refused a call", out["stopped"])
        self.assertEqual((out["graphql"]["calls"], out["graphql"]["atOnce"]), (2, 1))
        self.assertEqual({self.listed()[k]["state"] for k in range(1101, 1201)}, {"unasked"})
        self.assertEqual(call_threads(), [])

    def test_a_failure_mid_flight_starts_no_call_until_those_in_flight_end(self):
        gh = self.due(2000, Failing, at=[1201], answer=failure(f"x: HTTP 500 from {API}/graphql", 500))
        out, held = self.held_run(gh, when=at(0.25))
        g = out["graphql"]
        started = {r.ticket: r.started for r in held.released}
        alone = {r.ticket: r.flying for r in held.released}
        # (call 3 failed: 4 to 10, in flight then, ended before any other started; then 11 alone; then eight again)
        self.assertEqual([started[t] for t in range(4, 11)], [10] * 7)
        self.assertEqual((started[11], alone[11], started[12]), (11, 1, 19))
        self.assertEqual((g["calls"], g["failed"], g["stopped"], g["atOnce"]), (20, 1, None, WIDTH))
        listed = self.listed()
        self.assertEqual({listed[k]["state"] for k in range(1201, 1301)}, {"unasked"})
        self.assertIn("HTTP 500", listed[1201]["last_error"])
        self.assertEqual(sum(1 for r in listed.values() if r["state"] == "empty"), 1900)

    def test_failures_in_flight_together_count_as_one(self):
        # (the first call answered, then GitHub failing every call: the eight in flight then one failure, and two
        # more, each of a call started after the one before failed, stop it: three, as one at a time)
        gh = self.due(2000, Failing, fine=1, answer=failure(f"x: HTTP 500 from {API}/graphql", 500))
        out, held = self.held_run(gh, when=at(0.25))
        g = out["graphql"]
        self.assertEqual((g["calls"], g["failed"]), (11, 10))
        self.assertTrue(g["stopped"].startswith("10 GraphQL calls failed (the last: x: HTTP 500"), g["stopped"])
        self.assertEqual([r.flying for r in held.released][-2:], [1, 1])    # (the last two alone)
        self.assertEqual(sum(1 for r in self.listed().values() if r["state"] == "empty"), 100)
        self.setUp()
        gh = self.due(2000, Failing, fine=1, answer=failure(f"x: HTTP 500 from {API}/graphql", 500))
        one = self.scan_all(gh, when=at(0.25), graphql_concurrency=1)["graphql"]
        self.assertEqual((one["calls"], one["failed"], one["stopped"][:24]), (4, 3, "3 GraphQL calls failed ("))

    def test_an_error_of_the_store_mid_flight_leaves_no_thread_and_loses_nothing(self):
        gh = self.due(800)
        gh.code |= set(range(1001, 1801, 50))
        real, made = self.store.add_github_candidates, []

        def failing(rows):
            made.append(len(rows))
            if len(made) == 2:
                raise sqlite3.OperationalError("disk I/O error")
            return real(rows)
        with mock.patch.object(self.store, "add_github_candidates", failing), \
                self.assertRaises(sqlite3.OperationalError):
            self.held_run(gh, when=at(0.25))
        self.assertEqual(call_threads(), [])
        listed = self.listed()
        self.assertEqual(sorted(self.queued()), list(range(1001, 1101, 50)))       # (the first call's, stored)
        self.assertEqual({listed[k]["state"] for k in listed if k > 1100}, {"unasked"})   # (the rest as they were)
        self.scan_all(gh, when=at(0.5), graphql_concurrency=1)
        self.assertEqual(sorted(self.queued()), list(range(1001, 1801, 50)))

    def test_a_fault_of_the_seam_on_a_calls_thread_is_raised_on_the_runs(self):
        gh = self.due(800, Failing, at=[1301], answer=RuntimeError("the seam broke"))
        with self.assertRaises(RuntimeError):
            self.held_run(gh, when=at(0.25))
        self.assertEqual(call_threads(), [])


class IsolationTests(ConcurrencyCase):
    def test_a_poison_batch_in_flight_with_others_is_isolated_one_call_at_a_time(self):
        # (it is answered first, seven calls in flight then, the rest last started first: those seven end before its
        # halves are asked)
        gh = self.due(1200, PoisonGitHub, poison=[1377])
        out, held = self.held_run(gh, pick=lambda held: next((h for h in held if node_id(1377) in h[1]), held[-1]),
                                  when=at(0.25))
        self.assertEqual([r.flying for r in held.released[:2]], [1, WIDTH])
        g = out["graphql"]
        halves = [r for r in sorted(held.released) if len(r.ids) < 100]
        self.assertEqual([len(r.ids) for r in halves], [50, 50, 25, 25, 13, 12, 7, 6, 4, 3, 2, 2, 1, 1])
        self.assertEqual({r.flying for r in halves}, {1})                  # (alone: nothing else in flight)
        self.assertEqual((g["isolated"], g["unanswered"], g["unreadable"], g["empty"], g["stopped"]),
                         (1, 1, 8, 1199, None))
        self.assertEqual(self.listed()[1377]["fails"], 1)

    def test_a_control_call_is_made_alone_about_one_github_answered_about(self):
        poison = [1301, 1326, 1351, 1376]
        gh = self.due(1200, PoisonGitHub, poison=poison)
        out, held = self.held_run(gh, pick=last, when=at(0.25))
        g = out["graphql"]
        controls = [(r.ids, r.flying) for r in sorted(held.released)
                    if len(r.ids) == 1 and not 1301 <= int(r.ids[0][6:]) <= 1400]
        self.assertEqual(len(controls), 1, controls)
        (ids, alone), = controls
        self.assertEqual(alone, 1)
        self.assertEqual(self.listed()[int(ids[0][6:])]["state"], "empty")    # (one GitHub answered about this run)
        self.assertEqual((g["isolated"], g["empty"], g["stopped"]), (4, 1196, None))
        self.assertEqual({self.listed()[p]["fails"] for p in poison}, {1})


class Slow(FakeGitHub):
    """FakeGitHub whose GraphQL calls each take `seconds` on `clock` (a list), one at a time."""

    def __init__(self, *a, clock, seconds, **kw):
        super().__init__(*a, **kw)
        self.clock, self.seconds, self.ends = clock, seconds, []

    def _graphql(self, url, headers, data, hosts, reply_headers):
        self.clock[0] += self.seconds
        self.ends.append((self.clock[0], self.seconds))
        return super()._graphql(url, headers, data, hosts, reply_headers)


class PacingTests(ConcurrencyCase):
    """GitHub's secondary limit on compute (its documentation, read Oct 21: "No more than 60 seconds of this CPU time
    may be for the GraphQL API", per 60 seconds of real time, estimated "by measuring the total response time for your
    API requests"): with several calls at once the run keeps its calls' response seconds in any minute of its clock to
    GRAPHQL_CPU_PER_MINUTE, waiting on a fake clock here (ghdiscover's _clock and _sleep); one at a time, whose calls
    cannot overlap, is not paced (the review of Oct 21)."""

    def setUp(self):
        super().setUp()
        self.clock = [0.0]
        for patcher in (mock.patch.object(ghdiscover, "_clock", lambda: self.clock[0]),
                        mock.patch.object(ghdiscover, "_sleep",
                                          lambda s: self.clock.__setitem__(0, self.clock[0] + s))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_paced(self, ends, most=ghdiscover.GRAPHQL_CPU_PER_MINUTE):
        """No minute of the clock holds more than `most` seconds of calls ending in it."""
        for t, _s in ends:
            used = sum(s for end, s in ends if t - ghdiscover.GRAPHQL_CPU_WINDOW < end <= t)
            self.assertLessEqual(used, most + 1e-9, (t, used))

    def test_eight_at_once_of_calls_of_3_5_seconds_keep_under_50_seconds_a_minute(self):
        gh = self.due(6000)
        out, held = self.held_run(gh, when=at(0.25), clock=self.clock, seconds=3.5, graphql_seconds=3600)
        g = out["graphql"]
        self.assert_paced(held.ends)
        self.assertEqual((g["calls"], g["empty"], g["stopped"], g["atOnce"]), (60, 6000, None, WIDTH))
        self.assertGreater(g["paced"], 0)
        # (some 14 calls a minute whatever the concurrency: 60 calls in over four minutes)
        self.assertGreater(g["seconds"], 4 * 60)
        self.assertEqual(max(sum(1 for e, _s in held.ends if t - 60 < e <= t) for t, _s in held.ends), 14)

    def test_a_slow_call_in_flight_counts_its_time_so_far(self):
        # (calls of 1 s, one of 9 s, under the 10 GitHub ends a call at: the estimate of a call in flight is its time so
        # far once that passes the median, so fewer calls start while it runs. A call is counted at the median when it
        # starts, so the minute it ends in can hold more than 50 s: 53 here, under GitHub's 60; 58 counted at the
        # median alone)
        gh = self.due(6000)
        slow = node_id(1101)
        out, held = self.held_run(gh, when=at(0.25), clock=self.clock, graphql_seconds=3600,
                                  seconds=lambda ids: 9.0 if slow in ids else 1.0)
        worst = max(sum(s for e, s in held.ends if t - 60 < e <= t) for t, _s in held.ends)
        self.assertEqual((out["graphql"]["calls"], worst), (60, 53.0))

    def test_fast_calls_have_eight_in_flight_unpaced(self):
        gh = self.due(6000)
        out, held = self.held_run(gh, when=at(0.25), clock=self.clock, seconds=0.1)
        g = out["graphql"]
        self.assertEqual((g["calls"], g["atOnce"], g["paced"], g["pacedSeconds"]), (60, WIDTH, 0, 0.0))
        self.assertLess(g["seconds"], 2)

    def test_one_at_a_time_is_not_paced(self):
        # (calls of 3.5 s back to back, as before the pacing: any minute of the clock holds 60 s of calls at most,
        # which one at a time cannot pass; the 120 seconds end at the call that starts at 119 s: 35 calls; the due
        # share a quarter of the 120: 30 s, 9 calls oldest first, then newest first)
        gh = Slow(repos(1001, 6000), clock=self.clock, seconds=3.5)
        self.scan_all(gh, max_graphql_calls=0)
        gh.posts.clear()
        g = self.scan_all(gh, when=at(0.25), graphql_seconds=120)["graphql"]
        worst = max(sum(max(0.0, min(e, t) - max(e - s, t - 60)) for e, s in gh.ends) for t, _s in gh.ends)
        self.assertEqual((g["calls"], g["seconds"], g["paced"], g["pacedSeconds"], g["concurrency"], worst),
                         (35, 122.5, 0, 0.0, 1, 60.0))
        self.assertEqual(g["stopped"], "the GraphQL part's 120 seconds for a run were spent")
        self.assertEqual([p[0] for p in gh.posts[8:10]], [node_id(1801), node_id(7000)])

    def paced_in_turn(self, gh, **kw):
        """Eight at once, each call answered before the run goes on (test_ghdiscover_at_eight's), at the fake clock."""
        with mock.patch.object(ghdiscover, "_spawn", answered_in_turn):
            return self.scan_all(gh, when=at(0.25), graphql_concurrency=WIDTH, **kw)["graphql"]

    def test_the_waits_count_toward_the_graphql_seconds(self):
        # (eight allowed at once, each call of 3.5 s answered before the next starts: 14 by 49 s, 49 s of calls, and
        # a 15th would pass 50: a wait until the first leaves the minute, at 63.5 s; then a call as each leaves, 14
        # more by 112.5 s; then a wait until 127 s, which the 120 seconds end at 120: 28 calls, 14 a minute, 22
        # seconds waiting in two waits; the due share a quarter of the 120, as at one)
        gh = Slow(repos(1001, 6000), clock=self.clock, seconds=3.5)
        self.scan_all(gh, max_graphql_calls=0)
        gh.posts.clear()
        g = self.paced_in_turn(gh, graphql_seconds=120)
        self.assert_paced(gh.ends)
        self.assertEqual((g["calls"], g["seconds"], g["paced"], g["pacedSeconds"], g["concurrency"]),
                         (28, 120.0, 2, 22.0, WIDTH))
        self.assertEqual(g["stopped"], "the GraphQL part's 120 seconds for a run were spent")
        self.assertEqual([p[0] for p in gh.posts[8:10]], [node_id(1801), node_id(7000)])

    def test_the_run_says_how_long_its_calls_waited(self):
        gh = Slow(repos(1001, 6000), clock=self.clock, seconds=3.5)
        self.scan_all(gh, max_graphql_calls=0)
        code, out, err = CommandLineTests.cli(self, "discover", "--ecosystem", "github", "--resume",
                                              "--github-scan-all", "--max-scans", "0", "--graphql-seconds", "120",
                                              "--graphql-concurrency", "8", gh=gh)
        self.assertEqual(code, 0, err)
        self.assertIn("  GraphQL: 28 call(s) in 120.0 s of the 120 allowed (wall clock, while calls were in flight or "
                      "waited), 1 at once at most of the 8 allowed (--graphql-concurrency)", out)
        self.assertIn("  GraphQL: waited 22.0 s in all, 2 time(s), for GitHub's CPU-time limit (50 s of calls a minute "
                      "at most)", out)


class TimeLimitTests(ConcurrencyCase):
    """John's input of Oct 20: GitHub answered 502 twice in ten calls of some 8 s (its GraphQL API ends a call over
    10 seconds with a 502 or 504). Such a batch is asked again in halves, not counted as a failure of the call unless
    they fail too."""

    def both(self, make, check):
        for width in (1, WIDTH):
            with self.subTest(concurrency=width):
                self.setUp()
                gh = make()
                if width == 1:
                    out = self.scan_all(gh, graphql_concurrency=1)
                else:
                    out, _held = self.held_run(gh)
                check(gh, out["graphql"], out)

    def test_a_call_github_ends_at_its_time_limit_is_asked_again_in_halves(self):
        def check(gh, g, out):
            self.assertEqual(sorted(len(p) for p in gh.posts), [50] * 6 + [100] * 3)
            self.assertEqual((g["timeouts"], g["failed"], g["unreadable"], g["stopped"]), (3, 0, 0, None))
            self.assertEqual((g["asked"], g["code"], g["empty"], g["unanswered"]), (300, 30, 270, 0))
            self.assertEqual({(r["state"], r["fails"], r["last_error"]) for r in self.listed().values()},
                             {("empty", 0, None)})
        for status in (502, 504):
            self.both(lambda status=status: Timing(repos(1001, 300), code=range(1001, 1301, 10), status=status),
                      check)

    def test_github_ending_every_call_still_stops_the_graphql_part(self):
        def check(gh, g, out):
            self.assertEqual([len(p) for p in gh.posts], [100, 50] * 3)    # (each half of 50 ended too: a failure)
            self.assertEqual((g["timeouts"], g["failed"]), (3, 3))
            self.assertTrue(g["stopped"].startswith("3 GraphQL calls failed (the last: asking: HTTP 502"), g["stopped"])
            self.assertEqual((out["caughtUp"], out["stopped"], g["waiting"]), (True, None, 500))
            self.assertEqual({(r["state"], r["checks"], r["fails"]) for r in self.listed().values()},
                             {("unasked", 0, 0)})                          # (none dropped, none backed off)
            self.assertTrue(all("HTTP 502" in r["last_error"] for r in self.listed().values() if r["repo_id"] < 1301))
        self.both(lambda: Timing(repos(1001, 500), most=0), check)

    def test_a_half_github_ends_too_is_the_failure_of_the_call_it_was(self):
        def check(gh, g, out):
            self.assertEqual([len(p) for p in gh.posts], [100, 50, 100, 50, 100, 50])
            self.assertEqual((g["timeouts"], g["failed"], g["isolated"]), (3, 3, 0))
        self.both(lambda: Timing(repos(1001, 300), most=40), check)

    def test_a_half_that_fails_makes_no_control_call(self):
        # (it is the failure of the call the batch's was: not a batch nothing of which could be read)
        for width in (1, WIDTH):
            with self.subTest(concurrency=width):
                self.setUp()
                gh = Timing(repos(1001, 30), most=40)
                self.scan_all(gh, graphql_concurrency=width)                # (30 answered: one to name)
                gh.repos += repos(1031, 100)
                gh.posts.clear()
                g = self.scan_all(gh, when=at(0.25), graphql_concurrency=width)["graphql"]
                self.assertEqual([len(p) for p in gh.posts], [100, 50])
                self.assertEqual((g["timeouts"], g["failed"], g["unreadable"], g["stopped"]), (1, 1, 0, None))

    def test_a_single_row_or_no_halves_is_a_failure_as_before(self):
        gh = Timing(repos(1001, 1), most=0, status=504)
        g = self.scan_all(gh, graphql_concurrency=WIDTH)["graphql"]
        self.assertEqual((len(gh.posts), g["timeouts"], g["failed"]), (1, 0, 1))
        self.setUp()
        gh = Timing(repos(1001, 3), most=0)
        with mock.patch.object(ghdiscover, "GRAPHQL_SPLIT_DEPTH", 0):
            g = self.scan_all(gh, graphql_concurrency=1)["graphql"]
        self.assertEqual((len(gh.posts), g["timeouts"], g["failed"]), (1, 0, 1))

    def test_timed_out_batches_in_flight_together_are_each_asked_in_halves(self):
        gh = self.due(1600, Timing, most=60, status=504)
        out, held = self.held_run(gh, when=at(0.25))
        g = out["graphql"]
        self.assertEqual((g["timeouts"], g["failed"], g["empty"], g["calls"]), (16, 0, 1600, 48))
        self.assertEqual({r.flying for r in held.released if len(r.ids) == 50}, {1})     # (one at a time)


class OneThreadTests(ConcurrencyCase):
    """Every database read and write on the run's thread alone, the HTTP on the calls' own (SQLite's connection
    would refuse another thread too; Postgres's would not)."""

    class Watched:
        def __init__(self, store):
            self._store, self.threads = store, set()

        def __getattr__(self, name):
            attr = getattr(self._store, name)
            if not callable(attr):
                return attr

            def call(*a, **kw):
                self.threads.add(threading.get_ident())
                return attr(*a, **kw)
            return call

    def test_the_database_is_written_from_the_runs_thread_alone(self):
        class Conn(ListedConn):
            def __init__(self, **kw):
                super().__init__(**kw)
                self.threads = set()

            def fetch(self, sql, *args):
                self.threads.add(threading.get_ident())
                return super().fetch(sql, *args)

            def execute(self, sql, *args):
                self.threads.add(threading.get_ident())
                return super().execute(sql, *args)
        conn = Conn()
        for name, store in (("sqlite", self.store), ("postgres", pg_store(conn))):
            with self.subTest(store=name):
                if name == "postgres":
                    store.save_discovery_cursor("github", 1000, NOW)
                    store.save_discovery_cursor("github-scan-all", 1000)
                watched = self.Watched(store)
                gh = PoisonGitHub(repos(1001, 1200), poison=[1550], code=range(1001, 2201, 11))
                out, held = self.held_run(gh, store=watched, pick=last)
                self.assertEqual(watched.threads, {threading.get_ident()})
                self.assertTrue(held.threads and all(t.startswith("lazaret-graphql-") for t in held.threads))
                self.assertEqual((out["graphql"]["atOnce"], out["graphql"]["isolated"]), (WIDTH, 1))
        self.assertEqual(conn.threads, {threading.get_ident()})


class TransportTests(unittest.TestCase):
    """The POST (sources._post, what Client.post sends GraphQL's calls through) from WIDTH threads at once, on each
    transport, against a local HTTPS server (test_nativenet's root and certificate, tests/_pki.py's) that answers no
    call until all WIDTH are in it: all in flight together, each on a connection of its own, each answered its own
    body. Python's server speaks HTTP/1.1; the native client's HTTP/2 streams from many threads are pratique's own
    tests'."""

    @classmethod
    def setUpClass(cls):
        from tests.scanner.test_nativenet import NO_PROXY_ENV, make_pki
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root, cert, key = make_pki(cls.tmp.name)
        trusted = os.path.join(cls.tmp.name, "trusted.pem")         # (urllib's roots: the test's alone)
        with open(trusted, "w", encoding="ascii") as f:
            f.write(cls.root)
        seen, together = [], threading.Barrier(WIDTH, timeout=WAIT)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                seen.append(self.client_address[1])
                try:
                    together.wait()                       # (no answer until every call is in)
                    status = 200
                except threading.BrokenBarrierError:
                    status = 503
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass
        cls.seen, cls.together = seen, together
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.daemon_threads = True
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.host = f"localhost:{cls.server.server_address[1]}"
        cls.env = mock.patch.dict(os.environ, {**NO_PROXY_ENV, "SSL_CERT_FILE": trusted}, clear=True)
        cls.env.start()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def posts(self):
        self.seen.clear()
        self.together.reset()
        got = {}

        def post(k):
            body = json.dumps({"query": "q", "variables": {"ids": [f"R_{k}"]}}).encode()
            try:
                got[k] = (sources._post(f"https://{self.host}/graphql", {"User-Agent": "t", "Authorization": "Bearer x",
                                                                          "Content-Type": "application/json"},
                                        body, sources.POST_BYTES, {self.host}, "localhost", what="w", has_token=True,
                                        seconds=WAIT), body)
            except Exception as exc:                                    # noqa: BLE001
                got[k] = (exc, body)
        threads = [threading.Thread(target=post, args=(k,)) for k in range(WIDTH)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(2 * WAIT)
        self.assertEqual({k: answer == body for k, (answer, body) in got.items()}, {k: True for k in range(WIDTH)}, got)
        self.assertEqual(len(set(self.seen)), WIDTH)                    # (a connection each)

    def test_the_native_transport(self):
        from lazaret.scanner import nativenet
        if not nativenet.available():
            self.skipTest(f"no native transport here ({nativenet.why_not()})")
        nativenet.configure_roots(self.root)
        self.addCleanup(nativenet.configure_roots, None)
        with mock.patch.object(sources._net, "chosen", lambda url: True), \
                mock.patch.object(sources, "_post_urllib", side_effect=AssertionError("urllib's, not the native")):
            self.posts()

    def test_urllibs(self):
        with mock.patch.object(sources._net, "chosen", lambda url: False):
            self.posts()


class CommandLineTests(ConcurrencyCase):
    def cli(self, *argv, gh=None):
        gh = gh or FakeGitHub()
        archive = FakeArchive()

        def both(url, *a, **kw):
            return (archive if "gharchive" in url else gh)(url, *a, **kw)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "argv", ["lazaret-registry", *argv, "--db", self.db]), \
                mock.patch.dict(os.environ, ENV), mock.patch.object(sources, "_http", both), \
                mock.patch.object(ghdiscover, "_spawn", answered_in_turn), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_a_run_says_its_calls_wall_clock_and_how_many_were_at_once(self):
        gh = Timing(repos(1001, 250), most=60)
        code, out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all",
                                  "--max-scans", "0", "--graphql-concurrency", "3", gh=gh)
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"  GraphQL: 7 call\(s\) in \d[\d,]*\.\d s of the 900 allowed \(wall clock, while "
                              r"calls were in flight or waited\), 1 at once at most of the 3 allowed "
                              r"\(--graphql-concurrency\)")
        self.assertIn("  GraphQL: 2 call(s) GitHub ended at its own time limit for a call (HTTP 502 or 504), their "
                      "repositories asked again in halves", out)

    def test_the_options_bounds_and_that_they_go_with_scan_all(self):
        for option, value, text in (("--graphql-concurrency", "0", "a number of calls at once, 1 to 8"),
                                    ("--graphql-concurrency", "9", "a number of calls at once, 1 to 8"),
                                    ("--graphql-seconds", "0", "a number of seconds, 1 to 3600"),
                                    ("--graphql-seconds", "3601", "a number of seconds, 1 to 3600")):
            with self.subTest(option=option, value=value):
                code, _out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all",
                                           option, value)
                self.assertIn(f"{option} takes {text}", str(code) + err)
        for option in ("--graphql-concurrency", "--graphql-seconds"):
            with self.subTest(option=option):
                code, _out, err = self.cli("discover", "--ecosystem", "github", "--resume", option, "3")
                self.assertEqual(code, 2)
                self.assertIn(f"{option} goes with --github-scan-all", err)
                code, _out, err = self.cli("discover", option, "3")
                self.assertEqual(code, 2)
                self.assertIn(f"{option}: these go with discover --ecosystem github --resume", err)
        code, out, _err = self.cli("--help")
        self.assertIn("--graphql-seconds 1800", out)
        self.assertIn("(default 1, at most 8)", " ".join(out.split()))

    def test_the_seconds_are_passed_and_said(self):
        gh = FakeGitHub(repos(1001, 100))
        code, out, err = self.cli("discover", "--ecosystem", "github", "--resume", "--github-scan-all",
                                  "--max-scans", "0", "--graphql-seconds", "1800", gh=gh)
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"  GraphQL: 1 call\(s\) in \d[\d,]*\.\d s of the 1,800 allowed")


if __name__ == "__main__":
    unittest.main()
