"""npm's replication feed read forward from a sequence number, for
`discover --resume`.

discover_npm reads the newest 3 x --limit rows of npm's replication feed
(descending), so a daily run sees minutes of npm. The feed also pages
forward: since=<seq>&limit=<n> (at most 10,000) returns the changes after
seq. _npm_changes_since() reads it that way from a stored position until a
page comes back short (caught up) or its page budget is spent, and says
where it stopped so the next run continues there.

The feed is a fake with harmless names; nothing touches the network.
"""

import unittest
import urllib.parse
from unittest import mock

from lazaret.registry import repo


def rows(first, last, **extra):
    return [{"seq": s, "id": f"pkg-{s}", "changes": [{"rev": "1-a"}], **extra}
            for s in range(first, last + 1)]


class FakeFeed:
    """http_json stand-in for the replication feed: answers since=/limit= as
    npm does (the rows after `since`, at most `limit`, in seq order). `pages`
    maps a request number (1-based) to an exception to raise or an answer to
    return instead."""

    def __init__(self, feed_rows, pages=None):
        self.rows, self.pages, self.urls = feed_rows, pages or {}, []

    def __call__(self, url, accept=None):
        self.urls.append(url)
        parts = urllib.parse.urlsplit(url)
        assert f"{parts.scheme}://{parts.netloc}{parts.path}" == repo.NPM_CHANGES_URL, url
        query = urllib.parse.parse_qs(parts.query)
        assert set(query) == {"since", "limit"}, url
        replaced = self.pages.get(len(self.urls))
        if isinstance(replaced, Exception):
            raise replaced
        if replaced is not None:
            return replaced
        since, limit = int(query["since"][0]), int(query["limit"][0])
        page = [r for r in self.rows if isinstance(r.get("seq"), int) and r["seq"] > since][:limit]
        return {"results": page, "last_seq": page[-1]["seq"] if page else since}


def changes_since(feed, seq=100, pages=None, page_size=10):
    with mock.patch.object(repo, "http_json", side_effect=feed), \
            mock.patch.object(repo, "NPM_CHANGES_MAX", page_size):
        return repo._npm_changes_since(seq, pages)


def since_params(feed):
    return [urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)["since"][0] for u in feed.urls]


class PagingTests(unittest.TestCase):
    def test_the_request(self):
        feed = FakeFeed(rows(124, 125))
        with mock.patch.object(repo, "http_json", side_effect=feed):
            got = repo._npm_changes_since(123)
        self.assertEqual(feed.urls, ["https://replicate.npmjs.com/registry/_changes?since=123&limit=10000"])
        self.assertEqual(got["changes"], [(124, "pkg-124"), (125, "pkg-125")])
        self.assertTrue(got["caught_up"])

    def test_pages_until_caught_up(self):
        feed = FakeFeed(rows(101, 125))
        got = changes_since(feed)
        self.assertEqual(since_params(feed), ["100", "110", "120"])
        self.assertEqual([s for s, _ in got["changes"]], list(range(101, 126)))
        self.assertEqual((got["last"], got["caught_up"], got["pages"], got["rows"], got["error"]),
                         (125, True, 3, 25, None))

    def test_a_full_last_page_is_followed_by_an_empty_one(self):
        feed = FakeFeed(rows(101, 120))
        got = changes_since(feed)
        self.assertEqual(since_params(feed), ["100", "110", "120"])
        self.assertEqual((got["last"], got["caught_up"], got["pages"]), (120, True, 3))

    def test_nothing_new(self):
        got = changes_since(FakeFeed(rows(90, 100)))
        self.assertEqual((got["changes"], got["last"], got["caught_up"]), ([], None, True))

    def test_the_page_budget(self):
        feed = FakeFeed(rows(101, 145))
        got = changes_since(feed, pages=2)
        self.assertEqual(since_params(feed), ["100", "110"])
        self.assertEqual((got["last"], got["caught_up"], got["pages"]), (120, False, 2))
        self.assertEqual(len(got["changes"]), 20)
        more = changes_since(feed, seq=got["last"], pages=2)              # the next run
        self.assertEqual((more["changes"][0], more["last"]), ((121, "pkg-121"), 140))

    def test_each_package_once_at_its_newest_seq(self):
        feed = FakeFeed([{"seq": 101, "id": "a"}, {"seq": 102, "id": "b"}, {"seq": 103, "id": "a"},
                         {"seq": 111, "id": "b"}, {"seq": 112, "id": "c"}])
        got = changes_since(feed, page_size=3)
        self.assertEqual(got["changes"], [(103, "a"), (111, "b"), (112, "c")])

    def test_rows_that_are_not_packages(self):
        feed = FakeFeed([], pages={1: {"results": [
            None, "x", [101], {"seq": True, "id": "flag"}, {"seq": "102", "id": "text"},
            {"seq": -1, "id": "neg"}, {"id": "noseq"}, {"seq": 99, "id": "before"},
            {"seq": 103, "id": "gone", "deleted": True}, {"seq": 104, "id": "_design/app"},
            {"seq": 105, "id": "../x"}, {"seq": 106, "id": "a" * 215}, {"seq": 107, "id": 5},
            {"seq": 108, "id": ""}, {"seq": 109, "id": "@s/ok"},
            {"seq": 110, "id": "gone-later", "deleted": True}]}})
        got = changes_since(feed, page_size=100)
        self.assertEqual(got["changes"], [(109, "@s/ok")])
        self.assertEqual(got["last"], 110)             # passed over, but read
        self.assertEqual(got["rejected"], 2)
        self.assertTrue(got["caught_up"])


class FailureTests(unittest.TestCase):
    def test_the_first_page_failing_raises(self):
        for label, answer in (("network", repo.FetchError("URL error fetching …: timed out")),
                              ("shape", {"results": {}}), ("not an object", ["results"])):
            with self.subTest(label), self.assertRaises((repo.FetchError, repo.FeedError)):
                changes_since(FakeFeed(rows(101, 125), pages={1: answer}))

    def test_a_later_page_failing_keeps_what_was_read(self):
        rejected = repo.FetchError("HTTP 429 fetching …")
        rejected.status = 429
        got = changes_since(FakeFeed(rows(101, 135), pages={3: rejected}))
        self.assertIs(got["error"], rejected)
        self.assertEqual((got["last"], got["caught_up"], got["pages"]), (120, False, 2))
        self.assertEqual(len(got["changes"]), 20)

    def test_a_full_page_with_nothing_new(self):
        stuck = {"results": rows(90, 99)}                  # a full page, all at or before `since`
        with self.assertRaisesRegex(repo.FeedError, "nothing after sequence number 100"):
            changes_since(FakeFeed([], pages={1: stuck}))
        got = changes_since(FakeFeed(rows(101, 125), pages={2: {"results": rows(1, 10)}}))
        self.assertIsInstance(got["error"], repo.FeedError)
        self.assertEqual((got["last"], got["pages"], got["caught_up"]), (110, 2, False))

    def test_pages_go_through_the_json_limits(self):
        # http_json: the 5 MB feed cap and the deep-nesting guard
        with mock.patch.object(repo, "_fetch", return_value=b"[" * 100_000) as fetch:
            with self.assertRaisesRegex(repo.FetchError, "too deeply nested"):
                repo._npm_changes_since(100)
        self.assertEqual(fetch.call_args.kwargs["max_bytes"], repo.MAX_FEED_BYTES)
        self.assertEqual(fetch.call_args.kwargs["timeout"], repo.METADATA_TIMEOUT)


if __name__ == "__main__":
    unittest.main()
