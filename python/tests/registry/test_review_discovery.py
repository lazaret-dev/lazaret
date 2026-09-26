"""Review findings 11, 15 and 16: package names and discovery feeds.

11. resolve_npm re-checked the whole name against NAME_RE, so every scoped
    package (npm:@babel/core) was a SpecError although parse_spec accepted it.
15. (MCP discover_packages: see tests/mcp/test_review_tools.py) npm feed names were not validated (a legal
    120-character name stopped `discover --scan --ci` and then crashed every
    scan-all); unexpected JSON shapes in _changes raised AttributeError and
    discarded the fetched results.
16. discover_pypi fetched RSS with the 200 MB artifact budget; FEED_MAX_BYTES
    (16 MiB) exceeded MAX_FEED_BYTES (5 MB); ParseError escaped _parse_xml.
"""

import contextlib
import datetime
import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.parse
from unittest import mock

from lazaret.mcp import server as mcp_server
from lazaret.registry import repo
from tests.registry._review_support import tarball

NOW = datetime.datetime.now(datetime.timezone.utc)
GOOD_TGZ = tarball({"package.json": json.dumps({"name": "g"}), "index.js": "module.exports = 1;\n"})


class ScopedNameTests(unittest.TestCase):
    def test_parse_and_resolve_scoped(self):
        self.assertEqual(repo.parse_spec("npm:@babel/core@7.0.0"), ("npm", "@babel/core", "7.0.0"))
        self.assertEqual(repo.parse_spec("npm:@types/node"), ("npm", "@types/node", None))
        meta = {"name": "@babel/core", "version": "7.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz"}}
        with mock.patch.object(repo, "http_json", return_value=meta) as http_json:
            version, url, container, artifact, _ = repo.resolve_npm("@babel/core", "7.0.0")
        http_json.assert_called_once_with("https://registry.npmjs.org/@babel%2Fcore/7.0.0")
        self.assertEqual((version, container, artifact), ("7.0.0", "tgz", "npm"))

    def test_invalid_names(self):
        for spec in ("npm:@scope", "npm:@/x", "npm:@a/b/c", "npm:.hidden", "npm:_under",
                     "npm:a/b", "npm:" + "a" * 215, "pypi:@x/y", "pypi:-x", "npm:../x",
                     "npm:node_modules", "npm:x\ny"):
            with self.subTest(spec=spec):
                with self.assertRaises(repo.SpecError):
                    repo.parse_spec(spec)
        self.assertEqual(repo.parse_spec("npm:" + "a" * 120)[1], "a" * 120)
        self.assertEqual(repo.parse_spec("pypi:zope.interface==5.0")[1:], ("zope.interface", "5.0"))

    def test_mcp_scan_package_scoped(self):
        meta = {"name": "@scope/pkg", "version": "1.0.0",
                "dist": {"tarball": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz"}}
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(mcp_server, "REGISTRY_DB", os.path.join(d, "r.db")), \
                mock.patch.object(repo, "http_json", return_value=meta), \
                mock.patch.object(repo, "http_bytes", return_value=GOOD_TGZ), \
                mock.patch.object(repo, "verify_digest", return_value=None):
            out = mcp_server.tool_scan_package({"spec": "npm:@scope/pkg"})
            status = mcp_server.tool_registry_status({})
        self.assertEqual(out["package"], "npm:@scope/pkg@1.0.0")
        self.assertEqual(out["verdict"], "OK")
        self.assertNotIn("storeError", out)
        self.assertEqual(status["packages"][0]["package"], "npm:@scope/pkg")


class FakeNpm:
    """Stands in for http_json: npm's replication feed (names only, newest
    first, as npm's 2025 replication API returns them) and the registry's
    abbreviated documents. `docs` maps a name to its document, or to an
    exception the lookup raises; a name missing from `docs` is a 404."""

    def __init__(self, feed, docs=None):
        self.feed, self.docs, self.calls = feed, docs or {}, []

    def __call__(self, url, accept=None):
        self.calls.append((url, accept))
        if url.startswith("https://replicate.npmjs.com/"):
            if isinstance(self.feed, Exception):
                raise self.feed
            return self.feed
        name = urllib.parse.unquote(url[len("https://registry.npmjs.org/"):])
        doc = self.docs.get(name)
        if isinstance(doc, Exception):
            raise doc
        if doc is None:
            err = repo.FetchError(f"HTTP 404 fetching {url}")
            err.status = 404
            raise err
        return doc


def names(*ids):
    return {"results": [{"seq": 100 - i, "id": n, "changes": [{"rev": "1-x"}]}
                        for i, n in enumerate(ids)]}


def doc(modified, latest="1.0.0"):
    return {"name": "x", "dist-tags": {"latest": latest}, "versions": {},
            "modified": modified.isoformat().replace("+00:00", "Z")}


class NpmFeedTests(unittest.TestCase):
    CUTOFF = NOW - datetime.timedelta(days=1)

    def discover(self, fake, limit=50):
        notes = {}
        with mock.patch.object(repo, "http_json", side_effect=fake), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            found = repo.discover_npm(self.CUTOFF, limit, notes)
        return found, err.getvalue(), notes

    def test_the_feed_is_read_without_include_docs(self):
        # npm's 2025 replication API rejects include_docs with HTTP 400 (the
        # 0.1.0 discover never ran); metadata comes from the registry instead
        real = {"name": "@s/ok", "dist-tags": {"latest": "1.0.0"}, "versions": {},
                "modified": NOW.strftime("%Y-%m-%dT%H:%M:%S.") + "036Z"}   # npm's own format
        fake = FakeNpm(names("@s/ok"), {"@s/ok": real})
        found, _, notes = self.discover(fake)
        feed_url, accept = fake.calls[0]
        self.assertEqual(feed_url, "https://replicate.npmjs.com/registry/_changes?descending=true&limit=150")
        self.assertNotIn("include_docs", feed_url)
        self.assertIsNone(accept)
        self.assertEqual(fake.calls[1], ("https://registry.npmjs.org/@s%2Fok", repo.NPM_ABBREVIATED))
        self.assertEqual([(e, n, v) for e, n, v, _ in found], [("npm", "@s/ok", "1.0.0")])
        self.assertEqual(notes, {})

    def test_the_window_and_the_limit(self):
        old = NOW - datetime.timedelta(days=3)
        feed = names("new-a", "new-b", "old-c", "new-d", *[f"old-{i}" for i in range(10)])
        docs = {"new-a": doc(NOW), "new-b": doc(NOW - datetime.timedelta(hours=2)),
                "old-c": doc(old), "new-d": doc(NOW - datetime.timedelta(hours=3)),
                **{f"old-{i}": doc(old) for i in range(10)}}
        found, _, _ = self.discover(FakeNpm(feed, docs))
        self.assertEqual([n for _, n, _, _ in found], ["new-a", "new-b", "new-d"])
        found, _, _ = self.discover(FakeNpm(feed, docs), limit=2)
        self.assertEqual([n for _, n, _, _ in found], ["new-a", "new-b"])

    def test_the_walk_stops_once_the_feed_is_behind_the_window(self):
        old = NOW - datetime.timedelta(days=3)
        feed = names("new", *[f"old-{i}" for i in range(200)])
        fake = FakeNpm(feed, {"new": doc(NOW), **{f"old-{i}": doc(old) for i in range(200)}})
        found, _, _ = self.discover(fake)
        self.assertEqual([n for _, n, _, _ in found], ["new"])
        lookups = len(fake.calls) - 1
        self.assertLessEqual(lookups, 2 * repo.NPM_LOOKUP_WORKERS)   # one batch, not 150

    def test_a_failed_lookup_is_listed_with_an_estimated_time(self):
        two_h = NOW - datetime.timedelta(hours=2)
        feed = names("a", "big", "c", "d")
        fake = FakeNpm(feed, {"a": doc(NOW), "big": repo.FetchError("response exceeds 5MB budget"),
                              "c": doc(two_h), "d": {"name": "d"}})     # d: no modified time
        found, err, notes = self.discover(fake)
        when = {n: w for _, n, _, w in found}
        self.assertEqual(sorted(when), ["a", "big", "c", "d"])
        self.assertEqual(when["c"], two_h)
        self.assertEqual(when["big"], two_h)               # the nearest older known time
        self.assertEqual(when["d"], self.CUTOFF)           # nothing older known: the window start
        self.assertIn("could not read the registry entry of 2 npm package(s)", err)
        self.assertEqual(notes, {})                        # npm was checked

    def test_feed_rows_that_are_not_packages(self):
        feed = {"results": [None, [], "x", {"id": 5}, {"id": ""}, {"id": "_design/app"},
                            {"id": "gone", "deleted": True}, {"id": "ok"}, {"id": "ok"}]}
        fake = FakeNpm(feed, {"ok": doc(NOW)})
        found, _, _ = self.discover(fake)
        self.assertEqual([n for _, n, _, _ in found], ["ok"])
        self.assertEqual([u for u, _ in fake.calls[1:]], ["https://registry.npmjs.org/ok"])

    def test_names_npm_would_reject_are_never_looked_up(self):
        feed = names("a" * 120, "x" * 215, "../etc", "@s/ok")
        fake = FakeNpm(feed, {"a" * 120: doc(NOW), "@s/ok": doc(NOW)})
        found, err, _ = self.discover(fake)
        self.assertEqual(sorted(n for _, n, _, _ in found), sorted(["a" * 120, "@s/ok"]))
        self.assertIn("skipped 2 npm feed name(s)", err)
        self.assertFalse([u for u, _ in fake.calls if "etc" in u or "x" * 215 in u])

    def test_hostile_version_dropped(self):
        found, _, _ = self.discover(FakeNpm(names("ok"), {"ok": doc(NOW, latest="../../x")}))
        self.assertEqual(found[0][2], None)

    def test_a_feed_that_cannot_be_read_is_reported_and_noted(self):
        rejected = repo.FetchError("HTTP 400 fetching https://replicate.npmjs.com/…")
        rejected.status = 400
        cases = {
            "rejected": (rejected, "npm rejected the changes-feed request (HTTP 400; "
                                   "its replication API may have changed)"),
            "unreachable": (repo.FetchError("URL error fetching …: timed out"),
                            "could not reach replicate.npmjs.com"),
            "shape": ({"results": {}}, "npm changes feed has an unexpected shape"),
        }
        for label, (feed, message) in cases.items():
            with self.subTest(label):
                found, err, notes = self.discover(FakeNpm(feed))
                self.assertEqual(found, [])
                self.assertIn(message, err)
                self.assertIn("npm was not checked", err)
                self.assertNotIn("needs access", err)
                self.assertTrue(notes["npm"].startswith("not checked: "), notes)

    def test_fetch_errors_carry_the_http_status(self):
        err = urllib.error.HTTPError("https://replicate.npmjs.com/x", 400, "Bad Request", {}, None)
        with mock.patch.object(repo._OPENER, "open", side_effect=err):
            with self.assertRaises(repo.FetchError) as caught:
                repo.http_json("https://replicate.npmjs.com/x")
        self.assertEqual(caught.exception.status, 400)


class DiscoveryGapTests(unittest.TestCase):
    """A registry that could not be checked must not look like "nothing new":
    the CLI says so, and --ci fails the run."""

    def run_cli(self, *argv):
        rejected = repo.FetchError("HTTP 400 fetching …")
        rejected.status = 400
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(repo, "http_json", side_effect=FakeNpm(rejected)), \
                mock.patch("sys.argv", ["lazaret-registry", "discover", "--ecosystem", "npm",
                                        *argv, "--db", os.path.join(d, "r.db")]), \
                contextlib.redirect_stdout(io.StringIO()) as out, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            try:
                repo.main()
                code = 0
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_cli(self):
        code, out, err = self.run_cli("--scan")
        self.assertEqual(code, 0)                           # without --ci: a warning
        self.assertIn("Nothing was checked.", out)
        self.assertNotIn("No packages published", out)
        self.assertIn("discovery incomplete: npm not checked: npm rejected", err)
        code, _, _ = self.run_cli("--scan", "--ci")
        self.assertEqual(code, 1)

    def test_a_partly_read_pypi_is_noted(self):
        rss = (b"<rss><channel><item><title>goodpkg 1.0</title><pubDate>"
               + NOW.strftime("%a, %d %b %Y %H:%M:%S GMT").encode() + b"</pubDate></item></channel></rss>")

        def fetch(url, **kw):
            if url.endswith("updates.xml"):
                raise repo.FetchError("URL error fetching …")
            return rss
        notes = {}
        with mock.patch.object(repo, "_fetch", side_effect=fetch), \
                contextlib.redirect_stderr(io.StringIO()):
            found = repo.discover_pypi(NOW - datetime.timedelta(days=1), 10, notes)
        self.assertEqual([n for _, n, _, _ in found], ["goodpkg"])
        self.assertEqual(notes, {"pypi": "partly checked: the updates.xml feed failed"})

    def test_mcp_marks_the_call_incomplete(self):
        rejected = repo.FetchError("HTTP 400 fetching …")
        rejected.status = 400
        with mock.patch.object(repo, "http_json", side_effect=FakeNpm(rejected)), \
                contextlib.redirect_stderr(io.StringIO()):
            out = mcp_server.tool_discover_packages({"since": "1d", "ecosystem": ["npm"]})
        self.assertEqual(out["count"], 0)
        self.assertTrue(out["incomplete"])
        self.assertIn("npm not checked: npm rejected", out["incompleteReason"])


class DiscoverCliTests(unittest.TestCase):
    def test_discover_scan_ci_with_long_name_then_scan_all(self):
        feed = [("npm", "aaa-good", "1.0.0", NOW), ("npm", "a" * 120, "1.0.0", NOW),
                ("npm", "zzz-good", "1.0.0", NOW)]
        rv = ("1.0.0", "https://registry.npmjs.org/g/-/g-1.0.0.tgz", "tgz", "npm", {})
        with tempfile.TemporaryDirectory() as d:
            db = os.path.join(d, "r.db")
            for argv in (["discover", "--scan", "--ci"], ["scan-all"]):
                with self.subTest(argv=argv), \
                        mock.patch.object(repo, "discover_pypi", return_value=[]), \
                        mock.patch.object(repo, "discover_npm", return_value=feed), \
                        mock.patch.object(repo, "resolve_npm", return_value=rv), \
                        mock.patch.object(repo, "http_bytes", return_value=GOOD_TGZ), \
                        mock.patch.object(repo, "verify_digest", return_value=None), \
                        mock.patch("sys.argv", ["lazaret-registry"] + argv + ["--db", db]), \
                        contextlib.redirect_stdout(io.StringIO()) as out, \
                        contextlib.redirect_stderr(io.StringIO()):
                    repo.main()                          # no SystemExit: all OK
                self.assertEqual(out.getvalue().count("  OK "), 3 if argv[0] == "discover" else 0)


class PypiFeedTests(unittest.TestCase):
    def test_feed_budget(self):
        self.assertLessEqual(repo.FEED_MAX_BYTES, repo.MAX_FEED_BYTES)
        rss = (b"<rss><channel><item><title>goodpkg 1.0</title>"
               b"<pubDate>" + NOW.strftime("%a, %d %b %Y %H:%M:%S GMT").encode() + b"</pubDate>"
               b"</item></channel></rss>")
        with mock.patch.object(repo, "_fetch", return_value=rss) as fetch, \
                mock.patch.object(repo, "http_bytes", side_effect=AssertionError("artifact budget")):
            found = repo.discover_pypi(NOW - datetime.timedelta(days=1), 10)
        self.assertEqual([(e, n, v) for e, n, v, _ in found], [("pypi", "goodpkg", "1.0")])
        for call in fetch.call_args_list:
            self.assertEqual(call.kwargs.get("max_bytes"), repo.MAX_FEED_BYTES)
            self.assertEqual(call.kwargs.get("timeout"), repo.METADATA_TIMEOUT)

    def test_parse_xml_raises_feed_error(self):
        for raw in (b"<rss><channel>", b"not xml", b"<a>&undefined;</a>"):
            with self.subTest(raw=raw):
                with self.assertRaises(repo.FeedError):
                    repo._parse_xml(raw)

    def test_malformed_feed_is_a_warning(self):
        with mock.patch.object(repo, "_fetch", return_value=b"<rss><channel"), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(repo.discover_pypi(NOW, 10), [])
        self.assertIn("rejected", err.getvalue())


class ParseSinceTests(unittest.TestCase):
    def test_huge_window_is_a_value_error(self):
        with self.assertRaises(ValueError):
            repo.parse_since("99999999999999d")


if __name__ == "__main__":
    unittest.main()
