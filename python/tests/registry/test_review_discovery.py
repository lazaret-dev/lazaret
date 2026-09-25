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


class NpmFeedTests(unittest.TestCase):
    def feed(self, data):
        with mock.patch.object(repo, "http_json", return_value=data), \
                contextlib.redirect_stderr(io.StringIO()) as err:
            return repo.discover_npm(NOW - datetime.timedelta(days=1), 50), err.getvalue()

    def row(self, name, modified=None, latest="1.0.0"):
        return {"id": name, "doc": {"name": name, "time": {"modified": modified or NOW.isoformat()},
                                    "dist-tags": {"latest": latest}}}

    def test_unexpected_shapes_are_skipped_not_fatal(self):
        data = {"results": [None, [], "x", {"doc": None, "id": "ok-a"},
                            {"doc": {"name": "t", "time": "yesterday"}},
                            {"doc": {"name": "u", "time": {"modified": 12}}},
                            {"doc": {"name": 5}},
                            {"doc": {"name": "v", "time": {"modified": NOW.isoformat()},
                                     "dist-tags": ["1"]}},
                            self.row("good")]}
        found, _err = self.feed(data)
        self.assertEqual(sorted((e, n, str(v)) for e, n, v, _ in found),
                         [("npm", "good", "1.0.0"), ("npm", "v", "None")])
        for bad in ([], None, "x", {"results": {}}, {"results": None}):
            with self.subTest(data=bad):
                self.assertEqual(self.feed(bad)[0], [])

    def test_names_npm_would_reject_are_skipped(self):
        found, err = self.feed({"results": [self.row("a" * 120), self.row("x" * 215),
                                            self.row("../etc"), self.row("@s/ok")]})
        self.assertEqual(sorted(n for _, n, _, _ in found), sorted(["a" * 120, "@s/ok"]))
        self.assertIn("skipped 2 npm feed name(s)", err)

    def test_hostile_version_dropped(self):
        found, _ = self.feed({"results": [self.row("ok", latest="../../x")]})
        self.assertEqual(found[0][2], None)


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
