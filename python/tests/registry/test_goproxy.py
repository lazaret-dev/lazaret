"""The Go proxy protocol and Go's settings for it (registry/goproxy.py): GOPROXY lists, GOPRIVATE patterns, what a request path
asks for, and the order of versions. Also `golang.unescape`, which reads the case encoding of a request path."""

import unittest
from unittest import mock

from lazaret.registry import goproxy
from lazaret.registry.ecosystems import golang
from lazaret.scanner import sca


class ParseGoproxyTests(unittest.TestCase):
    def test_a_comma_goes_on_after_a_missing_module_and_a_bar_after_any_error(self):
        self.assertEqual(goproxy.parse_goproxy("https://a.example,https://b.example|https://c.example"),
                         [goproxy.Proxy("https://a.example", False), goproxy.Proxy("https://b.example", True),
                          goproxy.Proxy("https://c.example", False)])

    def test_the_default(self):
        self.assertEqual(goproxy.parse_goproxy("https://proxy.golang.org,direct"),
                         [goproxy.Proxy("https://proxy.golang.org", False), goproxy.Proxy("direct", False)])

    def test_the_list_ends_at_off_and_at_direct(self):
        self.assertEqual(goproxy.parse_goproxy("off,https://x.example"), [goproxy.Proxy("off", False)])
        self.assertEqual(goproxy.parse_goproxy("https://a.example|direct,https://x.example"),
                         [goproxy.Proxy("https://a.example", True), goproxy.Proxy("direct", False)])

    def test_spaces_and_empty_entries_are_left_out(self):
        self.assertEqual(goproxy.parse_goproxy(" https://a.example , ,,|https://b.example "),
                         [goproxy.Proxy("https://a.example", False), goproxy.Proxy("https://b.example", False)])

    def test_nothing(self):
        for text in ("", " ", ",", None, 5):
            with self.subTest(text):
                self.assertEqual(goproxy.parse_goproxy(text), [])


class GlobTests(unittest.TestCase):
    def matches(self, globs, path):
        found = goproxy.glob_matches(globs, path)
        self.assertIsInstance(found, bool)
        return found

    def test_a_pattern_names_the_module_and_what_is_below_it(self):
        self.assertTrue(self.matches("rsc.io/private", "rsc.io/private"))
        self.assertTrue(self.matches("rsc.io/private", "rsc.io/private/quux"))
        self.assertFalse(self.matches("rsc.io/private", "rsc.io/privateer"))
        self.assertFalse(self.matches("rsc.io/private", "rsc.io"))
        self.assertFalse(self.matches("rsc.io/private/quux", "rsc.io/private"))

    def test_a_star_stays_inside_one_path_element(self):
        self.assertTrue(self.matches("*.corp.example.com", "git.corp.example.com/team/repo"))
        self.assertFalse(self.matches("*.corp.example.com", "corp.example.com/team"))
        self.assertTrue(self.matches("example.com/*", "example.com/anything/below"))
        self.assertFalse(self.matches("example.com/*/x", "example.com/a/b/x"))
        self.assertTrue(self.matches("example.com/*/x", "example.com/a/x"))

    def test_question_mark_and_classes(self):
        self.assertTrue(self.matches("a.io/v?", "a.io/v2/x"))
        self.assertFalse(self.matches("a.io/v?", "a.io/v22"))
        self.assertTrue(self.matches("a.io/[b-d]x", "a.io/cx/y"))
        self.assertFalse(self.matches("a.io/[b-d]x", "a.io/ex/y"))
        self.assertTrue(self.matches("a.io/[^b-d]x", "a.io/ex"))
        self.assertFalse(self.matches("a.io/[^b-d]x", "a.io/cx"))
        self.assertTrue(self.matches("a.io/[xyz]", "a.io/y"))

    def test_a_negated_class_takes_the_caret_as_a_character_it_does_not_name(self):
        self.assertTrue(self.matches("[^a-z]", "^"))                         # (the ^ opens the negation; it is not in the class)
        self.assertTrue(self.matches("[^a-z]", "X"))
        self.assertFalse(self.matches("[^a-z]", "q"))

    def test_a_range_may_be_of_one_character_and_a_class_must_be_closed(self):
        self.assertTrue(self.matches("[a-a]", "a"))
        self.assertFalse(self.matches("[a-a]", "b"))
        for malformed in ("[abc", "[a", "[a-", "[", "[]", "[^]", "[z-a]", "[a-]"):
            with self.subTest(malformed):
                self.assertFalse(self.matches(malformed, malformed))
                self.assertFalse(self.matches(malformed, "a"))

    def test_a_backslash_makes_the_next_character_plain(self):
        self.assertTrue(self.matches("a.io/x\\*y", "a.io/x*y"))
        self.assertFalse(self.matches("a.io/x\\*y", "a.io/xzzy"))

    def test_a_backslash_in_a_class(self):
        self.assertTrue(self.matches("a.io/[\\]]", "a.io/]"))                  # (a class of the one character ])
        self.assertFalse(self.matches("a.io/[\\]]", "a.io/\\"))
        self.assertTrue(self.matches("a.io/[\\-x]", "a.io/-"))                 # (a class of - and x)
        self.assertTrue(self.matches("a.io/[\\-x]", "a.io/x"))
        self.assertFalse(self.matches("a.io/[\\-x]", "a.io/y"))
        self.assertTrue(self.matches("a.io/[a-\\z]", "a.io/m"))               # (a range up to a plain z)
        self.assertTrue(self.matches("a.io/[\\a-c]x", "a.io/bx"))

    def test_a_malformed_pattern_matches_nothing(self):
        for glob in ("a.io/[", "a.io/[]", "a.io/[a-", "a.io/[z-a]", "a.io/x\\", "a.io/[-a]", "a.io/[a\\"):
            with self.subTest(glob):
                self.assertFalse(self.matches(glob, "a.io/a"))
                self.assertFalse(self.matches(glob, "a.io/-"))

    def test_the_list_is_commas_with_empty_entries_skipped(self):
        self.assertTrue(self.matches(",a.io,", "a.io/x"))
        self.assertTrue(self.matches("b.io,a.io", "a.io/x"))
        self.assertFalse(self.matches("", "a.io"))
        self.assertFalse(self.matches(None, "a.io"))
        self.assertFalse(self.matches(",,", "a.io"))
        self.assertFalse(self.matches(",,", ""))


class RequestTests(unittest.TestCase):
    def req(self, path):
        return goproxy.parse_request(path)

    def test_what_the_protocol_asks(self):
        self.assertEqual(self.req("/example.com/m/@v/list"), goproxy.Request("list", "example.com/m", None, None))
        self.assertEqual(self.req("/example.com/m/@latest"), goproxy.Request("latest", "example.com/m", None, None))
        for kind in ("info", "mod", "zip"):
            self.assertEqual(self.req(f"/example.com/m/@v/v1.2.3.{kind}"),
                             goproxy.Request(kind, "example.com/m", "v1.2.3", None))

    def test_capitals_are_decoded(self):
        self.assertEqual(self.req("/github.com/!burnt!sushi/toml/@v/v1.3.2.zip"),
                         goproxy.Request("zip", "github.com/BurntSushi/toml", "v1.3.2", None))
        self.assertEqual(self.req("/x.io/m/@v/v1.0.0-!r!c1.mod").version, "v1.0.0-RC1")

    def test_a_capital_that_is_not_encoded_is_not_a_request(self):
        self.assertIsNone(self.req("/github.com/BurntSushi/toml/@v/list"))
        self.assertIsNone(self.req("/x.io/m/@v/V1.0.0.zip"))
        self.assertIsNone(self.req("/x.io/m/!/@v/list"))

    def test_an_info_request_may_name_a_branch_or_a_commit(self):
        self.assertEqual(self.req("/x.io/m/@v/master.info").version, "master")
        self.assertEqual(self.req("/x.io/m/@v/0123abcd.info").version, "0123abcd")
        self.assertEqual(self.req("/x.io/m/@v/v1.2.info").version, "v1.2")
        self.assertIsNone(self.req("/x.io/m/@v/feature/x.info"))
        self.assertIsNone(self.req("/x.io/m/@v/a b.info"))
        self.assertIsNone(self.req("/x.io/m/@v/" + "a" * 201 + ".info"))
        self.assertEqual(self.req("/x.io/m/@v/" + "a" * 200 + ".info").version, "a" * 200)

    def test_a_mod_or_a_zip_names_a_version(self):
        for kind in ("mod", "zip"):
            for bad in ("master", "v1.2", "1.2.3", "v1.2.3/x", "v1.2.3.4"):
                with self.subTest(kind=kind, version=bad):
                    self.assertIsNone(self.req(f"/x.io/m/@v/{bad}.{kind}"))
        self.assertEqual(self.req("/x.io/m/@v/v1.2.3+incompatible.zip").version, "v1.2.3+incompatible")
        self.assertEqual(self.req("/x.io/m/@v/v0.0.0-20200101000000-abcdef123456.mod").version,
                         "v0.0.0-20200101000000-abcdef123456")
        edge = "v1.0.0-" + "a" * (golang.MAX_VERSION - len("v1.0.0-"))
        self.assertEqual(len(edge), golang.MAX_VERSION)
        self.assertEqual(self.req(f"/x.io/m/@v/{edge}.zip").version, edge)
        self.assertIsNone(self.req(f"/x.io/m/@v/{edge}a.zip"))

    def test_the_module_must_be_a_module_path(self):
        for path in ("/m/@v/list", "/example.com/../x/@v/list", "/example.com//m/@v/list", "//@v/list", "/@v/list",
                     "/-bad.example/m/@v/list", "/example.com/m/@v/v1.0.0.zip/more"):
            with self.subTest(path):
                self.assertIsNone(self.req(path))
        edge = "x.io/" + "a" * (golang.MAX_NAME - len("x.io/"))
        self.assertEqual(len(edge), golang.MAX_NAME)
        self.assertEqual(self.req(f"/{edge}/@v/list").module, edge)
        self.assertIsNone(self.req(f"/{edge}a/@v/list"))

    def test_everything_else_is_not_a_request(self):
        for path in ("", "x", "/", "/example.com/m", "/example.com/m/@v/", "/example.com/m/@v/v1.0.0", "/example.com/m/@v/v1.0.0.txt",
                     "/example.com/m/@x", "/example.com/m/@x/v1.0.0.zip", "/example.com/m/@w/list", "/example.com/m/@v/list/", "/example.com/m\\x/@v/list", "/example.com/m/@v/v1.0.0.zip\x00",
                     None, 5):
            with self.subTest(path):
                self.assertIsNone(self.req(path))

    def test_the_checksum_database_is_relayed_as_it_is_asked(self):
        got = self.req("/sumdb/sum.golang.org/supported")
        self.assertEqual((got.kind, got.rest), ("sumdb", "sumdb/sum.golang.org/supported"))
        for path in ("/sumdb/sum.golang.org/latest", "/sumdb/sum.golang.org/tile/8/0/x001/234", "/sumdb/sum.golang.org/tile/8/1/012",
                     "/sumdb/sum.golang.org/tile/8/data/x001/234.p/17", "/sumdb/sum.golang.org/lookup/github.com/!burnt!sushi/toml@v1.3.2"):
            with self.subTest(path):
                self.assertEqual(self.req(path).kind, "sumdb")
        self.assertIsNone(self.req("/sumdb/../x"))
        self.assertIsNone(self.req("/sumdb/a/../../b"))

    def test_nothing_but_what_go_asks_of_the_checksum_database_is_relayed(self):
        # (any path below /sumdb/ was relayed to the proxy with the user's credentials for it, a decoded `?` as a query
        # string: the Go/Rust review's GO-3)
        for path in ("/sumdb/sum.golang.org/other", "/sumdb/sum.golang.org/tile/8/0/x001", "/sumdb/sum.golang.org/latest?x=1",
                     "/sumdb/sum.golang.org/lookup/x.io/m@v1.0.0?y", "/sumdb/sum.golang.org/lookup/../../etc@v1.0.0",
                     "/sumdb/sum.golang.org/lookup/x.io/m", "/sumdb/sum.golang.org/lookup/x.io/m@notaversion",
                     "/sumdb/" + "a" * 300 + "/latest", "/sumdb//latest", "/sumdb/sum.golang.org/tile/8/0/../x"):
            with self.subTest(path):
                self.assertIsNone(self.req(path))

    def test_the_path_at_another_proxy_is_made_again_from_the_checked_names(self):
        for path in ("/github.com/!burnt!sushi/toml/@v/v1.3.2.zip", "/x.io/m/@v/list", "/x.io/m/@latest", "/x.io/m/@v/master.info",
                     "/x.io/m/@v/v1.0.0-!r!c1.mod", "/sumdb/sum.golang.org/supported"):
            with self.subTest(path):
                self.assertEqual(goproxy.upstream_path(self.req(path)), path.lstrip("/"))


class NewestFirstTests(unittest.TestCase):
    def test_semver_order(self):
        self.assertEqual(goproxy.newest_first(["v1.0.0", "v1.10.0", "v1.2.0", "v2.0.0-rc.1", "v2.0.0", "v1.10.0-beta"]),
                         ["v2.0.0", "v2.0.0-rc.1", "v1.10.0", "v1.10.0-beta", "v1.2.0", "v1.0.0"])

    def test_what_is_not_a_version_comes_first(self):
        self.assertEqual(goproxy.newest_first(["v1.0.0", "junk", "v1.1.0"])[0], "junk")

    def test_nothing(self):
        self.assertEqual(goproxy.newest_first([]), [])

    def test_versions_that_cannot_be_compared_are_left_as_they_came(self):
        with mock.patch.object(sca, "version_key", side_effect=lambda v, eco: 1 if v == "v1.0.0" else "x"):
            self.assertEqual(goproxy.newest_first(["v1.0.0", "v2.0.0", "v3.0.0"]), ["v1.0.0", "v2.0.0", "v3.0.0"])


class UnescapeTests(unittest.TestCase):
    def test_what_escape_made_is_made_again(self):
        for text in ("github.com/BurntSushi/toml", "v1.0.0-RC1", "a.io/x", "", "AbC", "!"[:0]):
            with self.subTest(text):
                self.assertEqual(golang.unescape(golang.escape(text)), text)

    def test_what_is_not_an_encoding(self):
        for text in ("a/B", "a!", "a!B", "a!!b", "a!1", "é", "!", "a!/b"):
            with self.subTest(text):
                self.assertIsNone(golang.unescape(text))

    def test_the_encoding_of_a_capital(self):
        self.assertEqual(golang.unescape("!a!b!c"), "ABC")
        self.assertEqual(golang.unescape("a!b"), "aB")


if __name__ == "__main__":
    unittest.main()
