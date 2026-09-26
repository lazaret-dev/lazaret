"""PyPI's changelog over XML-RPC, for `discover --resume`.

PyPI's RSS feeds reach back about 20 minutes. Its XML-RPC mirroring methods
list every change after a serial number: changelog_last_serial() and
changelog_since_serial(serial) -> [(name, version, timestamp, action,
serial)], at most 50,000 rows per call. The request goes through _fetch
(https to pypi.org only, byte and time limits; POST support added for it)
and the answer is parsed by lazaret.safexml's XML-RPC parser. Only releases
and new projects are kept.

Every answer here is built in memory (no network). The hostile ones are
inert XML: entity declarations, an external entity pointing at 192.0.2.1,
deep nesting, oversized and malformed documents, faults.
"""

import datetime
import io
import unittest
import xmlrpc.client
from unittest import mock

from lazaret.registry import repo

UTC = datetime.timezone.utc
T0 = int(datetime.datetime(2026, 9, 26, 17, 0, tzinfo=UTC).timestamp())


def answer(value):
    return xmlrpc.client.dumps((value,), methodresponse=True, allow_none=True).encode()


def fault(code, text):
    return xmlrpc.client.dumps(xmlrpc.client.Fault(code, text), methodresponse=True).encode()


def row(serial, name, version, action="new release", stamp=None):
    return [name, version, T0 + (serial - 100) if stamp is None else stamp, action, serial]


def changelog(raw, since=100):
    with mock.patch.object(repo, "_fetch", return_value=raw):
        return repo._pypi_changelog(since)


class RequestTests(unittest.TestCase):
    def test_one_post_through_the_fetch_limits(self):
        with mock.patch.object(repo, "_fetch", return_value=answer([])) as fetch:
            repo._pypi_changelog(30000000)
        fetch.assert_called_once()
        (url,), kw = fetch.call_args
        self.assertEqual(url, "https://pypi.org/pypi")
        self.assertEqual(kw["max_bytes"], repo.PYPI_XMLRPC_MAX_BYTES)
        self.assertEqual(kw["timeout"], repo.METADATA_TIMEOUT)
        self.assertEqual(kw["content_type"], "text/xml")
        self.assertEqual(xmlrpc.client.loads(kw["data"]), ((30000000,), "changelog_since_serial"))

    def test_fetch_posts_a_body(self):
        seen = []

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def open_(req, timeout=None):
            seen.append(req)
            return Response(answer(7))
        with mock.patch.object(repo._OPENER, "open", side_effect=open_):
            self.assertEqual(repo._pypi_last_serial(), 7)
        req = seen[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.full_url, "https://pypi.org/pypi")
        self.assertEqual(req.get_header("Content-type"), "text/xml")
        self.assertEqual(xmlrpc.client.loads(req.data), ((), "changelog_last_serial"))
        # GETs are unchanged
        seen.clear()
        with mock.patch.object(repo._OPENER, "open", side_effect=open_):
            repo._fetch("https://pypi.org/rss/updates.xml", max_bytes=10_000)
        self.assertEqual(seen[0].get_method(), "GET")
        self.assertIsNone(seen[0].data)

    def test_a_post_elsewhere_is_refused_before_any_request(self):
        with mock.patch.object(repo._OPENER, "open", side_effect=AssertionError("fetched")):
            for url in ("https://pypi.invalid/pypi", "http://pypi.org/pypi"):
                with self.subTest(url=url), self.assertRaises(repo.FetchError):
                    repo._fetch(url, data=b"<methodCall/>", content_type="text/xml")

    def test_an_answer_over_the_byte_limit_is_not_read(self):
        class Endless(io.RawIOBase):
            def readinto(self, b):
                b[:] = b"x" * len(b)
                return len(b)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False
        with mock.patch.object(repo, "PYPI_XMLRPC_MAX_BYTES", 256 * 1024), \
                mock.patch.object(repo._OPENER, "open", return_value=Endless()):
            with self.assertRaisesRegex(repo.FetchError, "budget"):
                repo._pypi_changelog(1)


class ChangelogTests(unittest.TestCase):
    def test_releases_and_new_projects_oldest_first(self):
        got = changelog(answer([
            row(103, "later-pkg", "2.0"),
            row(101, "fresh-pkg", None, "create"),
            row(102, "fresh-pkg", "0.1"),
            row(104, "fresh-pkg", "0.1", "add py3 file fresh_pkg-0.1-py3-none-any.whl"),
            row(105, "only-created", None, "create"),
            row(106, "Some.Project", "1.0", "remove release"),
            row(107, "Some.Project", "1.0rc1"),
            row(108, "some-project", "1.0rc1"),                # the same release, another spelling
        ]))
        self.assertEqual([e[1:3] for e in got["events"]],
                         [("fresh-pkg", "0.1"), ("later-pkg", "2.0"), ("only-created", None),
                          ("Some.Project", "1.0rc1")])
        self.assertEqual([e[0] for e in got["events"]], [102, 103, 105, 107])
        self.assertEqual(got["events"][0][3], datetime.datetime(2026, 9, 26, 17, 0, 2, tzinfo=UTC))
        self.assertEqual(got["rows"], 8)
        self.assertEqual(got["last"][0], 108)                  # other actions count as read
        self.assertEqual((got["unread"], got["names"]), (0, 0))

    def test_rows_that_cannot_be_read(self):
        raw = answer([
            "not a row", ["too", "short"], row(101, "a", "1.0") + ["extra"],
            ["b", "1.0", T0, "new release", "102"],            # serial as text
            ["c", "1.0", T0, "new release", True],             # a boolean is not a serial
            ["d", "1.0", T0, "new release", -5],
            ["e", "1.0", "yesterday", "new release", 103],
            ["f", "1.0", "HUGE", "new release", 104],          # <i8>, year out of range
            ["g", "1.0", T0, 7, 105],                          # action not text
            row(106, "ok-pkg", "1.0"),
        ]).replace(b"<string>HUGE</string>", b"<i8>1000000000000000</i8>")
        got = changelog(raw)
        self.assertEqual([e[1] for e in got["events"]], ["ok-pkg"])
        self.assertEqual(got["unread"], 9)
        self.assertEqual(got["last"][0], 106)

    def test_names_and_versions_are_checked(self):
        got = changelog(answer([
            row(101, "../../etc", "1.0"), row(102, "a/b", "1.0"), row(103, "-x", "1.0"),
            row(104, None, "1.0"), row(105, "x" * 300, "1.0"),
            row(106, "ok-a", "1.0;touch x"), row(107, "ok-b", None), row(108, "ok-c", "1!2.0"),
        ]))
        self.assertEqual([e[1:3] for e in got["events"]],
                         [("ok-a", None), ("ok-b", None), ("ok-c", None)])
        self.assertEqual(got["names"], 5)

    def test_rows_at_or_before_the_serial_are_ignored(self):
        got = changelog(answer([row(99, "old", "1.0"), row(100, "same", "1.0"), row(101, "new", "1.0")]))
        self.assertEqual([e[1] for e in got["events"]], ["new"])
        self.assertEqual(got["last"][0], 101)
        empty = changelog(answer([]))
        self.assertEqual((empty["events"], empty["rows"], empty["last"]), ([], 0, None))

    def test_answers_that_are_not_a_changelog(self):
        cases = {
            "a struct": answer({"rows": []}),
            "a number": answer(5),
            "nil": answer(None),
            "two values": (b"<methodResponse><params><param><value><array><data/></array></value>"
                           b"</param><param><value><int>1</int></value></param></params>"
                           b"</methodResponse>"),
            "a call": xmlrpc.client.dumps(([],), "changelog_since_serial").encode(),
        }
        for label, raw in cases.items():
            with self.subTest(label), self.assertRaises(repo.FeedError):
                changelog(raw)

    def test_faults(self):
        with self.assertRaises(repo.FeedError) as caught:
            changelog(fault(-32500, "RuntimeError: rate limited" + "x" * 1000))
        msg = str(caught.exception)
        self.assertIn("changelog_since_serial failed: fault -32500: RuntimeError: rate limited", msg)
        self.assertLess(len(msg), 300)
        odd = (b"<?xml version='1.0'?><methodResponse><fault><value><struct><member><name>x</name>"
               b"<value><int>1</int></value></member></struct></value></fault></methodResponse>")
        with self.assertRaisesRegex(repo.FeedError, "rejected"):
            changelog(odd)


BILLION_LAUGHS = (b'<?xml version="1.0"?>\n<!DOCTYPE lolz [<!ENTITY lol "lol">'
                  b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
                  b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>'
                  b'<methodResponse><params><param><value><string>&lol3;</string></value>'
                  b'</param></params></methodResponse>')
EXTERNAL_ENTITY = (b'<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY ext SYSTEM "http://192.0.2.1/x">]>'
                   b'<methodResponse><params><param><value><string>&ext;</string></value>'
                   b'</param></params></methodResponse>')
DOCTYPE_ONLY = (b'<?xml version="1.0"?>\n<!DOCTYPE methodResponse>'
                b'<methodResponse><params><param><value><int>1</int></value></param></params>'
                b'</methodResponse>')


def deep(levels):
    return (b"<methodResponse><params><param><value>" + b"<array><data><value>" * levels
            + b"<int>1</int>" + b"</value></data></array>" * levels
            + b"</value></param></params></methodResponse>")


class HostileAnswerTests(unittest.TestCase):
    def test_refused_by_the_safe_parser(self):
        for label, raw in (("entity expansion", BILLION_LAUGHS), ("external entity", EXTERNAL_ENTITY),
                           ("any DOCTYPE", DOCTYPE_ONLY), ("deep nesting", deep(2000))):
            with self.subTest(label), \
                    mock.patch("urllib.request.urlopen", side_effect=AssertionError("fetched")):
                with self.assertRaisesRegex(repo.FeedError, r"answer was rejected \(\w+\)"):
                    changelog(raw)

    def test_malformed(self):
        for raw in (b"", b"<methodResponse><params>", b"not xml at all", b"\xff\xfe<\x00",
                    b"<methodResponse><params><param><value><int>12x</int></value></param>"
                    b"</params></methodResponse>",
                    b"<methodResponse><params><param><value><boolean>7</boolean></value></param>"
                    b"</params></methodResponse>"):
            with self.subTest(raw=raw[:40]), self.assertRaises(repo.FeedError):
                changelog(raw)

    def test_the_parser_has_the_same_byte_limit(self):
        # _fetch caps what is read; the parser caps it again
        rows = [row(101 + i, f"pkg-{i}", "1.0") for i in range(400)]
        raw = answer(rows)
        self.assertGreater(len(raw), 20_000)
        with mock.patch.object(repo, "PYPI_XMLRPC_MAX_BYTES", 20_000):
            with self.assertRaisesRegex(repo.FeedError, r"rejected \(\w+\)"):
                changelog(raw)
        self.assertEqual(len(changelog(raw)["events"]), 400)

    def test_the_answer_is_not_echoed(self):
        with self.assertRaises(repo.FeedError) as caught:
            changelog(b"<methodResponse>\x1b]0;owned\x07<oops")
        self.assertNotIn("owned", str(caught.exception))


class LastSerialTests(unittest.TestCase):
    def last(self, raw):
        with mock.patch.object(repo, "_fetch", return_value=raw) as fetch:
            value = repo._pypi_last_serial()
        self.assertEqual(xmlrpc.client.loads(fetch.call_args.kwargs["data"]),
                         ((), "changelog_last_serial"))
        return value

    def test_a_serial(self):
        self.assertEqual(self.last(answer(30123456)), 30123456)
        big = (b"<methodResponse><params><param><value><i8>4294967296</i8></value></param>"
               b"</params></methodResponse>")
        self.assertEqual(self.last(big), 2 ** 32)

    def test_not_a_serial(self):
        for value in (True, -1, "30123456", 3.5, None, [1]):
            with self.subTest(value=value), self.assertRaises(repo.FeedError):
                self.last(answer(value))

    def test_network_errors_stay_fetch_errors(self):
        with mock.patch.object(repo, "_fetch", side_effect=repo.FetchError("URL error fetching …")):
            with self.assertRaises(repo.FetchError):
                repo._pypi_last_serial()


if __name__ == "__main__":
    unittest.main()
