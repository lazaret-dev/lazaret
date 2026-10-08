"""The HTTPS transports of live secret verification (scanner/secretverify_http.py): lazaret-net's and urllib's, against a stub
provider on 127.0.0.1 (no real service is called; the stub's certificates are made with `openssl`, and the tests that need the stub
are skipped without it; lazaret-net's are skipped where the native transport is not available)."""

import datetime
import hashlib
import hmac
import os
import re
import socket
import ssl
import threading
import time
import unittest
from http.client import HTTPSConnection
from unittest import mock

from lazaret.scanner import _native, nativenet
from lazaret.scanner import secretverify_http as http
from tests.scanner import _verify_stub as vs

GOOD = http.Request("GET", "api.github.com", "/user", {"Authorization": "Bearer abc"}, None, ("Authorization",))


#: a credential of each provider's format (made up)
SAMPLES = {
    "github": "ghp_" + "a1B2" * 9, "slack": "xoxb-1234567890-abcdefghij", "stripe": "sk_live_" + "a1" * 12,
    "npm": "npm_" + "A1b2" * 9, "openai": "sk-proj-" + "a1" * 20, "anthropic": "sk-ant-api03-" + "Ab1_" * 10,
    "aws": {"id": "AKIAABCDEFGHIJKLMNOP", "secret": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
}
NO_PROXY_ENV = {k: v for k, v in os.environ.items() if k.lower() not in ("https_proxy", "http_proxy", "all_proxy", "no_proxy")}


def request(**changes):
    """GOOD with `changes`; new headers keep the credential's field if they still have it."""
    req = GOOD._replace(**changes)
    if "headers" in changes and "secret_headers" not in changes and isinstance(req.headers, dict):
        req = req._replace(secret_headers=tuple(n for n in GOOD.secret_headers if n in req.headers))
    return req


def sigv4_holds(seen, secret_key):
    """Does the signature in what the stub received (`seen`) hold over it? AWS's Signature Version 4 worked out here, with
    hashlib and hmac, over the fields it names as they came (each must have come once)."""
    m = re.fullmatch(r"AWS4-HMAC-SHA256 Credential=[^/]+/(\d{8})/([^/]+)/([^/]+)/aws4_request, SignedHeaders=([a-z0-9;-]+), "
                     r"Signature=([0-9a-f]{64})", seen.headers["authorization"])
    date, region, service, signed, signature = m.groups()
    fields = ""
    for name in signed.split(";"):
        values = [v for n, v in seen.raw if n.lower() == name]
        if len(values) != 1:
            return False
        fields += f"{name}:{' '.join(values[0].split())}\n"
    path, _, query = seen.path.partition("?")
    canonical = "\n".join([seen.method, path, query, fields, signed, hashlib.sha256(seen.body).hexdigest()])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", seen.headers["x-amz-date"], scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + secret_key).encode()
    for part in (date, region, service, "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    return hmac.compare_digest(hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest(), signature)


class CheckRequestTests(unittest.TestCase):
    def refused(self, req):
        with self.assertRaises(http.TransportError) as caught:
            http.check_request(req)
        self.assertEqual(caught.exception.kind, "refused")

    def test_a_good_request_is_let_through_as_it_is(self):
        self.assertIs(http.check_request(GOOD), GOOD)
        post = request(method="POST", body=b"a=1")
        self.assertIs(http.check_request(post), post)

    def test_what_is_not_a_request_is_refused(self):
        for thing in (None, "GET https://x/", ("GET", "a.b", "/", {}, None), {"method": "GET"}):
            with self.subTest(thing):
                self.refused(thing)

    def test_only_get_and_post_are_sent(self):
        for method in ("PUT", "DELETE", "HEAD", "CONNECT", "get", "", None, 5):
            with self.subTest(method):
                self.refused(request(method=method))

    def test_a_host_is_a_lower_case_dns_name(self):
        for host in ("", "localhost", "127.0.0.1", "[::1]", "1.2.3.4", "API.github.com", "api.github.com.", "api.github.com:443", "a@api.github.com",
                     "api_github.com", "api.github.com/x", "api github.com", "api.github.com\n", "-a.example.com", "a-.example.com", "a..example.com",
                     ".example.com", "é.example.com", "a" * 64 + ".example.com", "a.b.c.d" + "." + "x" * 250, "xn--é.example", 5, None,
                     "example.123", "example.c"):
            with self.subTest(host):
                self.refused(request(host=host))
        for host in ("api.github.com", "slack.com", "a-b.example.co.uk", "a" * 63 + ".example.com", "sts.amazonaws.com", "xn--bcher-kva.example",
                     "x.zz"):
            with self.subTest(host):
                self.assertIsNotNone(http.check_request(request(host=host)))

    def test_the_longest_host_is_253_characters(self):
        label = "a" * 63
        host = ".".join([label, label, label, "b" * 57 + ".com"])
        self.assertEqual(len(host), 253)
        self.assertIsNotNone(http.check_request(request(host=host)))
        self.refused(request(host="c" + host))

    def test_the_length_of_the_whole_name_is_bounded_and_not_only_the_length_of_its_labels(self):
        head = ".".join(["a" * 61] * 4)                               # (four labels that are each allowed)
        self.assertEqual(len(head + "." + "b" * 5), 253)
        self.assertIsNotNone(http.check_request(request(host=head + "." + "b" * 5)))
        self.refused(request(host=head + "." + "b" * 6))             # (254)

    def test_the_limits_are_the_ones_the_documentation_names(self):
        self.assertEqual((http.MAX_ANSWER_BYTES, http.MAX_HEADERS, http.MAX_HEADER_VALUE, http.MAX_PATH), (65536, 64, 512, 2000))
        self.assertIsNotNone(http.check_request(request(path="/" + "a" * 1999)))                     # (2,000 characters)
        self.refused(request(path="/" + "a" * 2000))
        self.assertIsNotNone(http.check_request(request(headers={"X-A": "v" * 512})))
        self.refused(request(headers={"X-A": "v" * 513}))
        self.assertIsNotNone(http.check_request(request(headers={f"X-{i}": "v" for i in range(64)})))
        self.refused(request(headers={f"X-{i}": "v" for i in range(65)}))

    def test_what_an_error_says_is_its_kind_and_its_note(self):
        self.assertEqual(str(http.TransportError("tls")), "tls")
        self.assertEqual(str(http.TransportError("tls", "bad")), "tls: bad")
        self.assertEqual(http.TransportError("proxy", "x").kind, "proxy")

    def test_a_path_is_printable_ascii_that_starts_with_a_slash(self):
        for path in ("", "user", "/a b", "/a\nb", "/é", "/a\x00", "/\x7f", None, 5, "/" + "a" * http.MAX_PATH):
            with self.subTest(repr(path)):
                self.refused(request(path=path))
        for path in ("/", "/user", "/a?b=c&d=%20", "/" + "a" * (http.MAX_PATH - 1)):
            with self.subTest(path[:20]):
                self.assertIsNotNone(http.check_request(request(path=path)))

    def test_headers_are_a_small_mapping_of_printable_text(self):
        for headers in (None, [("a", "b")], {"a b": "c"}, {"": "c"}, {"a": "b\r\nX: y"}, {"a": "b\n"}, {"a": "é"}, {"a": 5}, {5: "a"}, {"a\n": "b"},
                        {"a": "x" * (http.MAX_HEADER_VALUE + 1)}, {"x" * 65: "b"}, {f"h{i}": "v" for i in range(http.MAX_HEADERS + 1)}):
            with self.subTest(str(headers)[:40]):
                self.refused(request(headers=headers))
        self.assertIsNotNone(http.check_request(request(headers={"a": "x" * http.MAX_HEADER_VALUE})))
        self.assertIsNotNone(http.check_request(request(headers={"x" * 64: "b"})))
        self.assertIsNotNone(http.check_request(request(headers={f"h{i}": "v" for i in range(http.MAX_HEADERS)})))
        self.assertIsNotNone(http.check_request(request(headers={"X-Api-Key": "a b c"})))

    def test_the_headers_that_are_the_transports_are_refused_in_any_case(self):
        for name in ("Host", "host", "CONTENT-LENGTH", "Transfer-Encoding", "Connection"):
            with self.subTest(name):
                self.refused(request(headers={name: "x"}))

    def test_a_body_is_bytes(self):
        for body in ("a=1", 5, bytearray(b"a"), [b"a"]):
            with self.subTest(repr(body)):
                self.refused(request(method="POST", body=body))
        self.assertIsNotNone(http.check_request(request(method="POST", body=b"")))

    def test_the_fields_that_carry_the_credential_are_the_request_s_own(self):
        for names in (None, "Authorization", ("X-Other",), (5,), ("Authorization", None)):
            with self.subTest(names):
                self.refused(request(secret_headers=names))
        for names in ((), ["Authorization"], ("authorization",), ("AUTHORIZATION", "Authorization")):
            with self.subTest(names):
                self.assertIsNotNone(http.check_request(request(secret_headers=names)))
        self.assertEqual(http.Request("GET", "a.example", "/", {}, None).secret_headers, ())

    def test_what_is_refused_says_nothing_of_the_request(self):
        secret = "ghp_" + "s" * 36
        with self.assertRaises(http.TransportError) as caught:
            http.check_request(request(host="Bad Host", headers={"Authorization": "Bearer " + secret}))
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("Bad Host", str(caught.exception))


class ProxySettingsTests(unittest.TestCase):
    def test_no_setting_no_proxy(self):
        self.assertIsNone(http._proxy("api.github.com", {}))
        self.assertIsNone(http._proxy("api.github.com", {"HTTPS_PROXY": ""}))
        self.assertIsNone(http._proxy("api.github.com", {"HTTP_PROXY": "http://p:1"}))

    def test_an_http_proxy_with_or_without_a_port_and_a_scheme(self):
        self.assertEqual(http._proxy("api.github.com", {"HTTPS_PROXY": "http://proxy.example:3128"}), ("proxy.example", 3128, {}))
        self.assertEqual(http._proxy("api.github.com", {"https_proxy": "http://proxy.example"}), ("proxy.example", 80, {}))
        self.assertEqual(http._proxy("api.github.com", {"https_proxy": "proxy.example:8080"}), ("proxy.example", 8080, {}))

    def test_the_upper_case_name_is_read_first(self):
        self.assertEqual(http._proxy("a.example", {"HTTPS_PROXY": "http://up:1", "https_proxy": "http://low:2"})[0], "up")

    def test_the_proxy_s_own_credentials_go_to_the_proxy_as_basic(self):
        host, port, headers = http._proxy("a.example", {"https_proxy": "http://user:p%40ss@proxy.example:3128"})
        self.assertEqual((host, port), ("proxy.example", 3128))
        self.assertEqual(headers, {"Proxy-Authorization": "Basic dXNlcjpwQHNz"})
        self.assertEqual(http._proxy("a.example", {"https_proxy": "http://user@proxy.example"})[2],
                         {"Proxy-Authorization": "Basic dXNlcjo="})

    def test_no_proxy_names_the_hosts_that_are_not_proxied(self):
        env = {"https_proxy": "http://proxy.example:3128", "no_proxy": "github.com,.internal"}
        self.assertIsNone(http._proxy("api.github.com", env))
        self.assertIsNone(http._proxy("x.internal", env))
        self.assertIsNotNone(http._proxy("slack.com", env))
        self.assertIsNone(http._proxy("slack.com", {"https_proxy": "http://p:1", "NO_PROXY": "*"}))

    def test_a_proxy_that_is_not_an_http_proxy_is_an_error_and_not_a_request_with_none(self):
        for value in ("https://proxy.example:3128", "socks5://proxy.example:1080", "http://proxy.example:notaport", "http://proxy.example:99999",
                      "http://:3128"):
            with self.subTest(value), self.assertRaises(http.TransportError) as caught:
                http._proxy("a.example", {"https_proxy": value})
            self.assertEqual(caught.exception.kind, "proxy")


@unittest.skipUnless(vs.have_openssl(), "the stub provider needs the openssl command")
class StubCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stub = vs.ProviderStub()
        cls.addClassCleanup(cls.stub.close)

    def setUp(self):
        self.stub.reset()
        self.send = self.stub.transport()

    def seen(self):
        with self.stub.lock:
            return list(self.stub.requests)


class RequestTests(StubCase):
    def test_a_request_goes_as_it_is_asked(self):
        self.stub.script["api.github.com", "/user"] = vs.Answer(200, b'{"login": "octocat"}', {"X-Thing": "one"})
        got = self.send(GOOD, 5, 1000)
        self.assertEqual((got.status, got.body, got.truncated), (200, b'{"login": "octocat"}', False))
        self.assertEqual(got.headers["x-thing"], "one")
        (seen,) = self.seen()
        self.assertEqual((seen.method, seen.host, seen.path), ("GET", "api.github.com", "/user"))
        self.assertEqual(seen.headers["authorization"], "Bearer abc")
        self.assertEqual(seen.headers["user-agent"], http.USER_AGENT)
        self.assertEqual(seen.headers["accept-encoding"], "identity")
        self.assertEqual(seen.body, b"")

    def test_a_post_sends_its_body(self):
        self.stub.script["sts.amazonaws.com"] = vs.Answer(200, b"<ok/>")
        got = self.send(http.Request("POST", "sts.amazonaws.com", "/", {"Content-Type": "application/x-www-form-urlencoded"}, b"Action=X"), 5, 1000)
        self.assertEqual(got.status, 200)
        (seen,) = self.seen()
        self.assertEqual((seen.method, seen.body, seen.headers["content-length"]), ("POST", b"Action=X", "8"))

    @unittest.skipUnless(_native.available(), "the requests are the engine's")
    def test_each_provider_s_request_arrives_as_it_was_made(self):
        from lazaret.scanner import secretverify as sv
        now = datetime.datetime(2026, 10, 3, 12, 0)
        for pid, credential in SAMPLES.items():
            with self.subTest(pid):
                self.stub.reset()
                req = sv.build_request(sv._by_id()[pid], credential if isinstance(credential, dict) else {"secret": credential}, now)
                self.stub.script[req.host] = vs.Answer(200, b"{}")
                self.assertEqual(self.send(req, 5, 1000).status, 200)
                (seen,) = self.seen()
                self.assertEqual((seen.method, seen.host, seen.path, seen.body), (req.method, req.host, req.path, req.body or b""))
                for name, value in req.headers.items():                     # (each field once, as it was made)
                    self.assertEqual([v for n, v in seen.raw if n.lower() == name.lower()], [value], name)
                self.assertTrue(req.secret_headers)
                parts = list(credential.values()) if isinstance(credential, dict) else [credential]
                for name, value in seen.raw:                                # (the credential in its own fields alone)
                    if name.lower() not in {n.lower() for n in req.secret_headers}:
                        self.assertFalse(any(part in value for part in parts), name)

    @unittest.skipUnless(_native.available(), "the request is the engine's")
    def test_aws_s_signature_holds_over_the_request_the_provider_receives(self):
        from lazaret.scanner import secretverify as sv
        pair = SAMPLES["aws"]
        req = sv.build_request(sv._by_id()["aws"], pair, datetime.datetime(2026, 10, 3, 12, 0))
        self.stub.script["sts.amazonaws.com"] = vs.Answer(200, b"<ok/>")
        self.assertEqual(self.send(req, 5, 1000).status, 200)
        (seen,) = self.seen()
        self.assertTrue(sigv4_holds(seen, pair["secret"]))
        self.assertFalse(sigv4_holds(seen._replace(body=seen.body + b"&x=1"), pair["secret"]))     # (the check can fail)
        self.assertNotIn(pair["secret"], repr(seen))                                              # (the key itself never goes)

    def test_a_request_s_own_user_agent_replaces_the_default(self):
        self.stub.script["slack.com"] = vs.Answer(200, b"{}")
        self.send(request(host="slack.com", path="/api/auth.test", headers={"User-Agent": "mine"}), 5, 1000)
        self.assertEqual(self.seen()[0].headers["user-agent"], "mine")

    def test_the_query_stays_in_the_path(self):
        self.stub.script["api.github.com", "/user"] = vs.Answer(200, b"{}")
        self.send(request(path="/user?a=1&b=%20"), 5, 1000)
        self.assertEqual(self.seen()[0].path, "/user?a=1&b=%20")

    def test_an_error_status_is_an_answer_and_not_an_error(self):
        for status in (400, 401, 403, 404, 429, 500, 503):
            with self.subTest(status):
                self.stub.script["api.github.com"] = vs.Answer(status, b"no")
                self.assertEqual(self.send(GOOD, 5, 1000).status, status)

    def test_a_refused_request_is_not_sent(self):
        with self.assertRaises(http.TransportError) as caught:
            self.send(request(host="127.0.0.1"), 5, 1000)
        self.assertEqual(caught.exception.kind, "refused")          # (refused by the transport itself, before any connection)
        self.assertEqual(self.seen(), [])

    def test_a_request_that_asks_for_no_room_for_an_answer_is_refused(self):
        for room in (0, -1, 1.5, None, "5"):
            with self.subTest(room), self.assertRaises(http.TransportError) as caught:
                self.send(GOOD, 5, room)
            self.assertEqual(caught.exception.kind, "refused")
        self.assertEqual(self.seen(), [])

    def test_room_for_one_byte_is_room(self):
        self.stub.script["api.github.com"] = vs.Answer(200, b"yz")
        got = self.send(GOOD, 5, 1)
        self.assertEqual((got.body, got.truncated), (b"y", True))

class UrllibTests(StubCase):
    """What only urllib's transport has: its connection, its watchdog."""

    def test_a_request_the_connection_cannot_form_is_refused(self):
        with mock.patch.object(HTTPSConnection, "request", side_effect=ValueError("bad")):
            with self.assertRaises(http.TransportError) as caught:
                self.send(GOOD, 5, 1000)
        self.assertEqual(caught.exception.kind, "refused")

    def test_the_connection_is_closed_when_the_answer_is_not_one(self):
        closed, original = [], http._Connection.close

        def spy(conn):
            closed.append(conn)
            original(conn)

        self.stub.script["api.github.com"] = vs.Answer(200, b"{}", delay=1.5)           # (an answer that does not come: the connection is not
        with mock.patch.object(http._Connection, "close", spy), self.assertRaises(http.TransportError):    # closed by anything but the guard)
            self.send(GOOD, 0.3, 1000)
        self.assertGreaterEqual(len(closed), 1)

    def test_nothing_is_left_waiting_after_an_answer(self):
        made = []

        class Spy(threading.Timer):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                made.append(self)

        self.stub.script["api.github.com"] = vs.Answer(200, b"{}")
        with mock.patch.object(threading, "Timer", Spy):
            self.send(GOOD, 30, 1000)                                    # (its limit of 30 seconds is not left running)
        (timer,) = made
        timer.join(3)
        self.assertFalse(timer.is_alive())


class RedirectTests(StubCase):
    def test_a_redirect_is_an_error_and_never_followed(self):
        self.stub.script["api.github.com", "/user"] = vs.Answer(302, b"", {"Location": "https://slack.com/steal"})
        self.stub.script["slack.com"] = vs.Answer(200, b"stolen")
        with self.assertRaises(http.TransportError) as caught:
            self.send(GOOD, 5, 1000)
        self.assertEqual(caught.exception.kind, "redirect")
        self.assertEqual([(s.host, s.path) for s in self.seen()], [("api.github.com", "/user")])

    def test_every_redirect_status_is_the_same(self):
        for status in http.REDIRECTS:
            with self.subTest(status):
                self.stub.reset()
                self.stub.script["api.github.com"] = vs.Answer(status, b"", {"Location": "/elsewhere"})
                with self.assertRaises(http.TransportError) as caught:
                    self.send(GOOD, 5, 1000)
                self.assertEqual(caught.exception.kind, "redirect")
                self.assertEqual(len(self.seen()), 1)

    def test_a_status_that_does_not_redirect_is_an_answer_whatever_it_names(self):
        for status, headers in ((302, {}), (300, {"Location": "/elsewhere"}), (304, {"Location": "/elsewhere"})):
            with self.subTest(status):
                self.stub.reset()
                self.stub.script["api.github.com"] = vs.Answer(status, b"", headers)
                self.assertEqual(self.send(GOOD, 5, 1000).status, status)
                self.assertEqual(len(self.seen()), 1)


class SizeTests(StubCase):
    def test_a_body_is_read_to_the_limit_and_no_further(self):
        self.stub.script["api.github.com"] = vs.Answer(200, huge=200_000)
        got = self.send(GOOD, 5, 1000)
        self.assertEqual((len(got.body), got.truncated), (1000, True))

    def test_the_limit_is_exact(self):
        for size, truncated in ((999, False), (1000, False), (1001, True)):
            with self.subTest(size):
                self.stub.script["api.github.com"] = vs.Answer(200, b"y" * size)
                got = self.send(GOOD, 5, 1000)
                self.assertEqual((len(got.body), got.truncated), (min(size, 1000), truncated))

    def test_what_is_read_is_the_bytes_the_server_sent(self):
        body = bytes(range(256)) * 4
        self.stub.script["api.github.com"] = vs.Answer(200, body)
        self.assertEqual(self.send(GOOD, 5, 5000).body, body)

    def test_headers_are_lower_case_bounded_and_the_first_of_a_name_wins(self):
        self.stub.script["api.github.com"] = vs.Answer(200, b"{}", {"X-Long": "v" * 2000, "Retry-After": "7"})
        got = self.send(GOOD, 5, 1000)
        self.assertEqual(got.headers["retry-after"], "7")
        self.assertEqual(len(got.headers["x-long"]), http.MAX_HEADER_VALUE)
        self.assertTrue(all(name == name.lower() for name in got.headers))


class TimeTests(StubCase):
    def test_a_server_that_answers_too_late_is_a_timeout(self):
        self.stub.script["api.github.com"] = vs.Answer(200, b"{}", delay=3)
        started = time.monotonic()
        with self.assertRaises(http.TransportError) as caught:
            self.send(GOOD, 0.5, 1000)
        self.assertEqual(caught.exception.kind, "timeout")
        self.assertLess(time.monotonic() - started, 2.5)

    def test_a_server_that_answers_a_byte_at_a_time_is_stopped_at_the_deadline(self):
        self.stub.script["api.github.com"] = vs.Answer(200, b"y" * 200, drip=0.1)
        started = time.monotonic()
        with self.assertRaises(http.TransportError) as caught:
            self.send(GOOD, 1.0, 1000)
        self.assertEqual(caught.exception.kind, "timeout")
        self.assertLess(time.monotonic() - started, 3.0)

    def test_a_server_that_goes_quiet_in_the_middle_is_cut_off_at_the_deadline(self):
        # the first of its bytes comes at 0.7 s of 1.0: a read that waited its own full second would end at 1.7
        self.stub.script["api.github.com"] = vs.Answer(200, b"y" * 50, delay=0.7, pause=(1, 5.0))
        started = time.monotonic()
        with self.assertRaises(http.TransportError) as caught:
            self.send(GOOD, 1.0, 1000)
        self.assertEqual(caught.exception.kind, "timeout")
        self.assertLess(time.monotonic() - started, 1.45)

    def test_an_answer_cut_short_is_not_an_answer(self):
        self.stub.script["api.github.com"] = vs.Answer(200, b'{"login": "x"', claim=100)
        with self.assertRaises(http.TransportError) as caught:
            self.send(GOOD, 5, 1000)
        self.assertEqual(caught.exception.kind, "connection")

    def test_a_server_that_hangs_up_is_a_connection_error(self):
        self.stub.script["api.github.com"] = vs.Answer(close=True)
        with self.assertRaises(http.TransportError) as caught:
            self.send(GOOD, 5, 1000)
        self.assertEqual(caught.exception.kind, "connection")


class ConnectionTests(StubCase):
    def test_a_certificate_that_is_not_trusted_is_a_tls_error(self):
        send = http.https_transport(None, self.stub.address, {})                    # (the default trust: the stub's certificate is not in it)
        with self.assertRaises(http.TransportError) as caught:
            send(GOOD, 5, 1000)
        self.assertEqual(caught.exception.kind, "tls")
        self.assertEqual(self.seen(), [])                                          # (nothing was sent: the handshake failed first)

    def test_a_certificate_for_another_host_is_a_tls_error(self):
        send = self.stub.transport()
        with self.assertRaises(http.TransportError) as caught:
            send(request(host="not-in-the-certificate.example"), 5, 1000)
        self.assertEqual(caught.exception.kind, "tls")
        self.assertEqual(self.seen(), [])

    def test_a_port_nobody_listens_on_is_a_connection_error(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        send = http.https_transport(self.stub.client_context(), ("127.0.0.1", port), {})
        with self.assertRaises(http.TransportError) as caught:
            send(GOOD, 2, 1000)
        self.assertEqual(caught.exception.kind, "connection")

    def test_a_plain_http_server_where_https_is_expected_is_not_an_answer(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            send = http.https_transport(self.stub.client_context(), server.getsockname(), {})
            with self.assertRaises(http.TransportError) as caught:
                send(GOOD, 1, 1000)
        self.assertIn(caught.exception.kind, ("timeout", "tls", "connection"))

    def test_what_an_error_says_holds_no_secret(self):
        secret = "ghp_" + "s" * 36
        send = http.https_transport(None, self.stub.address, {})
        with self.assertRaises(http.TransportError) as caught:
            send(request(headers={"Authorization": "Bearer " + secret}), 5, 1000)
        self.assertNotIn(secret, str(caught.exception))

    def test_without_an_address_of_its_own_the_connection_is_the_standard_one(self):
        calls = []
        with mock.patch.object(HTTPSConnection, "connect", lambda conn: calls.append(conn)):
            conn = http._Connection("api.github.com", 1, ssl.create_default_context(), None)
            conn.connect()
        self.assertEqual(calls, [conn])


class ProxyTests(StubCase):
    def through(self, proxy, environ_extra=None):
        env = {"https_proxy": f"http://{proxy.address[0]}:{proxy.address[1]}", **(environ_extra or {})}
        return self.stub.transport(env, direct=False)

    def test_a_request_goes_through_a_connect_tunnel_and_the_proxy_sees_only_the_host(self):
        proxy = self.stub.proxy()
        self.stub.script["api.github.com", "/user"] = vs.Answer(200, b'{"login": "x"}')
        got = self.through(proxy)(request(headers={"Authorization": "Bearer sekrit-token-value"}), 5, 1000)
        self.assertEqual(got.status, 200)
        (line, headers) = proxy.requests[0]
        self.assertRegex(line, r"^CONNECT api\.github\.com:443 HTTP/1\.[01]$")                  # (3.10 says 1.0, 3.12 says 1.1)
        self.assertNotIn("authorization", headers)
        self.assertNotIn("sekrit-token-value", repr(proxy.requests))
        self.assertEqual(self.seen()[0].headers["authorization"], "Bearer sekrit-token-value")

    def test_the_proxy_s_credentials_go_to_the_proxy(self):
        proxy = self.stub.proxy(require="Basic dXNlcjpwYXNz")
        self.stub.script["api.github.com"] = vs.Answer(200, b"{}")
        env = {"https_proxy": f"http://user:pass@{proxy.address[0]}:{proxy.address[1]}"}
        self.assertEqual(self.stub.transport(env, direct=False)(GOOD, 5, 1000).status, 200)
        self.assertEqual(proxy.requests[0][1]["proxy-authorization"], "Basic dXNlcjpwYXNz")
        self.assertNotIn("proxy-authorization", self.seen()[0].headers)                  # (not passed on to the provider)

    def test_the_proxy_settings_are_the_process_s_unless_they_are_given(self):
        proxy = self.stub.proxy()
        url = f"http://{proxy.address[0]}:{proxy.address[1]}"
        self.stub.script["api.github.com", "/user"] = vs.Answer(200, b"{}")
        env = {"HTTPS_PROXY": url, "https_proxy": url, "NO_PROXY": "", "no_proxy": ""}
        with mock.patch.dict(os.environ, env):
            got = http.https_transport(self.stub.client_context())(GOOD, 5, 1000)         # (no settings given, no address of its own)
        self.assertEqual(got.status, 200)
        self.assertEqual(len(proxy.requests), 1)

    def test_an_address_of_its_own_is_not_proxied(self):
        proxy = self.stub.proxy()
        proxy.refuse = True
        self.stub.script["api.github.com"] = vs.Answer(200, b"{}")
        env = {"https_proxy": f"http://{proxy.address[0]}:{proxy.address[1]}"}
        got = http.https_transport(self.stub.client_context(), self.stub.address, env)(GOOD, 5, 1000)
        self.assertEqual(got.status, 200)
        self.assertEqual(proxy.requests, [])

    def test_a_proxy_that_wants_credentials_the_request_has_not_is_a_proxy_error(self):
        proxy = self.stub.proxy(require="Basic dXNlcjpwYXNz")
        with self.assertRaises(http.TransportError) as caught:
            self.through(proxy)(GOOD, 5, 1000)
        self.assertEqual(caught.exception.kind, "proxy")
        self.assertEqual(self.seen(), [])

    def test_a_proxy_that_refuses_is_a_proxy_error(self):
        proxy = self.stub.proxy()
        proxy.refuse = True
        with self.assertRaises(http.TransportError) as caught:
            self.through(proxy)(GOOD, 5, 1000)
        self.assertEqual(caught.exception.kind, "proxy")

    def test_a_proxy_that_is_down_is_a_proxy_error(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with self.assertRaises(http.TransportError) as caught:
            self.stub.transport({"https_proxy": f"http://127.0.0.1:{port}"}, direct=False)(GOOD, 2, 1000)
        self.assertEqual(caught.exception.kind, "proxy")

    def test_an_https_proxy_is_refused_and_the_request_is_not_sent_without_it(self):
        with self.assertRaises(http.TransportError) as caught:
            self.stub.transport({"https_proxy": "https://proxy.example:3128"}, direct=False)(GOOD, 2, 1000)
        self.assertEqual(caught.exception.kind, "proxy")
        self.assertEqual(self.seen(), [])


class Native(vs.OverLazaretNet):
    """The same tests on lazaret-net's transport, which reaches the stub through its CONNECT proxy, with the stub's root as its
    trust anchor (put back when the class ends)."""

    def setUp(self):
        super().setUp()
        self.send = self.stub.native()


class NativeRequestTests(Native, RequestTests):
    def test_the_credential_goes_as_a_credential_and_nothing_else_does(self):
        self.stub.script["api.anthropic.com"] = vs.Answer(200, b"{}")
        req = http.Request("GET", "api.anthropic.com", "/v1/models", {"x-api-key": "sk-ant-x", "anthropic-version": "2023-06-01"},
                           None, ("x-api-key",))
        self.assertEqual(self.send(req, 5, 1000).status, 200)
        self.assertEqual(self.seen()[0].headers["x-api-key"], "sk-ant-x")
        # (a field lazaret-net would carry on to any hop, and that is not said to carry the credential, is refused)
        for headers, secret in (({"x-api-key": "sk-ant-x"}, ()), ({"Authorization": "Bearer abc"}, ())):
            with self.subTest(headers), self.assertRaises(http.TransportError) as caught:
                self.send(http.Request("GET", "api.anthropic.com", "/v1/models", headers, None, secret), 5, 1000)
            self.assertEqual(caught.exception.kind, "refused")
            self.assertNotIn("sk-ant-x", str(caught.exception))
        self.assertEqual(len(self.seen()), 1)


class NativeRedirectTests(Native, RedirectTests):
    pass


class NativeSizeTests(Native, SizeTests):
    def test_an_answer_that_declares_more_than_it_may_be_read_is_cut_not_refused(self):
        # (lazaret-net fails a request whose answer declares more than its budget before its status is known)
        self.stub.script["api.github.com"] = vs.Answer(401, huge=3 * 1024 * 1024)
        got = self.send(GOOD, 5, 1000)
        self.assertEqual((got.status, len(got.body), got.truncated), (401, 1000, True))


class NativeTimeTests(Native, TimeTests):
    pass


class NativeConnectionTests(Native, StubCase):
    def test_a_certificate_that_is_not_trusted_is_a_tls_error(self):
        nativenet.configure_roots(None)                                 # (the system's anchors: the stub's root is not one)
        try:
            with self.assertRaises(http.TransportError) as caught:
                self.send(request(headers={"Authorization": "Bearer ghp_sekrit"}), 5, 1000)
        finally:
            nativenet.configure_roots(self.stub.root)
        self.assertEqual(caught.exception.kind, "tls")
        self.assertNotIn("ghp_sekrit", str(caught.exception))
        self.assertEqual(self.seen(), [])

    def test_a_certificate_for_another_host_is_a_tls_error(self):
        with self.assertRaises(http.TransportError) as caught:
            self.send(request(host="not-in-the-certificate.example"), 5, 1000)
        self.assertEqual(caught.exception.kind, "tls")
        self.assertEqual(self.seen(), [])


class NativeProxyTests(Native, StubCase):
    def test_a_request_goes_through_a_connect_tunnel_and_the_proxy_sees_only_the_host(self):
        proxy = self.stub.proxy()
        self.stub.script["api.github.com", "/user"] = vs.Answer(200, b'{"login": "x"}')
        got = self.stub.native(proxy)(request(headers={"Authorization": "Bearer sekrit-token-value"}), 5, 1000)
        self.assertEqual(got.status, 200)
        (line, headers) = proxy.requests[0]
        self.assertEqual(line, "CONNECT api.github.com:443 HTTP/1.1")
        self.assertNotIn("authorization", headers)
        self.assertNotIn("sekrit-token-value", repr(proxy.requests))
        self.assertEqual(self.seen()[0].headers["authorization"], "Bearer sekrit-token-value")

    def test_the_proxy_s_credentials_go_to_the_proxy(self):
        proxy = self.stub.proxy(require="Basic dXNlcjpwYXNz")
        self.stub.script["api.github.com"] = vs.Answer(200, b"{}")
        self.assertEqual(self.stub.native(proxy, "user:pass")(GOOD, 5, 1000).status, 200)
        self.assertEqual(proxy.requests[0][1]["proxy-authorization"], "Basic dXNlcjpwYXNz")
        self.assertNotIn("proxy-authorization", self.seen()[0].headers)

    def test_a_proxy_that_refuses_or_wants_credentials_the_request_has_not_is_a_proxy_error(self):
        refusing = self.stub.proxy()
        refusing.refuse = True
        for proxy in (self.stub.proxy(require="Basic dXNlcjpwYXNz"), refusing):
            with self.subTest(proxy.require), self.assertRaises(http.TransportError) as caught:
                self.stub.native(proxy)(GOOD, 5, 1000)
            self.assertEqual(caught.exception.kind, "proxy")
        self.assertEqual(self.seen(), [])


class DefaultTransportTests(unittest.TestCase):
    def test_lazaret_net_s_transport_sends_and_urllib_s_takes_what_it_will_not(self):
        calls = []

        def native(req, timeout, max_bytes):
            calls.append("native")
            if req.host == "slack.com":
                raise nativenet.UsePython("a proxy reached over TLS")
            return http.Response(200, {}, b"", False)

        def python(req, timeout, max_bytes):
            calls.append("python")
            return http.Response(201, {}, b"", False)

        with mock.patch.object(http, "native_transport", return_value=native), mock.patch.object(http, "https_transport", return_value=python):
            send = http.default_transport()
        self.assertEqual(send(GOOD, 5, 100).status, 200)
        self.assertEqual(send(request(host="slack.com"), 5, 100).status, 201)
        self.assertEqual(calls, ["native", "native", "python"])

    def test_LAZARET_NETWORK_python_asks_for_urllib_s(self):
        python = mock.Mock(return_value=http.Response(204, {}, b"", False))
        with mock.patch.dict(os.environ, {nativenet.ENV: "python"}), mock.patch.object(http, "https_transport", return_value=python):
            self.assertEqual(http.default_transport()(GOOD, 2, 1000).status, 204)
        python.assert_called_once()

    def test_an_https_proxy_is_refused_and_the_request_is_not_sent_without_it(self):
        env = dict(NO_PROXY_ENV, https_proxy="https://proxy.example:3128", HTTPS_PROXY="https://proxy.example:3128")
        env.pop(nativenet.ENV, None)
        with mock.patch.dict(os.environ, env, clear=True), self.assertRaises(http.TransportError) as caught:
            http.default_transport()(GOOD, 2, 1000)
        self.assertEqual(caught.exception.kind, "proxy")

    def test_what_lazaret_net_says_is_one_of_the_transport_s_kinds_and_holds_none_of_its_message(self):
        for kind, message, expected in (("timeout", "read timed out at api.github.com", "timeout"),
                                        ("tls", "certificate: unknown issuer for api.github.com", "tls"),
                                        ("http", "too many redirects (limit 0)", "redirect"),
                                        ("http", "proxy refused CONNECT: HTTP/1.1 407", "proxy"),
                                        ("http", "connection closed before the body ended", "connection"),
                                        ("network", "Connection refused (os error 111)", "connection"),
                                        ("too-large", "the response is larger than the budget", "connection"),
                                        ("refused", "request refused: host not allowed", "refused"),
                                        ("setup", "header \"X\" is not one a request sets", "refused")):
            with self.subTest(kind, message=message):
                error = http._native_error(nativenet.NetError(kind, message))
                self.assertEqual(error.kind, expected)
                self.assertNotIn(message, str(error))


if __name__ == "__main__":
    unittest.main()
