"""Live secret verification (scanner/secretverify.py and its provider table): what is asked of whom, how an answer is read, and what
is promised about the credential. No call reaches a real service: a stand-in transport answers, and the last class asks a stub
provider over TLS on 127.0.0.1 (skipped without `openssl`)."""

import copy
import datetime
import json
import re
import threading
import unittest

from lazaret.scanner import secretverify as sv
from lazaret.scanner import secretverify_http as http
from lazaret.scanner import secretverify_providers as data
from tests.scanner import _verify_stub as vs

NOW = datetime.datetime(2026, 10, 3, 12, 0, 0, tzinfo=datetime.timezone.utc)
SECRETS = {
    "github": "ghp_" + "a1B2" * 9,
    "slack": "xoxb-1234567890-abcdefghij",
    "stripe": "sk_live_" + "a1" * 12,
    "npm": "npm_" + "A1b2" * 9,
    "openai": "sk-proj-" + "a1" * 20,
    "anthropic": "sk-ant-api03-" + "Ab1_" * 10,
    "aws": {"id": "AKIAABCDEFGHIJKLMNOP", "secret": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"},
}
AWS_LIVE = (b'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>'
            b"<Arn>arn:aws:iam::123456789012:user/alice</Arn><UserId>AIDAEXAMPLE</UserId><Account>123456789012</Account>"
            b"</GetCallerIdentityResult></GetCallerIdentityResponse>")


def aws_error(code):
    return (f'<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>{code}</Code>'
            f"<Message>text</Message></Error><RequestId>x</RequestId></ErrorResponse>").encode()


def resp(status, body=b"", truncated=False, headers=None):
    return http.Response(status, headers or {}, body if isinstance(body, bytes) else json.dumps(body).encode(), truncated)


def entry(pid):
    return next(p for p in sv.PROVIDERS if p["id"] == pid)


class Fake:
    """A transport that answers from a table of host -> Response, a callable or an exception, and keeps what it was asked."""

    def __init__(self, answers=None, default=None):
        self.answers, self.default, self.calls = answers or {}, default, []
        self.lock = threading.Lock()

    def __call__(self, request, timeout, max_bytes):
        with self.lock:
            self.calls.append((request, timeout, max_bytes))
        answer = self.answers.get(request.host, self.default)
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer(request)
        return answer if answer is not None else resp(404)

    @property
    def requests(self):
        return [c[0] for c in self.calls]


def verifier(fake=None, **kw):
    return sv.Verifier(fake or Fake(default=resp(200)), now=lambda: NOW, **kw)


# ------------------------------------------------------------------------------------------------ the table

class TableTests(unittest.TestCase):
    def test_the_shipped_table_is_valid_and_every_provider_has_a_sample(self):
        self.assertEqual(sv.validate(data.PROVIDERS), tuple(data.PROVIDERS))
        self.assertEqual(sv.provider_ids(), ["github", "slack", "stripe", "npm", "openai", "anthropic", "aws"])
        self.assertEqual(set(SECRETS), set(sv.provider_ids()))

    def test_provider_info_says_where_a_credential_would_go(self):
        info = dict((pid, (label, host)) for pid, label, host in sv.provider_info())
        self.assertEqual(info["github"], ("GitHub token", "api.github.com"))
        self.assertEqual(info["aws"], ("AWS access key", "sts.amazonaws.com"))
        self.assertEqual(len(info), 7)

    def test_every_host_is_a_name_the_transport_will_send_to_and_no_credential_part_is_in_a_path_or_a_query(self):
        for p in sv.PROVIDERS:
            with self.subTest(p["id"]):
                self.assertTrue(http.HOST_RE.fullmatch(p["host"]))
                self.assertNotIn("{", p["request"]["path"])
                self.assertEqual(p["request"]["query"], {})
                http.check_request(http.Request(p["request"]["method"], p["host"], p["request"]["path"], {}, None))

    def test_the_hosts_are_the_providers_own_and_https_only_by_construction(self):
        self.assertEqual({p["id"]: p["host"] for p in sv.PROVIDERS},
                         {"github": "api.github.com", "slack": "slack.com", "stripe": "api.stripe.com", "npm": "registry.npmjs.org",
                          "openai": "api.openai.com", "anthropic": "api.anthropic.com", "aws": "sts.amazonaws.com"})

    def test_every_request_only_authenticates(self):
        for p in sv.PROVIDERS:
            with self.subTest(p["id"]):
                method, path = p["request"]["method"], p["request"]["path"]
                if p["id"] == "aws":
                    self.assertEqual((method, p["request"]["body"]), ("POST", "Action=GetCallerIdentity&Version=2011-06-15"))
                else:
                    self.assertEqual(method, "GET")
                self.assertIn(path, ("/user", "/api/auth.test", "/v1/balance", "/-/whoami", "/v1/models", "/"))


class IdentifyTests(unittest.TestCase):
    def test_each_sample_names_its_provider_alone(self):
        for pid, secret in SECRETS.items():
            if isinstance(secret, str):
                with self.subTest(pid):
                    self.assertEqual(sv.identify(secret), [pid])

    def test_a_pair_is_not_named_by_a_part(self):
        self.assertEqual(sv.identify(SECRETS["aws"]["id"]), [])
        self.assertEqual(sv.identify(SECRETS["aws"]["secret"]), [])

    def test_the_two_sk_families_do_not_overlap(self):
        self.assertEqual(sv.identify("sk-ant-" + "a" * 30), ["anthropic"])
        self.assertEqual(sv.identify("sk-" + "a" * 30), ["openai"])
        self.assertEqual(sv.identify("sk-proj-" + "a" * 30), ["openai"])
        self.assertEqual(sv.identify("sk-svcacct-" + "a" * 30), ["openai"])
        self.assertEqual(sv.identify("sk-ant" + "a" * 30), ["openai"])            # (no dash after ant: not Anthropic's)

    def test_the_lengths_are_the_formats(self):
        edge = [("ghp_", "a", 36, 251), ("gho_", "a", 36, 251), ("ghs_", "a", 36, 251), ("github_pat_", "a", 22, 255), ("xoxb-", "a", 10, 250),
                ("xoxp-", "1", 10, 250), ("sk_live_", "a", 16, 247), ("rk_live_", "a", 16, 247), ("npm_", "a", 36, 36),
                ("sk-", "a", 20, 200), ("sk-ant-", "a", 20, 200)]
        for prefix, ch, low, high in edge:
            with self.subTest(prefix):
                self.assertNotEqual(sv.identify(prefix + ch * low), [])
                self.assertNotEqual(sv.identify(prefix + ch * high), [])
                self.assertEqual(sv.identify(prefix + ch * (low - 1)), [])
                self.assertEqual(sv.identify(prefix + ch * (high + 1)), [])

    def test_what_is_not_a_credential_is_none(self):
        good = SECRETS["github"]
        for text in (good + "\n", good + " ", " " + good, "\n" + good, good + "\r\nX-Evil: 1", good[:-1] + "é", good[:-1] + "١",
                     good[:-1] + "\x00", "", None, 5, b"ghp_", ["ghp_"], good.upper(), "xxx" + good, good + "x" * 600, "ghp_" + "a" * 600):
            with self.subTest(repr(text)[:30]):
                self.assertEqual(sv.identify(text), [])


class ValidateTests(unittest.TestCase):
    def table(self, pid, change):
        entries = copy.deepcopy(list(sv.PROVIDERS))
        target = next(e for e in entries if e["id"] == pid)
        change(target)
        return entries

    def refused(self, pid, change, text=""):
        with self.assertRaisesRegex(ValueError, text):
            sv.validate(self.table(pid, change))

    def test_a_good_table_with_a_changed_value_is_still_good(self):
        sv.validate(self.table("github", lambda e: e.update(label="Another label")))

    def test_ids(self):
        for bad in ("", "Git", "1git", "git hub", "g" * 33, None, 5):
            with self.subTest(bad):
                self.refused("github", lambda e, bad=bad: e.update(id=bad), "provider id")
        with self.assertRaisesRegex(ValueError, "repeated"):
            sv.validate(list(sv.PROVIDERS) + [sv.PROVIDERS[0]])
        with self.assertRaisesRegex(ValueError, "provider id"):
            sv.validate(["github"])

    def test_labels_and_parts(self):
        self.refused("github", lambda e: e.update(label=""), "label")
        self.refused("github", lambda e: e.update(label="x" * 61), "label")
        self.refused("github", lambda e: e.update(label=5), "label")
        sv.validate(self.table("github", lambda e: e.update(label="x" * 60)))
        self.refused("github", lambda e: e.update(parts={}), "parts")
        self.refused("github", lambda e: e.update(parts={"id": "a"}), "secret")
        self.refused("github", lambda e: e.update(parts={"secret": "(["}), "compile")
        self.refused("github", lambda e: e.update(parts={"secret": 5}), "part")
        self.refused("github", lambda e: e.update(parts={"Secret": "a", "secret": "a"}), "part")

    def test_the_host(self):
        for bad in ("API.github.com", "127.0.0.1", "localhost", "api.github.com:443", "", None, "a b.com", "api.github.com/x"):
            with self.subTest(bad):
                self.refused("github", lambda e, bad=bad: e.update(host=bad), "host")

    def test_the_request(self):
        self.refused("github", lambda e: e["request"].update(method="PUT"), "method")
        self.refused("github", lambda e: e["request"].update(method=None), "method")
        self.refused("github", lambda e: e.update(request=None), "method")
        for path in ("user", "/user/{secret}", "/a b", "", 5):
            with self.subTest(path):
                self.refused("github", lambda e, path=path: e["request"].update(path=path), "path")
        self.refused("github", lambda e: e["request"].update(query={"k": "{secret}"}), "query")
        self.refused("github", lambda e: e["request"].update(query={"{secret}": "v"}), "query")
        self.refused("github", lambda e: e["request"].update(query={"k": 5}), "query")
        sv.validate(self.table("github", lambda e: e["request"].update(query={"a": "b"})))

    def test_where_a_part_goes(self):
        self.refused("github", lambda e: e["request"]["headers"].update(Authorization="Bearer {nothing}"), "not one")
        self.refused("github", lambda e: e["request"].update(body="x={secret}"), "POST")
        self.refused("github", lambda e: e["request"].update(headers={"User-Agent": "x"}), "sent nowhere")
        self.refused("github", lambda e: e["request"]["headers"].update(X=5), "not text")
        self.refused("github", lambda e: e["request"].update(body=5, method="POST"), "not text")
        sv.validate(self.table("github", lambda e: e["request"].update(method="POST", body="token={secret}")))

    def test_a_signed_request_is_signed_with_a_pair_and_does_not_send_its_secret(self):
        self.refused("aws", lambda e: e["request"].update(sigv4={"service": "sts"}), "sigv4")
        self.refused("aws", lambda e: e["request"].update(sigv4={"service": "sts", "region": ""}), "sigv4")
        self.refused("aws", lambda e: e["request"].update(sigv4=[]), "sigv4")
        self.refused("aws", lambda e: e.update(parts={"secret": "a"}), "id and a secret")
        self.refused("aws", lambda e: e["request"]["headers"].update(X="{secret}"), "does not send")
        sv.validate(self.table("aws", lambda e: e["request"]["headers"].update(X="{id}")))

    def test_the_answers(self):
        self.refused("github", lambda e: e.update(answers=[]), "answers")
        self.refused("github", lambda e: e.update(answers="x"), "answers")
        self.refused("github", lambda e: e["answers"].append({"status": [200], "outcome": "maybe"}), "answer rule")
        self.refused("github", lambda e: e["answers"].append({"status": [200], "outcome": "live", "extra": 1}), "answer rule")
        self.refused("github", lambda e: e["answers"].append("x"), "answer rule")
        for status in ([], None, [99], [600], ["200"], [True], 200):
            with self.subTest(status):
                self.refused("github", lambda e, status=status: e["answers"].append({"status": status, "outcome": "live"}), "status")
        sv.validate(self.table("github", lambda e: e["answers"].append({"status": [100, 599], "outcome": "unknown"})))

    def test_the_conditions(self):
        for cond in ({}, [], {"": "x"}, {"a": 5}, {"a": []}, {"a": [1]}, {"a": None}, {5: "x"}):
            with self.subTest(cond):
                self.refused("slack", lambda e, cond=cond: e["answers"][0].update(json=cond), "json")
        for code in ([], "x", [""], [5]):
            with self.subTest(code):
                self.refused("aws", lambda e, code=code: e["answers"][1].update(code=code), "code")
        sv.validate(self.table("slack", lambda e: e["answers"][0].update(json={"a.b": ["x", True]})))

    def test_why_and_who(self):
        self.refused("github", lambda e: e["answers"][1].update(why="x" * 101), "why")
        self.refused("github", lambda e: e["answers"][1].update(why=5), "why")
        sv.validate(self.table("github", lambda e: e["answers"][1].update(why="x" * 100)))
        self.refused("github", lambda e: e["answers"][1].update(who={"json": "login"}), "who")
        self.refused("github", lambda e: e["answers"][0].update(who={"json": "a", "xml": "b"}), "who")
        self.refused("github", lambda e: e["answers"][0].update(who={"yaml": "a"}), "who")
        self.refused("github", lambda e: e["answers"][0].update(who="login"), "who")


# ------------------------------------------------------------------------------------------------ reading an answer

CASES = {
    "github": [
        (200, {"login": "octocat", "id": 1}, "live", "octocat"), (200, b"", "live", None), (200, b"not json", "live", None),
        (401, {"message": "Bad credentials"}, "rejected", None), (403, {"message": "rate limit"}, "unknown", None),
        (429, b"", "unknown", None), (404, b"", "unknown", None), (500, b"", "unknown", None), (302, b"", "unknown", None),
        (200, {"login": 5}, "live", None), (200, {"login": ""}, "live", None), (200, [1], "live", None),
    ],
    "slack": [
        (200, {"ok": True, "user": "bot", "team": "t"}, "live", "bot"), (200, {"ok": True}, "live", None),
        (200, {"ok": False, "error": "invalid_auth"}, "rejected", None), (200, {"ok": False, "error": "token_revoked"}, "rejected", None),
        (200, {"ok": False, "error": "not_authed"}, "rejected", None), (200, {"ok": False, "error": "token_expired"}, "rejected", None),
        (200, {"ok": False, "error": "account_inactive"}, "rejected", None), (200, {"ok": False, "error": "ratelimited"}, "unknown", None),
        (200, {"ok": False, "error": "fatal_error"}, "unknown", None), (200, {"ok": False}, "unknown", None),
        (200, {"ok": "true"}, "unknown", None), (200, {"ok": 1}, "unknown", None), (200, {"ok": None}, "unknown", None),
        (200, b"", "unknown", None), (200, [1], "unknown", None), (200, b"<html>", "unknown", None), (429, b"", "unknown", None),
        (401, {"ok": False, "error": "invalid_auth"}, "unknown", None), (500, b"", "unknown", None),
    ],
    "stripe": [
        (200, {"object": "balance"}, "live", None), (401, {"error": {"type": "invalid_request_error"}}, "rejected", None),
        (403, {"error": {"type": "permission_error"}}, "live", None), (403, {"error": {"type": "other"}}, "unknown", None),
        (403, b"", "unknown", None), (403, {"error": "permission_error"}, "unknown", None), (429, b"", "unknown", None),
        (500, b"", "unknown", None),
    ],
    "npm": [
        (200, {"username": "alice"}, "live", "alice"), (200, b"", "live", None), (401, {"error": "x"}, "rejected", None),
        (403, b"", "unknown", None), (429, b"", "unknown", None), (404, b"", "unknown", None),
    ],
    "openai": [
        (200, {"data": []}, "live", None), (401, {"error": {"code": "invalid_api_key"}}, "rejected", None), (403, b"", "unknown", None),
        (429, b"", "unknown", None), (503, b"", "unknown", None),
    ],
    "anthropic": [
        (200, {"data": []}, "live", None), (401, {"type": "error"}, "rejected", None), (403, b"", "unknown", None),
        (429, b"", "unknown", None), (529, b"", "unknown", None),
    ],
    "aws": [
        (200, AWS_LIVE, "live", "arn:aws:iam::123456789012:user/alice"), (200, b"<x/>", "live", None),
        (403, aws_error("InvalidClientTokenId"), "rejected", None), (403, aws_error("SignatureDoesNotMatch"), "rejected", None),
        (403, aws_error("ExpiredToken"), "rejected", None), (403, aws_error("AccessDenied"), "unknown", None),
        (403, b"", "unknown", None), (400, aws_error("Throttling"), "unknown", None), (400, aws_error("InvalidClientTokenId"), "unknown", None),
        (403, aws_error("Throttling"), "unknown", None), (503, aws_error("ServiceUnavailable"), "unknown", None),
        (429, aws_error("RequestLimitExceeded"), "unknown", None), (500, b"", "unknown", None),
    ],
}


class InterpretTests(unittest.TestCase):
    def test_what_each_provider_s_answer_means(self):
        for pid, cases in CASES.items():
            for status, body, outcome, who in cases:
                with self.subTest(pid=pid, status=status, body=str(body)[:50]):
                    got = sv.interpret(entry(pid), resp(status, body))
                    self.assertEqual((got[0], got[2]), (outcome, who))

    def test_every_provider_has_a_live_a_rejected_and_an_unknown_case(self):
        for pid, cases in CASES.items():
            self.assertEqual({c[2] for c in cases}, {"live", "rejected", "unknown"}, pid)

    def test_the_detail_is_the_rules_reason_or_the_status(self):
        self.assertEqual(sv.interpret(entry("github"), resp(401))[1], "GitHub says the token is not valid")
        self.assertEqual(sv.interpret(entry("github"), resp(200, {"login": "x"}))[1], "HTTP 200")
        self.assertEqual(sv.interpret(entry("stripe"), resp(403, {"error": {"type": "permission_error"}}))[1],
                         "Stripe knows the key but it may not read the balance")
        self.assertEqual(sv.interpret(entry("github"), resp(418))[1], "the answer was not one this module knows (HTTP 418)")
        self.assertEqual(sv.interpret(entry("github"), resp(502))[1], "the provider failed (HTTP 502)")
        self.assertEqual(sv.interpret(entry("github"), resp(599))[1], "the provider failed (HTTP 599)")
        self.assertEqual(sv.interpret(entry("github"), resp(499))[1], "the answer was not one this module knows (HTTP 499)")

    def test_an_answer_cut_short_is_read_by_its_status_only(self):
        slack = entry("slack")
        whole = json.dumps({"ok": True, "user": "bot"}).encode()
        self.assertEqual(sv.interpret(slack, resp(200, whole))[0], "live")
        self.assertEqual(sv.interpret(slack, resp(200, whole, truncated=True))[0], "unknown")
        self.assertIn("larger than", sv.interpret(slack, resp(200, whole, truncated=True))[1])
        self.assertEqual(sv.interpret(entry("github"), resp(200, b'{"login": "x"}', truncated=True)), ("live", "HTTP 200", None))
        aws = entry("aws")
        self.assertEqual(sv.interpret(aws, resp(403, aws_error("InvalidClientTokenId"), truncated=True))[0], "unknown")
        self.assertEqual(sv.interpret(aws, resp(200, AWS_LIVE, truncated=True)), ("live", "HTTP 200", None))

    def test_the_first_rule_that_holds_decides(self):
        provider = {"answers": [{"status": [200], "json": {"a": "x"}, "outcome": "rejected"}, {"status": [200], "outcome": "live"},
                                {"status": [200], "outcome": "rejected"}]}
        self.assertEqual(sv.interpret(provider, resp(200, {"a": "x"}))[0], "rejected")
        self.assertEqual(sv.interpret(provider, resp(200, {"a": "y"}))[0], "live")

    def test_a_json_path_is_dotted_and_a_value_may_be_one_of_several(self):
        provider = {"answers": [{"status": [200], "json": {"a.b": ["x", "y"], "c": True}, "outcome": "live"}]}
        self.assertEqual(sv.interpret(provider, resp(200, {"a": {"b": "y"}, "c": True}))[0], "live")
        self.assertEqual(sv.interpret(provider, resp(200, {"a": {"b": "z"}, "c": True}))[0], "unknown")
        self.assertEqual(sv.interpret(provider, resp(200, {"a": {"b": "x"}, "c": 1}))[0], "unknown")
        self.assertEqual(sv.interpret(provider, resp(200, {"a": {"b": "x"}}))[0], "unknown")
        self.assertEqual(sv.interpret(provider, resp(200, {"a": "b", "c": True}))[0], "unknown")
        self.assertEqual(sv.interpret(provider, resp(200, {"a": ["b"], "c": True}))[0], "unknown")

    def test_a_who_is_text_that_is_safe_to_print(self):
        github = entry("github")
        self.assertEqual(sv.interpret(github, resp(200, {"login": "\x1b[31mred\nline‮"}))[2], "?[31mred?line?")
        self.assertEqual(sv.interpret(github, resp(200, {"login": "x" * 500}))[2], "x" * sv.MAX_WHO)
        self.assertEqual(sv.interpret(github, resp(200, {"login": "a b"}))[2], "a?b")
        self.assertEqual(sv.interpret(github, resp(200, {"login": "é ü"}))[2], "é ü")

    def test_a_credential_in_an_answer_is_not_echoed(self):
        secret = SECRETS["github"]
        got = sv.interpret(entry("github"), resp(200, {"login": f"user-{secret}-x"}), [secret])
        self.assertEqual(got[2], "user-[redacted]-x")
        self.assertNotIn(secret, repr(got))
        arn = b"<Arn>arn:aws:iam::1:user/" + SECRETS["aws"]["secret"].encode() + b"</Arn>"
        got = sv.interpret(entry("aws"), resp(200, arn), list(SECRETS["aws"].values()))
        self.assertNotIn(SECRETS["aws"]["secret"], repr(got))

    def test_hostile_answers_raise_nothing(self):
        bodies = [b"", b"\xff\xfe\x00", b"\x00" * 100, b"[" * 70_000, b"{" * 70_000, b'{"a":' * 30_000, b"[" * 5_000 + b"]" * 5_000, b"NaN", b"1e999999",
                  b'{"ok": NaN, "error": Infinity}', b"<" * 1000, b"<Code>" * 1000, b"<Arn>" + b"a" * 60_000, b"<Arn></Arn>", b"\xef\xbb\xbf{}",
                  b'{"login": "\\ud800"}', b'{"ok": true, "user": "\\u0000"}']
        for pid in sv.provider_ids():
            for status in (200, 401, 403, 429, 500, 302, 0, 99, 600, 999):
                for body in bodies:
                    for truncated in (False, True):
                        got = sv.interpret(entry(pid), resp(status, body, truncated))
                        self.assertIn(got[0], sv.OUTCOMES)
                        self.assertIsInstance(got[1], str)
                        self.assertTrue(got[2] is None or got[2].isprintable())

    def test_an_answer_of_the_wrong_kind_is_not_a_rule_s_condition(self):
        slack = entry("slack")
        for body in ([True], "ok", 5, None, [], {"ok": [True]}, {"ok": {"x": 1}}):
            with self.subTest(str(body)):
                self.assertEqual(sv.interpret(slack, resp(200, json.dumps(body).encode()))[0], "unknown")


# ------------------------------------------------------------------------------------------------ the requests

class RequestTests(unittest.TestCase):
    def build(self, pid, credential=None):
        credential = SECRETS[pid] if credential is None else credential
        v = verifier()
        parts = v._parts(entry(pid), credential)
        self.assertIsNotNone(parts)
        return sv.build_request(entry(pid), parts, NOW)

    def test_the_secret_goes_in_a_header(self):
        r = self.build("github")
        self.assertEqual((r.method, r.host, r.path, r.body), ("GET", "api.github.com", "/user", None))
        self.assertEqual(r.headers["Authorization"], "Bearer " + SECRETS["github"])
        self.assertEqual(r.headers["Accept"], "application/vnd.github+json")
        self.assertEqual(r.headers["User-Agent"], "lazaret-secret-verify")
        r = self.build("slack")
        self.assertEqual((r.method, r.host, r.path), ("GET", "slack.com", "/api/auth.test"))
        self.assertEqual(r.headers["Authorization"], "Bearer " + SECRETS["slack"])
        r = self.build("anthropic")
        self.assertEqual((r.host, r.path, r.headers["x-api-key"], r.headers["anthropic-version"]),
                         ("api.anthropic.com", "/v1/models", SECRETS["anthropic"], "2023-06-01"))
        self.assertNotIn("Authorization", r.headers)

    def test_no_request_holds_a_secret_in_its_host_or_path(self):
        for pid, secret in SECRETS.items():
            parts = [secret] if isinstance(secret, str) else list(secret.values())
            r = self.build(pid)
            for part in parts:
                self.assertNotIn(part, r.host + r.path, pid)

    def test_the_aws_request_is_signed_and_does_not_hold_the_secret_key(self):
        r = self.build("aws")
        self.assertEqual((r.method, r.host, r.path), ("POST", "sts.amazonaws.com", "/"))
        self.assertEqual(r.body, b"Action=GetCallerIdentity&Version=2011-06-15")
        self.assertEqual(r.headers["x-amz-date"], "20261003T120000Z")
        self.assertRegex(r.headers["authorization"], r"^AWS4-HMAC-SHA256 Credential=AKIAABCDEFGHIJKLMNOP/20261003/us-east-1/sts/aws4_request, "
                                                     r"SignedHeaders=accept;content-type;host;user-agent;x-amz-date, Signature=[0-9a-f]{64}$")
        self.assertNotIn(SECRETS["aws"]["secret"], repr(r))
        self.assertEqual(r.headers["Content-Type"], "application/x-www-form-urlencoded; charset=utf-8")
        self.assertIsNotNone(http.check_request(r))

    def test_every_request_is_one_the_transport_will_send(self):
        for pid in SECRETS:
            with self.subTest(pid):
                http.check_request(self.build(pid))

    def test_a_query_in_a_table_is_encoded_and_sorted(self):
        provider = copy.deepcopy(entry("github"))
        provider["request"]["query"] = {"b": "x y", "a": "é"}
        parts = {"secret": SECRETS["github"]}
        self.assertEqual(sv.build_request(provider, parts, NOW).path, "/user?a=%C3%A9&b=x%20y")


# ------------------------------------------------------------------------------------------------ the verifier

class VerifyTests(unittest.TestCase):
    def test_a_live_credential(self):
        fake = Fake({"api.github.com": resp(200, {"login": "octocat"})})
        got = verifier(fake).verify("github", SECRETS["github"])
        self.assertEqual(got, sv.Result("github", "live", "HTTP 200", "octocat", 200))
        (call,) = fake.calls
        self.assertEqual((call[0].host, call[1], call[2]), ("api.github.com", http.DEFAULT_TIMEOUT, http.MAX_ANSWER_BYTES))

    def test_a_rejected_credential(self):
        got = verifier(Fake(default=resp(401))).verify("github", SECRETS["github"])
        self.assertEqual((got.outcome, got.detail, got.who, got.status), ("rejected", "GitHub says the token is not valid", None, 401))

    def test_each_provider_with_its_own_credential(self):
        answers = {"api.github.com": resp(200, {"login": "a"}), "slack.com": resp(200, {"ok": True}), "api.stripe.com": resp(200, {}),
                   "registry.npmjs.org": resp(200, {"username": "n"}), "api.openai.com": resp(200, {}), "api.anthropic.com": resp(200, {}),
                   "sts.amazonaws.com": resp(200, AWS_LIVE)}
        fake = Fake(answers)
        v = verifier(fake)
        for pid, secret in SECRETS.items():
            with self.subTest(pid):
                self.assertEqual(v.verify(pid, secret).outcome, "live")
        self.assertEqual([r.host for r in fake.requests], [p["host"] for p in sv.PROVIDERS])

    def test_an_unknown_provider_is_an_error(self):
        with self.assertRaises(KeyError):
            verifier().verify("nonesuch", "x")

    def test_what_is_not_the_providers_format_is_not_sent(self):
        github = SECRETS["github"]
        bad = [github + "\n", github + "\r\nX-Evil: 1", "ghp_" + "a" * 35, "", None, 5, b"ghp_", [github], {"secret": github + "\n"},
               {"secret": github, "extra": "x"}, {"token": github}, {}, SECRETS["slack"], "Bearer " + github]
        fake = Fake(default=resp(200))
        v = verifier(fake)
        for credential in bad:
            with self.subTest(repr(credential)[:40]):
                got = v.verify("github", credential)
                self.assertEqual((got.outcome, got.status), ("unknown", None))
                self.assertIn("not this provider's format", got.detail)
        self.assertEqual(fake.calls, [])

    def test_a_pair_needs_both_parts_and_a_single_secret_is_not_a_pair(self):
        fake = Fake(default=resp(200, AWS_LIVE))
        v = verifier(fake)
        aws = SECRETS["aws"]
        for credential in (aws["id"], aws["secret"], {"id": aws["id"]}, {"secret": aws["secret"]}, {"id": aws["secret"], "secret": aws["id"]},
                           {"id": aws["id"], "secret": aws["secret"][:-1]}, {"id": aws["id"], "secret": aws["secret"], "token": "x"},
                           {"id": aws["id"], "secret": aws["secret"] + "\n"}):
            with self.subTest(repr(credential)[:50]):
                self.assertEqual(v.verify("aws", credential).outcome, "unknown")
        self.assertEqual(fake.calls, [])
        self.assertEqual(v.verify("aws", aws).outcome, "live")

    def test_a_credential_is_not_sent_to_another_provider(self):
        fake = Fake(default=resp(200))
        for pid in SECRETS:
            for other, secret in SECRETS.items():
                if other != pid:
                    self.assertEqual(verifier(fake).verify(pid, secret).outcome, "unknown", (pid, other))
        self.assertEqual(fake.calls, [])

    def test_a_failed_call_is_never_rejected(self):
        for kind, words in (("timeout", "did not answer in time"), ("connection", "could not be reached"), ("tls", "certificate"),
                            ("proxy", "proxy"), ("refused", "not allowed"), ("other", "call failed")):
            with self.subTest(kind):
                got = verifier(Fake(default=http.TransportError(kind, "detail"))).verify("github", SECRETS["github"])
                self.assertEqual((got.outcome, got.status, got.who), ("unknown", None, None))
                self.assertIn(words, got.detail)
                self.assertNotIn("detail", got.detail)

    def test_a_transport_that_fails_in_its_own_way_is_unknown_and_says_nothing_of_it(self):
        secret = SECRETS["github"]
        got = verifier(Fake(default=RuntimeError("boom " + secret))).verify("github", secret)
        self.assertEqual((got.outcome, got.detail), ("unknown", "the call failed unexpectedly (RuntimeError)"))
        self.assertNotIn(secret, repr(got))

    def test_nothing_returned_holds_the_credential(self):
        secret = SECRETS["github"]
        for answer in (resp(200, {"login": secret}), resp(401, {"message": secret}), resp(500, secret.encode()),
                       http.TransportError("tls", secret), RuntimeError(secret)):
            got = verifier(Fake(default=answer)).verify("github", secret)
            self.assertNotIn(secret, repr(got))

    def test_the_timeout_and_the_size_limit_are_passed_to_the_transport(self):
        fake = Fake(default=resp(200))
        verifier(fake, timeout=3.5).verify("github", SECRETS["github"])
        self.assertEqual((fake.calls[0][1], fake.calls[0][2]), (3.5, http.MAX_ANSWER_BYTES))

    def test_the_calls_are_listed_for_a_report(self):
        v = verifier(Fake(default=resp(200)))
        v.verify("github", SECRETS["github"])
        v.verify("npm", SECRETS["npm"])
        self.assertEqual(v.requests, [("github", "api.github.com", "/user"), ("npm", "registry.npmjs.org", "/-/whoami")])


class CacheTests(unittest.TestCase):
    def test_a_credential_is_asked_once_when_the_answer_settles_it(self):
        for answer, outcome in ((resp(200, {"login": "x"}), "live"), (resp(401), "rejected")):
            with self.subTest(outcome):
                fake = Fake(default=answer)
                v = verifier(fake)
                first, second = v.verify("github", SECRETS["github"]), v.verify("github", SECRETS["github"])
                self.assertEqual((first, len(fake.calls)), (second, 1))
                self.assertEqual(first.outcome, outcome)

    def test_an_answer_that_does_not_settle_it_is_asked_again(self):
        for answer in (resp(500), resp(429), http.TransportError("timeout")):
            with self.subTest(str(answer)[:20]):
                fake = Fake(default=answer)
                v = verifier(fake)
                v.verify("github", SECRETS["github"])
                v.verify("github", SECRETS["github"])
                self.assertEqual(len(fake.calls), 2)

    def test_another_credential_is_another_question(self):
        fake = Fake(default=resp(200, {"login": "x"}))
        v = verifier(fake)
        v.verify("github", SECRETS["github"])
        v.verify("github", "ghp_" + "z" * 36)
        self.assertEqual(len(fake.calls), 2)

    def test_the_key_is_the_provider_the_endpoint_and_a_hash_of_the_credential(self):
        v = verifier()
        key = v._key(entry("github"), {"secret": SECRETS["github"]})
        self.assertEqual(key[:2], ("github", "api.github.com/user"))
        self.assertRegex(key[2], r"^[0-9a-f]{64}$")
        self.assertNotIn(SECRETS["github"], repr(key))
        other = copy.deepcopy(entry("github"))
        other["request"]["path"] = "/other"
        self.assertNotEqual(key, v._key(other, {"secret": SECRETS["github"]}))
        other = copy.deepcopy(entry("github"))
        other["id"], other["host"] = "ghe", "ghe.example.com"
        self.assertNotEqual(key, v._key(other, {"secret": SECRETS["github"]}))
        self.assertNotEqual(key, v._key(entry("github"), {"secret": "ghp_" + "z" * 36}))

    def test_a_pair_is_keyed_by_both_parts_in_order_of_name(self):
        v = verifier()
        aws = SECRETS["aws"]
        a = v._key(entry("aws"), dict(aws))
        self.assertEqual(a, v._key(entry("aws"), {"secret": aws["secret"], "id": aws["id"]}))
        self.assertNotEqual(a, v._key(entry("aws"), {"id": "AKIA" + "Z" * 16, "secret": aws["secret"]}))
        self.assertNotEqual(a, v._key(entry("aws"), {"id": aws["id"], "secret": "a" * 40}))

    def test_a_cached_answer_is_given_after_the_budget_is_spent(self):
        clock = [0.0]
        fake = Fake(default=resp(200, {"login": "x"}))
        v = verifier(fake, budget=10, clock=lambda: clock[0])
        v.verify("github", SECRETS["github"])
        clock[0] = 11.0
        self.assertEqual(v.verify("github", SECRETS["github"]).outcome, "live")
        self.assertEqual(len(fake.calls), 1)


class LimitTests(unittest.TestCase):
    def test_the_time_budget_is_for_the_run(self):
        clock = [100.0]
        fake = Fake(default=resp(401))
        v = verifier(fake, budget=10, clock=lambda: clock[0])
        self.assertEqual(v.verify("github", "ghp_" + "a" * 36).outcome, "rejected")
        clock[0] = 110.0
        self.assertEqual(v.verify("github", "ghp_" + "b" * 36).outcome, "rejected")              # (the budget is spent after more than 10 seconds)
        clock[0] = 110.5
        got = v.verify("github", "ghp_" + "c" * 36)
        self.assertEqual((got.outcome, got.detail, got.status), ("unknown", "the time budget for verification is spent", None))
        self.assertEqual(len(fake.calls), 2)

    def test_the_number_of_calls_is_bounded(self):
        fake = Fake(default=resp(401))
        v = verifier(fake, max_calls=3)
        results = [v.verify("github", "ghp_" + ch * 36) for ch in "abcde"]
        self.assertEqual([r.outcome for r in results], ["rejected"] * 3 + ["unknown"] * 2)
        self.assertEqual(results[3].detail, "the limit on verification calls is reached")
        self.assertEqual(len(fake.calls), 3)
        self.assertEqual(v.verify("github", "ghp_" + "a" * 36).outcome, "rejected")              # (an answer already had)
        self.assertEqual(len(fake.calls), 3)

    def test_a_format_that_is_refused_does_not_use_a_call(self):
        fake = Fake(default=resp(401))
        v = verifier(fake, max_calls=1)
        for _ in range(5):
            v.verify("github", "not a token")
        self.assertEqual(v.verify("github", "ghp_" + "a" * 36).outcome, "rejected")

    def test_the_least_interval_between_calls_to_one_provider(self):
        clock, slept = [0.0], []
        v = verifier(Fake(default=resp(500)), interval=2.0, clock=lambda: clock[0], sleep=slept.append)
        v.verify("github", "ghp_" + "a" * 36)
        self.assertEqual(slept, [])
        v.verify("github", "ghp_" + "b" * 36)
        self.assertEqual(slept, [2.0])
        v.verify("slack", SECRETS["slack"])                                                         # (another provider: not held)
        self.assertEqual(slept, [2.0])
        v.verify("github", "ghp_" + "c" * 36)
        self.assertEqual(slept, [2.0, 4.0])
        clock[0] = 100.0
        v.verify("github", "ghp_" + "d" * 36)
        self.assertEqual(slept, [2.0, 4.0])

    def test_no_interval_no_wait(self):
        slept = []
        v = verifier(Fake(default=resp(500)), sleep=slept.append)
        for ch in "abc":
            v.verify("github", "ghp_" + ch * 36)
        self.assertEqual(slept, [])

    def test_calls_to_one_provider_in_flight_are_bounded_and_providers_do_not_wait_for_each_other(self):
        for width in (1, 2, 3):
            with self.subTest(width=width):
                inflight, peak, lock = [0], [0], threading.Lock()
                gate = threading.Event()

                def slow(request):
                    with lock:
                        inflight[0] += 1
                        peak[0] = max(peak[0], inflight[0])
                    gate.wait(0.05)
                    with lock:
                        inflight[0] -= 1
                    return resp(401)

                v = verifier(Fake(default=slow), per_provider=width)
                items = [("github", "ghp_" + ch * 36) for ch in "abcdefgh"]
                got = v.verify_all(items, workers=8)
                self.assertEqual([r.outcome for r in got], ["rejected"] * 8)
                self.assertLessEqual(peak[0], width)
                self.assertEqual(peak[0], width)

    def test_two_providers_can_be_asked_at_once_when_each_allows_one(self):
        barrier = threading.Barrier(2, timeout=5)

        def meet(request):
            barrier.wait()
            return resp(401)

        v = verifier(Fake(default=meet), per_provider=1)
        got = v.verify_all([("github", "ghp_" + "a" * 36), ("npm", "npm_" + "a" * 36)], workers=2)
        self.assertEqual([r.outcome for r in got], ["rejected", "rejected"])


class VerifyAllTests(unittest.TestCase):
    def test_results_come_back_in_the_order_asked(self):
        answers = {"api.github.com": resp(200, {"login": "g"}), "registry.npmjs.org": resp(401), "slack.com": resp(500)}
        v = verifier(Fake(answers))
        got = v.verify_all([("npm", SECRETS["npm"]), ("github", SECRETS["github"]), ("slack", SECRETS["slack"]), ("github", "bad")])
        self.assertEqual([(r.provider, r.outcome) for r in got], [("npm", "rejected"), ("github", "live"), ("slack", "unknown"), ("github", "unknown")])

    def test_the_same_credential_is_asked_once(self):
        fake = Fake(default=resp(200, {"login": "g"}))
        got = verifier(fake).verify_all([("github", SECRETS["github"])] * 5, workers=4)
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(len(got), 5)
        self.assertEqual(len({r for r in got}), 1)

    def test_a_pair_given_in_either_order_of_keys_is_one_credential(self):
        fake = Fake(default=resp(200, AWS_LIVE))
        aws = SECRETS["aws"]
        got = verifier(fake).verify_all([("aws", dict(aws)), ("aws", {"secret": aws["secret"], "id": aws["id"]})])
        self.assertEqual(len(fake.calls), 1)
        self.assertEqual(got[0], got[1])

    def test_nothing_and_one_worker(self):
        self.assertEqual(verifier().verify_all([]), [])
        got = verifier(Fake(default=resp(401))).verify_all([("github", "ghp_" + "a" * 36), ("github", "ghp_" + "b" * 36)], workers=1)
        self.assertEqual([r.outcome for r in got], ["rejected", "rejected"])

    def test_hostile_items_are_unknown_and_do_not_stop_the_rest(self):
        got = verifier(Fake(default=resp(401))).verify_all([("github", None), ("github", ["x"]), ("github", {"a": 1}), ("github", "ghp_" + "a" * 36)])
        self.assertEqual([r.outcome for r in got], ["unknown", "unknown", "unknown", "rejected"])


class PromiseTests(unittest.TestCase):
    """What is promised about the credential, over every provider, every answer and every failure."""

    def test_no_result_holds_any_part_of_a_credential(self):
        answers = [resp(s, b) for s in (200, 401, 403, 429, 500) for b in (b"", b"{}", b"x" * 100)]
        answers += [http.TransportError(k, "x") for k in ("timeout", "connection", "tls", "proxy", "refused")]
        for pid, secret in SECRETS.items():
            parts = [secret] if isinstance(secret, str) else list(secret.values())
            for answer in answers:
                got = verifier(Fake(default=answer)).verify(pid, secret)
                for part in parts:
                    self.assertNotIn(part, repr(got), (pid, str(answer)[:30]))

    def test_every_call_goes_to_the_hosts_of_the_table_and_nowhere_else(self):
        fake = Fake(default=resp(200, {"login": "x"}))
        v = verifier(fake)
        for pid, secret in SECRETS.items():
            v.verify(pid, secret)
        self.assertEqual({r.host for r in fake.requests}, {p["host"] for p in sv.PROVIDERS})

    def test_an_answer_cannot_change_where_the_next_call_goes(self):
        fake = Fake(default=resp(302, b"", headers={"location": "https://evil.example/"}))
        v = verifier(fake)
        v.verify("github", SECRETS["github"])
        v.verify("github", "ghp_" + "z" * 36)
        self.assertEqual({r.host for r in fake.requests}, {"api.github.com"})


# ------------------------------------------------------------------------------------------------ over TLS, against the stub

@unittest.skipUnless(vs.have_openssl(), "the stub provider needs the openssl command")
class StubCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stub = vs.ProviderStub()
        cls.addClassCleanup(cls.stub.close)

    def setUp(self):
        self.stub.reset()
        self.v = sv.Verifier(self.stub.transport(), timeout=5)

    def seen(self):
        with self.stub.lock:
            return list(self.stub.requests)


class StubTests(StubCase):
    def answer(self, host, path, status, body=b""):
        self.stub.script[host, path] = vs.Answer(status, body if isinstance(body, bytes) else json.dumps(body).encode())

    def test_each_provider_live_and_rejected_over_tls(self):
        plan = {
            "github": ("api.github.com", "/user", (200, {"login": "octocat"}), (401, {"message": "Bad credentials"})),
            "slack": ("slack.com", "/api/auth.test", (200, {"ok": True, "user": "bot"}), (200, {"ok": False, "error": "invalid_auth"})),
            "stripe": ("api.stripe.com", "/v1/balance", (200, {"object": "balance"}), (401, {"error": {"type": "invalid_request_error"}})),
            "npm": ("registry.npmjs.org", "/-/whoami", (200, {"username": "alice"}), (401, {})),
            "openai": ("api.openai.com", "/v1/models", (200, {"data": []}), (401, {})),
            "anthropic": ("api.anthropic.com", "/v1/models", (200, {"data": []}), (401, {})),
            "aws": ("sts.amazonaws.com", "/", (200, AWS_LIVE), (403, aws_error("InvalidClientTokenId"))),
        }
        for pid, (host, path, live, rejected) in plan.items():
            for (status, body), outcome in ((live, "live"), (rejected, "rejected")):
                with self.subTest(pid=pid, outcome=outcome):
                    self.v = sv.Verifier(self.stub.transport(), timeout=5)
                    self.answer(host, path, status, body)
                    got = self.v.verify(pid, SECRETS[pid])
                    self.assertEqual((got.outcome, got.status), (outcome, status))

    def test_what_the_provider_sees(self):
        self.answer("api.github.com", "/user", 200, {"login": "octocat"})
        self.answer("sts.amazonaws.com", "/", 200, AWS_LIVE)
        self.v.verify("github", SECRETS["github"])
        self.v.verify("aws", SECRETS["aws"])
        github, aws = self.seen()
        self.assertEqual((github.method, github.host, github.path), ("GET", "api.github.com", "/user"))
        self.assertEqual(github.headers["authorization"], "Bearer " + SECRETS["github"])
        self.assertEqual((aws.method, aws.host, aws.path, aws.body), ("POST", "sts.amazonaws.com", "/", b"Action=GetCallerIdentity&Version=2011-06-15"))
        self.assertRegex(aws.headers["authorization"], r"^AWS4-HMAC-SHA256 Credential=AKIAABCDEFGHIJKLMNOP/\d{8}/us-east-1/sts/aws4_request, ")
        self.assertNotIn(SECRETS["aws"]["secret"], repr(aws))
        self.assertTrue(re.fullmatch(r"\d{8}T\d{6}Z", aws.headers["x-amz-date"]))

    def test_a_redirect_to_another_host_is_not_followed_and_the_secret_goes_nowhere_else(self):
        self.stub.script["api.github.com", "/user"] = vs.Answer(302, b"", {"Location": "https://slack.com/steal"})
        self.answer("slack.com", "/steal", 200, {"ok": True})
        got = self.v.verify("github", SECRETS["github"])
        self.assertEqual((got.outcome, got.status), ("unknown", 302))
        self.assertEqual([s.host for s in self.seen()], ["api.github.com"])

    def test_an_answer_that_is_too_slow_or_too_big_or_cut_short_is_unknown(self):
        self.stub.script["api.github.com", "/user"] = vs.Answer(200, b"{}", delay=3)
        v = sv.Verifier(self.stub.transport(), timeout=0.5)
        got = v.verify("github", SECRETS["github"])
        self.assertEqual((got.outcome, got.detail), ("unknown", "the provider did not answer in time"))
        self.stub.script["api.github.com", "/user"] = vs.Answer(200, huge=500_000)
        got = self.v.verify("github", SECRETS["github"])
        self.assertEqual(got.outcome, "live")                                                      # (the status is what a github answer needs)
        self.stub.script["slack.com", "/api/auth.test"] = vs.Answer(200, huge=500_000)
        got = self.v.verify("slack", SECRETS["slack"])
        self.assertEqual(got.outcome, "unknown")
        self.assertIn("larger than", got.detail)
        self.stub.script["registry.npmjs.org", "/-/whoami"] = vs.Answer(200, b'{"username": "a"', claim=500)
        got = self.v.verify("npm", SECRETS["npm"])
        self.assertEqual((got.outcome, got.detail), ("unknown", "the provider could not be reached"))

    def test_a_certificate_that_is_not_trusted_is_unknown_and_nothing_is_sent(self):
        v = sv.Verifier(http.https_transport(None, self.stub.address, {}), timeout=5)
        got = v.verify("github", SECRETS["github"])
        self.assertEqual((got.outcome, got.detail), ("unknown", "the provider's certificate could not be checked"))
        self.assertEqual(self.seen(), [])

    def test_through_a_proxy(self):
        proxy = self.stub.proxy()
        self.answer("api.github.com", "/user", 200, {"login": "octocat"})
        v = sv.Verifier(self.stub.transport({"https_proxy": f"http://127.0.0.1:{proxy.address[1]}"}, direct=False), timeout=5)
        self.assertEqual(v.verify("github", SECRETS["github"]).outcome, "live")
        self.assertEqual([line.rsplit(" HTTP/", 1)[0] for line, _ in proxy.requests], ["CONNECT api.github.com:443"])
        self.assertNotIn(SECRETS["github"], repr(proxy.requests))

    def test_a_run_over_all_the_providers_at_once(self):
        for host, path, body in (("api.github.com", "/user", {"login": "o"}), ("slack.com", "/api/auth.test", {"ok": True}),
                                 ("api.stripe.com", "/v1/balance", {}), ("registry.npmjs.org", "/-/whoami", {"username": "n"}),
                                 ("api.openai.com", "/v1/models", {}), ("api.anthropic.com", "/v1/models", {})):
            self.answer(host, path, 200, body)
        self.answer("sts.amazonaws.com", "/", 200, AWS_LIVE)
        got = self.v.verify_all(list(SECRETS.items()), workers=7)
        self.assertEqual([r.outcome for r in got], ["live"] * 7)
        self.assertEqual({s.host for s in self.seen()}, {p["host"] for p in sv.PROVIDERS})


if __name__ == "__main__":
    unittest.main()
