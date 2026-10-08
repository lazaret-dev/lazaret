"""`lazaret scan --verify-secrets` (scanner/verifyscan.py, V-1 stage 2; John's decision 4): a scan's secret findings asked about
after the scan. A stand-in transport answers, and the last classes ask the stub provider over TLS on 127.0.0.1, over urllib and
over lazaret-net (skipped without `openssl`, and lazaret-net's where the native transport is not available); no call reaches a
real service. The values are looked for in everything a verifying scan writes: none is there."""

import contextlib
import copy
import io
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from lazaret.scanner import _native, core
from lazaret.scanner import secretverify as sv
from lazaret.scanner import secretverify_http as http
from lazaret.scanner import verifyscan
from tests.scanner import _verify_stub as vs


def setUpModule():
    if not _native.available():
        raise unittest.SkipTest(f"the scan and the table are the native engine's ({_native.load_error()})")


GITHUB = "ghp_" + "a1B2" * 9
SLACK = "xoxb-1234567890-abcdefghij"
STRIPE = "sk_live_" + "a1" * 12
ANTHROPIC = "sk-ant-api03-" + "Ab1_" * 10
AWS_ID, AWS_SECRET = "AKIAABCDEFGHIJKLMNOP", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
#: every part of every credential the project holds
VALUES = (GITHUB, SLACK, STRIPE, ANTHROPIC, AWS_ID, AWS_SECRET)
APP = (f'import os\nGITHUB_TOKEN = "{GITHUB}"\nslack = "{SLACK}"\nheaders = {{"Authorization": "Bearer {STRIPE}"}}\n'
       f'AWS_ACCESS_KEY_ID = "{AWS_ID}"\nAWS_SECRET_ACCESS_KEY = "{AWS_SECRET}"\npassword = "hunter2hunter2"\n')
ENV = f"ANTHROPIC_API_KEY={ANTHROPIC}\n"
AWS_LIVE = b"<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/alice</Arn></GetCallerIdentityResult>"
AWS_REJECTED = b"<ErrorResponse><Error><Code>InvalidClientTokenId</Code></Error></ErrorResponse>"
ANTHROPIC_REJECTED = b'{"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}'


def write_project(folder, app=APP, env=ENV):
    with open(os.path.join(folder, "app.py"), "w", encoding="utf-8", newline="") as f:
        f.write(app)
    if env is not None:
        with open(os.path.join(folder, ".env"), "w", encoding="utf-8", newline="") as f:
            f.write(env)
    return folder


class Answers:
    """A stand-in transport: an answer for each host (by default 503), and what it was asked."""

    def __init__(self, answers=None, before=None):
        self.answers, self.asked, self.before, self.lock = dict(answers or {}), [], before, threading.Lock()

    def __call__(self, request, timeout, max_bytes):
        if self.before is not None:
            self.before(request)
        with self.lock:
            self.asked.append(request)
        status, body = self.answers.get(request.host, (503, b""))
        return http.Response(status, {}, body, False)

    def hosts(self):
        return sorted(r.host for r in self.asked)


SCRIPT = {"api.github.com": (200, b'{"login": "octocat"}'), "slack.com": (200, b'{"ok": false, "error": "invalid_auth"}'),
          "sts.amazonaws.com": (200, AWS_LIVE), "api.anthropic.com": (401, ANTHROPIC_REJECTED)}


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.folder("proj")

    def folder(self, name, app=APP, env=ENV):
        root = os.path.join(self.tmp.name, name)
        os.mkdir(root)
        return write_project(root, app, env)

    def scan(self, root=None):
        return core.scan_project(root or self.root)

    def verify(self, res, answers=None, root=None, out=None):
        transport = answers if answers is not None else Answers(SCRIPT)
        verifyscan.verify_findings(root or self.root, res, sv.Verifier(transport, timeout=5), out if out is not None else io.StringIO())
        return transport

    @staticmethod
    def by_line(res, file="app.py"):
        return {i["line"]: i for i in res["issues"] if i["file"] == file and i["rule"] in core.SECRET_RULES}


class LinesTests(Case):
    def write(self, name, data):
        path = os.path.join(self.root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return name

    def test_a_line_is_read_as_the_scan_numbers_it(self):
        self.assertEqual(verifyscan.lines_of(self.root, "app.py", [2, 6, 99]),
                         {2: f'GITHUB_TOKEN = "{GITHUB}"', 6: f'AWS_SECRET_ACCESS_KEY = "{AWS_SECRET}"'})
        name = self.write("crlf.cfg", b"a\r\nb\rc\nd")
        self.assertEqual(verifyscan.lines_of(self.root, name, [1, 2, 3, 4]), {1: "a", 2: "b", 3: "c", 4: "d"})
        name = self.write("utf16.env", "x=1\nTOKEN=abc\n".encode("utf-16"))
        self.assertEqual(verifyscan.lines_of(self.root, name, [2]), {2: "TOKEN=abc"})
        # (JavaScript ends a line at U+2028 too, as the scan reads it; a config file does not)
        self.write("a.js", "x y\nz".encode())
        self.write("a.json", "x y\nz".encode())
        self.assertEqual(verifyscan.lines_of(self.root, "a.js", [3]), {3: "z"})
        self.assertEqual(verifyscan.lines_of(self.root, "a.json", [2]), {2: "z"})

    def test_what_the_scan_would_not_read_is_not_read(self):
        outside = os.path.join(self.tmp.name, "outside.env")
        with open(outside, "w", encoding="utf-8") as f:
            f.write(f"T={GITHUB}\n")
        os.symlink(outside, os.path.join(self.root, "link.env"))
        os.symlink(os.path.join(self.root, "app.py"), os.path.join(self.root, "inner.py"))
        os.mkdir(os.path.join(self.root, "d"))
        for rel in ("link.env", "inner.py", "../outside.env", "d", "missing.py", os.path.join("d", "..", "..", "outside.env")):
            with self.subTest(rel):
                self.assertEqual(verifyscan.lines_of(self.root, rel, [1]), {})
        with mock.patch.object(core, "SOURCE_SIZE_CAP", 10):
            self.assertEqual(verifyscan.lines_of(self.root, "app.py", [1]), {})


class VerifyFindingsTests(Case):
    def test_each_finding_gets_what_its_credential_s_provider_said(self):
        res = self.scan()
        answers = self.verify(res)
        lines = self.by_line(res)
        self.assertEqual({n: (i["verified"]["outcome"], i["verified"]["provider"]) for n, i in lines.items() if "verified" in i},
                         {2: ("live", "github"), 3: ("rejected", "slack"), 4: ("unknown", "stripe"), 5: ("live", "aws"), 6: ("live", "aws")})
        self.assertNotIn("verified", lines[7])                                    # (a password: no provider to ask)
        self.assertEqual(lines[2]["verified"]["who"], "octocat")
        self.assertIn("Verified live: the provider accepts this GitHub token (the account: octocat). Revoke it now.", lines[2]["msg"])
        self.assertIn("Verified rejected: Slack says the token is not valid. Revoke it anyway: the history keeps it.", lines[3]["msg"])
        self.assertIn("Not verified: the provider failed (HTTP 503).", lines[4]["msg"])
        (env,) = [i for i in res["issues"] if i["file"] == ".env"]
        self.assertEqual((env["verified"]["outcome"], env["verified"]["provider"]), ("rejected", "anthropic"))
        self.assertEqual(answers.hosts(), ["api.anthropic.com", "api.github.com", "api.stripe.com", "slack.com", "sts.amazonaws.com"])
        self.assertEqual(res["verification"]["credentials"], {"live": 2, "rejected": 2, "unknown": 1})
        self.assertEqual(res["verification"]["findings"], {"live": 3, "rejected": 2, "unknown": 1, "notVerified": 1})
        self.assertEqual([(p["provider"], p["host"], p["credentials"]) for p in res["verification"]["providers"]],
                         [("anthropic", "api.anthropic.com", 1), ("github", "api.github.com", 1), ("slack", "slack.com", 1),
                          ("stripe", "api.stripe.com", 1), ("aws", "sts.amazonaws.com", 1)])

    def test_an_aws_key_and_its_secret_are_asked_about_as_a_pair(self):
        res = self.scan()
        answers = self.verify(res, Answers({"sts.amazonaws.com": (403, AWS_REJECTED)}))
        (sts,) = [r for r in answers.asked if r.host == "sts.amazonaws.com"]
        self.assertIn(f"Credential={AWS_ID}/", sts.headers["authorization"])
        lines = self.by_line(res)
        self.assertEqual((lines[5]["verified"]["outcome"], lines[6]["verified"]["outcome"]), ("rejected", "rejected"))
        # a key in one file and a secret in another are not a pair
        root = self.folder("split", APP.replace(f'AWS_SECRET_ACCESS_KEY = "{AWS_SECRET}"\n', ""),
                           ENV + f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}\n")
        res = self.scan(root)
        answers = self.verify(res, Answers(SCRIPT), root)
        self.assertNotIn("sts.amazonaws.com", answers.hosts())

    def test_a_live_credential_is_a_blocker_vulnerability_and_the_result_is_graded_again(self):
        res = self.scan()
        entropy = {"rule": "S-ENTROPY", "name": "High-entropy string", "type": "HOTSPOT", "sev": "MAJOR", "file": "app.py", "line": 2,
                   "msg": "High-entropy string literal.", "snippet": ["[redacted]"], "snipStart": 2}
        res["issues"] = [i for i in res["issues"] if i["file"] == "app.py" and i["line"] != 2] + [entropy]
        core.regrade(res)
        self.assertEqual(res["counts"]["HOTSPOT"], 1)
        hotspots = res["counts"]["HOTSPOT"]
        self.verify(res)
        self.assertEqual((entropy["sev"], entropy["type"]), ("BLOCKER", "VULN"))
        self.assertEqual(res["counts"]["HOTSPOT"], hotspots - 1)
        self.assertEqual(res["issues"][0]["sev"], "BLOCKER")
        self.assertFalse(res["pass"])
        # rejected and unknown leave a finding as it was
        for script, outcome in (({"api.github.com": (401, b"")}, "rejected"), ({}, "unknown")):
            with self.subTest(outcome):
                res = self.scan()
                lines = self.by_line(res)
                before = {n: (i["sev"], i["type"]) for n, i in lines.items()}
                self.verify(res, Answers(script))
                self.assertEqual(lines[2]["verified"]["outcome"], outcome)
                self.assertEqual({n: (i["sev"], i["type"]) for n, i in lines.items()}, before)

    def test_grading_again_a_result_nothing_changed_in_changes_nothing(self):
        res = self.scan()
        self.assertEqual(core.regrade(copy.deepcopy(res)), res)

    def test_a_finding_takes_the_most_telling_of_its_line_s_credentials(self):
        root = self.folder("two", f'TOKENS = ["{GITHUB}", "{SLACK}"]\n', None)
        for script, outcome in (({"api.github.com": (401, b""), "slack.com": (200, b'{"ok": true, "user": "bot"}')}, "live"),
                                ({"api.github.com": (401, b"")}, "unknown"),
                                ({"api.github.com": (401, b""), "slack.com": (200, b'{"ok": false, "error": "invalid_auth"}')}, "rejected")):
            with self.subTest(outcome):
                res = self.scan(root)
                self.verify(res, Answers(script), root)
                (finding,) = [i for i in res["issues"] if i["rule"] in core.SECRET_RULES]
                self.assertEqual(finding["verified"]["outcome"], outcome)

    def test_the_note_comes_before_the_first_call_and_says_where_each_credential_goes(self):
        out = io.StringIO()
        noted = []
        res = self.scan()
        self.verify(res, Answers(SCRIPT, before=lambda request: noted.append(out.getvalue())), out=out)
        self.assertTrue(noted and all(n == noted[0] and n for n in noted))
        note = out.getvalue()
        self.assertTrue(note.startswith("note: --verify-secrets: asking 5 providers whether 5 credentials are live"), note)
        for label, host in (("GitHub token", "api.github.com"), ("AWS access key", "sts.amazonaws.com"), ("Slack token", "slack.com"),
                            ("Anthropic API key", "api.anthropic.com"), ("Stripe live key", "api.stripe.com")):
            self.assertIn(f"{label} at {host} (1)", note)

    def test_nothing_is_asked_when_no_finding_holds_a_credential(self):
        root = self.folder("none", 'password = "hunter2hunter2"\nimport os\n', None)
        res = self.scan(root)
        out = io.StringIO()
        answers = self.verify(res, Answers(SCRIPT), root, out)
        self.assertEqual((answers.asked, out.getvalue()), ([], ""))
        self.assertEqual(res["verification"]["findings"]["notVerified"], 1)
        self.assertEqual(res["verification"]["providers"], [])

    def test_the_project_is_read_and_not_written(self):
        def listing():
            return sorted((d, tuple(sorted(f))) for d, _, f in os.walk(self.tmp.name))
        res = self.scan()
        before = listing()
        self.verify(res)
        self.assertEqual(listing(), before)


class CliCase(Case):
    """`lazaret scan` itself, the reports in a folder of their own; `transport` is what `default_transport` gives."""

    def run_cli(self, *extra, transport=None):
        reports = os.path.join(self.tmp.name, "reports")
        os.makedirs(reports, exist_ok=True)
        argv = [self.root, "--json", os.path.join(reports, "r.json"), "--html", os.path.join(reports, "r.html"),
                "--sarif", os.path.join(reports, "r.sarif"), "--force-overwrite", *extra]
        out, err = io.StringIO(), io.StringIO()
        stand_in = transport if transport is not None else Answers(SCRIPT)
        with mock.patch.object(http, "default_transport", lambda: stand_in), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                code = core.main(argv)
            except SystemExit as exc:
                code = exc.code
        written = {}
        for name in sorted(os.listdir(reports)):
            with open(os.path.join(reports, name), encoding="utf-8") as f:
                written[name] = f.read()
        return code, out.getvalue(), err.getvalue(), written, stand_in

    def assert_no_value(self, *texts):
        for k, text in enumerate(texts):
            for value in VALUES:
                self.assertNotIn(value, text, f"output {k}")


class CliTests(CliCase):
    def test_without_the_flag_nothing_is_asked(self):
        code, out, err, written, answers = self.run_cli()
        self.assertEqual(answers.asked, [])
        self.assertNotIn("verification", json.loads(written["r.json"]))
        self.assertNotIn("--verify-secrets", err)
        self.assertNotIn("Secrets verified", out)

    def test_a_verifying_scan_says_what_each_provider_said_and_no_output_holds_a_value(self):
        code, out, err, written, answers = self.run_cli("--verify-secrets")
        self.assertEqual(len(answers.asked), 5)
        self.assertIn("note: --verify-secrets: asking 5 providers", err)
        self.assertIn("Secrets verified  2 live, 2 rejected, 1 unknown (of 5 asked about); 1 secret finding no provider can be asked about", out)
        self.assertIn("Verified live: the provider accepts this GitHub token (the account: octocat)", out)
        report = json.loads(written["r.json"])
        self.assertEqual(report["verification"]["findings"]["live"], 3)
        verified = {i["line"]: i["verified"]["outcome"] for i in report["issues"] if i["file"] == "app.py" and "verified" in i}
        self.assertEqual(verified, {2: "live", 3: "rejected", 4: "unknown", 5: "live", 6: "live"})
        results = json.loads(written["r.sarif"])["runs"][0]["results"]
        self.assertEqual(sorted(r["properties"]["verified"]["outcome"] for r in results if "properties" in r),
                         ["live", "live", "live", "rejected", "rejected", "unknown"])
        self.assertIn("Verified live", written["r.html"])
        self.assertIn('<p class="verified">Secrets verified  2 live, 2 rejected, 1 unknown (of 5 asked about)', written["r.html"])
        self.assertFalse(report["pass"])
        self.assertEqual(code, core.EXIT_OK)
        self.assert_no_value(out, err, *written.values())

    def test_the_gate_fails_on_a_live_credential_with_ci(self):
        self.assertEqual(self.run_cli("--verify-secrets", "--ci")[0], core.EXIT_GATE)

    def test_the_help_names_the_flag(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            core.main(["--help"])
        self.assertIn("--verify-secrets", out.getvalue())


@unittest.skipUnless(vs.have_openssl(), "the stub provider needs the openssl command")
class StubCliTests(CliCase):
    """The same scan over TLS against the stub provider: each credential reaches its own provider's host, and only there."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.stub = vs.ProviderStub()
        cls.addClassCleanup(cls.stub.close)

    def setUp(self):
        super().setUp()
        self.stub.reset()
        for host, (status, body) in SCRIPT.items():
            self.stub.script[host] = vs.Answer(status, body)

    def transport(self):
        return self.stub.transport()

    def test_each_credential_reaches_its_own_provider_and_no_output_holds_a_value(self):
        code, out, err, written, _ = self.run_cli("--verify-secrets", transport=self.transport())
        with self.stub.lock:
            seen = list(self.stub.requests)
        self.assertEqual(sorted(s.host for s in seen), ["api.anthropic.com", "api.github.com", "api.stripe.com", "slack.com",
                                                        "sts.amazonaws.com"])
        expected = {"api.github.com": GITHUB, "slack.com": SLACK, "api.stripe.com": STRIPE, "api.anthropic.com": ANTHROPIC,
                    "sts.amazonaws.com": AWS_ID}
        for s in seen:
            self.assertEqual([v for v in VALUES if v in repr(s)], [expected[s.host]], s.host)   # (its own, and no other)
        self.assertNotIn(AWS_SECRET, repr(seen))                                                # (AWS's secret key is never sent)
        report = json.loads(written["r.json"])
        self.assertEqual(report["verification"]["credentials"], {"live": 2, "rejected": 2, "unknown": 1})
        self.assert_no_value(out, err, *written.values())


class NativeStubCliTests(vs.OverLazaretNet, StubCliTests):
    def transport(self):
        return self.stub.native()


if __name__ == "__main__":
    unittest.main()
