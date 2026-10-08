"""scripts/verifylive (0.1.9, V-1 stage 1): the manual check of the provider table against the real services.

The tests never call a service. They check what the script does around the calls: nothing is sent without `--yes`, which
credentials it asks about (a made-up one for each provider, and the ones in the environment), what it says about each, that no
credential is printed, and the exit status when an expectation does not hold."""

import datetime
import io
import os
import unittest

from lazaret.scanner import secretverify as sv
from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "verifylive")
verifylive = _support.load_script(os.path.join(SCRIPT, "verifylive.py"), "verifylive_script")

GITHUB = "ghp_" + "a1B2" * 9
AWS = {"id": "AKIAABCDEFGHIJKLMNOP", "secret": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}


class Verifier:
    """Answers for the made-up credentials as a provider would (rejected), and for any other as `live`, with a login."""

    def __init__(self, timeout=None, lie_about=()):
        self.timeout, self.lie_about, self.asked = timeout, set(lie_about), []

    def verify(self, pid, credential):
        self.asked.append((pid, credential))
        made_up = credential == verifylive.MADE_UP[pid]
        outcome = "rejected" if made_up else "live"
        if pid in self.lie_about:
            outcome = "unknown"
        return sv.Result(pid, outcome, "HTTP 401" if made_up else "HTTP 200", None if made_up else "octocat", 401 if made_up else 200)


def run(argv, environ=None, verifier=None):
    out = io.StringIO()
    code = verifylive.main(argv, environ if environ is not None else {}, (lambda timeout: verifier) if verifier is not None else None, out)
    return code, out.getvalue()


class MadeUpTests(unittest.TestCase):
    def test_a_made_up_credential_is_in_the_format_of_every_provider_and_is_not_a_real_pattern_of_any_account(self):
        self.assertEqual(set(verifylive.MADE_UP), set(sv.provider_ids()))
        now = datetime.datetime(2026, 10, 3, 12, 0, tzinfo=datetime.timezone.utc)
        for pid, credential in verifylive.MADE_UP.items():
            with self.subTest(pid):
                parts = sv.Verifier._parts(credential)
                self.assertIsNotNone(parts)
                sv.build_request(next(p for p in sv.PROVIDERS if p["id"] == pid), parts, now)    # (ValueError: not the format)
                text = credential if isinstance(credential, str) else "".join(credential.values())
                self.assertRegex(text.split("-")[-1].split("_")[-1].replace("AKIA", ""), r"^0+$")


class UsageTests(unittest.TestCase):
    def test_the_list_says_where_a_credential_would_go_and_sends_nothing(self):
        verifier = Verifier()
        code, out = run(["--list"], verifier=verifier)
        self.assertEqual(code, 0)
        self.assertIn("api.github.com", out)
        self.assertIn("sts.amazonaws.com", out)
        self.assertEqual(verifier.asked, [])

    def test_nothing_is_sent_without_yes(self):
        verifier = Verifier()
        code, out = run([], {"LAZARET_VERIFY_GITHUB": GITHUB}, verifier)
        self.assertEqual(code, 2)
        self.assertEqual((verifier.asked, out), ([], ""))

    def test_a_provider_that_is_not_there_is_a_usage_error(self):
        verifier = Verifier()
        self.assertEqual(run(["--yes", "--only", "github,nonesuch"], verifier=verifier)[0], 2)
        self.assertEqual(verifier.asked, [])

    def test_a_timeout_must_be_above_zero(self):
        for value in ("0", "-1", "nan"):
            with self.subTest(value):
                self.assertEqual(run(["--yes", "--timeout", value], verifier=Verifier())[0], 2)

    def test_an_unknown_option_is_a_usage_error_and_help_is_not(self):
        self.assertEqual(run(["--nonesuch"])[0], 2)
        self.assertEqual(run(["--help"])[0], 0)

    def test_nothing_to_ask_is_a_usage_error(self):
        verifier = Verifier()
        self.assertEqual(run(["--yes", "--no-made-up"], {}, verifier)[0], 2)
        self.assertEqual(verifier.asked, [])


class PlanTests(unittest.TestCase):
    def test_a_made_up_credential_for_each_provider_expected_rejected(self):
        rows = verifylive.plan(sv.provider_ids(), {})
        self.assertEqual([(pid, which, expected) for pid, which, _, expected in rows], [(pid, "made-up", "rejected") for pid in sv.provider_ids()])

    def test_the_environment_adds_the_credentials_expected_live_or_as_told(self):
        env = {"LAZARET_VERIFY_GITHUB": GITHUB, "LAZARET_VERIFY_NPM": "npm_" + "a" * 36, "LAZARET_VERIFY_NPM_EXPECT": "rejected",
               "LAZARET_VERIFY_AWS_ID": AWS["id"], "LAZARET_VERIFY_AWS_SECRET": AWS["secret"]}
        rows = verifylive.plan(["github", "npm", "aws"], env)
        self.assertEqual([(pid, which, expected) for pid, which, _, expected in rows],
                         [("github", "made-up", "rejected"), ("github", "yours", "live"), ("npm", "made-up", "rejected"),
                          ("npm", "yours", "rejected"), ("aws", "made-up", "rejected"), ("aws", "yours", "live")])
        self.assertEqual(rows[1][2], GITHUB)
        self.assertEqual(rows[5][2], AWS)

    def test_a_pair_needs_both_parts_and_an_empty_value_is_none(self):
        for env in ({"LAZARET_VERIFY_AWS_ID": AWS["id"]}, {"LAZARET_VERIFY_AWS_SECRET": AWS["secret"]}, {"LAZARET_VERIFY_AWS_ID": "", "LAZARET_VERIFY_AWS_SECRET": ""}):
            self.assertIsNone(verifylive.yours("aws", env))
        self.assertIsNone(verifylive.yours("github", {"LAZARET_VERIFY_GITHUB": ""}))
        self.assertIsNone(verifylive.yours("github", {}))

    def test_no_made_up_leaves_only_what_the_environment_gives(self):
        rows = verifylive.plan(["github", "npm"], {"LAZARET_VERIFY_NPM": "npm_" + "a" * 36}, made_up=False)
        self.assertEqual([(r[0], r[1]) for r in rows], [("npm", "yours")])


class RunTests(unittest.TestCase):
    def test_every_expectation_held(self):
        verifier = Verifier()
        code, out = run(["--yes", "--only", "github,npm"], {"LAZARET_VERIFY_GITHUB": GITHUB}, verifier)
        self.assertEqual(code, 0, out)
        self.assertEqual([(pid, cred == verifylive.MADE_UP[pid]) for pid, cred in verifier.asked], [("github", True), ("github", False), ("npm", True)])
        self.assertIn("3 of 3 as expected", out)
        self.assertRegex(out, r"(?m)^github\s+yours\s+live\s+live\s+200\s+HTTP 200 \(octocat\)$")
        self.assertRegex(out, r"(?m)^github\s+made-up\s+rejected\s+rejected\s+401\s+HTTP 401$")

    def test_a_credential_is_never_printed(self):
        verifier = Verifier()
        env = {"LAZARET_VERIFY_GITHUB": GITHUB, "LAZARET_VERIFY_AWS_ID": AWS["id"], "LAZARET_VERIFY_AWS_SECRET": AWS["secret"]}
        code, out = run(["--yes"], env, verifier)
        for secret in (GITHUB, AWS["id"], AWS["secret"], *[c for c in verifylive.MADE_UP.values() if isinstance(c, str)]):
            self.assertNotIn(secret, out)

    def test_an_expectation_that_did_not_hold_is_marked_and_the_exit_is_one(self):
        verifier = Verifier(lie_about=["slack"])
        code, out = run(["--yes", "--only", "github,slack"], {}, verifier)
        self.assertEqual(code, 1)
        self.assertRegex(out, r"(?m)^slack\s+made-up\s+rejected\s+unknown\s+401\s+HTTP 401   <-- not what was expected$")
        self.assertIn("1 of 2 as expected", out)

    def test_a_key_you_say_is_revoked_is_expected_rejected(self):
        verifier = Verifier()
        env = {"LAZARET_VERIFY_GITHUB": GITHUB, "LAZARET_VERIFY_GITHUB_EXPECT": "rejected"}
        code, out = run(["--yes", "--only", "github", "--no-made-up"], env, verifier)
        self.assertEqual(code, 1)                                         # (the stand-in says live: the expectation did not hold)
        self.assertIn("<-- not what was expected", out)

    def test_the_default_verifier_asks_one_call_at_a_time_a_second_apart(self):
        seen = {}

        original = sv.Verifier

        class Recorder(original):
            def __init__(self, *args, **kw):
                seen.update(kw)
                super().__init__(lambda *a: None, **{k: v for k, v in kw.items() if k != "transport"})

            def verify(self, pid, credential):
                return sv.Result(pid, "rejected", "x", None, 401)

        sv.Verifier = Recorder
        try:
            code, out = run(["--yes", "--only", "github", "--timeout", "3"])
        finally:
            sv.Verifier = original
        self.assertEqual(code, 0, out)
        self.assertEqual((seen["timeout"], seen["per_provider"], seen["interval"]), (3.0, 1, 1.0))


class ScriptRulesTests(unittest.TestCase):
    def test_the_script_sends_through_the_module_and_opens_no_connection_of_its_own(self):
        with open(os.path.join(SCRIPT, "verifylive.py"), encoding="utf-8") as fh:
            text = fh.read()
        for word in ("urllib", "http.client", "socket", "requests", "ssl"):
            self.assertNotIn("import " + word, text)

    def test_the_readme_names_every_provider(self):
        with open(os.path.join(SCRIPT, "README.md"), encoding="utf-8") as fh:
            text = fh.read()
        for pid in sv.provider_ids():
            self.assertIn(f"| {pid} |", text)


if __name__ == "__main__":
    unittest.main()
