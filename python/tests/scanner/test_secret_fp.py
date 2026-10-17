"""SECRET-FP (0.1.9): the engine's secret rules on what John's crates.io discovery run of Oct 15 flagged.

Of 465 scans, S-SECRET and S-TOKEN gave 30 BLOCKERs and S-ENTROPY 238 MAJORs, and every one read was not a
credential: names (Hugging Face repositories, feature flags, link names, RPC names, media types), placeholders and
environment variables' names, AWS's documentation key, unsigned test JWTs, alphabets, Ethereum addresses, base64 of
documents. Each is held here as a case of its kind, and so is what the rules must still report: credentials of the
same shapes, made here from random characters at run time (nothing in this file is a credential). Values that are
names are taken from public packages' sources (the popular set) or invented.
"""
import base64
import json
import random
import string
import unittest

from lazaret.scanner import core

B62 = string.ascii_letters + string.digits
RNG = random.Random(20261015)


def rand(n, alphabet=B62):
    return "".join(RNG.choice(alphabet) for _ in range(n))


def rules(src, lang="py"):
    """{(rule, line)} of the secret rules' findings."""
    return {(i["rule"], i["line"]) for i in core.scan_file("f." + lang, src, lang)
            if i["rule"] in ("S-SECRET", "S-TOKEN", "S-ENTROPY")}


def assigned(value, name="value", lang="py"):
    return rules(f"import os\n{name} = '{value}'\n", lang)


class NotCredentialsTests(unittest.TestCase):
    def test_names_are_not_high_entropy_values(self):
        for value in ("kernels-community/flash-attn2", "ApproveDisplayVideo360AdvertiserLinkProposal",
                      "Win32_NetworkManagement_WindowsFilteringPlatform", "aws_lc_0_45_0_OPENSSL_isxdigit",
                      "V1alpha1MutatingAdmissionPolicy", "CreateOAuth2TokenRequestBody",
                      "AWSSecurityTokenServiceV20110615", "swiss-ai/Apertus-8B-Instruct-2509",
                      "application/3gpdash-qoe-report+xml", "ESMFold2TriangleMultiplication"):
            with self.subTest(value=value):
                self.assertEqual(assigned(value), set())

    def test_alphabets_sequences_addresses_and_documents_are_not_keys(self):
        doc = base64.b64encode(json.dumps({"issuer": "made-up", "subject": "user 7", "n": 12345}).encode()).decode()
        xml = base64.b64encode(b'<samlp:Response ID="r1" Version="2.0"><Issuer>made-up</Issuer>').decode()
        for value in (string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/",
                      "0123456789abcdefghijklmnopqrstuvwxyz", "01234567890ABCDEFGHIJK" * 2,
                      "0x" + rand(40, "0123456789abcdef"), doc, xml):
            with self.subTest(value=value[:24]):
                self.assertEqual(assigned(value), set())

    def test_placeholders_and_names_are_not_hardcoded_credentials(self):
        for name, value in (("api_key", "your-api-key"), ("client_secret", "my-client-secret"),
                            ("api_key", "OPENAI_API_KEY"), ("password", "change-me"),
                            ("REG_JWT_SECRET", "JwtSecret"), ("ApiKey", "fintekkers.models.util.api.API_Key"),
                            ("PLACEHOLDER_API_KEY", "tapes-gateway"), ("api_key", "CONFIG_KEY_CANARY"),
                            ("password", "tiger"), ("PWD", "pwd -P >|")):
            with self.subTest(name=name, value=value):
                self.assertEqual(assigned(value, name), set())

    def test_documentation_and_unsigned_tokens_are_samples(self):
        jwt_head = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        for value in ("AKI" + "AIOSFODNN7" + "EXAMPLE", jwt_head + ".c2ln", jwt_head + ".SIGNATURE",
                      "sk_" + "live_" + "example" + rand(16), "gh" + "p_" + "FAKE" + rand(32)):
            with self.subTest(value=value[:12]):
                self.assertNotIn("S-TOKEN", {r for r, _l in assigned(value, "token")})


class CredentialsTests(unittest.TestCase):
    def test_random_keys_are_still_high_entropy_values(self):
        for alphabet, n in ((B62, 32), (B62 + "-_", 43), (B62 + "+/", 43)):
            # (a key with two slashes reads as a path, and was not reported before either)
            keys = [k for k in (rand(n, alphabet) for _ in range(400)) if k.count("/") < 2]
            src = "import os\n" + "".join(f"k{i} = '{k}'\n" for i, k in enumerate(keys))
            flagged = {line for r, line in rules(src) if r == "S-ENTROPY"}
            # (a few have too little entropy, as before)
            with self.subTest(alphabet=alphabet[-2:], n=n):
                self.assertGreaterEqual(len(flagged), 0.97 * len(keys))

    def test_a_public_key_is_not_a_secret_but_a_public_field_is_read(self):
        value = rand(32)
        self.assertEqual(rules(f"const vapidPublicKey = '{value}';\n", "js"), set())
        self.assertEqual(rules(f"PUBLIC_KEY = '{value}'\n"), set())
        self.assertEqual(rules(f"class C {{ public session = '{value}'; }}\n", "js"), {("S-ENTROPY", 1)})

    def test_provider_tokens_are_still_reported(self):
        signed = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + rand(43, B62 + "-_")
        for value in ("AKI" + "A" + rand(16, string.ascii_uppercase + string.digits), "gh" + "p_" + rand(36),
                      "sk_" + "live_" + rand(24), signed):
            with self.subTest(value=value[:6]):
                self.assertIn("S-TOKEN", {r for r, _l in assigned(value, "token")})

    def test_passwords_are_still_hardcoded_credentials(self):
        for lang, line in (("py", f'password = "{rand(20)}"'), ("py", 'password = "sup3r' + 'Secret!"'),
                           ("js", f"const db = {{user: 'bob', pwd: '{rand(20)}'}};"),
                           ("js", f"const db = {{user: 'bob', pwd: '{rand(10)}/{rand(10)}+{rand(4)}'}};"),
                           ("py", f'login(password="correct horse {rand(6, string.ascii_lowercase)} staple")'),
                           ("go", f'password := "{rand(16)}"'), ("rs", f'let api_key = "{rand(24)}";')):
            with self.subTest(line=line[:30]):
                self.assertIn(("S-SECRET", 2), rules(f"import os\n{line}\n", lang))


if __name__ == "__main__":
    unittest.main()
