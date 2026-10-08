"""The npm package's engine is the native engine (see test_wasm_parity), for live secret verification's calls too (V-1 stage 2:
the table and the logic in the engine, one copy for both packages): the WebAssembly build against the native library on
`secrets.providers`, `secrets.identify`, `secrets.request` (every provider, AWS's signature at several times, credentials not in
the format) and `secrets.judge` (every provider's answers, cut and whole, and hostile bodies). Skipped where node, the
WebAssembly build or the native library is missing.
"""
import json
import unittest

from lazaret.scanner import _native
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_wasm_parity import both, differences

SAMPLES = {
    "github": "ghp_" + "a1B2" * 9, "slack": "xox\x62-1234567890-abcdefghij", "stripe": "sk_live_" + "a1" * 12,
    "npm": "npm_" + "A1b2" * 9, "openai": "sk-proj-" + "a1" * 20, "anthropic": "sk-ant-api03-" + "Ab1_" * 10,
}
AWS = {"id": "AKI\x41ABCDEFGHIJKLMNOP", "secret": "wJalrXUtnFEMI/K7MDEN\x47+bPxRfiCYEXAMPLEKEY"}
BODIES = [b"", b"not json", b'{"login": "octocat"}', b'{"ok": true, "user": "bot"}', b'{"ok": false, "error": "invalid_auth"}',
          b'{"error": {"type": "permission_error"}}', b'{"username": "alice"}', b"\xff\xfe\x00", b"[" * 3000, b"NaN", b"\xef\xbb\xbf{}",
          b'{"login": "\\ud800"}', b'{"login": "a\\u2028b ' + b"x" * 300 + b'"}', b"<Error><Code>InvalidClientTokenId</Code></Error>",
          b"<Error><Code>Throttling</Code></Error>", b"<Arn>arn:aws:iam::1:user/a</Arn>", b"<Arn>caf\xc3\xa9\xff</Arn>",
          b'{"login": "' + b"x" * 70 + b"octocat" * 60 + b'", "user": "octobotocat-bot"}', b"<Arn>bot" + b"octocat" * 40 + b"</Arn>"]


def calls():
    out = [("secrets.providers", {}, "")]
    for text in list(SAMPLES.values()) + [AWS["id"], AWS["secret"], "ghp_short", "sk-ant" + "a" * 30, "", "x" * 600]:
        out.append(("secrets.identify", {}, text))
    for pid, secret in SAMPLES.items():
        for parts in ({"secret": secret}, {"secret": secret[:-3]}, {"secret": secret + "\n"}, {"token": secret}):
            out.append(("secrets.request", {"provider": pid, "parts": parts, "time": "20261003T120000Z"}, ""))
    for time in ("20261003T120000Z", "20150830T123600Z", "20991231T235959Z"):
        out.append(("secrets.request", {"provider": "aws", "parts": AWS, "time": time}, ""))
    for pid in list(SAMPLES) + ["aws"]:
        for status in (200, 400, 401, 403, 429, 500, 0):
            for body in BODIES:
                for truncated in (False, True):
                    out.append(("secrets.judge", {"provider": pid, "status": status, "truncated": truncated,
                                                  "secrets": ["bot", "octocat"]}, body.decode("latin-1")))
    return out


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmSecretsParityTests(unittest.TestCase):
    maxDiff = None

    def test_the_secrets_calls(self):
        cs = [list(c) for c in calls()]
        wasm, native = both(cs)
        self.assertEqual(len(wasm), len(cs))
        self.assertEqual(differences(cs, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))                          # every call answered
        # (the calls were answered, and the requests made: an AWS signature, the refusals)
        answers = [_native.call(*c) for c in cs[:40]]
        self.assertTrue(any(isinstance(a, dict) and "authorization" in json.dumps(a) for a in answers))
        self.assertTrue(any(isinstance(a, dict) and "refused" in a for a in answers))


if __name__ == "__main__":
    unittest.main()
