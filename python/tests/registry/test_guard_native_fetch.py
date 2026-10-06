"""The guard's fetcher on the native transport (0.1.9, NET-1): an https request without credentials goes through
the native library's client, with the fetcher's hosts as the rule for every redirect; plain http, and a request with
credentials, stay on urllib. Against a local HTTPS server of Python's ssl, as tests.scanner.test_nativenet's."""

import hashlib
import os
import shutil
import tempfile
import unittest
import urllib.error
from unittest import mock

from lazaret.registry import guard, pmsettings, repo
from lazaret.scanner import nativenet
from tests.scanner.test_nativenet import NO_PROXY_ENV, make_pki, serve


@unittest.skipUnless(shutil.which("openssl"), "no openssl command to make the test's certificates with")
class GuardNativeFetchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get(nativenet.ENV, "").strip().lower() == "python":
            raise unittest.SkipTest("LAZARET_NETWORK=python")
        if not nativenet.available():
            raise unittest.SkipTest(f"no native transport here ({nativenet.why_not()})")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root, cert, key = make_pki(cls.tmp.name)
        nativenet.configure_roots(cls.root)
        cls.server, cls.port = serve(cert, key)
        cls.host = f"localhost:{cls.port}"
        cls.env = mock.patch.dict(os.environ, NO_PROXY_ENV, clear=True)
        cls.env.start()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.server.stop()
        nativenet.configure_roots(None)
        cls.tmp.cleanup()

    def url(self, path):
        return f"https://{self.host}{path}"

    def fetcher(self, **kw):
        f = guard.Fetcher([self.host], **kw)
        self.addCleanup(f.close)
        return f

    def no_urllib(self, fetcher):
        return mock.patch.object(fetcher, "_opener", side_effect=AssertionError("urllib was used"))

    def test_a_fetch_goes_native(self):
        f = self.fetcher()
        with self.no_urllib(f):
            body, headers = f.fetch(self.url("/ok"), max_bytes=100)
            self.assertEqual((body, headers.get("x-test"), headers.get("X-TEST")), (b"hello", "1", "1"))
            self.assertEqual(f.json(self.url("/json")), {"a": [1, 2]})

    def test_a_download_to_a_file(self):
        f = self.fetcher()
        with tempfile.TemporaryDirectory() as d, self.no_urllib(f):
            path = os.path.join(d, "x")
            size, sha = f.fetch_to_file(self.url("/size/300000"), path, 300_000)
            self.assertEqual((size, sha), (300_000, hashlib.sha256(b"x" * 300_000).hexdigest()))
            with self.assertRaises(guard.TooLarge):
                f.fetch_to_file(self.url("/size/300001"), path, 300_000)
        with self.assertRaises(guard.TooLarge):
            f.fetch(self.url("/size/5001"), max_bytes=5000)

    def test_the_fetchers_hosts_hold_on_a_redirect(self):
        f = self.fetcher()
        with self.no_urllib(f):
            self.assertEqual(f.get(self.url("/in"), max_bytes=100), b"hello")
            with self.assertRaises(repo.FetchError) as caught:
                f.get(self.url("/out"), max_bytes=100)          # (to 127.0.0.1: a host the fetcher does not name)
            self.assertIn("redirect blocked", str(caught.exception))
        f = self.fetcher(https_redirects=True)
        with self.no_urllib(f):
            self.assertEqual(f.get(self.url("/out"), max_bytes=100), b"hello", "any https host on a redirect")

    def test_a_status_is_the_fetchers_error(self):
        f = self.fetcher()
        with self.no_urllib(f), self.assertRaises(repo.FetchError) as caught:
            f.get(self.url("/missing"), max_bytes=100)
        self.assertEqual(caught.exception.status, 404)

    def test_credentials_stay_on_urllib(self):
        auth = pmsettings.Credentials()
        f = self.fetcher(auth=auth)

        class Opener:
            def open(self, req, timeout=None):
                raise urllib.error.URLError("the urllib path")

        with mock.patch.object(auth, "header", lambda url: "Bearer t0ken"), \
                mock.patch.object(f, "_opener", lambda url: Opener()), self.assertRaises(repo.FetchError) as caught:
            f.get(self.url("/ok"), max_bytes=100)
        self.assertIn("the urllib path", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
