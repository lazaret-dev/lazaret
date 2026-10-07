"""The guard's fetcher on the native transport (0.1.9, NET-1): an https request goes through the native library's
client, with the fetcher's hosts as the rule for every redirect and its credentials given hop by hop, each to its own
host (decision 14); plain http, and a credential the native client cannot send, stay on urllib. Against a local HTTPS
server of Python's ssl, as tests.scanner.test_nativenet's."""

import hashlib
import os
import shutil
import ssl
import tempfile
import time
import unittest
import urllib.error
import urllib.request
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

    def trusting_the_root(self):
        """urllib's default context trusting the test's root: PEP 476's hook, which Python's transport builds its
        context on (nativenet.tls_context), with the floor of TLS 1.2."""
        return mock.patch.object(ssl, "_create_default_https_context", lambda: ssl.create_default_context(cadata=self.root))

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

    def test_a_download_that_drips_past_the_deadline_stops(self):
        # (the native transport's total timeout is the guard's download deadline: GR-3)
        f = self.fetcher()
        with self.no_urllib(f), mock.patch.dict(os.environ, {"LAZARET_GUARD_DOWNLOAD_SECONDS": "1"}):
            started = time.monotonic()
            with self.assertRaises(repo.FetchError):
                f.get(self.url("/drip"), timeout=5)
            self.assertLess(time.monotonic() - started, 3.5)

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

    def test_credentials_go_native_each_to_its_own_host(self):
        # (decision 14: the settings' credentials of each hop's URL, the URL's own user:password with the request
        # alone, as urllib's redirect hook gives them; tiny_https's hop hook, never a header a redirect carries on)
        auth = pmsettings.Credentials()
        auth.token(self.url("/"), "t0ken")
        auth.token(self.url("/team/"), "team-t0ken")
        f = self.fetcher(auth=auth, https_redirects=True)
        with self.no_urllib(f):
            self.assertEqual(f.json(self.url("/headers")).get("authorization"), "Bearer t0ken")
            self.assertEqual(f.json(self.url("/to-headers")).get("authorization"), "Bearer t0ken", "the same host")
            self.assertNotIn("authorization", f.json(self.url("/out-headers")), "another host (127.0.0.1)")
            own = f.json(f"https://user:pw@{self.host}/headers")
            self.assertEqual(own.get("authorization"), pmsettings.basic("user", "pw"), "the URL's own, before the settings'")
            after = f.json(f"https://user:pw@{self.host}/to-headers")
            self.assertEqual(after.get("authorization"), "Bearer t0ken", "a redirect: the settings', never the URL's own")
        plain = self.fetcher()
        with self.no_urllib(plain):
            self.assertNotIn("authorization", plain.json(self.url("/headers")), "a fetcher without credentials")

    def test_a_credential_goes_with_a_path_it_covers_however_the_server_reads_it(self):
        # (the credentials review of decision 14: a token for /team/ went with /team/../x, which a server reads as /x,
        # and a path that starts with "//" sent the choice round forever.) The request's own URL is sent with its dot
        # segments resolved, on both transports, and its credentials are chosen by it; a redirect's path urllib
        # resolves too, and tiny_https sends as the Location gives it, so a credential goes with it when both of its
        # readings are under the credential's path (lazaret-net's `granted`)
        auth = pmsettings.Credentials()
        auth.token(self.url("/team/"), "team-t0ken")
        team = "Bearer team-t0ken"
        cases = [  # path asked for: (what the server saw, the credential) on the native transport, then on urllib
            ("/team/../echo", ("/echo", None), ("/echo", None)),
            ("/team/%2e%2e/echo", ("/echo", None), ("/echo", None)),
            ("/x/../team/echo", ("/team/echo", team), ("/team/echo", team)),
            ("//team/echo", ("/team/echo", None), ("/team/echo", None)),
            ("/to-dots", ("/team/../echo", None), ("/echo", None)),                 # Location: /team/../echo
            ("/to-abs-dots", ("/team/%2e%2e/echo", None), ("/echo", None)),         # Location: https://…/team/%2e%2e/echo
            ("/to-into-team", ("/x/../team/echo", None), ("/team/echo", team)),     # Location: https://…/x/../team/echo
            ("/team/..%2fx/echo", ("/team/..%2fx/echo", None), ("/team/..%2fx/echo", None)),   # (/x/echo to nginx)
            ("/team/..;/echo", ("/team/..;/echo", None), ("/team/..;/echo", None)),       # (/echo to Tomcat)
        ]
        for python in (False, True):
            f = self.fetcher(auth=auth)
            with mock.patch.dict(os.environ, {nativenet.ENV: "python"} if python else {}), self.trusting_the_root():
                for path, native, by_urllib in cases:
                    with self.subTest(path=path, python=python):
                        if python:
                            seen = f.json(self.url(path))
                        else:
                            with self.no_urllib(f):
                                seen = f.json(self.url(path))
                        # (http.server reads a path that starts with "//" as one that starts with "/")
                        self.assertEqual(("/" + seen["path"].lstrip("/"), seen.get("authorization")),
                                         by_urllib if python else native)

    def test_a_redirect_from_another_origin_gets_a_credential_of_the_whole_host_only(self):
        # (the second review of decision 14's credentials: any host the guard fetches from can redirect to one that has
        # a token for a path; npm sends none on a redirect to another host, and pip a .netrc login for it)
        start = f"https://127.0.0.1:{self.port}/to-localhost/team/echo"
        for whole, want in ((False, None), (True, "Bearer wh0le")):
            auth = pmsettings.Credentials()
            auth.token(self.url("/team/"), "team-t0ken")
            if whole:
                auth.token(self.url("/"), "wh0le")
            for python in (False, True):
                f = guard.Fetcher([self.host, f"127.0.0.1:{self.port}"], auth=auth)
                self.addCleanup(f.close)
                with self.subTest(whole=whole, python=python), \
                        mock.patch.dict(os.environ, {nativenet.ENV: "python"} if python else {}), \
                        self.trusting_the_root():
                    if python:
                        seen = f.json(start)
                    else:
                        with self.no_urllib(f):
                            seen = f.json(start)
                    self.assertEqual((seen["path"], seen.get("authorization")), ("/team/echo", want))
                    self.assertEqual(f.json(self.url("/team/echo")).get("authorization"), "Bearer team-t0ken",
                                     "the request itself, and a redirect on its own origin, get the path's")

    def test_one_host_the_native_rule_cannot_read_does_not_stop_the_others(self):
        # (the credentials review of decision 14: a link of an index page let into the fetcher made every later native
        # request fail with "invalid host rule")
        f = self.fetcher()
        f.allow("https://files.example.invalid:+1/pkg-1.0-py3-none-any.whl")
        f.allow("https://*.example.invalid/pkg-1.0-py3-none-any.whl")
        with self.no_urllib(f):
            self.assertEqual(f.get(self.url("/ok"), max_bytes=100), b"hello")
            with self.assertRaises(repo.FetchError):
                f.get("https://files.example.invalid:+1/pkg-1.0-py3-none-any.whl", max_bytes=100)

    def test_a_credential_the_native_client_cannot_send_goes_through_urllib(self):
        auth = pmsettings.Credentials()
        auth.token(self.url("/"), "töken")
        f = self.fetcher(auth=auth)

        class Opener:
            def open(self, req, timeout=None):
                raise urllib.error.URLError("the urllib path")

        with mock.patch.object(f, "_opener", lambda url: Opener()), self.assertRaises(repo.FetchError) as caught:
            f.get(self.url("/ok"), max_bytes=100)
        self.assertIn("the urllib path", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
