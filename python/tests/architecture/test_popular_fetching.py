"""scripts/popular/fetching.py: how popular.py and packaged.py fetch. Its Opener is urllib's urlopen on Lazaret's
native client, run here against a local HTTPS server of Python's ssl (tests.scanner.test_nativenet's): a body read
as urllib reads it, the host rule on every redirect, a download never asked for compressed, a status or a failure as
the OSErrors urllib raises, and urllib's opener used where the native client is not. `each` runs work N at a time
and gives the results in order."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from lazaret.scanner import nativenet
from tests import _support
from tests.scanner.test_nativenet import NO_PROXY_ENV, make_pki, serve

fetching = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "popular", "fetching.py"),
                                "popular_fetching")


class Fallback:
    """urllib's opener as a test sees it: what it was asked for."""

    def __init__(self):
        self.asked = []

    def __call__(self, req, timeout=None):
        self.asked.append(req.full_url)
        return contextlib.closing(io.BytesIO(b"from urllib"))


def request(url, **marks):
    req = urllib.request.Request(url, headers={"User-Agent": "lazaret-test"})
    for name, value in marks.items():
        setattr(req, name, value)
    return req


@unittest.skipUnless(shutil.which("openssl"), "no openssl command to make the test's certificates with")
class NativeOpenerTests(unittest.TestCase):
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
        cls.env = mock.patch.dict(os.environ, NO_PROXY_ENV, clear=True)
        cls.env.start()

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.server.stop()
        nativenet.configure_roots(None)
        cls.tmp.cleanup()

    def setUp(self):
        self.fallback = Fallback()
        self.opener = fetching.Opener([f"localhost:{self.port}"], self.fallback)

    def url(self, path):
        return f"https://localhost:{self.port}{path}"

    def test_a_body_read_as_urllib_reads_it(self):
        with self.opener(request(self.url("/size/300000"), download=True, max_bytes=300_001), timeout=10) as resp:
            first = resp.read(100_000)                              # n bytes unless the body ends first
            rest = resp.read()
        self.assertEqual((len(first), len(rest), first + rest), (100_000, 200_000, b"x" * 300_000))
        with self.opener(request(self.url("/ok")), timeout=10) as resp:
            self.assertEqual(resp.read(1000), b"hello")
        self.assertEqual(self.fallback.asked, [])                   # all of it natively

    def test_a_download_is_asked_for_as_published_and_a_document_compressed(self):
        with self.opener(request(self.url("/headers"), download=True), timeout=10) as resp:
            sent = json.loads(resp.read())
        self.assertEqual(sent["user-agent"], "lazaret-test")
        self.assertNotIn("gzip", sent.get("accept-encoding", ""))
        with self.opener(request(self.url("/headers"), max_bytes=1 << 20), timeout=10) as resp:
            self.assertIn("gzip", json.loads(resp.read()).get("accept-encoding", ""))

    def test_failures_are_urllibs_oserrors(self):
        with self.assertRaises(urllib.error.HTTPError) as caught:
            self.opener(request(self.url("/missing")), timeout=10)
        self.assertEqual(caught.exception.code, 404)
        with self.assertRaisesRegex(urllib.error.URLError, "refused"):    # a redirect to a host not in the rule
            self.opener(request(self.url("/out")), timeout=10)
        with self.assertRaisesRegex(urllib.error.URLError, "too-large"):
            self.opener(request(self.url("/size/5001"), download=True, max_bytes=5000), timeout=10).read()
        for exc in (urllib.error.HTTPError, urllib.error.URLError):
            self.assertTrue(issubclass(exc, OSError))

    def test_urllib_where_the_native_client_is_not_used(self):
        with mock.patch.dict(os.environ, {nativenet.ENV: "python"}):
            with self.opener(request(self.url("/ok")), timeout=10) as resp:
                self.assertEqual(resp.read(), b"from urllib")
        with mock.patch.object(fetching, "native", return_value=None), \
                self.opener(request(self.url("/ok")), timeout=10) as resp:
            self.assertEqual(resp.read(), b"from urllib")
        self.assertEqual(self.fallback.asked, [self.url("/ok")] * 2)

    def test_threads_fetch_at_once(self):
        def one(n):
            with self.opener(request(self.url(f"/size/{1000 + n}"), download=True), timeout=10) as resp:
                return len(resp.read())
        self.assertEqual(fetching.each(range(12), one, 4), [1000 + n for n in range(12)])


class EachTests(unittest.TestCase):
    def test_results_in_order_and_progress_counted(self):
        seen, lock, running, most = [], threading.Lock(), [0], [0]

        def work(n):
            with lock:
                running[0] += 1
                most[0] = max(most[0], running[0])
            time.sleep(0.01 * (5 - n % 5))                          # later items finish first
            with lock:
                running[0] -= 1
            return n * n
        self.assertEqual(fetching.each(range(10), work, 3, seen.append), [n * n for n in range(10)])
        self.assertEqual(seen, list(range(1, 11)))
        self.assertLessEqual(most[0], 3)
        self.assertGreater(most[0], 1)
        seen.clear()
        self.assertEqual(fetching.each([1, 2], lambda n: -n, 1, seen.append), [-1, -2])
        self.assertEqual(seen, [1, 2])

    def test_an_error_in_work_is_raised(self):
        def work(n):
            if n == 3:
                raise ValueError("three")
            return n
        with self.assertRaisesRegex(ValueError, "three"):
            fetching.each(range(6), work, 2)


if __name__ == "__main__":
    unittest.main()
