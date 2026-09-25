"""Benchmark against real, legitimate packages (needs network access).

    LAZARET_BENCHMARK=1 python -m unittest tests.registry.test_benchmark -v

All of these are legitimate, so none may be SUSPICIOUS. The expected verdicts
pin today's results: a change to OK is an improvement worth confirming, a
change to WARN/INCOMPLETE/SUSPICIOUS is a regression. Pair with the samples
corpus (tests/scanner/test_detection_corpus.py), which checks the other
direction: that malicious packages are still caught.
"""

import unittest

from lazaret.registry import repo as lazaret_repo
from tests import _support

EXPECTED = {
    # most-downloaded (PyPI and npm, 2026)
    "pypi:boto3": "OK", "pypi:packaging": "OK", "pypi:urllib3": "OK", "pypi:setuptools": "WARN",
    "pypi:certifi": "OK", "pypi:requests": "OK",
    "npm:semver": "OK", "npm:ansi-styles": "OK", "npm:debug": "OK", "npm:chalk": "OK",
    "npm:supports-color": "OK",
    # hard cases: legitimate packages that do malware-like things
    "npm:esbuild": "WARN", "npm:core-js": "WARN", "npm:puppeteer": "WARN", "npm:sharp": "OK",
    "npm:typescript": "OK", "pypi:cryptography": "OK", "pypi:numpy": "OK", "pypi:pillow": "OK",
    "pypi:pip": "WARN", "pypi:grpcio": "OK",
}


@_support.requires_env("LAZARET_BENCHMARK")
class BenchmarkTests(unittest.TestCase):
    def test_legitimate_packages(self):
        for spec, expected in EXPECTED.items():
            with self.subTest(package=spec):
                eco, name = spec.split(":", 1)
                res = lazaret_repo.scan_package(eco, name)
                self.assertNotEqual(res["verdict"], "SUSPICIOUS",
                                    f"{spec}@{res['version']}: {res['verdictReason']}")
                self.assertEqual(res["verdict"], expected,
                                 f"{spec}@{res['version']}: {res['verdictReason']}")


if __name__ == "__main__":
    unittest.main()
