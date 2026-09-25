"""Review finding 6: resolve_pypi scanned the sdist if there was one, else the
first wheel — but pip installs a compatible WHEEL, so the file that actually
gets installed was usually never scanned. Every file of the release pip may
install (the sdist and each distinct wheel) is now scanned, the verdict is
the worst of them, and the per-file detail is kept in the result and in the
scans.artifacts column (see test_review_store.py for the schema migration).
"""

import hashlib
import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import DECODE_EXEC_PY, tarball, zipball


def entry(filename, data, packagetype):
    return {"filename": filename, "packagetype": packagetype,
            "url": f"https://files.pythonhosted.org/packages/xx/{filename}",
            "digests": {"sha256": hashlib.sha256(data).hexdigest()}}


class Release:
    """A fake PyPI release: metadata document + artifact bytes by URL."""

    def __init__(self, files):
        self.blobs = {}
        urls = []
        for filename, data, kind in files:
            e = entry(filename, data, kind)
            self.blobs[e["url"]] = data
            urls.append(e)
        self.meta = {"info": {"version": "1.0"}, "urls": urls}
        self.fetched = []

    def http_bytes(self, url):
        self.fetched.append(url)
        return self.blobs[url]

    def scan(self, **kw):
        with mock.patch.object(repo, "http_json", return_value=self.meta), \
                mock.patch.object(repo, "http_bytes", side_effect=self.http_bytes):
            return repo.scan_package("pypi", "x", "1.0", **kw)


SDIST = tarball({"setup.py": "from setuptools import setup\nsetup(name='x')\n"}, root="x-1.0/")
CLEAN_WHEEL = zipball({"x/__init__.py": "VERSION = '1.0'\n"})
EVIL_WHEEL = zipball({"x/__init__.py": DECODE_EXEC_PY})


class AllArtifactsTests(unittest.TestCase):
    def test_hostile_wheel_behind_a_clean_sdist_is_found(self):
        rel = Release([("x-1.0.tar.gz", SDIST, "sdist"),
                       ("x-1.0-py3-none-any.whl", CLEAN_WHEEL, "bdist_wheel"),
                       ("x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", EVIL_WHEEL, "bdist_wheel")])
        res = rel.scan()
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual(len(rel.fetched), 3)
        self.assertEqual([(a["filename"], a["verdict"]) for a in res["artifacts"]],
                         [("x-1.0.tar.gz", "OK"), ("x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", "SUSPICIOUS"),
                          ("x-1.0-py3-none-any.whl", "OK")])
        hit = [i for i in res["issues"] if i["rule"] == "SC-EVAL-DECODE"][0]
        self.assertEqual(hit["file"], "x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl/x/__init__.py")
        self.assertIn("worst: x-1.0-cp312", res["verdictReason"])
        self.assertEqual(res["artifact"], "sdist+2 wheels")

    def test_identical_files_are_scanned_once_and_eggs_skipped(self):
        rel = Release([("x-1.0-py3-none-any.whl", CLEAN_WHEEL, "bdist_wheel"),
                       ("x-1.0-py2.py3-none-any.whl", CLEAN_WHEEL, "bdist_wheel"),
                       ("x-1.0-py3.8.egg", b"egg", "bdist_egg")])
        res = rel.scan()
        self.assertEqual(len(rel.fetched), 1)
        self.assertEqual(res["verdict"], "OK")
        self.assertEqual(res["artifact"], "wheel")

    def test_digest_is_verified_per_file(self):
        rel = Release([("x-1.0.tar.gz", SDIST, "sdist"),
                       ("x-1.0-py3-none-any.whl", CLEAN_WHEEL, "bdist_wheel")])
        rel.blobs[rel.meta["urls"][1]["url"]] = EVIL_WHEEL          # swapped on the CDN
        with self.assertRaises(repo.DigestError):
            rel.scan()

    def test_more_files_than_the_limit_is_incomplete(self):
        files = [(f"x-1.0-cp3{i}-none-any.whl", zipball({"x/__init__.py": f"V = {i}\n"}), "bdist_wheel")
                 for i in range(5)]
        res = Release(files).scan(max_artifacts=3)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertEqual(len(res["artifacts"]), 3)
        self.assertTrue(any("2 more release file(s)" in i["msg"] for i in res["issues"]))

    def test_resolution_keeps_the_old_tuple_shape(self):
        rel = Release([("x-1.0.tar.gz", SDIST, "sdist")])
        with mock.patch.object(repo, "http_json", return_value=rel.meta):
            resolved = repo.resolve_pypi("x", "1.0")
        version, url, container, artifact, entry_ = resolved
        self.assertEqual((version, container, artifact), ("1.0", "tgz", "sdist"))
        self.assertEqual(len(resolved.artifacts), 1)

    def test_single_npm_artifact_result_shape_unchanged(self):
        from tests.registry._review_support import scan_npm
        res = scan_npm({"index.js": "1;\n"})
        self.assertEqual(res["artifact"], "npm")
        self.assertEqual(len(res["artifacts"]), 1)
        self.assertEqual(res["issues"], [])


if __name__ == "__main__":
    unittest.main()
