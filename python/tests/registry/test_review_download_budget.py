"""Final-review item 1: scanning every PyPI artifact made popular packages
permanently INCOMPLETE. With the old default of 50 artifacts per release,
numpy (66 files), pillow (87) and grpcio (61) could never be cleared, so
`--ci` always failed on them. The default is now 200 artifacts, and the real
cost bound is a per-package DOWNLOAD budget (--max-download-bytes /
LAZARET_MAX_DOWNLOAD_BYTES, default 2 GiB): it is checked BEFORE each
download against the size PyPI's metadata declares, so a file that cannot
fit is never fetched. Files left out make the verdict INCOMPLETE with a
reason that names the budget; digests are still verified per artifact.

All archives are built in memory from inert text; the network seam
(http_json / http_bytes) is patched, nothing is fetched.
"""

import contextlib
import hashlib
import io
import os
import subprocess
import sys
import time
import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import DECODE_EXEC_PY, zipball


def release(files, version="1.0"):
    """files: [(filename, data, packagetype, declared_size or None)] ->
    (metadata document, {url: bytes}, fetched urls list)."""
    urls, blobs = [], {}
    for filename, data, kind, size in files:
        entry = {"filename": filename, "packagetype": kind,
                 "url": f"https://files.pythonhosted.org/packages/xx/{filename}",
                 "digests": {"sha256": hashlib.sha256(data).hexdigest()}}
        if size is not None:
            entry["size"] = size
        urls.append(entry)
        blobs[entry["url"]] = data
    return {"info": {"version": version}, "urls": urls}, blobs


def run_scan(meta, blobs, **kw):
    fetched = []

    def http_bytes(url):
        fetched.append(url)
        return blobs[url]
    with mock.patch.object(repo, "http_json", return_value=meta), \
            mock.patch.object(repo, "http_bytes", side_effect=http_bytes):
        res = repo.scan_package("pypi", "x", "1.0", **kw)
    return res, fetched


def wheel(i, text=None):
    return zipball({"x/__init__.py": text if text is not None else f"V = {i}\n"})


class DefaultsTests(unittest.TestCase):
    @unittest.skipIf("LAZARET_MAX_ARTIFACTS" in os.environ, "overridden in the environment")
    def test_default_artifact_limit_fits_popular_binary_packages(self):
        # numpy 66, grpcio 61, pillow 87 files per release (live PyPI, 2026)
        self.assertEqual(repo.MAX_ARTIFACTS, 200)

    @unittest.skipIf("LAZARET_MAX_DOWNLOAD_BYTES" in os.environ, "overridden in the environment")
    def test_default_download_budget_is_2_gib(self):
        self.assertEqual(repo.MAX_PACKAGE_DOWNLOAD_BYTES, 2 * 1024 ** 3)

    def test_a_release_with_87_files_is_ok_under_the_defaults(self):
        files = [(f"x-1.0-cp3{i:02d}-none-any.whl", wheel(i), "bdist_wheel", None) for i in range(87)]
        meta, blobs = release(files)
        res, fetched = run_scan(meta, blobs)
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        self.assertEqual(len(fetched), 87)
        self.assertEqual(len(res["artifacts"]), 87)
        self.assertEqual(res["skippedArtifacts"], [])

    def test_env_variable_sets_the_budget(self):
        env = dict(os.environ, LAZARET_MAX_DOWNLOAD_BYTES="12345")
        out = subprocess.run(
            [sys.executable, "-c", "from lazaret.registry import repo; "
                                   "print(repo.MAX_PACKAGE_DOWNLOAD_BYTES)"],
            capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(out.stdout.strip(), "12345", out.stderr)


class BudgetTests(unittest.TestCase):
    def test_files_past_the_budget_are_never_downloaded(self):
        a, b, c = wheel(1), wheel(2), wheel(3)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", a, "bdist_wheel", 600),
                               ("x-1.0-cp311-none-any.whl", b, "bdist_wheel", 600),
                               ("x-1.0-cp312-none-any.whl", c, "bdist_wheel", 600)])
        res, fetched = run_scan(meta, blobs, max_download_bytes=1000)
        self.assertEqual(len(fetched), 1)                      # checked BEFORE downloading
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("download budget", res["verdictReason"])
        self.assertIn("--max-download-bytes", res["verdictReason"])
        self.assertIn("2 of 3 release files not scanned", res["verdictReason"])
        self.assertEqual([(s["filename"], s["reason"]) for s in res["skippedArtifacts"]],
                         [("x-1.0-cp311-none-any.whl", "budget"),
                          ("x-1.0-cp312-none-any.whl", "budget")])
        trunc = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(len(trunc), 1)
        self.assertIn("download budget", trunc[0]["msg"])
        self.assertIn("x-1.0-cp311-none-any.whl", trunc[0]["msg"])

    def test_a_smaller_later_file_still_fits(self):
        big, small = wheel(1), wheel(2)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", big, "bdist_wheel", 900),
                               ("x-1.0-cp311-none-any.whl", big, "bdist_wheel", 900),
                               ("x-1.0-cp312-none-any.whl", small, "bdist_wheel", 50)])
        # identical digests are scanned once: give the second "big" its own bytes
        meta["urls"][1]["digests"]["sha256"] = hashlib.sha256(b"other").hexdigest()
        res, fetched = run_scan(meta, blobs, max_download_bytes=1000)
        self.assertEqual([u.rsplit("/", 1)[1] for u in fetched],
                         ["x-1.0-cp310-none-any.whl", "x-1.0-cp312-none-any.whl"])
        self.assertEqual(res["verdict"], "INCOMPLETE")

    def test_undeclared_sizes_are_charged_as_they_download(self):
        a, b, c = wheel(1), wheel(2), wheel(3)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", a, "bdist_wheel", None),
                               ("x-1.0-cp311-none-any.whl", b, "bdist_wheel", None),
                               ("x-1.0-cp312-none-any.whl", c, "bdist_wheel", None)])
        res, fetched = run_scan(meta, blobs, max_download_bytes=len(a) + len(b))
        self.assertEqual(len(fetched), 2)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertEqual(res["skippedArtifacts"][0]["reason"], "budget")

    def test_a_file_over_the_per_file_limit_is_not_fetched(self):
        a, b = wheel(1), wheel(2)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", a, "bdist_wheel", len(a)),
                               ("x-1.0-cp311-manylinux.whl", b, "bdist_wheel",
                                repo.MAX_DOWNLOAD_BYTES + 1)])
        res, fetched = run_scan(meta, blobs)
        self.assertEqual(len(fetched), 1)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("per-file", res["verdictReason"])
        self.assertEqual(res["skippedArtifacts"][0]["reason"], "filesize")
        self.assertTrue(any("per-file download limit" in i["msg"] for i in res["issues"]))

    def test_a_hostile_file_inside_the_budget_is_still_suspicious(self):
        evil, clean = wheel(1, DECODE_EXEC_PY), wheel(2)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", evil, "bdist_wheel", len(evil)),
                               ("x-1.0-cp311-none-any.whl", clean, "bdist_wheel", 10 ** 9)])
        res, _ = run_scan(meta, blobs, max_download_bytes=len(evil) + 10)
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("1 of 2 release files not scanned", res["verdictReason"])

    def test_digest_is_still_verified_per_file(self):
        a, b = wheel(1), wheel(2)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", a, "bdist_wheel", len(a)),
                               ("x-1.0-cp311-none-any.whl", b, "bdist_wheel", len(b))])
        blobs[meta["urls"][1]["url"]] = wheel(1, DECODE_EXEC_PY)     # swapped on the CDN
        with self.assertRaises(repo.DigestError):
            run_scan(meta, blobs)

    def test_bogus_declared_sizes_are_ignored(self):
        a = wheel(1)
        for size in (-1, True, "600", 1.5):
            with self.subTest(size=size):
                meta, blobs = release([("x-1.0-cp310-none-any.whl", a, "bdist_wheel", size)])
                res, fetched = run_scan(meta, blobs)
                self.assertEqual(len(fetched), 1)
                self.assertEqual(res["verdict"], "OK")

    def test_every_file_left_out(self):
        a, b = wheel(1), wheel(2)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", a, "bdist_wheel", 5000),
                               ("x-1.0-cp311-none-any.whl", b, "bdist_wheel", 5000)])
        res, fetched = run_scan(meta, blobs, max_download_bytes=1000)
        self.assertEqual(fetched, [])
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertEqual(res["artifacts"], [])
        self.assertEqual(res["archiveBytes"], 0)

    def test_deadline_and_cancel_are_checked_before_each_download(self):
        a, b = wheel(1), wheel(2)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", a, "bdist_wheel", None),
                               ("x-1.0-cp311-none-any.whl", b, "bdist_wheel", None)])
        res, fetched = run_scan(meta, blobs, deadline=time.monotonic() - 1)
        self.assertEqual(fetched, [])
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("time budget", res["verdictReason"])
        self.assertTrue(any(i["rule"] == "SC-TRUNCATED" for i in res["issues"]))
        with self.assertRaises(repo.ScanCancelled):
            run_scan(meta, blobs, cancel=lambda: True)


class CliTests(unittest.TestCase):
    def test_max_download_bytes_flag(self):
        a, b = wheel(1), wheel(2)
        meta, blobs = release([("x-1.0-cp310-none-any.whl", a, "bdist_wheel", 600),
                               ("x-1.0-cp311-none-any.whl", b, "bdist_wheel", 600)])
        saved = repo.MAX_PACKAGE_DOWNLOAD_BYTES
        self.addCleanup(setattr, repo, "MAX_PACKAGE_DOWNLOAD_BYTES", saved)
        import tempfile
        # main() leaves its Store open (the traceback keeps it alive): on
        # Windows the database file can't be removed until it is collected
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
            argv = ["lazaret-registry", "scan", "pypi:x@1.0", "--db", os.path.join(d, "r.db"),
                    "--max-download-bytes", "1000", "--ci"]
            with mock.patch.object(repo, "http_json", return_value=meta), \
                    mock.patch.object(repo, "http_bytes", side_effect=blobs.__getitem__), \
                    mock.patch("sys.argv", argv), \
                    contextlib.redirect_stdout(io.StringIO()) as out, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    repo.main()
        self.assertEqual(cm.exception.code, 1)                 # INCOMPLETE fails --ci
        self.assertIn("INCOMPLETE", out.getvalue())
        self.assertIn("download budget", out.getvalue())
        self.assertEqual(repo.MAX_PACKAGE_DOWNLOAD_BYTES, 1000)


if __name__ == "__main__":
    unittest.main()
