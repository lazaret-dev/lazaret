"""PyPI release files that are not scanned, and how they are counted.

- Three of four wheels left out by the download budget were reported as
  "1 part not fully scanned": `truncated` counted the SC-TRUNCATED findings,
  one per reason, not the files. It counts files now.
- pip 24 unpacks .tlz, .tar.lz and .tar.lzma sdists (its XZ_EXTENSIONS,
  opened with tarfile's "r:xz", i.e. lzma's FORMAT_AUTO), but
  pypi_container() returned None for them, and resolve_pypi's list of files
  it did not select (Resolution.skipped) was never reported: a release
  whose sdist was x-1.0.tar.lzma scanned only its wheel and said OK with
  skippedArtifacts []. Those archives are scanned now, and every file of the
  release that is not scanned is listed; one pip may install anyway (an
  archive PyPI lists as bdist_dumb) makes the release INCOMPLETE.

All archives are built in memory from inert text; the network seam
(http_json / http_bytes) is patched, nothing is fetched.
"""

import gzip
import hashlib
import lzma
import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import DECODE_EXEC_PY, issues, scan_bytes, tarball, zipball

# pip 24.0, pip/_internal/utils/filetypes.py: every name pip unpacks
PIP_ARCHIVE_EXTENSIONS = (".zip", ".whl", ".tar.bz2", ".tbz", ".tar.gz", ".tgz", ".tar",
                          ".tar.xz", ".txz", ".tlz", ".tar.lz", ".tar.lzma")
SETUP_EVIL = {"setup.py": "from setuptools import setup\n" + DECODE_EXEC_PY + "setup(name='x')\n"}
SETUP_CLEAN = {"setup.py": "from setuptools import setup\nsetup(name='x')\n"}


def raw_sdist(files):
    return tarball(files, root="x-1.0/", compress=False)


def release(files, version="1.0"):
    """files: [(filename, data, packagetype, declared size or None)] ->
    (metadata document, {url: bytes})."""
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
        return repo.scan_package("pypi", "x", "1.0", **kw), fetched


def wheel(i):
    return zipball({"x/__init__.py": f"V = {i}\n"})


class SkippedFileCountTests(unittest.TestCase):
    def test_each_skipped_file_is_one_part(self):
        meta, blobs = release([(f"x-1.0-cp31{i}-none-any.whl", wheel(i), "bdist_wheel", 1000)
                               for i in range(4)])
        res, fetched = run_scan(meta, blobs, max_download_bytes=1500)
        self.assertEqual(len(fetched), 1)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertEqual(res["truncated"], 3)
        self.assertIn("3 parts not fully scanned", res["verdictReason"])
        self.assertIn("3 of 4 release files not scanned", res["verdictReason"])
        # still one finding per reason
        self.assertEqual(len([i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]), 1)

    def test_files_skipped_for_different_reasons_add_up(self):
        meta, blobs = release([("x-1.0-cp310-none-any.whl", wheel(0), "bdist_wheel", 100),
                               ("x-1.0-cp311-none-any.whl", wheel(1), "bdist_wheel",
                                repo.MAX_DOWNLOAD_BYTES + 1),
                               ("x-1.0-cp312-none-any.whl", wheel(2), "bdist_wheel", 5000),
                               ("x-1.0-cp313-none-any.whl", wheel(3), "bdist_wheel", 5000)])
        res, _ = run_scan(meta, blobs, max_download_bytes=1000)
        self.assertEqual(sorted(s["reason"] for s in res["skippedArtifacts"]),
                         ["budget", "budget", "filesize"])
        self.assertEqual(res["truncated"], 3)
        self.assertIn("3 parts not fully scanned", res["verdictReason"])


class LzmaSdistTests(unittest.TestCase):
    def test_every_archive_name_pip_unpacks_has_a_container(self):
        for ext in PIP_ARCHIVE_EXTENSIONS:
            with self.subTest(ext=ext):
                self.assertIsNotNone(repo.pypi_container("x-1.0" + ext))
        for name in ("x-1.0.tlz", "x-1.0.tar.lz", "x-1.0.tar.lzma", "X-1.0.TAR.LZMA"):
            self.assertEqual(repo.pypi_container(name), "tlz")
        self.assertIsNone(repo.pypi_container("x-1.0-py3.8.egg"))

    def scan(self, data, container="tlz"):
        return scan_bytes(data, container=container, artifact="sdist", eco="pypi")

    def test_legacy_lzma_and_xz_streams_are_read(self):
        raw = raw_sdist(SETUP_EVIL)
        for fmt in (lzma.FORMAT_ALONE, lzma.FORMAT_XZ):
            with self.subTest(fmt=fmt):
                res = self.scan(lzma.compress(raw, format=fmt))
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
                self.assertEqual(res["filesScanned"], 1)
        res = self.scan(lzma.compress(raw_sdist(SETUP_CLEAN), format=lzma.FORMAT_ALONE))
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_concatenated_streams_are_all_read(self):
        # LZMAFile (so pip) reads on into the next stream; the payload is in the second
        raw = raw_sdist({"README": "x\n" * 300, **SETUP_EVIL})
        cut = 1024
        data = lzma.compress(raw[:cut], format=lzma.FORMAT_ALONE) + lzma.compress(raw[cut:])
        self.assertEqual(self.scan(data)["verdict"], "SUSPICIOUS")

    def test_other_codecs_and_trailing_data_are_incomplete(self):
        raw = raw_sdist(SETUP_CLEAN)
        res = self.scan(gzip.compress(raw))
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertTrue(any("gz-compressed" in i["msg"] for i in issues(res, "SC-TRUNCATED")))
        res = self.scan(lzma.compress(raw, format=lzma.FORMAT_ALONE) + b"not a stream" * 20)
        self.assertEqual(res["verdict"], "INCOMPLETE")

    def test_a_tar_lzma_sdist_on_pypi_is_scanned(self):
        sdist = lzma.compress(raw_sdist(SETUP_EVIL), format=lzma.FORMAT_ALONE)
        meta, blobs = release([("x-1.0.tar.lzma", sdist, "sdist", None),
                               ("x-1.0-py3-none-any.whl", wheel(1), "bdist_wheel", None)])
        res, fetched = run_scan(meta, blobs)
        self.assertEqual(len(fetched), 2)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual([a["filename"] for a in res["artifacts"]],
                         ["x-1.0.tar.lzma", "x-1.0-py3-none-any.whl"])
        self.assertEqual(res["skippedArtifacts"], [])


class UnselectedReleaseFileTests(unittest.TestCase):
    def test_files_pip_does_not_install_are_listed_not_counted(self):
        meta, blobs = release([("x-1.0-py3-none-any.whl", wheel(1), "bdist_wheel", None),
                               ("x-1.0-py3.8.egg", b"egg", "bdist_egg", 3),
                               ("x-1.0.win32.exe", b"exe", "bdist_wininst", None)])
        res, fetched = run_scan(meta, blobs)
        self.assertEqual(len(fetched), 1)
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        self.assertEqual(res["truncated"], 0)
        self.assertEqual(res["skippedArtifacts"],
                         [{"filename": "x-1.0-py3.8.egg", "reason": "not-installable", "declaredBytes": 3},
                          {"filename": "x-1.0.win32.exe", "reason": "not-installable",
                           "declaredBytes": None}])

    def test_an_archive_pip_may_install_is_counted(self):
        dumb = tarball({"x/__init__.py": "V = 1\n"}, root="usr/")
        meta, blobs = release([("x-1.0-py3-none-any.whl", wheel(1), "bdist_wheel", None),
                               ("x-1.0.linux-x86_64.tar.gz", dumb, "bdist_dumb", 700)])
        res, fetched = run_scan(meta, blobs)
        self.assertEqual(len(fetched), 1)
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertEqual(res["truncated"], 1)
        self.assertEqual(res["skippedArtifacts"],
                         [{"filename": "x-1.0.linux-x86_64.tar.gz", "reason": "packagetype",
                           "declaredBytes": 700}])
        self.assertIn("1 of 2 release files not scanned", res["verdictReason"])
        (msg,) = [i["msg"] for i in issues(res, "SC-TRUNCATED")]
        self.assertIn("x-1.0.linux-x86_64.tar.gz", msg)

    def test_resolution_marks_what_pip_may_install(self):
        meta, _ = release([("x-1.0-py3-none-any.whl", wheel(1), "bdist_wheel", None),
                           ("x-1.0.linux-x86_64.zip", b"z", "bdist_dumb", None),
                           ("x-1.0-py3.8.egg", b"egg", "bdist_egg", None)])
        with mock.patch.object(repo, "http_json", return_value=meta):
            resolved = repo.resolve_pypi("x", "1.0")
        self.assertEqual([(s["filename"], s["installable"]) for s in resolved.skipped],
                         [("x-1.0.linux-x86_64.zip", True), ("x-1.0-py3.8.egg", False)])


if __name__ == "__main__":
    unittest.main()
