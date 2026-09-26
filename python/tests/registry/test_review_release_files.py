"""PyPI release files that are not scanned, and how they are counted.

- Three of four wheels left out by the download budget were reported as
  "1 part not fully scanned": `truncated` counted the SC-TRUNCATED findings,
  one per reason, not the files. It counts files now.

All archives are built in memory from inert text; the network seam
(http_json / http_bytes) is patched, nothing is fetched.
"""

import hashlib
import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import zipball


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


if __name__ == "__main__":
    unittest.main()
