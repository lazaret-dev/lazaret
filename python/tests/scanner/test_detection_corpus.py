"""Detection against the private samples corpus (lazaret-dev/lazaret-samples).

Skipped unless LAZARET_SAMPLES_DIR points at a checkout of that repository.
Every sample is listed in its manifest.json with a SHA-256, the language to
scan it as, and the rule IDs the scanner must report. Samples are defanged
and stored so nothing can execute them; this test only reads them.

manifest.json (JSON rather than TOML: reading TOML on Python 3.10 would need
a third-party parser):

    {"samples": [
      {"id": "install-hook-001", "path": "synthetic/install-hook/001.js.txt",
       "sha256": "…", "lang": "js", "category": "install-hook",
       "source": "synthetic", "expect": ["SC-HOOK"]}
    ]}
"""

import hashlib
import json
import os
import unittest

from lazaret.scanner import core as lazaret
from tests import _support

SAMPLES = os.environ.get("LAZARET_SAMPLES_DIR")


@_support.requires_env("LAZARET_SAMPLES_DIR")
class DetectionCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(SAMPLES, "manifest.json"), encoding="utf-8") as f:
            cls.samples = json.load(f)["samples"]

    def read(self, sample):
        path = os.path.realpath(os.path.join(SAMPLES, sample["path"]))
        self.assertTrue(path.startswith(os.path.realpath(SAMPLES) + os.sep), f"path escapes corpus: {sample['path']}")
        with open(path, "rb") as f:
            data = f.read()
        self.assertEqual(hashlib.sha256(data).hexdigest(), sample["sha256"], f"{sample['id']}: hash mismatch")
        return data.decode("utf-8", errors="replace")

    def test_manifest_is_well_formed(self):
        required = {"id", "path", "sha256", "lang", "category", "source", "expect"}
        ids = [s["id"] for s in self.samples]
        self.assertEqual(len(ids), len(set(ids)), "duplicate sample ids")
        for sample in self.samples:
            with self.subTest(sample=sample.get("id")):
                self.assertEqual(required - set(sample), set())
                self.assertIn(sample["lang"], {"py", "js", "sql"})

    def test_every_sample_is_detected(self):
        for sample in self.samples:
            with self.subTest(sample=sample["id"]):
                content = self.read(sample)
                found = {issue["rule"] for issue in lazaret.scan_file(sample["path"], content, sample["lang"])}
                missing = set(sample["expect"]) - found
                self.assertEqual(missing, set(), f"{sample['id']} not flagged for {sorted(missing)}")


if __name__ == "__main__":
    unittest.main()
