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
       "source": "synthetic", "defanged": true, "expect": ["SC-INSTALL-HOOK"]}
    ]}

The same manifest is checked by the JavaScript engine's corpus test
(js/test/corpus.test.js), so both engines must flag every sample.
"""

import hashlib
import json
import os
import unittest

from lazaret.scanner import core as lazaret
from tests import _support

SAMPLES = os.environ.get("LAZARET_SAMPLES_DIR")
REQUIRED = {"id", "path", "sha256", "lang", "category", "source", "defanged", "expect"}
CATEGORIES = {"typosquat", "install-hook", "obfuscation", "secrets",
              "taint-sql", "taint-command", "exfiltration"}


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
        ids = [s["id"] for s in self.samples]
        self.assertEqual(len(ids), len(set(ids)), "duplicate sample ids")
        for sample in self.samples:
            with self.subTest(sample=sample.get("id")):
                self.assertEqual(REQUIRED - set(sample), set())
                self.assertIn(sample["lang"], {"py", "js", "sql"})
                self.assertIn(sample["category"], CATEGORIES)
                self.assertIs(sample["defanged"], True, "every sample must be defanged")

    def test_every_sample_on_disk_is_listed(self):
        root = os.path.realpath(SAMPLES)
        listed = {os.path.normpath(s["path"]).replace(os.sep, "/") for s in self.samples}
        on_disk = set()
        for top in ("synthetic", "real"):
            for dirpath, _, files in os.walk(os.path.join(root, top)):
                for name in files:
                    if name == ".gitkeep" or name.startswith("README"):
                        continue
                    on_disk.add(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
        self.assertEqual(sorted(on_disk - listed), [], "samples on disk but not in manifest.json")

    def test_every_sample_is_detected(self):
        for sample in self.samples:
            with self.subTest(sample=sample["id"]):
                content = self.read(sample)
                found = {issue["rule"] for issue in lazaret.scan_file(sample["path"], content, sample["lang"])}
                missing = set(sample["expect"]) - found
                self.assertEqual(missing, set(), f"{sample['id']} not flagged for {sorted(missing)}")


if __name__ == "__main__":
    unittest.main()
