"""The source-size limit and what it reports, from real discovery results.

- A CLI bundle over the old 1,000,000-byte limit (npm:pullfrog's dist/cli.mjs
  and dist/index.js, 8.0 and 7.8 MB) made every such package INCOMPLETE. The
  limit is now 16,000,000 bytes by default, and --max-source-bytes /
  LAZARET_MAX_SOURCE_BYTES change it.
- One oversized file gave up to four SC-TRUNCATED findings (its size, then
  once for each of main / bin / exports naming it) and counted as four
  "parts not fully scanned". Now: one finding per file, one part.
- The message said "(8,192 real decompressed bytes available)", which read
  as if the file were 8 KB.
- A stylesheet named in `exports` (npm:react-reason-editor's dist/style.css)
  was "code that runs at install/import time". It isn't; a file with an
  unknown extension still is (require() runs it as JavaScript).
"""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import DECODE_EXEC_JS, issues, manifest, scan_npm

LIMIT = 10_000
BIG = b"// padding\n" * 2_000                      # 22,000 bytes of harmless text


class OneFindingPerFileTests(unittest.TestCase):
    def scan(self, files):
        with mock.patch.object(repo, "MAX_MEMBER", LIMIT):
            return scan_npm(files)

    def test_an_oversized_entry_point_is_one_finding(self):
        res = self.scan({"package.json": manifest(main="dist/index.js", bin={"x": "dist/index.js"},
                                                  exports={".": "./dist/index.js"}),
                         "dist/index.js": BIG})
        found = issues(res, "SC-TRUNCATED")
        self.assertEqual(len(found), 1, [i["msg"] for i in found])
        self.assertEqual(res["truncated"], 1)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        msg = found[0]["msg"]
        self.assertIn("dist/index.js is larger than the 10,000-byte source-scan limit, so it was not "
                      "scanned (raise the limit with --max-source-bytes); it runs at install/import time.",
                      msg)
        self.assertNotIn("real decompressed bytes", msg)

    def test_an_oversized_file_that_is_not_source(self):
        # extensionless bin script: no size finding while reading, one when it turns out to run
        res = self.scan({"package.json": manifest(bin={"x": "bin/tool"}), "bin/tool": b"#!/usr/bin/env node\n" + BIG})
        found = issues(res, "SC-TRUNCATED")
        self.assertEqual([i["msg"] for i in found],
                         ["File not fully scanned: bin/tool runs at install/import time but is larger "
                          "than the 10,000-byte source-scan limit."])

    def test_exported_stylesheets_and_assets_are_not_run(self):
        res = self.scan({"package.json": manifest(main="index.js", exports={
                             ".": "./index.js", "./style.css": "./dist/style.css",
                             "./font": "./dist/icons.woff2", "./map": "./dist/index.js.map"}),
                         "index.js": b"module.exports = 1;\n",
                         "dist/style.css": BIG, "dist/icons.woff2": BIG, "dist/index.js.map": BIG})
        self.assertEqual(issues(res, "SC-TRUNCATED"), [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_an_odd_extension_named_as_code_still_runs(self):
        res = self.scan({"package.json": manifest(exports={"require": "./dist/x.cjs.txt"}),
                         "dist/x.cjs.txt": DECODE_EXEC_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")


class LimitTests(unittest.TestCase):
    def test_default_fits_a_large_bundle(self):
        self.assertGreaterEqual(repo.MAX_MEMBER, 16_000_000)
        bundle = b"var a=1;" * 250_000                 # 2 MB: INCOMPLETE under the old limit
        res = scan_npm({"package.json": manifest(main="dist/index.js"), "dist/index.js": bundle})
        self.assertEqual(issues(res, "SC-TRUNCATED"), [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_cli_option(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(repo, "MAX_MEMBER", repo.MAX_MEMBER), \
                mock.patch.object(sys, "argv", ["lazaret-registry", "list", "--max-source-bytes", "123456",
                                                "--db", os.path.join(d, "r.db")]), \
                contextlib.redirect_stdout(io.StringIO()):
            repo.main()
            self.assertEqual(repo.MAX_MEMBER, 123456)

    def test_env_variable(self):
        with mock.patch.dict(os.environ, {"LAZARET_MAX_SOURCE_BYTES": "2000000"}):
            self.assertEqual(repo._env_number("LAZARET_MAX_SOURCE_BYTES", 16_000_000), 2_000_000)


if __name__ == "__main__":
    unittest.main()
