"""The scan deadline: which one passed, and where the scan stops.

- An archive is scanned under the earlier of two deadlines: --scan-timeout
  (SCAN_TIMEOUT, per archive) and the caller's deadline for the whole
  package (the MCP server's LAZARET_MCP_MAX_SECONDS). When the caller's
  passed first, the finding still said "scan time budget of 120 s
  exceeded". It names the deadline that passed now.

Time is a fake clock patched into repo (core's per-file budget keeps the
real one), so nothing here depends on how fast the machine is.
"""

import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import issues, scan_npm, zipball


class Clock:
    """repo's `time`: monotonic() advances `step` per call."""

    def __init__(self, step=0.0):
        self.now, self.step = 1000.0, step

    def monotonic(self):
        self.now += self.step
        return self.now


def many_files(n=60):
    return {f"lib/f{i}.js": f"module.exports = {i};\n" for i in range(n)}


def time_findings(res):
    return [i["msg"] for i in issues(res, "SC-TRUNCATED")]


class WhichDeadlineTests(unittest.TestCase):
    def test_the_callers_deadline_is_named(self):
        clock = Clock(step=0.01)
        with mock.patch.object(repo, "time", clock):
            res = scan_npm(many_files(), deadline=clock.now + 0.3)
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertTrue(time_findings(res))
        for msg in time_findings(res):
            self.assertIn("the caller's time budget of 0.3 s for this package ran out", msg)
            self.assertNotIn("120", msg)

    def test_scan_timeout_is_named_when_it_comes_first(self):
        clock = Clock(step=0.01)
        with mock.patch.object(repo, "time", clock), mock.patch.object(repo, "SCAN_TIMEOUT", 0.3):
            res = scan_npm(many_files(), deadline=clock.now + 500)
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertTrue(time_findings(res))
        for msg in time_findings(res):
            self.assertIn("scan time budget of 0.3 s per archive (--scan-timeout) exceeded", msg)
            self.assertNotIn("caller", msg)

    def test_files_not_downloaded_name_the_callers_budget(self):
        wheel = zipball({"x/__init__.py": "V = 1\n"})
        arts = [{"url": f"https://files.pythonhosted.org/x-1.0-{t}.whl", "container": "zip",
                 "artifact": "wheel", "entry": {}, "filename": f"x-1.0-{t}.whl"} for t in "ab"]
        with mock.patch.object(repo, "http_bytes", return_value=wheel), \
                mock.patch.object(repo, "verify_digest", return_value=None):
            res = repo.scan_package("pypi", "x", "1.0", resolved=repo.Resolution("1.0", arts),
                                    deadline=0)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("the caller's time budget ran out", res["verdictReason"])
        self.assertTrue(any("the caller's time budget for this package ran out" in m
                            for m in time_findings(res)))


if __name__ == "__main__":
    unittest.main()
