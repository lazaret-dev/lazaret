"""The scan deadline: which one passed, and where the scan stops.

- An archive is scanned under the earlier of two deadlines: --scan-timeout
  (SCAN_TIMEOUT, per archive) and the caller's deadline for the whole
  package (the MCP server's LAZARET_MCP_MAX_SECONDS). When the caller's
  passed first, the finding still said "scan time budget of 120 s
  exceeded". It names the deadline that passed now.
- The deadline was checked only between archive members. A member was
  scanned even when reading it took the time past the deadline, and the
  second pass — entry points and hook targets scanned once package.json is
  known, local files they load, the cross-file analysis — ran to the end
  whatever the time (--scan-timeout 1: one archive took 11.6 s). It is
  checked before every file and phase now, so the scan stops at the next
  file past the deadline, INCOMPLETE, with one finding saying where.

Time is a fake clock patched into repo (core's per-file budget keeps the
real one), so nothing here depends on how fast the machine is.
"""

import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import issues, manifest, scan_npm, zipball


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


class StopsAtTheDeadlineTests(unittest.TestCase):
    """The fake clock moves only when a file is decoded or scanned."""

    def advancing(self, clock, name):
        real = getattr(repo.lazaret, name)

        def slow(*args, **kwargs):
            clock.now += 1.0
            return real(*args, **kwargs)
        return mock.patch.object(repo.lazaret, name, slow)

    def test_one_finding_when_the_deadline_passes_while_reading(self):
        clock = Clock(step=0.01)
        with mock.patch.object(repo, "time", clock):
            res = scan_npm(many_files(), deadline=clock.now + 0.3)
        self.assertEqual(len(time_findings(res)), 1, time_findings(res))
        self.assertEqual(res["truncated"], 1)

    def test_a_member_read_past_the_deadline_is_not_scanned(self):
        clock = Clock()
        with mock.patch.object(repo, "time", clock), mock.patch.object(repo, "SCAN_TIMEOUT", 2.5), \
                self.advancing(clock, "decode_member"):
            res = scan_npm(many_files(10))
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertEqual(res["filesScanned"], 2)
        (msg,) = time_findings(res)
        self.assertIn("scan time budget of 2.5 s per archive (--scan-timeout) exceeded "
                      "(stopped at lib/f2.js)", msg)

    def test_entry_points_scanned_in_the_second_pass_stop_at_the_deadline(self):
        # .dat files are only known to be code once package.json is read:
        # each is scanned in the second pass, where no deadline was checked
        files = {f"lib/f{i:02d}.dat": f"module.exports = {i};\n" for i in range(30)}
        files["package.json"] = manifest(main="lib/f00.dat", exports={
            f"./f{i:02d}": f"./lib/f{i:02d}.dat" for i in range(30)})
        clock = Clock()
        with mock.patch.object(repo, "time", clock), mock.patch.object(repo, "SCAN_TIMEOUT", 5), \
                self.advancing(clock, "scan_file"):
            res = scan_npm(files)
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertEqual(res["filesScanned"], 6)          # the 7th file would start past 5 s
        (msg,) = time_findings(res)
        self.assertRegex(msg, r"per archive \(--scan-timeout\) exceeded \(stopped at lib/f\d\d\.dat\)")

    def test_later_phases_are_skipped(self):
        files = {"package.json": manifest(main="lib/a.dat"), "lib/a.dat": "module.exports = 1;\n"}
        clock = Clock()
        flow = mock.Mock(return_value=[])
        with mock.patch.object(repo, "time", clock), mock.patch.object(repo, "SCAN_TIMEOUT", 0.5), \
                self.advancing(clock, "scan_file"), \
                mock.patch.object(repo.lazaret, "lazaret_flow", mock.Mock(analyze=flow)):
            res = scan_npm(files, full=True)
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])
        self.assertEqual(res["filesScanned"], 1)
        flow.assert_not_called()
        (msg,) = time_findings(res)
        self.assertIn("(stopped at the install hooks)", msg)

    def test_within_the_deadline_nothing_changes(self):
        files = {"package.json": manifest(main="lib/a.dat"), "lib/a.dat": "module.exports = 1;\n"}
        clock = Clock()
        flow = mock.Mock(return_value=[])
        with mock.patch.object(repo, "time", clock), self.advancing(clock, "scan_file"), \
                mock.patch.object(repo.lazaret, "lazaret_flow", mock.Mock(analyze=flow)):
            res = scan_npm(files, full=True)
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])
        flow.assert_called_once()

    def test_cancel_is_checked_in_the_second_pass(self):
        files = {"package.json": manifest(main="lib/a.dat"), "lib/a.dat": "module.exports = 1;\n"}
        second_pass = []
        real = repo._package_entry_targets

        def entry_targets(*args, **kwargs):          # only the second pass calls it
            second_pass.append(True)
            return real(*args, **kwargs)
        with mock.patch.object(repo, "_package_entry_targets", entry_targets), \
                self.assertRaises(repo.ScanCancelled):
            scan_npm(files, cancel=lambda: bool(second_pass))
        self.assertTrue(second_pass)


if __name__ == "__main__":
    unittest.main()
