"""Review: two reports could be given the same file.

`--sarif lazaret-report.json` (the default JSON report's name) wrote the
SARIF log and then replaced it with the JSON report while printing both
paths, exit 0; `--json X --html X` scanned the whole project, wrote X, and
only then refused to overwrite it with the HTML report (exit 3). Report
destinations that resolve to the same file ('..', relative and absolute
spellings, a symlinked directory; case-folded where paths are) are now
refused with the other pre-scan checks: exit 3 before anything is scanned
or written. Same in the npm engine (lib/fs.js checkDistinctPaths) and for
lazaret-sca, which shares validate_report_paths.
"""
import os
import subprocess
import sys
import tempfile
import unittest

from lazaret.scanner import reports
from tests import _support


def cli(root, *args):
    return subprocess.run([sys.executable, _support.CLI, root, *args],
                          capture_output=True, encoding="utf-8", errors="replace", timeout=40)


class DistinctPathTests(unittest.TestCase):
    def test_spellings_of_one_file(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "sub"))
            same = [(os.path.join(d, "r.json"), os.path.join(d, "r.json")),
                    (os.path.join(d, "r.json"), os.path.join(d, "sub", "..", "r.json")),
                    (os.path.join(d, "sub", "r.json"), os.path.join(d, ".", "sub", "r.json"))]
            if hasattr(os, "symlink") and sys.platform != "win32":
                os.symlink(os.path.join(d, "sub"), os.path.join(d, "link"))
                same.append((os.path.join(d, "sub", "r.json"), os.path.join(d, "link", "r.json")))
            for a, b in same:
                with self.subTest(a=a, b=b):
                    with self.assertRaises(reports.ReportPathError) as ctx:
                        reports.validate_report_paths({"json": a, "html": None, "sarif": b})
                    self.assertIn("JSON and SARIF reports would both be written to", str(ctx.exception))
            reports.validate_report_paths({"json": os.path.join(d, "r.json"),
                                           "html": os.path.join(d, "r.html"), "sarif": None})

    def test_sarif_on_the_default_json_name(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            with open(os.path.join(root, "a.py"), "w", encoding="utf-8") as f:
                f.write("import os\nos.system(cmd)\n")
            p = cli(root, "--out-dir", out, "--sarif", "lazaret-report.json")
            self.assertEqual(p.returncode, 3, p.stdout)                         # was 0
            self.assertIn("reports would both be written to", p.stderr)
            self.assertNotIn("Lazaret scan", p.stdout)                          # refused before the scan
            self.assertEqual(os.listdir(out), [])
            p = cli(root, "--out-dir", out, "--no-json", "--no-html", "--sarif", "lazaret-report.json")
            self.assertEqual(p.returncode, 0, p.stderr)                         # nothing else goes there
            with open(os.path.join(out, "lazaret-report.json"), encoding="utf-8") as f:
                self.assertIn('"version": "2.1.0"', f.read())

    def test_json_and_html_on_one_path_fail_before_the_scan(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            with open(os.path.join(root, "a.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            p = cli(root, "--out-dir", out, "--json", "X", "--html", os.path.join(out, "sub", "..", "X"))
            self.assertEqual(p.returncode, 3, p.stderr)
            self.assertIn("the JSON and HTML reports would both be written to", p.stderr)
            self.assertNotIn("Lazaret scan", p.stdout)                          # was: after the full scan
            self.assertEqual(os.listdir(out), [])


if __name__ == "__main__":
    unittest.main()
