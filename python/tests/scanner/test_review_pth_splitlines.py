"""Review: SC-PTH-EXEC split .pth files at \\n only.

site.addpackage iterated the file (lines end at \\n, \\r, \\r\\n) up to
Python 3.11; 3.13 (and recent 3.12 releases) iterate
`pth_content.splitlines()`, which also ends a line at \\v, \\f, \\x1c,
\\x1d, \\x1e, \\x85, U+2028 and U+2029. `# path notes\\fimport sys;
print("PTH-MARKER-LINE-RAN")` gave no finding (the physical line starts with
'#') while python3.13's site.py ran the import. pth_issues (shared with the
registry) and its npm and dashboard twins now check the lines of both
splittings and report a statement at its physical line.

The ground-truth test runs the interpreter's own site.addsitedir on inert
.pth files (each import only prints a marker) and requires a finding for
every statement it ran.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest

from lazaret.scanner import core
from tests import _support
from tests.scanner import _dashboard_vm as dash

SEPARATORS = ["\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]


def marker_line(n, prefix="# path notes"):
    return f'{prefix}{SEPARATORS[n]}import sys; print("PTH-MARKER-{n}")\n'


class PthIssuesTests(unittest.TestCase):
    def test_every_splitlines_boundary(self):
        for n, sep in enumerate(SEPARATORS):
            with self.subTest(sep=hex(ord(sep))):
                got = core.pth_issues("n.pth", marker_line(n))
                self.assertEqual([(i["line"], i["sev"]) for i in got], [(1, "MAJOR")])

    def test_the_review_sample(self):
        got = core.pth_issues("notes.pth", '# path notes\x0cimport sys; print("PTH-MARKER-LINE-RAN")\n')
        self.assertEqual([(i["rule"], i["line"], i["sev"]) for i in got], [("SC-PTH-EXEC", 1, "MAJOR")])

    def test_physical_lines_and_severity(self):
        text = ("./lib\nx\x85import zlib; zlib.decompress(b)\n./a\u2028./b\n"
                "import os\f./c\n# a\vimport a\x1cimport b\nimports\x1dimportlib\n")
        got = core.pth_issues("m.pth", text)
        self.assertEqual([(i["line"], i["sev"]) for i in got], [(2, "CRITICAL"), (4, "MAJOR"), (5, "MAJOR")])
        self.assertEqual(got[0]["snippet"][1], "x\x85import zlib; zlib.decompress(b)")

    def test_crlf_and_plain_lines_unchanged(self):
        got = core.pth_issues("a.pth", "import sys\r\n./x\rimport os; exec(s)\r\n")
        self.assertEqual([(i["line"], i["sev"]) for i in got], [(1, "MAJOR"), (3, "CRITICAL")])


class GroundTruthTests(unittest.TestCase):
    """Every import statement this interpreter's site.py runs is reported."""

    def test_what_site_runs_is_reported(self):
        samples = {f"s{n}.pth": marker_line(n) for n in range(len(SEPARATORS))}
        samples["plain.pth"] = 'import sys; print("PTH-MARKER-plain")\n'
        samples["cr.pth"] = './x\rimport sys; print("PTH-MARKER-cr")\n'
        with tempfile.TemporaryDirectory() as site_dir:
            for name, text in samples.items():
                with open(os.path.join(site_dir, name), "w", encoding="utf-8", newline="") as f:
                    f.write(text)
            p = subprocess.run([sys.executable, "-S", "-c", "import site, sys; site.addsitedir(sys.argv[1])",
                                site_dir], capture_output=True, encoding="utf-8", errors="replace", timeout=30)
        ran = {line.strip() for line in p.stdout.splitlines() if line.startswith("PTH-MARKER-")}
        self.assertIn("PTH-MARKER-plain", ran, p.stderr)
        for name, text in samples.items():
            marker = text[text.index("PTH-MARKER-"):].split('"')[0]
            if marker in ran:
                with self.subTest(file=name, python=sys.version.split()[0]):
                    self.assertTrue(core.pth_issues(name, text), f"{marker} ran but was not reported")


class ProjectScanTests(unittest.TestCase):
    def test_review_tree_fails_the_gate(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            for name, text in (("notes.pth", '# path notes\x0cimport sys; print("PTH-MARKER-LINE-RAN")\n'),
                               ("plain.pth", 'import sys; print("PTH-MARKER-LINE-RAN")\n')):
                with open(os.path.join(root, name), "w", encoding="utf-8", newline="") as f:
                    f.write(text)
            res = core.scan_project(root)
            self.assertEqual(sorted((i["file"], i["line"]) for i in res["issues"]),
                             [("notes.pth", 1), ("plain.pth", 1)])
            p = subprocess.run([sys.executable, _support.CLI, root, "--ci", "--out-dir", out, "--quiet"],
                               capture_output=True, encoding="utf-8", errors="replace", timeout=40)
            self.assertEqual(p.returncode, 1, p.stderr)


@dash.requires_node
class DashboardTests(unittest.TestCase):
    def test_uploads_split_like_the_cli(self):
        uploads = [(f"s{n}.pth", marker_line(n).encode("utf-8")) for n in range(len(SEPARATORS))]
        uploads.append(("m.pth", "x\x85import zlib; zlib.decompress(b)\n# a\vimport a\x1cimport b\n".encode("utf-8")))
        (page,) = dash.run([{"op": "uploadScan", "files": [
            {"name": n, "b64": base64.b64encode(d).decode("ascii")} for n, d in uploads]}])
        key = lambda i: json.dumps(i, sort_keys=True, ensure_ascii=False)
        for (name, data), got in zip(uploads, page):
            with self.subTest(file=name):
                cli = core.pth_issues(name, data.decode("utf-8-sig", "replace"))
                self.assertTrue(cli)
                self.assertEqual(sorted(map(key, got)), sorted(map(key, cli)))


if __name__ == "__main__":
    unittest.main()
