"""Review: a newline in a file name could forge terminal output.

sanitize_term maps every control character to '·' but keeps LF (so a
multi-line message prints as lines), and the report printed file paths,
messages (which embed paths and symlink targets), report paths and errors
through it. A file named `zz\\n\\n  Quality gate:  PASSED \\n::notice::…\\n
x.py` printed a fake "Quality gate: PASSED" line and a `::notice::` GitHub
workflow command at column 0, in both engines. Values printed inside one
line now go through sanitize_term_line, which also maps LF, U+2028 and
U+2029 (every other line break is a control character already): the npm
engine's twin is sanitizeTermLine, and the two are compared code point by
code point. sanitize_term itself is unchanged.
"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import _support

from lazaret.scanner import core

HOSTILE = "zz\n\n  Quality gate:  PASSED \n::notice::marker-from-a-file-name\n  x.py"
NODE = shutil.which("node")
REPORT_JS = os.path.join(_support.REPO_ROOT, "js", "src", "report.js")
LINE_BREAKS = ["\n", "\r", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]


class SanitizeTermLineTests(unittest.TestCase):
    def test_every_line_break_is_mapped(self):
        for ch in LINE_BREAKS:
            with self.subTest(ch=hex(ord(ch))):
                self.assertEqual(core.sanitize_term_line("a" + ch + "b"), "a·b")
                self.assertEqual(len(("a" + core.sanitize_term_line(ch) + "b").splitlines()), 1)

    def test_otherwise_sanitize_term(self):
        for n in range(0x3000):
            ch = chr(n)
            if ch not in LINE_BREAKS:
                self.assertEqual(core.sanitize_term_line(ch), core.sanitize_term(ch), hex(n))
        self.assertEqual(core.sanitize_term_line("a\tb \x1b[31m"), "a\tb ·[31m")
        self.assertEqual(core.sanitize_term("a\nb"), "a\nb")          # the multi-line contract stays


def run_cli(root, *extra):
    return subprocess.run([sys.executable, _support.CLI, root, "--no-json", "--no-html", *extra],
                          capture_output=True, encoding="utf-8", errors="replace", timeout=40)


@_support.skip_on_windows("file names can't hold a newline on Windows")
class CliTests(unittest.TestCase):
    def assert_no_forged_line(self, text):
        lines = text.split("\n")
        self.assertFalse([l for l in lines if l.startswith("::")], text)
        self.assertEqual([l for l in lines if l.lstrip().startswith("Quality gate")], ["  Quality gate:  FAILED "], text)

    def test_hostile_file_name(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
                f.write("import os\nos.system(cmd)\n")
            with open(os.path.join(root, HOSTILE), "w", encoding="utf-8") as f:
                f.write("# TODO marker\n")
            p = run_cli(root)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assert_no_forged_line(p.stdout)
            self.assertIn("  zz··  Quality gate:  PASSED ·::notice::marker-from-a-file-name·  x.py\n", p.stdout)

    def test_hostile_link_target_in_a_message(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "app.py"), "w", encoding="utf-8") as f:
                f.write("import os\nos.system(cmd)\n")
            os.symlink("x\n::notice::from-a-link-target\ny", os.path.join(root, "link"))
            p = run_cli(root)
            self.assert_no_forged_line(p.stdout)
            self.assertIn("-> x·::notice::from-a-link-target·y was not followed", p.stdout)


_NODE_SCRIPT = r"""
import { sanitizeTermLine } from %s;
import { readFileSync } from "node:fs";
const cps = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(cps.map((n) => sanitizeTermLine("a" + String.fromCodePoint(n) + "b"))));
"""


@unittest.skipUnless(NODE, "node is not installed")
class SameAsTheNpmEngine(unittest.TestCase):
    def test_sanitize_term_line_identical_up_to_u2fff(self):
        cps = [n for n in range(0x3000) if not 0xD800 <= n <= 0xDFFF]
        url = pathlib.Path(REPORT_JS).resolve().as_uri()
        p = subprocess.run([NODE, "--input-type=module", "-e", _NODE_SCRIPT % json.dumps(url)],
                           input=json.dumps(cps), capture_output=True, encoding="utf-8", timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        for n, js in zip(cps, json.loads(p.stdout)):
            self.assertEqual(core.sanitize_term_line("a" + chr(n) + "b"), js, hex(n))


if __name__ == "__main__":
    unittest.main()
