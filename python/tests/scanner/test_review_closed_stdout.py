"""Review: a closed stdout lost the scan.

The terminal report is printed before the reports are written, and only a
write error from the report files was handled: `lazaret --ci dir | head -n
2` ended with `error: internal: BrokenPipeError`, exit 5 (not 1), and no
JSON or HTML report; with stdout closed at start (`>&-`, sys.stdout is
None) it was `AttributeError`, exit 5. While the CLI runs, stdout is now
guarded (_PipeSafeStdout): once the reader is gone the rest of the output is
dropped (stdout pointed at the null device, so the flush at exit cannot
turn the exit status into 120) and the scan writes both reports and exits
with its own code. The npm engine already did (its console ignores EPIPE);
review-closed-stdout.test.js and test_js_parity_core check it.
"""
import os
import subprocess
import sys
import tempfile
import unittest

from tests import _support

MANY = "import os\n" + "".join(f"os.system(cmd_{n})\n" for n in range(1500))   # ~150 KB of output


def make_tree(root, text=MANY):
    with open(os.path.join(root, "many.py"), "w", encoding="utf-8") as f:
        f.write(text)


def reports(out):
    return sorted(n for n in os.listdir(out) if n.startswith("lazaret-report"))


class ClosedStdoutTests(unittest.TestCase):
    def run_to_closed_pipe(self, root, out, *extra):
        r, w = os.pipe()
        os.close(r)                                     # the reader is gone before the first write
        try:
            return subprocess.run([sys.executable, _support.CLI, root, "--out-dir", out, *extra],
                                  stdout=w, stderr=subprocess.PIPE, encoding="utf-8",
                                  errors="replace", timeout=40)
        finally:
            os.close(w)

    def assert_clean(self, p):
        self.assertNotIn("internal", p.stderr)
        self.assertNotIn("Exception ignored", p.stderr)

    def test_reader_gone_before_the_first_line(self):
        for extra, want in ((("--ci",), 1), ((), 0), (("--ci", "-q"), 1)):
            with self.subTest(args=extra), tempfile.TemporaryDirectory() as root, \
                    tempfile.TemporaryDirectory() as out:
                make_tree(root)
                p = self.run_to_closed_pipe(root, out, *extra)
                self.assertEqual(p.returncode, want, p.stderr)              # was 5
                self.assert_clean(p)
                self.assertEqual(reports(out), ["lazaret-report.html", "lazaret-report.json"])

    def test_output_small_enough_to_stay_buffered(self):
        """Nothing fails until the flush at exit, which used to make it 120."""
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            make_tree(root, "import os\nos.system(cmd)\n")
            p = self.run_to_closed_pipe(root, out, "--ci", "-q")
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assert_clean(p)
            self.assertEqual(reports(out), ["lazaret-report.html", "lazaret-report.json"])

    def test_reader_leaves_after_two_lines(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            make_tree(root)
            with subprocess.Popen([sys.executable, _support.CLI, root, "--ci", "--out-dir", out],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
                head = [p.stdout.readline() for _ in range(2)]      # `| head -n 2`
                p.stdout.close()
                err = p.stderr.read().decode("utf-8", "replace")
                code = p.wait(timeout=40)
            self.assertEqual(head[1][:12], b"Lazaret scan")
            self.assertEqual(code, 1, err)
            self.assertNotIn("internal", err)
            self.assertEqual(reports(out), ["lazaret-report.html", "lazaret-report.json"])

    @_support.skip_on_windows("closing a child's descriptor 1 needs preexec_fn")
    def test_stdout_closed_at_start(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as out:
            make_tree(root)
            p = subprocess.run([sys.executable, _support.CLI, root, "--ci", "--out-dir", out],
                               stderr=subprocess.PIPE, encoding="utf-8", errors="replace", timeout=40,
                               preexec_fn=lambda: os.close(1))
            self.assertEqual(p.returncode, 1, p.stderr)                     # was 5 (AttributeError)
            self.assert_clean(p)
            self.assertEqual(reports(out), ["lazaret-report.html", "lazaret-report.json"])


if __name__ == "__main__":
    unittest.main()
