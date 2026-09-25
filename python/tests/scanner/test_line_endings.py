"""Line endings never change what the engine finds. Registry archives are
decoded from bytes rather than read in text mode, so scan_file itself
normalizes \\r\\n and lone \\r, exactly as text mode would."""

import unittest

from lazaret.scanner import core as lazaret

SAMPLE = (
    "import subprocess\n"
    "def run(cmd):\n"
    "    subprocess.run(cmd, shell=True)  # nosec\n"
    "    subprocess.run(cmd, shell=True)\n"
    "    eval(user_input)  # lazaret-ignore: S-EVAL-PY\n"
)


class LineEndingTests(unittest.TestCase):
    def test_normalize_newlines(self):
        self.assertEqual(lazaret.normalize_newlines("a\r\nb\rc\nd"), "a\nb\nc\nd")
        self.assertEqual(lazaret.normalize_newlines("plain\n"), "plain\n")

    def test_crlf_and_lone_cr_scan_like_lf(self):
        lf = sorted((i["rule"], i["line"]) for i in lazaret.scan_file("t.py", SAMPLE, "py"))
        crlf = sorted((i["rule"], i["line"]) for i in lazaret.scan_file("t.py", SAMPLE.replace("\n", "\r\n"), "py"))
        cr = sorted((i["rule"], i["line"]) for i in lazaret.scan_file("t.py", SAMPLE.replace("\n", "\r"), "py"))
        self.assertEqual(crlf, lf)
        self.assertEqual(cr, lf)

    def test_snippets_carry_no_carriage_returns(self):
        issues = lazaret.scan_file("t.py", SAMPLE.replace("\n", "\r\n"), "py")
        self.assertTrue(issues)
        for issue in issues:
            self.assertFalse(any("\r" in line for line in issue.get("snippet", []) if isinstance(line, str)))


if __name__ == "__main__":
    unittest.main()
