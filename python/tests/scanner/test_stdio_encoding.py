"""Output never crashes on an encoding the characters don't fit.

Reports print check and cross marks. On Windows, output redirected to a pipe
or a file defaulted to the ANSI code page (cp1252), which can't encode them,
and the CLIs died with UnicodeEncodeError mid-report. configure_stdio() fixes
that; these tests pin it down on every platform."""

import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

from lazaret.scanner import core as lazaret
from tests import _support


def fake_stream(encoding, tty=False):
    stream = io.TextIOWrapper(io.BytesIO(), encoding=encoding)
    stream.isatty = lambda: tty
    return stream


class ConfigureStdioTests(unittest.TestCase):
    def configure(self, platform, stdout, stderr=None, env=None):
        stderr = stderr or fake_stream(stdout.encoding)
        with mock.patch.object(sys, "platform", platform), \
                mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr), \
                mock.patch.dict(os.environ, env or {}, clear=False):
            if env is None:
                os.environ.pop("PYTHONIOENCODING", None)
            lazaret.configure_stdio()
        return stdout

    def test_redirected_windows_output_becomes_utf8(self):
        out = self.configure("win32", fake_stream("cp1252"))
        self.assertEqual(out.encoding.lower().replace("-", ""), "utf8")
        out.write("\u2713 passed \u2717 failed")
        out.flush()
        self.assertEqual(out.buffer.getvalue().decode("utf-8"), "\u2713 passed \u2717 failed")

    def test_windows_console_is_left_alone(self):
        out = self.configure("win32", fake_stream("cp1252", tty=True))
        self.assertEqual(out.encoding, "cp1252")
        out.write("\u2713")          # replaced instead of raising
        out.flush()
        self.assertEqual(out.buffer.getvalue(), b"?")

    def test_explicit_pythonioencoding_is_respected(self):
        out = self.configure("win32", fake_stream("cp1252"), env={"PYTHONIOENCODING": "cp1252"})
        self.assertEqual(out.encoding, "cp1252")

    def test_redirected_output_is_utf8_on_every_platform(self):
        # Linux/macOS under a bare C locale (ASCII) behave like Windows' code
        # page: redirected output is written as UTF-8 there too, so a CI log
        # or a piped report is the same bytes on every OS.
        for platform, encoding in (("linux", "ascii"), ("darwin", "ascii"), ("win32", "cp1252")):
            with self.subTest(platform=platform):
                out = self.configure(platform, fake_stream(encoding))
                self.assertEqual(out.encoding.lower().replace("-", ""), "utf8")

    def test_a_utf8_terminal_or_pipe_is_left_as_is(self):
        out = self.configure("linux", fake_stream("utf-8"))
        self.assertEqual(out.encoding, "utf-8")

    def test_unencodable_characters_never_raise_anywhere(self):
        for platform in ("linux", "darwin", "win32"):
            with self.subTest(platform=platform):
                out = self.configure(platform, fake_stream("ascii", tty=True))
                out.write("\u2713 \u2014 \u00b7")   # must not raise
                out.flush()


class CliOutputEncodingTests(unittest.TestCase):
    """End to end: the CLI with an output encoding that can't hold its marks."""

    def test_scan_completes_under_a_narrow_output_encoding(self):
        for encoding in ("cp1252", "ascii"):
            with self.subTest(encoding=encoding):
                p = subprocess.run(
                    [sys.executable, _support.CLI, os.path.join(_support.FIXTURES, "testproj"),
                     "--no-html", "--no-json"],
                    capture_output=True, env=dict(os.environ, PYTHONIOENCODING=encoding), timeout=120)
                self.assertNotIn(b"Traceback", p.stderr, p.stderr[-600:])
                self.assertNotIn(b"UnicodeEncodeError", p.stderr)
                self.assertIn(b"Quality gate", p.stdout)


class McpUtf8Tests(unittest.TestCase):
    def test_non_ascii_request_round_trips_whatever_the_locale(self):
        request = json.dumps({"jsonrpc": "2.0", "id": "caf\u00e9-\u2713", "method": "ping"},
                             ensure_ascii=False).encode("utf-8") + b"\n"
        p = subprocess.run([sys.executable, _support.MCP], input=request, capture_output=True,
                           env=dict(os.environ, PYTHONIOENCODING="cp1252"), timeout=60)
        replies = [json.loads(line) for line in p.stdout.decode("utf-8").splitlines() if line.strip()]
        self.assertEqual(replies[0]["id"], "caf\u00e9-\u2713", p.stderr[-400:])


if __name__ == "__main__":
    unittest.main()
