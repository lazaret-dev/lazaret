"""Registry verdicts on a program under a source file's name (0.1.8): an
executable's bytes in a .py or .js member are SC-BINARY, CRITICAL, in every
kind of release, a wheel too. A binary named for what it is stays what it was
(inventory in a wheel, MAJOR elsewhere), and bytes that are not a program
stay SC-TRUNCATED: the release is INCOMPLETE, not cleared.

num2words 0.5.15's `_build.py`, a Windows executable, was INCOMPLETE.
Fixtures are inert: a format's first bytes and zeros, nothing that runs.
"""
import json
import unittest

from tests.registry._review_support import issues, scan_npm, scan_sdist, scan_wheel

PE = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff" + b"\x00" * 2034
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 2041
OPAQUE = bytes((i * 151 + 7) % 251 for i in range(4096))       # no format's header
SETUP = "from setuptools import setup\nsetup(name='x')\n"
WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}


def binaries(res):
    return sorted((i["file"], i["sev"], i["msg"]) for i in issues(res, "SC-BINARY"))


class DisguisedTests(unittest.TestCase):
    def test_a_windows_executable_named_as_python(self):
        res = scan_sdist({"setup.py": SETUP, "x/_build.py": PE})
        self.assertEqual(binaries(res), [(
            "x/_build.py", "CRITICAL", "_build.py is not source code but a program: Windows PE executable/DLL.")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_an_elf_named_as_javascript(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0", "main": "index.js"}),
                        "index.js": ELF})
        self.assertEqual([(f, s) for f, s, _ in binaries(res)], [("index.js", "CRITICAL")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_in_a_wheel_too(self):
        res = scan_wheel({"x/__init__.py": ELF, **WHEEL_META})
        self.assertEqual([(f, s) for f, s, _ in binaries(res)], [("x/__init__.py", "CRITICAL")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])


class NotADisguiseTests(unittest.TestCase):
    def test_a_binary_named_for_what_it_is(self):
        res = scan_wheel({"x/__init__.py": "VERSION = 1\n", "x/_native.so": ELF, **WHEEL_META})
        self.assertEqual([(f, s) for f, s, _ in binaries(res)], [("x/_native.so", "INFO")])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_text_that_starts_like_a_header(self):
        res = scan_sdist({"setup.py": SETUP, "x/mz.py": "MZ = 1\nELF = 2\n"})
        self.assertEqual(binaries(res), [])

    def test_bytes_that_are_no_program_stay_unread(self):
        res = scan_sdist({"setup.py": SETUP, "x/blob.py": OPAQUE})
        self.assertEqual(binaries(res), [])
        self.assertEqual(res["verdict"], "INCOMPLETE", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
