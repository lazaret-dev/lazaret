"""A baseline written on one OS must match scans on another. Report paths use
the platform's separator, so fingerprints normalize it: without that, a
baseline recorded on macOS makes every finding look new on Windows CI."""

import unittest

from lazaret.scanner import core as lazaret


def issue(path):
    return {"rule": "S-EVAL-PY", "file": path, "line": 3, "snipStart": 1,
            "snippet": ["import os", "", "eval(data)", ""]}


class BaselinePortabilityTests(unittest.TestCase):
    def test_fingerprint_ignores_the_path_separator(self):
        self.assertEqual(lazaret.fingerprint(issue("app\\views\\admin.py")),
                         lazaret.fingerprint(issue("app/views/admin.py")))

    def test_different_files_still_differ(self):
        self.assertNotEqual(lazaret.fingerprint(issue("app/a.py")),
                            lazaret.fingerprint(issue("app/b.py")))


if __name__ == "__main__":
    unittest.main()
