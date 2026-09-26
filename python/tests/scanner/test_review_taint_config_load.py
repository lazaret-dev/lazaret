"""Final-review item 2: an explicit --taint-config that could not be loaded
(missing, unreadable, not valid JSON, nested too deep, an integer past the
digit limit, ...) printed a warning and the scan went on WITHOUT the rules,
exit 0 — although the README promises that with an explicit config "CI
cannot silently lose coverage". Now any failure to load an explicit
--taint-config is `error: could not load taint config …` and exit 4 (never a
traceback, no scan). A repository config (--trust-repo-config) that can't be
loaded still warns and scans; with --strict-taint-config it exits 4 too.

Fixtures are inert text; nothing is executed.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import _support

PY = sys.executable or "python3"
CLI = _support.CLI
DEEP = "[" * 100_000 + "]" * 100_000


class Base(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="tcl-root-")
        self.out = tempfile.mkdtemp(prefix="tcl-out-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.addCleanup(shutil.rmtree, self.out, True)
        with open(os.path.join(self.root, "a.py"), "w") as fh:
            fh.write("x = 1\n")

    def cfg(self, name, data):
        path = os.path.join(self.out, name)
        with open(path, "wb") as fh:
            fh.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def scan(self, *extra):
        return subprocess.run(
            [PY, CLI, self.root, "--no-html", "--no-json", *extra],
            capture_output=True, encoding="utf-8", errors="replace", timeout=40)

    def assert_exit_4(self, p, needle="could not load taint config"):
        self.assertNotIn("Traceback", p.stderr + p.stdout)
        self.assertEqual(p.returncode, 4, p.stderr[-600:])
        self.assertIn(needle, p.stderr)
        self.assertNotIn("Quality gate", p.stdout)             # no scan without the rules


class ExplicitConfigTests(Base):
    CASES = {
        "invalid_json": b'{"python": {"sources": [',
        "not_json_at_all": b"sources: request\n",
        "deep": DEEP.encode(),
        "bad_utf8": b'{"python": {"sources": ["\xff"]}}',
        "empty_file": b"",
    }

    def test_unloadable_explicit_config_exits_4(self):
        for name, data in self.CASES.items():
            with self.subTest(case=name):
                p = self.scan("--taint-config", self.cfg(name + ".json", data))
                self.assert_exit_4(p)
                self.assertIn("error: could not load taint config", p.stderr)

    def test_huge_integer_exits_4(self):
        # Python >= 3.10.7 refuses to parse it (int max str digits): a load
        # error. An interpreter without that limit parses it and validation
        # rejects the non-string source. Exit 4 either way.
        p = self.scan("--taint-config",
                      self.cfg("bigint.json", b'{"python": {"sources": [' + b"9" * 5000 + b"]}}"))
        self.assertNotIn("Traceback", p.stderr + p.stdout)
        self.assertEqual(p.returncode, 4, p.stderr[-600:])
        self.assertRegex(p.stderr, r"error: (could not load taint config|\d+ taint-config rule)")

    def test_missing_file_exits_4(self):
        p = self.scan("--taint-config", os.path.join(self.out, "does-not-exist.json"))
        self.assert_exit_4(p)

    def test_directory_exits_4(self):
        p = self.scan("--taint-config", self.out)
        self.assert_exit_4(p)

    def test_oversized_file_exits_4(self):
        big = '{"python": {"sources": ["' + "a" * 1_000_001 + '"]}}'
        p = self.scan("--taint-config", self.cfg("big.json", big))
        self.assert_exit_4(p)
        self.assertIn("limit", p.stderr)

    @_support.skip_unless_permissions_enforced
    def test_unreadable_file_exits_4(self):
        path = self.cfg("secret.json", b'{"python": {"sources": ["x"]}}')
        os.chmod(path, 0)
        self.addCleanup(os.chmod, path, 0o600)
        p = self.scan("--taint-config", path)
        self.assert_exit_4(p)

    def test_wrong_top_level_shapes_exit_4(self):
        for name, data in (("list", "[]"), ("number", "42"), ("null", "null"),
                           ("string", '"python"')):
            with self.subTest(case=name):
                p = self.scan("--taint-config", self.cfg(name + ".json", data))
                self.assertNotIn("Traceback", p.stderr + p.stdout)
                self.assertEqual(p.returncode, 4, p.stderr[-600:])
                self.assertIn("error:", p.stderr)

    def test_valid_explicit_config_still_scans(self):
        # vacuity guard: a loadable config is applied and the scan runs
        p = self.scan("--taint-config", self.cfg("ok.json", '{"python": {"sources": ["\\\\bx\\\\b"]}}'))
        self.assertEqual(p.returncode, 0, p.stderr[-600:])
        self.assertIn("Loaded taint config", p.stdout)
        self.assertIn("Quality gate", p.stdout)


class RepoConfigTests(Base):
    def write_repo_config(self, data):
        with open(os.path.join(self.root, ".lazaret-taint.json"), "wb") as fh:
            fh.write(data)

    def test_unloadable_repo_config_warns_and_scans(self):
        self.write_repo_config(b'{"python": ')
        p = self.scan("--trust-repo-config")
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr[-600:])
        self.assertIn("warning: could not load taint config", p.stderr)
        self.assertIn("Quality gate", p.stdout)

    def test_unloadable_repo_config_with_strict_exits_4(self):
        self.write_repo_config(DEEP.encode())
        p = self.scan("--trust-repo-config", "--strict-taint-config")
        self.assert_exit_4(p)
        self.assertIn("error: could not load taint config", p.stderr)

    def test_untrusted_repo_config_is_not_read(self):
        # without --trust-repo-config the file is only noted, whatever it holds
        self.write_repo_config(DEEP.encode())
        p = self.scan("--strict-taint-config")
        self.assertEqual(p.returncode, 0, p.stderr[-600:])
        self.assertIn("found but not loaded", p.stdout)

    def test_symlinked_repo_config_warns_or_exits_4_with_strict(self):
        target = self.cfg("real.json", '{"python": {"sources": ["x"]}}')
        try:
            os.symlink(target, os.path.join(self.root, ".lazaret-taint.json"))
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("cannot create symlinks here")
        p = self.scan("--trust-repo-config")
        self.assertEqual(p.returncode, 0, p.stderr[-600:])
        self.assertIn("not a regular file", p.stderr)
        p = self.scan("--trust-repo-config", "--strict-taint-config")
        self.assert_exit_4(p)


if __name__ == "__main__":
    unittest.main()
