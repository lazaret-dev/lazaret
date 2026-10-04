"""scripts/make_pre_commit_mirror.py: the pre-commit mirror of a release (H-1).

pre-commit installs a Python hook with `pip install .` at the root of the
hook's repository, which Lazaret's own can't serve (its Python project is in
python/, with a native engine per platform), so a mirror repository pins the
release and runs `lazaret hook`."""
import os
import re
import tempfile
import unittest

from tests import _support

mirror = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "make_pre_commit_mirror.py"),
                              "make_pre_commit_mirror")


def read(folder, name):
    with open(os.path.join(folder, name), encoding="utf-8") as f:
        return f.read()


class MirrorTests(unittest.TestCase):
    def test_the_files_for_a_release(self):
        with tempfile.TemporaryDirectory() as d:
            paths = mirror.write_mirror("0.1.9", d)
            self.assertEqual(sorted(os.listdir(d)), sorted(mirror.FILES))
            self.assertEqual([os.path.basename(p) for p in paths], list(mirror.FILES))
            hooks = read(d, ".pre-commit-hooks.yaml")
            for line in ("- id: lazaret", "  entry: lazaret hook", "  language: python", "  require_serial: true"):
                self.assertIn(line + "\n", hooks)
            self.assertNotIn("pass_filenames", hooks)          # (pre-commit passes the files being committed)
            pyproject = read(d, "pyproject.toml")
            self.assertIn('dependencies = ["lazaret==0.1.9"]', pyproject)
            self.assertIn('version = "0.1.9"', pyproject)
            self.assertIn("py-modules = []", pyproject)
            self.assertEqual(re.findall(r"rev: (\S+)", read(d, "README.md")), ["v0.1.9"])
            self.assertEqual(read(d, "LICENSE"), read(_support.REPO_ROOT, "LICENSE"))

    def test_the_hook_is_lazaret_hook(self):
        """The entry is the subcommand the package's CLI dispatches."""
        from lazaret import _cli
        entry = re.search(r"entry: (.+)", mirror.HOOKS).group(1).split()
        self.assertEqual(entry[0], "lazaret")
        self.assertTrue(_cli.is_hook(entry[1:]))

    def test_refusals(self):
        with tempfile.TemporaryDirectory() as d:
            for version in ("0.1", "v0.1.9", "0.1.9rc1", ""):
                with self.subTest(version=version), self.assertRaises(ValueError):
                    mirror.write_mirror(version, d)
            with open(os.path.join(d, "notes.txt"), "w", encoding="utf-8") as f:
                f.write("x")
            with self.assertRaises(ValueError):                # a folder that isn't a mirror
                mirror.write_mirror("0.1.9", d)
        with tempfile.TemporaryDirectory() as d:
            mirror.write_mirror("0.1.9", d)
            os.mkdir(os.path.join(d, ".git"))
            mirror.write_mirror("0.2.0", d)                    # a mirror: rewritten for the next release
            self.assertIn('dependencies = ["lazaret==0.2.0"]', read(d, "pyproject.toml"))
            self.assertEqual(mirror.main(["0.2", d]), 1)


if __name__ == "__main__":
    unittest.main()
