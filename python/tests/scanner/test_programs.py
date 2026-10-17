"""Where Lazaret finds a program it runs (lazaret.scanner.programs; the Go/Rust review's GO-8, Oct 4, 2026).

shutil.which looked in the current folder first on Windows, and on every system for an empty or relative PATH entry; subprocess
given a bare name looks there on Windows too. `lazaret guard` runs in the project's folder and `lazaret hook` in the
repository's, so a go.exe, an npm.cmd or a git.exe of the project's own ran in the real tool's place. A program is now looked up
in PATH's folders named by an absolute path only."""

import ntpath
import os
import stat
import tempfile
import types
import unittest
from unittest import mock

from lazaret.registry import guard
from lazaret.scanner import hook, programs


def _executable(folder, name):
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


@unittest.skipIf(os.name == "nt", "POSIX paths")
class PosixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-programs-")
        self.addCleanup(guard.remove_tree, self.tmp)
        self.here = os.path.join(self.tmp, "project")
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.here)
        os.makedirs(self.bin)
        cwd = os.getcwd()
        os.chdir(self.here)
        self.addCleanup(os.chdir, cwd)

    def test_a_program_in_the_current_folder_is_not_found_for_an_empty_or_relative_entry(self):
        _executable(self.here, "lzprog")
        for path in ("", ":", ".", "./", "project", f":{self.bin}", f".:{self.bin}"):
            with self.subTest(path=path):
                self.assertIsNone(programs.find("lzprog", path))

    def test_the_first_absolute_folder_that_holds_it_wins(self):
        _executable(self.here, "lzprog")
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        want = _executable(self.bin, "lzprog")
        _executable(other, "lzprog")
        self.assertEqual(programs.find("lzprog", f".:{self.bin}:{other}"), want)

    def test_a_file_that_is_not_executable_or_a_folder_is_passed_over(self):
        with open(os.path.join(self.bin, "lzprog"), "w", encoding="utf-8") as f:
            f.write("not a program\n")
        os.makedirs(os.path.join(self.tmp, "dirs", "lzprog"))
        self.assertIsNone(programs.find("lzprog", f"{self.bin}:{os.path.join(self.tmp, 'dirs')}"))

    def test_a_name_with_a_folder_in_it_is_refused(self):
        _executable(self.here, "lzprog")
        for name in ("./lzprog", os.path.join(self.here, "lzprog"), "", "a/lzprog"):
            with self.subTest(name=name):
                self.assertIsNone(programs.find(name, self.bin))

    def test_the_environments_path_is_read_when_none_is_given(self):
        want = _executable(self.bin, "lzprog")
        with mock.patch.dict(os.environ, {"PATH": f".:{self.bin}"}):
            self.assertEqual(programs.find("lzprog"), want)

    def test_the_guard_does_not_run_a_package_manager_from_the_project_folder(self):
        _executable(self.here, "go")
        with mock.patch.dict(os.environ, {"PATH": f".:{self.bin}"}):
            with self.assertRaisesRegex(guard.GuardError, "go is not on PATH .*not in the current folder"):
                guard.find_tool("go")
            want = _executable(self.bin, "go")
            self.assertEqual(guard.find_tool("go"), want)

    def test_the_hook_does_not_run_a_git_from_the_repository(self):
        _executable(self.here, "git")
        with mock.patch.dict(os.environ, {"PATH": "."}), mock.patch("subprocess.run") as run, \
                mock.patch("subprocess.Popen") as popen:
            self.assertIsNone(hook._git(self.here, "status"))
            self.assertEqual(hook.write_blobs(self.here, [("0" * 40, "a.py")], self.tmp),
                             [("a.py", "git could not be run (it is not on PATH)")])
        run.assert_not_called()
        popen.assert_not_called()


class WindowsTests(unittest.TestCase):
    """Windows' rules, read with ntpath: a program is found under PATHEXT's extensions, in a folder with a drive or a share,
    and never in the current folder (which shutil.which and CreateProcess look in first)."""

    def find(self, name, path, files, pathext=None):
        """The path found, in lower case (Windows' file names are not case-sensitive, and PATHEXT's extensions are upper
        case: go.EXE is go.exe)."""
        environ = {"PATH": path} | ({"PATHEXT": pathext} if pathext is not None else {})
        present = {f.lower() for f in files}
        fake_path = types.SimpleNamespace(**{k: getattr(ntpath, k) for k in ("isabs", "splitdrive", "normcase", "normpath",
                                                                          "join", "dirname")},
                                          isfile=lambda p: p.lower() in present)
        fake_os = types.SimpleNamespace(path=fake_path, pathsep=";", sep="\\", altsep="/", name="nt", environ=environ,
                                        defpath=".;C:\\bin", access=lambda p, m: True, X_OK=os.X_OK)
        with mock.patch.object(programs, "os", fake_os):
            got = programs.find(name)
        return got.lower() if got else got

    def test_the_current_folder_and_relative_entries_are_never_searched(self):
        files = {"go.exe", ".\\go.exe", "project\\go.exe", "\\go.exe", "C:go.exe", "C:\\Go\\bin\\go.exe"}
        got = self.find("go", ".;;project;\\;C:;C:\\Go\\bin", files)
        self.assertEqual(got, "c:\\go\\bin\\go.exe")

    def test_pathext_gives_the_extensions_in_order(self):
        files = {"C:\\node\\npm.cmd", "C:\\node\\npm"}
        self.assertEqual(self.find("npm", "C:\\node", files), "c:\\node\\npm.cmd")
        self.assertEqual(self.find("npm", "C:\\node", files | {"C:\\node\\npm.exe"}, pathext=".EXE;.CMD"), "c:\\node\\npm.exe")

    def test_a_name_with_its_extension_is_looked_up_as_it_is(self):
        self.assertEqual(self.find("go.exe", "C:\\Go\\bin", {"C:\\Go\\bin\\go.exe"}), "c:\\go\\bin\\go.exe")
        self.assertIsNone(self.find("go.exe", "C:\\Go\\bin", {"C:\\Go\\bin\\go.exe.exe"}))

    def test_a_quoted_entry_and_a_share_are_folders(self):
        files = {"C:\\Program Files\\Go\\bin\\go.exe", "\\\\server\\tools\\cargo.exe"}
        self.assertEqual(self.find("go", '"C:\\Program Files\\Go\\bin"', files), "c:\\program files\\go\\bin\\go.exe")
        self.assertEqual(self.find("cargo", "\\\\server\\tools", files), "\\\\server\\tools\\cargo.exe")


if __name__ == "__main__":
    unittest.main()
