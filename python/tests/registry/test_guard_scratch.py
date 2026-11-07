"""The guard's own folders for a package manager's plan (the Go/Rust review's CG-1, Oct 4, 2026).

cargo install, yarn 1, a global npm install and go --plan made their plan in a folder of the system's temporary folder.
cargo, rustup, yarn, npm and go read settings from every folder above where they run (cargo's configuration and workspace,
rustup's toolchain file, yarn's `yarn-path`, npm's workspace root, go.work), and on Linux /tmp is a folder every user can
write to: a file another user put there made the guard run their program, or check nothing. The folders are now the
user's own (LAZARET_GUARD_SCRATCH, else the user's cache folder, else a temporary folder no one else can write above).
"""

import os
import stat
import tempfile
import unittest
from unittest import mock

from lazaret.registry import guard


class SharedAboveTests(unittest.TestCase):
    def test_a_folder_under_one_every_user_can_write_to_is_shared(self):
        with tempfile.TemporaryDirectory() as tmp:
            shared = os.path.join(tmp, "shared")
            os.makedirs(os.path.join(shared, "a", "b"))
            os.chmod(shared, 0o777)
            if os.name != "nt":
                self.assertTrue(guard._shared_above(os.path.join(shared, "a", "b")))

    def test_a_folder_that_cannot_be_read_counts_as_shared(self):
        with mock.patch("os.stat", side_effect=OSError("no")):
            if os.name != "nt":
                self.assertTrue(guard._shared_above("/x/y"))

    def test_a_chain_of_private_folders_is_not_shared(self):
        private = os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        with mock.patch("os.stat", return_value=private):
            self.assertFalse(guard._shared_above("/home/someone/.cache/lazaret/tmp"))


class PrivateScratchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-scratch-test-")
        self.addCleanup(guard.remove_tree, self.tmp)
        self.env = mock.patch.dict(os.environ, {"XDG_CACHE_HOME": os.path.join(self.tmp, "cache")})
        self.env.start()
        self.addCleanup(self.env.stop)
        os.environ.pop("LAZARET_GUARD_SCRATCH", None)

    def test_the_named_folder_is_used_as_given(self):
        os.environ["LAZARET_GUARD_SCRATCH"] = os.path.join(self.tmp, "mine")
        made = guard.private_scratch("lazaret-guard-")
        self.assertEqual(os.path.dirname(made), os.path.join(self.tmp, "mine"))
        self.assertTrue(os.path.basename(made).startswith("lazaret-guard-"))
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(os.stat(made).st_mode), 0o700)

    def test_the_cache_folder_is_used_when_no_folder_above_it_is_shared(self):
        with mock.patch.object(guard, "_shared_above", return_value=False):
            made = guard.private_scratch("lazaret-guard-")
        self.assertEqual(os.path.dirname(made), os.path.join(self.tmp, "cache", "lazaret", "tmp"))

    def test_the_temporary_folder_is_used_when_the_cache_folder_is_shared_and_it_is_not(self):
        cache = os.path.join(self.tmp, "cache", "lazaret", "tmp")
        with mock.patch.object(guard, "_shared_above", side_effect=lambda p: os.path.abspath(p) == cache), \
                mock.patch("tempfile.gettempdir", return_value=os.path.join(self.tmp, "own-tmp")):
            made = guard.private_scratch("lazaret-guard-")
        self.assertEqual(os.path.dirname(made), os.path.join(self.tmp, "own-tmp"))

    def test_no_folder_of_ones_own_is_an_error_not_a_shared_folder(self):
        with mock.patch.object(guard, "_shared_above", return_value=True):
            with self.assertRaisesRegex(guard.GuardError, "LAZARET_GUARD_SCRATCH"):
                guard.private_scratch("lazaret-guard-")


class CargoScratchProjectTests(unittest.TestCase):
    """The scratch project is a workspace of its own, and cargo runs from the user's folder (so its settings and rustup's
    toolchain are the ones `cargo install` reads there)."""

    def test_the_manifest_is_its_own_workspace_and_cargo_runs_in_the_users_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            seen = {}

            def fake_run(argv, env, cwd=None, capture=False):
                seen["argv"], seen["cwd"] = argv, cwd
                return mock.Mock(returncode=1, stdout="", stderr="no")

            ctx = mock.Mock()
            with mock.patch.object(guard, "run_tool", side_effect=fake_run), mock.patch.object(guard, "show_failure"):
                got = guard.cargo_scratch_lock(ctx, "cargo", [], {}, os.path.join(tmp, "s"), "tool", None, False,
                                               os.path.join(tmp, "user"))
            self.assertIsNone(got)
            self.assertEqual(seen["cwd"], os.path.join(tmp, "user"))
            with open(os.path.join(tmp, "s", "Cargo.toml"), encoding="utf-8") as f:
                self.assertIn("\n[workspace]\n", f.read())


if __name__ == "__main__":
    unittest.main()
