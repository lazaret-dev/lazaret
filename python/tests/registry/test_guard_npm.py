"""lazaret guard with the real npm, against a fake registry on 127.0.0.1 (tests/registry/_guard_support.py):
what is installed, what is blocked and put back, a global install's plan and the folder npm works in, and --trust.
Skipped where npm is not installed. (A lockfile's packages: test_guard_npm_lockfile.py; what npm resolves:
test_guard_npm_resolve.py; pnpm: test_guard_pnpm.py; yarn, Bun and private registries: test_guard_yarn.py,
test_guard_bun.py, test_guard_private_registry.py.)

(MAC-TESTS: the guard's tests of the real tools are split into modules of a few tests each, so each module
runs well inside the 45 s a module gets alone, on a Mac too, where starting the tools and the guard's
workers takes longer: test_guard_npm, _npm_lockfile, _npm_resolve, _pnpm, _yarn, _bun, _private_registry,
_python, _pip_indexes, _uv, _uv_tool, _uv_project.)

The tools run with scripts off (npm_config_ignore_scripts), so no package
code runs, blocked or not."""

import os
import shutil
import unittest

from tests.registry import _guard_support as gs


@unittest.skipUnless(shutil.which("npm"), "npm is not installed")
class NpmGuardTests(gs.RegistryCase):
    def test_a_clean_package_is_installed(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "npm", "install", "good-pkg")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.installed(d, "good-pkg"), "1.0.0")
        self.assertIn("lazaret guard: checked 1 OK", out)

    def test_a_suspicious_dependency_blocks_the_install_and_puts_the_files_back(self):
        d = gs.project(self.tmp)
        before = gs.read(os.path.join(d, "package.json"))
        code, out = self.guard(d, "npm", "install", "dep-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)
        self.assertIn("SC-INSTALL-HOOK (CRITICAL)", out)
        self.assertIn("1 blocked — nothing was installed; package.json and package-lock.json put back", out)
        self.assertEqual(sorted(os.listdir(d)), ["package.json"])
        self.assertEqual(gs.read(os.path.join(d, "package.json")), before)

    def test_a_global_install_is_planned_in_a_folder_no_project_above_takes_in(self):
        # (the Go/Rust review's CG-1 class: npm looks above a project for a workspace root that names it, and a global
        # install's plan was made in /tmp, where any user can write such a package.json and its .npmrc)
        base = self.env["LAZARET_GUARD_SCRATCH"]
        os.makedirs(base, exist_ok=True)
        planted = os.path.join(base, "package.json")
        with open(planted, "w", encoding="utf-8") as f:
            f.write('{"name": "planted", "version": "1.0.0", "private": true, "workspaces": ["lazaret-guard-*"]}\n')
        self.addCleanup(os.remove, planted)
        code, out = self.guard(gs.project(self.tmp), "--plan", "npm", "install", "-g", "dep-parent")
        self.assertEqual(code, 1, out)
        self.assertIn("BLOCKED    evil-pkg@1.0.0: SUSPICIOUS", out)
        self.assertFalse(os.path.exists(os.path.join(base, "package-lock.json")))

    def test_npm_works_in_the_nearest_folder_with_a_package_json(self):
        """With no package.json here, npm works in the nearest folder up that
        has one: the guard checks the lockfile npm writes there, says where,
        and --plan puts that folder's files back (it used to look here, find
        no lockfile, and leave the parent's package.json changed)."""
        parent = gs.project(self.tmp)
        child = os.path.join(parent, "sub", "dir")
        os.makedirs(child)
        before = gs.read(os.path.join(parent, "package.json"))
        code, out = self.guard(child, "--plan", "npm", "install", "good-pkg")
        self.assertEqual(code, 0, out)
        said = [line for line in out.splitlines() if line.startswith("lazaret guard: npm works in ")]
        self.assertEqual(len(said), 1, out)
        self.assertTrue(os.path.samefile(said[0][len("lazaret guard: npm works in "):], parent), out)
        self.assertIn("1 package to check (package-lock.json)", out)
        self.assertIn("nothing blocked (--plan: nothing was installed; package.json and package-lock.json put back)",
                      out)
        self.assertEqual(sorted(os.listdir(parent)), ["package.json", "sub"])
        self.assertEqual(gs.read(os.path.join(parent, "package.json")), before)
        self.assertEqual(os.listdir(child), [])

    def test_plan_installs_nothing(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "--plan", "npm", "install", "good-pkg")
        self.assertEqual(code, 0, out)
        self.assertIn("nothing blocked (--plan: nothing was installed", out)
        self.assertEqual(sorted(os.listdir(d)), ["package.json"])

    def test_trust_installs_a_blocked_package_and_says_so(self):
        d = gs.project(self.tmp)
        code, out = self.guard(d, "--trust", "evil-*", "npm", "install", "dep-parent")
        self.assertEqual(code, 0, out)
        self.assertIn("TRUSTED    evil-pkg@1.0.0: installed anyway (--trust): SUSPICIOUS", out)
        self.assertEqual(self.installed(d, "evil-pkg"), "1.0.0")


if __name__ == "__main__":
    unittest.main()
