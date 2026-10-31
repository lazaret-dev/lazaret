"""action.yml's install step on this repository's own python/, the real build backend (F-01).

lazaret_build takes the engine's library from LAZARET_NATIVE_LIBRARY and LAZARET_WHEEL_PLATFORM when they are set
(release CI's), else compiles it with $CARGO or the cargo on PATH; the runtime loader takes LAZARET_NATIVE_LIB; cargo
takes RUSTC, RUSTC_WRAPPER, RUSTFLAGS and the CARGO_* settings. In the action they are the workflow's, and none may
name the checkout's files: the step drops them (CARGO_HOME and RUSTUP_HOME find the toolchain) and gives the backend
the cargo it resolved by its absolute path. Here they all point into a checkout whose files only write markers, and
the cargo on PATH is a stand-in that records what it was given and fails, which stops the build: the backend went to
the engine's build (`_native_payload` -> `build_native`, not the override's bytes) with that cargo, in this
repository's rust/, given none of the variables; nothing is compiled or installed. One venv, about 6 s.
"""

import os
import tempfile
import unittest

from tests import _support
from tests.build.test_action_isolation import SKIP_BASH, base_env, ensurepip_missing, hostile_checkout, inside, write
from tests.build.test_review_action import ACTION, read, run_script, steps


@unittest.skipUnless(*SKIP_BASH)
class RealBackendTests(unittest.TestCase):
    def test_the_backend_builds_the_engine_with_the_resolved_cargo(self):
        why = ensurepip_missing()
        if why:
            self.skipTest(why)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = os.path.realpath(tmp.name)
        markers, temp, bindir = (os.path.join(root, n) for n in ("markers", "runner-temp", "bin"))
        for folder in (markers, temp):
            os.makedirs(folder)
        checkout, hostile, shell = hostile_checkout(root, markers)
        record = os.path.join(root, "cargo-record")
        write(os.path.join(bindir, "cargo"),
              "#!/bin/sh\n{ printf 'argv:'; printf ' %s' \"$@\"; printf '\\ncwd: %s\\n' \"$(pwd -P)\";\n"
              "  env | grep -E '^(LAZARET_|CARGO|RUST|PYTHON|PIP_)' | sed 's/^/env: /'; } > \"$STANDIN_RECORD\"\n"
              "exit 3\n", 0o755)
        env = base_env(root, bindir)
        env.update(GITHUB_WORKSPACE=checkout, GITHUB_ACTION_PATH=_support.REPO_ROOT, RUNNER_TEMP=temp,
                   STANDIN_RECORD=record, **hostile, **shell)
        p = run_script(steps(read(ACTION))[0], temp, checkout, env, timeout=30)
        self.assertEqual(sorted(os.listdir(markers)), [], p.stdout + p.stderr)
        self.assertNotEqual(p.returncode, 0)                                  # (the stand-in cargo failed the build)
        self.assertIn("cargo exited with 3", p.stdout + p.stderr)
        lines = read(record).splitlines()
        self.assertEqual(lines[0], "argv: build --release --offline --locked -p lazaret-ffi")
        self.assertEqual(lines[1], "cwd: " + os.path.realpath(os.path.join(_support.REPO_ROOT, "rust")))
        seen = dict(line[len("env: "):].partition("=")[::2] for line in lines[2:])
        self.assertEqual(seen.pop("CARGO"), os.path.join(bindir, "cargo"))
        for name in ("PIP_CONFIG_FILE", "PIP_BUILD_TRACKER", "PYTHONNOUSERSITE"):     # (pip's own)
            self.assertFalse(inside(seen.pop(name, root), checkout), name)
        self.assertFalse(inside(seen.pop("PYTHONPATH", root), checkout))
        self.assertEqual(seen, {})                       # none of the overrides, no RUSTC*, RUSTFLAGS, CARGO_BUILD_*
        site = [d for d, _dirs, _files in os.walk(os.path.join(temp, "lazaret-action")) if d.endswith("site-packages")]
        self.assertTrue(site)
        self.assertFalse(os.path.exists(os.path.join(site[0], "lazaret")))   # nothing installed


if __name__ == "__main__":
    unittest.main()
