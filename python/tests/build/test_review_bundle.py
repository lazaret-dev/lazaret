"""scripts/make_bundle.py: credential files never ship, only git-tracked
files ship from a checkout, and the archive is byte-for-byte reproducible.

Before: only .env* counted as secret (.npmrc, .pypirc, .envrc, .netrc,
*.pem, id_rsa, id_ed25519, *.key were bundled), any stray file inside a
whitelisted tree was bundled (scripts/..t.sh), and two runs differed (gzip
header time, file modes from the umask)."""

import gzip
import os
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tests import _support

GIT = shutil.which("git")
LEGIT = {
    "README.md": "# Lazaret\n",
    "LICENSE": "Apache License\n",
    "python/pyproject.toml": "[build-system]\n",
    "python/src/lazaret/__init__.py": '__version__ = "0.0.1"\n',
    "python/src/lazaret/scanner/core.py": "def main():\n    pass\n",
    "python/tests/fixtures/cfgproj/.lazaret-taint.json": "{}\n",   # a dotfile fixture: ships
    "scripts/check-versions.sh": "#!/bin/sh\necho ok\n",
    "examples/.env.example": "DB_PASSWORD=change-me\n",           # a template: ships
    "docs/RELEASING.md": "# Releasing\n",
}
CREDENTIALS = ["python/.npmrc", "js/.npmrc", ".github/.pypirc", "python/.envrc", "docs/.netrc",
               "scripts/deploy.pem", "python/src/lazaret/tls.key", "examples/id_rsa",
               "examples/id_ed25519.pub", "docs/.git-credentials", "python/.env.local",
               "js/cert.P12"]
JUNK = ["python/src/lazaret/._core.py", "docs/.DS_Store", "js/node_modules/x/index.js",
        "python/src/lazaret/__pycache__/core.cpython-312.pyc"]
STRAY = ["scripts/..t.sh", "docs/notes-to-self.txt"]


def make_bundle():
    return _support.load_script(_support.MAKE_BUNDLE, "make_bundle_review")


class BundleCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = os.path.join(self._tmp.name, "repo")
        self.write(LEGIT)
        os.chmod(os.path.join(self.repo, "scripts", "check-versions.sh"), 0o755)

    def write(self, files):
        for rel, text in files.items():
            path = os.path.join(self.repo, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", newline="\n") as f:
                f.write(text)

    def plant(self, rels):
        self.write({rel: "SECRET=dummy-not-a-secret\n" for rel in rels})

    def bundle(self, name="out.tgz", *extra, env=None):
        out = os.path.join(self._tmp.name, name)
        p = subprocess.run([sys.executable, _support.MAKE_BUNDLE, out, "--repo", self.repo, *extra],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40,
                           env=dict(os.environ, **(env or {})))
        self.assertEqual(p.returncode, 0, p.stderr)
        with tarfile.open(out) as tf:
            names = sorted(m.name[len("lazaret/"):] for m in tf.getmembers())
        return out, names, p.stderr

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
                   GIT_CONFIG_NOSYSTEM="1", HOME=self._tmp.name)
        subprocess.run([GIT, *args], cwd=self.repo, env=env, check=True, capture_output=True, timeout=30)


class CredentialFileTests(BundleCase):
    def test_names(self):
        mb = make_bundle()
        for rel in CREDENTIALS + [".env", "a/.env.production", "id_ecdsa", "id_dsa.pub", "x/_netrc",
                                  "server.PEM", "k.pfx"]:
            self.assertTrue(mb.is_credential_file(rel), rel)
            self.assertTrue(mb.is_junk(rel), rel)
        for rel in ("examples/.env.example", "keys.py", "monkey.js", "docs/pem-format.md",
                    "fixtures/cfgproj/.lazaret-taint.json", "identity.py"):
            self.assertFalse(mb.is_junk(rel), rel)

    def test_gitignore_lists_the_same_names(self):
        with open(os.path.join(_support.REPO_ROOT, ".gitignore"), encoding="utf-8") as f:
            ignored = {line.strip() for line in f}
        self.assertEqual([p for p in make_bundle().CREDENTIAL_NAMES if p not in ignored], [])
        self.assertTrue({".env", ".env.*", "!.env.example"} <= ignored)

    def test_walk_mode_skips_credentials_and_junk(self):
        self.plant(CREDENTIALS + JUNK)
        _, names, err = self.bundle("walk.tgz", "--no-git")
        self.assertEqual(names, sorted(LEGIT))
        self.assertIn("skipping prior-run artifact or credential file: python/.npmrc", err)

    def test_strict_mode_fails_on_a_credential_file(self):
        self.plant(["python/.pypirc"])
        p = subprocess.run([sys.executable, _support.MAKE_BUNDLE, os.path.join(self._tmp.name, "s.tgz"),
                            "--repo", self.repo, "--no-git", "--strict"],
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 1)
        self.assertIn("python/.pypirc", p.stderr)

    def test_symlinks_are_not_followed(self):
        target = os.path.join(self._tmp.name, "outside-secret.txt")
        with open(target, "w") as f:
            f.write("not part of the repo\n")
        try:
            os.symlink(target, os.path.join(self.repo, "docs", "linked.md"))
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"cannot create symlinks here: {exc}")
        _, names, err = self.bundle("link.tgz", "--no-git")
        self.assertNotIn("docs/linked.md", names)
        self.assertIn("symlink: docs/linked.md", err)


@unittest.skipUnless(GIT, "git not installed")
class GitTrackedTests(BundleCase):
    def setUp(self):
        super().setUp()
        self.git("init", "-q")
        self.git("add", *LEGIT)
        self.git("update-index", "--chmod=+x", "scripts/check-versions.sh")   # also where chmod is a no-op (Windows)
        self.git("commit", "-q", "-m", "legit")

    def test_only_tracked_files_ship(self):
        self.plant(STRAY + CREDENTIALS + JUNK)
        _, names, err = self.bundle()
        self.assertEqual(names, sorted(LEGIT))
        self.assertIn("not tracked by git, not bundled: scripts/..t.sh", err)
        # ...and the walk fallback would have taken the stray files
        _, walked, _ = self.bundle("walk.tgz", "--no-git")
        self.assertEqual(sorted(set(walked) - set(names)), sorted(STRAY))

    def test_tracked_credential_files_still_never_ship(self):
        self.plant(["python/.npmrc", "examples/id_rsa"])
        self.git("add", "-f", "python/.npmrc", "examples/id_rsa")
        self.git("commit", "-q", "-m", "oops")
        _, names, err = self.bundle()
        self.assertEqual(names, sorted(LEGIT))
        self.assertIn("python/.npmrc", err)

    def test_modes_come_from_git(self):
        out, _, _ = self.bundle()
        with tarfile.open(out) as tf:
            modes = {m.name: m.mode for m in tf.getmembers()}
        self.assertEqual(modes["lazaret/scripts/check-versions.sh"], 0o755)
        self.assertEqual(modes["lazaret/README.md"], 0o644)


class DeterminismTests(BundleCase):
    def test_two_runs_are_byte_identical(self):
        for extra in ((), ("--no-git",)):
            with self.subTest(mode=extra or "default"):
                first, _, _ = self.bundle("a.tgz", *extra)
                os.utime(os.path.join(self.repo, "README.md"), (1, 1))   # mtimes don't leak in
                second, _, _ = self.bundle("different-name.tgz", *extra)
                with open(first, "rb") as f1, open(second, "rb") as f2:
                    self.assertEqual(f1.read(), f2.read())

    def test_metadata_is_normalized(self):
        out, _, _ = self.bundle(env={"SOURCE_DATE_EPOCH": "1700000000"})
        with open(out, "rb") as f:
            header = f.read(10)
        self.assertEqual(struct.unpack("<I", header[4:8])[0], 1700000000)   # gzip MTIME
        self.assertEqual(header[3] & 0x08, 0)                                # no FNAME field
        with gzip.open(out) as g:
            g.read()
        with tarfile.open(out) as tf:
            for m in tf.getmembers():
                self.assertTrue(m.isreg(), m.name)
                self.assertEqual((m.uid, m.gid, m.uname, m.gname, m.mtime), (0, 0, "", "", 1700000000))
                self.assertIn(m.mode, (0o644, 0o755), m.name)
        out0, _, _ = self.bundle("zero.tgz", env={"SOURCE_DATE_EPOCH": ""})
        with tarfile.open(out0) as tf:
            self.assertEqual({m.mtime for m in tf.getmembers()}, {0})


if __name__ == "__main__":
    unittest.main()
