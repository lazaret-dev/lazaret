"""scripts/check-versions.sh and scripts/tag-release.sh, run against a
throwaway repository with a bare "origin".

The incident they prevent: v0.1.0 was pushed pointing at a commit whose
version files still said 0.0.1. check-versions.sh read the working tree, so
it passed with the bump uncommitted, and nothing checked the tag itself.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

from tests import _support

SH, GIT, NODE = shutil.which("sh"), shutil.which("git"), shutil.which("node")
SCRIPTS = os.path.join(_support.REPO_ROOT, "scripts")

# Stands in for gpg: emits a signature block and the status line git expects.
FAKE_SIGNER = textwrap.dedent("""\
    #!/bin/sh
    cat >/dev/null
    echo "[GNUPG:] SIG_CREATED D 22 8 00 0 FAKEKEY" >&2
    printf -- '-----BEGIN PGP SIGNATURE-----\\n\\nZmFrZSBzaWduYXR1cmU=\\n-----END PGP SIGNATURE-----\\n'
    """)


def version_files(py, js, crlf=False):
    nl = "\r\n" if crlf else "\n"
    return {
        "python/src/lazaret/__init__.py": f'"""Lazaret."""{nl}__version__ = "{py}"{nl}',
        "js/package.json": f'{{{nl}  "name": "lazaret",{nl}  "version": "{js}"{nl}}}{nl}',
    }


@unittest.skipUnless(SH and GIT and NODE, "needs sh, git and node")
class RepoCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        tmp = self._tmp.name
        home = os.path.join(tmp, "home")
        os.makedirs(home)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("GIT_", "GITHUB_", "RELEASE_"))}
        self.env.update(HOME=home, USERPROFILE=home, GIT_CONFIG_NOSYSTEM="1",
                        GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.invalid",
                        GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.invalid")
        self.origin = os.path.join(tmp, "origin.git")
        self.repo = os.path.join(tmp, "work")
        subprocess.run([GIT, "init", "-q", "--bare", self.origin], check=True, env=self.env)
        os.makedirs(os.path.join(self.repo, "scripts"))
        for name in ("check-versions.sh", "tag-release.sh"):
            shutil.copy2(os.path.join(SCRIPTS, name), os.path.join(self.repo, "scripts", name))
        self.git("init", "-q")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        self.git("config", "core.autocrlf", "false")
        self.git("remote", "add", "origin", self.origin)
        self.commit(version_files("0.0.1", "0.0.1"), "Release 0.0.1")
        self.git("push", "-q", "origin", "main")

    def git(self, *args, check=True):
        p = subprocess.run([GIT, *args], cwd=self.repo, env=self.env, capture_output=True,
                           encoding="utf-8", errors="replace", timeout=30)
        if check and p.returncode:
            raise AssertionError(f"git {' '.join(args)}: {p.stderr}")
        return p.stdout.strip()

    def write(self, files):
        for rel, text in files.items():
            path = os.path.join(self.repo, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.write(text)

    def commit(self, files, msg):
        self.write(files)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)

    def run_script(self, name, *args, env=None):
        return subprocess.run([SH, os.path.join("scripts", name), *args], cwd=self.repo,
                              env=dict(self.env, **(env or {})), capture_output=True,
                              encoding="utf-8", errors="replace", timeout=40)


class CheckVersionsTests(RepoCase):
    def check(self, *args, env=None):
        return self.run_script("check-versions.sh", *args, env=env)

    def test_clean_tree(self):
        p = self.check()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("python: 0.0.1  npm: 0.0.1", p.stdout)

    def test_uncommitted_bump_fails_but_head_reads_the_commit(self):
        self.write(version_files("0.1.0", "0.1.0"))
        p = self.check()
        self.assertEqual(p.returncode, 1)
        self.assertIn("uncommitted changes to the version files", p.stderr)
        p = self.check("HEAD")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("python: 0.0.1  npm: 0.0.1", p.stdout)   # what a tag would get
        p = self.check("HEAD", "v0.1.0")
        self.assertEqual(p.returncode, 1)
        self.assertIn("tag v0.1.0 does not match the committed version v0.0.1", p.stderr)

    def test_a_tag_is_checked_against_its_own_commit(self):
        old = self.git("rev-parse", "HEAD")
        self.git("tag", "v0.0.1")
        self.commit(version_files("0.1.0", "0.1.0"), "Bump version to 0.1.0")
        self.git("tag", "v0.1.0", old)                  # the incident: tag on the old commit
        p = self.check("v0.0.1")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("tag: v0.0.1 matches", p.stdout)
        p = self.check("v0.1.0")
        self.assertEqual(p.returncode, 1)
        self.assertIn("tag v0.1.0 does not match the committed version v0.0.1", p.stderr)
        self.assertIn("Recovering from a bad tag", p.stderr)
        self.assertEqual(self.check().returncode, 0)    # the tree itself is consistent

    def test_ci_tag_push(self):
        p = self.check(env={"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v0.0.1"})
        self.assertEqual(p.returncode, 0, p.stderr)
        p = self.check(env={"GITHUB_REF_TYPE": "tag", "GITHUB_REF_NAME": "v0.1.0"})
        self.assertEqual(p.returncode, 1)
        p = self.check(env={"GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main"})
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_crlf_files(self):
        self.commit(version_files("0.0.2", "0.0.2", crlf=True), "CRLF")
        for args in ((), ("HEAD",), ("HEAD", "v0.0.2")):
            p = self.check(*args)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("python: 0.0.2  npm: 0.0.2  (", p.stdout)

    def test_mismatch_and_unknown_ref(self):
        self.commit(version_files("0.0.2", "0.0.1"), "Half a bump")
        p = self.check()
        self.assertEqual(p.returncode, 1)
        self.assertIn("version mismatch: python 0.0.2, npm 0.0.1", p.stderr)
        p = self.check("no-such-ref")
        self.assertEqual(p.returncode, 1)
        self.assertIn("unknown git ref", p.stderr)


class TagReleaseTests(RepoCase):
    def tag(self, *args):
        return self.run_script("tag-release.sh", *args)

    def use_signer(self, program):
        self.git("config", "gpg.program", program)
        self.git("config", "user.signingkey", "FAKEKEY")

    def assertNoTags(self):
        self.assertEqual(self.git("tag", "-l"), "")
        self.assertEqual(self.git("ls-remote", "--tags", "origin"), "")

    def test_refuses_uncommitted_changes(self):
        self.write({"js/package.json": version_files("0.0.1", "0.0.2")["js/package.json"]})
        p = self.tag()
        self.assertEqual(p.returncode, 1)
        self.assertIn("uncommitted changes", p.stderr)
        self.assertNoTags()

    def test_refuses_a_commit_that_is_not_on_main(self):
        self.commit(version_files("0.0.2", "0.0.2"), "Local only")
        p = self.tag()
        self.assertEqual(p.returncode, 1)
        self.assertIn("is not on refs/remotes/origin/main", p.stderr)
        self.git("switch", "-q", "-c", "feature", "main~0")
        p = self.tag()
        self.assertEqual(p.returncode, 1)
        self.assertNoTags()

    def test_refuses_a_tag_that_does_not_match_the_committed_version(self):
        p = self.tag("v0.1.0")
        self.assertEqual(p.returncode, 1)
        self.assertIn("does not match the committed version v0.0.1", p.stderr)
        p = self.tag("0.0.1")
        self.assertEqual(p.returncode, 1)
        self.assertIn("vX.Y.Z", p.stderr)
        self.assertNoTags()

    def test_never_creates_an_unsigned_tag(self):
        self.use_signer("false")               # a signing program that always fails
        p = self.tag()
        self.assertEqual(p.returncode, 1)
        self.assertIn("could not sign the tag, so no tag was created", p.stderr)
        self.assertIn("gpg.format ssh", p.stderr)
        self.assertNoTags()

    @unittest.skipIf(sys.platform == "win32", "the fake signer is a shell script")
    def test_creates_a_signed_annotated_tag_and_prints_a_single_tag_push(self):
        signer = os.path.join(self._tmp.name, "fake-gpg")
        with open(signer, "w", newline="\n") as f:
            f.write(FAKE_SIGNER)
        os.chmod(signer, 0o755)
        self.use_signer(signer)
        p = self.tag()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.git("cat-file", "-t", "v0.0.1"), "tag")
        self.assertIn("-----BEGIN PGP SIGNATURE-----", self.git("cat-file", "tag", "v0.0.1"))
        self.assertEqual(self.git("rev-parse", "v0.0.1^{commit}"), self.git("rev-parse", "HEAD"))
        self.assertIn("git push origin refs/tags/v0.0.1", p.stdout)
        self.assertNotIn("--tags\n", p.stdout)
        self.assertEqual(self.git("ls-remote", "--tags", "origin"), "")   # it never pushes
        # a second run refuses: the tag exists locally
        p = self.tag()
        self.assertEqual(p.returncode, 1)
        self.assertIn("already exists locally", p.stderr)

    def test_refuses_a_tag_that_is_already_on_the_remote(self):
        self.git("tag", "v0.0.1")
        self.git("push", "-q", "origin", "refs/tags/v0.0.1")
        self.git("tag", "-d", "v0.0.1")
        p = self.tag()
        self.assertEqual(p.returncode, 1)
        self.assertIn("already exists on origin", p.stderr)
        self.assertIn("Recovering from a bad tag", p.stderr)


if __name__ == "__main__":
    unittest.main()
