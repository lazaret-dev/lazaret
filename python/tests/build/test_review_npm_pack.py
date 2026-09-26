"""The npm tarball never carries dotfiles or keys.

package.json "files" whitelists bin/ and src/, and npm's built-in ignores
already drop ._*, .DS_Store, *.orig and .*.swp, but a .env, .env.local,
.envrc, id_rsa or *.pem inside those directories was packed. The negations
at the end of "files" exclude them; this runs `npm pack --dry-run` on a copy
of js/ with such files planted.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

from tests import _support

JS = os.path.join(_support.REPO_ROOT, "js")
PLANTED = ["src/.env", "src/.env.local", "src/lib/.env.production", "bin/.env", "src/.envrc",
           "src/._index.js", "src/.DS_Store", "src/scanner/.hidden.js", "src/.cache/a.js",
           "src/.npmrc", "src/id_rsa", "src/id_ed25519.pub", "src/server.pem", "src/tls.key"]


def npm():
    return shutil.which("npm")


def packed(root):
    env = dict(os.environ, npm_config_update_notifier="false", npm_config_fund="false",
               npm_config_audit="false", npm_config_cache=os.path.join(root, ".npm-cache"))
    p = subprocess.run([npm(), "pack", "--dry-run", "--json", "--ignore-scripts"], cwd=root,
                       capture_output=True, encoding="utf-8", errors="replace", env=env, timeout=40)
    if p.returncode != 0:
        raise AssertionError(p.stderr[-2000:])
    return sorted(f["path"] for f in json.loads(p.stdout)[0]["files"])


@unittest.skipUnless(npm(), "npm not installed")
class NpmPackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = os.path.join(self.tmp.name, "js")
        os.makedirs(self.root)
        for name in ("package.json", "README.md", "LICENSE"):
            shutil.copy2(os.path.join(JS, name), self.root)
        for tree in ("bin", "src"):
            shutil.copytree(os.path.join(JS, tree), os.path.join(self.root, tree))

    def test_planted_dotfiles_and_keys_are_not_packed(self):
        clean = packed(self.root)
        self.assertIn("src/index.js", clean)
        self.assertIn("bin/lazaret.js", clean)
        for rel in PLANTED:
            path = os.path.join(self.root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write("TOKEN=dummy-not-a-secret\n")
        self.assertEqual(packed(self.root), clean)


if __name__ == "__main__":
    unittest.main()
