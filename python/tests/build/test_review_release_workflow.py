"""The npm commands in the GitHub workflows name local files as paths npm
reads as paths.

npm resolves a package argument like "npm-dist/lazaret-0.1.0.tgz" as the
GitHub repository npm-dist/lazaret-0.1.0.tgz, not as a file, and tries to
clone it: the v0.1.0 release run failed that way in `npm stage publish`,
after PyPI had already published. A local path needs "./" (or "../", "/").
"""

import glob
import os
import re
import shlex
import unittest

from tests import _support

WORKFLOWS = os.path.join(_support.REPO_ROOT, ".github", "workflows")
NPM_CMD = re.compile(r"\bnpm\s+(?:stage\s+)?(?:publish|install|i|add|pack)\b(.*)")
LOCAL = ("./", "../", "/", "~/", "$")         # "$VAR/x": the variable holds a path


def misread_specs(text):
    """-> [(line number, argument)] for npm arguments npm would take for a
    GitHub owner/repo instead of the local file they name."""
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        code = line.strip()
        if code.startswith("#"):
            continue
        if code.startswith("- run:"):
            code = code[len("- run:"):]
        m = NPM_CMD.search(code)
        if not m:
            continue
        try:
            args = shlex.split(m.group(1), comments=True)
        except ValueError:
            args = m.group(1).split()
        for arg in args:
            if (arg.startswith("-") or "/" not in arg or arg.startswith(LOCAL)
                    or arg.startswith("@") or "://" in arg or arg in ("|", "&&", ";")):
                continue
            found.append((n, arg))
    return found


class NpmPathTests(unittest.TestCase):
    def test_workflows_pass_local_paths_npm_reads_as_paths(self):
        for path in sorted(glob.glob(os.path.join(WORKFLOWS, "*.yml"))):
            with self.subTest(workflow=os.path.basename(path)):
                with open(path, encoding="utf-8") as fh:
                    self.assertEqual(misread_specs(fh.read()), [])

    def test_the_check_catches_the_v010_line(self):
        bad = '      - run: npm stage publish "npm-dist/lazaret-${GITHUB_REF_NAME#v}.tgz"\n'
        good = ('      - run: npm stage publish "./npm-dist/lazaret-${GITHUB_REF_NAME#v}.tgz"\n'
                "          npm pack --ignore-scripts --pack-destination ../npm-dist\n"
                "      # npm publish npm-dist/x.tgz (a comment)\n"
                "        run: npm install @scope/pkg lazaret\n")
        self.assertEqual(misread_specs(bad), [(1, "npm-dist/lazaret-${GITHUB_REF_NAME#v}.tgz")])
        self.assertEqual(misread_specs(good), [])


if __name__ == "__main__":
    unittest.main()
