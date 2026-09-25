"""No pre-rename "CodeGuard" branding in anything that ships.

The dashboard header still read Code<span>Guard</span> (and "Python &
JavaScript", omitting SQL), and the CLI's HTML report header does too
(scanner/core.py, fixed separately by the core-cli owner). Markup is stripped
before matching, so a name split across tags is still caught."""

import os
import re
import unittest

from tests import _support

SHIPPED_TREES = [os.path.join(_support.PKG),                               # python/src/lazaret
                 os.path.join(_support.REPO_ROOT, "js", "src"),
                 os.path.join(_support.REPO_ROOT, "js", "bin")]
SHIPPED_FILES = [os.path.join(_support.PY_ROOT, "README.md"),
                 os.path.join(_support.REPO_ROOT, "js", "README.md"),
                 os.path.join(_support.REPO_ROOT, "js", "package.json")]
OLD_NAME = re.compile(r"code[\s_-]*guard", re.I)
TAG = re.compile(r"<[^<>]*>")


def shipped_text_files():
    for tree in SHIPPED_TREES:
        for root, dirs, files in os.walk(tree):
            dirs[:] = [d for d in dirs if d not in ("__pycache__", "node_modules")]
            for name in files:
                if not name.endswith((".pyc", ".pyo")):
                    yield os.path.join(root, name)
    yield from (f for f in SHIPPED_FILES if os.path.isfile(f))


class BrandingTests(unittest.TestCase):
    def test_no_codeguard_in_shipped_files(self):
        offenders = []
        for path in shipped_text_files():
            with open(path, encoding="utf-8", errors="replace") as f:
                for no, line in enumerate(f, 1):
                    if OLD_NAME.search(line) or OLD_NAME.search(TAG.sub("", line)):
                        offenders.append(f"{os.path.relpath(path, _support.REPO_ROOT)}:{no}: {line.strip()[:100]}")
        self.assertEqual(offenders, [])

    def test_the_check_sees_through_markup(self):
        line = '<div class="logo">Code<span>Guard</span></div>'
        self.assertTrue(OLD_NAME.search(TAG.sub("", line)))

    def test_dashboard_header(self):
        with open(os.path.join(_support.PKG, "web", "lazaret.html"), encoding="utf-8") as f:
            header = re.search(r"<header>(.*?)</header>", f.read(), re.S).group(1)
        text = " ".join(TAG.sub(" ", header).split())
        self.assertIn("Lazaret", text)
        self.assertIn("SQL", text)


if __name__ == "__main__":
    unittest.main()
