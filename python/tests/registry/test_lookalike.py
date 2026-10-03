"""0.1.8: names like a popular package's (SC-TYPOSQUAT, registry/lookalike.py).

A release whose own name, or a dependency it declares, is one change from
one of the 5,000 most-downloaded packages of its registry — a character
added, dropped or changed, two swapped, or the separators changed — gets a
MAJOR finding, unless the name is a popular package itself (mysql2 next to
mysql), the popular name is shorter than 5 characters, or it is in the
package's own npm scope. Archives are built in memory; nothing runs.
"""
import json
import unittest

from lazaret.registry import lookalike
from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel

META = "Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n{requires}\nA description.\n"


def typos(res):
    return [(i["file"], i["line"], i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-TYPOSQUAT"]


class LookalikeTests(unittest.TestCase):
    def test_one_change_from_a_popular_name(self):
        cases = {("pypi", "requesxs"): ("requests", "a character changed"),
                 ("pypi", "reqeusts"): ("requests", "two characters swapped"),
                 ("pypi", "python-dateuti"): ("python-dateutil", "a character dropped"),
                 ("pypi", "Python_Dateuti"): ("python-dateutil", "a character dropped"),     # PEP 503 names
                 ("pypi", "tiketoken"): ("tiktoken", "a character added"),
                 ("pypi", "pythondateutil"): ("python-dateutil", "its separators changed"),
                 ("npm", "lodahs"): ("lodash", "two characters swapped"),
                 ("npm", "expresss"): ("express", "a character added"),
                 ("npm", "@hestjs/core"): ("@nestjs/core", "a character changed")}
        for (eco, name), want in cases.items():
            with self.subTest(name):
                self.assertEqual(lookalike.lookalike(eco, name), want)

    def test_not_a_lookalike(self):
        for eco, name in (("pypi", "requests"), ("pypi", "numpy"), ("pypi", "fastai"),     # popular themselves
                          ("npm", "mysql"), ("npm", "mysql2"), ("npm", "delegate"),
                          ("npm", "fs"), ("npm", "os2"), ("pypi", "attr"),               # short popular names
                          ("npm", "@babel/corf"),                                       # its own scope's name
                          ("pypi", "a-name-far-from-any-popular-one"), ("npm", "x" * 300), ("npm", ""),
                          ("npm", None)):
            with self.subTest(name):
                self.assertIsNone(lookalike.lookalike(eco, name))

    def test_the_popular_names(self):
        with open(lookalike.__file__.replace("lookalike.py", "popular_names.json"), encoding="utf-8") as f:
            raw = json.load(f)
        for eco in ("npm", "pypi"):
            with self.subTest(eco):
                sec = raw[eco]
                self.assertEqual(len(sec["targets"]), 5000)
                self.assertEqual(len(set(sec["targets"])), 5000)
                self.assertTrue(sec["source"] and sec["license"])
                self.assertEqual(sec["known"], sorted(sec["known"]))
                # the known names are exactly the popular ones that would otherwise be flagged
                bare = lookalike.tables(sec["targets"], ())
                for name in sec["known"]:
                    self.assertIsNotNone(lookalike.lookalike(eco, name, bare), name)
                    self.assertIsNone(lookalike.lookalike(eco, name), name)
        self.assertEqual(raw["npm"]["license"], "MIT")
        self.assertIn("CC BY 4.0", raw["pypi"]["license"])

    def test_the_findings(self):
        text = json.dumps({"name": "lodahs", "version": "1.0.0", "dependencies": {"expresss": "^4", "react": "^18"}},
                          indent=2)
        found = lookalike.issues("npm", "lodahs", {"expresss", "react"}, "package.json", text)
        self.assertEqual([(i["rule"], i["sev"], i["line"], i["msg"]) for i in found], [
            ("SC-TYPOSQUAT", "MAJOR", 2, 'The package is named "lodahs", one change from "lodash" (two characters '
                                         'swapped), one of the 5,000 most-downloaded npm packages.'),
            ("SC-TYPOSQUAT", "MAJOR", 5, 'Depends on "expresss", one change from "express" (a character added), one '
                                         'of the 5,000 most-downloaded npm packages.')])


class LookalikeRegistryTests(unittest.TestCase):
    def test_an_sdist_named_like_requests(self):
        res = scan_sdist({"PKG-INFO": META.format(name="requesxs", requires=""), "setup.py": "from setuptools import setup\n"
                          "setup(name='requesxs', version='1.0')\n", "requesxs/__init__.py": ""})
        self.assertEqual(res["verdict"], "WARN", res["issues"])
        self.assertEqual(typos(res), [("PKG-INFO", 2, "MAJOR", 'The package is named "requesxs", one change from '
                                       '"requests" (a character changed), one of the 5,000 most-downloaded PyPI '
                                       'projects.')])

    def test_a_wheel_that_requires_a_lookalike(self):
        requires = "Requires-Dist: reqeusts>=2\nRequires-Dist: pytset; extra == \"dev\"\nRequires-Dist: numpy"
        res = scan_wheel({"lit/__init__.py": "", "lit-1.0.dist-info/METADATA": META.format(name="lit", requires=requires)})
        self.assertEqual([m for _f, _l, _s, m in typos(res)],
                         ['Depends on "reqeusts", one change from "requests" (two characters swapped), one of the '
                          '5,000 most-downloaded PyPI projects.'])

    def test_an_npm_package_and_its_dependencies(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0",
                                                    "dependencies": {"lodahs": "1.0.0", "chalk": "^5"},
                                                    "optionalDependencies": {"axois": "1"}})})
        self.assertEqual(res["verdict"], "WARN", res["issues"])
        self.assertEqual(sorted(m for _f, _l, _s, m in typos(res)), [
            'Depends on "axois", one change from "axios" (two characters swapped), one of the 5,000 '
            'most-downloaded npm packages.',
            'Depends on "lodahs", one change from "lodash" (two characters swapped), one of the 5,000 '
            'most-downloaded npm packages.'])

    def test_a_name_like_a_node_builtin(self):
        """0.1.8: Node's built-in modules named with a separator are compared
        too: a dependency on child-process installs a stranger's package."""
        res = scan_npm({"package.json": json.dumps({"name": "crypto-hash-kit", "version": "1.0.0",
                                                    "dependencies": {"child-process": "^1"}})})
        self.assertEqual([m for _f, _l, _s, m in typos(res)], [
            'Depends on "child-process", one change from "child_process" (its separators changed), a module '
            "built into Node."])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
        res = scan_npm({"package.json": json.dumps({"name": "worker-threads", "version": "1.0.0"})})
        self.assertEqual([m for _f, _l, _s, m in typos(res)], [
            'The package is named "worker-threads", one change from "worker_threads" (its separators changed), a '
            "module built into Node."])
        for name, want in (("childprocess", ("child_process", "its separators changed")),
                           ("child_proces", ("child_process", "a character dropped")),
                           ("perf_hook", ("perf_hooks", "a character dropped")),
                           ("child_process", None), ("events", None), ("async-hook", None),
                           ("child-process-promise", None)):
            with self.subTest(name):
                self.assertEqual(lookalike.builtin_lookalike(name), want)

    def test_popular_packages_stay_ok(self):
        res = scan_npm({"package.json": json.dumps({"name": "express", "version": "4.0.0",
                                                    "dependencies": {"debug": "2", "mysql2": "3", "qs": "6"}})})
        self.assertEqual(typos(res), [])
        res = scan_wheel({"requests/__init__.py": "", "requests-2.0.dist-info/METADATA": META.format(
            name="requests", requires="Requires-Dist: urllib3\nRequires-Dist: idna")})
        self.assertEqual(typos(res), [])


if __name__ == "__main__":
    unittest.main()
