"""`make_typosquat_stubs.py --check`: which misspellings are still up for
grabs. Twelve hours after lazaret 0.0.1 went live, lazarat, lazarett and
lazeret were unclaimed on both PyPI and npm; the check makes that visible
(exit 1) instead of relying on someone remembering step 7. No network here:
the registry lookups are faked."""

import io
import os
import unittest

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "make_typosquat_stubs.py")


def stubs():
    return _support.load_script(SCRIPT, "make_typosquat_stubs_check")


def registry(answers):
    """fetch() stand-in: answers maps (registry host, name) -> (status, data) or an exception."""
    def fetch(url):
        host = "pypi" if "pypi.org" in url else "npm"
        name = url.rstrip("/").split("/")[-2 if host == "pypi" else -1]
        answer = answers[(host, name)]
        if isinstance(answer, BaseException):
            raise answer
        return answer
    return fetch


OURS_PYPI = (200, {"info": {"summary": "Reserved misspelling of lazaret. Install 'lazaret' instead."}})
OURS_NPM = (200, {"description": "Reserved misspelling of lazaret. Install 'lazaret' instead."})


class TyposquatCheckTests(unittest.TestCase):
    def run_check(self, answers, names=("lazarat",)):
        out = io.StringIO()
        code = stubs().check_names(list(names), fetch=registry(answers), out=out)
        return code, out.getvalue()

    def test_unclaimed_names_fail(self):
        code, out = self.run_check({("pypi", "lazarat"): (404, None), ("npm", "lazarat"): (404, None)})
        self.assertEqual(code, 1)
        self.assertIn("lazarat is UNCLAIMED on PyPI", out)
        self.assertIn("lazarat is UNCLAIMED on npm", out)
        self.assertIn("step 7", out)

    def test_our_stubs_pass(self):
        code, out = self.run_check({("pypi", "lazarat"): OURS_PYPI, ("npm", "lazarat"): OURS_NPM})
        self.assertEqual(code, 0)
        self.assertIn("All misspellings are reserved.", out)

    def test_a_name_held_by_someone_else_fails(self):
        code, out = self.run_check({("pypi", "lazarat"): OURS_PYPI,
                                    ("npm", "lazarat"): (200, {"description": "totally legit"})})
        self.assertEqual(code, 1)
        self.assertIn("HELD BY SOMEONE ELSE", out)

    def test_offline_warns_and_passes(self):
        err = OSError("network is unreachable")
        code, out = self.run_check({("pypi", "lazarat"): err, ("npm", "lazarat"): err})
        self.assertEqual(code, 0)
        self.assertIn("warning: could not reach every registry", out)
        self.assertNotIn("All misspellings are reserved.", out)

    def test_partial_offline_still_reports_what_it_saw(self):
        code, out = self.run_check({("pypi", "lazarat"): (404, None), ("npm", "lazarat"): OSError("down")})
        self.assertEqual(code, 1)
        self.assertIn("lazarat is UNCLAIMED on PyPI", out)
        self.assertIn("warning: could not reach", out)

    def test_default_names_and_name_validation(self):
        s = stubs()
        self.assertEqual(s.DEFAULT_NAMES, ["lazarat", "lazarett", "lazeret"])
        with self.assertRaises(ValueError):
            s.check_names(["../evil"], fetch=registry({}))


if __name__ == "__main__":
    unittest.main()
