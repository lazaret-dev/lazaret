"""D-13 (0.1.9): a package an npm release's code loads when the package is loaded that its package.json names only in
devDependencies, which npm does not install for the package's users.

dotenv-express 17.4.3 (the benchmark's) is a copy of dotenv with `const gate = require('environment-gate')` added at
the top of lib/main.js, and `gate.gate()` called first in config(); its package.json lists environment-gate only in
devDependencies. It was OK. Such a load is now SC-DEV-DEPENDENCY (MAJOR, so WARN), read on the engine's tree (a
require() given a literal outside any function, class body and try statement; an import or export-from declaration).

The code is what the package's main entry and its commands reach: not a subpath export, which runs when a user
imports it by name (@cucumber/cucumber's `./lib/*` exports its test helpers, which load its test tools), nor a type
declaration.

Not flagged: a load in a function (it runs when the function is called) or a try (an optional dependency); a package
the release installs (dependencies, optionalDependencies, peerDependencies, bundled); one of npm's most-downloaded
packages (es-abstract loads for-each, listed only there); one of the release's own scope; Ember's own modules, which
the app provides; a package no field names (cypress/svelte loads the framework its user brings); a file nothing
loads. Measured first: none of the popular set's 801 npm releases, the benchmark's 219 popular ones or the 1,623
installed packages here has one.

Payloads are inert: nothing is installed or run.
"""
import unittest

from tests.registry._review_support import issues, manifest, scan_npm

DX = ("const fs = require('fs')\nconst path = require('path')\nconst gate = require('environment-gate')\n\n"
      "function config (options) {\n  gate.gate()\n  return { parsed: {} }\n}\n\nmodule.exports = { config }\n")


def dev_dep(res):
    return [(i["file"], i["line"], i["sev"], i["msg"]) for i in issues(res, "SC-DEV-DEPENDENCY")]


def scan(main_text, main="lib/main.js", extra=None, **fields):
    files = {"package.json": manifest(main=main, **fields), main: main_text}
    files.update(extra or {})
    return scan_npm(files)


class FoundTests(unittest.TestCase):
    def test_dotenv_express(self):
        res = scan(DX, devDependencies={"tap": "^19.2.0", "environment-gate": "^7.3.5"})
        ((file, line, sev, msg),) = dev_dep(res)
        self.assertEqual((file, line, sev), ("lib/main.js", 3, "MAJOR"))
        self.assertIn('lib/main.js, which runs when the package is loaded or its command runs, loads "environment-gate"',
                      msg)
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])

    def test_the_forms_that_load_it(self):
        dev = {"devDependencies": {"payload-x": "1.0.0"}}
        for text in ("import p from 'payload-x';\n", "import 'payload-x/register';\n", "export * from 'payload-x';\n",
                     "export { a } from 'payload-x';\n", "if (process.env.CI !== '1') { require('payload-x'); }\n",
                     "const p = require(`payload-x`);\n", "class C { static { require('payload-x'); } }\n"):
            with self.subTest(text):
                ((file, line, _sev, _msg),) = dev_dep(scan(text, main="index.mjs" if "import" in text or
                                                             "export" in text else "index.js", **dev))
                self.assertEqual(line, 1)

    def test_a_module_the_entry_point_loads(self):
        res = scan("module.exports = require('./lib/inner');\n", main="index.js",
                   extra={"lib/inner.js": "require('payload-x');\nmodule.exports = 1;\n"},
                   devDependencies={"payload-x": "1"})
        self.assertEqual([(f, ln) for f, ln, _s, _m in dev_dep(res)], [("lib/inner.js", 1)])

    def test_the_main_entry_of_exports_and_a_command(self):
        for fields in ({"exports": {".": {"types": "./index.d.ts", "require": "./lib/main.js"}}},
                       {"exports": {"require": "./lib/main.js", "default": "./lib/main.js"}},
                       {"exports": "./lib/main.js"},
                       {"bin": {"x": "./lib/main.js"}}):
            with self.subTest(fields):
                res = scan("module.exports = 1;\n", main="index.js", extra={"lib/main.js": DX},
                           devDependencies={"environment-gate": "1"}, **fields)
                self.assertEqual([(f, ln) for f, ln, _s, _m in dev_dep(res)], [("lib/main.js", 3)])


class NotFoundTests(unittest.TestCase):
    def test_what_does_not_run_when_it_is_loaded(self):
        dev = {"devDependencies": {"payload-x": "1"}}
        for text in ("function f() { return require('payload-x'); }\nmodule.exports = f;\n",
                     "try { require('payload-x'); } catch (e) {}\n",
                     "module.exports = () => import('payload-x');\n",
                     "class C { m() { return require('payload-x'); } }\n",
                     "// require('payload-x')\nconst s = \"require('payload-x')\";\n"):
            with self.subTest(text):
                self.assertEqual(dev_dep(scan(text, main="index.js", **dev)), [])

    def test_what_the_release_installs_or_needs_no_install(self):
        for fields in ({"dependencies": {"payload-x": "1"}, "devDependencies": {"payload-x": "1"}},
                       {"optionalDependencies": {"payload-x": "1"}, "devDependencies": {"payload-x": "1"}},
                       {"peerDependencies": {"payload-x": "1"}, "devDependencies": {"payload-x": "1"}},
                       {"bundleDependencies": ["payload-x"], "devDependencies": {"payload-x": "1"}},
                       {"dependencies": {}},                                  # (named nowhere: not this test)
                       {"devDependencies": {"events": "3"}}):                 # (Node's own module)
            with self.subTest(fields):
                text = "require('payload-x');\nrequire('events');\n"
                self.assertEqual(dev_dep(scan(text, main="index.js", **fields)), [])

    def test_popular_own_scope_and_ember(self):
        cases = [("require('for-each');\n", {"for-each": "1"}, "x"),                  # (one of npm's 5,000)
                 ("require('@me/helper');\n", {"@me/helper": "1"}, "@me/x"),       # (the release's own scope)
                 ("import { tracked } from '@glimmer/tracking';\n", {"@glimmer/tracking": "1"}, "x")]  # (Ember's)
        for text, dev, name in cases:
            with self.subTest(text):
                self.assertEqual(dev_dep(scan(text, main="index.mjs", devDependencies=dev, name=name)), [])

    def test_a_subpath_export_or_a_type_declaration(self):
        helper = {"lib/api/test_helpers.js": "const r = require('payload-x');\nexports.setup = () => r;\n",
                  "index.d.ts": "import { P } from 'payload-x';\nexport declare const x: P;\n"}
        for exports in ({".": "./index.js", "./helpers": "./lib/api/test_helpers.js"},
                        {".": {"types": "./index.d.ts", "require": "./index.js"}, "./lib/*": {"require": "./lib/*.js"}}):
            with self.subTest(exports):
                res = scan("module.exports = 1;\n", main="index.js", extra=helper, exports=exports, types="index.d.ts",
                           devDependencies={"payload-x": "1"})
                self.assertEqual(dev_dep(res), [])

    def test_a_file_nothing_loads(self):
        res = scan("module.exports = 1;\n", main="index.js", extra={"scripts/dev.js": DX},
                   devDependencies={"environment-gate": "1"})
        self.assertEqual(dev_dep(res), [])


if __name__ == "__main__":
    unittest.main()
