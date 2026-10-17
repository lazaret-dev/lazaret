"""D-9 (0.1.9): code written into another package's folder, when the package is loaded or installed.

@dinzid04/libsignal-node 2.2.5 (the benchmark's) finds @whiskeysockets/baileys (`require.resolve` of its
package.json, or a path joined from `node_modules`) and writes its own text over baileys's
`lib/Socket/newsletter.js` a second after it is loaded; it was OK. A code file (`.js`, `.cjs`, `.mjs`) written,
copied or moved into another package's folder (named by `require.resolve('<pkg>…')` or `node_modules` and the
package's name) is now "rewrites another package's code (<pkg>)": SC-IMPORT-RISK CRITICAL when the package is loaded,
SC-INSTALL-HOOK CRITICAL in an install script. The release's own package and its scope are its own code; a data file,
a dot folder (`node_modules/.cache`) and a read are not rewrites.

Payloads are inert: nothing is installed or run.
"""
import json
import unittest

from tests.registry._review_support import issues, manifest, scan_npm

FIND = ("const fs = require('fs');\nconst path = require('path');\nfunction findTarget() {\n"
        "  const possible = [path.join(process.cwd(), 'node_modules', '@whiskeysockets', 'baileys')];\n"
        "  try { possible.unshift(require.resolve('@whiskeysockets/baileys/package.json').replace('/package.json', '')); }"
        " catch (e) {}\n"
        "  for (const p of possible) { if (fs.existsSync(path.join(p, 'lib', 'Socket', 'newsletter.js'))) return p; }\n"
        "  return null;\n}\n")
PATCH = ("const MODIFIED = `'use strict';\\nexports.x = 1;\\n`;\n"
         "function install() {\n  const base = findTarget();\n  if (!base) return;\n"
         "  fs.writeFileSync(path.join(base, 'lib', 'Socket', 'newsletter.js'), MODIFIED);\n}\n")
INDEX = "exports.ok = 1;\nsetTimeout(() => { require('./install').install(); }, 1000);\n"
REASON = "rewrites another package's code (@whiskeysockets/baileys)"


def found(res, rule):
    return [(i["file"], i["sev"], i["msg"]) for i in issues(res, rule)]


class RewriteTests(unittest.TestCase):
    def test_at_import_libsignal_nodes_shape(self):
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": INDEX,
                        "install.js": FIND + PATCH + "module.exports = { install };\n"})
        ((file, sev, msg),) = found(res, "SC-IMPORT-RISK")
        self.assertEqual((file, sev), ("install.js", "CRITICAL"))
        self.assertIn(REASON, msg)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_in_an_install_script(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0",
                                                    "scripts": {"postinstall": "node setup.js"}}),
                        "setup.js": FIND + PATCH + "install();\n"})
        self.assertTrue(any(REASON in m for _f, _s, m in found(res, "SC-INSTALL-HOOK")), found(res, "SC-INSTALL-HOOK"))
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_the_ways_to_name_its_folder(self):
        # require.resolve alone, a path joined from node_modules alone, an ES module's createRequire and
        # import.meta.resolve
        head = "const fs = require('fs');\nconst path = require('path');\n"
        esm = ("import fs from 'fs';\nimport path from 'path';\nimport { createRequire } from 'module';\n"
               "import { fileURLToPath } from 'url';\nconst require = createRequire(import.meta.url);\n")
        cases = [("index.js", head + "const base = path.dirname(require.resolve('@whiskeysockets/baileys'));\n"
                  "fs.writeFileSync(path.join(base, 'lib', 'Socket', 'newsletter.js'), 'exports.x = 1;');\n"),
                 ("index.js", head + "fs.writeFileSync(path.join(process.cwd(), 'node_modules/@whiskeysockets/baileys', "
                  "'lib', 'Socket', 'newsletter.js'), 'exports.x = 1;');\n"),
                 ("index.mjs", esm + "const base = path.dirname(require.resolve('@whiskeysockets/baileys'));\n"
                  "fs.writeFileSync(path.join(base, 'lib', 'Socket', 'newsletter.js'), 'exports.x = 1;');\n"),
                 ("index.mjs", esm + "const base = path.dirname(fileURLToPath(import.meta.resolve('@whiskeysockets/baileys')));\n"
                  "fs.writeFileSync(path.join(base, 'lib', 'Socket', 'newsletter.js'), 'exports.x = 1;');\n")]
        for main, text in cases:
            with self.subTest(text):
                res = scan_npm({"package.json": manifest(main=main), main: text})
                ((file, sev, msg),) = found(res, "SC-IMPORT-RISK")
                self.assertEqual((file, sev), (main, "CRITICAL"))
                self.assertIn(REASON, msg)

    def test_a_climb_to_a_scoped_package_beside_its_own(self):
        # D-9b: out of the script's own folder to a scoped sibling package's; an unscoped name after the climb is as
        # likely one of the package's own folders, so it is not one
        head = "const fs = require('fs');\nconst path = require('path');\n"
        write = "fs.writeFileSync(path.join(%s, 'Socket', 'newsletter.js'), 'exports.x = 1;');\n"
        for where in ("__dirname, '..', '..', '@whiskeysockets', 'baileys', 'lib'",
                      "path.dirname(__filename), '../../@whiskeysockets/baileys/lib'"):
            with self.subTest(where):
                res = scan_npm({"package.json": manifest(main="index.js"), "index.js": head + write % where})
                ((file, sev, msg),) = found(res, "SC-IMPORT-RISK")
                self.assertEqual((file, sev), ("index.js", "CRITICAL"))
                self.assertIn(REASON, msg)
        res = scan_npm({"package.json": manifest(main="index.js"),
                        "index.js": head + write % "__dirname, '..', 'baileys', 'lib'"})
        self.assertFalse(any("rewrites another package" in m for _f, _s, m in found(res, "SC-IMPORT-RISK")))

    def test_its_own_package_or_scope(self):
        # a release that writes into its own folder, or a sibling of its scope, through node_modules: its own code
        for name in ("@whiskeysockets/baileys", "@whiskeysockets/helper"):
            with self.subTest(name):
                res = scan_npm({"package.json": manifest(name=name, main="index.js"), "index.js": INDEX,
                                "install.js": FIND + PATCH + "module.exports = { install };\n"})
                self.assertFalse(any("rewrites another package" in m for _f, _s, m in found(res, "SC-IMPORT-RISK")))

    def test_what_is_not_a_rewrite(self):
        for text in ("const fs = require('fs'), path = require('path');\n"
                     "fs.writeFileSync(path.join(process.cwd(), 'node_modules', 'x', 'data.json'), '{}');\n",
                     "const fs = require('fs'), path = require('path');\n"
                     "fs.writeFileSync(path.join(process.cwd(), 'node_modules', '.cache', 'x', 'a.js'), s);\n",
                     "const fs = require('fs');\nconst s = fs.readFileSync(require.resolve('x/index.js'), 'utf8');\n"):
            with self.subTest(text):
                res = scan_npm({"package.json": manifest(main="index.js"), "index.js": text})
                self.assertFalse(any("rewrites another package" in m for _f, _s, m in found(res, "SC-IMPORT-RISK")))


if __name__ == "__main__":
    unittest.main()
