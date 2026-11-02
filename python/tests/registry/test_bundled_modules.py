"""EG-6 (0.1.9): a bare `require` into a package's own node_modules folder. A VS Code extension ships the packages
it needs inside its .vsix (vsce packs node_modules), and an npm package its bundleDependencies inside its tarball;
Node resolves `require('dep')` from a file to `node_modules/dep` in that file's folder or the nearest above it, so
what an entry point loads by a bare name is the bundled package's code, run when the extension activates or the
package is loaded. The walk from the entry points followed relative requires alone, so a bundled package's
load-time code had the use-time test only (its strongest shapes). Now the walk follows a bare require into the
archive's node_modules (repo._js_deps, _resolve_bare): Node's built-ins and `vscode` are no package's, and a
package the archive does not hold is the registry's.

Every hostile fragment is one of the suite's inert ones (_review_support): documentation addresses, nothing ever
run."""
import json
import unittest

from lazaret.registry import repo
from tests.registry._review_support import EXFIL_JS, issues, manifest, tarball
from tests.registry.test_vsix import ext_manifest, scan as scan_vsix


def import_risks(res):
    return [(i["file"], i["sev"]) for i in issues(res, "SC-IMPORT-RISK")]


class ExtensionTests(unittest.TestCase):
    def files(self, entry, **extra):
        return {"package.json": ext_manifest(main="out/extension.js", activationEvents=["*"]),
                "out/extension.js": entry, **extra}

    def test_a_bundled_package_the_entry_requires(self):
        res = scan_vsix(self.files("const helper = require('tiny-helper');\nexports.activate = () => helper();\n",
                                   **{"node_modules/tiny-helper/package.json": json.dumps({"name": "tiny-helper",
                                                                                         "main": "lib/main.js"}),
                                      "node_modules/tiny-helper/lib/main.js": EXFIL_JS}))
        self.assertIn(("node_modules/tiny-helper/lib/main.js", "CRITICAL"), import_risks(res))
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_the_nearest_node_modules_and_a_subpath(self):
        res = scan_vsix(self.files("require('@acme/kit/sub');\n",
                                   **{"node_modules/@acme/kit/sub.js": "require('./more');\n",
                                      "node_modules/@acme/kit/more.js": EXFIL_JS,
                                      "out/node_modules/@acme/kit/sub.js": "module.exports = 1;\n"}))
        # (out/extension.js's own folder first: out/node_modules)
        self.assertEqual(import_risks(res), [])

    def test_what_no_folder_gives(self):
        # a built-in, the editor's API, a package the archive does not hold
        res = scan_vsix(self.files("require('fs'); require('node:path'); require('fs/promises');\n"
                                   "const vscode = require('vscode'); require('left-pad');\n",
                                   **{"node_modules/fs/index.js": EXFIL_JS, "node_modules/vscode/index.js": EXFIL_JS,
                                      "node_modules/other/index.js": EXFIL_JS}))
        self.assertNotIn("CRITICAL", [sev for _f, sev in import_risks(res)])


class NpmTests(unittest.TestCase):
    def test_a_bundle_dependency(self):
        from tests.registry._review_support import scan_npm
        res = scan_npm({"package.json": manifest(main="index.js", dependencies={"tiny-helper": "1"},
                                                 bundleDependencies=["tiny-helper"]),
                        "index.js": "module.exports = require('tiny-helper');\n",
                        "node_modules/tiny-helper/index.js": EXFIL_JS})
        self.assertIn(("node_modules/tiny-helper/index.js", "CRITICAL"), import_risks(res))

    def test_no_node_modules_folder_reads_nothing_more(self):
        scanned = []
        real = repo._ArtifactScan._resolve_bare

        def spy(self, folder, spec):
            scanned.append(spec)
            return real(self, folder, spec)
        from unittest import mock
        with mock.patch.object(repo._ArtifactScan, "_resolve_bare", spy):
            data = tarball({"package.json": manifest(main="index.js"), "index.js": "require('left-pad');\n"})
            repo._scan_artifact(data, "tgz", "npm", False, None)
        self.assertEqual(scanned, [])


if __name__ == "__main__":
    unittest.main()
