"""SC-DEP-URL: a dependency npm fetches over plain http or from a raw IP address (D-14, 0.1.9; core's section of
the name, the npm engine's supplychain.js dependencyUrlIssues).

npm installs a dependency from wherever its spec says. One given as a plain-http URL (http:, git+http:) is fetched
with no integrity check, and one at a raw IP address names no registry and no domain: five of the benchmark's
in-sample releases did this (D-1's reading), and none of the 801 popular npm releases does (8,437 dependency specs,
devDependencies included, measured Oct 14). MAJOR, so WARN in the registry. Inert manifests only: hosts are .invalid
or TEST-NET addresses, nothing is fetched.
"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from lazaret.scanner import core
from tests.registry import _review_support as rs

RISKY = {
    "http:\x2f/registry.invalid/b-1.0.0.tgz": ["a plain-http URL"],
    "  HTTP:\x2f/registry.invalid/b.tgz": ["a plain-http URL"],
    "git+http:\x2f/git.invalid/d.git": ["a plain-http URL"],
    "https://203.0.113.7/c.tgz": ["a raw IP address (203.0.113.7)"],
    "http:\x2f/203.0.113.7/c.tgz": ["a plain-http URL", "a raw IP address (203.0.113.7)"],
    # the URL standard reads a host whose last label is a number as an IPv4 address
    "https://3405803783/e.tgz": ["a raw IP address (3405803783)"],
    "https://0xcb.0.113.7/e.tgz": ["a raw IP address (0xcb.0.113.7)"],
    "https://203.0.113.7./e.tgz": ["a raw IP address (203.0.113.7.)"],
    "https://[2001:db8::1]/f.tgz": ["a raw IP address ([2001:db8::1])"],
    "git+ssh://git@198.51.100.4/u/k.git": ["a raw IP address (198.51.100.4)"],
}
QUIET = ["^1.2.3", "~2", "latest", "npm:other@^1", "file:../h", "link:../h", "github:u/i", "u/i",
         "https://registry.invalid/j.tgz", "git+https://git.invalid/u/g.git", "git+ssh://git@git.invalid/u/g.git",
         "https://1.2.3.example/l.tgz", "https://registry.invalid./j.tgz", "", 12, None, ["x"]]


def manifest(**fields):
    return json.dumps({"name": "app", "version": "1.0.0", **fields}, indent=2)


def found(path, text, registry):
    return [(i["line"], i["msg"]) for i in core.scan_manifest(path, text, registry=registry) if i["rule"] == "SC-DEP-URL"]


class RiskTests(unittest.TestCase):
    def test_what_is_risky(self):
        for spec, why in RISKY.items():
            with self.subTest(spec=spec):
                self.assertEqual(core.dependency_url_risk(spec), why)

    def test_what_is_not(self):
        for spec in QUIET:
            with self.subTest(spec=spec):
                self.assertEqual(core.dependency_url_risk(spec), [])


class ManifestTests(unittest.TestCase):
    TEXT = manifest(dependencies={"a": "^1", "b": "http:\x2f/registry.invalid/b.tgz"},
                    optionalDependencies={"c": "https://203.0.113.7/c.tgz"},
                    peerDependencies={"d": "git+http:\x2f/git.invalid/d.git"},
                    devDependencies={"z": "http:\x2f/dev.invalid/z.tgz"})

    def test_a_package_from_a_registry_reads_what_npm_installs(self):
        self.assertEqual(found("package.json", self.TEXT, True), [
            (6, 'Dependency "b" (dependencies) is fetched from a plain-http URL: \'http:\x2f/registry.invalid/b.tgz\'.'),
            (9, 'Dependency "c" (optionalDependencies) is fetched from a raw IP address (203.0.113.7): '
                '\'https://203.0.113.7/c.tgz\'.'),
            (12, 'Dependency "d" (peerDependencies) is fetched from a plain-http URL: \'git+http:\x2f/git.invalid/d.git\'.')])

    def test_a_projects_own_install_takes_its_dev_dependencies_too(self):
        lines = found("package.json", self.TEXT, False)
        self.assertEqual(len(lines), 4)
        self.assertEqual(lines[-1], (15, 'Dependency "z" (devDependencies) is fetched from a plain-http URL: '
                                         '\'http:\x2f/dev.invalid/z.tgz\'.'))
        self.assertEqual(len(found("packages/web/package.json", self.TEXT, False)), 4)   # a workspace's

    def test_only_a_packages_root_manifest_in_a_registry_or_deps_scan(self):
        self.assertEqual(len(found("node_modules/x/package.json", self.TEXT, True)), 3)
        self.assertEqual(len(found("node_modules/@s/x/package.json", self.TEXT, True)), 3)
        for path in ("test/fixtures/package.json", "node_modules/x/test/package.json"):
            with self.subTest(path=path):
                self.assertEqual(found(path, self.TEXT, True), [])

    def test_not_an_extensions_or_an_actions_manifest(self):
        for hooks in ((), ("vscode:uninstall",)):
            with self.subTest(hooks=hooks):
                self.assertFalse([i for i in core.scan_manifest("package.json", self.TEXT, registry=True, hooks=hooks)
                                  if i["rule"] == "SC-DEP-URL"])

    def test_the_key_on_its_line_and_credentials_redacted(self):
        word = "hun" + "ter2val"
        text = manifest(dependencies={"b": "^1"}, optionalDependencies={"b": "https://ci:" + word + "@203.0.113.7/b.tgz"})
        ((line, msg),) = found("package.json", text, True)
        self.assertEqual(line, 8)                       # the key inside optionalDependencies, not the first "b" (5)
        self.assertNotIn(word, msg)
        self.assertIn("203.0.113.7", msg)

    def test_a_manifest_with_no_such_dependency(self):
        text = manifest(dependencies={k: v for k, v in zip("abcdefghijklmnopq", QUIET) if isinstance(v, str)})
        self.assertEqual(found("package.json", text, True), [])


class WindowsPathTests(unittest.TestCase):
    """WIN-DEP-PATHS: on Windows the walk names a dependency's fixture node_modules\\dep\\test\\package.json
    (os.sep), which the engine read '/'-separated as a manifest at the top of a package, so --deps reported the
    fixture's dependencies there alone (test_js_parity_dep_url, PR #17's windows-latest job). The walk's paths go
    with `windows` on Windows; elsewhere, and in a registry's members, a backslash is a file name's. These run on
    every system: the engine is given the Windows form."""

    TEXT = manifest(dependencies={"f": "http:\x2f/fixture.invalid/f.tgz"},
                    devDependencies={"z": "https://3405803783/z.tgz"})

    def dep_url(self, path, registry, windows):
        return len([i for i in core.scan_manifest(path, self.TEXT, registry=registry, windows=windows)
                    if i["rule"] == "SC-DEP-URL"])

    def test_a_windows_walks_path_is_read_with_its_separators(self):
        for path, registry, want in (("node_modules\\dep\\test\\package.json", True, 0),   # a dependency's fixture
                                     ("node_modules\\@s\\dep\\test\\package.json", True, 0),
                                     ("node_modules\\dep\\package.json", True, 1),         # its root, not devDeps
                                     ("a\\node_modules\\@s\\dep\\package.json", True, 1),
                                     ("package.json", False, 2),                           # the project's own
                                     ("packages\\web\\package.json", False, 2)):           # a workspace's
            with self.subTest(path=path):
                self.assertEqual(self.dep_url(path, registry, True), want)

    def test_elsewhere_a_backslash_is_a_file_names(self):
        # POSIX unchanged: one file at the top of the tree, or one folder's name
        self.assertEqual(self.dep_url("node_modules\\dep\\test\\package.json", True, False), 1)
        self.assertEqual(self.dep_url("node_modules/a\\b/package.json", True, False), 1)
        self.assertEqual(self.dep_url("node_modules/a\\b/package.json", True, True), 0)
        self.assertEqual(len([i for i in core.scan_manifest("node_modules\\dep\\test\\package.json", self.TEXT,
                                                            registry=True) if i["rule"] == "SC-DEP-URL"]), 1)

    def test_the_walks_manifests_go_with_the_hosts_separator(self):
        entries = [{"path": "node_modules\\dep\\test\\package.json", "content": self.TEXT, "dep": True},
                   {"path": "node_modules\\dep\\package.json", "content": self.TEXT, "dep": True},
                   {"path": "package.json", "content": self.TEXT, "dep": False}]

        def files(windows):
            with mock.patch.object(core, "_WINDOWS_PATHS", windows):
                return sorted(i["file"] for mf in entries for i in core._scan_manifest_entry(mf)
                              if i["rule"] == "SC-DEP-URL")
        self.assertEqual(files(True), ["node_modules\\dep\\package.json", "package.json", "package.json"])
        self.assertEqual(files(False), ["node_modules\\dep\\package.json", "node_modules\\dep\\test\\package.json",
                                        "package.json", "package.json"])


class ScanTests(unittest.TestCase):
    def test_a_project_scan_reports_it_and_fails_the_gate(self):
        root = tempfile.mkdtemp(prefix="lz-dep-url-")
        try:
            with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as fh:
                fh.write(manifest(dependencies={"b": "http:\x2f/registry.invalid/b.tgz"}))
            res = core.scan_project(root)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-DEP-URL"]
        self.assertEqual((issue["file"], issue["sev"]), ("package.json", "MAJOR"))
        self.assertFalse(res["pass"])

    def test_a_release_from_the_registry_is_warn(self):
        res = rs.scan_npm({"package.json": manifest(dependencies={"c": "https://203.0.113.7/c.tgz"}),
                           "index.js": "module.exports = 1;\n",
                           "test/fixture/package.json": manifest(dependencies={"t": "http:\x2f/fixture.invalid/t.tgz"})})
        self.assertEqual(res["verdict"], "WARN")
        self.assertEqual([i["file"] for i in rs.issues(res, "SC-DEP-URL")], ["package.json"])


if __name__ == "__main__":
    unittest.main()
