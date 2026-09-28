"""Audit P0: lazaret-sca reads uv.lock, pylock.toml (PEP 751) and bun.lock.

The audit's SCA benchmark found six transitive advisories that Lazaret
missed in projects locked with uv or pylock.toml (only the direct
dependencies in pyproject.toml were seen), and Bun's text lockfile was not
read at all; OSV-Scanner reads all three.

What is inventoried, as for the other lockfiles: a registry release with its
version; a git, URL or local-archive package with an unknown version (a
matching advisory is reported unknown, never cleared); first-party entries
(the project itself, workspace members, local project directories, links)
not at all.

Fixtures are inert lock text: example.invalid URLs, made-up hashes and
synthetic CVE ids.
"""
import os
import shutil
import tempfile
import time
import unittest
from unittest import mock

from lazaret.scanner import sca

H = "0" * 64
UV_LOCK = f'''version = 1
revision = 3
requires-python = ">=3.9"
resolution-markers = [
    "python_full_version >= '3.10'",
    "python_full_version < '3.10'",
]

[manifest]
members = ["app", "app-plugin"]

[[package]]
name = "app"
version = "0.1.0"
source = {{ editable = "." }}
dependencies = [
    {{ name = "requests" }},
    {{ name = "Django", marker = "python_full_version >= '3.10'" }},
]

[package.metadata]
requires-dist = [{{ name = "requests", specifier = "==2.19.0" }}]

[[package]]
name = "app-plugin"
version = "0.1.0"
source = {{ virtual = "plugins/app-plugin" }}

[[package]]
name = "localtools"
version = "1.0.0"
source = {{ directory = "../localtools" }}

[[package]]
name = "requests"
version = "2.19.0"
source = {{ registry = "https://pypi.example.invalid/simple" }}
dependencies = [
    {{ name = "urllib3" }},
]
sdist = {{ url = "https://files.example.invalid/requests-2.19.0.tar.gz", hash = "sha256:{H}", size = 1, upload-time = "2018-06-12T15:02:16.084Z" }}
wheels = [
    {{ url = "https://files.example.invalid/requests-2.19.0-py2.py3-none-any.whl", hash = "sha256:{H}", size = 1, upload-time = "2018-06-12T15:02:13.955Z" }},
]

[package.optional-dependencies]
socks = [
    {{ name = "pysocks" }},
]

[[package]]
name = "urllib3"
version = "1.26.0"
source = {{ registry = "https://pypi.example.invalid/simple" }}

[[package]]
name = "django"
version = "2.2.0"
source = {{ git = "https://git.example.invalid/django.git?rev=2.2#{"a" * 40}" }}

[[package]]
name = "flask"
version = "1.1.0"
source = {{ url = "https://files.example.invalid/flask-1.1.0.tar.gz" }}

[[package]]
name = "six"
version = "1.16.0"
source = {{ path = "wheels/six-1.16.0-py2.py3-none-any.whl" }}
'''

PYLOCK = f'''lock-version = "1.0"
created-by = "uv"
requires-python = ">=3.9"
environments = ["sys_platform == 'linux'"]

[[packages]]
name = "app"
directory = {{ path = ".", editable = true }}

[[packages]]
name = "requests"
version = "2.19.0"
index = "https://pypi.example.invalid/simple"
sdist = {{ url = "https://files.example.invalid/requests-2.19.0.tar.gz", upload-time = 2018-06-12T15:02:16Z, size = 1, hashes = {{ sha256 = "{H}" }} }}
wheels = [
    {{ url = "https://files.example.invalid/requests-2.19.0-py2.py3-none-any.whl", upload-time = 2018-06-12T15:02:13Z, size = 1, hashes = {{ sha256 = "{H}" }} }},
]

[[packages]]
name = "urllib3"
version = "1.26.0"
marker = "python_version >= '3.9'"

[[packages.wheels]]
name = "urllib3-1.26.0-py2.py3-none-any.whl"
url = "https://files.example.invalid/urllib3-1.26.0-py2.py3-none-any.whl"
hashes = {{ sha256 = "{H}" }}

[[packages]]
name = "django"
version = "2.2.0"
vcs = {{ type = "git", url = "https://git.example.invalid/django.git", commit-id = "{"a" * 40}" }}

[[packages]]
name = "flask"
archive = {{ url = "https://files.example.invalid/flask-1.1.0.tar.gz", hashes = {{ sha256 = "{H}" }} }}

[[packages]]
name = "gunicorn"
sdist = {{ url = "https://files.example.invalid/gunicorn.tar.gz", hashes = {{ sha256 = "{H}" }} }}
'''

INTEGRITY = "sha512-" + "A" * 86 + "=="
BUN_LOCK = '''{
  "lockfileVersion": 1,
  "configVersion": 1,
  // comments are allowed (JSONC), and so are trailing commas
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "lodash": "4.17.11",
        "old-zzz": "npm:zzz@0.1.5",
        "is-number": "https://registry.example.invalid/is-number/-/is-number-7.0.0.tgz",
      },
    },
    "packages/ui": {
      "name": "@app/ui",
      "version": "1.0.0",
      "dependencies": { "@s/p": "1.2.3", "@app/core": "workspace:*", },
    },
  },
  "packages": {
    "@app/core": ["@app/core@workspace:packages/core"],

    "@app/ui": ["@app/ui@workspace:packages/ui"],

    "@s/p": ["@s/p@1.2.3", "", { "dependencies": { "zzz": "^0.1.0" } }, "INTEGRITY"],

    "is-number": ["is-number@https://registry.example.invalid/is-number/-/is-number-7.0.0.tgz", {}, "INTEGRITY"],

    "lodash": ["lodash@4.17.11", "", {}, "INTEGRITY"],

    "old-zzz": ["zzz@0.1.5", "", {}, "INTEGRITY"],

    "@s/p/zzz": ["zzz@0.1.7", "", {}, "INTEGRITY"],

    "gh": ["gh@github:someone/gh#1a2b3c4", {}, "someone-gh-1a2b3c4"],

    "viagit": ["viagit@git+ssh://git@git.example.invalid/viagit.git#1a2b3c4", {}, "1a2b3c4"],

    "linked": ["linked@link:linked"],

    "folder": ["folder@file:../folder", {}],

    "tarball": ["tarball@./vendor/tarball-1.0.0.tgz", {}, "INTEGRITY"], /* a local archive */
  }
}
'''.replace("INTEGRITY", INTEGRITY)

NOW = "2099-01-01T00:00:00Z"


def adv(cve, name, eco, to):
    return {"cve": cve, "title": cve.lower(), "cvss": 9.8, "packages": [
        {"name": name, "ecosystem": eco, "ranges": [
            {"fromVersion": "*", "fromInclusive": True, "toVersion": to, "toInclusive": False}]}]}


BUNDLE = {"bundleVersion": 1, "generatedAt": NOW, "sources": ["test"], "advisories": [
    adv("CVE-TEST-REQ", "requests", "pypi", "2.20.0"),
    adv("CVE-TEST-URL", "urllib3", "pypi", "1.26.5"),
    adv("CVE-TEST-DJ", "django", "pypi", "3.2.0"),
    adv("CVE-TEST-APP", "app", "pypi", "9.0"),
    adv("CVE-TEST-LODASH", "lodash", "npm", "4.17.21"),
    adv("CVE-TEST-ZZZ", "zzz", "npm", "0.1.6"),
    adv("CVE-TEST-UI", "@app/ui", "npm", "9.0.0"),
]}


class Tmp(unittest.TestCase):
    def mk(self, files):
        root = tempfile.mkdtemp(prefix="lz-sca-locks-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, content in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if isinstance(content, str):
                content = content.encode("utf-8")
            with open(path, "wb") as fh:
                fh.write(content)
        return root

    def entries(self, root, fn=None):
        warn = sca._Warnings()
        got = (fn or sca.scan_all)(root, warn=warn)
        return sorted((n, v, w) for e, n, v, w in got), warn.lines()

    def verdicts(self, root):
        matches, unknown = sca.match_inventory(sca.scan_all(root), sca.CveBundle(BUNDLE))
        return (sorted((m[2][1], m[2][2], m[0]["cve"]) for m in matches),
                sorted((u[0][1], u[1]["cve"]) for u in unknown))


class UvLock(Tmp):
    WANT = [("django", "", "uv.lock (git source)"), ("flask", "", "uv.lock (url source)"),
            ("requests", "2.19.0", "uv.lock"), ("six", "", "uv.lock (path source)"),
            ("urllib3", "1.26.0", "uv.lock")]

    def test_registry_releases_are_versioned_and_first_party_skipped(self):
        got, warnings = self.entries(self.mk({"uv.lock": UV_LOCK}), sca.scan_pypi_declared)
        self.assertEqual(got, self.WANT)
        self.assertEqual(warnings, [])

    def test_the_python_310_parser_reads_it_the_same(self):
        with mock.patch.object(sca, "_tomllib", return_value=None):
            got, _ = self.entries(self.mk({"uv.lock": UV_LOCK}), sca.scan_pypi_declared)
        self.assertEqual(got, self.WANT)
        lib = sca._tomllib()
        if lib is not None:
            self.assertEqual(sca.toml_subset_loads(UV_LOCK), lib.loads(UV_LOCK))

    def test_transitive_advisories_are_found(self):
        affected, unknown = self.verdicts(self.mk({"uv.lock": UV_LOCK}))
        self.assertEqual(affected, [("requests", "2.19.0", "CVE-TEST-REQ"),
                                    ("urllib3", "1.26.0", "CVE-TEST-URL")])
        self.assertEqual(unknown, [("django", "CVE-TEST-DJ")])     # git: unknown, not cleared

    def test_broken_files_are_named(self):
        cases = {"[[package]\nname = ": "unparseable uv.lock file(s)",
                 'package = "x"\n': "malformed uv.lock file(s)",
                 '[[package]]\nversion = "1.0"\n\n[[package]]\nname = "urllib3"\nversion = "1.26.0"\n'
                 'source = { registry = "https://pypi.example.invalid/simple" }\n':
                     "malformed uv.lock entries"}
        for text, warning in cases.items():
            with self.subTest(warning=warning):
                got, warnings = self.entries(self.mk({"uv.lock": text}), sca.scan_pypi_declared)
                self.assertTrue(any(warning in w for w in warnings), warnings)
        self.assertIn(("urllib3", "1.26.0", "uv.lock"), got)          # the good entry is kept


class Pylock(Tmp):
    WANT = [("django", "", "pylock.toml (vcs)"), ("flask", "", "pylock.toml (archive)"),
            ("gunicorn", "", "pylock.toml"), ("requests", "2.19.0", "pylock.toml"),
            ("urllib3", "1.26.0", "pylock.toml")]

    def test_index_packages_are_versioned_and_directories_skipped(self):
        got, warnings = self.entries(self.mk({"pylock.toml": PYLOCK}), sca.scan_pypi_declared)
        self.assertEqual(got, self.WANT)
        self.assertEqual(warnings, [])

    def test_the_python_310_parser_reads_it_the_same(self):
        with mock.patch.object(sca, "_tomllib", return_value=None):
            got, _ = self.entries(self.mk({"pylock.toml": PYLOCK}), sca.scan_pypi_declared)
        self.assertEqual(got, self.WANT)

    def test_named_lock_files(self):
        root = self.mk({"pylock.dev.toml": PYLOCK.replace("2.19.0", "2.18.0"),
                        "pylock.a.b.toml": PYLOCK, "pylock.toml.bak": PYLOCK})
        got, _ = self.entries(root, sca.scan_pypi_declared)
        self.assertIn(("requests", "2.18.0", "pylock.dev.toml"), got)
        self.assertEqual({w for _, _, w in got}, {"pylock.dev.toml", "pylock.dev.toml (vcs)",
                                                  "pylock.dev.toml (archive)"})

    def test_transitive_advisories_are_found(self):
        affected, unknown = self.verdicts(self.mk({"pylock.toml": PYLOCK}))
        self.assertEqual(affected, [("requests", "2.19.0", "CVE-TEST-REQ"),
                                    ("urllib3", "1.26.0", "CVE-TEST-URL")])
        self.assertEqual(unknown, [("django", "CVE-TEST-DJ")])

    def test_broken_file_is_named(self):
        _, warnings = self.entries(self.mk({"pylock.toml": "packages = [\n"}), sca.scan_pypi_declared)
        self.assertTrue(any("unparseable pylock.toml" in w for w in warnings), warnings)


class BunLock(Tmp):
    WANT = [("@s/p", "1.2.3"), ("gh", ""), ("is-number", ""), ("lodash", "4.17.11"),
            ("viagit", ""), ("zzz", "0.1.5"), ("zzz", "0.1.7")]

    def test_parse(self):
        self.assertEqual(sorted(sca.parse_bun_lock(BUN_LOCK)), self.WANT)

    def test_inventory_and_advisories(self):
        root = self.mk({"bun.lock": BUN_LOCK})
        got, warnings = self.entries(root, sca.scan_npm_other_locks)
        self.assertEqual([(n, v) for n, v, _ in got], self.WANT)
        self.assertEqual({w for _, _, w in got}, {"bun.lock"})
        self.assertEqual(warnings, [])
        affected, unknown = self.verdicts(root)
        self.assertEqual(affected, [("lodash", "4.17.11", "CVE-TEST-LODASH"),
                                    ("zzz", "0.1.5", "CVE-TEST-ZZZ")])  # 0.1.7 is fixed
        self.assertEqual(unknown, [])          # @app/ui is a workspace: not inventoried

    def test_jsonc(self):
        J = sca.jsonc_loads
        self.assertEqual(J('{"a": [1, 2,], "b": {"c": "d",},}'), {"a": [1, 2], "b": {"c": "d"}})
        self.assertEqual(J('{"u": "https://x.invalid/a,}", // c\n "v": "/* not */",}'),
                         {"u": "https://x.invalid/a,}", "v": "/* not */"})
        self.assertEqual(J('{"q": "say \\"hi\\", // no",}'), {"q": 'say "hi", // no'})
        self.assertEqual(J('/* lead */ {"a": 1 /* mid */, } // tail'), {"a": 1})
        for bad in ('{"a": 1', '{"a": }', '{"a": "x}', '{"a": 1} /* open', '{"a": 1} /*/', "[,1]",
                    '{"a": 1} / 2'):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    J(bad)

    def test_jsonc_work_is_linear(self):
        # every alternative matches to the end of the text rather than fail, so
        # none of these can make the regex rescan: each is ~2 MB
        for text in ('"' + "\\" * 2_000_000, '"a' * 1_000_000, "/*" * 1_000_000,
                     '{"k": "' + "\\\"," * 700_000, "," + " " * 2_000_000 + "x",
                     "[" + ", " * 1_000_000):
            with self.subTest(text=text[:12]):
                t0 = time.perf_counter()
                with self.assertRaises(ValueError):
                    sca.jsonc_loads(text)
                dt = time.perf_counter() - t0
                self.assertLess(dt, 10.0, f"jsonc_loads took {dt:.1f}s")

    def test_broken_files_are_named(self):
        cases = {"{": "unparseable bun.lock file(s)",
                 '{"packages": []}': "unparseable bun.lock file(s)",
                 '{"packages": {"a": "x", "b": [], "c": [42], "d": ["noversion"],'
                 ' "lodash": ["lodash@4.17.11", "", {}, "x"]}}': "4 malformed bun.lock entries"}
        for text, warning in cases.items():
            with self.subTest(warning=warning):
                got, warnings = self.entries(self.mk({"bun.lock": text}), sca.scan_npm_other_locks)
                self.assertTrue(any(warning in w for w in warnings), warnings)
        self.assertEqual([(n, v) for n, v, _ in got], [("lodash", "4.17.11")])

    def test_the_binary_lockfile_is_named_not_read(self):
        root = self.mk({"bun.lockb": b"#!/usr/bin/env bun\nbun-lockfile-format-v0\n\x00\x01"})
        got, warnings = self.entries(root, sca.scan_npm_other_locks)
        self.assertEqual(got, [])
        self.assertTrue(any("binary bun.lockb" in w for w in warnings), warnings)
        both = self.mk({"bun.lockb": b"\x00", "bun.lock": BUN_LOCK})
        _, warnings = self.entries(both, sca.scan_npm_other_locks)
        self.assertEqual(warnings, [])          # the text lockfile is what counts


if __name__ == "__main__":
    unittest.main()
