"""lazaret guard's parts (0.1.7): lockfiles, digests, this machine's platform,
the policy (--min-age, --allow-new, --trust, --block-warn), the verdict cache,
fetching, the local PyPI index, the report and the `lazaret guard` command
line; (0.1.8) yarn's and Bun's lockfiles, credentials on the wire, several
indexes relayed at once, uv's tool command lines. No package manager and no
network: test_guard_npm.py and test_guard_python.py run the real tools
against fake registries; test_pmsettings.py reads their settings."""

import argparse
import base64
import datetime
import hashlib
import http.server
import io
import json
import os
import shutil
import socketserver
import tempfile
import threading
import unittest
from unittest import mock

from lazaret import _cli
from lazaret.registry import guard, repo

UTC = datetime.timezone.utc


def options(**kw):
    base = dict(min_age=2 * 86400, allow_new=[], trust=[], block_warn=False, plan=False, json=None, no_cache=True,
                jobs=1, scan_timeout=60.0, tool="npm", args=[])
    base.update(kw)
    return argparse.Namespace(**base)


def context(**kw):
    return guard.Context(options(**kw), out=io.StringIO())


def sri(data, alg="sha512"):
    return f"{alg}-" + base64.b64encode(hashlib.new(alg, data).digest()).decode()


class DurationAndTimeTests(unittest.TestCase):
    def test_durations(self):
        for text, seconds in (("2d", 172800), ("36h", 129600), ("90m", 5400), ("1w", 604800), ("3600s", 3600),
                              ("0", 0), ("1.5d", 129600), (" 3 D ", 259200), ("7", 604800)):
            with self.subTest(text):
                self.assertEqual(guard.parse_duration(text), seconds)
        for bad in ("", "two days", "-1d", "1y", "1dd"):
            with self.subTest(bad), self.assertRaises(guard.GuardError):
                guard.parse_duration(bad)

    def test_ages(self):
        self.assertEqual([guard.format_age(s) for s in (0, 1, 59, 60, 3599, 3600, 86399, 86400, 172800)],
                         ["0 seconds", "1 second", "59 seconds", "1 minute", "59 minutes", "1 hour", "23 hours",
                          "1 day", "2 days"])

    def test_iso_times(self):
        self.assertEqual(guard.parse_time("2026-09-28T08:33:55.944Z"),
                         datetime.datetime(2026, 9, 28, 8, 33, 55, 944000, tzinfo=UTC))
        # seven fraction digits (npm's `time` sometimes has them; Python 3.10 reads 3 or 6)
        self.assertEqual(guard.parse_time("2026-09-28T08:33:55.9441234Z").microsecond, 944123)
        self.assertEqual(guard.parse_time("2026-09-28T08:33:55").tzinfo, UTC)
        for bad in (None, "", "yesterday", 5):
            self.assertIsNone(guard.parse_time(bad))

    def test_http_dates(self):
        self.assertEqual(guard.parse_http_date("Mon, 01 Dec 2025 20:49:45 GMT"),
                         datetime.datetime(2025, 12, 1, 20, 49, 45, tzinfo=UTC))
        for bad in (None, "", "not a date"):
            self.assertIsNone(guard.parse_http_date(bad))


class DigestTests(unittest.TestCase):
    def test_the_strongest_valid_digest_wins(self):
        data = b"tarball"
        both = f"{sri(data, 'sha1')} {sri(data)}"
        self.assertEqual(guard.sri_best(both), ("sha512", sri(data)[len("sha512-"):]))
        self.assertTrue(guard.sri_matches(b"tarball", guard.sri_best(both)))
        self.assertFalse(guard.sri_matches(b"other", guard.sri_best(both)))
        # a digest of the wrong length or that isn't base64 is skipped, not trusted
        self.assertEqual(guard.sri_best(f"sha512-AAAA {sri(data, 'sha1')}")[0], "sha1")
        self.assertIsNone(guard.sri_best("sha512-!!!"))
        self.assertIsNone(guard.sri_best("md5-AAAA"))
        self.assertIsNone(guard.sri_best(None))

    def test_the_registry_digest_falls_back_to_shasum(self):
        data = b"tarball"
        self.assertEqual(guard.registry_digest({"dist": {"shasum": hashlib.sha1(data).hexdigest()}})[0], "sha1")
        self.assertEqual(guard.registry_digest({"dist": {"integrity": sri(data)}})[0], "sha512")
        self.assertIsNone(guard.registry_digest({"dist": {"shasum": "zz"}}))
        self.assertIsNone(guard.registry_digest([]))


NPM_LOCK_V3 = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app", "version": "1.0.0", "workspaces": ["packages/*"]},
        "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
                           "integrity": "sha512-AAA="},
        "node_modules/ws": {"resolved": "packages/ws", "link": True},
        "packages/ws": {"name": "ws", "version": "0.0.1"},
        "packages/ws/node_modules/c": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/c/-/c-2.0.0.tgz"},
        "node_modules/a/node_modules/bundled": {"version": "1.0.0", "inBundle": True},
        "node_modules/alias": {"name": "real", "version": "3.0.0",
                               "resolved": "https://registry.npmjs.org/real/-/real-3.0.0.tgz"},
        "node_modules/@img/native": {"version": "0.1.0", "os": ["darwin"], "cpu": "arm64", "libc": ["glibc"]},
    },
}
NPM_LOCK_V1 = {
    "lockfileVersion": 1,
    "dependencies": {
        "a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-A",
              "dependencies": {"b": {"version": "2.0.0", "integrity": "sha512-B"}}},
        "local": {"version": "file:../local"},
        "al": {"version": "npm:real@2.0.0", "integrity": "sha512-R"},
        "packed": {"version": "1.0.0", "bundled": True},
    },
}
PNPM_LOCK_V9 = """lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.0.0

packages:

  a@1.0.0:
    resolution: {integrity: sha512-AAA=}
    engines: {node: '>=0.12.0'}

  '@img/sharp-darwin-arm64@0.35.4':
    resolution: {integrity: sha512-BBB=}
    cpu: [arm64]
    os: [darwin]

  blk@2.0.0:
    resolution:
      integrity: sha512-CCC=
    os:
      - linux
    libc:
      - glibc

  gitdep@https://codeload.github.com/u/r/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/u/r/tar.gz/abc}
    version: 1.0.0

  local@file:../local:
    resolution: {directory: ../local, type: directory}

snapshots:

  a@1.0.0: {}
"""
PNPM_LOCK_V6 = """lockfileVersion: '6.0'

packages:

  /b@1.2.3(react@18.0.0):
    resolution: {integrity: sha512-DDD=}
    dev: false

  /c/4.5.6:
    resolution: {integrity: sha512-EEE=}
"""
UV_LOCK = """version = 1
requires-python = ">=3.9"

[[package]]
name = "proj"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "idna"
version = "3.10"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/aa/idna-3.10.tar.gz", hash = "sha256:%s", size = 1, upload-time = "2024-09-15T18:07:39.745Z" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/bb/idna-3.10-py3-none-any.whl", hash = "sha256:%s", size = 1 },
]

[[package]]
name = "gitpkg"
version = "1.0"
source = { git = "https://github.com/u/r?rev=abc#abc" }
""" % ("a" * 64, "b" * 64)


class LockfileTests(unittest.TestCase):
    def test_npm_lockfile_v3(self):
        got = {(e["name"], e["version"]): e for e in guard.npm_lock_packages(json.dumps(NPM_LOCK_V3))}
        # the project, the workspace folder, its link and a bundled dependency are not installed packages
        self.assertEqual(sorted(got), [("@img/native", "0.1.0"), ("a", "1.0.0"), ("c", "2.0.0"), ("real", "3.0.0")])
        self.assertEqual(got[("a", "1.0.0")]["integrity"], "sha512-AAA=")
        native = got[("@img/native", "0.1.0")]
        self.assertEqual((native["os"], native["cpu"], native["libc"]), (["darwin"], ["arm64"], ["glibc"]))

    def test_npm_lockfile_v1(self):
        got = sorted((e["name"], e["version"], e["integrity"])
                     for e in guard.npm_lock_packages(json.dumps(NPM_LOCK_V1)))
        self.assertEqual(got, [("a", "1.0.0", "sha512-A"), ("b", "2.0.0", "sha512-B"), ("real", "2.0.0", "sha512-R")])

    def test_npm_lockfile_that_is_not_one(self):
        for text in ("", "[]", "{", '{"packages": 5}', "[" * 10000):
            self.assertEqual(guard.npm_lock_packages(text), [])

    def test_pnpm_lockfile_v9(self):
        got = guard.pnpm_lock_packages(PNPM_LOCK_V9)
        self.assertEqual(sorted(got), [("@img/sharp-darwin-arm64", "0.35.4"), ("a", "1.0.0"), ("blk", "2.0.0"),
                                       ("gitdep", "")])
        self.assertEqual(got[("a", "1.0.0")]["integrity"], "sha512-AAA=")
        self.assertEqual((got[("@img/sharp-darwin-arm64", "0.35.4")]["os"],
                          got[("@img/sharp-darwin-arm64", "0.35.4")]["cpu"]), (["darwin"], ["arm64"]))
        self.assertEqual((got[("blk", "2.0.0")]["integrity"], got[("blk", "2.0.0")]["os"],
                          got[("blk", "2.0.0")]["libc"]), ("sha512-CCC=", ["linux"], ["glibc"]))
        self.assertEqual(got[("gitdep", "")]["tarball"], "https://codeload.github.com/u/r/tar.gz/abc")

    def test_pnpm_lockfile_v6_and_v5_keys(self):
        self.assertEqual(sorted(guard.pnpm_lock_packages(PNPM_LOCK_V6)), [("b", "1.2.3"), ("c", "4.5.6")])

    def test_uv_lockfile(self):
        got = {p["name"]: p for p in guard.uv_lock_packages(UV_LOCK)}
        self.assertEqual({n: p["source"] for n, p in got.items()}, {"proj": "local", "idna": "registry",
                                                                      "gitpkg": "git"})
        self.assertEqual(got["idna"]["sdist"]["filename"], "idna-3.10.tar.gz")
        self.assertEqual(got["idna"]["sdist"]["upload-time"], "2024-09-15T18:07:39.745Z")
        self.assertEqual([w["filename"] for w in got["idna"]["wheels"]], ["idna-3.10-py3-none-any.whl"])
        self.assertEqual(guard.uv_lock_packages("not toml ["), [])

    def test_installed_python_distributions(self):
        with tempfile.TemporaryDirectory() as venv:
            site = os.path.join(venv, "lib", "python3.11", "site-packages")
            for d in ("Typing_Extensions-4.16.0.dist-info", "idna-3.10.dist-info", "idna", "junk.dist-info"):
                os.makedirs(os.path.join(site, d))
            self.assertEqual(guard.installed_python(guard.venv_site_dirs(venv)),
                             {("typing-extensions", "4.16.0"), ("idna", "3.10")})


YARN_CLASSIC_LOCK = """# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@scope/a@^1.0.0", "@scope/a@^1.1.0":
  version "1.1.0"
  resolved "https://registry.yarnpkg.com/@scope/a/-/a-1.1.0.tgz#0123456789abcdef0123456789abcdef01234567"
  integrity sha512-AAA=
  dependencies:
    b "^2.0.0"

b@^2.0.0:
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/b/-/b-2.0.0.tgz#0123456789abcdef0123456789abcdef01234567"

old-name@npm:real@^3:
  version "3.0.0"
  resolved "https://registry.yarnpkg.com/real/-/real-3.0.0.tgz"
  integrity sha512-RRR=

local@file:../local:
  version "0.0.1"

gitdep@git+https://github.com/u/r.git:
  version "1.0.0"
  resolved "git+https://github.com/u/r.git#abc"
"""

YARN_BERRY_LOCK = """# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 8
  cacheKey: 10c0

"@esbuild/darwin-arm64@npm:0.25.0":
  version: 0.25.0
  resolution: "@esbuild/darwin-arm64@npm:0.25.0"
  conditions: os=darwin & cpu=arm64
  languageName: node
  linkType: hard

"a@npm:^1.0.0":
  version: 1.0.0
  resolution: "a@npm:1.0.0"
  dependencies:
    b: "npm:^2.0.0"
  checksum: 10c0/aaaa
  languageName: node
  linkType: hard

"gh@npm:^1.0.0":
  version: 1.0.0
  resolution: "gh@npm:1.0.0::__archiveUrl=https%3A%2F%2Fnpm.pkg.example%2Fdownload%2Fgh%2F1.0.0%2Fabc"
  checksum: 10c0/bbbb
  languageName: node
  linkType: hard

"old-name@npm:real@^3":
  version: 3.0.0
  resolution: "real@npm:3.0.0"
  checksum: 10c0/cccc
  languageName: node
  linkType: hard

"a@patch:a@npm%3A^1.0.0#~/.yarn/patches/a.patch":
  version: 1.0.0
  resolution: "a@patch:a@npm%3A1.0.0#~/.yarn/patches/a.patch::version=1.0.0&hash=abc"
  languageName: node
  linkType: hard

"proj@workspace:.":
  version: 0.0.0-use.local
  resolution: "proj@workspace:."
  languageName: unknown
  linkType: soft

"gitdep@https://github.com/u/r.git#commit=abc":
  version: 1.0.0
  resolution: "gitdep@https://github.com/u/r.git#commit=abc"
  languageName: node
  linkType: hard
"""

BUN_LOCK = """{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "proj", "dependencies": { "a": "^1.0.0" } } },
  "packages": {
    "a": ["a@1.0.0", "", { "dependencies": { "b": "^2" } }, "sha512-AAA="],
    "b": ["b@2.0.0", "https://reg.example/b/-/b-2.0.0.tgz", {}, "sha512-BBB="],
    "@img/x": ["@img/x@0.1.0", "", { "os": "darwin", "cpu": ["arm64"] }, "sha512-XXX="],
    "gh": ["gh@github:u/r#abc", {}, "u-r-abc"],
    "ws": ["ws@workspace:packages/ws"],
    // a comment
    "loc": ["loc@file:../loc", {}],
  },
}
"""


class YarnAndBunLockTests(unittest.TestCase):
    def test_yarn_classic(self):
        got = guard.yarn_classic_lock(YARN_CLASSIC_LOCK)
        self.assertEqual(sorted(got), [("@scope/a", "1.1.0"), ("b", "2.0.0"), ("gitdep", "1.0.0"), ("real", "3.0.0")])
        self.assertEqual(got[("@scope/a", "1.1.0")]["resolved"],
                         "https://registry.yarnpkg.com/@scope/a/-/a-1.1.0.tgz")          # no #sha1
        self.assertEqual(got[("@scope/a", "1.1.0")]["integrity"], "sha512-AAA=")
        self.assertEqual(guard.sri_best(got[("b", "2.0.0")]["integrity"])[0], "sha1")    # from the #sha1
        self.assertEqual(got[("gitdep", "1.0.0")]["resolved"], "git+https://github.com/u/r.git")

    def test_yarn_berry(self):
        got = {(e["name"], e["version"]): e for e in guard.yarn_berry_lock(YARN_BERRY_LOCK)}
        self.assertEqual(sorted(got), [("@esbuild/darwin-arm64", "0.25.0"), ("a", "1.0.0"), ("gh", "1.0.0"),
                                       ("gitdep", "1.0.0"), ("real", "3.0.0")])
        esb = got[("@esbuild/darwin-arm64", "0.25.0")]
        self.assertEqual((esb["os"], esb["cpu"], esb["resolved"], esb["lock_digest"]), (["darwin"], ["arm64"], "", None))
        self.assertEqual((got[("a", "1.0.0")]["lock_digest"], got[("a", "1.0.0")]["integrity"]), ("10c0/aaaa", ""))
        self.assertEqual(got[("gh", "1.0.0")]["resolved"], "https://npm.pkg.example/download/gh/1.0.0/abc")
        self.assertEqual((got[("gitdep", "1.0.0")]["resolved"], got[("gitdep", "1.0.0")]["lock_digest"]),
                         ("https://github.com/u/r.git#commit=abc", None))

    def test_bun(self):
        got = {(e["name"], e["version"]): e for e in guard.bun_lock_entries(BUN_LOCK)}
        self.assertEqual(sorted(got), [("@img/x", "0.1.0"), ("a", "1.0.0"), ("b", "2.0.0"), ("gh", "")])
        self.assertEqual((got[("a", "1.0.0")]["resolved"], got[("a", "1.0.0")]["integrity"]), ("", "sha512-AAA="))
        self.assertEqual(got[("b", "2.0.0")]["resolved"], "https://reg.example/b/-/b-2.0.0.tgz")
        self.assertEqual((got[("@img/x", "0.1.0")]["os"], got[("@img/x", "0.1.0")]["cpu"]), (["darwin"], ["arm64"]))
        self.assertEqual(got[("gh", "")]["resolved"], "github:u/r#abc")
        with self.assertRaises(ValueError):
            guard.bun_lock_entries("{}")

    def test_what_a_lockfile_adds_is_checked(self):
        """check_lock_entries: other platforms left out, what is installed
        skipped, git and digest-less tarballs noted; yarn 2+'s packages (no
        integrity) and npm's with one are fetched."""
        ctx = context()
        seen = []
        with mock.patch.object(guard, "check_npm_package", side_effect=lambda c, f, p: seen.append(p)), \
                mock.patch.object(guard, "node_platform", return_value=("linux", "x64", "glibc")):
            code = guard.check_lock_entries(ctx, guard.yarn_berry_lock(YARN_BERRY_LOCK),
                                            guard.Registries({"registry": "https://reg.example/"}),
                                            {("real", "3.0.0")}, "yarn.lock", rewrite=False)
        self.assertIsNone(code)
        self.assertEqual(sorted((p["name"], p["tarball"], p["lock_digest"]) for p in seen), [
            ("a", "https://reg.example/a/-/a-1.0.0.tgz", "10c0/aaaa"),
            ("gh", "https://npm.pkg.example/download/gh/1.0.0/abc", "10c0/bbbb")])
        self.assertEqual(ctx.skipped_platform, 1)
        self.assertEqual([(c.name, c.notes) for c in ctx.checks],
                         [("gitdep", ["a tarball URL with no digest in the lockfile (like a git dependency): "
                                      "not checked"])])


class ToolArgumentTests(unittest.TestCase):
    def test_index_options_are_taken_out(self):
        args, default, extras, strategy = guard.take_index_options(
            ["-i", "https://a.example/simple", "--extra-index-url=https://b.example/simple", "--pre", "x"])
        self.assertEqual((args, default.url, [e.url for e in extras], strategy),
                         (["--pre", "x"], "https://a.example/simple/", ["https://b.example/simple/"], None))
        args, default, extras, strategy = guard.take_index_options(
            ["--index", "corp=https://c.example/simple", "--default-index", "https://d.example/simple",
             "--index-strategy", "unsafe-best-match", "-ihttps://e.example/simple", "y"], uv=True)
        self.assertEqual((args, default.url, [(e.name, e.url) for e in extras], strategy),
                         (["y"], "https://e.example/simple/", [("corp", "https://c.example/simple/")],
                          "unsafe-best-match"))
        self.assertEqual(guard.take_index_options(["--index", "x"])[0], ["--index", "x"])      # not pip's

    def test_uv_tool_command_lines(self):
        self.assertEqual(guard.split_uv_args(["--with", "a", "-p", "3.12", "--isolated", "ruff", "check", "--fix"]),
                         (["--with", "a", "-p", "3.12", "--isolated"], "ruff", ["check", "--fix"]))
        self.assertEqual(guard.split_uv_args(["-q", "--", "black", "."]), (["-q"], "black", ["."]))
        self.assertEqual(guard.split_uv_args(["--offline"]), (["--offline"], None, []))
        req = guard._tool_requirements
        self.assertEqual(req([], "ruff@0.6.0", False), (["ruff==0.6.0"], []))
        self.assertEqual(req([], "ruff@latest", False), (["ruff"], []))
        self.assertEqual(req([], "python3.12", False), ([], []))                    # uvx python: no package
        self.assertEqual(req(["--from", "black[d]==24.1", "--with", "a,b[x,y]"], "black", False),
                         (["black[d]==24.1", "a", "b[x,y]"], []))
        self.assertEqual(req(["--from", "git+https://github.com/u/r", "--with", "p @ https://x.example/p.whl",
                              "--with-editable", "./local"], "r", False),
                         ([], ["git+https://github.com/u/r", "p @ https://x.example/p.whl", "./local"]))
        self.assertEqual(req([], "httpie==3.2", True), (["httpie==3.2"], []))


class CredentialsOnTheWireTests(unittest.TestCase):
    """What the fetcher sends: the credentials for a URL's own host and
    path, on that request only (not carried over a redirect to another
    host); a URL's user:password@ goes to its host alone and is never shown."""

    def setUp(self):
        self.seen = []
        seen = self.seen

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                seen.append((self.server.server_address[1], self.path, self.headers.get("Authorization")))
                if self.path.endswith("/away"):
                    self.send_response(302)
                    self.send_header("Location", other + "/landing")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path.startswith("/here"):
                    self.send_response(302)
                    self.send_header("Location", "/private/landing")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.servers = [Server(("127.0.0.1", 0), Handler) for _ in range(2)]
        for srv in self.servers:
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.addCleanup(srv.server_close)
            self.addCleanup(srv.shutdown)
        self.base = f"http://127.0.0.1:{self.servers[0].server_address[1]}"
        other = f"http://127.0.0.1:{self.servers[1].server_address[1]}"
        self.other = other
        creds = guard.pmsettings.Credentials()
        creds.token(self.base + "/private/", "t0ken")
        self.fetcher = guard.Fetcher({self.base[7:], other[7:]}, auth=creds)

    def auth_of(self, path):
        return [a for _p, got, a in self.seen if got == path]

    def test_only_to_the_host_and_path_they_are_for(self):
        self.fetcher.get(self.base + "/private/x")
        self.fetcher.get(self.base + "/public/x")
        self.assertEqual(self.auth_of("/private/x"), ["Bearer t0ken"])
        self.assertEqual(self.auth_of("/public/x"), [None])

    def test_not_over_a_redirect_to_another_host(self):
        self.fetcher.get(self.base + "/private/away")          # (the path has credentials; where it leads has none)
        self.assertEqual(self.auth_of("/private/away"), ["Bearer t0ken"])
        self.assertEqual(self.auth_of("/landing"), [None])

    def test_a_redirect_gets_where_it_leads_own(self):
        self.fetcher.get(self.base + "/here")
        self.assertEqual(self.auth_of("/here"), [None])
        self.assertEqual(self.auth_of("/private/landing"), ["Bearer t0ken"])

    def test_a_urls_own_credentials(self):
        url = self.other.replace("http://", "http://u:" + "s3cret@") + "/y"
        self.fetcher.get(url)
        self.assertEqual(self.auth_of("/y"), ["Basic " + base64.b64encode(b"u:s3cret").decode()])
        self.fetcher.allow("http://127.0.0.1:1/")
        with self.assertRaises(repo.FetchError) as cm:                # (nothing listens on port 1)
            self.fetcher.get(url.replace(self.other[7:], "127.0.0.1:1"))
        self.assertNotIn("s3cret", str(cm.exception))
        self.assertIn("http://127.0.0.1:1/y", str(cm.exception))


class RelayedIndexesTests(unittest.TestCase):
    """The local index relays several indexes: pip's (all at once) and uv's
    (the first that has the project); a PEP 503 HTML page is read too; a
    project none has gets an empty page (not a 404, so uv asks no other)."""
    A, B = "https://a.example/simple/", "https://b.example/simple/"

    def index(self, merge):
        old = (guard.now() - datetime.timedelta(days=30)).isoformat()
        pages = {self.A + "x/": {"name": "x", "files": [
                    {"filename": "x-1.0-py3-none-any.whl", "url": "https://files.a.example/x-1.0-py3-none-any.whl",
                     "hashes": {"sha256": "a" * 64}, "upload-time": old}]},
                 self.B + "x/": ('<a href="../../packages/x-2.0-py3-none-any.whl#sha256=' + "b" * 64 + '" '
                                 'data-requires-python="&gt;=3.9" data-dist-info-metadata="sha256=' + "c" * 64
                                 + '">x-2.0-py3-none-any.whl</a><a href="x-0.1.tar.gz" data-yanked="">x-0.1.tar.gz</a>'),
                 self.B + "y/": {"name": "y", "files": []}}
        spool = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, spool)
        return guard.PypiIndex(context(tool="pip"), _FakeFetcher(pages, {}), spool,
                               indexes=[guard.pmsettings.Index(self.A), guard.pmsettings.Index(self.B)], merge=merge)

    def test_merged(self):
        page = self.index(True).page("x")
        self.assertEqual([f["filename"] for f in page["files"]],
                         ["x-1.0-py3-none-any.whl", "x-2.0-py3-none-any.whl", "x-0.1.tar.gz"])
        html_file = page["files"][1]
        self.assertEqual((html_file["requires-python"], html_file["core-metadata"], html_file["hashes"]),
                         (">=3.9", {"sha256": "c" * 64}, {"sha256": "b" * 64}))
        self.assertIs(page["files"][2]["yanked"], True)

    def test_the_first_that_has_it(self):
        index = self.index(False)
        self.assertEqual([f["filename"] for f in index.page("x")["files"]], ["x-1.0-py3-none-any.whl"])
        self.assertEqual(index.page("y")["files"], [])                    # found on b (a has no page)
        self.assertEqual(index.page("nowhere"), {"meta": {"api-version": "1.1"}, "name": "nowhere", "files": []})

    def test_html_pages(self):
        doc = guard.parse_simple_html('<a href="/f/p-1.0.tar.gz#md5=00">p-1.0.tar.gz</a><a>no href</a>'
                                      '<a href="p-1.1.tar.gz" data-core-metadata="true">p-1.1.tar.gz</a>', "p")
        self.assertEqual(doc["files"], [{"filename": "p-1.0.tar.gz", "url": "/f/p-1.0.tar.gz", "hashes": {}},
                                        {"filename": "p-1.1.tar.gz", "url": "p-1.1.tar.gz", "hashes": {},
                                         "core-metadata": True}])


class PlatformTests(unittest.TestCase):
    HERE = ("linux", "x64", "glibc")

    def test_npm_install_checks_rules(self):
        cases = [({}, True), ({"os": ["darwin"]}, False), ({"os": ["!win32"]}, True), ({"os": ["!linux"]}, False),
                 ({"os": ["linux", "darwin"]}, True), ({"cpu": ["arm64"]}, False), ({"cpu": ["arm64", "x64"]}, True),
                 ({"os": ["any"]}, True), ({"libc": ["musl"]}, False), ({"libc": ["glibc"]}, True)]
        for entry, ok in cases:
            with self.subTest(entry=entry):
                self.assertEqual(guard.platform_ok(entry, self.HERE), ok)

    def test_libc_is_linux_only(self):
        self.assertFalse(guard.platform_ok({"libc": ["glibc"]}, ("darwin", "arm64", None)))

    def test_what_cant_be_told_filters_nothing(self):
        self.assertTrue(guard.platform_ok({"os": ["aix"], "cpu": ["s390x"], "libc": ["musl"]}, (None, None, None)))
        self.assertTrue(guard.platform_ok({"libc": ["musl"]}, ("linux", "x64", None)))

    def test_this_machine(self):
        plat, arch, libc = guard.node_platform()
        self.assertTrue(plat and arch)
        self.assertIn(libc, (None, "glibc", "musl"))


class WheelTests(unittest.TestCase):
    CP311_LINUX = ("cpython", 3, 11, "linux", "x86_64")

    def test_wheel_tags(self):
        fits = ["x-1.0-py3-none-any.whl", "x-1.0-py2.py3-none-any.whl",
                "x-1.0-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
                "x-1.0-cp38-abi3-manylinux_2_28_x86_64.whl", "x-1.0-cp311-cp311-musllinux_1_2_x86_64.whl",
                "x-1.0-1-py3-none-any.whl"]
        misfits = ["x-1.0-cp312-cp312-manylinux_2_17_x86_64.whl", "x-1.0-cp311-cp311-manylinux_2_17_aarch64.whl",
                   "x-1.0-cp311-cp311-macosx_11_0_arm64.whl", "x-1.0-cp311-cp311-win_amd64.whl",
                   "x-1.0-py2-none-any.whl", "not-a-wheel.whl"]
        for name in fits:
            with self.subTest(name):
                self.assertTrue(guard.wheel_fits(name, self.CP311_LINUX))
        for name in misfits:
            with self.subTest(name):
                self.assertFalse(guard.wheel_fits(name, self.CP311_LINUX))
        self.assertTrue(guard.wheel_fits("x-1.0-cp311-cp311-macosx_11_0_universal2.whl",
                                         ("cpython", 3, 11, "darwin", "arm64")))
        self.assertTrue(guard.wheel_fits("x-1.0-cp311-cp311-win_amd64.whl", ("cpython", 3, 11, "win32", "AMD64")))

    def test_picking_what_the_tool_may_install(self):
        sdist = {"filename": "x-1.0.tar.gz"}
        fit = {"filename": "x-1.0-py3-none-any.whl"}
        other = {"filename": "x-1.0-cp312-cp312-win_amd64.whl"}
        self.assertEqual(guard.pick_artifacts([sdist, fit, other], self.CP311_LINUX), [fit])
        self.assertEqual(guard.pick_artifacts([sdist, other], self.CP311_LINUX), [sdist])
        self.assertEqual(guard.pick_artifacts([other], self.CP311_LINUX), [other])


class RegistriesTests(unittest.TestCase):
    def test_default_and_scoped_registries(self):
        r = guard.Registries({"registry": "https://npm.example.com", "@corp:registry": "https://corp.example.com/npm/",
                              "@bad:registry": "ftp://x", "other": 5})
        self.assertEqual(r.for_name("left-pad"), "https://npm.example.com/")
        self.assertEqual(r.for_name("@corp/lib"), "https://corp.example.com/npm/")
        self.assertEqual(r.for_name("@bad/lib"), "https://npm.example.com/")
        self.assertEqual(r.tarball("@corp/lib", "1.0.0"), "https://corp.example.com/npm/@corp/lib/-/lib-1.0.0.tgz")
        self.assertEqual(guard.Registries({}).default, guard.NPM_REGISTRY)

    def test_npm_fetches_the_configured_registry_for_npmjs_urls(self):
        url = "https://registry.npmjs.org/a/-/a-1.0.0.tgz"
        self.assertEqual(guard.Registries({"registry": "https://mirror.example.com/"}).resolved("a", url),
                         "https://mirror.example.com/a/-/a-1.0.0.tgz")
        self.assertEqual(guard.Registries({"registry": "https://mirror.example.com/",
                                           "replace-registry-host": "never"}).resolved("a", url), url)
        self.assertEqual(guard.Registries({}).resolved("a", "https://other.example.com/a.tgz"),
                         "https://other.example.com/a.tgz")

    def test_plain_http_registries_are_the_configured_ones(self):
        r = guard.Registries({"registry": "http://npm.internal:4873/", "@x:registry": "https://x.example.com/"})
        self.assertEqual(r.http_hosts(), {"npm.internal:4873"})


class UvArgumentTests(unittest.TestCase):
    def test_the_lock_options_of_a_sync(self):
        self.assertEqual(guard.uv_lock_args(["sync", "--upgrade", "--all-extras", "-P", "x", "--python=3.12",
                                             "--no-dev", "-qq", "--index", "https://x.example", "-Pfoo",
                                             "--group", "docs"]),
                         ["--upgrade", "-P", "x", "--python=3.12", "-qq", "--index", "https://x.example", "-Pfoo"])

    def test_the_install_does_not_upgrade_again(self):
        self.assertEqual(guard.strip_uv_upgrade(["sync", "-U", "--upgrade-package", "x", "-Py",
                                                 "--upgrade-package=z", "--all-extras", "--upgrade"]),
                         ["sync", "--all-extras"])


class PipArgumentTests(unittest.TestCase):
    def test_other_indexes_are_refused(self):
        for args in (["-i", "https://x"], ["--index-url=https://x"], ["-ihttps://x"], ["--extra-index-url", "x"],
                     ["--no-index"], ["-f", "wheels/"], ["--find-links=wheels/"], ["--index", "x"]):
            with self.subTest(args), self.assertRaises(guard.GuardError):
                guard.check_pip_arguments(["requests"] + args)
        guard.check_pip_arguments(["requests", "--upgrade", "-r", "missing.txt"])     # fine

    def test_index_options_in_requirement_files(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "base.txt"), "w", encoding="utf-8") as f:
                f.write("requests\n--extra-index-url https://evil.example/simple\n")
            with open(os.path.join(d, "req.txt"), "w", encoding="utf-8") as f:
                f.write("# app\n-r base.txt\nidna\n")
            with open(os.path.join(d, "clean.txt"), "w", encoding="utf-8") as f:
                f.write("idna==3.10 --hash=sha256:" + "a" * 64 + "\n")
            with self.assertRaisesRegex(guard.GuardError, "base.txt"):
                guard.check_pip_arguments(["-r", os.path.join(d, "req.txt")])
            guard.check_pip_arguments(["-r", os.path.join(d, "clean.txt")])


class ProjectRootTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)

    def make(self, rel, text="{}"):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return os.path.dirname(path)

    def test_npm_workspaces(self):
        self.make("package.json", json.dumps({"name": "root", "workspaces": ["packages/*"]}))
        self.make("package-lock.json")
        member = self.make("packages/a/package.json")
        other = self.make("tools/b/package.json")
        self.assertEqual(guard.npm_root("npm", member), os.path.abspath(self.root))
        self.assertEqual(guard.npm_root("npm", other), other)                 # not one of the workspaces
        self.assertEqual(guard.npm_root("npm", self.root), self.root)

    def test_pnpm_workspace(self):
        self.make("pnpm-workspace.yaml", "packages:\n  - 'packages/*'\n")
        member = self.make("packages/a/package.json")
        self.assertEqual(guard.npm_root("pnpm", member), os.path.abspath(self.root))


class PolicyTests(unittest.TestCase):
    def test_suspicious_blocks_and_trust_lets_it_through(self):
        ctx = context(trust=["@corp/*", "Some_Lib"])
        hit = {"verdict": "SUSPICIOUS", "reason": "1 strong supply-chain indicator", "indicators": ["SC-X"]}
        blocked = ctx.add(guard.Check("npm", "evil", "1.0.0"))
        ctx.apply(blocked, hit)
        self.assertEqual(blocked.blocked, ["SUSPICIOUS: 1 strong supply-chain indicator"])
        trusted = ctx.add(guard.Check("npm", "@corp/tool", "1.0.0"))
        ctx.apply(trusted, hit)
        self.assertEqual((trusted.blocked, trusted.trusted), ([], True))
        self.assertIn("installed anyway (--trust)", trusted.notes[0])
        # PyPI names match the way pip compares them
        py = ctx.add(guard.Check("pypi", "some-lib", "1.0"))
        ctx.block(py, "could not be checked")
        self.assertTrue(py.trusted)
        self.assertEqual([c.name for c in ctx.blocked()], ["evil"])

    def test_warn_blocks_only_with_block_warn(self):
        hit = {"verdict": "WARN", "reason": "1 weaker indicator", "indicators": []}
        for block_warn, blocked in ((False, []), (True, ["WARN (--block-warn): 1 weaker indicator"])):
            ctx = context(block_warn=block_warn)
            c = ctx.add(guard.Check("npm", "x", "1.0.0"))
            ctx.apply(c, hit)
            self.assertEqual(c.blocked, blocked)

    def test_age(self):
        ctx = context(allow_new=["fresh"])
        hour_old = guard.now() - datetime.timedelta(hours=1)
        new = ctx.add(guard.Check("npm", "new", "1.0.0"))
        ctx.age_check(new, hour_old)
        self.assertEqual(len(new.blocked), 1)
        self.assertIn("published 1 hour ago, under --min-age 2 days (--allow-new new lets it through)",
                      new.blocked[0])
        allowed = ctx.add(guard.Check("npm", "fresh", "1.0.0"))
        ctx.age_check(allowed, hour_old)
        self.assertEqual((allowed.blocked, allowed.notes), ([], ["published 1 hour ago; let through by --allow-new"]))
        old = ctx.add(guard.Check("npm", "old", "1.0.0"))
        ctx.age_check(old, guard.now() - datetime.timedelta(days=3))
        self.assertEqual((old.blocked, old.age // 86400), ([], 3))
        unknown = ctx.add(guard.Check("npm", "unknown", "1.0.0"))
        ctx.age_check(unknown, None)
        self.assertEqual((unknown.blocked, unknown.age), ([], None))
        off = context(min_age=0)
        c = off.add(guard.Check("npm", "new", "1.0.0"))
        off.age_check(c, hour_old)
        self.assertEqual(c.blocked, [])

    def test_what_could_not_be_checked(self):
        ctx = context()
        failed = ctx.add(guard.Check("npm", "x", "1.0.0"))
        ctx.not_checked(failed, repo.FetchError("HTTP 404 fetching https://registry.example/x"))
        self.assertEqual(failed.blocked, ["could not be checked: HTTP 404 fetching https://registry.example/x"])
        big = ctx.add(guard.Check("npm", "big", "1.0.0"))
        ctx.not_checked(big, guard.TooLarge("response over 200MB: https://registry.example/big"))
        self.assertEqual((big.verdict, big.blocked), ("INCOMPLETE", []))
        strict = context(block_warn=True)
        big = strict.add(guard.Check("npm", "big", "1.0.0"))
        strict.not_checked(big, guard.TooLarge("response over 200MB: x"))
        self.assertEqual(len(big.blocked), 1)
        # (by its type, not its text: a server chooses the text, and a redirect to https://response over.example/ made a
        # failed download pass as one too large to scan: the Go/Rust review's CG-9)
        posing = ctx.add(guard.Check("npm", "posing", "1.0.0"))
        ctx.not_checked(posing, repo.FetchError("URL error fetching https://response over 200MB.example/: refused"))
        self.assertEqual(posing.verdict, None)
        self.assertEqual(len(posing.blocked), 1)

    def test_what_was_installed_but_not_checked(self):
        ctx = context()
        ctx.expected = {("a", "1.0.0")}
        ctx.add(guard.Check("npm", "b", "2.0.0"))
        guard.verify_installed(ctx, {("a", "1.0.0"), ("b", "2.0.0"), ("c", "3.0.0")}, "npm")
        self.assertEqual(ctx.unchecked, ["c@3.0.0"])
        py = context()
        py.expected = {("typing-extensions", "4.16.0")}
        guard.verify_installed(py, {("typing_extensions", "4.16.0")}, "pypi")
        self.assertEqual(py.unchecked, [])


class VerdictCacheTests(unittest.TestCase):
    HIT = {"verdict": "OK", "reason": "no supply-chain indicators", "indicators": []}

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "sub", "cache.json")

    def test_round_trip(self):
        cache = guard.VerdictCache(self.path)
        key = guard.VerdictCache.key("npm", "a", "1.0.0", "sha512-AAA=")
        published = datetime.datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
        cache.put(key, self.HIT, published)
        cache.save()
        again = guard.VerdictCache(self.path)
        self.assertEqual(again.get(key), dict(self.HIT, published="2025-01-02T03:04:05Z"))
        self.assertIsNone(again.get("npm:a@1.0.0#sha512-BBB="))

    def test_another_engine_version_starts_empty(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"engine": "0.0.1", "verdicts": {"k": dict(self.HIT, published=None)}}, f)
        self.assertIsNone(guard.VerdictCache(self.path).get("k"))

    def test_a_damaged_cache_is_ignored(self):
        os.makedirs(os.path.dirname(self.path))
        for text in ("{", "[]", json.dumps({"engine": repo.ENGINE_VERSION, "verdicts": {"k": {"verdict": "FINE"}}})):
            with open(self.path, "w", encoding="utf-8") as f:
                f.write(text)
            self.assertIsNone(guard.VerdictCache(self.path).get("k"))

    def test_a_device_or_a_folder_is_no_cache(self):
        """LAZARET_GUARD_CACHE=/dev/null (NUL on Windows) turns the cache off:
        nothing is read from it, and it is never written over (as root, a
        rename would have replaced /dev/null itself)."""
        for path in (os.devnull, self.dir):
            with self.subTest(path=path):
                cache = guard.VerdictCache(path)
                cache.put("k", self.HIT, None)
                with mock.patch.object(guard.tempfile, "mkstemp", side_effect=AssertionError("wrote a cache")):
                    cache.save()
                self.assertIsNone(cache.path)

    def test_a_failed_save_leaves_nothing_behind(self):
        cache = guard.VerdictCache(self.path)
        cache.put("k", self.HIT, None)
        with mock.patch.object(guard.os, "replace", side_effect=OSError("denied")):
            cache.save()
        self.assertEqual(os.listdir(os.path.dirname(self.path)), [])

    def test_the_oldest_are_dropped(self):
        cache = guard.VerdictCache(self.path)
        with mock.patch.object(guard.VerdictCache, "MAX_ENTRIES", 2):
            for k in ("a", "b", "c"):
                cache.put(k, self.HIT, None)
            cache.save()
        self.assertEqual(list(guard.VerdictCache(self.path).data), ["b", "c"])


class _Server:
    """A local HTTP server answering from a {path: (status, headers, body)} map."""

    def __init__(self, routes):
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                status, headers, body = routes.get(self.path, (404, {}, b""))
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class FetcherTests(unittest.TestCase):
    def test_what_may_be_fetched(self):
        f = guard.Fetcher({"registry.npmjs.org"}, http_hosts={"npm.internal:4873"})
        f.check("https://registry.npmjs.org/a")
        for bad in ("http://registry.npmjs.org/a", "https://evil.example/a", "ftp://registry.npmjs.org/a",
                    "file:///etc/passwd"):
            with self.subTest(bad), self.assertRaises(repo.FetchError):
                f.check(bad)
        f.allow("http://npm.internal:4873/a/-/a-1.0.0.tgz")
        f.check("http://npm.internal:4873/a/-/a-1.0.0.tgz")         # a registry the tool's settings name
        f.allow("http://127.0.0.1:9/x")
        f.check("http://127.0.0.1:9/x")                             # this machine
        self.assertTrue(guard.fetchable("https://x.example/a") and guard.fetchable("http://localhost:1/a"))
        self.assertFalse(guard.fetchable("http://x.example/a") or guard.fetchable("git+ssh://x/y"))

    def test_redirects_are_held_to_the_same_rule_and_bodies_to_a_budget(self):
        server = _Server({"/away": (302, {"Location": "https://evil.example/x"}, b""),
                          "/big": (200, {}, b"x" * 4096),
                          "/tgz": (200, {"Last-Modified": "Mon, 01 Dec 2025 20:49:45 GMT"}, b"data")})
        self.addCleanup(server.close)
        f = guard.Fetcher({server.url[len("http://"):]})
        with self.assertRaisesRegex(repo.FetchError, "redirect blocked"):
            f.get(server.url + "/away")
        with self.assertRaisesRegex(repo.FetchError, "response over"):
            f.get(server.url + "/big", max_bytes=1024)
        body, headers = f.fetch(server.url + "/tgz")
        self.assertEqual((body, headers.get("Last-Modified")), (b"data", "Mon, 01 Dec 2025 20:49:45 GMT"))
        with self.assertRaises(repo.FetchError) as cm:
            f.get(server.url + "/missing")
        self.assertEqual(cm.exception.status, 404)


class ScannerTests(unittest.TestCase):
    def test_a_scan_that_fails_is_an_error_not_a_verdict(self):
        s = guard.Scanner(None, timeout=10, jobs=1)
        with mock.patch.object(guard, "_scan_one", side_effect=RuntimeError("boom")):
            with self.assertRaisesRegex(guard.ScanError, "the scan failed"):
                s.scan(b"data", "tgz", "npm")

    def test_summaries(self):
        res = {"issues": [{"rule": "SC-B64", "sev": "MAJOR", "file": "b.js", "msg": "blob"},
                          {"rule": "SC-INSTALL-HOOK", "sev": "CRITICAL", "file": "package.json", "msg": "hook"},
                          {"rule": "SC-INVENTORY", "sev": "INFO", "file": "x", "msg": "info"},
                          {"rule": "S1234", "sev": "CRITICAL", "file": "x", "msg": "quality"}]}
        self.assertEqual(guard.summarize(res), ["SC-INSTALL-HOOK (CRITICAL) package.json: hook",
                                                "SC-B64 (MAJOR) b.js: blob"])


class _FakeFetcher:
    def __init__(self, pages, files):
        self.pages, self.files, self.allowed, self.http_hosts = pages, files, [], set()

    def json(self, url, accept=None):
        if url not in self.pages:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return self.pages[url]

    def fetch(self, url, max_bytes=None, accept=None, timeout=None):
        page = self.json(url)
        if isinstance(page, str):                                   # a PEP 503 (HTML) page
            return page.encode(), {"Content-Type": "text/html"}
        return json.dumps(page).encode(), {"Content-Type": "application/vnd.pypi.simple.v1+json"}

    def get(self, url, *args, **kw):
        if url not in self.files:
            raise repo.FetchError(f"HTTP 404 fetching {url}")
        return self.files[url]

    def allow(self, url):
        self.allowed.append(url)


class LocalIndexTests(unittest.TestCase):
    UP = "https://pypi.example/simple/"

    def setUp(self):
        from tests.registry._review_support import zipball
        self.good = zipball({"x/__init__.py": "V = 1\n", "x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"})
        old = (guard.now() - datetime.timedelta(days=30)).isoformat()
        new = (guard.now() - datetime.timedelta(hours=1)).isoformat()
        files = [
            {"filename": "x-1.0-py3-none-any.whl", "url": "https://files.example/x-1.0-py3-none-any.whl",
             "hashes": {"sha256": hashlib.sha256(self.good).hexdigest()}, "upload-time": old},
            {"filename": "x-1.1-py3-none-any.whl", "url": "https://files.example/x-1.1-py3-none-any.whl",
             "hashes": {"sha256": "0" * 64}, "upload-time": new},
            {"filename": "x-0.9-py3-none-any.whl", "url": "http://insecure.example/x-0.9-py3-none-any.whl",
             "hashes": {}, "upload-time": old},
            {"filename": "../x-0.8.tar.gz", "url": "https://files.example/x-0.8.tar.gz", "hashes": {}},
            {"filename": "x-0.7.tar.gz", "url": "https://files.example/x-0.7.tar.gz",
             "hashes": {"sha256": "1" * 64}, "upload-time": old},
            {"filename": "x-0.6.tar.gz", "url": "https://files.example/x-0.6.tar.gz", "size": 10 ** 12,
             "upload-time": old},
        ]
        self.fetcher = _FakeFetcher({self.UP + "x/": {"name": "x", "files": files,
                                                      "versions": ["0.6", "0.7", "0.9", "1.0", "1.1"]}},
                                    {"https://files.example/x-1.0-py3-none-any.whl": self.good,
                                     "https://files.example/x-0.7.tar.gz": b"not the published bytes"})
        self.spool = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.spool)
        self.ctx = context(tool="pip")
        self.index = guard.PypiIndex(self.ctx, self.fetcher, self.spool, self.UP)

    def test_the_page_it_serves(self):
        page = self.index.page("x")
        self.assertEqual([f["filename"] for f in page["files"]], ["x-1.0-py3-none-any.whl", "x-0.7.tar.gz",
                                                                   "x-0.6.tar.gz"])
        self.assertTrue(all(f["url"].startswith("/files/") for f in page["files"]))
        self.assertEqual(page["versions"], ["0.6", "0.7", "0.9", "1.0"])            # 1.1 is held back
        self.assertEqual(list(self.index.held_back), ["x"])
        self.assertEqual(self.index.release_files("X", "1.0.0")[0][1]["filename"], "x-1.0-py3-none-any.whl")

    def test_scanning_what_it_serves(self):
        self.index.page("x")
        numbers = {i["filename"]: n for n, i in self.index.files.items()}
        check, spooled = self.index.scan(numbers["x-1.0-py3-none-any.whl"])
        self.assertEqual((check.verdict, check.blocked), ("OK", []))
        with open(spooled, "rb") as f:
            self.assertEqual(f.read(), self.good)
        self.assertIs(self.index.scan(numbers["x-1.0-py3-none-any.whl"])[0], check)        # once
        check, spooled = self.index.scan(numbers["x-0.7.tar.gz"])
        self.assertEqual((check.blocked, spooled), (["its SHA-256 is not the one the index publishes"], None))
        check, spooled = self.index.scan(numbers["x-0.6.tar.gz"])
        self.assertEqual((check.verdict, check.blocked, spooled), ("INCOMPLETE", [], None))
        with self.assertRaises(repo.FetchError):
            self.index.scan("999")

    def test_the_server(self):
        server = guard.make_index_server(self.index)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        f = guard.Fetcher({base[len("http://"):]})
        page = json.loads(f.get(base + "/simple/X/", accept="application/vnd.pypi.simple.v1+json"))
        self.assertEqual(page["name"], "x")
        html_page = f.get(base + "/simple/x/", accept="text/html").decode()
        self.assertIn('href="/files/', html_page)
        self.assertIn("#sha256=", html_page)
        numbers = {i["filename"]: n for n, i in self.index.files.items()}
        self.assertEqual(f.get(f"{base}/files/{numbers['x-1.0-py3-none-any.whl']}/x-1.0-py3-none-any.whl"),
                         self.good)
        with self.assertRaises(repo.FetchError) as cm:
            f.get(f"{base}/files/{numbers['x-0.7.tar.gz']}/x-0.7.tar.gz")
        self.assertEqual(cm.exception.status, 403)
        for path in (f"/files/{numbers['x-0.7.tar.gz']}/other.tar.gz", "/files/999/x.whl", "/etc/passwd",
                     "/simple/../../x/"):
            with self.subTest(path), self.assertRaises(repo.FetchError) as cm:
                f.get(base + path)
            self.assertEqual(cm.exception.status, 404)

    def test_file_versions(self):
        self.assertEqual([guard.file_version(n) for n in ("x-1.0-py3-none-any.whl", "x_y-2.0.tar.gz",
                                                          "x-3.0.zip", "weird")], ["1.0", "2.0", "3.0", ""])
        self.assertTrue(guard._same_version("1.0", "1.0.0") and guard._same_version("v2.1", "2.1"))
        self.assertFalse(guard._same_version("1.0", "1.1"))


class ReportTests(unittest.TestCase):
    def test_what_is_printed_and_written(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = context(json=os.path.join(d, "out.json"), args=["install", "x"])
            evil = ctx.add(guard.Check("npm", "evil", "1.0.0"))
            evil.indicators = ["SC-INSTALL-HOOK (CRITICAL) package.json: hook"]
            ctx.block(evil, "SUSPICIOUS: 1 strong supply-chain indicator")
            warn = ctx.add(guard.Check("npm", "warn", "2.0.0"))
            ctx.apply(warn, {"verdict": "WARN", "reason": "1 weaker indicator", "indicators": []})
            ok = ctx.add(guard.Check("npm", "ok", "3.0.0"))
            ctx.apply(ok, {"verdict": "OK", "reason": "", "indicators": []})
            code = guard.finish(ctx, installed=False, restored=["package.json", "package-lock.json"])
            text = ctx.out.getvalue()
            self.assertEqual(code, guard.EXIT_BLOCKED)
            self.assertIn("checked 1 WARN, 1 not checked, 1 OK", text)
            self.assertIn("  BLOCKED    evil@1.0.0: SUSPICIOUS: 1 strong supply-chain indicator\n"
                          "             SC-INSTALL-HOOK (CRITICAL) package.json: hook", text)
            self.assertIn("  WARN       warn@2.0.0: 1 weaker indicator", text)
            self.assertNotIn("ok@3.0.0", text)
            self.assertIn("1 blocked — nothing was installed; package.json and package-lock.json put back", text)
            with open(os.path.join(d, "out.json"), encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual((doc["generatedBy"], doc["installed"], doc["blocked"], doc["exitCode"]),
                             ("lazaret-guard-1", False, 1, 1))
            self.assertEqual([p["name"] for p in doc["packages"]], ["evil", "warn", "ok"])

    def test_plan_and_unchecked(self):
        ctx = context(plan=True)
        self.assertEqual(guard.finish(ctx, installed=False, restored=["package.json"]), guard.EXIT_OK)
        self.assertIn("nothing blocked (--plan: nothing was installed; package.json put back)", ctx.out.getvalue())
        ctx = context()
        ctx.unchecked = ["c@3.0.0"]
        self.assertEqual(guard.finish(ctx, installed=True, code=0), guard.EXIT_BLOCKED)
        self.assertIn("installed but not checked: c@3.0.0", ctx.out.getvalue())
        self.assertEqual(guard.finish(context(), installed=False, code=guard.EXIT_RESOLVE), guard.EXIT_RESOLVE)

    def test_a_long_review_list_is_cut(self):
        ctx = context()
        for n in range(guard.SHOW_REVIEW + 5):
            ctx.apply(ctx.add(guard.Check("npm", f"p{n:02d}", "1.0.0")),
                      {"verdict": "WARN", "reason": "r", "indicators": []})
        guard.finish(ctx, installed=True, code=0)
        self.assertIn("… and 5 more to review (--json PATH lists them all)", ctx.out.getvalue())


class CommandLineTests(unittest.TestCase):
    def run_main(self, argv, path=None):
        err = io.StringIO()
        env = {"LAZARET_GUARD_CACHE": os.devnull}
        if path is not None:
            env["PATH"] = path
        with mock.patch("sys.stderr", err), mock.patch.dict(os.environ, env):
            try:
                code = guard.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, err.getvalue()

    def test_usage_errors(self):
        """The command line is checked before the package manager is looked
        for: these hold with none of them installed (CI's runners have no pnpm
        or uv)."""
        with tempfile.TemporaryDirectory() as empty:
            for argv, message in ((["--min-age", "soon", "npm", "install"], "--min-age"),
                                  (["npm", "publish"], "wraps npm's install commands"),
                                  (["pnpm", "add", "-g", "x"], "global installs"),
                                  (["uv", "tree"], "wraps uv add"),
                                  (["uv", "add", "x", "--script", "s.py"], "--script"),
                                  (["uv", "pip", "compile", "r.in"], "wraps `pip install`"),
                                  (["pip", "install", "-f", "./wheels", "x"], "local archives"),
                                  (["uvx", "--no-index", "ruff"], "local archives"),
                                  (["bun", "add", "-g", "x"], "global installs"),
                                  (["bun", "add", "x", "--no-verify"], "--no-verify"),
                                  (["yarn", "global", "add", "x"], "yarn global"),
                                  (["uv", "run", "x"], "uv is not on PATH"),
                                  (["uvx", "ruff"], "uv is not on PATH"),
                                  (["pip", "install", "-i", "https://x.example/simple", "x"],
                                   "pip is not on PATH"),
                                  (["--jobs", "0", "npm", "install"], "--jobs"),
                                  (["npm", "install", "x"], "npm is not on PATH"),
                                  (["uv", "sync"], "uv is not on PATH"),
                                  (["pip", "install", "x"], "pip is not on PATH")):
                with self.subTest(argv):
                    code, err = self.run_main(argv, path=empty)
                    self.assertEqual(code, guard.EXIT_USAGE, err)
                    self.assertIn(message, err)
        code, err = self.run_main(["poetry", "add", "x"])
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", err)

    def test_the_lazaret_command_dispatches_guard(self):
        self.assertTrue(_cli.is_guard(["guard", "npm", "install", "x"]))
        self.assertTrue(_cli.is_guard(["guard", "--plan", "--min-age", "7d", "pip", "install", "x"]))
        self.assertFalse(_cli.is_guard(["."]))
        self.assertFalse(_cli.is_guard(["guarded"]))
        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                self.assertTrue(_cli.is_guard(["guard"]))                   # guard's usage
                os.mkdir("guard")
                self.assertFalse(_cli.is_guard(["guard"]))                  # scan the folder named guard
                self.assertFalse(_cli.is_guard(["guard", "--json", "out.json"]))
                self.assertTrue(_cli.is_guard(["guard", "npm", "ci"]))
            finally:
                os.chdir(cwd)                   # before the folder goes: Windows can't remove a current directory


if __name__ == "__main__":
    unittest.main()
