"""`lazaret-registry go:… crates:…` (0.1.9, Part C, X-2's part): a Go module or a crate named by a spec is resolved,
downloaded and checked by its registry module (registry/ecosystems) through `repo.module_transport`, then scanned and
stored as an npm or PyPI release is.

Recorded responses: fnv 1.0.7's index file and `.crate` from crates.io, and github.com/pmezard/go-difflib v1.0.0's zip
with the checksum database's answer (tests/registry/recorded). The hostile modules and crates are built here, inert
(never built; documentation addresses). Nothing opens a socket."""

import hashlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from lazaret.registry import repo
from lazaret.registry.ecosystems import base, crates, golang
from lazaret.scanner import _native
from tests.registry import _cargo_support, _go_support
from tests.registry import test_golang as recorded_go
from tests import _support

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recorded", "crates")
INDEX = "https://index.crates.io/"
STATIC = "https://static.crates.io/crates/"
GO_MOD = recorded_go.MOD
PROXY = "https://proxy.golang.org/"
SUMDB = "https://sum.golang.org/lookup/"


def recorded(name):
    with open(os.path.join(HERE, name), "rb") as fh:
        return fh.read()


FNV_CRATE = recorded("fnv-1.0.7.crate")
FNV_INDEX = recorded("fnv.index")


def fnv_responses():
    return {INDEX + "3/f/fnv": FNV_INDEX, STATIC + "fnv/fnv-1.0.7.crate": FNV_CRATE}


def index_line(name, version, data, deps=()):
    return json.dumps({"name": name, "vers": version, "deps": list(deps), "cksum": hashlib.sha256(data).hexdigest(),
                       "features": {}, "yanked": False}).encode() + b"\n"


def crate_responses(name, version, files):
    """The index file and the `.crate` of a crate built here."""
    data = _cargo_support.crate_tgz(name, version, files)
    return {INDEX + crates.index_path(name): index_line(name, version, data), STATIC + f"{name}/{name}-{version}.crate": data}


def module_responses(module, version, files):
    """What the proxy and the checksum database answer for a Go module built here."""
    data, gomod = _go_support.module_zip(module, version, files)
    info = json.dumps({"Version": version, "Time": "2026-01-02T03:04:05Z"}).encode()
    lookup = recorded_go.lookup_text(module, version, zip_hash=golang.zip_h1(data), mod_hash=golang.file_h1(gomod.encode()))
    path = golang.escape(module)
    return {PROXY + f"{path}/@v/{version}.info": info, PROXY + f"{path}/@latest": info,
            SUMDB + f"{path}@{version}": lookup.encode(), PROXY + f"{path}/@v/{version}.zip": data}


class Served:
    """`repo.module_transport` over recorded responses: what was asked, and the URL rule each request came with."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def __call__(self, url, max_bytes=None, accept=None, timeout=None, check_redirect=None):
        self.calls.append((url, max_bytes, timeout))
        check_redirect(url)                                          # (the rule the real transport applies first)
        body = self.responses.get(url)
        if body is None:
            err = base.FetchError("not found")
            err.status = 404
            raise err
        return body

    def urls(self):
        return [url for url, _, _ in self.calls]


def served(responses):
    transport = Served(responses)
    return transport, mock.patch.object(repo, "module_transport", transport)


# ---------------------------------------------------------------------------
class SpecTests(unittest.TestCase):
    def test_go_and_crates_specs(self):
        for spec, want in (("go:github.com/pmezard/go-difflib@v1.0.0", ("go", GO_MOD, "v1.0.0")),
                           ("go:github.com/BurntSushi/toml", ("go", "github.com/BurntSushi/toml", None)),
                           ("go:gopkg.in/yaml.v3@v3.0.1", ("go", "gopkg.in/yaml.v3", "v3.0.1")),
                           ("crates:fnv@1.0.7", ("crates", "fnv", "1.0.7")), ("crates:Inflector", ("crates", "Inflector", None)),
                           (" Crates : serde@1.0.0-rc.1 ", ("crates", "serde", "1.0.0-rc.1")), ("GO:example.com/m", ("go", "example.com/m", None))):
            with self.subTest(spec=spec):
                self.assertEqual(repo.parse_spec(spec), want)

    def test_the_module_refuses_what_its_tool_refuses(self):
        for spec in ("go:x", "go:x@v1.0.0", "go:../x", "go:github.com/x/y@1.0.0", "go:github.com/x/y@latest", "go:",
                     "crates:", "crates:-a", "crates:a.b", "crates:fnv@v1.0.7", "crates:fnv@1.0", "crates:fnv==1.0.7",
                     "crates:" + "a" * 65):
            with self.subTest(spec=spec), self.assertRaises(repo.SpecError):
                repo.parse_spec(spec)

    def test_a_hostile_name_is_never_echoed_raw(self):
        for spec in ("go:example.com/a\x1b[31mb", "crates:a‮b", "go:example.com/m@v1.0.0\x1b[0m"):
            with self.subTest(spec=spec), self.assertRaises(repo.SpecError) as caught:
                repo.parse_spec(spec)
            self.assertNotIn("\x1b", str(caught.exception))
            self.assertNotIn("‮", str(caught.exception))

    def test_the_errors_name_every_ecosystem(self):
        with self.assertRaises(repo.SpecError) as caught:
            repo.parse_spec("cargo:fnv")
        self.assertIn("use npm, pypi, go, crates, openvsx or vscode", str(caught.exception))
        with self.assertRaises(repo.SpecError) as caught:
            repo.parse_spec("fnv")
        self.assertIn("go:<module>, crates:<name>, openvsx:<namespace>.<name> or vscode:<publisher>.<name>",
                      str(caught.exception))
        self.assertEqual(repo.ECOSYSTEMS, ("npm", "pypi", "go", "crates", "openvsx", "vscode"))

    def test_names_and_versions_are_the_modules(self):
        self.assertTrue(repo.valid_name("go", "github.com/pkg/errors"))
        self.assertFalse(repo.valid_name("go", "errors"))
        self.assertTrue(repo.valid_name("crates", "Foo_Bar"))
        self.assertFalse(repo.valid_name("crates", "_foo"))
        self.assertEqual(repo._check_version("go", " v1.2.3 "), "v1.2.3")
        self.assertEqual(repo._check_version("crates", "1.2.3"), "1.2.3")
        self.assertIsNone(repo._check_version("go", None))
        for eco, version in (("go", "1.2.3"), ("crates", "v1.2.3")):
            with self.subTest(eco=eco), self.assertRaises(repo.SpecError):
                repo._check_version(eco, version)

    def test_npm_and_pypi_are_read_as_before(self):
        self.assertEqual(repo.parse_spec("npm:@scope/pkg@1.0.0"), ("npm", "@scope/pkg", "1.0.0"))
        self.assertEqual(repo.parse_spec("pypi:requests==2.0"), ("pypi", "requests", "2.0"))
        self.assertIsNone(repo.registry_module("npm"))
        self.assertIsNone(repo.registry_module("pypi"))
        self.assertIs(repo.registry_module("go"), golang.ECOSYSTEM)
        self.assertIs(repo.registry_module("crates"), crates.ECOSYSTEM)


class ResolveTests(unittest.TestCase):
    def test_a_crate_resolves_through_the_sparse_index(self):
        transport, patch = served(fnv_responses())
        with patch:
            resolved = repo.resolve("crates", "fnv", None)
        self.assertEqual(resolved[:4], ("1.0.7", STATIC + "fnv/fnv-1.0.7.crate", "tgz", "crate"))
        self.assertIsInstance(resolved, repo.Resolution)
        self.assertEqual(transport.urls(), [INDEX + "3/f/fnv"])

    def test_a_go_module_resolves_through_the_proxy_and_the_checksum_database(self):
        transport, patch = served(recorded_go.difflib_responses())
        with patch:
            resolved = repo.resolve("go", GO_MOD, None)
        self.assertEqual(resolved[:4], ("v1.0.0", PROXY + GO_MOD + "/@v/v1.0.0.zip", "zip", "gomod"))
        self.assertEqual(transport.urls(), [PROXY + GO_MOD + "/@latest", SUMDB + GO_MOD + "@v1.0.0"])

    def test_the_transport_gets_the_modules_own_url_rule(self):
        seen = []

        def transport(url, max_bytes=None, accept=None, timeout=None, check_redirect=None):
            seen.append(check_redirect)
            return FNV_INDEX
        with mock.patch.object(repo, "module_transport", transport):
            repo.resolve("crates", "fnv", "1.0.7")
        (check,) = seen
        self.assertEqual(check(INDEX + "3/f/fnv"), INDEX + "3/f/fnv")
        for url in ("https://registry.npmjs.org/fnv", "https://proxy.golang.org/x", "http://index.crates.io/3/f/fnv",
                    "https://user@static.crates.io/x"):
            with self.subTest(url=url), self.assertRaises(repo.FetchError):
                check(url)

    def test_a_version_of_another_major_is_refused_before_any_request(self):
        for name, version in (("gopkg.in/yaml.v3", "v2.0.0"), ("github.com/x/y/v2", "v1.0.0"), ("github.com/x/y", "v2.0.0")):
            transport, patch = served({})
            with self.subTest(name=name), patch, self.assertRaises(repo.SpecError):
                repo.resolve("go", *repo.parse_spec(f"go:{name}@{version}")[1:])
            self.assertEqual(transport.urls(), [])

    def test_a_missing_version_is_a_spec_error_and_a_404_a_fetch_error(self):
        transport, patch = served(fnv_responses())
        with patch, self.assertRaises(repo.SpecError):
            repo.resolve("crates", "fnv", "9.9.9")
        transport, patch = served({})
        with patch, self.assertRaises(repo.FetchError) as caught:
            repo.resolve("go", GO_MOD, "v1.0.0")
        self.assertEqual(caught.exception.status, 404)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ScanTests(unittest.TestCase):
    def test_a_crate(self):
        transport, patch = served(fnv_responses())
        with patch, mock.patch.object(repo, "http_bytes", side_effect=AssertionError("npm and PyPI's fetch")):
            res = repo.scan_package("crates", "fnv", "1.0.7")
        self.assertEqual((res["ecosystem"], res["name"], res["version"], res["artifact"]), ("crates", "fnv", "1.0.7", "crate"))
        self.assertEqual((res["verdict"], res["truncated"]), ("OK", 0))
        self.assertEqual(res["digest"], ("sha256", hashlib.sha256(FNV_CRATE).hexdigest()))
        self.assertEqual(res["archiveBytes"], len(FNV_CRATE))
        self.assertGreaterEqual(res["filesScanned"], 1)
        self.assertEqual(transport.urls(), [INDEX + "3/f/fnv", STATIC + "fnv/fnv-1.0.7.crate"])
        self.assertEqual(transport.calls[1][1:], (repo.MAX_DOWNLOAD_BYTES, repo.DOWNLOAD_TIMEOUT))

    def test_a_go_module(self):
        transport, patch = served(recorded_go.difflib_responses())
        with patch:
            res = repo.scan_package("go", GO_MOD, "v1.0.0")
        self.assertEqual((res["version"], res["artifact"], res["verdict"]), ("v1.0.0", "gomod", "OK"))
        self.assertEqual(res["digest"], ("h1", recorded_go.DIFFLIB["h1"][3:]))
        self.assertEqual(transport.urls(), [PROXY + GO_MOD + "/@v/v1.0.0.info", SUMDB + GO_MOD + "@v1.0.0",
                                            PROXY + GO_MOD + "/@v/v1.0.0.zip"])

    def test_a_crate_whose_build_script_pipes_a_download_into_a_shell(self):
        transport, patch = served(crate_responses("buildevil", "0.1.0", {"build.rs": _cargo_support.BUILD_EVIL_RS}))
        with patch:
            res = repo.scan_package("crates", "buildevil", None)
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        hooks = [i for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
        self.assertTrue(hooks and all(i["file"] == "build.rs" and i["sev"] == "CRITICAL" for i in hooks), res["issues"])

    def test_a_go_module_whose_init_pipes_a_download_into_a_shell(self):
        module = "example.test/initevil"
        transport, patch = served(module_responses(module, "v1.0.0", {"e.go": _go_support.INIT_EVIL_GO}))
        with patch:
            res = repo.scan_package("go", module, None)
        self.assertEqual(res["verdict"], "SUSPICIOUS")
        self.assertIn("SC-IMPORT-RISK", {i["rule"] for i in res["issues"]})

    def test_a_download_that_does_not_match_its_digest_is_never_scanned(self):
        for eco, name, version, responses, url, swapped in (
                ("crates", "fnv", "1.0.7", fnv_responses(), STATIC + "fnv/fnv-1.0.7.crate",
                 _cargo_support.crate_tgz("fnv", "1.0.7", {})),
                ("go", GO_MOD, "v1.0.0", recorded_go.difflib_responses(), PROXY + GO_MOD + "/@v/v1.0.0.zip", recorded_go.ERRORS_ZIP)):
            with self.subTest(eco=eco):
                responses[url] = swapped
                transport, patch = served(responses)
                with patch, mock.patch.object(repo, "_scan_artifact", side_effect=AssertionError("scanned")), \
                        self.assertRaises(repo.DigestError) as caught:
                    repo.scan_package(eco, name, version)
                text = str(caught.exception)
                self.assertTrue(text.startswith(f"{eco}:{name}@{version} SC-DIGEST-MISMATCH: "), text)
                self.assertIn("refusing to scan an unverified artifact", text)

    def test_no_dependency_history_is_asked_of_npm_or_pypi(self):
        transport, patch = served(fnv_responses())
        with patch, mock.patch.object(repo, "npm_new_dependencies", side_effect=AssertionError("npm")), \
                mock.patch.object(repo, "pypi_new_dependencies", side_effect=AssertionError("pypi")):
            resolved = repo.resolve("crates", "fnv", "1.0.7")
            self.assertEqual(repo.new_dependency_issues("crates", "fnv", "1.0.7", resolved), [])
            self.assertEqual(repo.new_dependency_issues("go", GO_MOD, "v1.0.0", resolved), [])
            self.assertEqual(repo.scan_package("crates", "fnv", "1.0.7", resolved=resolved)["verdict"], "OK")


API = "https://crates.io/api/v1/crates/"


def history_line(name, version, pubtime, deps=()):
    """An index line with its publishing time; deps: (name, kind) pairs."""
    return json.dumps({"name": name, "vers": version, "cksum": "0" * 64, "features": {}, "yanked": False,
                       "pubtime": pubtime, "deps": [{"name": d, "req": "^1", "features": [], "optional": False,
                                                     "default_features": True, "target": None, "kind": k}
                                                    for d, k in deps]}).encode() + b"\n"


def owners(*logins):
    return json.dumps({"users": [{"id": k, "login": login, "kind": "user"} for k, login in enumerate(logins)]}).encode()


class NewCrateDependencyTests(unittest.TestCase):
    """SC-NEW-DEPENDENCY for a crate (0.1.9, N-3's second part): the release compared with the one crates.io published
    before it, from the sparse index's lines and their `pubtime`; a crate an owner of the release's also owns (the API's
    owners) is not counted."""

    def responses(self, added=("freshdep", "normal"), first="2026-05-01T09:00:00Z", app_owners=("alice",),
                  dep_owners=("mallory",)):
        out = {INDEX + crates.index_path("app"): (
                   history_line("app", "1.0.0", "2026-03-01T10:00:00Z", [("serde", "normal")])
                   + history_line("app", "1.0.1", "2026-05-02T10:00:00Z", [("serde", "normal"), added])),
               INDEX + crates.index_path(added[0]): history_line(added[0], "0.1.0", first)}
        if app_owners is not None:
            out[API + "app/owners"] = owners(*app_owners)
        if dep_owners is not None:
            out[API + added[0] + "/owners"] = owners(*dep_owners)
        return out

    def issues(self, responses):
        transport, patch = served(responses)
        with patch:
            resolved = repo.resolve("crates", "app", "1.0.1")
            return [(i["rule"], i["sev"], i["msg"]) for i in repo.new_dependency_issues("crates", "app", "1.0.1",
                                                                                         resolved)], transport

    def test_a_crate_published_the_day_before_by_a_stranger(self):
        found, transport = self.issues(self.responses())
        self.assertEqual(found, [("SC-NEW-DEPENDENCY", "CRITICAL",
                                  'Adds a dependency on "freshdep", which 1.0.0 did not have: a package first published '
                                  "25 hours before this release by mallory, who does not maintain this one.")])
        # the index for times, the API for the owners only, at most one request a second there
        self.assertEqual(sorted({u.split("/")[2] for u in transport.urls()}), ["crates.io", "index.crates.io"])
        self.assertEqual(crates.ECOSYSTEM.rate, {"crates.io": 1.0})

    def test_a_build_dependency_counts_and_a_dev_dependency_does_not(self):
        found, _ = self.issues(self.responses(added=("freshdep", "build")))
        self.assertEqual([sev for _r, sev, _m in found], ["CRITICAL"])
        found, transport = self.issues(self.responses(added=("freshdep", "dev")))
        self.assertEqual(found, [])
        self.assertNotIn(API + "freshdep/owners", transport.urls())

    def test_what_is_not_counted(self):
        # one of the crate's own owners'; a crate a month old; one already there before
        self.assertEqual(self.issues(self.responses(dep_owners=("mallory", "alice")))[0], [])
        self.assertEqual(self.issues(self.responses(first="2026-03-15T00:00:00Z"))[0], [])
        same = self.responses(added=("serde", "normal"))
        self.assertEqual(self.issues(same)[0], [])
        with mock.patch.dict(os.environ, {"LAZARET_NO_DEPENDENCY_HISTORY": "1"}):
            self.assertEqual(self.issues(self.responses())[0], [])

    def test_a_crate_is_as_old_as_its_first_version(self):
        responses = self.responses()
        responses[INDEX + crates.index_path("freshdep")] = (history_line("freshdep", "0.0.1", "2025-01-01T00:00:00Z")
                                                           + history_line("freshdep", "0.1.0", "2026-05-01T09:00:00Z"))
        self.assertEqual(self.issues(responses)[0], [])

    def test_a_release_is_compared_with_the_release_before_it(self):
        # (a pre-release between them is skipped, as for npm and PyPI)
        responses = self.responses()
        responses[INDEX + crates.index_path("app")] = (
            history_line("app", "1.0.0", "2026-03-01T10:00:00Z", [("serde", "normal")])
            + history_line("app", "1.0.1-beta.1", "2026-05-02T09:00:00Z", [("serde", "normal"), ("freshdep", "normal")])
            + history_line("app", "1.0.1", "2026-05-02T10:00:00Z", [("serde", "normal"), ("freshdep", "normal")]))
        found, _ = self.issues(responses)
        self.assertEqual([m.split(":", 1)[0] for _r, _s, m in found],
                         ['Adds a dependency on "freshdep", which 1.0.0 did not have'])

    def test_a_week_old_crate_is_major_and_an_unanswered_api_names_no_owner(self):
        found, _ = self.issues(self.responses(first="2026-04-20T10:00:00Z"))
        self.assertEqual([sev for _r, sev, _m in found], ["MAJOR"])
        found, _ = self.issues(self.responses(app_owners=None, dep_owners=None))
        self.assertEqual(found, [("SC-NEW-DEPENDENCY", "CRITICAL",
                                  'Adds a dependency on "freshdep", which 1.0.0 did not have: a package first published '
                                  "25 hours before this release.")])


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class SweepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = repo.Store(os.path.join(self.tmp.name, "state.db"))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def sweep(self, specs, rescan=False):
        errors, out, err = [], io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            bad = repo.cmd_scan(self.store, specs, False, rescan, errors=errors)
        return bad, errors, out.getvalue(), err.getvalue()

    def test_scanned_stored_and_skipped_the_next_time(self):
        responses = dict(fnv_responses(), **recorded_go.difflib_responses())
        transport, patch = served(responses)
        with patch:
            bad, errors, out, err = self.sweep(["crates:fnv@1.0.7", f"go:{GO_MOD}@v1.0.0"])
        self.assertEqual((bad, errors, err), (False, [], ""))
        self.assertEqual(self.store.report("crates", "fnv", "1.0.7")["verdict"], "OK")
        self.assertEqual(self.store.report("go", GO_MOD, "v1.0.0")["verdict"], "OK")
        self.assertEqual(sorted((eco, name) for _, eco, name in self.store.packages()), [("crates", "fnv"), ("go", GO_MOD)])
        transport, patch = served(responses)
        with patch:
            bad, errors, out, err = self.sweep(["crates:fnv", f"go:{GO_MOD}"])            # (scan-all's specs: no version)
        self.assertEqual((bad, errors), (False, []))
        self.assertIn("crates:fnv@1.0.7 already scanned (supply-chain, OK)", out)
        self.assertIn(f"go:{GO_MOD}@v1.0.0 already scanned (supply-chain, OK)", out)
        self.assertEqual(transport.urls(), [INDEX + "3/f/fnv", PROXY + GO_MOD + "/@latest", SUMDB + GO_MOD + "@v1.0.0"])

    def test_a_failure_is_one_packages_and_the_sweep_goes_on(self):
        responses = fnv_responses()
        responses[STATIC + "fnv/fnv-1.0.7.crate"] = b"not the crate"
        responses.update(crate_responses("buildevil", "0.1.0", {"build.rs": _cargo_support.BUILD_EVIL_RS}))
        transport, patch = served(responses)
        with patch:
            bad, errors, out, err = self.sweep(["crates:fnv@1.0.7", "go:x", "crates:buildevil"])
        self.assertTrue(bad)
        self.assertEqual(errors, ["crates:fnv@1.0.7", "go:x"])
        self.assertIn("error scanning crates:fnv@1.0.7: crates:fnv@1.0.7 SC-DIGEST-MISMATCH", err)
        self.assertIsNone(self.store.report("crates", "fnv", "1.0.7"))
        self.assertEqual(self.store.report("crates", "buildevil", "0.1.0")["verdict"], "SUSPICIOUS")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class McpTests(unittest.TestCase):
    def test_the_mcp_tool_takes_them_too(self):
        from lazaret.mcp import server
        transport, patch = served(dict(fnv_responses(), **recorded_go.difflib_responses()))
        with tempfile.TemporaryDirectory() as d, patch, mock.patch.object(server, "REGISTRY_DB", os.path.join(d, "r.db")):
            crate = server.tool_scan_package({"spec": "crates:fnv@1.0.7"})
            module = server.tool_scan_package({"spec": f"go:{GO_MOD}"})
            status = server.tool_registry_status({})
        self.assertEqual((crate["package"], crate["artifact"], crate["verdict"]), ("crates:fnv@1.0.7", "crate", "OK"))
        self.assertEqual((module["package"], module["artifact"], module["verdict"]), (f"go:{GO_MOD}@v1.0.0", "gomod", "OK"))
        self.assertNotIn("storeError", crate)
        self.assertEqual(sorted((p["package"], p["lastVersion"], p["verdict"]) for p in status["packages"]),
                         [("crates:fnv", "1.0.7", "OK"), (f"go:{GO_MOD}", "v1.0.0", "OK")])
        spec = next(t for t in server.TOOLS if t["name"] == "scan_package")["inputSchema"]["properties"]["spec"]
        self.assertIn("go:<module path>", spec["description"])
        self.assertIn("crates:<name>", spec["description"])


@mock.patch.dict(os.environ, _support.PYTHON_TRANSPORT)
class TransportTests(unittest.TestCase):
    """`module_transport`: _fetch's bounded read, with the module's URL rule for the URL and every redirect."""

    def setUp(self):
        self.fetch = base.Fetch(crates.ECOSYSTEM, repo.module_transport)

    class Opener:
        def __init__(self, chunks=(b"body",), error=None):
            self.chunks, self.error, self.requests = list(chunks), error, []

        def open(self, req, timeout=None):
            self.requests.append((req, timeout))
            if self.error is not None:
                raise self.error
            chunks = list(self.chunks)

            class Response(io.RawIOBase):
                def read(self, n=-1):
                    return chunks.pop(0) if chunks else b""
            return Response()

    def transport(self, url, opener, **kw):
        with mock.patch.object(repo, "_module_opener", lambda check: opener):
            return repo.module_transport(url, check_redirect=self.fetch.check_url, **kw)

    def test_the_modules_hosts_and_not_npm_and_pypis(self):
        opener = self.Opener()
        self.assertEqual(self.transport(INDEX + "3/f/fnv", opener, max_bytes=100, timeout=7), b"body")
        ((req, timeout),) = opener.requests
        self.assertEqual((req.full_url, timeout, req.get_header("User-agent")), (INDEX + "3/f/fnv", 7, repo.USER_AGENT))
        for url in ("https://registry.npmjs.org/x", "https://pypi.org/x", "http://index.crates.io/x", "file:///etc/passwd"):
            with self.subTest(url=url), self.assertRaises(repo.FetchError):
                self.transport(url, self.Opener(error=AssertionError("opened")))

    def test_the_rule_is_required(self):
        with mock.patch.object(repo, "_module_opener", side_effect=AssertionError("opened")), \
                self.assertRaises(repo.FetchError):
            repo.module_transport(INDEX + "3/f/fnv", max_bytes=10)

    def test_the_body_is_bounded(self):
        with self.assertRaises(repo.FetchError) as caught:
            self.transport(STATIC + "x", self.Opener([b"x" * 600, b"x" * 600]), max_bytes=1000)
        self.assertIn("exceeds", str(caught.exception))

    def test_an_http_error_keeps_its_status(self):
        error = urllib.error.HTTPError(INDEX + "3/f/fnv", 404, "Not Found", {}, None)
        with self.assertRaises(repo.FetchError) as caught:
            self.transport(INDEX + "3/f/fnv", self.Opener(error=error), max_bytes=10)
        self.assertEqual(caught.exception.status, 404)
        with mock.patch.object(repo, "_module_opener", lambda check: self.Opener(error=error)), \
                self.assertRaises(repo.FetchError) as caught:
            self.fetch.json(INDEX + "3/f/fnv")              # (what the module sees, through `Fetch`)
        self.assertEqual(caught.exception.status, 404)

    def test_a_redirect_is_checked_by_the_modules_rule(self):
        handler = repo._ModuleRedirects(self.fetch.check_url)
        req = urllib.request.Request(INDEX + "3/f/fnv")
        moved = handler.redirect_request(req, None, 302, "Found", {}, STATIC + "fnv/fnv-1.0.7.crate")
        self.assertEqual(moved.full_url, STATIC + "fnv/fnv-1.0.7.crate")
        for newurl in ("https://evil.invalid/x", "http://static.crates.io/x", "https://registry.npmjs.org/x"):
            with self.subTest(newurl=newurl), self.assertRaises(urllib.error.URLError):
                handler.redirect_request(req, None, 302, "Found", {}, newurl)
        self.assertEqual(handler.max_redirections, repo.MAX_REDIRECTS)
        opener = repo._module_opener(self.fetch.check_url)
        self.assertTrue(any(isinstance(h, repo._ModuleRedirects) for h in opener.handlers))
        self.assertFalse(any(type(h) is urllib.request.HTTPRedirectHandler for h in opener.handlers))


if __name__ == "__main__":
    unittest.main()
