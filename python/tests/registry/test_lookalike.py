"""0.1.8: names like a popular package's (SC-TYPOSQUAT, registry/lookalike.py).

A release whose own name, or a dependency it declares, is one change from
one of the 5,000 most-downloaded packages of its registry — a character
added, dropped or changed, two swapped, or the separators changed — gets a
MAJOR finding, unless the name is a popular package itself (mysql2 next to
mysql), the popular name is shorter than 5 characters, or it is in the
package's own npm scope. Archives are built in memory; nothing runs.

0.1.9 (N-3): a Go module's path, or one its go.mod requires, like a
well-known module's (awesome-go's and Debian's): its owner one change from
that module's, its separators changed or a word like "-go" added, with the
repository the same; its host one change, with the rest the
same; a gopkg.in name one change. Not a well-known module's owner or host,
nor one of the module's own, nor a short owner with a short repository, nor
another owner's module of the same name (a fork).

0.1.9 (N-3's second part): a crate's name, or a crate its Cargo.toml
depends on to build, one change from one of the 5,000 crates crates.io
counts the most downloads of in 90 days, compared as crates.io names them
(lower-cased, "_" as "-"). Not a [dev-dependencies] crate.
"""
import json
import lzma
import os
import tempfile
import time
import unittest
import unittest.mock

from lazaret.registry import lookalike, repo
from tests import _support
from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel, zipball

POPULAR_SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "update-popular-names.py")

META = "Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n{requires}\nA description.\n"


def typos(res):
    return [(i["file"], i["line"], i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-TYPOSQUAT"]


class LookalikeTests(unittest.TestCase):
    def test_one_change_from_a_popular_name(self):
        cases = {("pypi", "requesxs"): ("requests", "a character changed"),
                 ("pypi", "reqeusts"): ("requests", "two characters swapped"),
                 ("pypi", "python-dateuti"): ("python-dateutil", "a character dropped"),
                 ("pypi", "Python_Dateuti"): ("python-dateutil", "a character dropped"),     # PEP 503 names
                 ("pypi", "tiketoken"): ("tiktoken", "a character added"),
                 ("pypi", "pythondateutil"): ("python-dateutil", "its separators changed"),
                 ("npm", "lodahs"): ("lodash", "two characters swapped"),
                 ("npm", "expresss"): ("express", "a character added"),
                 ("npm", "@hestjs/core"): ("@nestjs/core", "a character changed")}
        for (eco, name), want in cases.items():
            with self.subTest(name):
                self.assertEqual(lookalike.lookalike(eco, name), want)

    def test_not_a_lookalike(self):
        for eco, name in (("pypi", "requests"), ("pypi", "numpy"), ("pypi", "fastai"),     # popular themselves
                          ("npm", "mysql"), ("npm", "mysql2"), ("npm", "delegate"),
                          ("npm", "fs"), ("npm", "os2"), ("pypi", "attr"),               # short popular names
                          ("npm", "@babel/corf"),                                       # its own scope's name
                          ("pypi", "a-name-far-from-any-popular-one"), ("npm", "x" * 300), ("npm", ""),
                          ("npm", None)):
            with self.subTest(name):
                self.assertIsNone(lookalike.lookalike(eco, name))

    def test_the_popular_names(self):
        with open(lookalike.__file__.replace("lookalike.py", "popular_names.json"), encoding="utf-8") as f:
            raw = json.load(f)
        for eco in ("npm", "pypi"):
            with self.subTest(eco):
                sec = raw[eco]
                self.assertEqual(len(sec["targets"]), 5000)
                self.assertEqual(len(set(sec["targets"])), 5000)
                self.assertTrue(sec["source"] and sec["license"])
                self.assertEqual(sec["known"], sorted(sec["known"]))
                # the known names are exactly the popular ones that would otherwise be flagged
                bare = lookalike.tables(sec["targets"], ())
                for name in sec["known"]:
                    self.assertIsNotNone(lookalike.lookalike(eco, name, bare), name)
                    self.assertIsNone(lookalike.lookalike(eco, name), name)
        self.assertEqual(raw["npm"]["license"], "MIT")
        self.assertIn("CC BY 4.0", raw["pypi"]["license"])

    def test_the_findings(self):
        text = json.dumps({"name": "lodahs", "version": "1.0.0", "dependencies": {"expresss": "^4", "react": "^18"}},
                          indent=2)
        found = lookalike.issues("npm", "lodahs", {"expresss", "react"}, "package.json", text)
        self.assertEqual([(i["rule"], i["sev"], i["line"], i["msg"]) for i in found], [
            ("SC-TYPOSQUAT", "MAJOR", 2, 'The package is named "lodahs", one change from "lodash" (two characters '
                                         'swapped), one of the 5,000 most-downloaded npm packages.'),
            ("SC-TYPOSQUAT", "MAJOR", 5, 'Depends on "expresss", one change from "express" (a character added), one '
                                         'of the 5,000 most-downloaded npm packages.')])


class LookalikeRegistryTests(unittest.TestCase):
    def test_an_sdist_named_like_requests(self):
        res = scan_sdist({"PKG-INFO": META.format(name="requesxs", requires=""), "setup.py": "from setuptools import setup\n"
                          "setup(name='requesxs', version='1.0')\n", "requesxs/__init__.py": ""})
        self.assertEqual(res["verdict"], "WARN", res["issues"])
        self.assertEqual(typos(res), [("PKG-INFO", 2, "MAJOR", 'The package is named "requesxs", one change from '
                                       '"requests" (a character changed), one of the 5,000 most-downloaded PyPI '
                                       'projects.')])

    def test_a_wheel_that_requires_a_lookalike(self):
        requires = "Requires-Dist: reqeusts>=2\nRequires-Dist: pytset; extra == \"dev\"\nRequires-Dist: numpy"
        res = scan_wheel({"lit/__init__.py": "", "lit-1.0.dist-info/METADATA": META.format(name="lit", requires=requires)})
        self.assertEqual([m for _f, _l, _s, m in typos(res)],
                         ['Depends on "reqeusts", one change from "requests" (two characters swapped), one of the '
                          '5,000 most-downloaded PyPI projects.'])

    def test_an_npm_package_and_its_dependencies(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0",
                                                    "dependencies": {"lodahs": "1.0.0", "chalk": "^5"},
                                                    "optionalDependencies": {"axois": "1"}})})
        self.assertEqual(res["verdict"], "WARN", res["issues"])
        self.assertEqual(sorted(m for _f, _l, _s, m in typos(res)), [
            'Depends on "axois", one change from "axios" (two characters swapped), one of the 5,000 '
            'most-downloaded npm packages.',
            'Depends on "lodahs", one change from "lodash" (two characters swapped), one of the 5,000 '
            'most-downloaded npm packages.'])

    def test_a_name_like_a_node_builtin(self):
        """0.1.8: Node's built-in modules named with a separator are compared
        too: a dependency on child-process installs a stranger's package."""
        res = scan_npm({"package.json": json.dumps({"name": "crypto-hash-kit", "version": "1.0.0",
                                                    "dependencies": {"child-process": "^1"}})})
        self.assertEqual([m for _f, _l, _s, m in typos(res)], [
            'Depends on "child-process", one change from "child_process" (its separators changed), a module '
            "built into Node."])
        self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
        res = scan_npm({"package.json": json.dumps({"name": "worker-threads", "version": "1.0.0"})})
        self.assertEqual([m for _f, _l, _s, m in typos(res)], [
            'The package is named "worker-threads", one change from "worker_threads" (its separators changed), a '
            "module built into Node."])
        for name, want in (("childprocess", ("child_process", "its separators changed")),
                           ("child_proces", ("child_process", "a character dropped")),
                           ("perf_hook", ("perf_hooks", "a character dropped")),
                           ("child_process", None), ("events", None), ("async-hook", None),
                           ("child-process-promise", None)):
            with self.subTest(name):
                self.assertEqual(lookalike.builtin_lookalike(name), want)

    def test_popular_packages_stay_ok(self):
        res = scan_npm({"package.json": json.dumps({"name": "express", "version": "4.0.0",
                                                    "dependencies": {"debug": "2", "mysql2": "3", "qs": "6"}})})
        self.assertEqual(typos(res), [])
        res = scan_wheel({"requests/__init__.py": "", "requests-2.0.dist-info/METADATA": META.format(
            name="requests", requires="Requires-Dist: urllib3\nRequires-Dist: idna")})
        self.assertEqual(typos(res), [])


def scan_gomod(files, root="github.com/x/y@v1.0.0/"):
    """A Go module's zip (members below `root`) scanned as the guard scans one."""
    budget = repo.Budget(deadline=time.monotonic() + 120, deadline_detail="scan time budget exceeded")
    return repo._scan_artifact(zipball({root + k: v for k, v in files.items()}), "zip", "gomod", False, budget)


class GoLookalikeTests(unittest.TestCase):
    def test_paths_like_a_well_known_modules(self):
        cases = {
            "github.com/shopsprint/decimal": ("github.com/shopspring/decimal", "owner", "shopsprint",
                                              'is one change from "shopspring" (a character changed)'),
            "github.com/boltdb-go/bolt": ("github.com/boltdb/bolt", "owner", "boltdb-go",
                                          'is "boltdb" with "-go" added'),
            "github.com/Spf-13/cobra/v2": ("github.com/spf13/cobra", "owner", "spf-13",
                                           'differs from "spf13" only in its separators'),
            "github.com/go-rediss/redis/v9": ("github.com/go-redis/redis", "owner", "go-rediss",
                                              'is one change from "go-redis" (a character added)'),
            "github.com/rs-go/zerolog": ("github.com/rs/zerolog", "owner", "rs-go", 'is "rs" with "-go" added'),
            "github.com/aws-go/aws-sdk-go-v2/service/s3": ("github.com/aws/aws-sdk-go-v2", "owner", "aws-go",
                                                           'is "aws" with "-go" added'),
            "githab.com/spf13/cobra": ("github.com/spf13/cobra", "host", "githab.com",
                                       'is one change from "github.com" (a character changed)'),
            "go.ubr.org/zap": ("go.uber.org/zap", "host", "go.ubr.org",
                               'is one change from "go.uber.org" (a character dropped)'),
            "gopkg.in/yanl.v3": ("gopkg.in/yaml.v3", "name", "yanl",
                                 'is one change from "yaml" (a character changed)'),
            "gopkg.in/yanl.v2": ("gopkg.in/yaml.v2", "name", "yanl",
                                 'is one change from "yaml" (a character changed)'),
            "github.com/spf31/cobra": ("github.com/spf13/cobra", "owner", "spf31",
                                       'is one change from "spf13" (two characters swapped)'),
        }
        for path, (target, part, mine, how) in cases.items():
            with self.subTest(path):
                found = lookalike.go_lookalike(path)
                self.assertEqual((found[0], found[1], found[2], found[4]), (target, part, mine, how))
                self.assertEqual(lookalike.lookalike("go", path), found)

    def test_not_a_lookalike(self):
        for path in ("github.com/shopspring/decimal", "github.com/ShopSpring/decimal", "github.com/spf13/cobra/v2",
                     "gopkg.in/yaml.v3", "gopkg.in/yaml.v4", "golang.org/x/net", "go.uber.org/zap",
                     "github.com/cavernouskina/mcp-go",          # another owner's module of the same name: a fork
                     "github.com/someone/decimal", "github.com/libs/pq",            # a short owner, a short repository
                     "gitlab.com/spf13/cobra",                  # a host of the well-known modules
                     "github.com/uber-go/zap", "github.com/pion/webrtc", "github.com/pions/webrtc",
                     "example.com/shopsprint", "x" * 600, "no-dot/x", "github.com/a b/c", "", None,
                     "go.uber.org/zapp", "golang.org/x/nett",   # a domain's owner owns every path below it
                     "google.golang.org/grpcc",
                     # a word taken away: an author who moved a module to an organization so named left the old path
                     # in what required it (Shopify/sarama's go.mod: github.com/xdg/scram, now github.com/xdg-go/scram)
                     "github.com/xdg/scram", "github.com/sql-driver/mysql",
                     "github.com/spf24/cobra", "github.com/spf32/cobra"):     # two characters changed, not swapped
            with self.subTest(path):
                self.assertIsNone(lookalike.go_lookalike(path))
        # a module's own owner names its own modules
        self.assertIsNone(lookalike.go_lookalike("github.com/shopsprint/decimal", own=("github.com", "shopsprint")))
        # an owner or a host of a well-known module is no stranger's
        data = lookalike.go_tables(["github.com/pion/webrtc", "github.com/pions/rtp", "k8s.io/client-go",
                                    "k3s.io/other"])
        self.assertIsNone(lookalike.go_lookalike("github.com/pions/webrtc", data))
        self.assertIsNone(lookalike.go_lookalike("k3s.io/client-go", data))
        self.assertEqual(lookalike.go_lookalike("github.com/pionn/webrtc", data)[:3],
                         ("github.com/pion/webrtc", "owner", "pionn"))
        self.assertEqual(lookalike.go_lookalike("k9s.io/client-go", data)[:3], ("k8s.io/client-go", "host", "k9s.io"))
        self.assertTrue(lookalike.popular("go", "github.com/Shopspring/decimal/v2"))

    def test_the_go_list(self):
        with open(lookalike.__file__.replace("lookalike.py", "popular_names.json"), encoding="utf-8") as f:
            sec = json.load(f)["go"]
        targets = sec["targets"]
        self.assertGreater(len(targets), 4000)
        self.assertEqual(targets, sorted(set(targets)))
        self.assertEqual([t for t in targets if lookalike.go_path(t) != t], [])
        self.assertIn("MIT", sec["license"])
        self.assertTrue(sec["source"] and sec["copyright"] and sec["notice"])
        for path in ("github.com/shopspring/decimal", "github.com/boltdb/bolt", "gopkg.in/yaml.v3",
                     "golang.org/x/sys", "github.com/spf13/cobra"):
            self.assertIn(path, targets)
        # Without itself, a module of the list is rarely like another's: 2 of the 4,893 (pions/webrtc, the
        # old name of pion/webrtc; gopkg.in/macaron.v1 next to macaroon.v1)
        rank, by_repo, by_tail, owners, hosts = lookalike.go_tables(targets)
        owned, hosted = {}, {}
        for t in targets:
            host, owner, _repo, _tail = lookalike._go_split(t)
            hosted[host] = hosted.get(host, 0) + 1
            if owner is not None:
                owned[(host, owner)] = owned.get((host, owner), 0) + 1
        alike = []
        for t in targets:                                  # the tables without t
            host, owner, repo, tail = lookalike._go_split(t)
            without = dict(rank)
            del without[t]
            repos, tails = dict(by_repo), dict(by_tail)
            if owner is not None:
                repos[(host, repo)] = [x for x in by_repo[(host, repo)] if x[1] != t]
            tails[tail] = [x for x in by_tail[tail] if x[1] != t]
            data = (without, repos, tails, owners - {(host, owner)} if owned.get((host, owner)) == 1 else owners,
                    hosts - {host} if hosted[host] == 1 else hosts)
            if lookalike.go_lookalike(t, data) is not None:
                alike.append(t)
        self.assertLessEqual(len(alike), 5, alike)

    def test_the_findings(self):
        text = ("module github.com/shopsprint/decimal\n\ngo 1.21\n\nrequire (\n\tgithub.com/boltdb-go/bolt v1.3.1\n"
                "\tgithub.com/shopsprint/util v1.0.0\n\tgolang.org/x/sys v0.28.0 // indirect\n)\n")
        found = lookalike.issues("go", "github.com/shopsprint/decimal",
                                 {"github.com/boltdb-go/bolt", "github.com/shopsprint/util", "golang.org/x/sys"},
                                 "go.mod", text)
        count = f"{len(lookalike._load()['go'][0]):,}"
        self.assertEqual([(i["rule"], i["sev"], i["line"], i["msg"]) for i in found], [
            ("SC-TYPOSQUAT", "MAJOR", 1, 'The module is "github.com/shopsprint/decimal": its owner "shopsprint" is '
                                         'one change from "shopspring" (a character changed), the owner of '
                                         f'"github.com/shopspring/decimal", one of the {count} Go modules awesome-go '
                                         "lists or Debian packages."),
            ("SC-TYPOSQUAT", "MAJOR", 6, 'Requires "github.com/boltdb-go/bolt": its owner "boltdb-go" is "boltdb" '
                                         'with "-go" added, the owner of "github.com/boltdb/bolt", one of the '
                                         f"{count} Go modules awesome-go lists or Debian packages.")])


class GoLookalikeRegistryTests(unittest.TestCase):
    def test_a_module_named_like_shopspring_decimal(self):
        res = scan_gomod({"go.mod": "module github.com/shopsprint/decimal\n\ngo 1.21\n\nrequire github.com/"
                                    "boltdb-go/bolt v1.3.1\n",
                          "decimal.go": "package decimal\n"}, root="github.com/shopsprint/decimal@v1.3.3/")
        self.assertEqual([(f, line, sev, m.split(":", 1)[0]) for f, line, sev, m in typos(res)], [
            ("shopsprint/decimal@v1.3.3/go.mod", 1, "MAJOR", 'The module is "github.com/shopsprint/decimal"'),
            ("shopsprint/decimal@v1.3.3/go.mod", 5, "MAJOR", 'Requires "github.com/boltdb-go/bolt"')])

    def test_only_the_root_go_mod(self):
        # a go.mod below the root is no module's (Go leaves a nested module out of the zip)
        res = scan_gomod({"sub/go.mod": "module github.com/shopsprint/decimal\n", "x.go": "package x\n"})
        self.assertEqual(typos(res), [])
        res = scan_gomod({"go.mod": "module example.com\n\nrequire github.com/boltdb-go/bolt v1.3.1\n"},
                         root="example.com@v1.0.0/")
        self.assertEqual([m.split(":", 1)[0] for _f, _l, _s, m in typos(res)], ['Requires "github.com/boltdb-go/bolt"'])

    def test_a_requirement_with_a_long_version(self):
        # a version longer than the go.mod reader reads is still a requirement (gomod's "unversioned")
        res = scan_gomod({"go.mod": "module example.com/m\n\nrequire github.com/boltdb-go/bolt v1.0.0-" + "a" * 120
                                    + "\n"}, root="example.com/m@v1.0.0/")
        self.assertEqual([m.split(":", 1)[0] for _f, _l, _s, m in typos(res)], ['Requires "github.com/boltdb-go/bolt"'])

    def test_the_go_mod_past_the_text_budget(self):
        # the text kept for later is bounded; the module's go.mod is read whatever came before it
        with unittest.mock.patch.object(repo, "DEFERRED_TEXT_BUDGET", 64):
            res = scan_gomod({"README.md": "x" * 50, "go.mod": "module github.com/shopsprint/decimal\n"},
                             root="github.com/shopsprint/decimal@v1.3.3/")
        self.assertEqual(len(typos(res)), 1, res["issues"])

    def test_well_known_modules_stay_quiet(self):
        res = scan_gomod({"go.mod": "module github.com/spf13/cobra\n\ngo 1.15\n\nrequire (\n\tgithub.com/cpuguy83/"
                                    "go-md2man/v2 v2.0.6\n\tgithub.com/inconshreveable/mousetrap v1.1.0\n\t"
                                    "github.com/spf13/pflag v1.0.6\n\tgopkg.in/yaml.v3 v3.0.1\n)\n",
                          "cobra.go": "package cobra\n"}, root="github.com/spf13/cobra@v1.9.1/")
        self.assertEqual(typos(res), [])


def scan_crate(files, name="x", version="1.0.0"):
    """A crate's .crate scanned as the guard and the registry scan one."""
    from tests.registry import _cargo_support
    budget = repo.Budget(deadline=time.monotonic() + 120, deadline_detail="scan time budget exceeded")
    return repo._scan_artifact(_cargo_support.crate_tgz(name, version, files), "tgz", "crate", False, budget)


class CratesLookalikeTests(unittest.TestCase):
    def test_names_like_a_popular_crates(self):
        for name, target, how in (("proc-macro1", "proc-macro2", "a character changed"),
                                  ("rustdecimal", "rust-decimal", "its separators changed"),
                                  ("reqwset", "reqwest", "two characters swapped"),
                                  ("tokyo", "tokio", "a character changed"),
                                  ("Serde_Jsom", "serde-json", "a character changed")):
            with self.subTest(name):
                self.assertEqual(lookalike.lookalike("crates", name), (target, how))

    def test_not_a_lookalike(self):
        # crates.io's one name (case, - and _), a popular crate, one the list knows, a target under five
        # characters (libc), two changes (faster_log for fast_log)
        for name in ("serde_json", "Serde-JSON", "rust_decimal", "tokio", "proc-macro2", "arrow2", "lbc", "faster_log",
                     "", "x" * 100):
            with self.subTest(name):
                self.assertIsNone(lookalike.lookalike("crates", name))

    def test_the_crates_list(self):
        with open(lookalike.__file__.replace("lookalike.py", "popular_names.json"), encoding="utf-8") as f:
            sec = json.load(f)["crates"]
        self.assertEqual(len(sec["targets"]), 5000)
        self.assertEqual(len(set(sec["targets"])), 5000)
        self.assertTrue(all(t == lookalike.normalize("crates", t) for t in sec["targets"] + sec["known"]))
        self.assertLess(sec["targets"].index("proc-macro2"), 50)
        self.assertEqual(sec["known"], sorted(sec["known"]))
        bare = lookalike.tables(sec["targets"], ())
        for name in sec["known"]:
            self.assertIsNotNone(lookalike.lookalike("crates", name, bare), name)
            self.assertIsNone(lookalike.lookalike("crates", name), name)
        self.assertIn("crates.io", sec["source"])
        self.assertTrue(sec["license"])

    def test_the_findings(self):
        toml = ('[package]\nname = "rustdecimal"\nversion = "1.0.0"\n\n[dependencies.proc-macro1]\nversion = "1"\n\n'
                '[dependencies.http]\nversion = "0.1"\npackage = "reqwset"\n\n[target."cfg(unix)".build-dependencies]\n'
                'tokyo = "1"\n\n[dev-dependencies.serde_jsom]\nversion = "1"\n')
        res = scan_crate({"Cargo.toml": toml}, name="rustdecimal")
        self.assertEqual(typos(res), [
            ("Cargo.toml", 2, "MAJOR", 'The package is named "rustdecimal", one change from "rust-decimal" (its '
                                       'separators changed), one of the 5,000 most-downloaded crates.'),
            ("Cargo.toml", 5, "MAJOR", 'Depends on "proc-macro1", one change from "proc-macro2" (a character changed), '
                                       'one of the 5,000 most-downloaded crates.'),
            ("Cargo.toml", 10, "MAJOR", 'Depends on "reqwset", one change from "reqwest" (two characters swapped), '
                                        'one of the 5,000 most-downloaded crates.'),
            ("Cargo.toml", 13, "MAJOR", 'Depends on "tokyo", one change from "tokio" (a character changed), one of '
                                        'the 5,000 most-downloaded crates.')])

    def test_popular_crates_stay_quiet(self):
        toml = ('[package]\nname = "reqwest"\nversion = "0.12.9"\n\n[dependencies]\nbase64 = "0.22"\nbytes = "1"\n'
                'futures-core = "0.3"\nhttp = "1"\nhyper = "1"\nserde = "1"\nserde_json = "1"\ntokio = "1"\n'
                'url = "2.4"\nrustls = { version = "0.23", optional = true }\n')
        self.assertEqual(typos(scan_crate({"Cargo.toml": toml}, name="reqwest", version="0.12.9")), [])


class PopularNamesScriptTests(unittest.TestCase):
    """scripts/update-popular-names.py's Go list, on small copies of its sources."""

    def setUp(self):
        self.script = _support.load_script(POPULAR_SCRIPT, "update_popular_names_for_tests")

    def test_awesome_go_entries(self):
        readme = ("# Awesome Go\n\n- [Contents](#contents)\n- [awesome](https://github.com/sindresorhus/awesome)\n\n"
                  "## Contents\n\n- [Actors](#actors)\n\n## Actors\n\n"
                  "- [Ergo](https://github.com/Ergo-Services/ergo) - Actors. See [x](https://github.com/a/b).\n"
                  "- [sub](https://github.com/pancsta/asyncmachine-go/tree/main/pkg/machine) - A subdirectory.\n"
                  "  - [nested](https://gitlab.com/tozd/go/fun/-/blob/main/README.md) - GitLab groups.\n"
                  "- [pkg](https://pkg.go.dev/golang.org/x/crypto/acme/autocert) - pkg.go.dev.\n"
                  "- [site](https://example.com/tool) - Not a repository.\n"
                  "- [git](https://github.com/owner/repo.git) - .git.\n\n"
                  "## Editor Plugins\n\n- [vim-go](https://github.com/fatih/vim-go) - Vim.\n\n"
                  "# Resources\n\n## Books\n\n- [book](https://github.com/x/book) - A book.\n")
        self.assertEqual(self.script.awesome_go_paths(readme), [
            "github.com/Ergo-Services/ergo", "github.com/pancsta/asyncmachine-go", "gitlab.com/tozd/go/fun",
            "golang.org/x/crypto/acme/autocert", "github.com/owner/repo"])

    def test_ubuntu_go_import_paths(self):
        sources = ("Package: golang-check.v1\nGo-Import-Path: gopkg.in/check.v1,\n launchpad.net/gocheck\n"
                   "Version: 1\n\nPackage: hello\nVersion: 2\n\nPackage: etcd\nGo-Import-Path: go.etcd.io/etcd, "
                   "github.com/coreos/etcd\n")
        self.assertEqual(self.script.ubuntu_go_paths(sources), [
            "gopkg.in/check.v1", "launchpad.net/gocheck", "go.etcd.io/etcd", "github.com/coreos/etcd"])

    def test_the_crates_section(self):
        def page(path, names):
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"crates": [{"name": n} for n in names], "meta": {}}, f)

        with tempfile.TemporaryDirectory() as d:
            page(os.path.join(d, "recent-0001.json"), ["Proc-Macro2", "serde_json", "tokio"])
            page(os.path.join(d, "recent-0002.json"), ["tokyo", "serde-json"])
            page(os.path.join(d, "alltime-0001.json"), ["proc-macro1x", "serde-jsom", "tokio"])
            index = os.path.join(d, "Sources.xz")
            with open(index, "wb") as f:
                f.write(lzma.compress(b"Package: rust-proc-macro3\nBinary: librust-proc-macro3-dev\n\n"
                                      b"Package: golang-x\nGo-Import-Path: example.com/x\n"))
            with unittest.mock.patch.object(self.script, "TARGETS", 3):
                sec = self.script.crates_section(d, [index])["crates"]
                without = self.script.crates_section(d)["crates"]
        # ranked as the recent pages list them, crates.io's one name each; known: tokyo (recent), serde-jsom (all
        # time), proc-macro3 (Debian's), each one change from a target
        self.assertEqual(sec["targets"], ["proc-macro2", "serde-json", "tokio"])
        self.assertEqual(sec["known"], ["proc-macro3", "serde-jsom", "tokyo"])
        self.assertEqual(without["known"], ["serde-jsom", "tokyo"])
        self.assertIn("2 and 1 pages", sec["source"])
        self.assertIn("rust-*", sec["source"])

    def test_the_go_section(self):
        with tempfile.TemporaryDirectory() as d:
            readme, index = os.path.join(d, "README.md"), os.path.join(d, "Sources.xz")
            with open(readme, "w", encoding="utf-8") as f:
                f.write("## Numbers\n\n- [decimal](https://github.com/ShopSpring/decimal) - Decimals.\n")
            with open(index, "wb") as f:
                f.write(lzma.compress(b"Package: a\nGo-Import-Path: github.com/go-redis/redis/v8\n\n"
                                      b"Package: b\nGo-Import-Path: github.com/shopspring/decimal\n"))
            sec = self.script.go_section(readme, [index])["go"]
        self.assertEqual(sec["targets"], ["github.com/go-redis/redis", "github.com/shopspring/decimal"])
        self.assertIn("awesome-go", sec["source"])
        self.assertEqual(sec["copyright"], "Copyright (c) 2014 Thiago Avelino")


if __name__ == "__main__":
    unittest.main()
