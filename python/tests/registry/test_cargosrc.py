"""registry/cargosrc.py: what the Cargo guard reads of Cargo's configuration, of Cargo.lock and of a registry. Nothing is fetched."""

import hashlib
import os
import shutil
import tempfile
import unittest

from lazaret.registry import cargosrc
from tests.registry import _cargo_support as cs

HEX = "ab" * 32


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lazaret-cargosrc-")
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)


class SourcesTests(TmpCase):
    def test_the_nearest_configuration_wins_key_by_key(self):
        home = os.path.join(self.tmp, "home")
        work = os.path.join(self.tmp, "a", "b")
        write(os.path.join(home, "config.toml"), '[source.crates-io]\nreplace-with = "far"\n[source.far]\nregistry = "sparse+https://far/"\n')
        write(os.path.join(self.tmp, "a", ".cargo", "config.toml"), '[source.far]\nregistry = "sparse+https://middle/"\n')
        write(os.path.join(work, ".cargo", "config.toml"), '[source.near]\ndirectory = "vendor"\n')
        table = cargosrc.sources(work, {"CARGO_HOME": home})
        self.assertEqual(table["crates-io"], {"replace-with": "far"})
        self.assertEqual(table["far"], {"registry": "sparse+https://middle/"})           # (a folder nearer overrides the home's)
        self.assertEqual(table["near"], {"directory": "vendor"})

    def test_the_older_name_wins_over_config_toml_in_one_folder_as_cargo_reads_them(self):
        # (cargo warns "both … exist. Using …/config" and reads that one only; the guard read config.toml over it, so it
        # checked crates.io's bytes while cargo built a replacement's: the Go/Rust review's CG-6)
        write(os.path.join(self.tmp, ".cargo", "config"), '[source.x]\nregistry = "sparse+https://old/"\n')
        write(os.path.join(self.tmp, ".cargo", "config.toml"), '[source.x]\nregistry = "sparse+https://new/"\n[source.y]\ndirectory = "v"\n')
        got = cargosrc.sources(self.tmp, {"CARGO_HOME": os.path.join(self.tmp, "none")})
        self.assertEqual(got, {"x": {"registry": "sparse+https://old/"}})

    def test_an_included_file_is_read_before_the_file_that_includes_it(self):
        write(os.path.join(self.tmp, ".cargo", "config.toml"),
              'include = ["more.toml", {path = "most.toml"}]\n[source.crates-io]\nreplace-with = "mine"\n')
        write(os.path.join(self.tmp, ".cargo", "more.toml"),
              '[source.crates-io]\nreplace-with = "theirs"\n[source.mine]\nregistry = "sparse+https://mine/"\n')
        write(os.path.join(self.tmp, ".cargo", "most.toml"), '[source.vendored]\ndirectory = "vendor"\n')
        got = cargosrc.sources(self.tmp, {"CARGO_HOME": os.path.join(self.tmp, "none")})
        self.assertEqual(got["crates-io"], {"replace-with": "mine"})             # (the including file's own value wins)
        self.assertEqual(got["vendored"], {"directory": "vendor"})
        self.assertEqual(cargosrc.registry_of(got), cargosrc.Registry("sparse", "https://mine/"))

    def test_includes_that_loop_or_go_on_and_on_are_read_once(self):
        write(os.path.join(self.tmp, ".cargo", "config.toml"), 'include = "a.toml"\n[source.x]\ndirectory = "d"\n')
        write(os.path.join(self.tmp, ".cargo", "a.toml"), 'include = ["config.toml", "a.toml"]\n[source.a]\ndirectory = "a"\n')
        got = cargosrc.sources(self.tmp, {"CARGO_HOME": os.path.join(self.tmp, "none")})
        self.assertEqual(set(got), {"x", "a"})

    def test_a_config_option_wins_over_every_file(self):
        write(os.path.join(self.tmp, ".cargo", "config.toml"), '[source.crates-io]\nreplace-with = "mine"\n')
        write(os.path.join(self.tmp, "extra.toml"), '[source.vendored]\ndirectory = "vendor"\n')
        got = cargosrc.config(self.tmp, {"CARGO_HOME": os.path.join(self.tmp, "none")},
                              ['source.crates-io.replace-with = "vendored"', "extra.toml"])["source"]
        self.assertEqual(got["crates-io"], {"replace-with": "vendored"})
        self.assertEqual(cargosrc.registry_of(got), cargosrc.Registry("directory", "vendor"))

    def test_a_replacement_by_a_registry_is_followed(self):
        # (`replace-with` may name a registry of [registries], or one an environment variable gives; the guard called it
        # unknown and checked nothing while cargo used it: the Go/Rust review's CG-4)
        write(os.path.join(self.tmp, ".cargo", "config.toml"),
              '[registries.corp]\nindex = "sparse+https://corp.example/index/"\n[source.crates-io]\nreplace-with = "corp"\n')
        conf = cargosrc.config(self.tmp, {"CARGO_HOME": os.path.join(self.tmp, "none")})
        self.assertEqual(cargosrc.registry_of(conf["source"], conf["registries"]),
                         cargosrc.Registry("sparse", "https://corp.example/index/"))
        self.assertEqual(cargosrc.registry_of({"crates-io": {"replace-with": "my-reg"}}, {},
                                              {"CARGO_REGISTRIES_MY_REG_INDEX": "https://git.example/index"}),
                         cargosrc.Registry("git", "https://git.example/index"))
        self.assertEqual(cargosrc.registry_of({"crates-io": {"replace-with": "nobody"}}, {}, {}),
                         cargosrc.Registry("unknown", "nobody"))

    def test_a_file_that_is_missing_too_large_or_not_toml_says_nothing(self):
        home = os.path.join(self.tmp, "home")
        env = {"CARGO_HOME": home}
        self.assertEqual(cargosrc.sources(self.tmp, env), {})
        write(os.path.join(home, "config.toml"), "[source\nbroken")
        self.assertEqual(cargosrc.sources(self.tmp, env), {})
        big = '[source.x]\nregistry = "sparse+https://big/"\n'
        write(os.path.join(home, "config.toml"), big + "# " + "x" * cargosrc.MAX_CONFIG_BYTES)
        self.assertEqual(cargosrc.sources(self.tmp, env), {})
        write(os.path.join(home, "config.toml"), big + "# " + "x" * (cargosrc.MAX_CONFIG_BYTES - len(big) - 2))   # (exactly the limit)
        self.assertEqual(cargosrc.sources(self.tmp, env), {"x": {"registry": "sparse+https://big/"}})

    def test_values_that_are_not_text_are_left_out(self):
        write(os.path.join(self.tmp, ".cargo", "config.toml"), '[source.x]\nregistry = 5\ndirectory = "d"\n[source.y]\nregistry = "r"\n')
        self.assertEqual(cargosrc.sources(self.tmp, {"CARGO_HOME": os.path.join(self.tmp, "none")}),
                         {"x": {"directory": "d"}, "y": {"registry": "r"}})
        write(os.path.join(self.tmp, ".cargo", "config.toml"), '[source]\nx = "text"\ny = 5\n')                # (a source that is not a table)
        self.assertEqual(cargosrc.sources(self.tmp, {"CARGO_HOME": os.path.join(self.tmp, "none")}), {})

    def test_the_home_is_cargo_home_or_dot_cargo(self):
        self.assertEqual(cargosrc.cargo_home({"CARGO_HOME": "/x/y"}), "/x/y")
        self.assertEqual(cargosrc.cargo_home({}), os.path.join(os.path.expanduser("~"), ".cargo"))
        self.assertEqual(cargosrc.cargo_home({"CARGO_HOME": ""}), os.path.join(os.path.expanduser("~"), ".cargo"))
        self.assertEqual(cargosrc.cargo_home(None), os.path.join(os.path.expanduser("~"), ".cargo"))


class RegistryTests(unittest.TestCase):
    def test_crates_io_by_default(self):
        self.assertEqual(cargosrc.registry_of({}), ("sparse", "https://index.crates.io/"))
        self.assertEqual(cargosrc.registry_of({"crates-io": {}}), ("sparse", cargosrc.DEFAULT_INDEX))

    def test_a_mirror_with_a_sparse_index(self):
        table = {"crates-io": {"replace-with": "m"}, "m": {"registry": "sparse+https://mirror.example/index"}}
        self.assertEqual(cargosrc.registry_of(table), ("sparse", "https://mirror.example/index/"))
        table["m"]["registry"] = "sparse+https://mirror.example/index/"
        self.assertEqual(cargosrc.registry_of(table), ("sparse", "https://mirror.example/index/"))

    def test_replacement_is_followed_through_several_sources(self):
        table = {"crates-io": {"replace-with": "a"}, "a": {"replace-with": "b"}, "b": {"registry": "sparse+http://h:1/"}}
        self.assertEqual(cargosrc.registry_of(table), ("sparse", "http://h:1/"))

    def test_crates_ios_own_git_index_is_crates_io(self):
        for url in ("https://github.com/rust-lang/crates.io-index", "https://github.com/rust-lang/crates.io-index/"):
            table = {"crates-io": {"replace-with": "m"}, "m": {"registry": url}}
            self.assertEqual(cargosrc.registry_of(table), ("sparse", cargosrc.DEFAULT_INDEX))

    def test_what_the_guard_cannot_read(self):
        git = {"crates-io": {"replace-with": "m"}, "m": {"registry": "https://git.example/index"}}
        self.assertEqual(cargosrc.registry_of(git), ("git", "https://git.example/index"))
        for key, kind in (("directory", "directory"), ("local-registry", "local-registry"), ("git", "git-source")):
            table = {"crates-io": {"replace-with": "v"}, "v": {key: "somewhere"}}
            self.assertEqual(cargosrc.registry_of(table), (kind, "somewhere"))
        self.assertEqual(cargosrc.registry_of({"crates-io": {"replace-with": "nowhere"}}), ("unknown", "nowhere"))
        self.assertEqual(cargosrc.registry_of({"crates-io": {"replace-with": "v"}, "v": {}}), ("unknown", "v"))

    def test_a_loop_is_unknown(self):
        table = {"crates-io": {"replace-with": "a"}, "a": {"replace-with": "crates-io"}}
        self.assertEqual(cargosrc.registry_of(table).kind, "unknown")
        self.assertEqual(cargosrc.registry_of({"crates-io": {"replace-with": "a"}, "a": {"replace-with": "a"}}).kind, "unknown")


class ClassifyTests(unittest.TestCase):
    def test_sources_of_a_lock(self):
        for text, want in (
                (None, ("path", "")), ("", ("path", "")), (5, ("path", "")),
                ("registry+https://github.com/rust-lang/crates.io-index", ("crates-io", "https://github.com/rust-lang/crates.io-index")),
                ("sparse+https://index.crates.io/", ("crates-io", "https://index.crates.io/")),
                ("sparse+https://index.crates.io", ("crates-io", "https://index.crates.io")),
                ("sparse+https://mirror.example/idx", ("sparse", "https://mirror.example/idx/")),
                ("sparse+https://mirror.example/idx/", ("sparse", "https://mirror.example/idx/")),
                ("registry+https://git.example/index", ("git-index", "https://git.example/index")),
                ("git+https://github.com/x/y?tag=v1#abc", ("git", "https://github.com/x/y?tag=v1#abc")),
                ("something-else", ("other", "something-else"))):
            with self.subTest(text):
                self.assertEqual(cargosrc.classify(text), want)


LOCK = f'''version = 4

[[package]]
name = "app"
version = "0.1.0"
dependencies = ["good"]

[[package]]
name = "good"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{HEX}"

[[package]]
name = "gitdep"
version = "0.3.0"
source = "git+https://github.com/x/y#abc"

[[package]]
name = "Shout"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "{HEX.upper()}"
'''


class LockTests(unittest.TestCase):
    def test_a_lock_is_read_in_order(self):
        pkgs = cargosrc.parse_lock(LOCK)
        self.assertEqual([(p.name, p.version, p.source) for p in pkgs],
                         [("app", "0.1.0", ""), ("good", "1.0.0", cs.CRATES_IO), ("gitdep", "0.3.0", "git+https://github.com/x/y#abc"),
                          ("Shout", "2.0.0", cs.CRATES_IO)])
        self.assertEqual([p.checksum for p in pkgs], [None, HEX, None, HEX])         # (lowercase)

    def test_a_checksum_that_is_not_a_sha256_is_none(self):
        for bad in ("abc", "g" * 64, "ab" * 33, ""):
            with self.subTest(bad):
                text = f'[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "{cs.CRATES_IO}"\nchecksum = "{bad}"\n'
                self.assertIsNone(cargosrc.parse_lock(text)[0].checksum)
        self.assertEqual(cargosrc.parse_lock(f'[[package]]\nname = "a"\nversion = "1.0.0"\nchecksum = 5\n')[0].checksum, None)

    def test_an_old_lock_keeps_its_checksums_in_metadata(self):
        text = (f'[[package]]\nname = "a"\nversion = "1.0.0"\nsource = "{cs.CRATES_IO}"\n\n[metadata]\n'
                f'"checksum a 1.0.0 ({cs.CRATES_IO})" = "{HEX}"\n"checksum b 1.0.0 ({cs.CRATES_IO})" = "{"cd" * 32}"\n'
                f'"other key" = "{HEX}"\n"checksum a 2.0.0 ({cs.CRATES_IO})" = 5\n')
        (pkg,) = cargosrc.parse_lock(text)
        self.assertEqual(pkg.checksum, HEX)

    def test_a_package_that_is_not_one_is_skipped(self):
        text = '[[package]]\nname = "a"\n[[package]]\nversion = "1.0.0"\n[[package]]\nname = 5\nversion = "1.0.0"\n[[package]]\nname = "ok"\nversion = "1.0.0"\n'
        self.assertEqual([p.name for p in cargosrc.parse_lock(text)], ["ok"])
        self.assertEqual(cargosrc.parse_lock("version = 4\n"), [])
        self.assertEqual(cargosrc.parse_lock('package = [1, "x", {name = "a", version = "1.0.0"}]\n')[0].name, "a")

    def test_what_is_not_a_lock_is_a_value_error(self):
        for bad in ("[[package", 'package = "x"\n', 'package = 5\n', None, b"x", "\x00"):
            with self.subTest(bad), self.assertRaises(ValueError):
                cargosrc.parse_lock(bad)

    def test_the_limits_are_the_documented_ones(self):
        self.assertEqual((cargosrc.MAX_CONFIG_BYTES, cargosrc.MAX_LOCK_BYTES, cargosrc.MAX_PACKAGES), (256 * 1024, 32 * 1024 * 1024, 5000))

    def test_the_limits_are_exact(self):
        one = '[[package]]\nname = "a"\nversion = "1.0.0"\n'
        self.assertEqual(len(cargosrc.parse_lock(one * cargosrc.MAX_PACKAGES)), cargosrc.MAX_PACKAGES)
        with self.assertRaises(ValueError):
            cargosrc.parse_lock(one * (cargosrc.MAX_PACKAGES + 1))
        pad = "#" * (cargosrc.MAX_LOCK_BYTES - len(one))
        self.assertEqual(len(cargosrc.parse_lock(one + pad)), 1)
        with self.assertRaises(ValueError):
            cargosrc.parse_lock(one + pad + "#")


class NamesTests(unittest.TestCase):
    def test_names_and_versions_that_may_reach_a_url(self):
        for name, version in (("serde", "1.0.200"), ("foo_bar", "0.1.0-alpha.1"), ("a", "1.0.0+build.5"), ("Foo-9", "10.20.30")):
            self.assertTrue(cargosrc.crate_ok(name, version), (name, version))
        for name, version in (("", "1.0.0"), ("a/b", "1.0.0"), ("a b", "1.0.0"), ("..", "1.0.0"), ("-a", "1.0.0"), ("é", "1.0.0"),
                              ("a" * 65, "1.0.0"), ("a", "1.0"), ("a", "1.0.0/../x"), ("a", "v1.0.0"), ("a", ""), ("a", None),
                              ("a", "1" * 100 + ".0.0"), (5, "1.0.0"), (None, "1.0.0")):
            self.assertIs(cargosrc.crate_ok(name, version), False, (name, version))
        self.assertTrue(cargosrc.crate_ok("a" * 64, "1.0.0"))

    def test_the_longest_version_is_ok_and_one_more_is_not(self):
        longest = "1.0.0-" + "a" * (100 - len("1.0.0-"))
        self.assertTrue(cargosrc.crate_ok("a", longest))
        self.assertFalse(cargosrc.crate_ok("a", longest + "a"))


class UrlTests(unittest.TestCase):
    def test_prefixes(self):
        for name, want in (("a", "1"), ("ab", "2"), ("abc", "3/a"), ("abcd", "ab/cd"), ("Cargo", "Ca/rg"), ("serde", "se/rd")):
            self.assertEqual(cargosrc.prefix(name), want)

    def test_the_index_file_of_a_crate(self):
        self.assertEqual(cargosrc.index_url("https://i.example/", "Serde"), "https://i.example/se/rd/serde")
        self.assertEqual(cargosrc.index_url("http://h:1/x/", "ab"), "http://h:1/x/2/ab")

    def test_download_urls(self):
        sums = hashlib.sha256(b"x").hexdigest()
        self.assertEqual(cargosrc.download_url("https://s.example/crates/{crate}/{crate}-{version}.crate", "serde", "1.0.0"),
                         "https://s.example/crates/serde/serde-1.0.0.crate")
        self.assertEqual(cargosrc.download_url("https://s.example/{prefix}/{crate}/{version}", "Serde", "1.0.0"),
                         "https://s.example/Se/rd/Serde/1.0.0")
        self.assertEqual(cargosrc.download_url("https://s.example/{lowerprefix}/{crate}", "Serde", "1.0.0"), "https://s.example/se/rd/Serde")
        self.assertEqual(cargosrc.download_url("https://s.example/{sha256-checksum}.crate", "a", "1.0.0", sums),
                         f"https://s.example/{sums}.crate")
        self.assertEqual(cargosrc.download_url("https://s.example/dl", "serde", "1.0.0"), "https://s.example/dl/serde/1.0.0/download")
        with self.assertRaises(ValueError):
            cargosrc.download_url("https://s.example/{sha256-checksum}", "a", "1.0.0")
        with self.assertRaises(ValueError):
            cargosrc.download_url("https://s.example/{sha256-checksum}", "a", "1.0.0", "")


class IndexRecordTests(unittest.TestCase):
    TEXT = ('{"name":"a","vers":"1.0.0","cksum":"' + HEX + '","yanked":false,"pubtime":"2025-11-12T19:30:12Z"}\n'
            '\n'
            'not json 1.1.0\n'
            '{"name":"a","vers":"1.1.0","cksum":"' + HEX.upper() + '","yanked":true}\n'
            '{"name":"a","vers":"1.2.0","cksum":"short","yanked":"yes","pubtime":"yesterday"}\n'
            '[1.3.0]\n'
            '{"name":"a","vers":"1.4.0-1.0.0","cksum":"' + HEX + '"}\n')

    def test_a_line_by_its_version(self):
        self.assertEqual(cargosrc.index_record(self.TEXT, "1.0.0"), {"cksum": HEX, "yanked": False, "pubtime": "2025-11-12T19:30:12Z"})
        self.assertEqual(cargosrc.index_record(self.TEXT, "1.1.0"), {"cksum": HEX, "yanked": True, "pubtime": None})
        self.assertEqual(cargosrc.index_record(self.TEXT, "1.2.0"), {"cksum": None, "yanked": False, "pubtime": None})

    def test_a_version_the_file_does_not_list(self):
        self.assertIsNone(cargosrc.index_record(self.TEXT, "9.9.9"))
        self.assertIsNone(cargosrc.index_record(self.TEXT, "1.3.0"))           # (the text is there, in a line that is not a record)
        self.assertIsNone(cargosrc.index_record(self.TEXT, "1.0"))
        self.assertIsNone(cargosrc.index_record("", "1.0.0"))
        self.assertEqual(cargosrc.index_record(self.TEXT, "1.4.0-1.0.0")["cksum"], HEX)           # (1.0.0 is in that line too, but it is not its version)

    def test_a_pubtime_must_have_the_documented_form(self):
        for bad in ("2025-11-12T19:30:12", "2025-11-12 19:30:12Z", "2025-11-12T19:30:12.5Z", "2025-11-12T19:30:12+00:00", ""):
            line = '{"vers":"1.0.0","pubtime":"%s"}' % bad
            self.assertIsNone(cargosrc.index_record(line, "1.0.0")["pubtime"], bad)


class InstallArgumentTests(unittest.TestCase):
    def three(self, args):
        got = cargosrc.parse_install(args)
        return got.crates, got.locked, got.offline

    def test_a_crate_a_version_and_the_options_that_matter(self):
        self.assertEqual(self.three(["ripgrep"]), ([("ripgrep", None)], False, False))
        self.assertEqual(self.three(["--locked", "ripgrep"]), ([("ripgrep", None)], True, False))
        self.assertEqual(self.three(["--frozen", "x"]), ([("x", None)], True, True))
        self.assertEqual(self.three(["--offline", "x"]), ([("x", None)], False, True))
        self.assertEqual(cargosrc.parse_install(["a", "b"]).crates, [("a", None), ("b", None)])

    def test_vers_is_cargos_other_name_for_version(self):
        # (the guard read no version from it and checked the newest release, while cargo installed the one asked for: CG-2)
        self.assertEqual(cargosrc.parse_install(["--vers", "1.0.0", "a"]).crates, [("a", "=1.0.0")])
        self.assertEqual(cargosrc.parse_install(["--vers=1.2", "a"]).crates, [("a", "1.2")])

    def test_an_option_the_guard_does_not_know_is_refused(self):
        # (it could take a value, which would then be read as a crate, or not)
        for args in (["--frobnicate", "a"], ["-fq", "a"], ["--git-fetch-with-cli", "a"]):
            with self.subTest(args), self.assertRaisesRegex(ValueError, "not an option the guard knows"):
                cargosrc.parse_install(args)
        self.assertEqual(cargosrc.parse_install(["-vv", "--timings=html", "-j4", "-Fx", "--bin", "--locked", "a"]).crates,
                         [("a", None)])

    def test_each_crate_is_pinned_to_the_version_checked(self):
        for args, pinned in ((["ripgrep"], ["ripgrep@=14.1.1"]),
                             (["--version", "14", "--locked", "ripgrep"], ["--locked", "ripgrep@=14.1.1"]),
                             (["--vers=14", "ripgrep", "--root", "/r"], ["ripgrep@=14.1.1", "--root", "/r"]),
                             (["ripgrep@^14", "-F", "pcre2"], ["ripgrep@=14.1.1", "-F", "pcre2"])):
            with self.subTest(args):
                want = cargosrc.parse_install(args)
                self.assertEqual(cargosrc.pinned_install(args, want, [("ripgrep", "14.1.1")]), pinned)
        want = cargosrc.parse_install(["a", "--", "b"])
        self.assertEqual(want.crates, [("a", None), ("b", None)])                     # (after `--` every argument is a crate)
        self.assertEqual(cargosrc.pinned_install(["a", "--", "b"], want, [("a", "1.0.0"), ("b", "2.0.0")]),
                         ["a@=1.0.0", "--", "b@=2.0.0"])

    def test_config_values_are_kept(self):
        self.assertEqual(cargosrc.parse_install(["--config", "k=1", "--config=other.toml", "a"]).configs, ["k=1", "other.toml"])

    def test_versions_three_numbers_are_exact_and_anything_else_a_requirement(self):
        self.assertEqual(cargosrc.parse_install(["a@1.2.3"]).crates, [("a", "=1.2.3")])
        self.assertEqual(cargosrc.parse_install(["a@1.2.3-rc.1+b5"]).crates, [("a", "=1.2.3-rc.1+b5")])
        self.assertEqual(cargosrc.parse_install(["a@^1.2"]).crates, [("a", "^1.2")])
        self.assertEqual(cargosrc.parse_install(["a@~1"]).crates, [("a", "~1")])
        self.assertEqual(cargosrc.parse_install(["a@>=1, <2"]).crates, [("a", ">=1, <2")])
        self.assertEqual(cargosrc.parse_install(["--version", "1.2.3", "a"]).crates, [("a", "=1.2.3")])
        self.assertEqual(cargosrc.parse_install(["--version=1.2", "a"]).crates, [("a", "1.2")])

    def test_options_with_values_do_not_take_a_crate_s_place(self):
        got = cargosrc.parse_install(["--features", "x,y", "-F", "z", "--bin", "b", "--root", "/r", "--target", "t", "-j", "4",
                                      "--profile", "release", "--config", "k=v", "a", "--locked", "--force", "-q"])
        self.assertEqual((got.crates, got.locked, got.offline), ([("a", None)], True, False))

    def test_after_two_dashes_every_argument_is_a_crate(self):
        # (cargo reads them so: the guard stopped reading there, and cargo installed a crate it never checked)
        self.assertEqual(cargosrc.parse_install(["a", "--", "b"]).crates, [("a", None), ("b", None)])
        with self.assertRaisesRegex(ValueError, "not a crate name"):
            cargosrc.parse_install(["a", "--", "--git"])

    def test_what_the_guard_does_not_read(self):
        for args in (["--git", "https://x/y", "a"], ["--git=https://x/y"], ["--path", "."], ["--path=."], ["--list"], ["--index", "u", "a"],
                     ["--registry", "r", "a"], [], ["--locked"], ["--version"], ["--features"], ["a", "b", "--version", "1.0.0"],
                     ["a@1.0.0", "--version", "1.0.0"], ["a@"], ["@1.0.0"], ["a/b"], ["a@1\n2"], ["a@" + "1" * 101], ["a@;rm"], ["é"]):
            with self.subTest(args), self.assertRaises(ValueError):
                cargosrc.parse_install(args)

    def test_a_crate_that_cannot_be_read_says_so(self):
        for spec in ("a@", "@1.0.0"):
            with self.subTest(spec), self.assertRaisesRegex(ValueError, "cannot read"):
                cargosrc.parse_install([spec])

    def test_what_is_quoted_in_a_message_is_cut_short(self):
        for args, text, kept in ((["a@" + ";" * 100], ";", 40), (["x" * 70 + "@"], "x", 60), (["é" * 70], "é", 60)):
            with self.subTest(args), self.assertRaises(ValueError) as caught:
                cargosrc.parse_install(args)
            self.assertIn(text * kept, str(caught.exception))
            self.assertNotIn(text * (kept + 1), str(caught.exception))

    def test_the_longest_requirement_is_read_and_one_more_is_not(self):
        self.assertEqual(cargosrc.parse_install(["a@^" + "1" * 99]).crates, [("a", "^" + "1" * 99)])
        with self.assertRaises(ValueError):
            cargosrc.parse_install(["a@^" + "1" * 100])


class ProjectArgumentTests(unittest.TestCase):
    def test_the_options_that_matter(self):
        self.assertEqual(cargosrc.parse_project(["--release"]), (None, False, False, []))
        self.assertEqual(cargosrc.parse_project(["--manifest-path", "x/Cargo.toml", "--locked"]), ("x/Cargo.toml", True, False, []))
        self.assertEqual(cargosrc.parse_project(["--manifest-path=y/Cargo.toml", "--offline"]), ("y/Cargo.toml", False, True, []))
        self.assertEqual(cargosrc.parse_project(["--frozen"]), (None, True, True, []))
        self.assertEqual(cargosrc.parse_project(["--config", "a=1", "--config=b.toml"]), (None, False, False, ["a=1", "b.toml"]))

    def test_what_comes_after_two_dashes_is_the_programs(self):
        self.assertEqual(cargosrc.parse_project(["--locked", "--", "--offline", "--manifest-path", "z", "--config", "x"]),
                         (None, True, False, []))

    def test_a_manifest_path_with_no_value_is_none(self):
        self.assertEqual(cargosrc.parse_project(["--manifest-path"]), (None, False, False, []))


class CargoFolderTests(TmpCase):
    def test_the_unpacked_crates(self):
        home = os.path.join(self.tmp, "home")
        self.assertEqual(cargosrc.crate_dirs(home), set())
        for d in ("registry/src/idx-a/foo-1.0.0", "registry/src/idx-a/bar-2.0.0", "registry/src/idx-b/foo-1.0.0"):
            os.makedirs(os.path.join(home, d))
        write(os.path.join(home, "registry", "src", "idx-a", "stray-file.txt"), "x")
        self.assertEqual(cargosrc.crate_dirs(home), {"foo-1.0.0", "bar-2.0.0"})

    def test_a_crate_cargo_holds_if_its_bytes_are_the_ones_asked_for(self):
        home = os.path.join(self.tmp, "home")
        data = cs.crate_tgz("foo", "1.0.0", {})
        digest = hashlib.sha256(data).hexdigest()
        self.assertIsNone(cargosrc.cached_crate(home, "foo", "1.0.0", digest))
        with open(os.path.join(home, "registry", "cache", "idx-a", "foo-1.0.0.crate"), "wb") if os.makedirs(
                os.path.join(home, "registry", "cache", "idx-a")) is None else None as f:
            f.write(b"not the crate")
        self.assertIsNone(cargosrc.cached_crate(home, "foo", "1.0.0", digest))               # (other bytes under that name)
        os.makedirs(os.path.join(home, "registry", "cache", "idx-b"))
        with open(os.path.join(home, "registry", "cache", "idx-b", "foo-1.0.0.crate"), "wb") as f:
            f.write(data)
        self.assertEqual(cargosrc.cached_crate(home, "foo", "1.0.0", digest), data)
        self.assertIsNone(cargosrc.cached_crate(home, "foo", "1.0.1", digest))

    def test_a_crate_file_of_more_than_64_mib_is_not_read(self):
        home = os.path.join(self.tmp, "home")
        folder = os.path.join(home, "registry", "cache", "idx-a")
        os.makedirs(folder)
        limit = 64 * 1024 * 1024
        digests = {}
        for name, size in (("exact", limit), ("over", limit + 1)):
            with open(os.path.join(folder, f"{name}-1.0.0.crate"), "wb") as f:
                f.truncate(size)                                                    # (a sparse file of zeros)
            digests[name] = hashlib.sha256(bytes(size)).hexdigest()
        self.assertEqual(len(cargosrc.cached_crate(home, "exact", "1.0.0", digests["exact"])), limit)
        self.assertIsNone(cargosrc.cached_crate(home, "over", "1.0.0", digests["over"]))
        self.assertIsNone(cargosrc.cached_crate(home, "foo", "1.0.0", HEX))


if __name__ == "__main__":
    unittest.main()
