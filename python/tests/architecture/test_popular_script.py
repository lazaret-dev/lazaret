"""scripts/popular (B-2): the release gate's second benign set, the popular releases pinned by version and sha256.

The pinned file is checked as it is in the tree (valid, and holding the nine popular releases 0.1.8 made
SUSPICIOUS, at the versions the sweep found them). Resolving, pinning and fetching run against a stand-in for
the registries: nothing here goes on the network."""

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
import urllib.error

from tests import _support

POPULAR = os.path.join(_support.REPO_ROOT, "scripts", "popular")
pop = _support.load_script(os.path.join(POPULAR, "popular.py"), "popular_set")

NPM_FILES = "https://registry.npmjs.org/"
PY_FILES = "https://files.pythonhosted.org/packages/ab/cd/"


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Registry:
    """A stand-in for urllib's urlopen: {url: bytes}, and the URLs asked for in order."""

    def __init__(self, pages):
        self.pages, self.asked = dict(pages), []

    def __call__(self, req, timeout=None):
        url = req.full_url
        self.asked.append(url)
        if url not in self.pages:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        return contextlib.closing(io.BytesIO(self.pages[url]))


def row(eco="npm", name="left-pad", version="1.3.0", data=b"tarball", **over):
    if eco == "npm":
        filename = f"{name.rsplit('/', 1)[-1]}-{version}.tgz"
        url, ck = f"{NPM_FILES}{name}/-/{filename}", ("tgz", "npm")
    else:
        filename = f"{name}-{version}-py3-none-any.whl"
        url, ck = PY_FILES + filename, ("zip", "wheel")
    r = {"id": f"{eco}:{name}@{version}", "ecosystem": eco, "name": name, "version": version, "filename": filename,
         "url": url, "container": ck[0], "kind": ck[1], "sha256": sha(data), "bytes": len(data)}
    r.update(over)
    return r


class PinnedFileTests(unittest.TestCase):
    def test_the_pinned_file_is_valid(self):
        rows = pop.read_releases()
        self.assertEqual(pop.validate(rows), [])
        ecos = [r["ecosystem"] for r in rows]
        self.assertGreater(ecos.count("npm"), 700)
        self.assertGreater(ecos.count("pypi"), 350)

    def test_it_holds_the_releases_0_1_8_made_suspicious(self):
        ids = {r["id"] for r in pop.read_releases()}
        for rid in ("npm:vite@8.3.2", "npm:vitest@5.0.3", "npm:monaco-editor@0.57.0", "pypi:coverage@7.16.2",
                    "pypi:numba@0.68.0", "pypi:future@1.0.0", "pypi:sympy@1.14.0", "pypi:ipython@9.17.1",
                    "pypi:kubernetes@36.0.3"):
            self.assertIn(rid, ids)

    def test_check_command(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.jsonl")
            pop.write_releases([row(), row("pypi", "six", "1.17.0")], path)
            self.assertEqual(pop.main(["--releases", path, "check"]), pop.EXIT_OK)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(row(sha256="0" * 63)) + "\n")
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(pop.main(["--releases", path, "check"]), pop.EXIT_INVALID)

    def test_written_sorted_with_its_fields_only(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "r.jsonl")
            pop.write_releases([row(name="zz"), dict(row(name="aa"), extra=1)], path)
            rows = pop.read_releases(path)
        self.assertEqual([r["name"] for r in rows], ["aa", "zz"])
        self.assertEqual(list(rows[0]), list(pop.FIELDS))


class ValidateTests(unittest.TestCase):
    def problems(self, *rows):
        return pop.validate(list(rows))

    def test_each_kind_of_problem(self):
        cases = {
            "pinned twice": [row(), row()],
            "the id is not": [row(id="npm:left-pad@9")],
            "sha256 is not": [row(sha256="ABC")],
            "bytes must be": [row(bytes=0)],
            "the url is not https": [row(url="http://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz")],
            "does not end in the filename": [row(url=NPM_FILES + "left-pad/-/other-1.3.0.tgz")],
            "container and kind": [row(kind="sdist")],
            "unknown ecosystem": [row(ecosystem="gem")],
            "missing": [{k: v for k, v in row().items() if k != "url"}],
            "not an object": [["npm:x@1"]],
        }
        for text, rows in cases.items():
            with self.subTest(text=text):
                problems = pop.validate(rows)
                self.assertTrue(problems and all(text in p for p in problems[-1:]), problems)

    def test_a_file_from_another_host_is_refused(self):
        other = row(url="https://evil.invalid/left-pad-1.3.0.tgz")
        self.assertIn("is not https on registry.npmjs.org", self.problems(other)[0])
        pypi_on_npm = row("pypi", "six", "1.17.0", url=NPM_FILES + "six-1.17.0-py3-none-any.whl")
        self.assertTrue(self.problems(pypi_on_npm))

    def test_container_kind(self):
        self.assertEqual(pop.container_kind("npm", "a-1.tgz"), ("tgz", "npm"))
        self.assertEqual(pop.container_kind("pypi", "a-1-py3-none-any.whl"), ("zip", "wheel"))
        self.assertEqual(pop.container_kind("pypi", "a-1.tar.gz"), ("tgz", "sdist"))
        self.assertEqual(pop.container_kind("pypi", "a-1.zip"), ("zip", "sdist"))
        self.assertIsNone(pop.container_kind("pypi", "a-1.egg"))
        self.assertIsNone(pop.container_kind("npm", "a-1.zip"))


class PickTests(unittest.TestCase):
    def files(self, *names):
        return [{"filename": n, "packagetype": "sdist" if n.endswith((".tar.gz", ".zip")) else "bdist_wheel"}
                for n in names]

    def pick(self, *names):
        got = pop.pypi_pick(self.files(*names))
        return got and got["filename"]

    def test_the_file_pip_installs_on_linux_x86_64(self):
        sdist, pure = "x-1.tar.gz", "x-1-py3-none-any.whl"
        cp311 = "x-1-cp311-cp311-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
        abi3 = "x-1-cp39-abi3-manylinux_2_28_x86_64.whl"
        cp313 = "x-1-cp313-cp313-manylinux_2_17_x86_64.whl"
        mac = "x-1-cp311-cp311-macosx_11_0_arm64.whl"
        arm = "x-1-cp311-cp311-manylinux_2_17_aarch64.whl"
        self.assertEqual(self.pick(sdist, cp311, pure), pure)
        self.assertEqual(self.pick(sdist, cp313, cp311), cp311)
        self.assertEqual(self.pick(sdist, cp313, abi3), abi3)
        self.assertEqual(self.pick(sdist, mac, cp313), cp313)
        self.assertEqual(self.pick(mac, arm, sdist), sdist)
        self.assertIsNone(self.pick(mac, arm))


class ResolveAndPinTests(unittest.TestCase):
    def npm_meta(self, name, version, tarball):
        return json.dumps({"name": name, "version": version, "dist": {"tarball": tarball}}).encode()

    def test_npm_latest_and_a_scoped_name(self):
        data = b"\x1f\x8b scoped tarball"
        tarball = NPM_FILES + "@scope/pkg/-/pkg-2.0.0.tgz"
        reg = Registry({"https://registry.npmjs.org/@scope%2Fpkg/latest": self.npm_meta("@scope/pkg", "2.0.0", tarball),
                        tarball: data})
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("npm", "@scope/pkg", None, cache, reg)
            self.assertTrue(os.path.isfile(os.path.join(cache, sha(data))))
        self.assertEqual(got, {"id": "npm:@scope/pkg@2.0.0", "ecosystem": "npm", "name": "@scope/pkg",
                               "version": "2.0.0", "filename": "pkg-2.0.0.tgz", "url": tarball, "container": "tgz",
                               "kind": "npm", "sha256": sha(data), "bytes": len(data)})
        self.assertEqual(pop.validate([got]), [])

    def pypi_registry(self, data, digest=None, size=None, files=None):
        whl = PY_FILES + "six-1.17.0-py3-none-any.whl"
        urls = files or [{"filename": "six-1.17.0.tar.gz", "packagetype": "sdist", "url": PY_FILES + "six-1.17.0.tar.gz",
                          "digests": {"sha256": "1" * 64}},
                         {"filename": "six-1.17.0-py3-none-any.whl", "packagetype": "bdist_wheel", "url": whl,
                          "digests": {"sha256": digest or sha(data)}, "size": size or len(data)}]
        meta = {"info": {"version": "1.17.0"}, "urls": urls}
        return Registry({"https://pypi.org/pypi/six/json": json.dumps(meta).encode(),
                         "https://pypi.org/pypi/six/1.17.0/json": json.dumps(meta).encode(), whl: data})

    def test_pypi_the_picked_file_checked_against_the_registrys_digest(self):
        data = b"PK wheel bytes"
        with tempfile.TemporaryDirectory() as cache:
            got = pop.pin_one("pypi", "six", None, cache, self.pypi_registry(data))
            self.assertEqual((got["filename"], got["kind"], got["sha256"]), ("six-1.17.0-py3-none-any.whl", "wheel", sha(data)))
            with self.assertRaisesRegex(pop.PinError, "not the file the registry lists"):
                pop.pin_one("pypi", "six", "1.17.0", cache, self.pypi_registry(data, digest="2" * 64))
            self.assertEqual(os.listdir(cache), [sha(data)])                # the bytes that failed are gone

    def test_what_is_not_pinned(self):
        with tempfile.TemporaryDirectory() as cache:
            with self.assertRaisesRegex(pop.PinError, "over"):
                pop.pin_one("pypi", "six", None, cache, self.pypi_registry(b"x", size=pop.MAX_FILE_BYTES + 1))
            mac = [{"filename": "six-1.17.0-cp311-cp311-macosx_11_0_arm64.whl", "packagetype": "bdist_wheel",
                    "url": PY_FILES + "six-1.17.0-cp311-cp311-macosx_11_0_arm64.whl"}]
            with self.assertRaisesRegex(pop.PinError, "no file to install"):
                pop.pin_one("pypi", "six", None, cache, self.pypi_registry(b"x", files=mac))
            reg = Registry({"https://registry.npmjs.org/gone/latest": json.dumps({"version": "1.0.0"}).encode()})
            with self.assertRaisesRegex(pop.PinError, "no tarball"):
                pop.pin_one("npm", "gone", None, cache, reg)
            with self.assertRaisesRegex(pop.PinError, "404"):
                pop.pin_one("npm", "missing", None, cache, Registry({}))
            elsewhere = Registry({"https://registry.npmjs.org/moved/latest":
                                  self.npm_meta("moved", "1.0.0", "https://cdn.invalid/moved-1.0.0.tgz")})
            with self.assertRaisesRegex(pop.PinError, "only https from registry.npmjs.org"):
                pop.pin_one("npm", "moved", None, cache, elsewhere)
            self.assertEqual(os.listdir(cache), [])


class FetchTests(unittest.TestCase):
    def test_fetched_once_named_by_sha256_and_hashed_again(self):
        data = b"the pinned bytes"
        r = row(data=data)
        reg = Registry({r["url"]: data})
        with tempfile.TemporaryDirectory() as cache:
            path = pop.fetch_file(r, cache, reg)
            self.assertEqual(os.path.basename(path), sha(data))
            pop.fetch_file(r, cache, reg)
            self.assertEqual(len(reg.asked), 1)                               # the cached file is used
            with open(path, "wb") as fh:
                fh.write(b"swapped")
            pop.fetch_file(r, cache, reg)                                      # and hashed again first
            self.assertEqual(len(reg.asked), 2)
            with open(path, "rb") as fh:
                self.assertEqual(fh.read(), data)

    def test_other_bytes_are_refused_and_not_kept(self):
        r = row(data=b"pinned")
        with tempfile.TemporaryDirectory() as cache:
            with self.assertRaisesRegex(pop.PinError, "not the pinned ones"):
                pop.fetch_file(r, cache, Registry({r["url"]: b"substituted"}))
            self.assertEqual(os.listdir(cache), [])

    def test_the_size_limit(self):
        r = row(data=b"x")
        big = b"x" * (2 << 20)
        with tempfile.TemporaryDirectory() as cache:
            old = pop.MAX_FILE_BYTES
            pop.MAX_FILE_BYTES = 1 << 20
            try:
                with self.assertRaisesRegex(pop.PinError, "more than 1 MiB"):
                    pop.fetch_file(r, cache, Registry({r["url"]: big}))
            finally:
                pop.MAX_FILE_BYTES = old
            self.assertEqual(os.listdir(cache), [])

    def test_fetch_command_writes_the_benchmark_manifest(self):
        good, bad = row(data=b"good"), row(name="other", data=b"pinned")
        reg = Registry({good["url"]: b"good", bad["url"]: b"changed"})
        with tempfile.TemporaryDirectory() as d:
            releases, cache, manifest = (os.path.join(d, n) for n in ("r.jsonl", "cache", "m.jsonl"))
            pop.write_releases([good, bad], releases)
            args = pop.build_parser().parse_args(["--releases", releases, "fetch", "--cache", cache,
                                                  "--manifest", manifest])
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(pop.cmd_fetch(args, reg), pop.EXIT_FETCH)
            self.assertIn("not the pinned ones", err.getvalue())
            with open(manifest, encoding="utf-8") as fh:
                lines = [json.loads(line) for line in fh]
        self.assertEqual(len(lines), 1)
        self.assertEqual({k: lines[0][k] for k in ("id", "cat", "container", "kind")},
                         {"id": "popular:npm:left-pad@1.3.0", "cat": "benign", "container": "tgz", "kind": "npm"})
        self.assertEqual(os.path.basename(lines[0]["artifact_path"]), sha(b"good"))


class NamesAndSpecsTests(unittest.TestCase):
    def test_top_names_less_the_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            names = os.path.join(d, "names.json")
            with open(names, "w", encoding="utf-8") as fh:
                json.dump({"npm": {"targets": ["semver", "debug", "chalk", "lodash"]},
                           "pypi": {"targets": ["boto3", "typing-extensions", "six"]}}, fh)
            exclude = os.path.join(d, "exclude.txt")
            with open(exclude, "w", encoding="utf-8") as fh:
                fh.write("npm:debug\n# the benchmark's\nTyping_Extensions\n")
            got = pop.top_names({"npm": 2, "pypi": 2}, pop.read_exclude(exclude), names)
        self.assertEqual(got, [("npm", "semver"), ("npm", "chalk"), ("pypi", "boto3"), ("pypi", "six")])

    def test_specs(self):
        self.assertEqual(pop.parse_spec("npm:@babel/parser@7.29.9"), ("npm", "@babel/parser", "7.29.9"))
        self.assertEqual(pop.parse_spec("pypi:sympy"), ("pypi", "sympy", None))
        for bad in ("gem:rails@7", "npm:", "lodash@4"):
            with self.subTest(spec=bad), self.assertRaises(ValueError):
                pop.parse_spec(bad)

    def test_pin_with_specs_keeps_the_others_and_moves_a_name(self):
        data = b"new tarball"
        url = NPM_FILES + "left-pad/-/left-pad-1.4.0.tgz"
        reg = Registry({"https://registry.npmjs.org/left-pad/1.4.0":
                        json.dumps({"version": "1.4.0", "dist": {"tarball": url}}).encode(), url: data})
        with tempfile.TemporaryDirectory() as d:
            releases = os.path.join(d, "r.jsonl")
            pop.write_releases([row(), row("pypi", "six", "1.17.0")], releases)
            args = pop.build_parser().parse_args(["--releases", releases, "pin", "npm:left-pad@1.4.0",
                                                  "--cache", os.path.join(d, "cache")])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pop.cmd_pin(args, reg), pop.EXIT_OK)
            ids = [r["id"] for r in pop.read_releases(releases)]
        self.assertEqual(ids, ["npm:left-pad@1.4.0", "pypi:six@1.17.0"])

    def test_pin_takes_specs_or_top(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pop.main(["pin", "--cache", "x"]), pop.EXIT_USAGE)
            self.assertEqual(pop.main(["pin", "npm:a@1", "--top", "1,1", "--cache", "x"]), pop.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
