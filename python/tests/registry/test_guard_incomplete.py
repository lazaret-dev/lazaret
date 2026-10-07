"""T-1 and decision 9 (0.1.9): a scan that could not read what a package can be made to hide blocks the guard by
default. A scan that ran out of time, an engine that could not finish, code cut at a limit (a payload padded past
the size limit inside its file: the Go/Rust review's GO-1) and an archive not read whole are INCOMPLETE for a reason
the package controls; `--allow-incomplete` lets them through, as before, and `--trust` one package. A time-out is
scanned once more and never cached. A download too large to scan, or a program too large to read (a 16 MB native
library), stays INCOMPLETE and goes through.

The scan's own result says why (`incomplete`, repo.INCOMPLETE_KINDS); the guard reads it."""

import datetime
import email.utils
import gzip
import unittest
from unittest import mock

from lazaret.registry import guard, repo
from lazaret.registry.ecosystems import base
from tests.registry._review_support import manifest, tar_member, tarball
from tests.registry.test_guard import context

LIMIT = 10_000
BIG = b"// padding\n" * 2_000                      # 22,000 bytes of harmless text
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 30_000    # a program's bytes, past the limit


def scan(data, budget=None, artifact="npm"):
    """repo's scan of one archive, as the guard makes it (one file, the per-archive deadline)."""
    with mock.patch.object(repo, "MAX_MEMBER", LIMIT):
        return repo._scan_artifact(data, "tgz", artifact, False, budget)


class Clock:
    """repo's `time`: monotonic() advances `step` per call."""

    def __init__(self, step=0.0):
        self.now, self.step = 1000.0, step

    def monotonic(self):
        self.now += self.step
        return self.now


class WhyTests(unittest.TestCase):
    """The scan result's `incomplete`: why it is INCOMPLETE, of the kinds the guard blocks."""

    def test_a_source_file_cut_at_the_limit_is_code(self):
        res = scan(tarball({"package.json": manifest(main="index.js"), "index.js": "module.exports = 1;\n",
                            "lib/pad.js": BIG}))
        self.assertEqual((res["verdict"], res["incomplete"]), ("INCOMPLETE", ["code"]))
        # (a file that runs, of a name that is not a source file's, read as the code it is: the same)
        res = scan(tarball({"package.json": manifest(main="lib/core.dat"), "lib/core.dat": BIG}))
        self.assertEqual((res["verdict"], res["incomplete"]), ("INCOMPLETE", ["code"]))

    def test_a_program_too_large_to_read_is_none_of_them(self):
        # (@img/sharp-libvips-linuxmusl-x64's shape: its 16 MB library, named by the package, is not code it reads)
        res = scan(tarball({"package.json": manifest(main="lib/libvips-cpp.so.42"), "lib/libvips-cpp.so.42": ELF}))
        self.assertEqual((res["verdict"], res["incomplete"]), ("INCOMPLETE", []))

    def test_a_scan_that_ran_out_of_time(self):
        files = {"package.json": manifest(main="index.js"), **{f"lib/f{i}.js": f"module.exports = {i};\n"
                                                                 for i in range(60)}}
        clock = Clock(step=0.01)
        with mock.patch.object(repo, "time", clock):
            res = scan(tarball(files), repo.Budget(deadline=clock.now + 0.3))
        self.assertEqual((res["verdict"], res["incomplete"]), ("INCOMPLETE", ["time"]))

    def test_an_archive_not_read_whole(self):
        files = {"package.json": manifest(main="index.js"), **{f"lib/f{i}.js": "1;\n" for i in range(30)}}
        with mock.patch.object(repo, "MAX_FILES", 10):
            res = scan(tarball(files))
        self.assertEqual((res["verdict"], res["incomplete"]), ("INCOMPLETE", ["archive"]))

    def test_an_engine_that_could_not_finish(self):
        from lazaret.scanner import _native
        files = {"package.json": manifest(main="index.js", scripts={"postinstall": "node setup.js"}),
                 "setup.js": "module.exports = 1;\n", "index.js": "module.exports = 1;\n"}
        real = _native.call

        def failing(name, args=None, text=""):
            if name == "install_script_risk":
                raise _native.NativeExhausted("install_script_risk: the call's work budget was spent")
            return real(name, args, text)
        with mock.patch.object(_native, "call", side_effect=failing):
            res = scan(tarball(files))
        self.assertEqual((res["verdict"], res["incomplete"]), ("INCOMPLETE", ["work"]))

    def test_none_when_the_scan_is_whole(self):
        res = scan(tarball({"package.json": manifest(main="index.js"), "index.js": "module.exports = 1;\n"}))
        self.assertEqual((res["verdict"], res["incomplete"]), ("OK", []))


class PolicyTests(unittest.TestCase):
    """What the guard does with such a verdict."""
    CUT = {"verdict": "INCOMPLETE", "reason": "1 part not fully scanned", "indicators": [], "incomplete": ["code"]}

    def test_blocked_by_default(self):
        ctx = context()
        check = ctx.add(guard.Check("npm", "x", "1.0.0"))
        ctx.apply(check, self.CUT)
        self.assertEqual(check.blocked, ["INCOMPLETE: 1 part not fully scanned (code was not read whole; "
                                         "--allow-incomplete lets it through)"])
        for kind, said in guard.INCOMPLETE_SAID.items():
            check = ctx.add(guard.Check("npm", kind, "1.0.0"))
            ctx.apply(check, {**self.CUT, "incomplete": [kind]})
            self.assertIn(said, check.blocked[0])

    def test_let_through_by_the_flag_or_trust(self):
        ctx = context(allow_incomplete=True)
        check = ctx.add(guard.Check("npm", "x", "1.0.0"))
        ctx.apply(check, self.CUT)
        self.assertEqual((check.verdict, check.blocked), ("INCOMPLETE", []))
        ctx = context(trust=["x"])
        check = ctx.add(guard.Check("npm", "x", "1.0.0"))
        ctx.apply(check, self.CUT)
        self.assertEqual(check.blocked, [])
        self.assertTrue(check.trusted)
        # (--block-warn still blocks every INCOMPLETE, the flag or not)
        ctx = context(allow_incomplete=True, block_warn=True)
        check = ctx.add(guard.Check("npm", "x", "1.0.0"))
        ctx.apply(check, self.CUT)
        self.assertEqual(len(check.blocked), 1)

    def test_other_incomplete_verdicts_go_through_as_before(self):
        ctx = context()
        for hit in ({**self.CUT, "incomplete": []}, {k: v for k, v in self.CUT.items() if k != "incomplete"},
                    {**self.CUT, "incomplete": ["something else"]}):
            check = ctx.add(guard.Check("npm", "x", "1.0.0"))
            ctx.apply(check, hit)
            self.assertEqual((check.verdict, check.blocked), ("INCOMPLETE", []))
        big = ctx.add(guard.Check("npm", "big", "1.0.0"))
        ctx.not_checked(big, guard.TooLarge("response over 200MB: x"))
        self.assertEqual((big.verdict, big.blocked), ("INCOMPLETE", []))

    def test_a_time_out_is_scanned_once_more_and_never_kept(self):
        timed = {"verdict": "INCOMPLETE", "reason": "1 part not fully scanned", "indicators": [], "incomplete": ["time"]}
        ok = {"verdict": "OK", "reason": "no supply-chain indicators", "indicators": [], "incomplete": []}
        scanner = guard.Scanner(None)
        with mock.patch.object(scanner, "_scan", side_effect=[timed, ok]) as made:
            self.assertEqual(scanner.scan(b"x", "tgz", "npm"), ok)
        self.assertEqual(made.call_count, 2)
        with mock.patch.object(scanner, "_scan", side_effect=[timed, timed]):
            self.assertEqual(scanner.scan(b"x", "tgz", "npm"), timed)
        with mock.patch.object(scanner, "_scan", side_effect=[ok]) as made:
            scanner.scan(b"x", "tgz", "npm")
        self.assertEqual(made.call_count, 1)
        cache = guard.VerdictCache(None)
        scanner = guard.Scanner(cache)
        scanner.remember("t", timed, None)
        scanner.remember("c", {**timed, "incomplete": ["code"]}, None)
        self.assertIsNone(cache.get("t"))
        self.assertEqual(cache.get("c")["incomplete"], ["code"])         # (kept, so that a hit blocks too)


class NpmFetcher:
    def __init__(self, answers, published):
        self.answers, self.published = answers, published

    def get(self, url, max_bytes=None, accept=None, timeout=None):
        if url not in self.answers:
            raise base.FetchError(f"HTTP 404 fetching {url}")
        return self.answers[url]

    def fetch(self, url, max_bytes=None, accept=None, timeout=None):
        return self.get(url), {"Last-Modified": email.utils.format_datetime(self.published, usegmt=True)}

    def json(self, url, accept=None):
        raise base.FetchError("not asked here")


class GuardTests(unittest.TestCase):
    """The npm guard on a package whose payload is padded past the size limit inside its file (GO-1's shape)."""

    def check(self, data, **opts):
        import base64
        import hashlib
        url = guard.NPM_REGISTRY + "x/-/x-1.0.0.tgz"
        fetcher = NpmFetcher({url: data}, guard.now() - datetime.timedelta(days=5))
        ctx = context(tool="npm", **opts)
        self.addCleanup(ctx.close)
        pkg = {"name": "x", "version": "1.0.0", "tarball": url, "registry": guard.NPM_REGISTRY, "lock_digest": None,
               "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()}
        with mock.patch.object(repo, "MAX_MEMBER", LIMIT):
            return guard.check_npm_package(ctx, fetcher, pkg)

    def test_a_padded_file_blocks_the_install_unless_let_through(self):
        data = tarball({"package.json": manifest(main="index.js"), "index.js": "require('./lib/pad');\n",
                        "lib/pad.js": BIG})
        check = self.check(data)
        self.assertEqual(check.verdict, "INCOMPLETE")
        self.assertTrue(check.blocked and check.blocked[0].startswith("INCOMPLETE: "), check.blocked)
        self.assertIn("--allow-incomplete lets it through", check.blocked[0])
        check = self.check(data, allow_incomplete=True)
        self.assertEqual((check.verdict, check.blocked), ("INCOMPLETE", []))

    def test_a_package_with_a_large_program_goes_through(self):
        data = gzip.compress(tar_member("package/package.json", manifest(main="lib/libvips-cpp.so.42"))
                             + tar_member("package/lib/libvips-cpp.so.42", ELF) + b"\0" * 1024, mtime=0)
        check = self.check(data)
        self.assertEqual((check.verdict, check.blocked), ("INCOMPLETE", []))


if __name__ == "__main__":
    unittest.main()
