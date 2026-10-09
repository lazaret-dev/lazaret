"""The Go checksum database's answer checked as the go command checks it (`golang.verify_lookup`, 0.1.9, NET-1 part 3),
on a capture of the real `sum.golang.org`: pratique's tests/data/sumdb (its README.txt says how it was made), the
lookup of golang.org/x/mod v0.17.0, a tree head the database served a little before it (`latest.txt`, kept here as if
from an earlier check) and the seven tiles Go's own client reads for the two. The check is the native library's
(`verify.go_sumdb`, over pratique's sumdb and tlog). The module proxy's `.info` is the documented shape, not a recording.
Nothing here opens a socket."""

import json
import os
import unittest
from unittest import mock

from lazaret.registry.ecosystems import base, golang
from lazaret.scanner import _native
from tests import _support

DATA = os.path.join(_support.REPO_ROOT, "rust", "crates", "pratique", "tests", "data", "sumdb")
MODULE, VERSION = "golang.org/x/mod", "v0.17.0"
ZIP_H1 = "h1:zY54UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA="
MOD_H1 = "h1:hTbmBsO62+eylJbnUtE2MGJUyE7QWk4xUqPFrRgJ+7c="
# the tiles that prove the record is in the lookup's tree (the same seven prove the head kept from before a prefix of it)
FOR_THE_LOOKUP = ("tile/8/0/x097/482", "tile/8/1/380", "tile/8/2/001", "tile/8/0/x260/730.p/101", "tile/8/1/x001/018.p/122",
                  "tile/8/2/003.p/250", "tile/8/3/000.p/3")
PROXY = "https://proxy.golang.org/"
SUMDB = "https://sum.golang.org/"
INFO_URL = PROXY + MODULE + "/@v/" + VERSION + ".info"
LOOKUP_URL = SUMDB + "lookup/" + MODULE + "@" + VERSION


def captured(rel):
    with open(os.path.join(DATA, *rel.split("/")), "rb") as fh:
        return fh.read()


LOOKUP = captured("lookup.txt")
LATEST = captured("latest.txt").decode("utf-8")
TILES = {path: captured(path) for path in FOR_THE_LOOKUP}


def responses(**changes):
    out = {INFO_URL: json.dumps({"Version": VERSION}).encode("utf-8"), LOOKUP_URL: LOOKUP}
    out.update({SUMDB + path: data for path, data in TILES.items()})
    out.update(changes)
    return {url: body for url, body in out.items() if body is not None}


class Served:
    """A `Fetch` over these responses, remembering what was asked for (a missing URL is a 404)."""

    def __init__(self, answers):
        self.urls = []

        def transport(url, **kw):
            self.urls.append(url)
            body = answers.get(url)
            if body is None:
                err = base.FetchError("not found")
                err.status = 404
                raise err
            return body
        self.fetch = base.Fetch(golang.Go(), transport, clock=lambda: 0.0, sleep=lambda s: None)

    def tiles(self):
        return sorted(u[len(SUMDB):] for u in self.urls if u.startswith(SUMDB + "tile/"))


def checks():
    """Is the check here: a native library that answers `verify.go_sumdb`?"""
    if not _native.available():
        return False
    try:
        _native.call("verify.go_sumdb", {})
    except _native.NativeError as exc:
        return "unknown call" not in str(exc)
    return True


@unittest.skipUnless(checks(), f"no native library with the checksum database check ({_native.load_error()})")
class CheckTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(golang, "_SUMDB", golang._Sumdb())          # (a fresh process's memory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def resolve(self, answers=None):
        served = Served(responses() if answers is None else answers)
        return golang.Go().resolve(MODULE, VERSION, served.fetch), served

    def keep_latest(self):
        """The head the database served a little before the lookup, as an earlier check would have kept it."""
        golang._SUMDB.latest = (66746896, LATEST)

    def test_the_real_lookup_is_verified(self):
        res, served = self.resolve()
        self.assertEqual(res.info["sumdb"], "verified")
        self.assertEqual(res.artifacts[0]["entry"], {"h1": ZIP_H1, "gomod_h1": MOD_H1})
        self.assertEqual(served.urls[:2], [INFO_URL, LOOKUP_URL])
        self.assertEqual(served.tiles(), sorted(FOR_THE_LOOKUP))
        size, note = golang._SUMDB.latest
        self.assertEqual(size, 66746981)                                         # (the lookup's own head, kept)
        self.assertTrue(note.startswith("go.sum database tree\n66746981\n"))

    def test_a_head_kept_from_before_is_proved_a_prefix(self):
        self.keep_latest()
        res, served = self.resolve()
        self.assertEqual(res.info["sumdb"], "verified")
        self.assertEqual(served.tiles(), sorted(FOR_THE_LOOKUP))
        self.assertEqual(golang._SUMDB.latest[0], 66746981)

    def test_the_tiles_are_kept_and_checked_again(self):
        self.keep_latest()
        self.resolve()
        res, served = self.resolve()
        self.assertEqual(res.info["sumdb"], "verified")
        self.assertEqual(served.tiles(), [], "the second check reads the kept tiles")
        golang._SUMDB.tiles["tile/8/1/380"] = bytes(len(TILES["tile/8/1/380"]))  # (a kept tile is checked again)
        with self.assertRaisesRegex(base.FetchError, "does not check out"):
            self.resolve()

    def test_a_changed_record_is_refused(self):
        changed = LOOKUP.replace(ZIP_H1.encode(), b"h1:zY55UmvipHiNd+pm+m0x9KhZ9hl1/7QNMyxXbc6ICqA=")
        with self.assertRaisesRegex(base.FetchError, "does not check out"):
            self.resolve(responses(**{LOOKUP_URL: changed}))
        self.assertIsNone(golang._SUMDB.latest, "nothing kept from a check that failed")

    def test_a_head_that_is_not_signed_is_refused(self):
        changed = LOOKUP.replace(b"\n66746981\n", b"\n66746982\n")
        with self.assertRaisesRegex(base.FetchError, "does not check out"):
            self.resolve(responses(**{LOOKUP_URL: changed}))

    def test_a_changed_tile_and_a_missing_one_are_refused(self):
        self.keep_latest()
        for path in FOR_THE_LOOKUP:
            with self.subTest(path=path):
                golang._SUMDB.tiles.clear()
                tile = bytearray(TILES[path])
                tile[40] ^= 1
                with self.assertRaisesRegex(base.FetchError, "does not check out"):
                    self.resolve(responses(**{SUMDB + path: bytes(tile)}))
                with self.assertRaises(base.FetchError):
                    self.resolve(responses(**{SUMDB + path: None}))

    def test_a_partial_tile_gone_is_read_from_the_full_one(self):
        # The database stops serving a partial tile once it has filled: the full one's first hashes are the same.
        partial = "tile/8/0/x260/730.p/101"
        full = "tile/8/0/x260/730"
        filled = TILES[partial] + bytes(i % 251 for i in range(8192 - len(TILES[partial])))     # (the hashes added since)
        self.assertEqual(len(filled), 8192)
        res, served = self.resolve(responses(**{SUMDB + partial: None, SUMDB + full: filled}))
        self.assertEqual(res.info["sumdb"], "verified")
        self.assertIn(full, served.tiles())
        self.assertIn(partial, served.tiles())
        # a full tile whose first hashes differ is refused
        wrong = bytes(32) + filled[32:]
        with self.assertRaisesRegex(base.FetchError, "does not check out"):
            golang._SUMDB.tiles.clear()
            self.resolve(responses(**{SUMDB + partial: None, SUMDB + full: wrong}))

    def test_another_databases_key_is_refused(self):
        with mock.patch.object(golang, "SUMDB_KEY", "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn9"):
            with self.assertRaisesRegex(base.FetchError, "does not check out"):
                self.resolve()

    def test_the_hashes_used_are_the_signed_records(self):
        # parse_lookup and the check read the same bytes; were they ever to read them differently, nothing is used
        record = golang.parse_lookup(LOOKUP.decode("utf-8"), MODULE, VERSION)
        served = Served(responses())
        lookup = LOOKUP.decode("utf-8")
        self.assertTrue(golang.verify_lookup(MODULE, VERSION, lookup, record, served.fetch))
        for wrong in (dict(record, h1="h1:" + "A" * 43 + "="), dict(record, gomod_h1="h1:" + "A" * 43 + "="), dict(record, id=7)):
            with self.subTest(wrong=wrong):
                with self.assertRaisesRegex(base.FetchError, "not the one its response reads as"):
                    golang.verify_lookup(MODULE, VERSION, lookup, wrong, served.fetch)

    def test_the_tiles_named_are_checked_before_any_is_fetched(self):
        record = golang.parse_lookup(LOOKUP.decode("utf-8"), MODULE, VERSION)
        lookup = LOOKUP.decode("utf-8")
        for needed in ([{"path": "../../etc/passwd", "full": "tile/8/0/000", "len": 32, "full_len": 8192}],
                       [{"path": "tile/8/0/000", "full": "tile/8/0/000", "len": 9000, "full_len": 9000}],
                       [{"path": "tile/8/0/000", "full": "tile/8/0/000", "len": True, "full_len": 8192}],
                       [{"path": "tile/8/0/000", "full": "tile/8/0/000", "len": 32, "full_len": 8192}] * 65, {"x": 1}):
            with self.subTest(needed=str(needed)[:80]):
                served = Served(responses())
                with mock.patch.object(_native, "call", return_value={"needed": needed}):
                    with self.assertRaisesRegex(base.FetchError, "named tiles it cannot have"):
                        golang.verify_lookup(MODULE, VERSION, lookup, record, served.fetch)
                self.assertEqual(served.urls, [])


class WithoutTheCheckTests(unittest.TestCase):
    """Without a native library that checks, the lookup is as good as the TLS that brought it, and the result says so."""

    def test_no_native_library(self):
        served = Served(responses())
        with mock.patch.object(_native, "available", return_value=False):
            res = golang.Go().resolve(MODULE, VERSION, served.fetch)
        self.assertEqual(res.info["sumdb"], "tls")
        self.assertEqual(served.urls, [INFO_URL, LOOKUP_URL])

    def test_a_library_from_before_the_check(self):
        served = Served(responses())
        older = _native.NativeError("verify.go_sumdb: unknown call verify.go_sumdb")
        with mock.patch.object(_native, "available", return_value=True), mock.patch.object(_native, "call", side_effect=older):
            res = golang.Go().resolve(MODULE, VERSION, served.fetch)
        self.assertEqual(res.info["sumdb"], "tls")

    def test_any_other_failure_of_the_check_fails_the_resolve(self):
        served = Served(responses())
        failed = _native.NativeError("verify.go_sumdb: panic in the checksum database check\x1b[31m")
        with mock.patch.object(_native, "available", return_value=True), mock.patch.object(_native, "call", side_effect=failed):
            with self.assertRaises(base.FetchError) as caught:
                golang.Go().resolve(MODULE, VERSION, served.fetch)
        self.assertIn("panic in the checksum database check?[31m", str(caught.exception))
        self.assertTrue(str(caught.exception).isprintable())


if __name__ == "__main__":
    unittest.main()
