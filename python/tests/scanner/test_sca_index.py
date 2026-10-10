"""The indexed CVE bundle (lazaret.scanner.sca_index, 0.1.9 P-5): the same bundle as `cve-bundle.json` in a file a
scan reads parts of. What these tests hold it to:

* **It answers as the JSON bundle does.** Same pairs, same order, same warnings, on a fixture of every shape the
  bundle has (exact and loose names, malformed ranges, junk entries) and on random bundles.
* **It reads little.** Opening reads the header, the metadata and two tables; a name the bundle does not have costs no
  read; a name it has costs its entry and its advisories.
* **It fails closed.** A file cut anywhere, a byte changed anywhere, a record that inflates to more than a record may,
  a table out of order, a posting that points nowhere: each is an error (`BundleDamaged`, a `ValueError`, so the CLI
  exits 4), never a lookup that finds nothing. The hostile files with correct checksums are built by taking a good
  file apart and putting it together again.
"""

import collections
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import tracemalloc
import unittest
import zlib
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from lazaret.scanner import sca, sca_feeds, sca_index
from tests.scanner import test_sca_feeds as feeds

HEAD_FIELDS = ("magic", "format", "flags", "file_len", "n_adv", "n_keys", "n_post", "meta_off", "meta_len",
               "advtab_off", "keytab_off", "blobs_off", "meta_crc", "advtab_crc", "keytab_crc", "header_crc")


# ---------------------------------------------------------------------------
# Bundles
# ---------------------------------------------------------------------------

def package(name, eco="npm", exact=True, ranges=(), **more):
    if ranges is not None and not isinstance(ranges, str):
        ranges = list(ranges)
    return dict({"name": name, "ecosystem": eco, "exact": exact, "ranges": ranges}, **more)


def rng(lo, hi, inclusive=False):
    return {"fromVersion": lo, "toVersion": hi, "toInclusive": inclusive}


def fixture():
    """A bundle with one of everything the reader has to treat the way `CveBundle` does."""
    return {
        "bundleVersion": 1, "generator": "tests", "generatedAt": "2026-10-01T00:00:00Z",
        "sources": ["osv:npm", "osv:pypi", "cisa-kev"], "counts": {"advisories": 12},
        "attribution": ["synthetic"], "feeds": {"osv": {"newestModified": "2026-09-30T00:00:00Z"}},
        "advisories": [
            {"cve": "CVE-2099-0001", "title": "lodash", "cvss": 9.8, "knownExploited": True,
             "packages": [package("lodash", ranges=[rng("0", "4.17.12")])]},
            {"cve": "CVE-2099-0002", "title": "django", "cvss": 7.5,
             "packages": [package("Django", "pypi", ranges=[rng("4.2", "4.2.7", True)])]},
            {"cve": "CVE-2099-0003", "packages": [package("python-urllib3", None, False, [rng("1.0", "1.26.17")])]},
            {"cve": "CVE-2099-0004", "packages": [package("babel-core", "npm", False, [rng("6.0.0", "6.26.3")]),
                                                    package("@babel/core", "npm", True, [rng("7.0.0", "7.1.0")])]},
            {"cve": "CVE-2099-0005", "packages": [package("requests", "pypi", True, "not a list")]},
            {"cve": "CVE-2099-0006", "packages": [package("requests", "pypi", True, None),
                                                    package("requests", "pypi", True, [rng("2.0", "2.31.0")])]},
            {"cve": "CVE-2099-0007", "malicious": True, "packages": [package("lodahs", ranges=[{}])]},
            {"id": "GHSA-aaaa-bbbb-cccc", "cvss": "bad", "packages": [package("lodash", ranges=[rng("0", "4.0.0")])]},
            {"title": "no id at all", "packages": [package("lodash", ranges=[rng("0", "1.0.0")])]},
            "junk",
            {"cve": "CVE-2099-0008", "packages": "not a list"},
            {"cve": "CVE-2099-0009", "packages": [None, {"name": " "}, {"name": 5}, package("lodash"),
                                                    package("python-", None, False),
                                                    package("maven-thing", "maven", True),
                                                    package("odd\ud800name", "npm", True)]},
        ],
    }


NAMES = ["lodash", "Lodash", "LODASH", "python-foo", "foo", "foo-bar", "foo_bar", "Foo.Bar", "@babel/core",
         "babel-core", "babel_core", "@types/lodash", "requests", "py-requests", "python-requests", "urllib3",
         "python-urllib3", "django", "Django", "lodahs", "maven-thing", "---", "a", "nothing-like-it", "odd\ud800name"]
ECOSYSTEMS = ("npm", "pypi", None, "maven")


def random_doc(seed):
    rnd = random.Random(seed)
    advisories = []
    for i in range(rnd.randrange(0, 30)):
        if rnd.random() < 0.05:
            advisories.append(rnd.choice(["junk", 5, None, ["x"]]))
            continue
        adv = {}
        if rnd.random() < 0.9:
            adv["cve"] = "CVE-2099-%d" % rnd.randrange(12)
        if rnd.random() < 0.6:
            adv["cvss"] = rnd.choice([7.5, 9.8, "bad", None, 3])
        if rnd.random() < 0.2:
            adv["knownExploited"] = rnd.choice([True, False, "yes"])
        if rnd.random() < 0.8:
            pkgs = []
            for _ in range(rnd.randrange(0, 4)):
                pkgs.append(rnd.choice([
                    {"name": rnd.choice(NAMES), "ecosystem": rnd.choice(ECOSYSTEMS), "exact": rnd.choice([True, False, "yes"]),
                     "ranges": rnd.choice([[], [rng("1.0.0", "2.0.0")], None, "bad", [1], [{}]])},
                    {"name": rnd.choice(NAMES), "ecosystem": rnd.choice(["npm", "pypi"]), "exact": True,
                     "ranges": [rng("0", "3.0.0")]},
                    {"name": rnd.choice(NAMES), "exact": True}, None, {"name": rnd.choice([5, None, " "])}]))
            adv["packages"] = pkgs if rnd.random() < 0.95 else rnd.choice([None, "x", 3])
        advisories.append(adv)
    doc = {"bundleVersion": 1, "advisories": advisories}
    if rnd.random() < 0.8:
        doc["generatedAt"] = rnd.choice(["2026-01-01T00:00:00Z", 5, "not a date"])
    if rnd.random() < 0.8:
        doc["sources"] = rnd.choice([["osv:npm"], ["a", 5], "x", []])
    if rnd.random() < 0.8:
        doc["counts"] = rnd.choice([{"advisories": len(advisories)}, [], {}])
    return doc


def dump(doc):
    buf = io.BytesIO()
    summary = sca_index.dump_index(doc, buf)
    return buf.getvalue(), summary


def parse(data):
    head = dict(zip(HEAD_FIELDS, sca_index.HEADER.unpack_from(data)))
    return {"head": head, "meta": data[head["meta_off"]:head["meta_off"] + head["meta_len"]],
            "advtab": bytearray(data[head["advtab_off"]:head["keytab_off"]]),
            "keytab": bytearray(data[head["keytab_off"]:head["blobs_off"]]), "blobs": bytes(data[head["blobs_off"]:])}


def build(p, **head):
    """The file for parts `p`, with the lengths and checksums recomputed (and the header fields in `head` set
    after that): a hostile file whose checksums are right."""
    meta, advtab, keytab, blobs = p["meta"], bytes(p["advtab"]), bytes(p["keytab"]), p["blobs"]
    h = dict(p["head"])
    h["meta_off"] = sca_index.HEADER.size
    h["meta_len"] = len(meta)
    h["advtab_off"] = h["meta_off"] + len(meta)
    h["keytab_off"] = h["advtab_off"] + len(advtab)
    h["blobs_off"] = h["keytab_off"] + len(keytab)
    h["file_len"] = h["blobs_off"] + len(blobs)
    h["n_adv"] = len(advtab) // sca_index.ADV_ENTRY.size
    h["n_keys"] = len(keytab) // sca_index.KEY_ENTRY.size
    h["meta_crc"], h["advtab_crc"], h["keytab_crc"] = zlib.crc32(meta), zlib.crc32(advtab), zlib.crc32(keytab)
    h.update(head)
    return sign(sca_index.HEADER.pack(*[h[k] for k in HEAD_FIELDS]) + meta + advtab + keytab + blobs)


def sign(data):
    """`data` with the header's own checksum made right."""
    head = bytearray(data[:sca_index.HEADER.size])
    head[-4:] = b"\0\0\0\0"
    head[-4:] = struct.pack("<I", zlib.crc32(bytes(head)))
    return bytes(head) + bytes(data[sca_index.HEADER.size:])


def patch_header(data, **fields):
    head = dict(zip(HEAD_FIELDS, sca_index.HEADER.unpack_from(data)))
    head.update(fields)
    return sign(sca_index.HEADER.pack(*[head[k] for k in HEAD_FIELDS]) + data[sca_index.HEADER.size:])


def stored(obj):
    return zlib.compress(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("ascii"))


def replace_record(data, stored_bytes, key=None, advisory=None):
    """`data` with the record for `key` (or advisory number `advisory`) replaced by `stored_bytes`, appended at the
    end of the records and pointed to from the table with a right length and checksum."""
    p = parse(data)
    entry = sca_index.ADV_ENTRY if key is None else sca_index.KEY_ENTRY
    table = p["advtab"] if key is None else p["keytab"]
    if key is None:
        at = advisory * entry.size
        fields = list(entry.unpack_from(table, at))
        fields[0:3] = [len(p["blobs"]), len(stored_bytes), zlib.crc32(stored_bytes)]
    else:
        digest = sca_index.key_digest(key)
        at = next(i for i in range(0, len(table), entry.size) if bytes(table[i:i + 16]) == digest)
        fields = list(entry.unpack_from(table, at))
        fields[1:4] = [len(p["blobs"]), len(stored_bytes), zlib.crc32(stored_bytes)]
    table[at:at + entry.size] = entry.pack(*fields)
    p["blobs"] = p["blobs"] + stored_bytes
    return build(p)


class CountingFile:
    """A file that counts what is read from it."""

    def __init__(self, fh):
        self.fh, self.reads, self.bytes = fh, 0, 0

    def fileno(self):
        return self.fh.fileno()

    def seek(self, *args):
        return self.fh.seek(*args)

    def read(self, n=-1):
        data = self.fh.read(n)
        self.reads += 1
        self.bytes += len(data)
        return data

    def close(self):
        self.fh.close()


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="lz-index-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.opened = []
        self.addCleanup(self.close_all)
        self.count = 0

    def close_all(self):
        for b in self.opened:
            b.close()

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def write(self, data, name=None):
        self.count += 1
        path = self.path(name or "bundle-%d.lzx" % self.count)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def open(self, data):
        b = sca_index.IndexedBundle.open(self.write(data))
        self.opened.append(b)
        return b

    def lookups(self, bundle):
        return [(n, e, bundle.advisories_for(n, e)) for n in NAMES for e in ECOSYSTEMS]


# ---------------------------------------------------------------------------
# It answers as the JSON bundle does
# ---------------------------------------------------------------------------

class EquivalenceTests(Base):
    def same(self, doc):
        data, summary = dump(doc)
        indexed, plain = self.open(data), sca.CveBundle(doc)
        self.assertEqual(indexed.warnings.lines(), plain.warnings.lines())
        self.assertEqual(summary["warnings"], plain.warnings.lines())
        self.assertEqual((indexed.generated_at, indexed.sources, indexed.counts),
                         (plain.generated_at, plain.sources, plain.counts))
        self.assertEqual(len(indexed.advisories), len(plain.advisories))
        self.assertEqual(list(indexed.advisories), plain.advisories)
        for name in NAMES:
            for eco in ECOSYSTEMS:
                self.assertEqual(indexed.advisories_for(name, eco), plain.advisories_for(name, eco), (name, eco))
        inventory = [(e, n, v, "x") for n in NAMES for e in ("npm", "pypi") for v in ("1.5.0", "", "x", "4.2.3")]
        self.assertEqual(sca.match_inventory(inventory, indexed), sca.match_inventory(inventory, plain))
        return indexed, plain

    def test_the_fixture(self):
        indexed, plain = self.same(fixture())
        self.assertGreater(len(plain.warnings.lines()), 3)                 # the fixture does have things to warn of
        found = indexed.advisories_for("lodash", "npm")
        self.assertEqual([a["cve"] for a, _ in found],
                         ["CVE-2099-0001", "GHSA-aaaa-bbbb-cccc", "advisory#9", "CVE-2099-0009"])

    def test_pairs_come_in_bundle_order_whichever_name_found_them(self):
        doc = {"bundleVersion": 1, "advisories": [
            {"cve": "A", "packages": [package("zed", "pypi", False), package("python-zed", None, False)]},
            {"cve": "B", "packages": [package("zed", "pypi", True)]},
            {"cve": "C", "packages": [package("py-zed", None, False)]}]}
        indexed, plain = self.same(doc)
        got = indexed.advisories_for("zed", "pypi")
        self.assertEqual([(a["cve"], p["name"]) for a, p in got], [("A", "zed"), ("A", "python-zed"), ("B", "zed"),
                                                                   ("C", "py-zed")])

    def test_a_package_listed_under_two_of_the_names_it_is_found_by_comes_back_once(self):
        doc = {"bundleVersion": 1, "advisories": [{"cve": "A", "packages": [package("python-zed", None, False)]}]}
        indexed, _ = self.same(doc)
        self.assertEqual(len(indexed.advisories_for("zed", "pypi")), 1)

    def test_an_empty_bundle(self):
        for doc in ({"bundleVersion": 1}, {"bundleVersion": 1, "advisories": []}, {"bundleVersion": 1, "advisories": ["x"]}):
            with self.subTest(doc=doc):
                indexed, _ = self.same(doc)
                self.assertEqual(len(indexed.advisories), 0)
                self.assertFalse(indexed.advisories)

    def test_random_bundles(self):
        for seed in range(60):
            with self.subTest(seed=seed):
                self.same(random_doc(seed))

    def test_the_same_advisory_objects_come_back_while_cached(self):
        indexed = self.open(dump(fixture())[0])
        first = indexed.advisories_for("lodash", "npm")
        second = indexed.advisories_for("lodash", "npm")
        self.assertTrue(all(a is c and b is d for (a, b), (c, d) in zip(first, second)))
        self.assertIs(first[0][1], first[0][0]["packages"][0])

    def test_the_sequence(self):
        indexed = self.open(dump(fixture())[0])
        plain = sca.CveBundle(fixture())
        self.assertEqual(indexed.advisories[0], plain.advisories[0])
        self.assertEqual(indexed.advisories[-1], plain.advisories[-1])
        self.assertEqual(indexed.advisories[1:3], plain.advisories[1:3])
        with self.assertRaises(IndexError):
            indexed.advisories[len(plain.advisories)]
        with self.assertRaises(IndexError):
            indexed.advisories[-len(plain.advisories) - 1]

    def test_hostile_content_is_cleaned_the_way_the_json_bundle_cleans_it(self):
        doc = {"bundleVersion": 1, "advisories": [
            {"cve": ["x"], "cvss": "9.9", "epss": True, "cwes": [1, "CWE-1"], "refs": "no", "knownExploited": "yes",
             "packages": [{"name": "lodash", "ecosystem": "npm", "exact": True, "ranges": [{"toVersion": 5}], "vendor": 3}]}]}
        indexed, plain = self.same(doc)
        (adv, pkg), = indexed.advisories_for("lodash", "npm")
        self.assertEqual((adv["cvss"], adv["epss"], adv["cwes"], adv["knownExploited"]), (None, None, ["CWE-1"], False))
        self.assertEqual(adv["cve"], "advisory#1")

    def test_the_cli_loader_picks_the_class_from_the_first_bytes(self):
        data, _ = dump(fixture())
        loaded = sca.CveBundle.load(self.write(data))
        self.opened.append(loaded)
        self.assertIsInstance(loaded, sca_index.IndexedBundle)
        self.assertIsInstance(sca.CveBundle.load(self.write(json.dumps(fixture()).encode(), "b.json")), sca.CveBundle)
        self.assertEqual(sca.INDEX_MAGIC, sca_index.MAGIC)
        self.assertTrue(sca_index.is_index(data[:8]) and not sca_index.is_index(b"{\"bundleV"))

    def test_a_file_that_is_neither_is_the_old_error(self):
        for data in (b"", b"LZSCA", b"not json at all", b"[1, 2]"):
            with self.subTest(data=data), self.assertRaises(ValueError):
                sca.CveBundle.load(self.write(data))
        with self.assertRaisesRegex(ValueError, "cannot read CVE bundle"):
            sca.CveBundle.load(self.write(b"not json at all"))

    def test_a_directory_and_a_missing_file(self):
        for path in (self.dir, self.path("nowhere")):
            with self.assertRaisesRegex(ValueError, "cannot read CVE bundle"):
                sca.CveBundle.load(path)


# ---------------------------------------------------------------------------
# It reads little
# ---------------------------------------------------------------------------

class LazyTests(Base):
    def counted(self, doc=None):
        data, _ = dump(doc or fixture())
        counting = CountingFile(open(self.write(data), "rb"))
        bundle = sca_index.IndexedBundle(counting, "counted")
        self.opened.append(bundle)
        return bundle, counting, len(data)

    def test_opening_reads_the_header_the_metadata_and_two_tables(self):
        bundle, counting, size = self.counted()
        self.assertEqual(counting.reads, 4)
        records = bundle._blobs_len
        self.assertEqual(counting.bytes, size - records)

    def test_a_name_the_bundle_does_not_have_costs_no_read(self):
        bundle, counting, _ = self.counted()
        before = counting.reads
        for name in ("nothing-like-it", "left-pad", "express"):
            for eco in ECOSYSTEMS:
                self.assertEqual(bundle.advisories_for(name, eco), [])
        self.assertEqual(counting.reads, before)

    def test_a_name_it_has_costs_its_entry_and_its_advisories_once(self):
        bundle, counting, _ = self.counted()
        before = counting.reads
        found = bundle.advisories_for("lodash", "npm")
        self.assertEqual(counting.reads - before, 1 + len({a["cve"] for a, _ in found}))
        before = counting.reads
        self.assertEqual(bundle.advisories_for("lodash", "npm"), found)
        self.assertEqual(counting.reads, before)                            # all of it cached

    def test_a_large_bundle_opens_by_reading_a_small_part_of_it(self):
        doc = {"bundleVersion": 1, "advisories": [
            {"cve": "CVE-2099-%d" % i, "title": "x" * 300, "packages": [package("pkg-%d" % i, ranges=[rng("0", "1.%d" % i)])]}
            for i in range(3000)]}
        bundle, counting, size = self.counted(doc)
        self.assertLess(counting.bytes, size * 0.25)
        before = counting.bytes
        self.assertEqual(len(bundle.advisories_for("pkg-1234", "npm")), 1)
        self.assertLess(counting.bytes - before, 4096)

    def test_the_caches_have_a_bound(self):
        doc = {"bundleVersion": 1, "advisories": [
            {"cve": "CVE-2099-%d" % i, "packages": [package("pkg-%d" % i)]} for i in range(50)]}
        plain = sca.CveBundle(doc)
        with mock.patch.object(sca_index, "ADVISORY_CACHE", 5), mock.patch.object(sca_index, "POSTING_CACHE", 5):
            bundle, _, _ = self.counted(doc)
            for i in range(50):
                self.assertEqual(bundle.advisories_for("pkg-%d" % i, "npm"), plain.advisories_for("pkg-%d" % i, "npm"))
            self.assertLessEqual(len(bundle._advs), 5)
            self.assertLessEqual(len(bundle._posts), 5)
            self.assertEqual(bundle.advisories_for("pkg-0", "npm"), plain.advisories_for("pkg-0", "npm"))

    def test_threads_get_the_answers_one_thread_gets(self):
        doc = random_doc(11)
        doc["advisories"] = [dict(a, cve="CVE-%d" % i) if isinstance(a, dict) else a for i, a in enumerate(doc["advisories"])]
        bundle = self.open(dump(doc)[0])
        want = {(n, e): bundle.advisories_for(n, e) for n in NAMES for e in ECOSYSTEMS}
        fresh = self.open(dump(doc)[0])
        errors = []

        def work(seed):
            rnd = random.Random(seed)
            try:
                for _ in range(300):
                    n, e = rnd.choice(NAMES), rnd.choice(ECOSYSTEMS)
                    if fresh.advisories_for(n, e) != want[(n, e)]:
                        errors.append((n, e))
            except Exception as exc:                      # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(s,)) for s in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_a_closed_bundle_says_so(self):
        bundle = self.open(dump(fixture())[0])
        bundle.close()
        bundle.close()                                                       # twice is harmless
        with self.assertRaisesRegex(ValueError, "is closed"):
            bundle.advisories_for("lodash", "npm")
        with sca_index.IndexedBundle.open(self.write(dump(fixture())[0])) as b:
            self.assertTrue(b.advisories_for("lodash", "npm"))
        with self.assertRaisesRegex(ValueError, "is closed"):
            b.advisories_for("lodash", "npm")


# ---------------------------------------------------------------------------
# The writer
# ---------------------------------------------------------------------------

class WriterTests(Base):
    def test_the_bytes_are_the_same_every_time(self):
        self.assertEqual(dump(fixture())[0], dump(fixture())[0])
        shuffled = fixture()
        shuffled["advisories"][0] = dict(reversed(list(shuffled["advisories"][0].items())))
        self.assertEqual(dump(shuffled)[0], dump(fixture())[0])             # key order in the document is not content

    def test_the_summary(self):
        data, summary = dump(fixture())
        plain = sca.CveBundle(fixture())                      # the JSON bundle's own indexes are the oracle
        want = {"advisories": len(plain.advisories), "keys": len(plain._index) + len(plain._exact),
                "postings": sum(map(len, plain._index.values())) + sum(map(len, plain._exact.values()))}
        self.assertEqual(want, {"advisories": 11, "keys": 9, "postings": 14})
        self.assertEqual(summary["bytes"], len(data))
        self.assertEqual({k: summary[k] for k in want}, want)
        self.assertEqual(self.open(data).verify(), want)

    def test_what_a_document_cannot_say_is_refused(self):
        for doc in ({"bundleVersion": 2, "advisories": []}, [], {"bundleVersion": 1, "advisories": {}}):
            with self.subTest(doc=doc), self.assertRaises(ValueError):
                dump(doc)
        with self.assertRaises(ValueError):                                  # not JSON: NaN
            dump({"bundleVersion": 1, "advisories": [{"cve": "A", "cvss": float("nan")}]})

    def test_a_record_a_reader_would_refuse_is_not_written(self):
        doc = {"bundleVersion": 1, "advisories": [{"cve": "A", "title": "x" * 5000, "packages": [package("p")]}]}
        with mock.patch.object(sca_index, "MAX_RECORD_BYTES", 1000), self.assertRaisesRegex(ValueError, "advisory 0"):
            dump(doc)
        with mock.patch.object(sca_index, "MAX_STORED_BYTES", 10), self.assertRaisesRegex(ValueError, "advisory 0"):
            dump(doc)
        with mock.patch.object(sca_index, "MAX_META_BYTES", 10), self.assertRaisesRegex(ValueError, "metadata"):
            dump(doc)

    def test_two_names_with_one_digest_are_refused(self):
        doc = {"bundleVersion": 1, "advisories": [{"cve": "A", "packages": [package("p"), package("q")]}]}
        with mock.patch.object(sca_index, "key_digest", lambda key: b"x" * 16), self.assertRaisesRegex(ValueError, "digest"):
            dump(doc)

    def test_keys_are_the_ones_the_json_bundle_looks_up(self):
        self.assertEqual(sca_index.keys_of_package(package("Django", "pypi")), ["E\0pypi\0django"])
        self.assertEqual(sca_index.keys_of_package(package("JSONStream", "npm")), ["E\0npm\0JSONStream"])
        self.assertEqual(sca_index.keys_of_package(package("foo_bar", None, False)), ["L\0foo-bar"])
        self.assertEqual(sca_index.keys_of_package(package("foo", "pypi", False)), ["L\0foo", "L\0py-foo", "L\0python-foo"])
        self.assertEqual(sca_index.keys_of_package(package("python-", None, False)), [])
        self.assertEqual(sca_index.keys_for_lookup("foo", "pypi"), ["L\0foo", "L\0py-foo", "L\0python-foo", "E\0pypi\0foo"])
        every = ["E\0npm\0foo", "E\0pypi\0foo", "E\0go\0foo", "E\0crates\0foo"]
        self.assertEqual(sca_index.keys_for_lookup("foo", None)[-4:], every)
        self.assertEqual(sca_index.keys_for_lookup("foo", "maven")[-4:], every)
        self.assertEqual(sca_index.keys_for_lookup("Foo_Bar", "crates"), ["E\0crates\0foo-bar"])      # (no loose keys: only an exact entry names a crate)
        self.assertEqual(sca_index.keys_for_lookup("github.com/A/b", "go"), ["E\0go\0github.com/A/b"])
        self.assertEqual(sca_index.keys_of_package(package("Foo_Bar", "crates")), ["E\0crates\0foo-bar"])
        self.assertEqual(sca_index.keys_of_package(package("github.com/A/b", "go")), ["E\0go\0github.com/A/b"])
        self.assertEqual(len(sca_index.key_digest("odd\ud800name")), 16)           # a lone surrogate is a name too

    def test_the_header(self):
        self.assertEqual(sca_index.HEADER.size, 104)
        self.assertEqual((sca_index.ADV_ENTRY.size, sca_index.KEY_ENTRY.size), (16, 32))
        data, _ = dump(fixture())
        self.assertEqual(data[:8], b"LZSCAIDX")
        head = dict(zip(HEAD_FIELDS, sca_index.HEADER.unpack_from(data)))
        self.assertEqual((head["format"], head["flags"], head["file_len"]), (1, 0, len(data)))
        self.assertEqual(head["meta_off"], 104)


# ---------------------------------------------------------------------------
# It fails closed
# ---------------------------------------------------------------------------

class DamageTests(Base):
    def setUp(self):
        super().setUp()
        self.data, _ = dump(fixture())

    def refused(self, data, what="a damaged file"):
        """The file cannot be opened, or opens and fails its check: it never answers."""
        try:
            b = self.open(data)
            b.verify()
        except ValueError:
            return True
        self.fail("%s was read" % what)

    def test_a_file_cut_anywhere(self):
        for n in range(len(self.data)):
            with self.subTest(length=n), self.assertRaises(ValueError):
                self.open(self.data[:n])

    def test_a_file_with_something_added(self):
        with self.assertRaisesRegex(sca_index.BundleDamaged, "truncated or extended"):
            self.open(self.data + b"\0")

    def test_a_byte_changed_anywhere(self):
        for i in range(len(self.data)):
            changed = bytearray(self.data)
            changed[i] ^= 1 << (i % 8)
            with self.subTest(offset=i):
                self.refused(bytes(changed), "a file changed at %d" % i)

    def test_a_changed_byte_never_changes_an_answer(self):
        want = self.lookups(self.open(self.data))
        for i in range(0, len(self.data), 7):
            changed = bytearray(self.data)
            changed[i] ^= 0x40
            try:
                got = self.lookups(self.open(bytes(changed)))
            except ValueError:
                continue
            self.assertEqual(got, want, i)

    def test_a_format_it_does_not_know(self):
        with self.assertRaisesRegex(ValueError, r"format 2, and this Lazaret reads format 1: rebuild it with "
                                                r"`lazaret-sca --update-bundle --bundle-format index`"):
            self.open(patch_header(self.data, format=2))
        with self.assertRaises(ValueError):                                       # without the checksum made right
            self.open(self.data[:8] + struct.pack("<I", 2) + self.data[12:])

    def test_not_an_index(self):
        with self.assertRaises(sca_index.NotAnIndex):
            self.open(b'{"bundleVersion": 1}' + b" " * 100)
        with self.assertRaises(sca_index.NotAnIndex):
            self.open(b"")

    def test_flags_and_limits(self):
        for fields in ({"flags": 1}, {"n_adv": sca_index.MAX_ADVISORIES + 1}, {"n_keys": sca_index.MAX_KEYS + 1},
                       {"meta_len": sca_index.MAX_META_BYTES + 1}, {"file_len": len(self.data) + 1},
                       {"n_adv": 2 ** 63}, {"n_keys": 2 ** 64 - 1}, {"blobs_off": len(self.data) + 8}):
            with self.subTest(fields=fields), self.assertRaises(sca_index.BundleDamaged):
                self.open(patch_header(self.data, **fields))

    def test_parts_that_are_not_laid_out_as_the_writer_lays_them_out(self):
        head = dict(zip(HEAD_FIELDS, sca_index.HEADER.unpack_from(self.data)))
        for name in ("meta_off", "advtab_off", "keytab_off"):
            for delta in (-1, 1, 16):
                with self.subTest(name=name, delta=delta), self.assertRaises(sca_index.BundleDamaged):
                    self.open(patch_header(self.data, **{name: head[name] + delta}))

    def test_a_key_table_out_of_order_is_refused_whatever_its_checksum(self):
        p = parse(self.data)
        size = sca_index.KEY_ENTRY.size
        a, b = bytes(p["keytab"][:size]), bytes(p["keytab"][size:2 * size])
        p["keytab"][:size], p["keytab"][size:2 * size] = b, a
        with self.assertRaisesRegex(sca_index.BundleDamaged, "not in order"):
            self.open(build(p))
        p = parse(self.data)
        p["keytab"][size:2 * size] = p["keytab"][:size]                            # a digest twice
        with self.assertRaisesRegex(sca_index.BundleDamaged, "not in order"):
            self.open(build(p))

    def test_records_that_are_not_what_their_table_entry_says(self):
        b = self.open(self.data)
        cases = {
            "not zlib": b"this is not a zlib stream",
            "cut short": stored({"k": "x", "p": []})[:-3],
            "bytes after the stream": stored({"k": "x", "p": []}) + b"x",
            "not json": zlib.compress(b"{nope"),
            "not utf-8": zlib.compress(b"\xff\xfe\xfd"),
            "too deep": zlib.compress(b"[" * 100000 + b"]" * 100000),
            "not an object": stored([1, 2, 3]),
        }
        key = "E\0npm\0lodash"
        for what, record in cases.items():
            with self.subTest(what=what):
                bad = self.open(replace_record(self.data, record, key=key))
                with self.assertRaises(sca_index.BundleDamaged):
                    bad.advisories_for("lodash", "npm")
                self.assertEqual(bad.advisories_for("django", "pypi"), b.advisories_for("django", "pypi"))
        for what, record in cases.items():
            with self.subTest(what="advisory, " + what):
                bad = self.open(replace_record(self.data, record, advisory=0))
                with self.assertRaises(sca_index.BundleDamaged):
                    bad.advisories_for("lodash", "npm")

    def test_a_record_that_says_it_is_another(self):
        key = "E\0npm\0lodash"
        for record in ({"k": "E\0npm\0other", "p": [[0, 0, 0]]}, {"p": [[0, 0, 0]]}, {"k": key}, {"k": key, "p": "no"}):
            with self.subTest(record=record), self.assertRaises(sca_index.BundleDamaged):
                self.open(replace_record(self.data, stored(record), key=key)).advisories_for("lodash", "npm")
        for record in ({"n": 5, "a": {"cve": "A"}}, {"a": {"cve": "A"}}, {"n": 0}, {"n": 0, "a": "no"}, {"n": 0, "a": None}):
            with self.subTest(record=record), self.assertRaises(sca_index.BundleDamaged):
                self.open(replace_record(self.data, stored(record), advisory=0)).advisories_for("lodash", "npm")

    def test_a_posting_that_points_nowhere(self):
        key = "E\0npm\0lodash"
        bad_items = ([0, 99, 0], [0, 0, 99], [-1, 0, 0], [0, 0], [0, 0, 0, 0], ["0", 0, 0], [True, 0, 0], [0, 0, 1.0], "x", 3)
        for item in bad_items:
            with self.subTest(item=item), self.assertRaises(sca_index.BundleDamaged):
                self.open(replace_record(self.data, stored({"k": key, "p": [item]}), key=key)).advisories_for("lodash", "npm")

    def test_a_record_that_inflates_to_more_than_a_record_may(self):
        key = "E\0npm\0lodash"
        bomb = zlib.compress(b"\0" * (64 << 20), 9)
        self.assertLess(len(bomb), 100000)
        bad = self.open(replace_record(self.data, bomb, key=key))
        tracemalloc.start()
        try:
            with self.assertRaisesRegex(sca_index.BundleDamaged, "within %d bytes" % sca_index.MAX_RECORD_BYTES):
                bad.advisories_for("lodash", "npm")
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, sca_index.MAX_RECORD_BYTES * 3)                       # never inflated to the end
        exact = zlib.compress(b" " * sca_index.MAX_RECORD_BYTES + b"1")             # one byte over
        with self.assertRaises(sca_index.BundleDamaged):
            self.open(replace_record(self.data, exact, key=key)).advisories_for("lodash", "npm")
        with mock.patch.object(sca_index, "MAX_STORED_BYTES", 10), self.assertRaisesRegex(
                sca_index.BundleDamaged, "lies outside"):
            self.open(self.data).advisories_for("lodash", "npm")

    def test_a_record_that_lies_outside_the_records(self):
        p = parse(self.data)
        p["keytab"][16:24] = struct.pack("<Q", len(p["blobs"]) - 1)                  # the first entry's offset
        bad = self.open(build(p))
        with self.assertRaisesRegex(sca_index.BundleDamaged, "lies outside the records"):
            for name in NAMES:
                for eco in ECOSYSTEMS:
                    bad.advisories_for(name, eco)

    def test_metadata_that_is_not_the_files(self):
        p = parse(self.data)
        meta = json.loads(p["meta"])
        for what, change in {
            "format": {"format": 2}, "bundleVersion": {"bundleVersion": 2}, "advisories": {"advisories": 99},
            "keys": {"keys": 0}, "postings": {"postings": 1}, "generatedAt": {"generatedAt": 5},
            "sources": {"sources": "osv"}, "source item": {"sources": [1]}, "counts": {"counts": []},
            "warnings": {"warnings": []}, "warning count": {"warnings": {"x": "1"}},
            "zero warnings": {"warnings": {"x": 0}}, "bool warning": {"warnings": {"x": True}},
            "huge warning": {"warnings": {"x": 1 << 41}}, "warning at the limit": {"warnings": {"x": 1 << 40}},
        }.items():
            q = dict(p, meta=json.dumps(dict(meta, **change), sort_keys=True).encode())
            with self.subTest(what=what), self.assertRaises(sca_index.BundleDamaged):
                self.open(build(q))
        with self.assertRaises(sca_index.BundleDamaged):
            self.open(build(dict(p, meta=b"[1]")))
        with self.assertRaises(sca_index.BundleDamaged):
            self.open(build(dict(p, meta=b"not json")))

    def test_the_check_finds_what_a_lookup_does_not(self):
        key = "E\0npm\0lodash"
        good = json.loads(zlib.decompress(self.chunk(key)))
        # a name's entry that lists a package under a name it is not indexed under
        wrong = {"k": key, "p": good["p"] + [[999, 3, 0]]}
        with self.assertRaises(sca_index.BundleDamaged):
            self.open(replace_record(self.data, stored(wrong), key=key)).verify()
        # one that is out of order
        shuffled = {"k": key, "p": list(reversed(good["p"]))}
        with self.assertRaisesRegex(sca_index.BundleDamaged, "not in order"):
            self.open(replace_record(self.data, stored(shuffled), key=key)).verify()
        # one that forgets a package (the name would clear a dependency it should not)
        forgot = {"k": key, "p": good["p"][:-1]}
        with self.assertRaisesRegex(sca_index.BundleDamaged, "name entries"):
            self.open(replace_record(self.data, stored(forgot), key=key)).verify()
        # one whose package number is past the advisory's
        past = {"k": key, "p": good["p"][:-1] + [[good["p"][-1][0], good["p"][-1][1], 50]]}
        with self.assertRaises(sca_index.BundleDamaged):
            self.open(replace_record(self.data, stored(past), key=key)).verify()
        # an empty entry
        with self.assertRaisesRegex(sca_index.BundleDamaged, "no packages"):
            self.open(replace_record(self.data, stored({"k": key, "p": []}), key=key)).verify()
        # an entry filed under another digest
        other = "E\0npm\0lodahs"
        with self.assertRaisesRegex(sca_index.BundleDamaged, "wrong digest"):
            self.open(replace_record(self.data, stored({"k": other, "p": good["p"]}), key=key)).verify()

    def test_the_check_finds_a_repeated_entry_and_a_package_or_advisory_that_is_not_there(self):
        key = "E\0npm\0lodash"
        good = json.loads(zlib.decompress(self.chunk(key)))["p"]
        self.assertGreaterEqual(len(good), 2)
        # the same package listed twice and another forgotten: the count is right, the order is not
        twice = {"k": key, "p": [good[0], good[0]] + good[2:]}
        with self.assertRaisesRegex(sca_index.BundleDamaged, "not in order"):
            self.open(replace_record(self.data, stored(twice), key=key)).verify()
        # a package number one past the advisory's last
        order, n, _j = good[-1]
        count = len(self.open(self.data).advisories[n]["packages"])
        edge = {"k": key, "p": good[:-1] + [[order, n, count]]}
        with self.assertRaises(sca_index.BundleDamaged):
            self.open(replace_record(self.data, stored(edge), key=key)).verify()
        # an advisory number one past the last advisory
        total = len(self.open(self.data).advisories)
        beyond = {"k": key, "p": good[:-1] + [[order, total, 0]]}
        with self.assertRaises(sca_index.BundleDamaged):
            self.open(replace_record(self.data, stored(beyond), key=key)).verify()
        with self.assertRaises(sca_index.BundleDamaged):
            self.open(replace_record(self.data, stored(beyond), key=key)).advisories_for("lodash", "npm")

    def chunk(self, key):
        p = parse(self.data)
        digest = sca_index.key_digest(key)
        size = sca_index.KEY_ENTRY.size
        at = next(i for i in range(0, len(p["keytab"]), size) if bytes(p["keytab"][i:i + 16]) == digest)
        _, off, length, _ = sca_index.KEY_ENTRY.unpack_from(p["keytab"], at)
        return p["blobs"][off:off + length]

    def test_a_good_file_passes_the_check(self):
        for seed in range(25):
            with self.subTest(seed=seed):
                self.assertEqual(sca_index.verify_path(self.write(dump(random_doc(seed))[0]))["advisories"],
                                 len(sca.CveBundle(random_doc(seed)).advisories))
        self.assertEqual(sca_index.verify_path(self.write(self.data))["keys"], 9)


# ---------------------------------------------------------------------------
# The edges: exactly at a limit, and a file that changes under the reader
# ---------------------------------------------------------------------------

class ShortFile:
    """A file whose reads, from the `short_from`th on, come back one byte short: what a file cut off between the
    reader's size check and its read looks like."""

    def __init__(self, fh, short_from=None):
        self.fh, self.reads, self.short_from = fh, 0, short_from

    def fileno(self):
        return self.fh.fileno()

    def seek(self, *args):
        return self.fh.seek(*args)

    def read(self, n=-1):
        data = self.fh.read(n)
        self.reads += 1
        if self.short_from is not None and self.reads >= self.short_from:
            return data[:-1]
        return data

    def close(self):
        self.fh.close()


class EdgeTests(Base):
    def setUp(self):
        super().setUp()
        self.data, _ = dump(fixture())

    def records(self):
        """-> [(stored length, inflated length)] of every record of `self.data`."""
        p = parse(self.data)
        out = []
        for table, entry in ((p["advtab"], sca_index.ADV_ENTRY), (p["keytab"], sca_index.KEY_ENTRY)):
            for i in range(0, len(table), entry.size):
                fields = entry.unpack_from(table, i)
                off, length = fields[-3:-1] if entry is sca_index.ADV_ENTRY else fields[1:3]
                stored_bytes = p["blobs"][off:off + length]
                out.append((length, len(zlib.decompress(stored_bytes))))
        return out

    def test_the_limits_are_the_ones_the_format_documents(self):
        self.assertEqual((sca_index.MAX_RECORD_BYTES, sca_index.MAX_STORED_BYTES, sca_index.MAX_META_BYTES),
                         (8 << 20, 8 << 20, 16 << 20))
        self.assertEqual((sca_index.MAX_ADVISORIES, sca_index.MAX_KEYS), (5_000_000, 8_000_000))

    def test_a_record_of_exactly_the_most_a_reader_accepts_is_written(self):
        obj = {"a": "x" * 3000, "b": list(range(300))}
        raw = sca_index._dumps(obj)
        packed = zlib.compress(raw, sca_index.LEVEL)
        with mock.patch.object(sca_index, "MAX_RECORD_BYTES", len(raw)):
            self.assertEqual(sca_index._pack(obj, "t"), packed)
        with mock.patch.object(sca_index, "MAX_RECORD_BYTES", len(raw) - 1), self.assertRaisesRegex(ValueError, "^t is "):
            sca_index._pack(obj, "t")
        with mock.patch.object(sca_index, "MAX_STORED_BYTES", len(packed)):
            self.assertEqual(sca_index._pack(obj, "t"), packed)
        with mock.patch.object(sca_index, "MAX_STORED_BYTES", len(packed) - 1), self.assertRaisesRegex(
                ValueError, "stored"):
            sca_index._pack(obj, "t")

    def test_a_record_of_exactly_the_most_a_reader_accepts_is_read(self):
        records = self.records()
        biggest = max(inflated for _stored, inflated in records)
        longest = max(stored_len for stored_len, _inflated in records)
        with mock.patch.object(sca_index, "MAX_RECORD_BYTES", biggest):
            self.assertEqual(self.open(self.data).verify()["keys"], 9)
        with mock.patch.object(sca_index, "MAX_RECORD_BYTES", biggest - 1), self.assertRaises(sca_index.BundleDamaged):
            self.open(self.data).verify()
        with mock.patch.object(sca_index, "MAX_STORED_BYTES", longest):
            self.assertEqual(self.open(self.data).verify()["keys"], 9)
        with mock.patch.object(sca_index, "MAX_STORED_BYTES", longest - 1), self.assertRaises(sca_index.BundleDamaged):
            self.open(self.data).verify()

    def test_counts_exactly_at_a_limit_open_and_one_over_do_not(self):
        head = dict(zip(HEAD_FIELDS, sca_index.HEADER.unpack_from(self.data)))
        for limit, field in (("MAX_ADVISORIES", "n_adv"), ("MAX_KEYS", "n_keys"), ("MAX_META_BYTES", "meta_len")):
            with self.subTest(limit=limit):
                with mock.patch.object(sca_index, limit, head[field]):
                    self.assertTrue(self.open(self.data).verify())
                with mock.patch.object(sca_index, limit, head[field] - 1), self.assertRaisesRegex(
                        sca_index.BundleDamaged, "over the limits"):
                    self.open(self.data)

    def test_the_temporary_file_is_closed_whether_the_write_works_or_not(self):
        made = []
        real = tempfile.TemporaryFile

        def spy(*args, **kwargs):
            made.append(real(*args, **kwargs))
            return made[-1]

        with mock.patch.object(sca_index.tempfile, "TemporaryFile", spy):
            dump(fixture())
            with mock.patch.object(sca_index, "MAX_STORED_BYTES", 10), self.assertRaises(ValueError):
                dump(fixture())
        self.assertEqual(len(made), 2)
        self.assertTrue(all(f.closed for f in made))

    def test_a_closed_bundle_gives_no_advisory_even_one_it_has_cached(self):
        bundle = self.open(self.data)
        first = bundle.advisories[0]
        self.assertIs(bundle.advisories[0], first)
        bundle.close()
        with self.assertRaisesRegex(ValueError, "is closed"):
            bundle.advisories[0]
        with self.assertRaisesRegex(ValueError, "is closed"):
            bundle.advisories[0:2]
        with self.assertRaisesRegex(ValueError, "is closed"):
            bundle.verify()
        with self.assertRaises(IndexError):                                  # (a bad index is still a bad index)
            bundle.advisories[10 ** 6]

    def test_a_bundle_closed_by_another_thread_after_the_check_says_it_is_closed(self):
        bundle = self.open(self.data)
        bundle.close()                                                        # (the check at the door has passed already)
        with self.assertRaisesRegex(ValueError, "is closed"):
            bundle._advisory(0)
        with self.assertRaisesRegex(ValueError, "is closed"):
            bundle._posting("E\0npm\0lodash")

    def test_a_closed_bundle_with_nothing_in_it_is_still_closed(self):
        bundle = self.open(dump({"bundleVersion": 1, "advisories": []})[0])
        self.assertEqual(bundle.verify(), {"advisories": 0, "keys": 0, "postings": 0})
        bundle.close()
        with self.assertRaisesRegex(ValueError, "is closed"):
            bundle.verify()
        with self.assertRaisesRegex(ValueError, "is closed"):
            bundle.advisories_for("lodash", "npm")

    @unittest.skipIf(os.name == "nt", "no /dev/null")
    def test_a_file_that_is_not_a_regular_file_is_damaged_not_empty(self):
        with self.assertRaisesRegex(sca_index.BundleDamaged, "not a regular file"):
            sca_index.IndexedBundle.open("/dev/null")

    def test_a_file_cut_off_after_the_size_was_checked(self):
        path = self.write(self.data)
        for read, what in ((2, "the metadata"), (3, "the advisory table"), (4, "the key table")):
            with self.subTest(what=what), self.assertRaisesRegex(sca_index.BundleDamaged, "%s is cut short" % what):
                sca_index.IndexedBundle(ShortFile(open(path, "rb"), short_from=read), path)

    def test_a_record_cut_off_after_the_file_was_opened(self):
        path = self.write(self.data)
        fh = ShortFile(open(path, "rb"))
        bundle = sca_index.IndexedBundle(fh, path)
        self.opened.append(bundle)
        fh.short_from = fh.reads + 1
        with self.assertRaisesRegex(sca_index.BundleDamaged, "is cut short"):
            bundle.verify()

    def test_a_package_number_exactly_one_past_an_advisorys_packages_is_refused(self):
        key = "E\0npm\0lodash"
        good = json.loads(zlib.decompress(self.records_of(key)))
        order, n, _ = good["p"][-1]
        count = len(self.open(self.data).advisories[n]["packages"])
        with self.assertRaisesRegex(sca_index.BundleDamaged, "points past"):
            self.open(replace_record(self.data, stored({"k": key, "p": good["p"][:-1] + [[order, n, count]]}),
                                     key=key)).advisories_for("lodash", "npm")
        last = good["p"][:-1] + [[order, n, count - 1]]                       # (the last package is the last one)
        self.assertTrue(self.open(replace_record(self.data, stored({"k": key, "p": last}), key=key))
                        .advisories_for("lodash", "npm"))

    def records_of(self, key):
        p = parse(self.data)
        digest = sca_index.key_digest(key)
        size = sca_index.KEY_ENTRY.size
        at = next(i for i in range(0, len(p["keytab"]), size) if bytes(p["keytab"][i:i + 16]) == digest)
        _, off, length, _ = sca_index.KEY_ENTRY.unpack_from(p["keytab"], at)
        return p["blobs"][off:off + length]

    def test_a_name_s_entry_that_is_not_an_object_fails_the_check_and_does_not_crash_it(self):
        key = "E\0npm\0lodash"
        for record in ([1, 2], "x", 3, None):
            with self.subTest(record=record), self.assertRaisesRegex(sca_index.BundleDamaged, "wrong digest"):
                self.open(replace_record(self.data, stored(record), key=key)).verify()

    def test_a_header_and_metadata_that_agree_on_a_count_the_records_do_not_have_fail_the_check(self):
        p = parse(self.data)
        meta = json.loads(p["meta"])
        meta["postings"] += 1
        p["meta"] = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("ascii")
        bundle = self.open(build(p, n_post=p["head"]["n_post"] + 1))
        with self.assertRaisesRegex(sca_index.BundleDamaged, r"\(15 in the header\)"):
            bundle.verify()

    def test_the_caches_hold_what_they_are_told_to_and_drop_the_longest_unused(self):
        doc = {"bundleVersion": 1, "advisories": [
            {"cve": "CVE-2099-%d" % i, "packages": [package("pkg-%d" % i)]} for i in range(10)]}
        with mock.patch.object(sca_index, "ADVISORY_CACHE", 3), mock.patch.object(sca_index, "POSTING_CACHE", 3):
            bundle = self.open(dump(doc)[0])
            for i in range(6):
                bundle._advisory(i)
                bundle._posting("E\0npm\0pkg-%d" % i)
            self.assertEqual((len(bundle._advs), len(bundle._posts)), (3, 3))
            self.assertEqual(list(bundle._advs), [3, 4, 5])
            bundle._advisory(3)                                                # (used again: no longer the oldest)
            bundle._posting("E\0npm\0pkg-3")
            bundle._advisory(6)
            bundle._posting("E\0npm\0pkg-6")
            self.assertEqual(list(bundle._advs), [5, 3, 6])
            self.assertEqual(list(bundle._posts), ["E\0npm\0pkg-5", "E\0npm\0pkg-3", "E\0npm\0pkg-6"])

    def test_a_file_that_is_not_opened_as_a_bundle_is_closed(self):
        for data in (b"", b"LZSCAIDX" + b"\0" * 50, self.data[:60], self.data[:-1], b'{"bundleVersion": 1}'):
            fh = ShortFile(open(self.write(data), "rb"))
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                sca_index.IndexedBundle(fh, "bundle")
            self.assertTrue(fh.fh.closed)

    def test_close_closes_the_file(self):
        path = self.write(self.data)
        fh = open(path, "rb")
        bundle = sca_index.IndexedBundle(fh, path)
        bundle.close()
        self.assertTrue(fh.closed)
        bundle.close()

    def test_the_module_commands_say_what_they_did_and_what_went_wrong(self):
        doc_path, target = self.path("doc.json"), self.path("built.lzx")
        with open(doc_path, "w", encoding="utf-8", newline="\n") as fh:
            sca_feeds.dump_bundle(fixture(), fh)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(sca_index.main(["build", doc_path, target]), 0, err.getvalue())
            with mock.patch.object(sys, "argv", ["sca_index", "check", target]):
                self.assertEqual(sca_index.main(), 0)                          # (no argument: the command line)
            self.assertEqual(sca_index.main(["check", self.path("nowhere")]), 4)
            self.assertEqual(sca_index.main([]), 2)
        self.assertRegex(out.getvalue(), r"^wrote .*built\.lzx \(\d+ bytes\)\nok: ")
        self.assertRegex(err.getvalue(), r"(?s)error: .*nowhere.*usage: python -m lazaret\.scanner\.sca_index")

    def test_the_module_runs_as_a_program_and_its_exit_code_is_the_answer(self):
        path = self.write(self.data)

        def run(*args):
            return subprocess.run([sys.executable, "-m", "lazaret.scanner.sca_index", *args], capture_output=True,
                                  encoding="utf-8", errors="replace", timeout=40)

        good = run("check", path)
        self.assertEqual((good.returncode, good.stdout.startswith("ok: ")), (0, True), good.stderr)
        bad = self.write(self.data[:-1])
        self.assertEqual(run("check", bad).returncode, sca.EXIT_BUNDLE)
        self.assertEqual(run().returncode, 2)


# ---------------------------------------------------------------------------
# Writing it, and the CLI
# ---------------------------------------------------------------------------

class WriteBundleTests(Base):
    def test_an_indexed_bundle_is_written_atomically_and_read_back(self):
        out = self.path("b.lzx")
        size = sca_feeds.write_bundle(fixture(), out, fmt="index")
        self.assertEqual(size, os.path.getsize(out))
        self.assertEqual(os.listdir(self.dir), ["b.lzx"])
        got = sca.CveBundle.load(out)
        self.assertIsInstance(got, sca_index.IndexedBundle)
        got.close()
        sca_feeds.write_bundle(fixture(), out, fmt="index")                          # replaces its own kind
        sca_feeds.write_bundle(fixture(), out, fmt="json")                           # or the other
        self.assertIsInstance(sca.CveBundle.load(out), sca.CveBundle)
        sca_feeds.write_bundle(fixture(), out, fmt="index")

    def test_a_bundle_that_fails_its_check_replaces_nothing(self):
        out = self.path("b.lzx")
        sca_feeds.write_bundle(fixture(), out, fmt="index")
        with open(out, "rb") as fh:
            before = fh.read()
        with mock.patch.object(sca_index, "verify_path", side_effect=sca_index.BundleDamaged("no")):
            with self.assertRaises(sca_feeds.BundleOutputError):
                sca_feeds.write_bundle(fixture(), out, fmt="index")
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertEqual(os.listdir(self.dir), ["b.lzx"])                           # no temporary file left

    def test_a_document_that_cannot_be_written_replaces_nothing(self):
        out = self.path("b.lzx")
        sca_feeds.write_bundle(fixture(), out, fmt="index")
        with open(out, "rb") as fh:
            before = fh.read()
        with self.assertRaises(sca_feeds.BundleOutputError):
            sca_feeds.write_bundle({"bundleVersion": 1, "advisories": [{"cve": "A", "cvss": float("nan")}]}, out, fmt="index")
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), before)
        self.assertEqual(os.listdir(self.dir), ["b.lzx"])

    def test_an_unknown_format(self):
        with self.assertRaises(ValueError):
            sca_feeds.write_bundle(fixture(), self.path("b"), fmt="yaml")
        self.assertEqual(os.listdir(self.dir), [])

    def test_the_warnings_of_the_document_are_passed_on(self):
        said = []
        sca_feeds.write_bundle(fixture(), self.path("b.lzx"), fmt="index", warn=said.append)
        self.assertEqual(said, sca.CveBundle(fixture()).warnings.lines())

    def test_what_may_be_overwritten(self):
        out = self.path("b.lzx")
        sca_feeds.write_bundle(fixture(), out, fmt="index")
        self.assertTrue(sca_feeds._looks_like_bundle(out))
        sca_feeds.write_bundle(fixture(), out, fmt="json")
        self.assertTrue(sca_feeds._looks_like_bundle(out))
        notes = self.path("notes.txt")
        with open(notes, "w", encoding="utf-8") as fh:
            fh.write("keep me")
        self.assertFalse(sca_feeds._looks_like_bundle(notes))
        with self.assertRaises(sca_feeds.BundleOutputError):
            sca_feeds.write_bundle(fixture(), notes, fmt="index")
        sca_feeds.write_bundle(fixture(), notes, force=True, fmt="index")
        self.assertTrue(sca_feeds._looks_like_bundle(notes))


class CliTests(feeds.Feeds):
    def setUp(self):
        super().setUp()
        self.out = self.path("out", "cve-bundle.lzx")
        os.makedirs(os.path.dirname(self.out))
        self.opened = []

    def main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = sca.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def update(self, *extra, bundle=None):
        return self.main("--update-bundle", "--bundle", bundle or self.out, "--osv-url", self.osv,
                         "--kev-url", self.kev, "--epss-url", self.epss, *extra)

    def project(self):
        root = self.path("proj")
        for rel, data in {
            "node_modules/lodash/package.json": {"name": "lodash", "version": "4.17.11"},
            "node_modules/@babel/core/package.json": {"name": "@babel/core", "version": "7.0.0"},
            "node_modules/lodahs/package.json": {"name": "lodahs", "version": "1.0.0"},
            "node_modules/vite/package.json": {"name": "vite", "version": "6.2.3"},
            "venv/lib/python3.12/site-packages/urllib3-2.0.5.dist-info/METADATA":
                "Metadata-Version: 2.1\nName: urllib3\nVersion: 2.0.5\n",
            "venv/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA":
                "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n",
        }.items():
            p = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(data if isinstance(data, str) else json.dumps(data))
        return root

    def report(self, bundle, root):
        path = self.path("out", "report-%s.json" % os.path.basename(bundle))
        rc, out, err = self.main(root, "--bundle", bundle, "--json", path, "-q")
        with open(path, encoding="utf-8") as fh:
            res = json.load(fh)
        return rc, out, err, res

    def test_update_writes_an_indexed_bundle(self):
        rc, out, err = self.update("--bundle-format", "index")
        self.assertEqual(rc, 0, err)
        self.assertIn("14 advisories", out)
        self.assertIn("OSV records that are not valid JSON (skipped): 1", err)
        with open(self.out, "rb") as fh:
            self.assertEqual(fh.read(8), b"LZSCAIDX")
        b = sca.CveBundle.load(self.out)
        self.addCleanup(b.close)
        self.assertEqual((len(b.advisories), b.warnings.lines()), (14, []))
        self.assertEqual(b.verify()["advisories"], 14)

    def test_a_scan_reads_the_two_formats_alike(self):
        json_path = self.path("out", "cve-bundle.json")
        self.assertEqual(self.update(bundle=json_path)[0], 0)
        self.assertEqual(self.update("--bundle-format", "index")[0], 0)
        root = self.project()
        rc1, out1, err1, res1 = self.report(json_path, root)
        rc2, out2, err2, res2 = self.report(self.out, root)
        self.assertEqual((rc1, rc2), (0, 0), (err1, err2))
        self.assertEqual(res1["issues"], res2["issues"])
        self.assertEqual(res1["conditions"], res2["conditions"])
        self.assertEqual(res1["pass"], res2["pass"])
        self.assertTrue(len(res2["issues"]) >= 4)
        self.assertEqual(out1.replace("cve-bundle.json", "X"), out2.replace("cve-bundle.lzx", "X"))

    def test_update_then_scan_in_one_run(self):
        root = self.project()
        rc, out, err = self.main(root, "--update-bundle", "--bundle-format", "index", "--bundle", self.out,
                                 "--osv-url", self.osv, "--kev-url", self.kev, "--epss-url", self.epss,
                                 "--no-json", "--ci")
        self.assertEqual(rc, 1, err)
        self.assertIn("✗ No known malicious packages", out)

    def test_the_format_is_for_updates(self):
        for argv in ([self.path("out"), "--bundle", "x", "--bundle-format", "index"],
                     ["--update-bundle", "--bundle-format", "yaml"]):
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as cm:
                    sca.main(argv)
                self.assertEqual(cm.exception.code, 2)
        self.assertEqual(self.update("--bundle-format", "json")[0], 0)
        with open(self.out, "rb") as fh:
            self.assertEqual(fh.read(1), b"{")

    def test_the_format_is_in_the_help(self):
        out = io.StringIO()
        with redirect_stdout(out), self.assertRaises(SystemExit):
            sca.main(["--help"])
        self.assertIn("--bundle-format", out.getvalue())

    def test_a_damaged_bundle_is_a_bundle_problem(self):
        self.assertEqual(self.update("--bundle-format", "index")[0], 0)
        with open(self.out, "rb") as fh:
            data = bytearray(fh.read())
        root = self.project()
        cut = self.path("out", "cut.lzx")
        with open(cut, "wb") as fh:
            fh.write(bytes(data[:len(data) // 2]))
        rc, _, err = self.main(root, "--bundle", cut, "--no-json")
        self.assertEqual(rc, 4)
        self.assertIn("damaged", err)

    def test_a_damaged_record_found_while_matching_is_a_bundle_problem_and_no_report(self):
        self.assertEqual(self.update("--bundle-format", "index")[0], 0)
        with open(self.out, "rb") as fh:
            data = fh.read()
        head = dict(zip(HEAD_FIELDS, sca_index.HEADER.unpack_from(data)))
        bad = bytearray(data)
        for i in range(head["blobs_off"], len(bad)):                              # every record loses a byte
            bad[i] ^= 0x01
        path = self.path("out", "bad.lzx")
        with open(path, "wb") as fh:
            fh.write(bytes(bad))
        report = self.path("out", "never.json")
        rc, out, err = self.main(self.project(), "--bundle", path, "--json", report)
        self.assertEqual(rc, 4, err)
        self.assertIn("damaged", err)
        self.assertFalse(os.path.exists(report))

    def test_the_bundle_is_closed_after_the_scan(self):
        self.assertEqual(self.update("--bundle-format", "index")[0], 0)
        closed = []
        real = sca_index.IndexedBundle.close
        with mock.patch.object(sca_index.IndexedBundle, "close", lambda self: (closed.append(1), real(self))[1]):
            rc, _, err = self.main(self.project(), "--bundle", self.out, "--no-json", "-q")
        self.assertEqual(rc, 0, err)
        self.assertEqual(closed, [1])

    def test_the_module_commands(self):
        json_path = self.path("out", "cve-bundle.json")
        self.assertEqual(self.update(bundle=json_path)[0], 0)
        out, err = io.StringIO(), io.StringIO()
        target = self.path("out", "built.lzx")
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(sca_index.main(["build", json_path, target]), 0, err.getvalue())
            self.assertEqual(sca_index.main(["check", target]), 0)
            self.assertEqual(sca_index.main(["info", target]), 0)
        self.assertIn("ok: 14 advisories", out.getvalue())
        self.assertIn("indexed CVE bundle: 14 advisories", out.getvalue())
        with open(target, "rb") as fh:
            data = bytearray(fh.read())
        data[-1] ^= 1
        with open(target, "wb") as fh:
            fh.write(bytes(data))
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            self.assertEqual(sca_index.main(["check", target]), 4)
            self.assertEqual(sca_index.main(["check", self.path("nowhere")]), 4)
            self.assertEqual(sca_index.main(["build", self.path("nowhere"), target]), 4)
            for argv in ([], ["build", "x"], ["check"], ["frob", "x"], ["info", "a", "b"]):
                self.assertEqual(sca_index.main(argv), 2, argv)


if __name__ == "__main__":
    unittest.main()
