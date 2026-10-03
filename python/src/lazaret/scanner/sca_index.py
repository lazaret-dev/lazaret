"""An indexed CVE bundle: read only the advisories a scan asks about (0.1.9, P-5).

`cve-bundle.json` is one JSON document of every advisory, and a scan parses all of it (about 92 MB, 6 to 7 s)
to look up a few hundred package names. This file holds the same bundle so that a scan reads a header and a
table of names, and then one small record for each name it looks up and one for each advisory that name has.
`CveBundle.load` (sca.py) tells the two apart by the first eight bytes and a scan cannot tell which it read:
`IndexedBundle.advisories_for` gives the same pairs, in the same order, as `CveBundle.advisories_for` does for
the document it was built from, and a test holds the two to that on random bundles.

Layout (little-endian; the header says where each part is, and the parts follow each other in this order):

    header (104 bytes)  magic LZSCAIDX, format, flags, file length, counts, the offset and length of each part,
                        a CRC-32 of the meta, the advisory table and the key table, and of the header itself
    meta                JSON: format, bundleVersion, generatedAt, sources, counts, the warnings counted when the
                        bundle was built, the feeds' own metadata
    advisory table      one 16-byte entry per advisory: offset into the records, stored length, CRC-32
    key table           one 32-byte entry per name, sorted by the first 16 bytes of SHA-256 of the name's key:
                        that digest, offset, stored length, CRC-32
    records             zlib streams: {"n": ordinal, "a": the advisory as the bundle document had it} and
                        {"k": key, "p": [[order, advisory, package], ...]}, in table order

A key is `E NUL ecosystem NUL name` for a package-manager name that matches exactly and `L NUL name` for a
loose (CPE product) name, one per `name_variants` entry. `order` is the package entry's position in the whole
bundle, and a lookup returns its pairs sorted by it: that is what makes the order the document's.

**Every way a file can be wrong is an error, and no error returns an answer.** The header, the meta and both
tables are checked against their CRCs when the file is opened, and the file's length against the header's;
the layout has to be the one the writer makes; the key table has to be strictly sorted (a bisect over an
unsorted table would miss a name and clear a dependency). Each record is checked against its CRC, inflated
within `MAX_RECORD_BYTES` (a record that inflates to more, or to less than its stream, or has bytes after it, is
refused), parsed with the bounded JSON reader, and must say which record it is. A posting has to name an
advisory and a package that exist. The advisory goes through `sca.normalize_advisory`, the function
`CveBundle` uses, so a hostile record is cleaned the same way from either file. All of that raises
`BundleDamaged` (a `ValueError`, so `lazaret-sca` exits 4 as for any bundle it cannot read); a version it does
not know raises `ValueError` saying so. CRCs find damage, not tampering: a bundle you do not trust can say
that nothing is vulnerable, as a JSON one can.

`python -m lazaret.scanner.sca_index build IN.json OUT | check FILE | info FILE`."""

import collections
import collections.abc
import hashlib
import json
import os
import stat
import struct
import sys
import tempfile
import threading
import zlib

from lazaret.scanner import core as lazaret
from lazaret.scanner import sca

__all__ = ["MAGIC", "FORMAT", "IndexedBundle", "BundleDamaged", "NotAnIndex", "dump_index", "verify_path",
           "is_index", "key_digest", "keys_of_package", "keys_for_lookup"]

MAGIC = b"LZSCAIDX"
FORMAT = 1
HEADER = struct.Struct("<8sII9Q4I")                  # 104 bytes
ADV_ENTRY = struct.Struct("<QII")                    # offset, stored length, crc32
KEY_ENTRY = struct.Struct("<16sQII")                 # digest, offset, stored length, crc32
DIGEST_BYTES = 16

#: One record inflated; the same bound the feeds' own reader keeps for an OSV record.
MAX_RECORD_BYTES = 8 << 20
#: One record as stored.
MAX_STORED_BYTES = 8 << 20
MAX_META_BYTES = 16 << 20
MAX_ADVISORIES = 5_000_000                           # sca_feeds.MAX_OSV_RECORDS
MAX_KEYS = 8_000_000                                 # a 256 MB key table
ADVISORY_CACHE = 20_000
POSTING_CACHE = 20_000
LEVEL = 6


class NotAnIndex(ValueError):
    """The file does not start with the indexed bundle's magic."""


class BundleDamaged(ValueError):
    """The indexed bundle is truncated, corrupt or not what the writer makes."""


def _damaged(path, what):
    return BundleDamaged("the indexed CVE bundle %s is damaged: %s" % (path, what))


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

def key_digest(key):
    return hashlib.sha256(key.encode("utf-8", "surrogatepass")).digest()[:DIGEST_BYTES]


def _loose_keys(name, ecosystem):
    return ["L\0" + k for k in sorted(sca.name_variants(name, ecosystem))]


def _exact_key(name, ecosystem):
    return "E\0%s\0%s" % (ecosystem, sca.exact_name_key(name, ecosystem))


def keys_of_package(pkg):
    """The keys a (normalized) package entry is indexed under: where `CveBundle` puts it in `_exact` or `_index`."""
    if pkg["exact"]:
        return [_exact_key(pkg["name"], pkg["ecosystem"])]
    return _loose_keys(pkg["name"], pkg["ecosystem"])


def keys_for_lookup(name, ecosystem=None):
    """The keys `CveBundle.advisories_for(name, ecosystem)` reads."""
    keys = _loose_keys(name, ecosystem)
    for eco in ((ecosystem,) if ecosystem in ("npm", "pypi") else ("npm", "pypi")):
        keys.append(_exact_key(name, eco))
    return keys


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def _dumps(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _pack(obj, what):
    raw = _dumps(obj)
    if len(raw) > MAX_RECORD_BYTES:
        raise ValueError("%s is %d bytes: over the %d a reader accepts" % (what, len(raw), MAX_RECORD_BYTES))
    data = zlib.compress(raw, LEVEL)
    if len(data) > MAX_STORED_BYTES:
        raise ValueError("%s is %d bytes stored: over the %d a reader accepts" % (what, len(data), MAX_STORED_BYTES))
    return data


def _assemble(fh, meta, adv_records, postings):
    """Write the file from a meta object, `adv_records` (the objects of the advisory records, in order) and
    `postings` ({key: [[order, advisory, package], ...]}). The records are written as given: the tests build
    damaged files through here with correct CRCs."""
    blobs = tempfile.TemporaryFile()
    try:
        pos = 0
        adv_table = bytearray()
        for n, obj in enumerate(adv_records):
            data = _pack(obj, "advisory %d" % n)
            adv_table += ADV_ENTRY.pack(pos, len(data), zlib.crc32(data))
            blobs.write(data)
            pos += len(data)
        key_table = bytearray()
        seen = {}
        entries = []
        for key in postings:
            digest = key_digest(key)
            if digest in seen:
                raise ValueError("two names share a key digest: %r and %r" % (seen[digest], key))
            seen[digest] = key
            entries.append((digest, key))
        entries.sort()
        for digest, key in entries:
            data = _pack({"k": key, "p": postings[key]}, "the entry for %r" % key)
            key_table += KEY_ENTRY.pack(digest, pos, len(data), zlib.crc32(data))
            blobs.write(data)
            pos += len(data)
        meta = dict(meta, format=FORMAT, advisories=len(adv_records), keys=len(postings),
                    postings=sum(len(p) for p in postings.values()))
        meta_bytes = _dumps(meta)
        if len(meta_bytes) > MAX_META_BYTES:
            raise ValueError("the bundle's metadata is %d bytes: over %d" % (len(meta_bytes), MAX_META_BYTES))
        meta_off = HEADER.size
        advtab_off = meta_off + len(meta_bytes)
        keytab_off = advtab_off + len(adv_table)
        blobs_off = keytab_off + len(key_table)
        file_len = blobs_off + pos
        head = [MAGIC, FORMAT, 0, file_len, len(adv_records), len(postings), meta["postings"], meta_off,
                len(meta_bytes), advtab_off, keytab_off, blobs_off, zlib.crc32(meta_bytes),
                zlib.crc32(bytes(adv_table)), zlib.crc32(bytes(key_table)), 0]
        head[-1] = zlib.crc32(HEADER.pack(*head))
        fh.write(HEADER.pack(*head))
        fh.write(meta_bytes)
        fh.write(adv_table)
        fh.write(key_table)
        blobs.seek(0)
        while True:
            chunk = blobs.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
        return {"advisories": len(adv_records), "keys": len(postings), "postings": meta["postings"],
                "bytes": file_len}
    finally:
        blobs.close()


def dump_index(doc, fh):
    """Write the bundle document `doc` (the JSON form `sca_feeds` builds) to the binary file `fh` as an indexed
    bundle. -> {advisories, keys, postings, bytes, warnings} where `warnings` are the lines `CveBundle(doc)`
    would have printed. The document goes through the same functions `CveBundle` reads it with, so the file
    holds exactly the advisories, in the order and with the order numbers, that `CveBundle` would have."""
    warnings = sca._Warnings()
    raws, generated_at, sources, counts = sca.bundle_header(doc, warnings)
    adv_records = []
    postings = {}
    order = 0
    for raw in raws:
        n = len(adv_records)
        adv = sca.normalize_advisory(raw, warnings, n + 1)
        if adv is None:
            continue
        adv_records.append({"n": n, "a": raw})
        for j, pkg in enumerate(adv["packages"]):
            for key in keys_of_package(pkg):
                postings.setdefault(key, []).append([order, n, j])
            order += 1
    extra = {k: doc[k] for k in ("generator", "attribution", "feeds") if k in doc}
    meta = {"bundleVersion": 1, "generatedAt": generated_at, "sources": sources, "counts": counts,
            "warnings": warnings.counts, "extra": extra}
    summary = _assemble(fh, meta, adv_records, postings)
    summary["warnings"] = warnings.lines()
    return summary


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def is_index(head):
    """True when `head` (the first bytes of a file) starts an indexed bundle."""
    return bytes(head[:len(MAGIC)]) == MAGIC


def _ignore(kind, n=1):
    return None


class _Advisories(collections.abc.Sequence):
    """`bundle.advisories` of an indexed bundle: the count is free, an advisory is read when asked for."""

    def __init__(self, bundle):
        self._bundle = bundle

    def __len__(self):
        return self._bundle._n_adv

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self[k] for k in range(*i.indices(len(self)))]
        n = len(self)
        if i < 0:
            i += n
        if not 0 <= i < n:
            raise IndexError("advisory index out of range")
        self._bundle._check_open()
        return self._bundle._advisory(i)


class IndexedBundle:
    """What `CveBundle` is, for a bundle in this file's format: `generated_at`, `sources`, `counts`, `warnings`,
    `advisories` (a sequence) and `advisories_for(name, ecosystem)`. Thread-safe; keeps the file open until
    `close()`."""

    def __init__(self, fh, path="<indexed bundle>"):
        self._fh = fh
        self.path = path
        self._lock = threading.RLock()
        self._advs = collections.OrderedDict()
        self._posts = collections.OrderedDict()
        try:
            self._open()
        except BaseException:
            self.close()
            raise

    @classmethod
    def open(cls, path):
        return cls(open(path, "rb"), path)

    # ---- the file
    def _open(self):
        fh, path = self._fh, self.path
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise _damaged(path, "not a regular file")
        head = fh.read(HEADER.size)
        if not is_index(head):
            raise NotAnIndex("not an indexed CVE bundle")
        if len(head) < HEADER.size:
            raise _damaged(path, "the header is cut short")
        fields = HEADER.unpack(head)
        (_magic, fmt, flags, file_len, n_adv, n_keys, n_post, meta_off, meta_len, advtab_off, keytab_off,
         blobs_off, meta_crc, advtab_crc, keytab_crc, header_crc) = fields
        if fmt != FORMAT:
            raise ValueError("the indexed CVE bundle %s is format %d, and this Lazaret reads format %d: "
                             "rebuild it with `lazaret-sca --update-bundle --bundle-format index`"
                             % (path, fmt, FORMAT))
        if zlib.crc32(head[:-4] + b"\0\0\0\0") != header_crc:
            raise _damaged(path, "the header does not match its checksum")
        if flags != 0:
            raise _damaged(path, "unknown flags")
        if file_len != st.st_size:
            raise _damaged(path, "the file is %d bytes and its header says %d (truncated or extended)"
                           % (st.st_size, file_len))
        if n_adv > MAX_ADVISORIES or n_keys > MAX_KEYS or meta_len > MAX_META_BYTES:
            raise _damaged(path, "a count over the limits")
        if (meta_off != HEADER.size or advtab_off != meta_off + meta_len
                or keytab_off != advtab_off + ADV_ENTRY.size * n_adv
                or blobs_off != keytab_off + KEY_ENTRY.size * n_keys or blobs_off > file_len):
            raise _damaged(path, "the parts are not laid out as the writer lays them out")
        self._blobs_off, self._blobs_len = blobs_off, file_len - blobs_off
        self._n_adv, self._n_keys, self._n_post = n_adv, n_keys, n_post
        meta_bytes = self._part(meta_off, meta_len, meta_crc, "the metadata")
        self._advtab = self._part(advtab_off, ADV_ENTRY.size * n_adv, advtab_crc, "the advisory table")
        self._keytab = self._part(keytab_off, KEY_ENTRY.size * n_keys, keytab_crc, "the key table")
        self._check_sorted()
        meta = self._json(meta_bytes, "the metadata")
        self._take_meta(meta)

    def _part(self, off, length, crc, what):
        with self._lock:
            self._fh.seek(off)
            data = self._fh.read(length)
        if len(data) != length:
            raise _damaged(self.path, "%s is cut short" % what)
        if zlib.crc32(data) != crc:
            raise _damaged(self.path, "%s does not match its checksum" % what)
        return data

    def _check_sorted(self):
        tab, size = self._keytab, KEY_ENTRY.size
        previous = None
        for i in range(0, len(tab), size):
            digest = tab[i:i + DIGEST_BYTES]
            if previous is not None and digest <= previous:
                raise _damaged(self.path, "the key table is not in order")
            previous = digest

    def _take_meta(self, meta):
        what = "the metadata"
        if not isinstance(meta, dict) or meta.get("format") != FORMAT or meta.get("bundleVersion") != 1:
            raise _damaged(self.path, "%s is not this format's" % what)
        if (meta.get("advisories"), meta.get("keys"), meta.get("postings")) != (self._n_adv, self._n_keys,
                                                                                self._n_post):
            raise _damaged(self.path, "%s and the header disagree on the counts" % what)
        gen, sources, counts, warned = (meta.get("generatedAt"), meta.get("sources"), meta.get("counts"),
                                        meta.get("warnings"))
        if gen is not None and not isinstance(gen, str):
            raise _damaged(self.path, "generatedAt is not text")
        if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
            raise _damaged(self.path, "sources is not a list of text")
        if not isinstance(counts, dict):
            raise _damaged(self.path, "counts is not an object")
        if (not isinstance(warned, dict)
                or not all(isinstance(k, str) and type(v) is int and 0 < v < 1 << 40 for k, v in warned.items())):
            raise _damaged(self.path, "the warnings are not counts")
        self.generated_at, self.sources, self.counts = gen, sources, counts
        self.warnings = sca._Warnings()
        for kind, n in sorted(warned.items()):
            self.warnings(kind, n)
        self.advisories = _Advisories(self)

    # ---- records
    def _json(self, raw, what):
        try:
            return lazaret.json_loads_bounded(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise _damaged(self.path, "%s is not JSON" % what) from None

    def _record(self, off, length, crc, what):
        if length > MAX_STORED_BYTES or off + length > self._blobs_len:
            raise _damaged(self.path, "%s lies outside the records" % what)
        with self._lock:
            if self._fh is None:
                raise ValueError("the indexed CVE bundle %s is closed" % self.path)
            self._fh.seek(self._blobs_off + off)
            data = self._fh.read(length)
        if len(data) != length:
            raise _damaged(self.path, "%s is cut short" % what)
        if zlib.crc32(data) != crc:
            raise _damaged(self.path, "%s does not match its checksum" % what)
        inflater = zlib.decompressobj()
        try:
            raw = inflater.decompress(data, MAX_RECORD_BYTES + 1)
        except zlib.error:
            raise _damaged(self.path, "%s is not a zlib stream" % what) from None
        if len(raw) > MAX_RECORD_BYTES or inflater.unconsumed_tail or inflater.unused_data or not inflater.eof:
            raise _damaged(self.path, "%s does not inflate to a whole record within %d bytes"
                           % (what, MAX_RECORD_BYTES))
        return self._json(raw, what)

    def _remember(self, cache, limit, key, value):
        cache[key] = value                                                   # (a name not cached yet: it goes last)
        while len(cache) > limit:
            cache.popitem(last=False)
        return value

    def _advisory(self, n):
        with self._lock:
            adv = self._advs.get(n)
            if adv is not None:
                self._advs.move_to_end(n)
                return adv
            off, length, crc = ADV_ENTRY.unpack_from(self._advtab, n * ADV_ENTRY.size)
            what = "advisory %d" % n
            rec = self._record(off, length, crc, what)
            if not isinstance(rec, dict) or rec.get("n") != n or "a" not in rec:
                raise _damaged(self.path, "%s is not advisory %d's record" % (what, n))
            adv = sca.normalize_advisory(rec["a"], _ignore, n + 1)
            if adv is None:
                raise _damaged(self.path, "%s is not an advisory" % what)
            return self._remember(self._advs, ADVISORY_CACHE, n, adv)

    def _find(self, digest):
        tab, size = self._keytab, KEY_ENTRY.size
        lo, hi = 0, self._n_keys
        while lo < hi:
            mid = (lo + hi) // 2
            here = tab[mid * size:mid * size + DIGEST_BYTES]
            if here < digest:
                lo = mid + 1
            elif here > digest:
                hi = mid
            else:
                return KEY_ENTRY.unpack_from(tab, mid * size)
        return None

    def _posting(self, key):
        """-> [(order, advisory, package)] for `key`, or [] when the bundle has no such name."""
        with self._lock:
            cached = self._posts.get(key)
            if cached is not None:
                self._posts.move_to_end(key)
                return cached
            entry = self._find(key_digest(key))
            if entry is None:
                return []
            _digest, off, length, crc = entry
            what = "the entry for a name"
            rec = self._record(off, length, crc, what)
            if not isinstance(rec, dict) or rec.get("k") != key or not isinstance(rec.get("p"), list):
                raise _damaged(self.path, "%s is not the record of the name asked for" % what)
            out = []
            for item in rec["p"]:
                if (not isinstance(item, list) or len(item) != 3
                        or not all(type(x) is int and x >= 0 for x in item) or item[1] >= self._n_adv):
                    raise _damaged(self.path, "%s lists something that is not a package" % what)
                out.append(tuple(item))
            return self._remember(self._posts, POSTING_CACHE, key, out)

    # ---- the interface of CveBundle
    def _check_open(self):
        if self._fh is None:
            raise ValueError("the indexed CVE bundle %s is closed" % self.path)

    def advisories_for(self, name, ecosystem=None):
        """Every (advisory, package entry) pair that names this dependency, each once, in bundle order: what
        `CveBundle.advisories_for` returns for the document this file was built from."""
        self._check_open()
        found = {}
        for key in keys_for_lookup(name, ecosystem):
            for order, n, j in self._posting(key):
                found.setdefault(order, (n, j))
        out = []
        for order in sorted(found):
            n, j = found[order]
            adv = self._advisory(n)
            if j >= len(adv["packages"]):
                raise _damaged(self.path, "the entry for a name points past advisory %d's packages" % n)
            out.append((adv, adv["packages"][j]))
        return out

    def verify(self):
        """Read every record and check them against each other: each advisory is its own, each name's entry
        is sorted and lists only packages that are indexed under that name, and every package is listed under
        every name it is indexed under. -> {advisories, keys, postings}; BundleDamaged otherwise. Reads the
        whole file: for a build, not for a scan."""
        self._check_open()
        expected = 0
        packages = []
        for n in range(self._n_adv):
            adv = self._advisory(n)
            packages.append(adv["packages"])
            for pkg in adv["packages"]:
                expected += len(keys_of_package(pkg))
        total = 0
        for i in range(self._n_keys):
            digest, off, length, crc = KEY_ENTRY.unpack_from(self._keytab, i * KEY_ENTRY.size)
            rec = self._record(off, length, crc, "the entry for name %d" % i)
            key = rec.get("k") if isinstance(rec, dict) else None
            if not isinstance(key, str) or key_digest(key) != digest:
                raise _damaged(self.path, "name %d's entry is filed under the wrong digest" % i)
            posting = self._posting(key)
            if not posting:
                raise _damaged(self.path, "name %d has no packages" % i)
            last = -1
            for order, n, j in posting:
                if order <= last:
                    raise _damaged(self.path, "name %d's entry is not in order" % i)
                last = order
                if j >= len(packages[n]) or key not in keys_of_package(packages[n][j]):
                    raise _damaged(self.path, "name %d lists a package that is not indexed under it" % i)
            total += len(posting)
        if total != expected or total != self._n_post:
            raise _damaged(self.path, "%d name entries for %d package keys (%d in the header)"
                           % (total, expected, self._n_post))
        return {"advisories": self._n_adv, "keys": self._n_keys, "postings": total}

    def close(self):
        with self._lock:
            fh, self._fh = self._fh, None
        if fh is not None:
            fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def verify_path(path):
    """Open the indexed bundle at `path` and check all of it (see `IndexedBundle.verify`)."""
    with IndexedBundle.open(path) as bundle:
        return bundle.verify()


# ---------------------------------------------------------------------------
# python -m lazaret.scanner.sca_index
# ---------------------------------------------------------------------------

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    usage = "usage: python -m lazaret.scanner.sca_index build IN.json OUT | check FILE | info FILE"
    if not argv or argv[0] not in ("build", "check", "info") or len(argv) != (3 if argv[0] == "build" else 2):
        print(usage, file=sys.stderr)
        return 2
    try:
        if argv[0] == "build":
            from lazaret.scanner import sca_feeds
            with open(argv[1], "rb") as f:
                doc = lazaret.json_loads_bounded(f.read().decode("utf-8"))
            size = sca_feeds.write_bundle(doc, argv[2], fmt="index")
            print("wrote %s (%d bytes)" % (lazaret.sanitize_term(argv[2]), size))
        elif argv[0] == "check":
            summary = verify_path(argv[1])
            print("ok: %(advisories)d advisories, %(keys)d names, %(postings)d entries" % summary)
        else:
            with IndexedBundle.open(argv[1]) as b:
                print("indexed CVE bundle: %d advisories, %d names, %d entries; generated %s; sources %s"
                      % (b._n_adv, b._n_keys, b._n_post, lazaret.sanitize_term(b.generated_at),
                         lazaret.sanitize_term(", ".join(b.sources))))
    except (OSError, ValueError, MemoryError) as exc:
        print("error: %s" % lazaret.sanitize_term(exc), file=sys.stderr)
        return sca.EXIT_BUNDLE
    return 0


if __name__ == "__main__":
    sys.exit(main())
