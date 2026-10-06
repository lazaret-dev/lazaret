#!/usr/bin/env python3
"""The popular releases: the release gate's second benign set (B-2).

The benchmark's benign set is 429 popular packages, mostly small libraries,
and it did not hold the nine popular releases 0.1.8 made SUSPICIOUS (vite,
vitest, monaco-editor, coverage, numba, future, sympy, ipython,
kubernetes). This set is the latest releases of most-downloaded npm and PyPI
packages the benchmark does not hold, and of the most-downloaded crates
(0.1.9, N-2), pinned by version and sha256 in releases.jsonl beside this
script, each the one file the guard scans: npm's tarball, for PyPI the file
pip would install on Linux x86-64 (a wheel for any platform, then a
manylinux x86-64 wheel for CPython 3.11 or the stable ABI, then any
manylinux x86-64 wheel, else the sdist), and a crate's .crate.

    python3 scripts/popular/popular.py fetch --cache DIR --manifest DIR/manifest.jsonl
    python3 scripts/bench.py run DIR/manifest.jsonl RUN.jsonl      (looped, as for the benchmark)
    python3 scripts/bench.py compare BEFORE.jsonl RUN.jsonl

    python3 scripts/popular/popular.py pin --top 800,400,500 --exclude FILE --cache DIR    (refresh, each release)
    python3 scripts/popular/popular.py pin npm:vite@8.3.2 pypi:sympy crates:syn --cache DIR (add or move some)
    python3 scripts/popular/popular.py check

`fetch` downloads each pinned file into DIR, named by its sha256 (a file
already there is hashed again), refuses bytes that are not the pinned ones,
and writes a manifest for scripts/bench.py, every release in the category
"benign". `pin --top N,M,K` takes the first N npm, M PyPI and K crates
names of python/src/lazaret/registry/popular_names.json (the most
downloaded), less the names --exclude lists (one per line, "npm:name",
"pypi:name", "crates:name", or a bare name for all: the benchmark's benign
set), resolves each one's latest release, downloads its file into DIR to
hash it, and writes releases.jsonl anew; a name whose release can't be
pinned (no file, a file over the size limit, a registry error) is reported
and left out. With specs, `pin` pins those releases (the latest one when a
spec names no version) and keeps the others. `check` validates
releases.jsonl.

A crate's release is crates.io's default version (the highest stable one
not yanked), read from crates.io's API at one request a second (its crawler
policy), with the sha256 the registry lists; its .crate comes from
static.crates.io. A crate is pinned only under licences Apache-2.0's terms
can take in (LICENCES: MIT, Apache-2.0, the BSD licences, ISC, Zlib, …),
since the findings on this set are read, and code under other licences is
not reviewed.

Only https from the registries' own hosts is fetched. Standard library only;
nothing is unpacked or run here (bench.py scans in memory).
"""
import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import re
import sys
import time
import urllib.parse
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
RELEASES = HERE / "releases.jsonl"
NAMES = ROOT / "python" / "src" / "lazaret" / "registry" / "popular_names.json"

ECOSYSTEMS = ("npm", "pypi", "crates")
NPM_REGISTRY = "https://registry.npmjs.org/"
PYPI_JSON = "https://pypi.org/pypi/"
CRATES_API = "https://crates.io/api/v1/crates/"
CRATES_FILES = "https://static.crates.io/crates/"
#: the hosts a pinned file may come from, by ecosystem
FILE_HOSTS = {"npm": ("registry.npmjs.org",), "pypi": ("files.pythonhosted.org",), "crates": ("static.crates.io",)}
#: seconds between two requests to crates.io's API (its crawler policy: one a second)
API_INTERVAL = 1.0
#: the licences a pinned crate may be under (SPDX ids, lower case; "+" or "-or-later" is the same licence): ones
#: Apache-2.0's terms can take in, since the set's findings are read; LICENCE_EXCEPTIONS may follow WITH
LICENCES = frozenset(("mit", "mit-0", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "0bsd", "isc", "zlib",
                      "unicode-3.0", "unicode-dfs-2016", "bsl-1.0", "cc0-1.0", "unlicense"))
LICENCE_EXCEPTIONS = frozenset(("llvm-exception",))
MAX_LICENCE_TOKENS = 64
MAX_FILE_BYTES = 100 << 20         # a release file larger than this is not pinned (torch, tensorflow)
MAX_META_BYTES = 64 << 20          # a registry's JSON answer
FETCH_TIMEOUT = 90
USER_AGENT = "lazaret-popular-set (https://lazaret.dev)"
FIELDS = ("id", "ecosystem", "name", "version", "filename", "url", "container", "kind", "sha256", "bytes")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SPEC_RE = re.compile(r"^(npm|pypi|crates):((?:@[^/@\s]+/)?[^@\s]+)(?:@([^@\s]+))?$")

EXIT_OK, EXIT_INVALID, EXIT_USAGE, EXIT_FETCH = 0, 1, 2, 3


class PinError(Exception):
    """A release that can't be pinned or fetched as pinned."""


class DigestError(PinError):
    """Bytes whose sha256 is not the one they must have."""


# ---- the pinned file
def release_id(eco, name, version):
    return f"{eco}:{name}@{version}"


def container_kind(eco, filename):
    """-> (container, kind) as scripts/bench.py reads them, or None for a file it can't scan."""
    low = filename.lower()
    if eco == "npm":
        return ("tgz", "npm") if low.endswith(".tgz") else None
    if eco == "crates":
        return ("tgz", "crate") if low.endswith(".crate") else None
    if low.endswith(".whl"):
        return "zip", "wheel"
    if low.endswith((".tar.gz", ".tgz")):
        return "tgz", "sdist"
    if low.endswith(".zip"):
        return "zip", "sdist"
    return None


def url_allowed(url, eco):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" and (parts.hostname or "") in FILE_HOSTS.get(eco, ())


def licence_ok(expr):
    """True when the SPDX expression `expr` (crates.io's `license`, where "/" is the old OR) lets the code be taken
    under LICENCES alone: an OR needs one side, an AND both, "X WITH Y" a LICENCE_EXCEPTIONS exception. No
    expression, or one that can't be read (or of more than MAX_LICENCE_TOKENS words), is False."""
    tokens = re.findall(r"[()/]|[^\s()/]+", expr or "")
    if len(tokens) > MAX_LICENCE_TOKENS:                # the registry's text: no deep nesting read
        return False
    pos = 0

    def at(*words):
        return pos < len(tokens) and tokens[pos].lower() in words

    def one():
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("an expression ends early")
        tok = tokens[pos]
        pos += 1
        if tok == "(":
            ok = either()
            if not at(")"):
                raise ValueError("no )")
            pos += 1
            return ok
        if tok in (")", "/") or tok.lower() in ("and", "or", "with"):
            raise ValueError(f"{tok} out of place")
        name = tok.lower()
        name = name[:-1] if name.endswith("+") else name[:-len("-or-later")] if name.endswith("-or-later") else name
        ok = name in LICENCES
        if at("with"):
            pos += 1
            if pos >= len(tokens):
                raise ValueError("WITH and no exception")
            ok = ok and tokens[pos].lower() in LICENCE_EXCEPTIONS
            pos += 1
        return ok

    def both():
        nonlocal pos
        ok = one()
        while at("and"):
            pos += 1
            ok = one() and ok
        return ok

    def either():
        nonlocal pos
        ok = both()
        while at("or", "/"):
            pos += 1
            ok = both() or ok
        return ok

    try:
        ok = either()
    except ValueError:
        return False
    return ok and pos == len(tokens)


def validate(rows):
    """-> the problems of `rows` (a list of releases), as text; [] when there are none."""
    problems, seen = [], set()
    for n, row in enumerate(rows, 1):
        where = f"line {n}"
        if not isinstance(row, dict):
            problems.append(f"{where}: not an object")
            continue
        missing = [f for f in FIELDS if f not in row]
        if missing:
            problems.append(f"{where}: missing {', '.join(missing)}")
            continue
        where = f"{where} ({row['id']})"
        eco = row["ecosystem"]
        if eco not in ECOSYSTEMS:
            problems.append(f"{where}: unknown ecosystem {eco!r}")
            continue
        if row["id"] != release_id(eco, row["name"], row["version"]):
            problems.append(f"{where}: the id is not {release_id(eco, row['name'], row['version'])}")
        if row["id"] in seen:
            problems.append(f"{where}: pinned twice")
        seen.add(row["id"])
        if not isinstance(row["sha256"], str) or not SHA256_RE.match(row["sha256"]):
            problems.append(f"{where}: sha256 is not 64 lower-case hex digits")
        if not isinstance(row["bytes"], int) or isinstance(row["bytes"], bool) or not 0 < row["bytes"] <= MAX_FILE_BYTES:
            problems.append(f"{where}: bytes must be 1 to {MAX_FILE_BYTES}")
        if not url_allowed(row["url"], eco):
            problems.append(f"{where}: the url is not https on {' or '.join(FILE_HOSTS[eco])}")
        elif urllib.parse.urlsplit(row["url"]).path.rsplit("/", 1)[-1] != row["filename"]:
            problems.append(f"{where}: the url does not end in the filename")
        if container_kind(eco, row["filename"]) != (row["container"], row["kind"]):
            problems.append(f"{where}: container and kind do not fit {row['filename']}")
    return problems


def read_releases(path=RELEASES):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_releases(rows, path=RELEASES):
    rows = sorted(rows, key=lambda r: r["id"])
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for row in rows:
            fh.write(json.dumps({f: row[f] for f in FIELDS}, ensure_ascii=False) + "\n")


# ---- the network
def get(url, limit, opener=urllib.request.urlopen):
    """The body at `url`, at most `limit` bytes (PinError past it, or on a network error)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*"})
        with opener(req, timeout=FETCH_TIMEOUT) as resp:
            data = resp.read(limit + 1)
    except (OSError, ValueError) as exc:               # (URLError and HTTPError are OSErrors)
        raise PinError(f"{url}: {exc}") from exc
    if len(data) > limit:
        raise PinError(f"{url}: more than {limit >> 20} MiB")
    return data


def get_json(url, opener=urllib.request.urlopen):
    try:
        return json.loads(get(url, MAX_META_BYTES, opener))
    except ValueError as exc:
        raise PinError(f"{url}: not JSON ({exc})") from exc


_api_last = [float("-inf")]


def crates_api(path, opener=urllib.request.urlopen):
    """crates.io's API answer at `path`, at most one request each API_INTERVAL seconds."""
    wait = _api_last[0] + API_INTERVAL - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _api_last[0] = time.monotonic()
    return get_json(CRATES_API + path, opener)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, eco, cache, opener=urllib.request.urlopen, expect=None):
    """Download `url` into `cache`, named by its sha256: -> (sha256, size, path). With `expect`, bytes whose
    sha256 is another are refused (PinError) and not kept."""
    if not url_allowed(url, eco):
        raise PinError(f"only https from {' or '.join(FILE_HOSTS[eco])} is fetched: {url}")
    os.makedirs(cache, exist_ok=True)
    part = os.path.join(cache, f".part-{os.getpid()}")
    h, size = hashlib.sha256(), 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with opener(req, timeout=FETCH_TIMEOUT) as resp, open(part, "wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise PinError(f"{url}: more than {MAX_FILE_BYTES >> 20} MiB")
                h.update(chunk)
                out.write(chunk)
        if size == 0:
            raise PinError(f"{url}: an empty file")
        digest = h.hexdigest()
        if expect is not None and digest != expect:
            raise DigestError(f"sha256 {digest}, expected {expect}; {url}")
        dest = os.path.join(cache, digest)
        os.replace(part, dest)
        return digest, size, dest
    except PinError:
        raise
    except (OSError, ValueError) as exc:
        raise PinError(f"{url}: {exc}") from exc
    finally:
        with contextlib.suppress(OSError):
            os.remove(part)


def fetch_file(row, cache, opener=urllib.request.urlopen):
    """-> the path of `row`'s file in `cache`, fetched if it is not there. A file already there is hashed
    again, so a damaged or swapped cache is not trusted. PinError for other bytes than the pinned ones."""
    dest = os.path.join(cache, row["sha256"])
    if os.path.isfile(dest) and sha256_file(dest) == row["sha256"]:
        return dest
    try:
        return download(row["url"], row["ecosystem"], cache, opener, expect=row["sha256"])[2]
    except DigestError as exc:
        raise DigestError(f"{row['id']}: the bytes are not the pinned ones ({exc})") from None


# ---- resolving a release
def pypi_pick(files):
    """The file pip would install on Linux x86-64, of a release's files (PyPI's `urls`), or None."""
    wheels = [f for f in files if f.get("filename", "").endswith(".whl")]
    for test in (lambda n: n.endswith("-none-any.whl"),
                 lambda n: "manylinux" in n and "x86_64" in n and ("-cp311-" in n or "-abi3-" in n),
                 lambda n: "manylinux" in n and "x86_64" in n):
        for f in wheels:
            if test(f["filename"]):
                return f
    for f in files:
        if f.get("packagetype") == "sdist" and f.get("filename", "").endswith((".tar.gz", ".zip")):
            return f
    return None


def resolve_crate(name, version=None, opener=urllib.request.urlopen):
    """-> (the crate's name as crates.io spells it, version, its .crate's url, the sha256 crates.io lists): the
    default version (the highest stable one not yanked) unless `version` is given. PinError for a release that is
    yanked, over the size limit, or under a licence LICENCES does not take."""
    meta = crates_api(urllib.parse.quote(name, safe=""), opener)
    crate = meta.get("crate") or {}
    canonical = crate.get("name")
    want = version or crate.get("default_version") or crate.get("max_stable_version") or crate.get("max_version")
    if not isinstance(canonical, str) or not isinstance(want, str) or not want:
        raise PinError(f"crates:{name}: no release in the registry's answer")
    entry = next((v for v in meta.get("versions") or () if isinstance(v, dict) and v.get("num") == want), None)
    if entry is None:                                  # an old version the crate's answer leaves out
        entry = crates_api(f"{urllib.parse.quote(canonical, safe='')}/{urllib.parse.quote(want, safe='')}",
                           opener).get("version") or {}
    if entry.get("num") != want:
        raise PinError(f"crates:{canonical}@{want}: no such release")
    if entry.get("yanked"):
        raise PinError(f"crates:{canonical}@{want}: yanked")
    if not licence_ok(entry.get("license")):
        raise PinError(f"crates:{canonical}@{want}: licence {entry.get('license')!r} is not one the set takes")
    if (entry.get("crate_size") or 0) > MAX_FILE_BYTES:
        raise PinError(f"crates:{canonical}@{want}: over {MAX_FILE_BYTES >> 20} MiB")
    q = urllib.parse.quote(canonical, safe="")
    url = f"{CRATES_FILES}{q}/{q}-{urllib.parse.quote(want, safe='+')}.crate"     # "+": semver's build metadata
    return canonical, want, url, entry.get("checksum")


def resolve(eco, name, version=None, opener=urllib.request.urlopen):
    """-> the release's row, without sha256 and bytes (and with "expect_sha256" when the registry gives it)."""
    if eco == "npm":
        meta = get_json(NPM_REGISTRY + urllib.parse.quote(name, safe="@") + "/" +
                        urllib.parse.quote(version or "latest", safe=""), opener)
        dist = meta.get("dist") or {}
        url, version = dist.get("tarball"), meta.get("version")
        if not url or not version:
            raise PinError(f"npm:{name}: no tarball in the registry's answer")
        expect = None
    elif eco == "pypi":
        path = urllib.parse.quote(name, safe="") + ("/" + urllib.parse.quote(version, safe="") if version else "")
        meta = get_json(f"{PYPI_JSON}{path}/json", opener)
        version = (meta.get("info") or {}).get("version")
        picked = pypi_pick(meta.get("urls") or [])
        if not version or picked is None:
            raise PinError(f"pypi:{name}: no file to install on Linux x86-64")
        url, expect = picked.get("url"), (picked.get("digests") or {}).get("sha256")
        if (picked.get("size") or 0) > MAX_FILE_BYTES:
            raise PinError(f"pypi:{name}@{version}: {picked['filename']} is over {MAX_FILE_BYTES >> 20} MiB")
    elif eco == "crates":
        name, version, url, expect = resolve_crate(name, version, opener)
    else:
        raise PinError(f"unknown ecosystem {eco!r}")
    filename = urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1]
    ck = container_kind(eco, filename)
    if ck is None:
        raise PinError(f"{eco}:{name}@{version}: {filename} is no archive the benchmark reads")
    row = {"id": release_id(eco, name, version), "ecosystem": eco, "name": name, "version": version,
           "filename": filename, "url": url, "container": ck[0], "kind": ck[1]}
    if expect:
        row["expect_sha256"] = expect.lower()
    return row


def pin_one(eco, name, version, cache, opener=urllib.request.urlopen):
    """Resolve the release and download its file into `cache` to hash it: -> its row."""
    row = resolve(eco, name, version, opener)
    expect = row.pop("expect_sha256", None)
    try:
        digest, size, _path = download(row["url"], eco, cache, opener, expect=expect)
    except DigestError as exc:
        raise DigestError(f"{row['id']}: not the file the registry lists ({exc})") from None
    row.update(sha256=digest, bytes=size)
    return row


# ---- which names
def read_exclude(path):
    """-> {(eco, name)}: "npm:name", "pypi:name", "crates:name", or a bare name for every ecosystem; # starts a
    comment."""
    out = set()
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            eco, sep, name = line.partition(":")
            if sep and eco in ECOSYSTEMS:
                out.add((eco, normal(eco, name)))
            else:
                out.update((e, normal(e, line)) for e in ECOSYSTEMS)
    return out


def normal(eco, name):
    """A name as the registry compares it (PEP 503 for PyPI; npm names are lower case; crates.io takes - for _)."""
    name = name.strip().lower()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name)
    return name.replace("_", "-") if eco == "crates" else name


def top_names(counts, exclude=frozenset(), names_path=NAMES):
    """The first counts[eco] names of popular_names.json's targets per ecosystem, less `exclude`."""
    with open(names_path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = []
    for eco in ECOSYSTEMS:
        want = counts.get(eco, 0)
        if want <= 0:
            continue
        for name in data[eco]["targets"]:
            if want <= 0:
                break
            if (eco, normal(eco, name)) in exclude:
                continue
            out.append((eco, name))
            want -= 1
    return out


def parse_spec(spec):
    m = SPEC_RE.match(spec.strip())
    if not m:
        raise ValueError(f"not ecosystem:name[@version]: {spec!r}")
    return m.group(1), m.group(2), m.group(3)


def parse_top(text):
    try:
        counts = [int(x) for x in text.split(",")]
    except ValueError:
        counts = []
    if len(counts) not in (2, 3):
        raise argparse.ArgumentTypeError("--top takes N,M[,K] (npm names, PyPI names, crates names)")
    if min(counts) < 0:
        raise argparse.ArgumentTypeError("--top takes counts of 0 or more")
    return dict(zip(ECOSYSTEMS, counts))


def bench_manifest(rows, paths):
    """scripts/bench.py's manifest lines for `rows`, whose files are at paths[sha256]."""
    return [{"id": "popular:" + row["id"], "cat": "benign", "set": "popular", "eco": row["ecosystem"],
             "name": row["name"], "version": row["version"], "artifact_path": paths[row["sha256"]],
             "container": row["container"], "kind": row["kind"]} for row in rows]


# ---- the command line
def _say(text):
    print(text, file=sys.stderr, flush=True)


def cmd_check(args):
    try:
        rows = read_releases(args.releases)
    except (OSError, ValueError) as exc:
        _say(f"error: {args.releases}: {exc}")
        return EXIT_INVALID
    problems = validate(rows)
    for p in problems:
        _say(p)
    counts = {eco: sum(1 for r in rows if isinstance(r, dict) and r.get("ecosystem") == eco) for eco in ECOSYSTEMS}
    print(f"{len(rows)} releases ({counts['npm']} npm, {counts['pypi']} PyPI, {counts['crates']} crates); "
          f"{len(problems)} problem{'' if len(problems) == 1 else 's'}")
    return EXIT_INVALID if problems else EXIT_OK


def cmd_fetch(args, opener=urllib.request.urlopen):
    rows = read_releases(args.releases)
    problems = validate(rows)
    if problems:
        for p in problems:
            _say(p)
        return EXIT_INVALID
    if args.only:
        rows = [r for r in rows if r["ecosystem"] == args.only]
    paths, failed = {}, 0
    for n, row in enumerate(rows, 1):
        try:
            paths[row["sha256"]] = fetch_file(row, args.cache, opener)
        except PinError as exc:
            failed += 1
            _say(f"error: {exc}")
        if n % 100 == 0:
            _say(f"{n} of {len(rows)} files")
    ok = [r for r in rows if r["sha256"] in paths]
    if args.manifest:
        with open(args.manifest, "w", encoding="utf-8", newline="\n") as fh:
            for line in bench_manifest(ok, paths):
                fh.write(json.dumps(line, ensure_ascii=False) + "\n")
    print(f"{len(ok)} of {len(rows)} files in {args.cache}" + (f"; manifest {args.manifest}" if args.manifest else ""))
    return EXIT_FETCH if failed else EXIT_OK


def cmd_pin(args, opener=urllib.request.urlopen):
    if bool(args.specs) == bool(args.top):
        _say("error: pin takes specs or --top N,M[,K] (not both)")
        return EXIT_USAGE
    try:
        if args.top:
            exclude = read_exclude(args.exclude) if args.exclude else set()
            wanted = [(eco, name, None) for eco, name in top_names(args.top, exclude)]
            keep = []
        else:
            wanted = [parse_spec(s) for s in args.specs]
            keep = read_releases(args.releases) if os.path.exists(args.releases) else []
    except (OSError, ValueError) as exc:
        _say(f"error: {exc}")
        return EXIT_USAGE
    pinned, failed = [], 0
    for n, (eco, name, version) in enumerate(wanted, 1):
        try:
            pinned.append(pin_one(eco, name, version, args.cache, opener))
        except PinError as exc:
            failed += 1
            _say(f"left out: {exc}")
        if n % 100 == 0:
            _say(f"{n} of {len(wanted)} releases")
    names = {(r["ecosystem"], normal(r["ecosystem"], r["name"])) for r in pinned}
    rows = [r for r in keep if (r["ecosystem"], normal(r["ecosystem"], r["name"])) not in names] + pinned
    write_releases(rows, args.releases)
    print(f"pinned {len(pinned)} of {len(wanted)} releases ({failed} left out); {len(rows)} in {args.releases}")
    return EXIT_OK


def build_parser():
    p = argparse.ArgumentParser(prog="popular.py", description=__doc__.split("\n\n")[0])
    p.add_argument("--releases", default=str(RELEASES), help="the pinned file (default: releases.jsonl here)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="validate the pinned file")
    c.set_defaults(func=cmd_check)
    f = sub.add_parser("fetch", help="download the pinned files and write a manifest for scripts/bench.py")
    f.add_argument("--cache", required=True, help="where the files go, named by sha256")
    f.add_argument("--manifest", help="write scripts/bench.py's manifest here")
    f.add_argument("--only", choices=ECOSYSTEMS, help="one ecosystem's releases")
    f.set_defaults(func=cmd_fetch)
    n = sub.add_parser("pin", help="resolve releases, hash their files and write the pinned file")
    n.add_argument("specs", nargs="*", metavar="ecosystem:name[@version]")
    n.add_argument("--top", type=parse_top,
                   help="N,M[,K]: the first N npm, M PyPI and K crates popular names (replaces the file)")
    n.add_argument("--exclude", help="names to leave out of --top, one per line")
    n.add_argument("--cache", required=True, help="where the downloaded files go, named by sha256")
    n.set_defaults(func=cmd_pin)
    return p


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(errors="backslashreplace")
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
