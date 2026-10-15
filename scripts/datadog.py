#!/usr/bin/env python3
"""The benchmark's malicious releases and a holdout, from DataDog's
malicious-software-packages-dataset: the manifests scripts/bench.py runs.

    git clone --no-checkout https://github.com/DataDog/malicious-software-packages-dataset.git DATASET
    python3 scripts/datadog.py DATASET OUT [--commit b302ad0b] [--only benchmark|holdout] [--holdout-seed N]

writes OUT/benchmark/manifest.jsonl and OUT/holdout/manifest.jsonl, each
release's file in its set's files/ folder, and prints the two entries of a
sets file (`bench.py all`) that run them.

The benchmark is the audit's draw (audits/lazaret-audit-2026-10-01.md,
Appendix: the dataset at b302ad0b, seed 20260928): 200 npm and 200 PyPI
malicious-intent packages, 100 compromised npm releases and every
compromised PyPI release (16), one version of each, drawn as the audit's
harness drew them (prepare_corpus.py's pick_malicious), so the same commit
gives the same 516 releases. The holdout of Sept 30 (747 releases) cannot be
drawn again: its draw was not kept. The holdout here is a new draw of the
same shape (seed 20261015): 300 npm and 300 PyPI malicious-intent packages
and 150 compromised npm releases, among the packages the benchmark does not
hold (and any compromised PyPI release it does not hold: none at b302ad0b).
Its first run is its baseline, and it is read in aggregate only
(docs/TESTING.md).

A sample is a zip, encrypted with the dataset's password ("infected"), of a
release's files and, for some compromised releases, the upstream sources
beside them. It is read in memory: nothing in it is unpacked to disk or run.
The release is written as its registry serves it, by the harness's rules:
its files are those of the folder holding the dataset's package_info-*.json
(else of the shallowest folder with a package.json, setup.py, pyproject.toml
or PKG-INFO), never an upstream sources/ tree, with the dataset's doubled
paths (a/b.py/a/b.py) undone; an npm release is a tarball, package/ inside;
a PyPI release is its own archive when the sample holds one at the release's
top, else its files packed as a wheel (a .dist-info folder at the top) or an
sdist. The zips are read from git at the commit (`git cat-file`), so the
clone needs no checkout, and one made with --filter=blob:none fetches the
samples drawn alone, in one request. Stopped, the same command goes on where
it was.

The samples are real malware: run this on a maintainer's machine, never in
an agent's session; keep OUT outside the repository and any synced folder,
and install nothing from it.
"""
import argparse
import calendar
import collections
import fnmatch
import gzip
import hashlib
import io
import json
import os
import pathlib
import random
import re
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import zipfile
import zlib

PASSWORD = b"infected"
COMMIT = "b302ad0b"                                   # the audit's (Sept 28, 2026)
BENCHMARK_SEED = 20260928
HOLDOUT_SEED = 20261015
EVERY = 10 ** 9                                       # a subset's size meaning "every package of it"
#: Each set's subsets, in the order they are drawn (the order is part of the draw).
SIZES = {
    "benchmark": {("npm", "malicious_intent"): 200, ("pypi", "malicious_intent"): 200,
                  ("npm", "compromised_lib"): 100, ("pypi", "compromised_lib"): EVERY},
    "holdout": {("npm", "malicious_intent"): 300, ("pypi", "malicious_intent"): 300,
                ("npm", "compromised_lib"): 150, ("pypi", "compromised_lib"): EVERY},
}
AUDIT_BENCHMARK = 516
MARKS = ("PKG-INFO", "setup.py", "pyproject.toml", "package.json")
SDIST_MARKS = {"PKG-INFO", "setup.py", "pyproject.toml"}
EXTENSION = {("tgz", "npm"): ".tgz", ("tgz", "sdist"): ".tar.gz", ("tbz2", "sdist"): ".tar.bz2",
             ("txz", "sdist"): ".tar.xz", ("zip", "sdist"): ".zip", ("zip", "wheel"): ".whl"}
PROGRESS_SECONDS = 15.0


class SetupError(Exception):
    """What stops the whole run (no git, no such commit, OUT inside the repository)."""


class Skip(Exception):
    """A sample that gives no release; the reason is recorded in the set's skipped.json."""


# ---------------------------------------------------------------- the draw
def samples_by_package(paths):
    """The dataset's sample zips, samples/ECO/CATEGORY/NAME/VERSION/FILE.zip, as
    {(eco, category, name): [(version, path)]}. `paths` are as `git ls-tree` prints them, so a path git
    quotes (one with a byte outside printable ASCII) is left out, as it was from the harness's list."""
    groups = collections.defaultdict(list)
    for path in paths:
        parts = path.split("/")
        if not path.endswith(".zip") or len(parts) != 6 or parts[0] != "samples":
            continue
        _, eco, cat, name, version, _file = parts
        if eco in ("npm", "pypi") and cat in ("malicious_intent", "compromised_lib"):
            groups[(eco, cat, name)].append((version, path))
    return groups


def draw(groups, seed, sizes, leave_out=frozenset()):
    """The harness's draw, unchanged: subset by subset in `sizes`' order, that many package names at random
    (every one when the subset has no more), then one version of each at random. `leave_out`: the
    (ecosystem, name) pairs not drawn from."""
    rnd = random.Random(seed)
    chosen = []
    for (eco, cat), n in sizes.items():
        names = sorted(k[2] for k in groups if k[0] == eco and k[1] == cat and (eco, k[2]) not in leave_out)
        pick = names if n >= len(names) else rnd.sample(names, n)
        for name in sorted(pick):
            version, path = rnd.choice(sorted(groups[(eco, cat, name)]))
            chosen.append({"eco": eco, "cat": cat, "name": name, "version": version, "path": path})
    return chosen


def fingerprint(chosen):
    """The draw's digest: two machines that drew the same releases print the same one."""
    text = "".join(item["path"] + "\n" for item in chosen)
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


# ---------------------------------------------------------------- the dataset's clone
class Dataset:
    """A clone of the dataset, read at one commit: its file list (`git ls-tree`) and its blobs (`git cat-file
    --batch`), whatever is checked out."""

    def __init__(self, path, commit):
        self.path = pathlib.Path(path).expanduser()
        if not self.path.is_dir():
            raise SetupError(f"{self.path} is not a folder")
        found = self._git("rev-parse", "--verify", "--quiet", commit + "^{commit}")
        if found.returncode != 0:
            raise SetupError(f"{self.path} has no commit {commit}: it needs a clone with the dataset's history "
                             "(a plain clone, or one made with --filter=blob:none; a shallow clone lacks it)")
        self.sha = found.stdout.decode("ascii").strip()
        self._proc = None

    def _git(self, *args):
        try:
            return subprocess.run(["git", "-C", str(self.path), "-c", "core.quotePath=true", *args],
                                  capture_output=True)
        except FileNotFoundError:
            raise SetupError("git is not installed") from None

    def paths(self):
        """Every path at the commit, as `git ls-tree -r` prints it; each blob's id kept for prefetch."""
        listed = self._git("ls-tree", "-r", self.sha)
        if listed.returncode != 0:
            raise SetupError(f"git ls-tree failed: {listed.stderr.decode(errors='replace').strip()}")
        self.blob_ids, paths = {}, []
        for line in listed.stdout.decode("utf-8", "surrogateescape").split("\n"):
            meta, tab, path = line.partition("\t")
            if tab:
                fields = meta.split()
                if len(fields) == 3 and fields[1] == "blob":
                    self.blob_ids[path] = fields[2]
                paths.append(path)
        return paths

    def prefetch(self, paths, log):
        """In a partial clone (--filter=blob:none), fetch the samples drawn that it lacks in one request, as git
        fetches a missing object (git would fetch them one at a time as they are read)."""
        name = self._promisor()
        if name is None:
            return                                    # a full clone has every sample
        listed = self._git("rev-list", "--objects", "--missing=print", self.sha)
        lacking = {line[1:] for line in listed.stdout.decode("ascii", "replace").split("\n") if line.startswith("?")}
        wanted = sorted({self.blob_ids[p] for p in paths if p in self.blob_ids} & lacking)
        if not wanted:
            return
        log(f"fetching the {len(wanted)} samples drawn from {name}")
        fetched = subprocess.run(["git", "-C", str(self.path), "-c", "fetch.negotiationAlgorithm=noop", "fetch", name,
                                  "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no",
                                  "--filter=blob:none", "--stdin"],
                                 input="".join(oid + "\n" for oid in wanted).encode("ascii"), capture_output=True)
        if fetched.returncode != 0:
            said = fetched.stderr.decode(errors="replace").strip().splitlines()
            log(f"  one request did not do ({said[-1] if said else fetched.returncode}): git fetches them one by one")

    def _promisor(self):
        """The remote a partial clone fetches missing objects from (extensions.partialClone, or a remote with
        promisor = true, as git 2.24 and later write it), else None."""
        named = self._git("config", "--get", "extensions.partialClone")
        if named.returncode == 0 and named.stdout.strip():
            return named.stdout.decode("utf-8", "replace").strip()
        flagged = self._git("config", "--bool", "--get-regexp", r"^remote\..*\.promisor$")
        for line in flagged.stdout.decode("utf-8", "replace").splitlines():
            key, _, value = line.partition(" ")
            if value.strip() == "true":
                return key[len("remote."):-len(".promisor")]
        return None

    def read(self, path):
        """A sample's bytes, at the commit (a clone without them fetches them now)."""
        if self._proc is None:
            self._proc = subprocess.Popen(["git", "-C", str(self.path), "cat-file", "--batch"],
                                          stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        self._proc.stdin.write(f"{self.sha}:{path}\n".encode("utf-8", "surrogateescape"))
        self._proc.stdin.flush()
        head = self._proc.stdout.readline()
        fields = head.split()
        if len(fields) != 3 or fields[1] != b"blob":
            if not head:
                raise SetupError("git cat-file stopped")
            raise Skip(f"not in the clone ({head.decode(errors='replace').strip()})")
        data = self._proc.stdout.read(int(fields[2]))
        self._proc.stdout.read(1)                     # the newline after the content
        return data

    def close(self):
        if self._proc is not None:
            self._proc.stdin.close()
            self._proc.wait()
            self._proc = None


# ---------------------------------------------------------------- one sample, in memory
def entry_name(info):
    """An entry's name as unzip reads it on a UTF-8 system: UTF-8 when the entry says so; else the name in
    Info-ZIP's Unicode Path field (0x7075) when that field is the stored name's; else the stored bytes, read as
    UTF-8 (zipfile reads them as cp437)."""
    if info.flag_bits & 0x800:
        return info.filename
    try:
        stored = info.orig_filename.encode("cp437")
    except UnicodeEncodeError:                        # a zipfile that read the name otherwise: take its reading
        return info.filename
    extra, at = info.extra, 0
    while at + 4 <= len(extra):
        tag, size = int.from_bytes(extra[at:at + 2], "little"), int.from_bytes(extra[at + 2:at + 4], "little")
        field = extra[at + 4:at + 4 + size]
        if tag == 0x7075 and len(field) > 5 and field[0] == 1 \
                and int.from_bytes(field[1:5], "little") == zlib.crc32(stored):
            try:
                return field[5:].decode("utf-8")
            except UnicodeDecodeError:
                break
        at += 4 + size
    return stored.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")


class Sample:
    """A sample's zip as `unzip -o -P infected` unpacked it for the harness, without unpacking it: each
    entry's path without empty, "." and ".." parts, the last entry of a path kept, links set apart.
    `files` and `tree` (files, links and the folders they imply) are sorted as pathlib sorts paths."""

    def __init__(self, data):
        if data.startswith(b"version https://git-lfs"):
            raise Skip("a Git LFS pointer, not the zip")
        try:
            self.zip = zipfile.ZipFile(io.BytesIO(data))
            infos = self.zip.infolist()
        except (zipfile.BadZipFile, ValueError, EOFError) as exc:
            raise Skip(f"not a zip ({exc})") from None
        self.entries = {}                             # path parts -> ZipInfo of a file, None for a link
        for info in infos:
            parts = tuple(p for p in entry_name(info).split("/") if p not in ("", ".", ".."))
            if parts and not info.is_dir():
                self.entries[parts] = None if stat.S_ISLNK(info.external_attr >> 16) else info
        self.files = sorted(p for p, info in self.entries.items() if info is not None)
        folders = {p[:k] for p in self.entries for k in range(1, len(p))}
        self.tree = sorted(set(self.entries) | folders)

    def read(self, parts):
        try:
            return self.zip.read(self.entries[parts], pwd=PASSWORD)
        except Exception as exc:                     # a damaged or unreadable entry: anything zipfile raises
            raise Skip(f"{'/'.join(parts)}: {exc}") from None

    def mode(self, parts):
        """The permissions unzip gives the file: a Unix entry's own, without setuid, setgid or sticky (unzip
        clears them unless given -K); 0o644 for another system's."""
        attr = self.entries[parts].external_attr >> 16
        return attr & 0o777 if self.entries[parts].create_system == 3 and attr else 0o644

    def mtime(self, parts):
        return calendar.timegm(self.entries[parts].date_time + (0, 0, 0))


def release_root(sample):
    """The folder holding the published release's own files: the one with the dataset's package_info-*.json
    (never in an upstream sources/ tree), else the shallowest one with PKG-INFO, setup.py, pyproject.toml or
    package.json outside sources/, else the sample's root."""
    infos = [p for p in sample.tree if fnmatch.fnmatchcase(p[-1], "package_info-*.json") and "sources" not in p]
    if infos:
        return min(infos, key=lambda p: (len(p), p))[:-1]
    marks = [p for p in sample.files if p[-1] in MARKS and "sources" not in p]
    if marks:
        return min(marks, key=lambda p: (len(p), p))[:-1]
    return ()


def undouble(parts):
    """A path the dataset stored at <rel>/<rel>, as <rel>."""
    n = len(parts)
    if n >= 2 and n % 2 == 0 and parts[:n // 2] == parts[n // 2:]:
        return parts[:n // 2]
    return parts


def release_files(sample, root):
    """(path in the release, entry) of each file under `root`, the doubled paths undone (the first of two
    that meet wins) and the dataset's package_info json left out."""
    out, seen = [], set()
    for parts in sample.files:
        if len(parts) <= len(root) or parts[:len(root)] != root or parts[-1].startswith("package_info-"):
            continue
        key = "/".join(undouble(parts[len(root):]))
        if key not in seen:
            seen.add(key)
            out.append((key, parts))
    return out


def norm_name(text):
    return re.sub(r"[-_.]+", "_", text).lower()


def archive_kind(data):
    """(container, kind) of a PyPI release file by its first bytes, (None, None) for anything else."""
    if data[:4] == b"PK\x03\x04":
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        except (zipfile.BadZipFile, ValueError, EOFError):
            return None, None
        return "zip", ("wheel" if any(re.search(r"\.dist-info/WHEEL$", n) for n in names) else "sdist")
    if data[:2] == b"\x1f\x8b":
        return "tgz", "sdist"
    if data[:3] == b"BZh":
        return "tbz2", "sdist"
    if data[:6] == b"\xfd7zXZ\x00":
        return "txz", "sdist"
    return None, None


def opens(data, container):
    """Whether the file opens as the archive its first bytes say (a gzipped pickle does not)."""
    try:
        if container == "zip":
            return zipfile.is_zipfile(io.BytesIO(data))
        return tarfile.is_tarfile(io.BytesIO(data))
    except Exception:                                  # a damaged archive: anything the readers raise
        return False


def release_archive(sample, root, name):
    """The release's own archive, at the release's top (not one nested in its tree), named for the package
    and opening as an archive -> (bytes, container, kind), else None."""
    want = norm_name(name)
    for parts in sample.files:
        if len(parts) != len(root) + 1 or parts[:len(root)] != root or not norm_name(parts[-1]).startswith(want):
            continue
        data = sample.read(parts)
        container, kind = archive_kind(data)
        if container and opens(data, container):
            return data, container, kind
    return None


def tgz(sample, files, prefix):
    """The files as a gzipped tar, each under `prefix`; gzip's header holds no time, so the same files give
    the same bytes on one machine."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz, tarfile.open(fileobj=gz, mode="w") as tar:
        for key, parts in files:
            data = sample.read(parts)
            info = tarfile.TarInfo(prefix + key)
            info.size, info.mode, info.mtime = len(data), sample.mode(parts), sample.mtime(parts)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def wheel(sample, files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as out:
        for key, parts in files:
            info = zipfile.ZipInfo(key, date_time=max(sample.entries[parts].date_time, (1980, 1, 1, 0, 0, 0)))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | sample.mode(parts)) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            try:
                out.writestr(info, sample.read(parts))
            except UnicodeEncodeError:                # a name that is not UTF-8: a zip cannot store it
                raise Skip(f"{key!r}: a file name a wheel cannot hold") from None
    return buf.getvalue()


def release(sample, item):
    """(bytes, container, kind) of the release a sample holds, as its registry serves it."""
    root = release_root(sample)
    files = release_files(sample, root)
    if item["eco"] == "npm":
        keys = {k for k, _ in files}
        if "package.json" not in keys and any(k.startswith("package/") for k in keys):
            files = [(k[len("package/"):], p) for k, p in files if k.startswith("package/")]
        if not any(k == "package.json" for k, _ in files):
            raise Skip("no package.json")
        return tgz(sample, files, "package/"), "tgz", "npm"
    found = release_archive(sample, root, item["name"])
    if found:
        return found
    prefix = f"{item['name']}-{item['version']}/"
    tops = {k.split("/", 1)[0] for k, _ in files}
    if len(tops) == 1 and all("/" in k for k, _ in files):
        top = next(iter(tops))                        # an sdist's own top folder
        if any(k in (top + "/PKG-INFO", top + "/setup.py", top + "/pyproject.toml") for k, _ in files):
            files = [(k[len(top) + 1:], p) for k, p in files]
            prefix = top + "/"
            tops = {k.split("/", 1)[0] for k, _ in files}
    if not files:
        raise Skip("no files")
    if any(t.endswith(".dist-info") for t in tops) and not SDIST_MARKS & tops:
        return wheel(sample, files), "zip", "wheel"
    return tgz(sample, files, prefix), "tgz", "sdist"


# ---------------------------------------------------------------- a set
def registry_name(item):
    return urllib.parse.unquote(item["name"])        # a scope's slash, if the dataset escapes it


def release_id(item):
    return f"datadog:{item['eco']}:{item['cat']}:{registry_name(item)}@{item['version']}"


def file_name(item, ext):
    stem = re.sub(r"[^A-Za-z0-9._@-]+", "_", f"{item['eco']}-{item['cat']}-{item['name']}-{item['version']}")
    tag = hashlib.sha256(item["path"].encode("utf-8", "surrogateescape")).hexdigest()[:8]
    return f"{stem[:100]}-{tag}{ext}"


def write_atomically(path, data):
    tmp = path.with_name(path.name + ".part")
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def read_lines(path):
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def prepare_set(dataset, set_dir, name, chosen, about, log):
    """Write one set: each release's file, a line for each in records.jsonl as it is done (what a stopped run
    goes on from), then manifest.jsonl (the releases, in the draw's order) and skipped.json."""
    files_dir = set_dir / "files"
    files_dir.mkdir(parents=True, exist_ok=True)
    about_path = set_dir / "draw.json"
    if about_path.exists():
        before = json.loads(about_path.read_text(encoding="utf-8"))
        if before != about:
            raise SetupError(f"{set_dir} holds another draw (commit {before.get('commit')}, seed "
                             f"{before.get('seed')}): give another OUT")
    else:
        about_path.write_text(json.dumps(about, indent=1) + "\n", encoding="utf-8")
    records = set_dir / "records.jsonl"
    done = {line["id"]: line for line in read_lines(records)}
    shown = time.monotonic()
    with open(records, "a", encoding="utf-8") as out:
        for n, item in enumerate(chosen, 1):
            rid = release_id(item)
            if rid in done and "skipped" not in done[rid] and os.path.isfile(done[rid]["artifact_path"]):
                continue                              # done (a skipped one is tried again: a fetch may have failed)
            try:
                body, container, kind = release(Sample(dataset.read(item["path"])), item)
            except Skip as exc:
                line = {"id": rid, "cat": item["cat"], "set": name, "skipped": str(exc)[:300], "source": item["path"]}
            else:
                dest = files_dir / file_name(item, EXTENSION[(container, kind)])
                write_atomically(dest, body)
                line = {"id": rid, "cat": item["cat"], "set": name, "eco": item["eco"], "name": registry_name(item),
                        "version": item["version"], "artifact_path": str(dest), "container": container,
                        "kind": kind, "sha256": hashlib.sha256(body).hexdigest(), "source": item["path"]}
            out.write(json.dumps(line) + "\n")
            out.flush()
            done[rid] = line
            if time.monotonic() - shown >= PROGRESS_SECONDS:
                log(f"{name}: {n} of {len(chosen)}")
                shown = time.monotonic()
    lines = [done[release_id(item)] for item in chosen]
    kept = [line for line in lines if "skipped" not in line]
    manifest = set_dir / "manifest.jsonl"
    write_atomically(manifest, "".join(json.dumps(line) + "\n" for line in kept).encode("utf-8"))
    skipped = [line for line in lines if "skipped" in line]
    write_atomically(set_dir / "skipped.json", (json.dumps(skipped, indent=1) + "\n").encode("utf-8"))
    return manifest, kept, skipped


def subsets(lines):
    counts = collections.Counter((line["eco"], line["cat"]) for line in lines)
    return ", ".join(f"{eco} {cat} {n}" for (eco, cat), n in sorted(counts.items()))


def lazaret_checkout(path):
    """The Lazaret checkout `path` is in (a folder with .git and scripts/bench.py), else None."""
    for folder in (path, *path.parents):
        if (folder / ".git").exists() and (folder / "scripts" / "bench.py").is_file():
            return folder
    return None


def prepare(dataset_path, out, commit=COMMIT, only=None, holdout_seed=HOLDOUT_SEED, log=print):
    out = pathlib.Path(out).expanduser().resolve()
    inside = lazaret_checkout(out)
    if inside:
        raise SetupError(f"{out} is inside the repository {inside}: keep the samples' files outside it")
    dataset = Dataset(dataset_path, commit)
    try:
        groups = samples_by_package(dataset.paths())
        benchmark = draw(groups, BENCHMARK_SEED, SIZES["benchmark"])
        holdout = draw(groups, holdout_seed, SIZES["holdout"], {(i["eco"], i["name"]) for i in benchmark})
        sets = [(name, seed, chosen) for name, seed, chosen in
                (("benchmark", BENCHMARK_SEED, benchmark), ("holdout", holdout_seed, holdout)) if only in (None, name)]
        dataset.prefetch([item["path"] for _name, _seed, chosen in sets for item in chosen], log)
        entries = []
        for name, seed, chosen in sets:
            about = {"dataset": "DataDog/malicious-software-packages-dataset", "commit": dataset.sha, "seed": seed,
                     "sizes": {f"{eco} {cat}": n for (eco, cat), n in SIZES[name].items()},
                     "releases": len(chosen), "draw": fingerprint(chosen)}
            log(f"{name}: {len(chosen)} releases drawn (draw {about['draw'][:16]})")
            manifest, kept, skipped = prepare_set(dataset, out / name, name, chosen, about, log)
            log(f"{name}: {len(kept)} releases ({subsets(kept)}), {len(skipped)} skipped")
            if name == "benchmark":
                for line in skipped:
                    log(f"  skipped {line['id']}: {line['skipped']}")
                if not dataset.sha.startswith(COMMIT) or len(chosen) != AUDIT_BENCHMARK or skipped:
                    log(f"  The audit's benchmark has {AUDIT_BENCHMARK} releases: this one differs, so its numbers "
                        "are not the ones the README and the CHANGELOG give.")
            elif skipped:
                log(f"  (the holdout's are in {out / name / 'skipped.json'}; read in aggregate only)")
            entry = {"name": name, "manifest": str(manifest)}
            if name == "holdout":
                entry["aggregate_only"] = True
            entries.append(entry)
    finally:
        dataset.close()
    log("A sets file's entries for them (scripts/bench.py all):")
    for entry in entries:
        log("  " + json.dumps(entry) + ",")
    return 0


def _configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    _configure_stdio()
    parser = argparse.ArgumentParser(
        description="Write the benchmark's and a holdout's manifests from DataDog's malicious-software-packages-"
                    "dataset, for scripts/bench.py.")
    parser.add_argument("dataset", help="a clone of DataDog/malicious-software-packages-dataset (not a shallow one)")
    parser.add_argument("out", help="the folder the sets go to: outside the repository and any synced folder")
    parser.add_argument("--commit", default=COMMIT, help="the dataset's commit (default: the audit's, %(default)s)")
    parser.add_argument("--only", choices=("benchmark", "holdout"), help="write one set")
    parser.add_argument("--holdout-seed", type=int, default=HOLDOUT_SEED,
                        help="the holdout's draw (default %(default)s); another seed draws another holdout")
    args = parser.parse_args(argv)
    try:
        return prepare(args.dataset, args.out, args.commit, args.only, args.holdout_seed)
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
