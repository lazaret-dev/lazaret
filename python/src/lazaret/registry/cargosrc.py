"""Cargo's settings, lockfile and registries: what `lazaret guard cargo` reads to find the crates a command will build and where each
one is fetched.

    sources(cwd, env)            the `[source.*]` tables of Cargo's configuration files -> {name: {key: value}}
    registry_of(sources)         where crates.io is read from once source replacement is applied -> Registry
    classify(source)             a Cargo.lock `source` -> Source(kind, url): path, git, crates-io, sparse, git-index, other
    parse_lock(text)             Cargo.lock -> [Package(name, version, source, checksum)]
    index_url(base, name)        where the sparse index keeps a crate's file
    download_url(dl, ...)        a crate's `.crate` from the registry's config.json `dl`
    index_record(text, version)  one version's line of an index file -> {cksum, yanked, pubtime}
    parse_install(args)          `cargo install` arguments -> Install(crates, locked, offline)
    parse_project(args)          the options of any other command that matter -> Project
    crate_dirs(home)             the crates cargo has unpacked; cached_crate(...) a `.crate` it holds

Nothing here fetches or runs anything. Every name and version that reaches a URL or a path is checked first (a crate name is
`[A-Za-z0-9_-]` up to 64, a version is SemVer), so a hostile lockfile can say nothing but a crate to fetch.

Standard library, `scanner.sca` (TOML) and `ecosystems.crates` (names, versions, the index layout)."""

import collections
import hashlib
import json
import os
import re

from lazaret.registry.ecosystems import base, crates
from lazaret.scanner import sca

__all__ = ["Registry", "Source", "Package", "Install", "Project", "sources", "registry_of", "classify", "parse_lock", "crate_ok",
           "index_url", "download_url", "index_record", "parse_install", "parse_project", "cargo_home", "crate_dirs",
           "cached_crate", "MAX_LOCK_BYTES", "MAX_PACKAGES", "MAX_CONFIG_BYTES", "DEFAULT_INDEX"]

DEFAULT_INDEX = "https://index.crates.io/"
#: the two spellings of crates.io's own index (the git one and the sparse one): the same crates
_CRATES_IO_INDEXES = ("https://github.com/rust-lang/crates.io-index", "https://index.crates.io")
MAX_CONFIG_BYTES = 256 * 1024
MAX_LOCK_BYTES = 32 * 1024 * 1024
MAX_PACKAGES = 5000
_HEX64 = re.compile(r"[0-9a-f]{64}")
_REQUIREMENT = re.compile(r"[0-9A-Za-z.*^~<>=, +-]{1,100}")
_EXACT = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.+-]*)?")
_PUBTIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_METADATA_KEY = re.compile(r"checksum (\S+) (\S+) \((.+)\)")

Registry = collections.namedtuple("Registry", "kind url")
Source = collections.namedtuple("Source", "kind url")
Package = collections.namedtuple("Package", "name version source checksum")
Install = collections.namedtuple("Install", "crates locked offline")
Project = collections.namedtuple("Project", "manifest_path locked offline")


def cargo_home(env):
    """CARGO_HOME, or ~/.cargo."""
    explicit = (env or {}).get("CARGO_HOME")
    return explicit if explicit else os.path.join(os.path.expanduser("~"), ".cargo")


def _read_config(path):
    """One configuration file as a dict, or {} when it is missing, too large or not TOML (cargo itself will then say so)."""
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            return {}
        doc = sca.load_toml(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return {}
    return doc


def sources(cwd, env):
    """The `[source.<name>]` tables of cargo's configuration -> {name: {key: str}}. Cargo reads `.cargo/config.toml` (or the older
    `.cargo/config`) in the current folder and each folder above it, then `$CARGO_HOME/config.toml`; what a folder nearer to the
    current one says wins, key by key."""
    folders, here = [], os.path.abspath(cwd)
    while True:
        folders.append(os.path.join(here, ".cargo"))
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    folders.append(cargo_home(env))                                  # (read twice when it is also one of the folders above: the same answer)
    merged = {}
    for folder in reversed(folders):                                 # (the farthest first, so that the nearest overrides)
        for name in ("config", "config.toml"):                       # (config.toml wins over config in one folder)
            table = _read_config(os.path.join(folder, name)).get("source")
            for source, keys in (table.items() if isinstance(table, dict) else ()):
                if isinstance(keys, dict):
                    merged.setdefault(source, {}).update({k: v for k, v in keys.items() if isinstance(v, str)})
    return merged


def registry_of(table):
    """Where crates.io is read from, once cargo's source replacement is followed (`[source.crates-io] replace-with`) ->
    Registry(kind, url). kind: "sparse" (an HTTP index: the default, or a mirror's), or what the guard cannot read: "git" (a git
    index), "directory", "local-registry", "git-source" (a vendor folder, a local registry, a git repository), "unknown"."""
    name, seen = "crates-io", set()
    while True:
        target = table.get(name, {}).get("replace-with")
        if not target:
            break
        if name in seen:
            return Registry("unknown", name)                         # (a loop: cargo refuses it too)
        seen.add(name)
        name = target
    if name == "crates-io":
        return Registry("sparse", DEFAULT_INDEX)
    keys = table.get(name, {})
    url = keys.get("registry")
    if url:
        if url.startswith("sparse+"):
            url = url[len("sparse+"):]
            return Registry("sparse", url if url.endswith("/") else url + "/")
        if url.rstrip("/") in _CRATES_IO_INDEXES:
            return Registry("sparse", DEFAULT_INDEX)
        return Registry("git", url)
    for key, kind in (("directory", "directory"), ("local-registry", "local-registry"), ("git", "git-source")):
        if key in keys:
            return Registry(kind, keys[key])
    return Registry("unknown", name)


def classify(source):
    """A Cargo.lock `source` -> Source(kind, url): "path" (none: the project's own or a workspace member), "git", "crates-io",
    "sparse" (another registry with an HTTP index; url is its index), "git-index" (another registry, a git index), "other"."""
    if not isinstance(source, str) or not source:
        return Source("path", "")
    if source.startswith("git+"):
        return Source("git", source[4:])
    for prefix, sparse in (("sparse+", True), ("registry+", False)):
        if source.startswith(prefix):
            url = source[len(prefix):]
            if url.rstrip("/") in _CRATES_IO_INDEXES:
                return Source("crates-io", url)
            if sparse:
                return Source("sparse", url if url.endswith("/") else url + "/")
            return Source("git-index", url)
    return Source("other", source)


def crate_ok(name, version):
    """Is this a crate name and a version that may be put in a URL or a path?"""
    try:
        crates.ECOSYSTEM.check_name(name)
    except base.SpecError:
        return False
    return isinstance(version, str) and len(version) <= crates.MAX_VERSION and crates.SEMVER_RE.fullmatch(version) is not None


def parse_lock(text):
    """Cargo.lock -> [Package(name, version, source, checksum)], in the file's order. source is the lock's text ("" for a path
    dependency or a workspace member); checksum is the lowercase hex SHA-256 of the `.crate`, or None (Cargo.lock before version 2
    keeps them in `[metadata]`: those are read too). ValueError when the text is not a lockfile, is over MAX_LOCK_BYTES or lists
    over MAX_PACKAGES crates."""
    if not isinstance(text, str) or len(text) > MAX_LOCK_BYTES:
        raise ValueError("Cargo.lock: not text, or too large")
    doc = sca.load_toml(text)
    items = doc.get("package", [])
    if not isinstance(items, list):
        raise ValueError("Cargo.lock: `package` is not a list")
    if len(items) > MAX_PACKAGES:
        raise ValueError(f"Cargo.lock: more than {MAX_PACKAGES} packages")
    metadata = doc.get("metadata")
    old = {}
    for key, value in (metadata.items() if isinstance(metadata, dict) else ()):
        m = _METADATA_KEY.fullmatch(key)                        # (a TOML key is always text)
        if m and isinstance(value, str):
            old[m.groups()] = value
    out = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str) or not isinstance(item.get("version"), str):
            continue
        name, version, source = item["name"], item["version"], item.get("source")
        source = source if isinstance(source, str) else ""
        checksum = item.get("checksum")
        if not isinstance(checksum, str):
            checksum = old.get((name, version, source))
        checksum = checksum.lower() if isinstance(checksum, str) and _HEX64.fullmatch(checksum.lower()) else None
        out.append(Package(name, version, source, checksum))
    return out


def prefix(name):
    """`{prefix}` in a registry's `dl`: the folders the index keeps a crate under, in the name's own case (`ca/rg` for cargo)."""
    if len(name) <= 2:
        return str(len(name))
    return f"3/{name[0]}" if len(name) == 3 else f"{name[:2]}/{name[2:4]}"


def index_url(base, name):
    """Where the sparse index at `base` (its url, with the trailing slash) keeps crate `name`'s file."""
    return base + crates.index_path(name)


def download_url(dl, name, version, checksum=None):
    """A crate's download URL from the registry's `dl` (config.json): the markers {crate}, {version}, {prefix}, {lowerprefix} and
    {sha256-checksum}, or with none of them `<dl>/<crate>/<version>/download`. ValueError when {sha256-checksum} is wanted and the
    checksum is not known."""
    markers = ("{crate}", "{version}", "{prefix}", "{lowerprefix}", "{sha256-checksum}")
    if not any(m in dl for m in markers):
        return f"{dl}/{name}/{version}/download"
    if "{sha256-checksum}" in dl and not checksum:
        raise ValueError("the registry's download URL wants the checksum, which is not known")
    return (dl.replace("{crate}", name).replace("{version}", version).replace("{prefix}", prefix(name))
            .replace("{lowerprefix}", prefix(name).lower()).replace("{sha256-checksum}", checksum or ""))


def index_record(text, version):
    """One version's line of an index file (one JSON object per line) -> {"cksum", "yanked", "pubtime"} (pubtime a string of the
    form 2025-11-12T19:30:12Z, or None: it is optional), or None when the file has no line of that version. A line that is not
    JSON is skipped."""
    for line in text.splitlines():
        if version not in line:                                       # (most lines are other versions: not worth parsing)
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("vers") != version:
            continue
        cksum, pubtime = rec.get("cksum"), rec.get("pubtime")
        return {"cksum": cksum.lower() if isinstance(cksum, str) and _HEX64.fullmatch(cksum.lower()) else None,
                "yanked": rec.get("yanked") is True,
                "pubtime": pubtime if isinstance(pubtime, str) and _PUBTIME.fullmatch(pubtime) else None}
    return None


#: `cargo install`'s options that take the next argument as their value
_INSTALL_VALUE = frozenset(("--version", "--git", "--branch", "--tag", "--rev", "--path", "--root", "--index", "--registry",
                            "--features", "-F", "--bin", "--example", "--target", "--target-dir", "--profile", "-j", "--jobs",
                            "--config", "--manifest-path", "--color", "-Z", "--message-format", "--lockfile-path",
                            "--artifact-dir"))
_INSTALL_REFUSED = {"--git": "a git repository", "--path": "a folder", "--index": "another index", "--registry": "another registry",
                    "--list": "a list"}


def _requirement(text):
    """A version for the scratch project's dependency: three numbers (and a pre-release) mean that version exactly, as for
    `cargo install --version`; anything else is a requirement. ValueError when it is neither."""
    text = text.strip()
    if _EXACT.fullmatch(text):
        return "=" + text
    if not _REQUIREMENT.fullmatch(text):
        raise ValueError(f"not a version or a version requirement: {text[:40]!r}")
    return text


def parse_install(args):
    """The arguments of `cargo install` (after the word install) -> Install(crates, locked, offline). crates: [(name, requirement
    or None)], each as `name`, `name@version` or with `--version`. ValueError, with the reason, for what the guard does not read:
    a git repository, a folder, another registry, no crate named, or an argument that cannot be read."""
    found, version, locked, offline = [], None, False, False
    k = 0
    while k < len(args):
        arg = args[k]
        k += 1
        flag, eq, value = arg.partition("=")
        if arg == "--":
            break
        if flag in _INSTALL_REFUSED:
            raise ValueError(f"cargo install {flag} is not one the guard reads ({_INSTALL_REFUSED[flag]}): it checks crates from "
                             f"crates.io")
        if arg in ("--locked", "--frozen"):
            locked = True
            offline = offline or arg == "--frozen"
        elif arg == "--offline":
            offline = True
        if arg.startswith("-"):
            if flag in _INSTALL_VALUE and not eq:
                if k >= len(args):
                    raise ValueError(f"{flag} wants a value")
                value, k = args[k], k + 1
            if flag == "--version":
                version = value
            continue
        found.append(arg)
    if not found:
        raise ValueError("name the crate to install: lazaret guard cargo install <crate>")
    if version is not None and len(found) > 1:
        raise ValueError("--version with more than one crate")
    out = []
    for spec in found:
        name, at, want = spec.partition("@")
        if not name or (at and not want):
            raise ValueError(f"cannot read {spec[:60]!r} as a crate")
        if at and version is not None:
            raise ValueError("a version both after @ and with --version")
        req = want if at else version
        out.append((name, _requirement(req) if req is not None else None))
        if not crate_ok(name, "0.0.0"):
            raise ValueError(f"{spec[:60]!r} is not a crate name")
    return Install(out, locked, offline)


def parse_project(args):
    """The options of a cargo command that the guard needs (up to `--`, after which come the program's own) ->
    Project(manifest_path or None, locked, offline); `--frozen` is both."""
    manifest, locked, offline = None, False, False
    k = 0
    while k < len(args):
        arg = args[k]
        k += 1
        if arg == "--":
            break
        if arg == "--manifest-path" and k < len(args):
            manifest, k = args[k], k + 1
        elif arg.startswith("--manifest-path="):
            manifest = arg[len("--manifest-path="):]
        elif arg == "--locked":
            locked = True
        elif arg == "--offline":
            offline = True
        elif arg == "--frozen":
            locked = offline = True
    return Project(manifest, locked, offline)


def crate_dirs(home):
    """The names (`name-version`) of the crates cargo has unpacked: the folders of `$CARGO_HOME/registry/src/<registry>/`."""
    found = set()
    root = os.path.join(home, "registry", "src")
    try:
        for registry in os.listdir(root):
            try:
                found.update(n for n in os.listdir(os.path.join(root, registry)) if os.path.isdir(os.path.join(root, registry, n)))
            except OSError:
                continue
    except OSError:
        pass
    return found


def cached_crate(home, name, version, checksum):
    """The bytes of crate `name-version` as cargo holds it (`$CARGO_HOME/registry/cache/<registry>/name-version.crate`) when their
    SHA-256 is `checksum`, else None. A file with other bytes is not that crate."""
    root = os.path.join(home, "registry", "cache")
    try:
        registries = sorted(os.listdir(root))
    except OSError:
        return None
    for registry in registries:
        path = os.path.join(root, registry, f"{name}-{version}.crate")
        try:
            if os.path.getsize(path) > 64 * 1024 * 1024:
                continue
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if hashlib.sha256(data).hexdigest() == checksum:
            return data
    return None
