"""crates.io (0.1.9, R-1): resolving a crate to its `.crate` archive, checking it against the registry's own checksum,
and saying which of its files run when it is built.

    names        `[A-Za-z0-9_-]`, 1 to 64 characters, starting with a letter or a digit. Two spellings that differ only in
                 case, `-` and `_` are one crate to crates.io; `identity` folds them. The index does NOT: its file for
                 `foo_bar` is not the file for `foo-bar`, so a spec uses the spelling the crate is registered under (as
                 cargo does), and the module does not guess.
    versions     SemVer 2.0, at most 100 characters. A build-metadata suffix is part of the version string the index
                 prints, and is ignored for ordering and for telling two versions apart (the index may not list both).
    the index    `https://index.crates.io/<path>` (sparse index): one JSON object per version, oldest first. The path is
                 lowercase: `1/a`, `2/ab`, `3/a/abc`, `se/rd/serde`. The `name` inside is the crate's spelling, and the
                 download URL needs that spelling (`Inflector/Inflector-0.11.4.crate`; the lowercase form is refused).
    the download `https://static.crates.io/crates/<name>/<name>-<version>.crate`: a gzip tar whose members all sit under
                 `<name>-<version>/`. `cksum` in the index is the SHA-256 of the file.
    the archive  cargo unpacks regular files and directories only and refuses the whole crate for any other entry type
                 or for a member outside `<name>-<version>/` (`cargo::sources::registry::unpack`), and skips files named
                 `.cargo-ok`. So `links_extracted` is False: no link is ever created. A crate with one cannot be built
                 from the registry, and `iter_archive` still reports it as an anomaly.
    what runs    at build, `build.rs` (or the path `package.build` names, unless it is `false`) and, for a proc-macro
                 crate, the library root; those are `install_scripts`. `entries` are the library root and the binaries.
                 Nothing runs when a crate is merely loaded, so `startup` is empty.

Only the two CDN hosts are declared (they have no rate limit; the 1 request per second of crates.io's crawler policy is for
its API, which this module does not use). The module reads the index with `fetch.json_lines` and keeps, for each version,
only what it needs: the `features` of a large crate are most of its index file. No Rust is run and no build is started."""

import hashlib
import re

from lazaret.registry.ecosystems import base
from lazaret.scanner import sca

__all__ = ["Crates", "ECOSYSTEM", "index_path", "semver_key", "MAX_NAME", "MAX_INDEX_BYTES"]

INDEX_HOST = "index.crates.io"
DOWNLOAD_HOST = "static.crates.io"
MAX_NAME = 64
MAX_VERSION = 100
MAX_INDEX_BYTES = 64 * 1024 * 1024        # the larger crates' index files are tens of MB (thousands of versions, long feature lists)
MAX_VERSIONS = 100_000
MAX_DEPS = 5_000
MAX_SPEC = 512                            # a version requirement kept as written, no further

_NAME_CHAR = re.compile(r"[A-Za-z0-9_-]")
_NUM = r"(?:0|[1-9][0-9]*)"
_PRE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_BUILD = r"[0-9A-Za-z-]+"
SEMVER_RE = re.compile(rf"({_NUM})\.({_NUM})\.({_NUM})(?:-({_PRE}(?:\.{_PRE})*))?(?:\+({_BUILD}(?:\.{_BUILD})*))?")
_CKSUM_RE = re.compile(r"[0-9a-fA-F]{64}")
_KINDS = ("normal", "build", "dev")


def index_path(name):
    """Where the sparse index keeps the file of crate `name` (already checked): lowercase, by length."""
    low = name.lower()
    if len(low) <= 2:
        return f"{len(low)}/{low}"
    if len(low) == 3:
        return f"3/{low[0]}/{low}"
    return f"{low[:2]}/{low[2:4]}/{low}"


def semver_key(version):
    """A key that sorts versions by SemVer precedence (build metadata ignored), or None for a string that is not a
    version. A release sorts after its own pre-releases; identifiers of digits sort below the others, as numbers."""
    m = SEMVER_RE.fullmatch(version) if isinstance(version, str) and len(version) <= MAX_VERSION else None
    if m is None:
        return None
    major, minor, patch, pre, _build = m.groups()
    ids = () if pre is None else tuple((0, int(i), "") if i.isdigit() else (1, 0, i) for i in pre.split("."))
    return int(major), int(minor), int(patch), 1 if pre is None else 0, ids


def _core(version):
    return version.split("+", 1)[0]


def _reduce(rec):
    """One index line -> only what the module uses, or FetchError. Shapes are checked here so that nothing after this
    handles an index line of the wrong type."""
    if not isinstance(rec, dict):
        raise base.FetchError("crates: an index line is not an object")
    name, vers, cksum, yanked = rec.get("name"), rec.get("vers"), rec.get("cksum"), rec.get("yanked")
    if not (isinstance(name, str) and isinstance(vers, str) and isinstance(cksum, str)
            and type(yanked) is bool and _CKSUM_RE.fullmatch(cksum)):
        raise base.FetchError("crates: an index line lacks a name, version, checksum or yanked flag, or has a wrong one")
    if semver_key(vers) is None:
        raise base.FetchError("crates: an index line has a version that is not SemVer")
    deps = rec.get("deps", [])
    if not isinstance(deps, list) or len(deps) > MAX_DEPS:
        raise base.FetchError("crates: an index line has a dependency list that is not a list, or is too long")
    kept = []
    for dep in deps:
        if not isinstance(dep, dict) or not isinstance(dep.get("name"), str):
            raise base.FetchError("crates: an index line has a dependency that is not an object with a name")
        kind = dep.get("kind") or "normal"
        package = dep.get("package")
        if kind not in _KINDS or not (package is None or isinstance(package, str)):
            raise base.FetchError("crates: an index line has a dependency with a wrong kind or package")
        kept.append((package or dep["name"], kind))
    rust_version, links = rec.get("rust_version"), rec.get("links")
    return {"name": name, "vers": vers, "cksum": cksum.lower(), "yanked": yanked, "deps": kept,
            "rust_version": rust_version if isinstance(rust_version, str) and len(rust_version) <= 40 else None,
            "links": links if isinstance(links, str) and len(links) <= 100 else None}


class Crates(base.Ecosystem):
    id = "crates"
    title = "crates.io"
    hosts = frozenset({INDEX_HOST, DOWNLOAD_HOST})
    artifact_kinds = ("crate",)
    rate = {}
    manifest_names = frozenset({"Cargo.toml"})

    # ---- names and versions
    def check_name(self, name):
        name = base.ascii_name(name, "crate name", _NAME_CHAR, MAX_NAME, self.id)
        if name[0] in "-_":
            raise base.SpecError("crates: a crate name starts with a letter or a digit")
        return name

    def identity(self, name):
        return self.check_name(name).lower().replace("_", "-")

    def check_version(self, version):
        if version is None:
            return None
        if not isinstance(version, str) or not version.strip():
            raise base.SpecError(f"crates: invalid version {base.show(version)}")
        version = version.strip()
        if semver_key(version) is None:
            raise base.SpecError(f"crates: invalid version {base.show(version)}")
        return version

    def _name_ok(self, name):
        try:
            self.check_name(name)
        except base.SpecError:
            return False
        return True

    # ---- the network
    def resolve(self, name, version, fetch):
        name = self.check_name(name)
        want = self.check_version(version)
        records = fetch.json_lines(f"https://{INDEX_HOST}/{index_path(name)}", max_bytes=MAX_INDEX_BYTES, select=_reduce)
        if not records:
            raise base.FetchError("crates: the index file lists no versions")
        if len(records) > MAX_VERSIONS:
            raise base.FetchError("crates: the index file lists too many versions")
        by_core = {}
        for rec in records:
            if rec["name"].lower() != name.lower():
                raise base.FetchError("crates: the index file lists another crate")
            if _core(rec["vers"]) in by_core:
                raise base.FetchError("crates: the index file lists a version twice")
            by_core[_core(rec["vers"])] = rec
        if want is not None:
            rec = by_core.get(_core(want))
            if rec is None:
                raise base.SpecError(f"crates: no version {base.show(want)} of {base.show(name)}")
        else:
            rec = self._latest(records, name)
        crate = self.check_name(rec["name"])
        filename = f"{crate}-{rec['vers']}.crate"
        url = f"https://{DOWNLOAD_HOST}/crates/{self.segment(crate)}/{self.segment(crate)}-{self.segment(rec['vers'])}.crate"
        art = {"url": url, "container": "tgz", "artifact": "crate", "entry": rec, "filename": filename}
        return base.Resolution(rec["vers"], [art], [], {"name": crate, "yanked": rec["yanked"],
                                                       "rust_version": rec["rust_version"], "links": rec["links"]})

    @staticmethod
    def _latest(records, name):
        """The highest version that is not yanked, a release before a pre-release (what `cargo add` picks)."""
        live = [r for r in records if not r["yanked"]]
        if not live:
            raise base.FetchError(f"crates: every version of {base.show(name)} is yanked")
        releases = [r for r in live if semver_key(r["vers"])[3] == 1]
        pool = releases or live
        return max(pool, key=lambda r: (semver_key(r["vers"]), r["vers"]))

    def verify(self, data, entry, name, version):
        cksum = entry.get("cksum") if isinstance(entry, dict) else None
        if not isinstance(cksum, str) or not _CKSUM_RE.fullmatch(cksum):
            return None
        actual = hashlib.sha256(data).hexdigest()
        if actual != cksum.lower():
            raise base.DigestError(f"crates: the SHA-256 of the download does not match the cksum the index published "
                                   f"for {base.show(name)} {base.show(version)}")
        return "sha256", actual

    def dependencies(self, resolved, fetch):
        """The crates a release depends on when it is built (normal and build dependencies; a dev dependency is never
        fetched for a user of the crate), as the registry spells them: the index line's `deps`, renames undone."""
        try:
            entry = resolved.artifacts[0]["entry"]
            deps = entry["deps"]
        except (AttributeError, IndexError, KeyError, TypeError):
            return None
        return tuple(sorted({n for n, kind in deps if kind in ("normal", "build") and self._name_ok(n)}))

    # ---- archives
    def container(self, filename):
        return "tgz" if isinstance(filename, str) and filename.endswith(".crate") else None

    def archive_root(self, resolved, artifact):
        try:
            crate, version = resolved.info["name"], resolved[0]
        except (AttributeError, KeyError, TypeError):
            return None
        return f"{crate}-{version}/" if self._name_ok(crate) and isinstance(version, str) and semver_key(version) else None

    def member_path(self, kind, name, root=None):
        rel, problem = base.root_stripped(name, root) if root else base.top_directory_stripped(name)
        if rel is not None and rel.rsplit("/", 1)[-1] == ".cargo-ok":                # (cargo skips these)
            return None, None
        return rel, problem

    def links_extracted(self, kind):
        return False

    # ---- what is read in an archive, and what runs
    @staticmethod
    def _cargo(manifests):
        text = manifests.get("Cargo.toml") if isinstance(manifests, dict) else None
        if not isinstance(text, str) or not text.strip():
            return {}
        try:
            doc = sca.load_toml(text)
        except (ValueError, RecursionError):
            return {}                                          # (a manifest cargo would refuse: its build.rs is still a risk)
        return doc if isinstance(doc, dict) else {}

    @staticmethod
    def _path(value):
        if not isinstance(value, str) or len(value) > 512:
            return None
        return base.finish_member_path(value.replace("\\", "/"))[0]

    def run_targets(self, kind, manifests, members):
        present = {m for m in (members or ()) if isinstance(m, str)}
        doc = self._cargo(manifests)
        pkg = doc.get("package") if isinstance(doc.get("package"), dict) else doc.get("project")
        pkg = pkg if isinstance(pkg, dict) else {}
        entries, scripts = set(), set()
        build = pkg.get("build")
        if build is not False:
            script = self._path(build) if isinstance(build, str) else "build.rs"
            if script in present:
                scripts.add(script)
        lib = doc.get("lib") if isinstance(doc.get("lib"), dict) else {}
        root = self._path(lib.get("path")) if isinstance(lib.get("path"), str) else "src/lib.rs"
        if root in present:
            entries.add(root)
            if lib.get("proc-macro") is True or lib.get("proc_macro") is True:
                scripts.add(root)                              # (it runs inside the compiler of every crate that uses it)
        bins = doc.get("bin") if isinstance(doc.get("bin"), list) else []
        for b in bins:
            if isinstance(b, dict) and isinstance(b.get("path"), str) and self._path(b["path"]) in present:
                entries.add(self._path(b["path"]))
        for m in present:
            parts = m.split("/")
            if m == "src/main.rs" or (parts[:2] == ["src", "bin"] and (
                    (len(parts) == 3 and m.endswith(".rs")) or (len(parts) == 4 and parts[3] == "main.rs"))):
                entries.add(m)
        return base.RunTargets(entries=entries, install_scripts=scripts)

    def declared(self, kind, manifests, members):
        doc = self._cargo(manifests)
        pkg = doc.get("package") if isinstance(doc.get("package"), dict) else doc.get("project")
        name = pkg.get("name") if isinstance(pkg, dict) and isinstance(pkg.get("name"), str) else None
        tables = [doc.get("dependencies"), doc.get("build-dependencies"), doc.get("build_dependencies")]
        target = doc.get("target")
        if isinstance(target, dict):
            for each in list(target.values())[:1000]:
                if isinstance(each, dict):
                    tables += [each.get("dependencies"), each.get("build-dependencies"), each.get("build_dependencies")]
        found, specs, aliases = set(), {}, {}
        for table in tables:
            if not isinstance(table, dict):
                continue
            for key, spec in list(table.items())[:MAX_DEPS]:
                real = spec.get("package") if isinstance(spec, dict) and isinstance(spec.get("package"), str) else key
                if not self._name_ok(real):
                    continue
                found.add(real)
                if real not in specs:                                # (the first table that names it: [dependencies] before the builds')
                    version = spec if isinstance(spec, str) else spec.get("version") if isinstance(spec, dict) else None
                    specs[real] = version[:MAX_SPEC] if isinstance(version, str) else None
                if real != key and real not in aliases and isinstance(key, str) and self._name_ok(key):
                    aliases[real] = key
        names = sorted(found)[:MAX_DEPS]
        keep = set(names)
        return base.Declared(name if name is not None and self._name_ok(name) else None, names,
                             {k: v for k, v in specs.items() if k in keep}, {k: v for k, v in aliases.items() if k in keep})


ECOSYSTEM = Crates()
