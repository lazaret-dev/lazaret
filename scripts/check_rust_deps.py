#!/usr/bin/env python3
"""Fail when the Rust workspace depends on anything outside itself.

The native engine uses no external crates (docs/RUST_ENGINE.md): every
member depends only on the standard library and on other members, so a
build needs no registry and the whole engine is in this repository to
audit. This checks rust/Cargo.lock (every package is a workspace member,
with no `source`: nothing from crates.io, git or another registry) and each
member's Cargo.toml (every dependency, dev- and build-dependency is a
`path` to another member). CI runs it; exit 1 names what is wrong.

It also holds the line between the engine and the network (NET-1): pratique
(rust/crates/pratique, taken as it is upstream) is depended on only by
lazaret-verify, without its `net` feature (`default-features = false`: no
I/O, no `unsafe`), and by lazaret-net; lazaret-net only by lazaret-ffi, and
only for targets other than WebAssembly; and the engine (lazaret-engine)
depends on neither pratique nor lazaret-net, so the engine may use the pure
verification part (through lazaret-verify) and never the sockets.

Usage: python3 scripts/check_rust_deps.py. Standard library only.
"""
import os
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUST = ROOT / "rust"
_SECTION_RE = re.compile(r"^\[(?:target\.[^\]]+\.)?((?:dev-|build-)?dependencies)\]\s*$")
_TABLE_RE = re.compile(r"^\[")
_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+)\s*=\s*(.*)$")


def _configure_stdio():
    """Redirected output is UTF-8 unless PYTHONIOENCODING says otherwise, and
    never raises on a character the stream can't encode (STRUCTURE.md,
    "Cross-platform rules")."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def members():
    """{name: directory} of the workspace members (rust/crates/*/Cargo.toml)."""
    out = {}
    for toml in sorted((RUST / "crates").glob("*/Cargo.toml"), key=lambda p: p.as_posix()):
        m = re.search(r'(?m)^name\s*=\s*"([^"]+)"', toml.read_text(encoding="utf-8"))
        if m:
            out[m.group(1)] = toml.parent
    return out


def lock_problems(names, lock=None):
    """What Cargo.lock (rust/Cargo.lock by default) holds beyond the
    workspace's own packages."""
    lock = RUST / "Cargo.lock" if lock is None else lock
    if not lock.is_file():
        return ["rust/Cargo.lock is missing"]
    problems, current = [], None
    for line in lock.read_text(encoding="utf-8").splitlines():
        if line.strip() == "[[package]]":
            current = None
            continue
        m = re.match(r'^name\s*=\s*"([^"]+)"', line)
        if m:
            current = m.group(1)
            if current not in names:
                problems.append(f"Cargo.lock: package {current} is not a workspace member")
        elif re.match(r"^source\s*=", line):
            problems.append(f"Cargo.lock: package {current} comes from {line.split('=', 1)[1].strip()}")
    return problems


def manifest_dependencies(directory):
    """(section header, its kind, dependency, value) for each dependency line of
    a member's Cargo.toml (`dependencies`, `dev-dependencies`,
    `build-dependencies`, a target's too)."""
    section = header = None
    for raw in (directory / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip() if not raw.strip().startswith("[target.") else raw.strip()
        if not line:
            continue
        m = _SECTION_RE.match(line)
        if m:
            section, header = m.group(1), line
            continue
        if _TABLE_RE.match(line):
            section = header = None
            continue
        if section is None:
            continue
        k = _KEY_RE.match(line)
        if k:
            yield header, section, k.group(1), k.group(2)


#: who may depend on the library and on the network crate (NET-1)
_NATIVE_ONLY = "[target.'cfg(not(target_arch = \"wasm32\"))'.dependencies]"


def purity_problems(names):
    """The dependencies that cross the line between the engine and the network
    (see the module documentation)."""
    problems = []
    for name, directory in names.items():
        for header, section, dep, value in manifest_dependencies(directory):
            if dep == "pratique":
                if name == "lazaret-verify" and section == "dependencies":
                    if not re.search(r"\bdefault-features\s*=\s*false\b", value):
                        problems.append("lazaret-verify: pratique without default-features = false (its pure part "
                                        "only: no I/O, no unsafe)")
                elif name != "lazaret-net":
                    problems.append(f"{name}: {header} pratique (only lazaret-verify, the pure part, and "
                                    "lazaret-net depend on the library)")
            elif dep == "lazaret-net":
                if name != "lazaret-ffi" or header != _NATIVE_ONLY:
                    problems.append(f"{name}: {header} lazaret-net (only the native library, lazaret-ffi, links the "
                                    f"network, under {_NATIVE_ONLY})")
    return problems


def manifest_problems(name, directory, names):
    """The dependencies of one member's Cargo.toml that are not path
    dependencies on another member."""
    problems, section = [], None
    for raw in (directory / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _SECTION_RE.match(line)
        if m:
            section = m.group(1)
            continue
        if _TABLE_RE.match(line):
            section = None
            continue
        if section is None:
            continue
        k = _KEY_RE.match(line)
        if not k:
            continue
        dep, value = k.group(1), k.group(2)
        if dep not in names or "path" not in value or re.search(r"\b(?:git|registry|version)\s*=", value):
            problems.append(f"{name}: {section} {dep} = {value} (only a path to a workspace member is allowed)")
    return problems


def main(argv=None):
    _configure_stdio()
    names = members()
    if not names:
        print("error: no workspace members under rust/crates", file=sys.stderr)
        return 1
    problems = lock_problems(names)
    for name, directory in names.items():
        problems += manifest_problems(name, directory, names)
    problems += purity_problems(names)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if problems:
        return 1
    print(f"ok: {len(names)} workspace crates, no external dependencies ({', '.join(sorted(names))})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
