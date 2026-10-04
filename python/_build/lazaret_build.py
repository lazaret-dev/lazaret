"""Lazaret's build backend (PEP 517 / PEP 660), standard library only.

Building Lazaret downloads nothing: pyproject.toml declares no build
requirements and points here via backend-path. pip uses these hooks for
`pip install .` and `pip install -e .`; release CI calls them directly:

    python _build/lazaret_build.py [output-dir]     # the sdist, and a wheel for this machine
    python _build/lazaret_build.py dist --platform manylinux_2_28_x86_64=liblazaret_native.so ...
                                                    # the sdist, and a platform wheel per --platform

Lazaret's engine is native code (rust/, docs/RUST_ENGINE.md): since the
Rust-first refactor the package has no engine without it, so every wheel is
a platform wheel carrying the library (there is no pure, py3-none-any
wheel). Release CI builds the libraries and names them (--platform, or
LAZARET_NATIVE_LIBRARY and LAZARET_WHEEL_PLATFORM); anywhere else the
library is compiled here with cargo, from the Rust workspace the sdist
carries, for this machine — so installing from source needs Rust, and
installing a platform wheel needs nothing.

Package metadata lives in this module (METADATA below) rather than in a
[project] table: a backend must honor [project] if it exists, and reading TOML
on Python 3.10 would need a third-party parser. The version has one source of
truth: __version__ in src/lazaret/__init__.py.

Outputs are reproducible: file order, timestamps, permissions and the zip
"made by" system are fixed, and text files are packed with LF line endings,
so building the same commit twice gives byte-identical artifacts on Linux,
macOS and Windows, whatever the checkout's line endings (set SOURCE_DATE_EPOCH
to stamp a specific time instead of 1980-01-01). Compressed bytes also depend
on the zlib build, so compare artifacts built by the same Python; release CI
pins one.

What ships is an allowlist, not "whatever is in the directory": a wheel
holds the package's *.py, *.sql, *.html and *.json files (and py.typed, if
one is added) and the native engine's library; the sdist holds the same
package files, pyproject.toml, README.md, the license files, PKG-INFO,
_build/*.py, and the engine's sources (rust/: the workspace's Cargo.toml and
Cargo.lock, each crate's Cargo.toml, src/**/*.rs and rules/*.json, and the
notices). Any other file under src/lazaret, _build or a crate's src or rules
(a .env, an editor swap file, a macOS ._* twin, a .orig backup, a symlink)
stops the build with an error listing it, instead of being published. Tests,
fixtures and the engine's examples never ship (see STRUCTURE.md, "What ships
to the registries").
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import pathlib
import re
import stat
import sys
import tarfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent      # python/ (or an unpacked sdist)
SRC = ROOT / "src"
PKG = SRC / "lazaret"
# The native engine's Rust workspace: rust/ next to python/ in a checkout,
# rust/ inside an unpacked sdist.
RUST = ROOT / "rust" if (ROOT / "rust" / "Cargo.toml").is_file() else ROOT.parent / "rust"

NAME = "lazaret"
METADATA = {
    "Summary": "Static security, supply-chain and quality analysis for Python, JavaScript and SQL",
    "Requires-Python": ">=3.10",
    # PEP 639 (Metadata-Version 2.4): an SPDX expression plus the license
    # files' paths (in the sdist root; in the wheel under .dist-info/licenses/).
    # No "License ::" classifier: PyPI rejects it next to License-Expression.
    # Unicode-3.0: the Unicode 13.0 table (scanner/_unicode13.py) and the
    # dashboard's copies of the npm engine's Unicode and codec tables are
    # Unicode data (0.1.8).
    "License-Expression": "Apache-2.0 AND Unicode-3.0",
    "License-File": ["LICENSE", "LICENSE-UNICODE"],
    "Keywords": "security,supply-chain,sast,taint-analysis,sca,pypi,npm",
    "Project-URL": [
        "Homepage, https://lazaret.dev",
        "Source, https://github.com/lazaret-dev/lazaret",
        "Issues, https://github.com/lazaret-dev/lazaret/issues",
    ],
    "Classifier": [
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
}
# Deliberately empty: Lazaret has no runtime dependencies. Tested.
REQUIRES_DIST: list[str] = []

# Every wheel carries the native engine, and the sdist its source, with
# its notice. The engine is Lazaret's own work since P-16 (rust/NOTICE);
# each still carries CPython's LICENSE, and says so in its license
# expression, while the project settles whether the CPython codec names
# the packages hold (the dashboard's here, the npm package's) need it.
NATIVE_LICENSE_EXPRESSION = "Apache-2.0 AND Python-2.0.1 AND Unicode-3.0"
NATIVE_LICENSE_FILES = {"LICENSE-PYTHON": RUST / "LICENSE-PYTHON", "NOTICE": RUST / "NOTICE"}

CONSOLE_SCRIPTS = {
    "lazaret": "lazaret._cli:main",
    "lazaret-registry": "lazaret.registry.repo:main",
    "lazaret-mcp": "lazaret.mcp.server:main",
    "lazaret-sca": "lazaret.scanner.sca:main",
    "lazaret-guard": "lazaret.registry.guard:main",
}

SDIST_TOP_FILES = ["pyproject.toml", "README.md", "LICENSE", "LICENSE-UNICODE"]
# The Rust workspace in the sdist (under rust/): these files, and for each
# crate under crates/ its Cargo.toml, src/**/*.rs and rules/*.json.
RUST_TOP_FILES = ["Cargo.toml", "Cargo.lock", "LICENSE-PYTHON", "LICENSE-UNICODE", "NOTICE"]
RUST_CRATE_DIRS = {"src": (".rs",), "rules": (".json",)}
# The oldest macOS a library built here supports (the release wheels' tags):
# cargo is given it as MACOSX_DEPLOYMENT_TARGET.
MACOS_MINIMUM = {"arm64": (11, 0), "x86_64": (10, 12)}

# The package allowlist: exactly these kinds of files ship from src/lazaret.
# .json ships data files (the registry's popular_names.json).
PACKAGE_SUFFIXES = (".py", ".sql", ".html", ".json")
PACKAGE_NAMES = frozenset({"py.typed"})
# Build helpers shipped in the sdist (pip needs them to build from it).
BUILD_SUFFIXES = (".py",)
# Bytecode caches appear whenever the code runs; they never ship and are not
# an error. Everything else that is not allowlisted is. (src/lazaret/_native/
# holds the library an editable install built: never packed from the tree.)
_SKIP_DIRS = {"__pycache__"}
# Files packed with LF line endings whatever the checkout has (a Windows
# checkout with core.autocrlf would otherwise change every member's bytes).
_TEXT_SUFFIXES = (".py", ".sql", ".html", ".md", ".toml", ".txt", ".json", ".rs", ".lock")
_TEXT_NAMES = frozenset({"LICENSE", "LICENSE-PYTHON", "LICENSE-UNICODE", "NOTICE", "PKG-INFO", "py.typed"})
# Zip "made by" system: 3 = Unix. zipfile defaults to 0 (MS-DOS) on Windows,
# which would change every central-directory record there.
_ZIP_CREATE_SYSTEM = 3
_FILE_MODE = 0o644


# A wheel carries the native engine (rust/crates/lazaret-ffi) as
# lazaret/_native/<library>, which lazaret.scanner._native loads with ctypes.
# Release CI builds it and sets LAZARET_NATIVE_LIBRARY to the library and
# LAZARET_WHEEL_PLATFORM to the platform tag it was built for
# (manylinux_2_28_x86_64, macosx_11_0_arm64, win_amd64 …); without them it
# is compiled here (build_native) and tagged for this machine
# (local_platform). The sdist never carries a library.
NATIVE_LIBRARY_ENV = "LAZARET_NATIVE_LIBRARY"
WHEEL_PLATFORM_ENV = "LAZARET_WHEEL_PLATFORM"
_PLATFORM_TAG_RE = re.compile(r"[a-z0-9_]+\Z")


class UnexpectedFilesError(RuntimeError):
    """Files that are not on the allowlist were found where the build packs from."""


def native_library_name(platform: str) -> str:
    """The file name _native.py loads on a platform, by its wheel tag."""
    if platform.startswith("win"):
        return "lazaret_native.dll"
    if platform.startswith("macosx"):
        return "liblazaret_native.dylib"
    return "liblazaret_native.so"


def _native_member(platform: str, library: str) -> dict[str, bytes]:
    """{arcname: bytes} of the native library in a platform wheel."""
    if not _PLATFORM_TAG_RE.match(platform) or platform == "any":
        raise RuntimeError(f"{platform!r} is not a platform tag")
    path = pathlib.Path(library)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{library!r} is not a regular file")
    missing = [str(p) for p in NATIVE_LICENSE_FILES.values() if p.is_symlink() or not p.is_file()]
    if missing:
        raise RuntimeError(f"a platform wheel carries the native engine's notices, and {', '.join(missing)} "
                           f"is missing")
    return {f"lazaret/_native/{native_library_name(platform)}": path.read_bytes()}


def local_platform() -> str:
    """The wheel tag of a library built here, for this interpreter:
    sysconfig's platform (linux_x86_64, win_amd64 …); on macOS the release
    wheels' tag for the machine's architecture (macosx_11_0_arm64,
    macosx_10_12_x86_64), the minimum build_native compiles for."""
    import platform as platform_module
    import sysconfig
    plat = sysconfig.get_platform()
    if plat.startswith("macosx"):
        arch = "arm64" if platform_module.machine() == "arm64" else "x86_64"
        major, minor = MACOS_MINIMUM[arch]
        return f"macosx_{major}_{minor}_{arch}"
    return re.sub(r"[^a-z0-9_]", "_", plat.lower())


def build_native() -> pathlib.Path:
    """Compile the native engine here (cargo build --release, in RUST, for
    this machine) and return the library's path, once it is shown to load in
    this interpreter and to be this release's. Building Lazaret from source
    needs Rust; installing a platform wheel does not."""
    import shutil
    import subprocess
    cargo = os.environ.get("CARGO") or shutil.which("cargo")
    if not cargo:
        raise RuntimeError(
            "Lazaret's engine is written in Rust, and building Lazaret from source compiles it, but cargo was not "
            "found: install Rust (https://rustup.rs; rust-version in rust/Cargo.toml or later) and build again — "
            "or install a platform wheel (pip install --only-binary lazaret lazaret), which needs no compiler")
    if not (RUST / "Cargo.toml").is_file():
        raise RuntimeError(f"the native engine's sources are missing ({RUST / 'Cargo.toml'})")
    env = dict(os.environ)
    if sys.platform == "darwin":
        import platform as platform_module
        major, minor = MACOS_MINIMUM["arm64" if platform_module.machine() == "arm64" else "x86_64"]
        env.setdefault("MACOSX_DEPLOYMENT_TARGET", f"{major}.{minor}")
    elif sys.platform == "win32":                   # as the release DLL: no Visual C++ runtime needed
        env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C target-feature=+crt-static").strip()
    # the workspace has no external crates: nothing is downloaded (--offline), and Cargo.lock is kept (--locked)
    cmd = [cargo, "build", "--release", "--offline", "--locked", "-p", "lazaret-ffi"]
    print(f"lazaret_build: building the native engine: {' '.join(cmd[1:])} (in {RUST})", file=sys.stderr)
    done = subprocess.run(cmd, cwd=RUST, env=env, stdout=sys.stderr)
    if done.returncode:
        raise RuntimeError(f"building the native engine failed (cargo exited with {done.returncode}; its "
                           f"messages are above)")
    target = pathlib.Path(env.get("CARGO_TARGET_DIR") or "target")
    library = (target if target.is_absolute() else RUST / target) / "release" / native_library_name(local_platform())
    if not library.is_file():
        raise RuntimeError(f"cargo built no {library}")
    _check_loads(library)
    return library


def _check_loads(library: pathlib.Path) -> None:
    """Load the library as lazaret.scanner._native does and hold its version
    to the package's (a library for another architecture, or a stale one,
    stops the build instead of an install that cannot scan)."""
    import ctypes
    try:
        lib = ctypes.CDLL(str(library))
        lib.lazaret_engine_version.restype = ctypes.c_char_p
        got = lib.lazaret_engine_version().decode("ascii")
    except (OSError, AttributeError) as exc:
        raise RuntimeError(f"the native engine built here ({library}) does not load in this Python "
                           f"({sys.executable}): {exc}") from None
    if got != version():
        raise RuntimeError(f"the native engine built here reports version {got}, but the package is {version()}: "
                           f"rust/Cargo.toml's workspace version must be the package's")


def _native_payload() -> tuple[str, dict[str, bytes]]:
    """(the wheel's platform tag, {arcname: bytes} of the native library): the
    one LAZARET_NATIVE_LIBRARY names, for LAZARET_WHEEL_PLATFORM (release
    CI), else one compiled here for this machine (build_native)."""
    library = os.environ.get(NATIVE_LIBRARY_ENV, "")
    platform = os.environ.get(WHEEL_PLATFORM_ENV, "")
    if not library and not platform:
        platform = local_platform()
        return platform, _native_member(platform, str(build_native()))
    if not (library and platform):
        raise RuntimeError(f"a wheel built from a library needs both {NATIVE_LIBRARY_ENV} and {WHEEL_PLATFORM_ENV}")
    try:
        return platform, _native_member(platform, library)
    except RuntimeError as exc:
        raise RuntimeError(f"{WHEEL_PLATFORM_ENV}, {NATIVE_LIBRARY_ENV}: {exc}") from None


# --- helpers -------------------------------------------------------------------

def version() -> str:
    text = (PKG / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.M)
    if not match:
        raise RuntimeError("__version__ not found in src/lazaret/__init__.py")
    return match.group(1)


def _epoch_date_time() -> tuple[int, int, int, int, int, int]:
    import time
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if not epoch:
        return (1980, 1, 1, 0, 0, 0)
    t = time.gmtime(max(int(epoch), 315532800))           # zip can't go before 1980
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def _normalize(name: str, data: bytes) -> bytes:
    """LF line endings for text members, so the artifact doesn't depend on how
    the tree was checked out."""
    if name.endswith(_TEXT_SUFFIXES) or name.rsplit("/", 1)[-1] in _TEXT_NAMES:
        return data.replace(b"\r\n", b"\n")
    return data


def _allowlisted(base: pathlib.Path, suffixes: tuple[str, ...], names=frozenset(),
                 label: str = "", skip_top=frozenset()) -> list[pathlib.Path]:
    """Every allowlisted file under base, sorted by its POSIX relative path.

    Raises UnexpectedFilesError naming every other file: dotfiles and
    dot-directories (.env, .DS_Store, ._* AppleDouble twins, .x.swp), anything
    with another suffix (x.orig, core.py~, a stray .pyc outside __pycache__)
    and symlinks, which could pull in files from outside the tree.
    `skip_top`: directories directly under base that are not walked."""
    ok: list[pathlib.Path] = []
    bad: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base):      # never follows symlinks
        here = pathlib.Path(dirpath)
        for d in sorted(dirnames):
            if (here / d).is_symlink():
                bad.append((here / d).relative_to(base).as_posix() + "/ (symlink)")
        dirnames[:] = sorted(d for d in dirnames
                             if d not in _SKIP_DIRS and not (here / d).is_symlink()
                             and not (here == base and d in skip_top))
        for fn in sorted(filenames):
            path = here / fn
            rel = path.relative_to(base)
            if path.is_symlink() or not path.is_file():
                bad.append(rel.as_posix() + " (not a regular file)")
            elif any(part.startswith(".") for part in rel.parts):
                bad.append(rel.as_posix())
            elif not (fn in names or fn.endswith(suffixes)):
                bad.append(rel.as_posix())
            else:
                ok.append(path)
    if bad:
        shown = label or base.name
        allowed = ", ".join([f"*{s}" for s in suffixes] + sorted(names))
        raise UnexpectedFilesError(
            f"refusing to build: {len(bad)} file(s) under {shown}/ are not part of the package:\n"
            + "".join(f"  {shown}/{b}\n" for b in sorted(bad))
            + f"Only {allowed} ship from {shown}/. Dotfiles, editor and OS leftovers "
            "(.env, .DS_Store, ._*, *.swp, *.orig) and symlinks are never packaged: "
            "delete or move them, then build again.")
    return sorted(ok, key=lambda p: p.relative_to(base).as_posix())


def _package_files() -> list[pathlib.Path]:
    return _allowlisted(PKG, PACKAGE_SUFFIXES, PACKAGE_NAMES, label="src/lazaret", skip_top={"_native"})


def _rust_files() -> list[tuple[str, pathlib.Path]]:
    """(the path under rust/, the file) of each of the engine's sources the
    sdist carries, sorted (RUST_TOP_FILES; each crate's Cargo.toml, and its
    src/ and rules/ by RUST_CRATE_DIRS' allowlists)."""
    out = []
    missing = [name for name in RUST_TOP_FILES if not (RUST / name).is_file() or (RUST / name).is_symlink()]
    crates = sorted(p for p in (RUST / "crates").iterdir() if p.is_dir() and not p.is_symlink()) \
        if (RUST / "crates").is_dir() else []
    if not crates:
        missing.append("crates/*")
    if missing:
        raise RuntimeError(f"the native engine's sources are incomplete in {RUST}: {', '.join(missing)} missing")
    out += [(name, RUST / name) for name in RUST_TOP_FILES]
    for crate in crates:
        manifest = crate / "Cargo.toml"
        if not manifest.is_file() or manifest.is_symlink():
            raise RuntimeError(f"{manifest} is missing")
        out.append((f"crates/{crate.name}/Cargo.toml", manifest))
        for sub, suffixes in RUST_CRATE_DIRS.items():
            if (crate / sub).is_dir():
                for path in _allowlisted(crate / sub, suffixes, label=f"rust/crates/{crate.name}/{sub}"):
                    out.append((path.relative_to(RUST).as_posix(), path))
    return sorted(out)


def _build_files() -> list[pathlib.Path]:
    return _allowlisted(pathlib.Path(__file__).resolve().parent, BUILD_SUFFIXES, label="_build")


def metadata_text() -> str:
    """METADATA (and the sdist's PKG-INFO): METADATA's fields, with the native
    engine's license files and expression."""
    lines = ["Metadata-Version: 2.4", f"Name: {NAME}", f"Version: {version()}"]
    for key, value in METADATA.items():
        if key == "License-Expression":
            value = NATIVE_LICENSE_EXPRESSION
        for item in (value if isinstance(value, list) else [value]):
            lines.append(f"{key}: {item}")
        if key == "License-File":
            lines += [f"License-File: {name}" for name in NATIVE_LICENSE_FILES]
    lines += [f"Requires-Dist: {req}" for req in REQUIRES_DIST]
    readme = ROOT / "README.md"
    if readme.exists():
        lines.append("Description-Content-Type: text/markdown")
        return "\n".join(lines) + "\n\n" + readme.read_text(encoding="utf-8")
    return "\n".join(lines) + "\n"


def _entry_points_text() -> str:
    body = "".join(f"{name} = {target}\n" for name, target in CONSOLE_SCRIPTS.items())
    return "[console_scripts]\n" + body


def _record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
    return f"sha256={digest}"


class _WheelWriter:
    def __init__(self, path: pathlib.Path):
        self._zip = zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED)
        self._records: list[str] = []
        self._date_time = _epoch_date_time()

    def _info(self, arcname: str) -> zipfile.ZipInfo:
        info = zipfile.ZipInfo(arcname, date_time=self._date_time)
        info.create_system = _ZIP_CREATE_SYSTEM          # same bytes on every OS
        info.external_attr = (stat.S_IFREG | _FILE_MODE) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        return info

    def add(self, arcname: str, data: bytes) -> None:
        data = _normalize(arcname, data)
        self._zip.writestr(self._info(arcname), data)
        self._records.append(f"{arcname},{_record_hash(data)},{len(data)}")

    def close(self, dist_info: str) -> None:
        record = f"{dist_info}/RECORD"
        body = "\n".join(self._records + [f"{record},,"]) + "\n"
        self._zip.writestr(self._info(record), body.encode("utf-8"))
        self._zip.close()


def _write_wheel(directory: str, payload: dict[str, bytes], platform: str) -> str:
    """A wheel of `payload` for `platform` ('any' only for the editable wheel,
    whose payload is a .pth file)."""
    ver = version()
    dist_info = f"{NAME}-{ver}.dist-info"
    filename = f"{NAME}-{ver}-py3-none-{platform}.whl"
    writer = _WheelWriter(pathlib.Path(directory) / filename)
    for arcname in sorted(payload):
        writer.add(arcname, payload[arcname])
    writer.add(f"{dist_info}/METADATA", metadata_text().encode("utf-8"))
    purelib = "true" if platform == "any" else "false"
    writer.add(f"{dist_info}/WHEEL", (
        f"Wheel-Version: 1.0\nGenerator: lazaret_build\nRoot-Is-Purelib: {purelib}\nTag: py3-none-{platform}\n"
    ).encode("utf-8"))
    writer.add(f"{dist_info}/entry_points.txt", _entry_points_text().encode("utf-8"))
    for name in METADATA["License-File"]:
        license_file = ROOT / name
        if license_file.exists():
            writer.add(f"{dist_info}/licenses/{name}", license_file.read_bytes())
    for name, path in NATIVE_LICENSE_FILES.items():
        writer.add(f"{dist_info}/licenses/{name}", path.read_bytes())
    writer.close(dist_info)
    return filename


# --- PEP 517 hooks ---------------------------------------------------------------

def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def get_requires_for_build_editable(config_settings=None):
    return []


def _package_payload() -> dict[str, bytes]:
    return {path.relative_to(SRC).as_posix(): path.read_bytes() for path in _package_files()}


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    """The package's files and the native library (_native_payload: the one
    release CI names, else one compiled here), tagged for its platform."""
    payload = _package_payload()
    platform, native = _native_payload()
    payload.update(native)
    return _write_wheel(wheel_directory, payload, platform)


def build_platform_wheel(wheel_directory: str, platform: str, library: str) -> str:
    """The package's files plus the native library built for `platform`
    (release CI, through `--platform TAG=LIBRARY`; the environment is not read)."""
    payload = _package_payload()
    payload.update(_native_member(platform, library))
    return _write_wheel(wheel_directory, payload, platform)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    """PEP 660: a wheel whose only payload is a .pth file pointing at src/.
    The native library (_native_payload) is written to src/lazaret/_native/,
    where lazaret.scanner._native finds it; after a change to the engine,
    install again (or set LAZARET_NATIVE_LIB to a fresh build)."""
    _platform, native = _native_payload()
    for arcname, data in native.items():
        target = SRC / arcname
        target.parent.mkdir(exist_ok=True)
        target.write_bytes(data)
    pth = f"__editable__.{NAME}-{version()}.pth"
    return _write_wheel(wheel_directory, {pth: (str(SRC) + "\n").encode("utf-8")}, "any")


def build_sdist(sdist_directory, config_settings=None):
    ver = version()
    base = f"{NAME}-{ver}"
    filename = f"{base}.tar.gz"
    mtime = int(os.environ.get("SOURCE_DATE_EPOCH", "315532800"))

    members: list[tuple[str, bytes]] = []
    for name in SDIST_TOP_FILES:
        path = ROOT / name
        if path.is_file() and not path.is_symlink():
            members.append((name, path.read_bytes()))
    build_dir = pathlib.Path(__file__).resolve().parent
    for path in _build_files():
        members.append(("_build/" + path.relative_to(build_dir).as_posix(), path.read_bytes()))
    for path in _package_files():
        members.append((path.relative_to(ROOT).as_posix(), path.read_bytes()))
    # the engine's sources (pip compiles them where no platform wheel fits), and
    # its license files at the root, where PKG-INFO's License-File finds them
    for rel, path in _rust_files():
        members.append(("rust/" + rel, path.read_bytes()))
    for name, path in NATIVE_LICENSE_FILES.items():
        members.append((name, path.read_bytes()))
    members.append(("PKG-INFO", metadata_text().encode("utf-8")))
    members = [(name, _normalize(name, data)) for name, data in members]

    # gzip header carries a timestamp too; pin it for reproducible output
    raw = io.BytesIO()
    import gzip
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=mtime) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for arcname, data in sorted(members):
                info = tarfile.TarInfo(f"{base}/{arcname}")
                info.size = len(data)
                info.mtime = mtime
                info.mode = _FILE_MODE
                info.type = tarfile.REGTYPE
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tar.addfile(info, io.BytesIO(data))
    (pathlib.Path(sdist_directory) / filename).write_bytes(raw.getvalue())
    return filename


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(
        prog="lazaret_build.py", description="Build Lazaret's sdist, and a wheel for this machine (its native "
                                             "engine compiled here with cargo) or one for each --platform.")
    parser.add_argument("out", nargs="?", default=str(ROOT / "dist"), help="output directory (default: dist/)")
    parser.add_argument("--platform", action="append", default=[], metavar="TAG=LIBRARY",
                        help="build the wheel for TAG, carrying the native library LIBRARY, instead of one for "
                             "this machine (repeat for each platform)")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    platforms = []
    for item in args.platform:
        tag, sep, library = item.partition("=")
        if not (sep and tag and library):
            parser.error(f"--platform takes TAG=LIBRARY, not {item!r}")
        if tag in dict(platforms):
            parser.error(f"--platform {tag} is given twice")
        platforms.append((tag, library))
    out = pathlib.Path(args.out)
    try:
        for tag, library in platforms:          # all of them, before anything is written
            try:
                _native_member(tag, library)
            except RuntimeError as exc:
                raise RuntimeError(f"--platform {tag}={library}: {exc}") from None
        out.mkdir(parents=True, exist_ok=True)
        print(out / build_sdist(str(out)))
        for tag, library in platforms:
            print(out / build_platform_wheel(str(out), tag, library))
        if not platforms:
            print(out / build_wheel(str(out)))
    except RuntimeError as exc:                 # UnexpectedFilesError, a bad --platform, a failed build
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
