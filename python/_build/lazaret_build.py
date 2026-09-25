"""Lazaret's build backend (PEP 517 / PEP 660), standard library only.

Building Lazaret downloads nothing: pyproject.toml declares no build
requirements and points here via backend-path. pip uses these hooks for
`pip install .` and `pip install -e .`; release CI calls them directly:

    python _build/lazaret_build.py [output-dir]     # writes the wheel and sdist

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

What ships is an allowlist, not "whatever is in the directory": the wheel
holds the package's *.py, *.sql and *.html files (and py.typed, if one is
added), the sdist adds pyproject.toml, README.md, LICENSE, PKG-INFO and
_build/*.py. Any other file under src/lazaret or _build (a .env, an editor
swap file, a macOS ._* twin, a .orig backup, a symlink) stops the build with
an error listing it, instead of being published. Tests and fixtures never
ship (see STRUCTURE.md, "What ships to the registries").
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

ROOT = pathlib.Path(__file__).resolve().parent.parent      # python/
SRC = ROOT / "src"
PKG = SRC / "lazaret"

NAME = "lazaret"
METADATA = {
    "Summary": "Static security, supply-chain and quality analysis for Python, JavaScript and SQL",
    "Requires-Python": ">=3.10",
    # PEP 639 (Metadata-Version 2.4): an SPDX expression plus the license
    # file's path (in the sdist root; in the wheel under .dist-info/licenses/).
    # No "License ::" classifier: PyPI rejects it next to License-Expression.
    "License-Expression": "Apache-2.0",
    "License-File": "LICENSE",
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

CONSOLE_SCRIPTS = {
    "lazaret": "lazaret.scanner.core:main",
    "lazaret-registry": "lazaret.registry.repo:main",
    "lazaret-mcp": "lazaret.mcp.server:main",
    "lazaret-sca": "lazaret.scanner.sca:main",
}

SDIST_TOP_FILES = ["pyproject.toml", "README.md", "LICENSE"]

# The package allowlist: exactly these kinds of files ship from src/lazaret.
PACKAGE_SUFFIXES = (".py", ".sql", ".html")
PACKAGE_NAMES = frozenset({"py.typed"})
# Build helpers shipped in the sdist (pip needs them to build from it).
BUILD_SUFFIXES = (".py",)
# Bytecode caches appear whenever the code runs; they never ship and are not
# an error. Everything else that is not allowlisted is.
_SKIP_DIRS = {"__pycache__"}
# Files packed with LF line endings whatever the checkout has (a Windows
# checkout with core.autocrlf would otherwise change every member's bytes).
_TEXT_SUFFIXES = (".py", ".sql", ".html", ".md", ".toml", ".txt")
_TEXT_NAMES = frozenset({"LICENSE", "PKG-INFO", "py.typed"})
# Zip "made by" system: 3 = Unix. zipfile defaults to 0 (MS-DOS) on Windows,
# which would change every central-directory record there.
_ZIP_CREATE_SYSTEM = 3
_FILE_MODE = 0o644


class UnexpectedFilesError(RuntimeError):
    """Files that are not on the allowlist were found where the build packs from."""


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
                 label: str = "") -> list[pathlib.Path]:
    """Every allowlisted file under base, sorted by its POSIX relative path.

    Raises UnexpectedFilesError naming every other file: dotfiles and
    dot-directories (.env, .DS_Store, ._* AppleDouble twins, .x.swp), anything
    with another suffix (x.orig, core.py~, a stray .pyc outside __pycache__)
    and symlinks, which could pull in files from outside the tree."""
    ok: list[pathlib.Path] = []
    bad: list[str] = []
    for dirpath, dirnames, filenames in os.walk(base):      # never follows symlinks
        here = pathlib.Path(dirpath)
        for d in sorted(dirnames):
            if (here / d).is_symlink():
                bad.append((here / d).relative_to(base).as_posix() + "/ (symlink)")
        dirnames[:] = sorted(d for d in dirnames
                             if d not in _SKIP_DIRS and not (here / d).is_symlink())
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
    return _allowlisted(PKG, PACKAGE_SUFFIXES, PACKAGE_NAMES, label="src/lazaret")


def _build_files() -> list[pathlib.Path]:
    return _allowlisted(pathlib.Path(__file__).resolve().parent, BUILD_SUFFIXES, label="_build")


def metadata_text() -> str:
    lines = ["Metadata-Version: 2.4", f"Name: {NAME}", f"Version: {version()}"]
    for key, value in METADATA.items():
        for item in (value if isinstance(value, list) else [value]):
            lines.append(f"{key}: {item}")
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


def _write_wheel(directory: str, payload: dict[str, bytes]) -> str:
    ver = version()
    dist_info = f"{NAME}-{ver}.dist-info"
    filename = f"{NAME}-{ver}-py3-none-any.whl"
    writer = _WheelWriter(pathlib.Path(directory) / filename)
    for arcname in sorted(payload):
        writer.add(arcname, payload[arcname])
    writer.add(f"{dist_info}/METADATA", metadata_text().encode("utf-8"))
    writer.add(f"{dist_info}/WHEEL", (
        "Wheel-Version: 1.0\nGenerator: lazaret_build\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    ).encode("utf-8"))
    writer.add(f"{dist_info}/entry_points.txt", _entry_points_text().encode("utf-8"))
    license_file = ROOT / "LICENSE"
    if license_file.exists():
        writer.add(f"{dist_info}/licenses/LICENSE", license_file.read_bytes())
    writer.close(dist_info)
    return filename


# --- PEP 517 hooks ---------------------------------------------------------------

def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []


def get_requires_for_build_editable(config_settings=None):
    return []


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    payload = {path.relative_to(SRC).as_posix(): path.read_bytes() for path in _package_files()}
    return _write_wheel(wheel_directory, payload)


def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    """PEP 660: a wheel whose only payload is a .pth file pointing at src/."""
    pth = f"__editable__.{NAME}-{version()}.pth"
    return _write_wheel(wheel_directory, {pth: (str(SRC) + "\n").encode("utf-8")})


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
    argv = sys.argv[1:] if argv is None else argv
    out = pathlib.Path(argv[0] if argv else ROOT / "dist")
    out.mkdir(parents=True, exist_ok=True)
    try:
        for build in (build_sdist, build_wheel):
            print(out / build(str(out)))
    except UnexpectedFilesError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
