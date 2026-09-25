"""Lazaret's build backend (PEP 517 / PEP 660), standard library only.

Building Lazaret downloads nothing: pyproject.toml declares no build
requirements and points here via backend-path. pip uses these hooks for
`pip install .` and `pip install -e .`; release CI calls them directly:

    python _build/lazaret_build.py [output-dir]     # writes the wheel and sdist

Package metadata lives in this module (METADATA below) rather than in a
[project] table: a backend must honor [project] if it exists, and reading TOML
on Python 3.10 would need a third-party parser. The version has one source of
truth: __version__ in src/lazaret/__init__.py.

Outputs are reproducible: file order, timestamps, and permissions are fixed,
so building the same tree twice gives byte-identical artifacts (set
SOURCE_DATE_EPOCH to stamp a specific time instead of 1980-01-01).

The wheel contains only the package. Tests and fixtures never ship, in the
wheel or the sdist (see STRUCTURE.md, "What ships to the registries").
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import pathlib
import re
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
_SKIP_DIRS = {"__pycache__"}
_SKIP_SUFFIXES = (".pyc", ".pyo")


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


def _package_files() -> list[pathlib.Path]:
    out = []
    for path in sorted(PKG.rglob("*")):
        if not path.is_file():
            continue
        if _SKIP_DIRS & set(path.relative_to(PKG).parts) or path.suffix in _SKIP_SUFFIXES:
            continue
        out.append(path)
    return out


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

    def add(self, arcname: str, data: bytes) -> None:
        info = zipfile.ZipInfo(arcname, date_time=self._date_time)
        info.external_attr = 0o644 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        self._zip.writestr(info, data)
        self._records.append(f"{arcname},{_record_hash(data)},{len(data)}")

    def close(self, dist_info: str) -> None:
        record = f"{dist_info}/RECORD"
        body = "\n".join(self._records + [f"{record},,"]) + "\n"
        info = zipfile.ZipInfo(record, date_time=self._date_time)
        info.external_attr = 0o644 << 16
        self._zip.writestr(info, body.encode("utf-8"))
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
        if path.exists():
            members.append((name, path.read_bytes()))
    members.append(("_build/lazaret_build.py", pathlib.Path(__file__).read_bytes()))
    for path in _package_files():
        members.append((path.relative_to(ROOT).as_posix(), path.read_bytes()))
    members.append(("PKG-INFO", metadata_text().encode("utf-8")))

    # gzip header carries a timestamp too; pin it for reproducible output
    raw = io.BytesIO()
    import gzip
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=mtime) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for arcname, data in sorted(members):
                info = tarfile.TarInfo(f"{base}/{arcname}")
                info.size = len(data)
                info.mtime = mtime
                info.mode = 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tar.addfile(info, io.BytesIO(data))
    (pathlib.Path(sdist_directory) / filename).write_bytes(raw.getvalue())
    return filename


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = pathlib.Path(argv[0] if argv else ROOT / "dist")
    out.mkdir(parents=True, exist_ok=True)
    for build in (build_sdist, build_wheel):
        print(out / build(str(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
