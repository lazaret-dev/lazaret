#!/usr/bin/env python3
"""Build defensive stub packages for likely misspellings of "lazaret".

Each stub holds a name on PyPI and npm so an attacker can't register it. It
has no dependencies and no functionality: importing or requiring it raises an
error pointing to the real package, so a misspelled dependency fails loudly
rather than silently. It deliberately does NOT depend on lazaret: a stub that
pulled in the real package would hide the typo and leave the misspelled name
in people's lockfiles.

Standard library only; the PyPI stub is written directly as a wheel, so no
build tool is involved.

Usage: python3 scripts/make_typosquat_stubs.py [name ...]
Output: build/typosquats/<name>/python/<name>-0.0.1-py3-none-any.whl
        build/typosquats/<name>/js/{package.json,index.js,README.md}
Then see docs/RELEASING.md for publishing, yanking, and deprecating them.

       python3 scripts/make_typosquat_stubs.py --check [name ...]
Asks pypi.org and registry.npmjs.org who holds each name and exits 1 if any
is unclaimed or held by someone else (a stub of ours says "Reserved
misspelling of lazaret"). Offline, it warns and exits 0: the check is
advisory there, the registries are the source of truth.
"""
import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import zipfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_NAMES = ["lazarat", "lazarett", "lazeret"]
VERSION = "0.0.1"
HOMEPAGE = "https://lazaret.dev"


def message(name):
    return f"'{name}' is a reserved misspelling. You probably want 'lazaret' ({HOMEPAGE})."


def _record_hash(data):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def build_python_stub(name, out_dir):
    if not re.fullmatch(r"[a-z][a-z0-9]*", name):
        raise ValueError(f"unsupported stub name: {name!r}")
    os.makedirs(out_dir, exist_ok=True)
    dist_info = f"{name}-{VERSION}.dist-info"
    files = {
        f"{name}/__init__.py": f'"""{message(name)}"""\nraise ImportError({message(name)!r})\n',
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {VERSION}\n"
            f"Summary: Reserved misspelling of lazaret. Install 'lazaret' instead.\n"
            f"Home-page: {HOMEPAGE}\nLicense: Apache-2.0\nRequires-Python: >=3.10\n"),
        f"{dist_info}/WHEEL": "Wheel-Version: 1.0\nGenerator: lazaret-stubs\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    path = os.path.join(out_dir, f"{name}-{VERSION}-py3-none-any.whl")
    records = []
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for arcname, text in files.items():
            data = text.encode()
            info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            z.writestr(info, data)
            records.append(f"{arcname},{_record_hash(data)},{len(data)}")
        records.append(f"{dist_info}/RECORD,,")
        info = zipfile.ZipInfo(f"{dist_info}/RECORD", date_time=(1980, 1, 1, 0, 0, 0))
        z.writestr(info, "\n".join(records) + "\n")
    return path


def build_js_stub(name, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    package = {
        "name": name, "version": VERSION,
        "description": "Reserved misspelling of lazaret. Install 'lazaret' instead.",
        "main": "index.js", "files": ["index.js", "README.md"],
        "homepage": HOMEPAGE, "license": "Apache-2.0", "publishConfig": {"access": "public"},
    }
    with open(os.path.join(out_dir, "package.json"), "w") as f:
        json.dump(package, f, indent=2)
        f.write("\n")
    with open(os.path.join(out_dir, "index.js"), "w") as f:
        f.write(f"throw new Error({json.dumps(message(name))});\n")
    with open(os.path.join(out_dir, "README.md"), "w") as f:
        f.write(f"# {name}\n\n{message(name)}\n\n    npm install lazaret\n")
    return out_dir


STUB_MARKER = "Reserved misspelling of lazaret"
REGISTRIES = {
    "PyPI": ("https://pypi.org/pypi/{}/json", lambda d: (d.get("info") or {}).get("summary") or ""),
    "npm": ("https://registry.npmjs.org/{}", lambda d: d.get("description") or ""),
}


def _fetch_json(url, timeout=10):
    """(status, parsed JSON or None). Raises OSError when the registry can't be reached."""
    req = urllib.request.Request(url, headers={"Accept": "application/json",
                                               "User-Agent": "lazaret-typosquat-check"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # fixed https URLs only
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, None


def check_names(names, fetch=_fetch_json, out=sys.stdout):
    """Report who holds each name on each registry. Returns the exit code:
    1 if any name is unclaimed or not ours, 0 otherwise (and when offline)."""
    problems, unreachable = [], []
    for name in names:
        if not re.fullmatch(r"[a-z][a-z0-9]*", name):
            raise ValueError(f"unsupported stub name: {name!r}")
        for registry, (url, describe) in REGISTRIES.items():
            try:
                status, data = fetch(url.format(urllib.parse.quote(name)))
            except (OSError, ValueError) as exc:        # offline, DNS, TLS, bad JSON
                unreachable.append(f"{registry} ({exc.__class__.__name__}: {exc})")
                print(f"  ?  {name:<10} {registry:<5} could not check", file=out)
                continue
            if status == 404:
                problems.append(f"{name} is UNCLAIMED on {registry}")
                print(f"  !  {name:<10} {registry:<5} UNCLAIMED: anyone can publish it", file=out)
            elif status == 200 and data is not None:
                summary = describe(data)
                if STUB_MARKER in summary:
                    print(f"  ok {name:<10} {registry:<5} reserved by our stub", file=out)
                else:
                    problems.append(f"{name} on {registry} is held by someone else: {summary!r}")
                    print(f"  !! {name:<10} {registry:<5} HELD BY SOMEONE ELSE: {summary!r}", file=out)
            else:
                unreachable.append(f"{registry} (HTTP {status})")
                print(f"  ?  {name:<10} {registry:<5} HTTP {status}", file=out)
    if unreachable:
        print("warning: could not reach every registry, so this check is incomplete: "
              + "; ".join(sorted(set(unreachable))), file=out)
    if problems:
        print("\nNot reserved yet. Publish the stubs now (docs/RELEASING.md, step 7):", file=out)
        for p in problems:
            print(f"  - {p}", file=out)
        return 1
    if not unreachable:
        print("All misspellings are reserved.", file=out)
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else list(argv)
    if args[:1] == ["--check"]:
        return check_names(args[1:] or DEFAULT_NAMES)
    names = args or DEFAULT_NAMES
    for name in names:
        base = os.path.join(REPO, "build", "typosquats", name)
        print(build_python_stub(name, os.path.join(base, "python")))
        print(build_js_stub(name, os.path.join(base, "js")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
