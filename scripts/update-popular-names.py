#!/usr/bin/env python3
"""Write python/src/lazaret/registry/popular_names.json: the names the
registry's look-alike check (SC-TYPOSQUAT, registry/lookalike.py) compares a
release's name and dependencies with.

Two sources, each read from a local copy (nothing is downloaded here):

  npm   npm-high-impact (MIT, Titus Wormer), https://github.com/wooorm/npm-high-impact
        — the package's lib/ directory: top-download.js (by downloads) and
        top.js (downloads and dependents together). Get it with
        `npm pack npm-high-impact` and unpack the tarball.
  PyPI  Top PyPI Packages (CC BY 4.0, Hugo van Kemenade),
        https://github.com/hugovk/top-pypi-packages — top-pypi-packages.min.json
        (30 days of downloads; its fields last_update and rows[].project).

For each registry the file keeps the TARGETS, the first 5,000 names by
downloads, and the KNOWN names: those of the whole list (17,000-odd for npm,
15,000 for PyPI) that are one change from a target — real packages the
check must not flag. A name of the list that is no target's look-alike can
never be flagged, so it need not be kept. PyPI names are PEP 503-normalized.

Usage: python3 scripts/update-popular-names.py NPM_LIB_DIR TOP_PYPI_JSON [--check]
--check compares with the file in the tree instead of writing it (exit 1 on
any difference). Standard library only.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python" / "src"))
from lazaret.registry import lookalike  # noqa: E402
from lazaret.scanner.core import configure_stdio  # noqa: E402

OUT = ROOT / "python" / "src" / "lazaret" / "registry" / "popular_names.json"
TARGETS = 5000
_JS_STRING_RE = re.compile(r"""^\s*'((?:[^'\\]|\\.)*)',?\s*$""", re.M)
MIT_NOTICE = (
    "Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated "
    "documentation files (the 'Software'), to deal in the Software without restriction, including without "
    "limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the "
    "Software, and to permit persons to whom the Software is furnished to do so, subject to the following "
    "conditions: The above copyright notice and this permission notice shall be included in all copies or "
    "substantial portions of the Software. THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS "
    "OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE "
    "AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR "
    "OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION "
    "WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.")


def js_names(path):
    """The quoted names of one npm-high-impact list file, in order."""
    return [m.group(1).lower() for m in _JS_STRING_RE.finditer(path.read_text(encoding="utf-8"))]


def unique(names):
    seen, out = set(), []
    for n in names:
        if n and n not in seen:
            seen.add(n)
            out.append(n)
    return out


def section(eco, ranked, everything):
    targets = unique(ranked)[:TARGETS]
    data = lookalike.tables(targets, ())
    known = sorted(n for n in set(everything) - set(targets) if lookalike.lookalike(eco, n, data) is not None)
    return targets, known


def build(npm_lib, top_pypi):
    npm_lib = pathlib.Path(npm_lib)
    version = json.loads((npm_lib.parent / "package.json").read_text(encoding="utf-8")).get("version", "?")
    npm_targets, npm_known = section("npm", js_names(npm_lib / "top-download.js"),
                                     js_names(npm_lib / "top.js") + js_names(npm_lib / "top-download.js"))
    doc = json.loads(pathlib.Path(top_pypi).read_text(encoding="utf-8"))
    pypi = [lookalike.normalize("pypi", r["project"]) for r in doc["rows"]]
    pypi_targets, pypi_known = section("pypi", pypi, pypi)
    return {
        "_about": ("Names for the registry's look-alike check (SC-TYPOSQUAT, lazaret/registry/lookalike.py): the "
                   f"{TARGETS:,} most-downloaded packages of each registry (targets), and the other popular ones "
                   "that are one change from a target (known). Written by scripts/update-popular-names.py."),
        "npm": {
            "source": f"npm-high-impact {version} (lib/top-download.js, lib/top.js), "
                      "https://github.com/wooorm/npm-high-impact",
            "license": "MIT", "copyright": "Copyright (c) Titus Wormer <tituswormer@gmail.com>",
            "notice": MIT_NOTICE, "targets": npm_targets, "known": npm_known},
        "pypi": {
            "source": ("Top PyPI Packages by Hugo van Kemenade, https://github.com/hugovk/top-pypi-packages, "
                       f"data of {doc.get('last_update', '?')} (source: {doc.get('source', '?')})"),
            "license": "CC BY 4.0, https://creativecommons.org/licenses/by/4.0/",
            "changes": ("project names only, PEP 503-normalized: the first 5,000 by downloads, and those of the "
                        "15,000 that are one change from one of them"),
            "targets": pypi_targets, "known": pypi_known},
    }


def main(argv):
    configure_stdio()
    args = [a for a in argv if a != "--check"]
    if len(args) != 2:
        print(__doc__.split("\n\n")[-2], file=sys.stderr)
        return 2
    text = json.dumps(build(*args), indent=1, ensure_ascii=False) + "\n"
    if "--check" in argv:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(f"{OUT.relative_to(ROOT)} differs from what the sources give", file=sys.stderr)
            return 1
        print("popular_names.json is current")
        return 0
    OUT.write_text(text, encoding="utf-8")
    data = json.loads(text)
    print(f"wrote {OUT.relative_to(ROOT)}: npm {len(data['npm']['targets'])} targets, {len(data['npm']['known'])} "
          f"known; PyPI {len(data['pypi']['targets'])} targets, {len(data['pypi']['known'])} known")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
