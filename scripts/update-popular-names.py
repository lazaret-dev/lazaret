#!/usr/bin/env python3
"""Write python/src/lazaret/registry/popular_names.json: the names the
registry's look-alike check (SC-TYPOSQUAT, registry/lookalike.py) compares a
release's name and dependencies with.

Each list is read from a local copy (nothing is downloaded here):

  npm   npm-high-impact (MIT, Titus Wormer), https://github.com/wooorm/npm-high-impact
        — the package's lib/ directory: top-download.js (by downloads) and
        top.js (downloads and dependents together). Get it with
        `npm pack npm-high-impact` and unpack the tarball.
  PyPI  Top PyPI Packages (CC BY 4.0, Hugo van Kemenade),
        https://github.com/hugovk/top-pypi-packages — top-pypi-packages.min.json
        (30 days of downloads; its fields last_update and rows[].project).
  Go    No registry publishes downloads (proxy.golang.org, pkg.go.dev and
        deps.dev give no list), so the well-known modules are two curated
        lists: awesome-go (MIT, Thiago Avelino),
        https://github.com/avelino/awesome-go — its README.md, of which the
        first link of each entry is read, outside its Resources and Editor
        Plugins (a GitHub, GitLab, Bitbucket, Codeberg, Gitee or sr.ht
        repository, or a pkg.go.dev path); and the Go modules Debian
        packages, from the Go-Import-Path field of Ubuntu 24.04's source
        package indices (UBUNTU_SOURCES), which carry Debian's Go packages:
        module paths only.
  crates  crates.io's API, /api/v1/crates?sort=recent-downloads (the last
        90 days' downloads; the targets) and ?sort=downloads (all of them;
        known names only): the pages scripts/fetch-top-crates.py saves
        (the API is the only ranked list crates.io publishes; its crawler
        policy's one request a second is kept there). Crate names only.
        Given Ubuntu's source package indices too, the crates Debian
        packages (its rust-* source packages) are known names as well:
        real crates, vetted by Debian, that the check must not flag.

For npm, PyPI and crates the file keeps the TARGETS, the first 5,000 names by
downloads, and the KNOWN names: those of the whole list (17,000-odd for npm,
15,000 for PyPI) that are one change from a target — real packages the
check must not flag. A name of the list that is no target's look-alike can
never be flagged, so it need not be kept. PyPI names are PEP 503-normalized,
crate names lower-cased with "_" as "-" (one crate to crates.io): the 20,000
by recent downloads and the 20,000 by all downloads (all the API pages
through) read, and Debian's.
For Go every module of the two lists is a target, as lookalike.go_path()
writes it (lower-cased, without a major version), sorted.

Usage: python3 scripts/update-popular-names.py [NPM_LIB_DIR TOP_PYPI_JSON]
           [--crates PAGES_DIR [UBUNTU_SOURCES...]] [--go AWESOME_GO_README UBUNTU_SOURCES...] [--check]
A list not given is kept as it is in the file. An Ubuntu index may be
xz-compressed. --check compares with the file in the tree instead of
writing it (exit 1 on any difference). Standard library only.
"""
import hashlib
import json
import lzma
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
#: The indices the Go list was made from (the release pocket: they do not change).
UBUNTU_SOURCES = ("Ubuntu 24.04 LTS (noble), http://archive.ubuntu.com/ubuntu/dists/noble/{main,universe}/source/"
                  "Sources.xz")
AWESOME_GO_COPYRIGHT = "Copyright (c) 2014 Thiago Avelino"
_ENTRY_LINK_RE = re.compile(r"^\s*[-*]\s+\[[^\]]*\]\((https?://[^)\s]+)\)")
_GO_FORGE_LINKS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitee.com", "git.sr.ht")
_SOURCES_SPLIT_RE = re.compile(r"[,\s]+")
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


ABOUT = ("Names for the registry's look-alike check (SC-TYPOSQUAT, lazaret/registry/lookalike.py): the "
         f"{TARGETS:,} most-downloaded packages of npm, of PyPI and of crates.io (targets), and the other popular ones "
         "that are one change from a target (known); the Go modules awesome-go lists and Debian packages (targets). "
         "Written by scripts/update-popular-names.py.")


def npm_pypi_sections(npm_lib, top_pypi):
    npm_lib = pathlib.Path(npm_lib)
    version = json.loads((npm_lib.parent / "package.json").read_text(encoding="utf-8")).get("version", "?")
    npm_targets, npm_known = section("npm", js_names(npm_lib / "top-download.js"),
                                     js_names(npm_lib / "top.js") + js_names(npm_lib / "top-download.js"))
    doc = json.loads(pathlib.Path(top_pypi).read_text(encoding="utf-8"))
    pypi = [lookalike.normalize("pypi", r["project"]) for r in doc["rows"]]
    pypi_targets, pypi_known = section("pypi", pypi, pypi)
    return {
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


def debian_crates(text):
    """The crates a source package index's rust-* packages carry (Debian's crates, named as Debian names them:
    lower-cased, "_" as "-")."""
    out = []
    for line in text.split("\n"):
        if line.startswith("Package: rust-"):
            out.append(line[len("Package: rust-"):].strip())
    return out


def _crate_pages(paths, digest):
    names = []
    for page in paths:
        raw = page.read_bytes()
        digest.update(raw)
        names += [lookalike.normalize("crates", c["name"]) for c in json.loads(raw)["crates"]
                  if isinstance(c, dict) and isinstance(c.get("name"), str)]
    return names


def crates_section(pages_dir, sources=()):
    """The crates list from fetch-top-crates.py's pages (recent-0001.json, …, in order: by recent downloads, the
    targets; alltime-0001.json, …: known names), and the crates Debian packages (`sources`: Ubuntu's source package
    indices) as known names."""
    pages = sorted(pathlib.Path(pages_dir).glob("recent-*.json"), key=lambda p: p.as_posix())
    alltime = sorted(pathlib.Path(pages_dir).glob("alltime-*.json"), key=lambda p: p.as_posix())
    if not pages:
        raise SystemExit(f"no recent-*.json in {pages_dir}")
    digest = hashlib.sha256()
    names = _crate_pages(pages, digest)
    older = _crate_pages(alltime, digest)
    debian, sums = [], []
    for src in sources:
        raw, text = _read_index(src)
        sums.append(hashlib.sha256(raw).hexdigest()[:16])
        debian += [lookalike.normalize("crates", n) for n in debian_crates(text)]
    targets, known = section("crates", names, names + older + debian)
    debian_text = (f", and the rust-* source packages of {UBUNTU_SOURCES} (sha256 {', '.join(s + '…' for s in sums)}), "
                   "which carry the crates Debian packages" if sources else "")
    return {"crates": {
        "source": (f"crates.io's API, https://crates.io/api/v1/crates?sort=recent-downloads (downloads of the last "
                   f"90 days) and ?sort=downloads, {len(pages)} and {len(alltime)} pages of 100 saved by "
                   f"scripts/fetch-top-crates.py (sha256 {digest.hexdigest()[:16]}…){debian_text}"),
        "license": "crate names, which are facts about the crates; no text of the API's answers or the indices is kept",
        "changes": (f"crate names only, lower-cased with '_' as '-': the first {TARGETS:,} by recent downloads, and "
                    f"those of the {len(unique(names)):,}, of the {len(unique(older)):,} by all downloads"
                    + (f" and of Debian's {len(unique(debian)):,}" if sources else "")
                    + " that are one change from one of them"),
        "targets": targets, "known": known}}


def link_path(url):
    """The module path an awesome-go entry's link names, else None: a
    repository's (its owner and name; a GitLab project's groups) on one of
    _GO_FORGE_LINKS, or a pkg.go.dev page's."""
    rest = re.sub(r"^https?://(?:www\.)?", "", url).split("#", 1)[0].split("?", 1)[0].rstrip("/")
    rest = rest[:-4] if rest.endswith(".git") else rest
    parts = rest.split("/")
    host = parts[0].lower()
    if host == "pkg.go.dev":
        return "/".join(parts[1:]) if len(parts) > 1 and "." in parts[1] else None
    if host not in _GO_FORGE_LINKS or len(parts) < 3:
        return None
    if host == "gitlab.com":                                # groups/subgroups/project; "/-/" starts GitLab's pages
        names = parts[1:parts.index("-")] if "-" in parts else parts[1:]
        return host + "/" + "/".join(names) if len(names) >= 2 else None
    return "/".join([host] + parts[1:3])


def awesome_go_paths(text):
    """The module paths awesome-go's README names: the first link of each
    entry, in its sections up to its Resources but its Contents and its
    Editor Plugins (plugins for editors, not modules)."""
    out, section = [], None
    for line in text.split("\n"):
        if line.startswith("# Resources"):
            break
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        m = _ENTRY_LINK_RE.match(line) if section not in (None, "Contents", "Editor Plugins") else None
        path = link_path(m.group(1)) if m else None
        if path:
            out.append(path)
    return out


def ubuntu_go_paths(text):
    """The Go-Import-Path values of a source package index (Sources): each
    package's, separated by commas or spaces, a field continued on the
    lines that start with a space."""
    out = []
    for para in text.split("\n\n"):
        value, inside = None, False
        for line in para.split("\n"):
            if line[:1] in (" ", "\t"):
                if inside:
                    value += " " + line.strip()
                continue
            inside = line.startswith("Go-Import-Path:")
            if inside:
                value = line.split(":", 1)[1]
        if value:
            out.extend(v for v in _SOURCES_SPLIT_RE.split(value) if v)
    return out


def _read_index(path):
    raw = pathlib.Path(path).read_bytes()
    return raw, (lzma.decompress(raw) if raw[:6] == b"\xfd7zXZ\x00" else raw).decode("utf-8", "replace")


def go_section(readme, sources):
    readme_raw = pathlib.Path(readme).read_bytes()
    paths = awesome_go_paths(readme_raw.decode("utf-8"))
    sums = []
    for src in sources:
        raw, text = _read_index(src)
        sums.append(hashlib.sha256(raw).hexdigest()[:16])
        paths += ubuntu_go_paths(text)
    targets = sorted({p for p in map(lookalike.go_path, paths) if p})
    return {"go": {
        "source": (f"awesome-go's README.md, https://github.com/avelino/awesome-go (sha256 "
                   f"{hashlib.sha256(readme_raw).hexdigest()[:16]}…), and the Go-Import-Path fields of "
                   f"{UBUNTU_SOURCES} (sha256 {', '.join(s + '…' for s in sums)}), which carry Debian's Go packages"),
        "license": ("awesome-go: MIT (the copyright and notice below). The Ubuntu indices: module paths, which are "
                    "facts about the packages; no text of them is kept"),
        "copyright": AWESOME_GO_COPYRIGHT,
        "notice": MIT_NOTICE,
        "changes": ("module paths only: the first link of each awesome-go entry outside its Resources and Editor "
                    "Plugins (a repository's owner and name, a pkg.go.dev page's path) and each Go-Import-Path; "
                    "lower-cased and without a major version (/v2), sorted"),
        "targets": targets}}


def build(current, npm_lib=None, top_pypi=None, go=None, crates=None):
    """The file: `current` (the file's data) with the lists given rebuilt."""
    out = {"_about": ABOUT}
    if npm_lib is not None:
        out.update(npm_pypi_sections(npm_lib, top_pypi))
    else:
        out.update({eco: current[eco] for eco in ("npm", "pypi")})
    out.update(crates_section(*crates) if crates is not None else {"crates": current["crates"]})
    out.update(go_section(*go) if go is not None else {"go": current["go"]})
    return out


def main(argv):
    configure_stdio()
    args = [a for a in argv if a != "--check"]
    crates = None
    if "--crates" in args:
        at = args.index("--crates")
        end = next((k for k in range(at + 1, len(args)) if args[k].startswith("--")), len(args))
        if end == at + 1:
            print(__doc__.split("\n\n")[-1].strip(), file=sys.stderr)
            return 2
        crates, args = (args[at + 1], args[at + 2:end]), args[:at] + args[end:]
    go = None
    if "--go" in args:
        at = args.index("--go")
        args, files = args[:at], args[at + 1:]
        go = (files[0], files[1:]) if len(files) >= 2 else ()          # (the README, then the indices)
    if len(args) not in ((0, 2) if go is not None or crates is not None else (2,)) or go == ():
        print(__doc__.split("\n\n")[-1].strip(), file=sys.stderr)
        return 2
    current = json.loads(OUT.read_text(encoding="utf-8")) if OUT.exists() else {}
    if ((not args and ("npm" not in current or "pypi" not in current)) or (go is None and "go" not in current)
            or (crates is None and "crates" not in current)):
        print(f"{OUT.relative_to(ROOT)} has no list to keep: give every source", file=sys.stderr)
        return 2
    text = json.dumps(build(current, *args, go=go, crates=crates), indent=1, ensure_ascii=False) + "\n"
    if "--check" in argv:
        now = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if now != text:
            print(f"{OUT.relative_to(ROOT)} differs from what the sources give", file=sys.stderr)
            return 1
        print("popular_names.json is current")
        return 0
    OUT.write_text(text, encoding="utf-8")
    data = json.loads(text)
    print(f"wrote {OUT.relative_to(ROOT)}: npm {len(data['npm']['targets'])} targets, {len(data['npm']['known'])} "
          f"known; PyPI {len(data['pypi']['targets'])} targets, {len(data['pypi']['known'])} known; crates "
          f"{len(data['crates']['targets'])} targets, {len(data['crates']['known'])} known; Go "
          f"{len(data['go']['targets'])} modules")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
