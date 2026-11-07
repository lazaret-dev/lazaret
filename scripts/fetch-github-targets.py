#!/usr/bin/env python3
"""Fetch where popular packages keep their code, for scripts/update-popular-names.py --github (GH-NEW-REPOS): the
GitHub repositories that new repositories are compared with (registry/lookalike.github_tables).

  npm    each of popular_names.json's npm targets (the 5,000 most-downloaded packages): the registry's
         /<name>/latest, of which the `repository` field is kept
  pypi   each of its PyPI targets: /pypi/<name>/json, of which info.project_urls and info.home_page are kept
  stars  with --stars and GITHUB_TOKEN (read-only): GitHub's search for the most-starred repositories,
         /search/repositories?q=stars:>10000&sort=stars, 10 pages of 100 (the most the search gives); each
         repository's full_name, description and stargazers_count are kept (the descriptions are what the copy test
         compares)

Only those fields are written, one JSON object a line (OUT_DIR/npm.jsonl, pypi.jsonl, stars.jsonl), with the
package's rank; popular_names.json keeps the repositories' names (facts), and for the most-starred their
descriptions. A package that cannot be read is written with its error and left out later. Eight requests at a time to
the registries, each with a User-Agent that says who is asking; GitHub's search, one a second.

Usage: python3 scripts/fetch-github-targets.py OUT_DIR [--only npm|pypi|stars] [--stars]
(--stars adds the most-starred list; --only fetches one list.) Standard library only, and the repository's own
python/src for configure_stdio.
"""
import concurrent.futures
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python" / "src"))
from lazaret.scanner.core import configure_stdio  # noqa: E402

NAMES = ROOT / "python" / "src" / "lazaret" / "registry" / "popular_names.json"
USER_AGENT = "lazaret-update-popular-names (https://lazaret.dev)"
WORKERS = 8
MAX_BYTES = 32 * 1024 * 1024
STAR_PAGES = 10
MIN_STARS = 10000


def get(url, headers=None):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                                               **(headers or {})})
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"over {MAX_BYTES} bytes")
    return json.loads(body)


def npm_one(rank, name):
    try:
        doc = get(f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest")
        return {"rank": rank, "name": name, "repository": doc.get("repository") if isinstance(doc, dict) else None}
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return {"rank": rank, "name": name, "error": f"{type(exc).__name__}: {exc}"[:200]}


def pypi_one(rank, name):
    try:
        info = (get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json") or {}).get("info") or {}
        return {"rank": rank, "name": name, "project_urls": info.get("project_urls"), "home_page": info.get("home_page")}
    except (OSError, ValueError, urllib.error.URLError, AttributeError) as exc:
        return {"rank": rank, "name": name, "error": f"{type(exc).__name__}: {exc}"[:200]}


def line(row):
    return json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"


def fetch_all(names, one, label):
    """-> the lines of one list, each package's row in rank order."""
    lines = []
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as pool:
        for row in pool.map(lambda pair: one(*pair), enumerate(names)):
            lines.append(line(row))
            if len(lines) % 500 == 0:
                print(f"  {label}: {len(lines):,} of {len(names):,}", file=sys.stderr)
    return lines


def stars():
    """-> the lines of GitHub's most-starred list (MIN_STARS and up, STAR_PAGES pages at most)."""
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise SystemExit("--stars needs GITHUB_TOKEN (read-only)")
    lines = []
    for page in range(1, STAR_PAGES + 1):
        doc = get(f"https://api.github.com/search/repositories?q=stars:%3E{MIN_STARS}&sort=stars&order=desc"
                  f"&per_page=100&page={page}",
                  {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
        items = doc.get("items") or []
        lines += [line({"rank": len(lines) + k, "full_name": it.get("full_name"), "description": it.get("description"),
                        "stargazers_count": it.get("stargazers_count")}) for k, it in enumerate(items)]
        if len(items) < 100:
            break
        time.sleep(1.0)
    return lines


def options(argv):
    """-> (OUT_DIR, --only's list or None, --stars) or None for a command line that is not one."""
    args = list(argv)
    only = None
    if "--only" in args[:-1]:
        at = args.index("--only")
        only, args = args[at + 1], args[:at] + args[at + 2:]
    with_stars = "--stars" in args
    args = [a for a in args if a != "--stars"]
    if len(args) != 1 or only not in (None, "npm", "pypi", "stars"):
        return None
    return args[0], only, with_stars


def main(argv):
    configure_stdio()
    opts = options(argv)
    if opts is None:
        print(__doc__.split("\n\n")[-1].strip(), file=sys.stderr)
        return 2
    out_dir, only, with_stars = pathlib.Path(opts[0]), opts[1], opts[2]
    out_dir.mkdir(parents=True, exist_ok=True)
    names = json.loads(NAMES.read_text(encoding="utf-8"))
    wanted = [("npm", "npm.jsonl", lambda: fetch_all(names["npm"]["targets"], npm_one, "npm"), "packages"),
              ("pypi", "pypi.jsonl", lambda: fetch_all(names["pypi"]["targets"], pypi_one, "PyPI"), "projects"),
              ("stars", "stars.jsonl", stars, "most-starred repositories")]
    for which, file, fetch, what in wanted:
        if only == which or (only is None and (which != "stars" or with_stars)):
            lines = fetch()
            (out_dir / file).write_text("".join(lines), encoding="utf-8")
            print(f"{which}: {len(lines):,} {what}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
