#!/usr/bin/env python3
"""Fetch the most-installed VS Code extensions for scripts/update-popular-names.py --vscode: the Visual Studio
Marketplace's and Open VSX's lists, a page per file, kept as the registries wrote them.

Neither registry publishes its ranking as a file, so the lists are their APIs': the Marketplace's gallery query (a POST
to `extensionquery`, as VS Code sends it: the extensions for VS Code, unpublished ones left out, sorted by installs, 100
a page) and Open VSX's search (`/api/-/search?sortBy=downloadCount&sortOrder=desc`, 100 a page). The look-alike check's
targets are the first 1,000 of each; the rest are known names, never flagged. Requests are paced, a second apart on the
Marketplace and two on Open VSX (which asks anonymous clients to go slowly), with a User-Agent that says who is asking.
Only the extensions' identifiers are kept in popular_names.json (facts, not the registries' text).

Usage: python3 scripts/fetch-top-extensions.py OUT_DIR [COUNT]
COUNT, per registry, defaults to 10,000 (100 pages each: about two minutes on the Marketplace, four on Open VSX). The
pages are OUT_DIR/marketplace-0001.json, … and OUT_DIR/openvsx-0001.json, … A registry that cannot be reached is said
and skipped; update-popular-names.py reads whichever pages there are. Standard library only.
"""
import json
import pathlib
import sys
import time
import urllib.error
import urllib.request

MARKETPLACE = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
OPENVSX = "https://open-vsx.org/api/-/search?sortBy=downloadCount&sortOrder=desc&size={size}&offset={offset}"
USER_AGENT = "lazaret-update-popular-names (https://lazaret.dev)"
PER_PAGE = 100
INTERVALS = {"marketplace": 1.0, "openvsx": 2.0}
MAX_PAGE_BYTES = 8 * 1024 * 1024
#: VS Code's gallery query: the extensions for VS Code (filter type 8), unpublished ones left out (type 12, flag
#: 4096), sorted by installs (sortBy 4); with their statistics (flag 256), so that a page says its install counts
QUERY_FLAGS = 256


def _read(req):
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read(MAX_PAGE_BYTES + 1)
    if len(body) > MAX_PAGE_BYTES:
        raise SystemExit(f"a page of {req.full_url} is over {MAX_PAGE_BYTES} bytes")
    return body


def marketplace_page(page):
    """(the page's bytes, how many extensions it lists) of the Marketplace's ranking."""
    query = {"filters": [{"criteria": [{"filterType": 8, "value": "Microsoft.VisualStudio.Code"},
                                       {"filterType": 12, "value": "4096"}],
                          "pageNumber": page, "pageSize": PER_PAGE, "sortBy": 4, "sortOrder": 0}],
             "assetTypes": [], "flags": QUERY_FLAGS}
    req = urllib.request.Request(MARKETPLACE, data=json.dumps(query).encode("utf-8"), method="POST",
                                 headers={"User-Agent": USER_AGENT, "Content-Type": "application/json",
                                          "Accept": "application/json;api-version=3.0-preview.1"})
    body = _read(req)
    data = json.loads(body)
    results = data.get("results") if isinstance(data, dict) else None
    exts = results[0].get("extensions") if isinstance(results, list) and results and isinstance(results[0], dict) \
        else None
    if not isinstance(exts, list):
        raise SystemExit(f"Marketplace page {page} has no list of extensions")
    return body, len(exts)


def openvsx_page(page):
    """(the page's bytes, how many extensions it lists) of Open VSX's ranking."""
    req = urllib.request.Request(OPENVSX.format(size=PER_PAGE, offset=(page - 1) * PER_PAGE),
                                 headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    body = _read(req)
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get("extensions"), list):
        raise SystemExit(f"Open VSX page {page} has no list of extensions")
    return body, len(data["extensions"])


def _configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main(argv):
    _configure_stdio()
    if not argv or len(argv) > 2:
        print(__doc__.strip().split("\n\n")[-1], file=sys.stderr)
        return 2
    out = pathlib.Path(argv[0])
    count = int(argv[1]) if len(argv) > 1 else 10_000
    out.mkdir(parents=True, exist_ok=True)
    pages = -(-count // PER_PAGE)
    for prefix, fetch in (("marketplace", marketplace_page), ("openvsx", openvsx_page)):
        last, written = 0.0, 0
        try:
            for page in range(1, pages + 1):
                wait = last + INTERVALS[prefix] - time.monotonic()
                if wait > 0:
                    time.sleep(wait)
                last = time.monotonic()
                body, n = fetch(page)
                (out / f"{prefix}-{page:04d}.json").write_bytes(body)
                written = page
                if n < PER_PAGE:
                    break
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"{prefix}: stopped at page {written + 1} ({exc})", file=sys.stderr)
        print(f"{prefix}: {written} pages in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
