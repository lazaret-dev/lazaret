#!/usr/bin/env python3
"""Fetch crates.io's lists of crates by downloads for scripts/update-popular-names.py --crates: the API's pages, one
file each, kept as the API wrote them.

crates.io publishes no ranked list as a file, so the lists are its API's `/api/v1/crates`, 100 crates a page: by recent
downloads (the last 90 days; the look-alike check's targets come from this one) and by all downloads (crates long in use
that are not among the recent ones: known names, never flagged). The crawler policy (https://crates.io/data-access) asks
for at most one request a second and a User-Agent that says who is asking; this script keeps both. Only the crates'
names are kept in popular_names.json (facts, not the API's text).

Usage: python3 scripts/fetch-top-crates.py OUT_DIR [COUNT]
COUNT, per list, defaults to 20,000 (200 pages, three and a half minutes a list), the most the API pages through ("Page
201 is unavailable for performance reasons"). The pages are OUT_DIR/recent-0001.json, … and OUT_DIR/alltime-0001.json,
… Standard library only.
"""
import json
import pathlib
import sys
import time
import urllib.request

API = "https://crates.io/api/v1/crates?sort={sort}&per_page=100&page={page}"
LISTS = (("recent", "recent-downloads"), ("alltime", "downloads"))
USER_AGENT = "lazaret-update-popular-names (https://lazaret.dev)"
PER_PAGE = 100
INTERVAL = 1.0
MAX_PAGE_BYTES = 4 * 1024 * 1024


def fetch(sort, page):
    req = urllib.request.Request(API.format(sort=sort, page=page),
                                 headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read(MAX_PAGE_BYTES + 1)
    if len(body) > MAX_PAGE_BYTES:
        raise SystemExit(f"{sort} page {page} is over {MAX_PAGE_BYTES} bytes")
    data = json.loads(body)
    if not isinstance(data, dict) or not isinstance(data.get("crates"), list):
        raise SystemExit(f"{sort} page {page} has no list of crates")
    return body, len(data["crates"])


def main(argv):
    if not argv or len(argv) > 2:
        print(__doc__.strip().split("\n\n")[-1], file=sys.stderr)
        return 2
    out = pathlib.Path(argv[0])
    count = int(argv[1]) if len(argv) > 1 else 20_000
    out.mkdir(parents=True, exist_ok=True)
    pages = -(-count // PER_PAGE)
    last = 0.0
    for prefix, sort in LISTS:
        for page in range(1, pages + 1):
            wait = last + INTERVAL - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            last = time.monotonic()
            body, n = fetch(sort, page)
            (out / f"{prefix}-{page:04d}.json").write_bytes(body)
            if n < PER_PAGE:
                break
        print(f"{prefix}: {page} pages in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
