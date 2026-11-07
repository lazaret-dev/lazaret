#!/usr/bin/env python3
"""Fetch who owns the popular packages, for scripts/update-popular-names.py --owners (SC-PUBLISHER-LOOKALIKE, RA-9):
the accounts a package named like a popular one's has its owners compared with (registry/lookalike.owner_lookalike).

  npm     each of popular_names.json's npm targets: the registry's /<name>/latest, of which the names of its
          `maintainers` are kept (the accounts that may publish it; their e-mail addresses are not, nor `_npmUser`,
          which is "GitHub Actions" for a release published from a workflow)
  pypi    each PyPI target: /pypi/<name>/json (asked for gzip-compressed: the largest are 4 MB), of which `ownership` is
          kept: its roles' user names and its organization's name
  crates  each crate target: crates.io's /api/v1/crates/<name>/owners, of which each owner's login is kept (a
          user's, or a team's, github:org:team), one request a second (crates.io's crawler policy,
          https://crates.io/data-access)

Only those names are written, lower-cased, one JSON object a line (OUT_DIR/npm.jsonl, pypi.jsonl, crates.jsonl):
{"rank", "name", "owners"}, or {"rank", "name", "error"} for a package that could not be read (left out later). A line
is written as each answer comes, so a run that stops goes on where it stopped when it is started again: a package
already written with its owners is not asked again, one written with an error is. --top N asks for the first N targets
of each list (by rank), and a later run with a larger N asks for the rest; with no --top, all of them (5,000 a list:
the crates' take 83 minutes). Four requests at a time to npm and PyPI, each with a User-Agent that says who is asking.

Usage: python3 scripts/fetch-target-owners.py OUT_DIR [--only npm|pypi|crates] [--top N]
Standard library only, and the repository's own python/src for configure_stdio.
"""
import concurrent.futures
import gzip
import json
import pathlib
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "python" / "src"))
from lazaret.scanner.core import configure_stdio  # noqa: E402

NAMES = ROOT / "python" / "src" / "lazaret" / "registry" / "popular_names.json"
USER_AGENT = "lazaret-update-popular-names (https://lazaret.dev)"
WORKERS = 4
MAX_BYTES = 32 * 1024 * 1024
#: the most owners kept of one package (crates.io lists a few, npm and PyPI rarely more than a dozen)
MAX_OWNERS = 64
#: crates.io's crawler policy: at most one request a second
CRATES_INTERVAL = 1.0
LISTS = ("npm", "pypi", "crates")


def _body(resp):
    """The response's body, gunzipped when it came compressed, at most MAX_BYTES either way."""
    raw = resp.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError(f"over {MAX_BYTES} bytes")
    if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
        out = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = out.decompress(raw, MAX_BYTES + 1)
        if len(raw) > MAX_BYTES or out.unconsumed_tail:
            raise ValueError(f"over {MAX_BYTES} bytes")
    return raw


def get(url, gzipped=False):
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if gzipped:
        headers["Accept-Encoding"] = "gzip"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(_body(resp))


def _names(values):
    """The account names of `values` (text), lower-cased, each once, sorted, at most MAX_OWNERS."""
    return sorted({v.strip().lower() for v in values if isinstance(v, str) and v.strip()})[:MAX_OWNERS]


def npm_owners(doc):
    """npm's /<name>/latest -> the names of its maintainers."""
    people = doc.get("maintainers") if isinstance(doc, dict) else None
    return _names(m.get("name") for m in people or () if isinstance(m, dict))


def pypi_owners(doc):
    """PyPI's /pypi/<name>/json -> its ownership's user names and organization."""
    own = doc.get("ownership") if isinstance(doc, dict) else None
    own = own if isinstance(own, dict) else {}
    users = [r.get("user") for r in own.get("roles") or () if isinstance(r, dict)]
    return _names(users + [own.get("organization")])


def crates_owners(doc):
    """crates.io's /api/v1/crates/<name>/owners -> its owners' logins."""
    users = doc.get("users") if isinstance(doc, dict) else None
    if not isinstance(users, list):
        raise ValueError("the owners answer has no list of users")
    return _names(u.get("login") for u in users if isinstance(u, dict))


def url_of(which, name):
    if which == "npm":
        return f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/latest"
    if which == "pypi":
        return f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    return f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}/owners"


_READ = {"npm": npm_owners, "pypi": pypi_owners, "crates": crates_owners}


def one(which, rank, name, fetch=get):
    """-> the line's row for one package."""
    try:
        return {"rank": rank, "name": name, "owners": _READ[which](fetch(url_of(which, name), gzipped=which == "pypi"))}
    except (OSError, ValueError, urllib.error.URLError, AttributeError, zlib.error, gzip.BadGzipFile) as exc:
        return {"rank": rank, "name": name, "error": f"{type(exc).__name__}: {exc}"[:200]}


def line(row):
    return json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"


def done_rows(path):
    """The rows of a file a run wrote before, those with owners only (one with an error is asked again)."""
    rows = {}
    if path.exists():
        for text in path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(text)
            except ValueError:
                continue                     # (a line cut short when the run stopped)
            if isinstance(row, dict) and isinstance(row.get("name"), str) and isinstance(row.get("owners"), list):
                rows[row["name"]] = row
    return rows


class Pace:
    """At most one request every `interval` seconds, from any number of threads."""

    def __init__(self, interval, clock=time.monotonic, sleep=time.sleep):
        self.interval, self.clock, self.sleep = interval, clock, sleep
        self.next = 0.0
        self.lock = threading.Lock()

    def __call__(self, fetch):
        def paced(url, **kw):
            with self.lock:
                wait = self.next - self.clock()
                if wait > 0:
                    self.sleep(wait)
                self.next = self.clock() + self.interval
            return fetch(url, **kw)
        return paced


def fetch_list(which, names, path, fetch=get, workers=WORKERS, progress=sys.stderr):
    """Ask for the owners of `names` (in rank order) not already in `path`, appending each row as it comes ->
    (asked, with owners, errors)."""
    kept = done_rows(path)
    with path.open("w", encoding="utf-8") as f:              # (the file again: its good rows, then the new ones)
        f.writelines(line(r) for r in sorted(kept.values(), key=lambda r: r.get("rank", 0)))
    todo = [(rank, name) for rank, name in enumerate(names) if name not in kept]
    if which == "crates":
        fetch, workers = Pace(CRATES_INTERVAL)(fetch), 1
    asked = good = 0
    with path.open("a", encoding="utf-8") as f, concurrent.futures.ThreadPoolExecutor(workers) as pool:
        for row in pool.map(lambda pair: one(which, *pair, fetch=fetch), todo):
            f.write(line(row))
            f.flush()
            asked += 1
            good += "owners" in row
            if asked % 250 == 0 and progress is not None:
                print(f"  {which}: {asked:,} of {len(todo):,}", file=progress)
    return asked, good, asked - good


def options(argv):
    """-> (OUT_DIR, the lists, --top or None), or None for a command line that is not one."""
    args, only, top = list(argv), None, None
    for flag in ("--only", "--top"):
        if flag in args:
            at = args.index(flag)
            if at + 1 >= len(args):
                return None
            value, args = args[at + 1], args[:at] + args[at + 2:]
            if flag == "--only":
                only = value
            elif value.isdigit() and int(value) > 0:
                top = int(value)
            else:
                return None
    if len(args) != 1 or only not in (None,) + LISTS:
        return None
    return pathlib.Path(args[0]), [only] if only else list(LISTS), top


def main(argv):
    configure_stdio()
    opts = options(argv)
    if opts is None:
        print(__doc__.split("\n\n")[-1].strip(), file=sys.stderr)
        return 2
    out_dir, lists, top = opts
    out_dir.mkdir(parents=True, exist_ok=True)
    data = json.loads(NAMES.read_text(encoding="utf-8"))
    for which in lists:
        names = data[which]["targets"][:top] if top else data[which]["targets"]
        asked, good, bad = fetch_list(which, names, out_dir / f"{which}.jsonl")
        print(f"{which}: {asked:,} asked, {good:,} with owners, {bad:,} not read", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
