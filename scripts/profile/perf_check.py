#!/usr/bin/env python3
"""The scheduled performance check (0.1.9, P-10): the native engine's time on a fixed set of real packages.

    python3 scripts/profile/perf_check.py fetch     [--cache DIR] [--only ID ...]
    python3 scripts/profile/perf_check.py run       [--cache DIR] [--runs N] [--only ID ...] [--json PATH]
                                                    [--summary PATH] [--no-fail]
    python3 scripts/profile/perf_check.py calibrate REPORT... [--margin 0.25] [--write]
    python3 scripts/profile/perf_check.py pin       ecosystem:name@version ...

`packages.json` lists the packages: every archive a registry scan would read for the release, with its URL and
its **sha256**. `fetch` downloads them (and refuses bytes that are not the pinned ones), `run` times
the scan of each, `calibrate` turns the reports of several runs into budgets, `pin` is how a maintainer adds
or moves a package (it resolves, downloads and hashes).

What is timed. The archives are fetched first and read into memory outside the timed part, so the network is
never in the numbers. Each run scans every archive of a package with `repo._scan_artifact` (the call the guard
makes), with the use-time step's 3-second box raised, so that every run reads the same files: until P-14
bounds that step by work, the box would make a fast runner read more than a slow one. The budget is on
`engine_s`, the seconds spent inside the native engine summed over its threads (the number that does not move
with the runner's core count the way the wall time does); `wall_s` is reported beside it. Each figure is the
median of `--runs` runs (3 by default); `spread` is (largest - smallest) / median across them.

Budgets. A package with `budget.engine_s` null is *uncalibrated*: reported, never failed. `calibrate` reads
the reports of several scheduled runs on the runner (the median of their medians) and proposes
`budget.engine_s` that many percent above it (25% by default, and at least 0.25 s above it, so that the
smallest packages do not flap on noise); `--write` puts it, and the number of files
scanned, in `packages.json`. The check fails (exit 1) only for a package that has a budget and is over it, and
`--no-fail` never fails. A scan of a different number of files than the calibration saw is reported as
"work changed": the budget no longer compares like with like.

Exit status: 0 done (or nothing over budget), 1 over budget, 2 usage or a bad packages file, 3 an archive could
not be fetched or is not the pinned one, 4 the native engine is not built. Standard library plus this checkout.
"""

import argparse
import contextlib
import hashlib
import json
import math
import os
import statistics
import sys
import tempfile
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402

PACKAGES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "packages.json")
SCHEMA = 1
DEFAULT_RUNS = 3
DEFAULT_MARGIN = 0.25
MIN_SLACK = 0.25                 # seconds: a budget is at least this far above the median, so a 0.1 s package does not flap
MAX_FILE_BYTES = 512 * 1024 * 1024
SCAN_SECONDS = 900.0
FETCH_TIMEOUT = 120
EXIT_OK, EXIT_OVER, EXIT_USAGE, EXIT_FETCH, EXIT_NO_ENGINE = 0, 1, 2, 3, 4
CONTAINERS = ("zip", "tgz", "tbz2", "txz")
ARTIFACTS = ("npm", "sdist", "wheel")
LOOPBACK = ("127.0.0.1", "::1", "localhost")


class ConfigError(ValueError):
    """packages.json is not what this script reads."""


class PinError(Exception):
    """An archive could not be fetched, or is not the pinned bytes."""


# ---- the packages file
def _is_sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def validate(cfg):
    """-> cfg, or ConfigError saying what is wrong (a bad file must stop the run, not skip a package)."""
    if not isinstance(cfg, dict) or cfg.get("version") != SCHEMA:
        raise ConfigError(f"packages.json: version must be {SCHEMA}")
    packages = cfg.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ConfigError("packages.json: packages must be a non-empty list")
    seen = set()
    for pkg in packages:
        pid = pkg.get("id") if isinstance(pkg, dict) else None
        if not isinstance(pid, str) or not pid or pid in seen:
            raise ConfigError(f"packages.json: a package has no id, or the id is used twice: {pid!r}")
        seen.add(pid)
        files = pkg.get("files")
        if not isinstance(files, list) or not files:
            raise ConfigError(f"{pid}: files must be a non-empty list")
        for f in files:
            if not isinstance(f, dict) or not isinstance(f.get("url"), str) or not _is_sha256(f.get("sha256")) \
                    or not isinstance(f.get("filename"), str) or f.get("container") not in CONTAINERS \
                    or f.get("artifact") not in ARTIFACTS:
                raise ConfigError(f"{pid}: each file needs url, filename, sha256 (64 hex digits), container "
                                  f"({'/'.join(CONTAINERS)}) and artifact ({'/'.join(ARTIFACTS)}): {f!r}")
            if not _url_allowed(f["url"]):
                raise ConfigError(f"{pid}: {f['filename']}: only https is fetched: {f['url']}")
        budget = (pkg.get("budget") or {}).get("engine_s")
        if budget is not None and (isinstance(budget, bool) or not isinstance(budget, (int, float)) or budget <= 0):
            raise ConfigError(f"{pid}: budget.engine_s must be a positive number or null")
    return cfg


def load_packages(path=PACKAGES):
    try:
        with open(path, encoding="utf-8") as fh:
            return validate(json.load(fh))
    except (OSError, ValueError) as exc:
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"{path}: {exc}") from exc


def select(cfg, only=None):
    """The packages named in `only` (all when it is empty); ConfigError for an id that is not there."""
    packages = cfg["packages"]
    if not only:
        return list(packages)
    known = {p["id"]: p for p in packages}
    missing = [i for i in only if i not in known]
    if missing:
        raise ConfigError(f"not in packages.json: {', '.join(missing)} (known: {', '.join(known)})")
    return [known[i] for i in only]


def save_packages(cfg, path=PACKAGES):
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(cfg, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


# ---- fetching by pinned hash
def _url_allowed(url):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" or (parts.scheme == "http" and (parts.hostname or "") in LOOPBACK)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_file(entry, cache, opener=urllib.request.urlopen):
    """-> the path of the pinned archive in `cache` (named by its sha256), fetched if it is not there. A file
    already there is read and hashed again, so a cache that was damaged or swapped is not trusted. PinError for
    bytes that are not the pinned ones, a URL that is not https, a download over MAX_FILE_BYTES, or any network
    error."""
    want, url = entry["sha256"], entry["url"]
    dest = os.path.join(cache, want)
    if os.path.isfile(dest) and sha256_file(dest) == want:
        return dest
    if not _url_allowed(url):
        raise PinError(f"{entry['filename']}: only https is fetched: {url}")
    os.makedirs(cache, exist_ok=True)
    part, h, size = dest + ".part", hashlib.sha256(), 0
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "lazaret-perf-check"})
        with opener(req, timeout=FETCH_TIMEOUT) as resp, open(part, "wb") as out:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise PinError(f"{entry['filename']}: more than {MAX_FILE_BYTES >> 20} MiB")
                h.update(chunk)
                out.write(chunk)
        if h.hexdigest() != want:
            raise PinError(f"{entry['filename']}: the bytes are not the pinned ones "
                           f"(sha256 {h.hexdigest()}, pinned {want}); {url}")
        os.replace(part, dest)
    except PinError:
        raise
    except (OSError, ValueError) as exc:               # (URLError and HTTPError are OSErrors)
        raise PinError(f"{entry['filename']}: {exc}; {url}") from exc
    finally:
        with contextlib.suppress(OSError):
            os.remove(part)
    return dest


def fetch_all(packages, cache, opener=urllib.request.urlopen, progress=None):
    """Fetch every file of `packages`; -> {sha256: path}."""
    paths = {}
    for pkg in packages:
        for f in pkg["files"]:
            if f["sha256"] not in paths:
                if progress:
                    progress(f"fetch {pkg['id']}: {f['filename']}")
                paths[f["sha256"]] = fetch_file(f, cache, opener)
    return paths


# ---- timing
def _median(values):
    return statistics.median(values) if values else 0.0


def measure(pkg, cache, runs, scan, progress=None):
    """Scan every archive of `pkg` `runs` times -> {"runs": [...], medians and spread}. The archives are read
    into memory before the first run; `scan(data, container, artifact)` -> a `_scan_artifact` result. Its
    engine calls are what `timings` spans of the phase "engine" add up to."""
    from lazaret.scanner import timings
    blobs = []
    for f in pkg["files"]:
        with open(os.path.join(cache, f["sha256"]), "rb") as fh:
            blobs.append((f, fh.read()))
    rows = []
    for n in range(runs):
        t = timings.Timings()
        with timings.capture(t), t.run():
            results = [scan(data, f["container"], f["artifact"]) for f, data in blobs]
        report = t.report()
        engine = report["phases"].get("engine", {"seconds": 0.0, "calls": 0})
        rows.append({"engine_s": engine["seconds"], "engine_calls": engine["calls"], "wall_s": report["wall"],
                     "files_scanned": sum(r.get("filesScanned", 0) for r in results),
                     "verdicts": [r.get("verdict") for r in results]})
        if progress:
            progress(f"{pkg['id']} run {n + 1}/{runs}: engine {rows[-1]['engine_s']:.2f} s, wall {rows[-1]['wall_s']:.2f} s")
    engine_s = _median([r["engine_s"] for r in rows])
    low, high = min(r["engine_s"] for r in rows), max(r["engine_s"] for r in rows)
    return {"id": pkg["id"], "files": len(blobs), "bytes": sum(len(d) for _, d in blobs), "runs": rows,
            "engine_s": engine_s, "wall_s": _median([r["wall_s"] for r in rows]),
            "spread": (high - low) / engine_s if engine_s > 0 else 0.0,
            "files_scanned": rows[0]["files_scanned"], "verdicts": rows[0]["verdicts"]}


def judge(pkg, result):
    """Add the budget's verdict to a measurement: status ok / over / uncalibrated, the ratio to the budget, and
    whether the work changed since calibration."""
    budget = (pkg.get("budget") or {}).get("engine_s")
    result["budget_s"] = budget
    result["ratio"] = result["engine_s"] / budget if budget else None
    result["status"] = "uncalibrated" if budget is None else ("over" if result["engine_s"] > budget else "ok")
    expected = (pkg.get("expect") or {}).get("files_scanned")
    result["work_changed"] = expected is not None and expected != result["files_scanned"]
    return result


def run_check(cfg, cache, runs, scan, only=None, progress=None):
    """-> the report: one judged measurement per package (see the module doc for its fields). The smallest
    archive is scanned once first, unmeasured: the engine's first call in a process pays for set-up that
    would otherwise sit in the first package's first run."""
    packages = select(cfg, only)
    smallest = min((f for p in packages for f in p["files"]), key=lambda f: f.get("bytes", 0))
    with open(os.path.join(cache, smallest["sha256"]), "rb") as fh:
        scan(fh.read(), smallest["container"], smallest["artifact"])
    results = []
    for pkg in packages:
        results.append(judge(pkg, measure(pkg, cache, runs, scan, progress)))
    return {"schema": SCHEMA, "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python": sys.version.split()[0], "platform": sys.platform, "cpus": os.cpu_count(),
            "runs": runs, "packages": results}


def over_budget(report):
    return [p["id"] for p in report["packages"] if p["status"] == "over"]


def render_table(report):
    """-> the report as a markdown table (for a job summary or the terminal)."""
    lines = ["| package | files | MB | engine s | wall s | spread | budget s | status |", "|---|---|---|---|---|---|---|---|"]
    for p in report["packages"]:
        status = p["status"] + (" (work changed)" if p["work_changed"] else "")
        budget = "-" if p["budget_s"] is None else f"{p['budget_s']:.1f}"
        lines.append(f"| {p['id']} | {p['files_scanned']} | {p['bytes'] / 1e6:.1f} | {p['engine_s']:.2f} | "
                     f"{p['wall_s']:.2f} | {100 * p['spread']:.0f}% | {budget} | {status} |")
    lines.append("")
    lines.append(f"Median of {report['runs']} runs per package; {report['cpus']} CPUs; Python {report['python']} on "
                 f"{report['platform']}; engine seconds are summed over the engine's threads.")
    if any(p["status"] == "uncalibrated" for p in report["packages"]):
        lines.append("Packages marked uncalibrated have no budget yet: reported, never failed. "
                     "`perf_check.py calibrate` reads reports of several runs on this runner.")
    return "\n".join(lines) + "\n"


# ---- calibration
def calibrate(reports, margin=DEFAULT_MARGIN):
    """-> {id: {"engine_s": budget, "median": m, "reports": n, "files_scanned": n}}: for each package in the
    reports, the median of its medians, plus `margin` (and at least MIN_SLACK), rounded up to a tenth of a second."""
    by_id = {}
    for report in reports:
        for p in report["packages"]:
            by_id.setdefault(p["id"], []).append(p)
    out = {}
    for pid, rows in by_id.items():
        median = _median([r["engine_s"] for r in rows])
        raw = max(median * (1 + margin), median + MIN_SLACK)
        out[pid] = {"engine_s": math.ceil(raw * 10 - 1e-9) / 10, "median": median,
                    "reports": len(rows), "files_scanned": rows[-1]["files_scanned"]}
    return out


def apply_budgets(cfg, proposed):
    """Write `proposed` into cfg's packages (budget.engine_s and expect.files_scanned); -> the ids changed."""
    changed = []
    for pkg in cfg["packages"]:
        p = proposed.get(pkg["id"])
        if p is not None:
            pkg["budget"] = {**(pkg.get("budget") or {}), "engine_s": p["engine_s"]}
            pkg["expect"] = {**(pkg.get("expect") or {}), "files_scanned": p["files_scanned"]}
            changed.append(pkg["id"])
    return changed


# ---- pinning (a maintainer's command)
def artifacts_of(resolution):
    refs = getattr(resolution, "artifacts", None)
    if refs:
        return [{"url": a["url"], "container": a["container"], "artifact": a["artifact"],
                 "filename": a.get("filename") or a["url"].rsplit("/", 1)[-1]} for a in refs]
    return [{"url": resolution[1], "container": resolution[2], "artifact": resolution[3],
             "filename": resolution[1].rsplit("/", 1)[-1]}]


def pin(specs, cfg, resolve, get, progress=None):
    """Resolve each spec, download its archives, hash them, and put the package in `cfg` (its budget and
    expectations stay when the id is already there). -> the ids pinned."""
    ids = []
    for spec in specs:
        eco, name, version = _common.split_spec(spec)
        resolution = resolve(eco, name, version)
        pid = f"{eco}:{name}@{resolution[0]}"
        files = []
        for ref in artifacts_of(resolution):
            if progress:
                progress(f"pin {pid}: {ref['filename']}")
            data = get(ref["url"])
            files.append({**ref, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        entry = {"id": pid, "ecosystem": eco, "name": name, "version": resolution[0], "files": files,
                 "budget": {"engine_s": None}}
        for k, existing in enumerate(cfg["packages"]):
            if existing["id"] == pid:
                entry["budget"], entry["expect"] = existing.get("budget") or entry["budget"], existing.get("expect")
                if entry["expect"] is None:
                    del entry["expect"]
                cfg["packages"][k] = entry
                break
        else:
            cfg["packages"].append(entry)
        ids.append(pid)
    return ids


# ---- the command line
def real_scan():
    """-> scan(data, container, artifact): the registry's scan of one archive, with a deadline."""
    from lazaret.registry import repo

    def scan(data, container, artifact):
        budget = repo.Budget(deadline=time.monotonic() + SCAN_SECONDS, deadline_detail="the check's time budget")
        return repo._scan_artifact(data, container, artifact, False, budget)
    return scan


@contextlib.contextmanager
def box_raised(repo):
    """Every run reads the same use-time files whatever the runner's speed (until P-14 bounds the step by work)."""
    if not hasattr(repo, "USE_RISK_SECONDS"):
        yield
        return
    saved, repo.USE_RISK_SECONDS = repo.USE_RISK_SECONDS, 1.0e9
    try:
        yield
    finally:
        repo.USE_RISK_SECONDS = saved


def build_parser():
    p = argparse.ArgumentParser(prog="perf_check.py", description="The scheduled performance check of the native engine.")
    p.add_argument("--packages", default=PACKAGES, help="the packages file (default: packages.json beside this script)")
    sub = p.add_subparsers(dest="command", required=True)
    cache = os.path.join(tempfile.gettempdir(), "lazaret-perf-archives")
    for name, doc in (("fetch", "download the pinned archives"), ("run", "time the engine on them")):
        s = sub.add_parser(name, help=doc)
        s.add_argument("--cache", default=cache, help=f"where the archives are kept (default {cache})")
        s.add_argument("--only", action="append", default=[], metavar="ID", help="a package id (repeatable)")
    r = sub.choices["run"]
    r.add_argument("--runs", type=int, default=DEFAULT_RUNS)
    r.add_argument("--json", metavar="PATH", help="write the report here")
    r.add_argument("--summary", metavar="PATH", help="append the table here (a job summary)")
    r.add_argument("--no-fail", action="store_true", help="exit 0 even when a package is over its budget")
    c = sub.add_parser("calibrate", help="propose budgets from the reports of several runs")
    c.add_argument("reports", nargs="+")
    c.add_argument("--margin", type=float, default=DEFAULT_MARGIN)
    c.add_argument("--write", action="store_true", help="put the budgets in the packages file")
    n = sub.add_parser("pin", help="add or move a package: resolve, download, hash")
    n.add_argument("specs", nargs="+", metavar="ecosystem:name@version")
    return p


def _say(text):
    print(text, file=sys.stderr, flush=True)


def _run(args):
    cfg = load_packages(args.packages)
    packages = select(cfg, args.only)
    if args.command == "fetch":
        try:
            fetch_all(packages, args.cache, progress=_say)
        except PinError as exc:
            _say(f"error: {exc}")
            return EXIT_FETCH
        return EXIT_OK
    if args.runs < 1:
        raise ConfigError("--runs must be at least 1")
    _common.use_source_tree()
    from lazaret.registry import repo
    from lazaret.scanner import _native, engine, timings
    if not engine.available():
        _say("error: the native engine is not built (cargo build --release in rust/)")
        return EXIT_NO_ENGINE
    try:
        fetch_all(packages, args.cache, progress=_say)
    except PinError as exc:
        _say(f"error: {exc}")
        return EXIT_FETCH
    with _common.engine_spans(_native, timings), box_raised(repo):
        report = run_check(cfg, args.cache, args.runs, real_scan(), args.only, _say)
    report["threads"] = engine.THREADS
    report["engine"] = _native.version()
    table = render_table(report)
    sys.stdout.write(table)
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(report, fh, indent=2)
            fh.write("\n")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8", newline="\n") as fh:
            fh.write("### Engine performance\n\n" + table)
    late = over_budget(report)
    if late:
        _say(f"over budget: {', '.join(late)}" + ("" if not args.no_fail else " (--no-fail)"))
    return EXIT_OVER if late and not args.no_fail else EXIT_OK


def _calibrate(args):
    reports = []
    for path in args.reports:
        with open(path, encoding="utf-8") as fh:
            reports.append(json.load(fh))
    proposed = calibrate(reports, args.margin)
    for pid, p in proposed.items():
        print(f"{pid}: median {p['median']:.2f} s over {p['reports']} report(s) -> budget {p['engine_s']:.1f} s "
              f"({p['files_scanned']} files)")
    if args.write:
        cfg = load_packages(args.packages)
        changed = apply_budgets(cfg, proposed)
        save_packages(cfg, args.packages)
        print(f"wrote {len(changed)} budget(s) to {args.packages}")
    return EXIT_OK


def _pin(args):
    _common.use_source_tree()
    from lazaret.registry import repo
    try:
        cfg = load_packages(args.packages)
    except ConfigError:
        if os.path.exists(args.packages):
            raise
        cfg = {"version": SCHEMA, "packages": []}
    try:
        ids = pin(args.specs, cfg, repo.resolve, repo.http_bytes, _say)
    except (ValueError, OSError, repo.FetchError) as exc:
        _say(f"error: {exc}")
        return EXIT_FETCH
    cfg["packages"].sort(key=lambda p: p["id"])
    save_packages(cfg, args.packages)
    print("pinned " + ", ".join(ids))
    return EXIT_OK


def main(argv=None):
    _common.configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "calibrate":
            return _calibrate(args)
        if args.command == "pin":
            return _pin(args)
        return _run(args)
    except (ConfigError, OSError, ValueError) as exc:
        _say(f"error: {exc}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
