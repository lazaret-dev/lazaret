#!/usr/bin/env python3
"""Where one registry scan spends its time (0.1.9, P-10; the harness behind audits/lazaret-profile-and-backlog).

    python3 scripts/profile/registry_scan.py npm:next@16.3.8 pypi:requests --mode cold --cache DIR
    python3 scripts/profile/registry_scan.py npm:next@16.3.8 --mode warm --cache DIR --reps 3 --json out.jsonl

Runs `repo.scan_package` for each spec and prints the split by phase, from `lazaret.scanner.timings`:
`network` (the registry fetches), `digest`, `archive` (reading the archive's members), `engine` (the native
calls, by name), `redact`, `resolve`, and `other`, the Python that is left. A **cold** run asks the network and
keeps the answers in `--cache`; a **warm** run replays them, so the network is out of the numbers. Each run
is one JSON line with `--json` (the report of `timings` and the scan's counts). A cold run is real network: use it
from a machine whose network you want to know about. Standard library plus this checkout; needs the native
engine (cargo build --release in rust/)."""

import argparse
import contextlib
import json
import os
import resource
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402


@contextlib.contextmanager
def instrumented(repo, core, timings):
    """Put the phases' spans around the functions that do that phase's work; restore them after. The registry
    times its own network and archive reading since P-4 (`repo._fetch`, `repo.iter_archive`); those are wrapped
    only where it does not."""
    saved = {}

    def wrap(owner, attr, phase, name=None):
        real = getattr(owner, attr)
        saved[(owner, attr)] = real

        def inner(*a, **k):
            with timings.span(phase, name or attr):
                return real(*a, **k)
        setattr(owner, attr, inner)

    if getattr(repo, "_timed_members", None) is None:
        real_iter = repo.iter_archive
        saved[(repo, "iter_archive")] = real_iter

        def iter_archive(*a, **k):
            gen = real_iter(*a, **k)
            while True:
                with timings.span("archive", "iter_archive"):
                    try:
                        member = next(gen)
                    except StopIteration:
                        return
                yield member

        wrap(repo, "_fetch", "network", "fetch")
        repo.iter_archive = iter_archive
    wrap(repo, "verify_digest", "digest")
    wrap(repo, "resolve", "resolve")
    if hasattr(repo, "new_dependency_issues"):
        wrap(repo, "new_dependency_issues", "new dependency")
    if hasattr(core, "redact_result"):
        wrap(core, "redact_result", "redact")
    try:
        yield
    finally:
        for (owner, attr), real in saved.items():
            setattr(owner, attr, real)


def build_parser():
    p = argparse.ArgumentParser(prog="registry_scan.py", description=__doc__.split("\n\n")[0])
    p.add_argument("specs", nargs="+", metavar="ecosystem:name[@version]")
    p.add_argument("--mode", choices=("cold", "warm"), default="cold")
    p.add_argument("--cache", default=os.path.join(tempfile.gettempdir(), "lazaret-profile-cache"))
    p.add_argument("--reps", type=int, default=1)
    p.add_argument("--json", metavar="PATH", help="append one JSON line per run")
    return p


def main(argv=None):
    _common.configure_stdio()
    args = build_parser().parse_args(argv)
    try:
        specs = [_common.split_spec(s) for s in args.specs]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _common.use_source_tree()
    from lazaret.registry import repo
    from lazaret.scanner import _native, engine, timings
    from lazaret.scanner import core
    if not engine.available():
        print("error: the native engine is not built (cargo build --release in rust/)", file=sys.stderr)
        return 4
    cold = args.mode == "cold"
    with _common.recorded_network(repo, args.cache, record=cold, replay=not cold), \
            _common.engine_spans(_native, timings), instrumented(repo, core, timings):
        for eco, name, version in specs:
            for rep in range(args.reps):
                t = timings.Timings()
                row = {"pkg": f"{eco}:{name}" + (f"@{version}" if version else ""), "mode": args.mode, "rep": rep}
                try:
                    with timings.capture(t), t.run():
                        res = repo.scan_package(eco, name, version, False)
                    row.update(version=res["version"], verdict=res["verdict"], filesScanned=res["filesScanned"],
                               archiveBytes=res["archiveBytes"], issues=len(res["issues"]))
                except Exception as exc:                        # noqa: BLE001 - a profile goes on to the next package
                    row["error"] = f"{type(exc).__name__}: {exc}"
                row["maxrss_mb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
                row["timings"] = t.report()
                print(f"{row['pkg']} ({args.mode}, run {rep + 1}/{args.reps})" + (f": {row['error']}" if "error" in row else ""))
                print("\n".join(timings.render(row["timings"])))
                if args.json:
                    with open(args.json, "a", encoding="utf-8", newline="\n") as fh:
                        fh.write(json.dumps(row) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
