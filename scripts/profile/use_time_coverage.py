#!/usr/bin/env python3
"""How much of a package the use-time step (SC-USE-RISK) reads (0.1.9, P-10; P-14's evidence).

    python3 scripts/profile/use_time_coverage.py npm:next@16.3.8 pypi:litellm@1.103.2 [--threads 1] [--one-artifact]
                                                 [--chars N] [--cache DIR]

Scans each package and prints, for the step that reads the files the entry points do not load, how many files
and characters it read of those it was given: each release file's `useTime` (P-14). The step reads at most
`repo.USE_RISK_CHARS` characters per release file, smallest files first, so every machine reads the same files;
`--chars N` changes the bound for the run. Standard library plus this checkout; needs the native engine."""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402


def main(argv=None):
    _common.configure_stdio()
    p = argparse.ArgumentParser(prog="use_time_coverage.py", description=__doc__.split("\n\n")[0])
    p.add_argument("specs", nargs="+", metavar="ecosystem:name[@version]")
    p.add_argument("--threads", type=int, help="engine threads (default: the engine's)")
    p.add_argument("--chars", type=int, help="characters the step may read per release file (default: the code's)")
    p.add_argument("--one-artifact", action="store_true", help="scan one artifact of a release")
    p.add_argument("--cache", default=None, help="replay and keep the registry's answers here")
    args = p.parse_args(argv)
    try:
        specs = [_common.split_spec(s) for s in args.specs]
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _common.use_source_tree()
    import contextlib
    from lazaret.registry import repo
    from lazaret.scanner import engine
    if not engine.available():
        print("error: the native engine is not built (cargo build --release in rust/)", file=sys.stderr)
        return 4
    if args.threads:
        engine.THREADS = args.threads
    if args.chars is not None:
        repo.USE_RISK_CHARS = args.chars
    cache = (_common.recorded_network(repo, args.cache, record=True, replay=True) if args.cache
             else contextlib.nullcontext())
    with cache:
        for eco, name, version in specs:
            started = time.perf_counter()
            kwargs = {"max_artifacts": 1} if args.one_artifact else {}
            res = repo.scan_package(eco, name, version, False, **kwargs)
            wall = time.perf_counter() - started
            label = f"{eco}:{name}" + (f"@{version}" if version else "")
            shares = [a["useTime"] for a in res.get("artifacts", ()) if a.get("useTime")]
            for u in shares:
                print(f"{label:28s} threads={engine.THREADS} wall {wall:6.1f} s  use-time step read {u['files']}/{u['ofFiles']} "
                      f"files, {u['chars'] / 1e6:.1f}/{u['ofChars'] / 1e6:.1f} M chars "
                      f"({100 * u['chars'] / max(u['ofChars'], 1):.0f}%; bound {u['boundChars'] / 1e6:.0f} M)")
            if not shares:
                print(f"{label}: the use-time step did not run (the package is SUSPICIOUS, or nothing to read)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
