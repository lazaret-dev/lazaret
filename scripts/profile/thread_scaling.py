#!/usr/bin/env python3
"""A whole scan on 1, 2, ... engine threads (0.1.9, P-10; the check behind "poor scaling" in the profile).

    python3 scripts/profile/thread_scaling.py npm:next@16.3.8 1 2 [--box SECONDS] [--cache DIR]

Wall seconds of one scan per thread count, with the engine's seconds by call name. **Mind the 3-second box**:
the use-time step stops after `repo.USE_RISK_SECONDS`, so scans on different thread counts may do different work,
and the comparison is of work as much as of speed; `--box 1000000` takes the box out of it (P-14 makes this
unnecessary). For equal work, `engine_replay.py scaling` replays recorded batches. Needs the native engine."""

import argparse
import collections
import contextlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402


def main(argv=None):
    _common.configure_stdio()
    p = argparse.ArgumentParser(prog="thread_scaling.py", description=__doc__.split("\n\n")[0])
    p.add_argument("spec", metavar="ecosystem:name[@version]")
    p.add_argument("threads", nargs="+", type=int)
    p.add_argument("--box", type=float, help="seconds the use-time step may take per artifact")
    p.add_argument("--cache", default=None, help="replay and keep the registry's answers here")
    args = p.parse_args(argv)
    try:
        eco, name, version = _common.split_spec(args.spec)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _common.use_source_tree()
    from lazaret.registry import repo
    from lazaret.scanner import _native, engine, timings
    if not engine.available():
        print("error: the native engine is not built (cargo build --release in rust/)", file=sys.stderr)
        return 4
    if args.box is not None:
        repo.USE_RISK_SECONDS = args.box
    cache = (_common.recorded_network(repo, args.cache, record=True, replay=True) if args.cache
             else contextlib.nullcontext())
    with cache, _common.engine_spans(_native, timings):
        for count in args.threads:
            engine.THREADS = count
            t = timings.Timings()
            started = time.perf_counter()
            with timings.capture(t):
                repo.scan_package(eco, name, version, False)
            wall = time.perf_counter() - started
            by = collections.OrderedDict(sorted(t.report()["phases"].get("engine", {}).get("by", {}).items(),
                                                key=lambda kv: -kv[1]["seconds"]))
            print(f"THREADS={count}: wall {wall:6.2f} s  " + "  ".join(f"{k}={v['seconds']:.2f}" for k, v in by.items()),
                  flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
