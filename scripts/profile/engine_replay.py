#!/usr/bin/env python3
"""Replay the engine calls of a real scan, alone (0.1.9, P-10; "What is slow inside the engine").

    python3 scripts/profile/engine_replay.py hot     npm:next@16.3.8 [--cache DIR]
    python3 scripts/profile/engine_replay.py scaling pypi:litellm@1.103.2 [--cache DIR] [--batch 64]

Both record the engine calls one registry scan makes, then run them again outside the scan, so the numbers are
the engine's and nothing else's.

`hot` replays each call by itself: seconds, characters and MB/s by call name, and the twelve slowest files.
`scaling` replays one artifact's recorded batches on 1 and on 2 threads, in the archive's order and
largest first: how well the engine scales on equal work (the scan itself does not, for other reasons: P-8).
Standard library plus this checkout; needs the native engine."""

import argparse
import collections
import contextlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402


def _record(repo, native, spec, one_artifact):
    """Run the scan once with the engine's batch and scan_file calls recorded -> (batched calls by kind, scan_file items)."""
    eco, name, version = _common.split_spec(spec)
    batched, files = collections.defaultdict(list), []
    real = native.call_raw
    from lazaret.scanner import engine
    real_files = engine.scan_files

    def call_raw(call, args=None, text=""):
        if call == "batch" and isinstance(args, dict) and args.get("calls"):
            batched[args["calls"][0][0]].extend(args["calls"])
        return real(call, args, text)

    def scan_files(items):
        files.extend(items)
        return real_files(items)

    native.call_raw, engine.scan_files = call_raw, scan_files
    try:
        kwargs = {"max_artifacts": 1} if one_artifact else {}
        repo.scan_package(eco, name, version, False, **kwargs)
    finally:
        native.call_raw, engine.scan_files = real, real_files
    return batched, files


def replay_hot(native, batched, files):
    from lazaret.scanner import engine
    rows = []
    for kind, calls in batched.items():
        for call in calls:
            started = time.perf_counter()
            with contextlib.suppress(Exception):
                native.call(call[0], call[1], call[2])
            rows.append((time.perf_counter() - started, kind, len(call[2]), json.dumps(call[1])[:90]))
    for path, content, lang, dep in files:
        started = time.perf_counter()
        with contextlib.suppress(Exception):
            engine.scan_files([(path, content, lang, dep)])
        rows.append((time.perf_counter() - started, "scan_file*", len(content), path[-60:]))
    return rows


def replay_scaling(native, calls, threads, largest_first, batch):
    items = sorted(calls, key=lambda c: -len(c[2])) if largest_first else list(calls)
    best = float("inf")
    for _ in range(2):
        started = time.perf_counter()
        for i in range(0, len(items), batch):
            native.call("batch", {"calls": items[i:i + batch], "threads": threads})
        best = min(best, time.perf_counter() - started)
    return best


def main(argv=None):
    _common.configure_stdio()
    p = argparse.ArgumentParser(prog="engine_replay.py", description=__doc__.split("\n\n")[0])
    p.add_argument("mode", choices=("hot", "scaling"))
    p.add_argument("spec", metavar="ecosystem:name[@version]")
    p.add_argument("--cache", default=None, help="replay and keep the registry's answers here")
    p.add_argument("--batch", type=int, default=64, help="items per call when replaying batches (scaling)")
    args = p.parse_args(argv)
    try:
        _common.split_spec(args.spec)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _common.use_source_tree()
    from lazaret.registry import repo
    from lazaret.scanner import _native, engine
    if not engine.available():
        print("error: the native engine is not built (cargo build --release in rust/)", file=sys.stderr)
        return 4
    cache = (_common.recorded_network(repo, args.cache, record=True, replay=True) if args.cache
             else contextlib.nullcontext())
    with cache:
        batched, files = _record(repo, _native, args.spec, one_artifact=args.mode == "scaling")
    if args.mode == "scaling":
        for kind, calls in batched.items():
            print(f"{kind}: {len(calls)} items, {sum(len(c[2]) for c in calls) / 1e6:.1f} M chars")
            for label, largest in (("archive", False), ("largest", True)):
                one = replay_scaling(_native, calls, 1, largest, args.batch)
                two = replay_scaling(_native, calls, 2, largest, args.batch)
                print(f"   {label:8s}: 1 thread {one:6.2f} s  2 threads {two:6.2f} s  -> {one / two:.2f}x")
        return 0
    rows = replay_hot(_native, batched, files)
    print(f"{args.spec}: {len(rows)} calls, {sum(r[0] for r in rows):.2f} s alone, {sum(r[2] for r in rows) / 1e6:.1f} MB")
    by = collections.defaultdict(lambda: [0, 0.0, 0])
    for seconds, kind, chars, _ in rows:
        entry = by[kind]
        entry[0] += 1
        entry[1] += seconds
        entry[2] += chars
    for kind, (n, seconds, chars) in by.items():
        print(f"  {kind:18s} {n:6d} calls {seconds:8.2f} s {chars / 1e6:8.1f} MB  {chars / 1e6 / max(seconds, 1e-9):7.1f} MB/s")
    print("slowest:")
    for seconds, kind, chars, what in sorted(rows, reverse=True)[:12]:
        print(f"  {seconds:7.3f} s {kind:16s} {chars / 1e3:9.0f} KB {chars / 1e6 / max(seconds, 1e-9):6.1f} MB/s  {what}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
