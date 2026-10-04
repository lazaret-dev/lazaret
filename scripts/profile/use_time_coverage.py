#!/usr/bin/env python3
"""How much of a package the use-time step (SC-USE-RISK) reads in its 3-second box (0.1.9, P-10; P-14's evidence).

    python3 scripts/profile/use_time_coverage.py npm:next@16.3.8 pypi:litellm@1.103.2 [--threads 1] [--one-artifact]
                                                 [--cache DIR]

Scans each package and prints, for the step that reads the files the entry points do not load, how many files
and characters it read of those it was given. The step stops after `repo.USE_RISK_SECONDS` per artifact, so on a
slower machine, or with fewer engine threads, it reads less, and nothing in the report says so (P-14).
`--box SECONDS` changes the box for the run. Standard library plus this checkout; needs the native engine."""

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
    p.add_argument("--box", type=float, help="seconds the step may take per artifact (default: the code's)")
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
    if args.box is not None:
        repo.USE_RISK_SECONDS = args.box
    stats = []
    original = repo._ArtifactScan._import_time_risks

    def wrapped(self, todo, stop=None):
        if stop is None:
            yield from original(self, todo, stop)
            return
        files, chars = len(todo), sum(len(t or "") for _r, t, _l in todo)
        read = read_chars = 0
        for item in original(self, todo, stop):
            read += 1
            read_chars += len(item[1] or "")
            yield item
        stats.append((read, files, read_chars, chars))

    repo._ArtifactScan._import_time_risks = wrapped
    cache = (_common.recorded_network(repo, args.cache, record=True, replay=True) if args.cache
             else contextlib.nullcontext())
    try:
        with cache:
            for eco, name, version in specs:
                stats.clear()
                started = time.perf_counter()
                kwargs = {"max_artifacts": 1} if args.one_artifact else {}
                repo.scan_package(eco, name, version, False, **kwargs)
                wall = time.perf_counter() - started
                label = f"{eco}:{name}" + (f"@{version}" if version else "")
                for n, nf, c, tc in stats:
                    print(f"{label:28s} threads={engine.THREADS} wall {wall:6.1f} s  use-time step read {n}/{nf} files, "
                          f"{c / 1e6:.1f}/{tc / 1e6:.1f} M chars ({100 * c / max(tc, 1):.0f}%)")
                if not stats:
                    print(f"{label}: the use-time step did not run (the package is SUSPICIOUS, or nothing to read)")
    finally:
        repo._ArtifactScan._import_time_risks = original
    return 0


if __name__ == "__main__":
    sys.exit(main())
