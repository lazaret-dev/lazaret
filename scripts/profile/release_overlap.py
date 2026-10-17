#!/usr/bin/env python3
"""How much of a release is the same bytes (0.1.9, P-10; the table "How much of a release is the same bytes").

    python3 scripts/profile/release_overlap.py npm:next@16.3.8 [--cache DIR]

Reads every archive the registry scan would read for the release, hashes each member's bytes (SHA-256), and
prints how many members and bytes are unique, in all and for the text-like files, and the biggest file types.
That is what a cache keyed by content (P-2a, P-2b) can save. Standard library plus this checkout."""

import argparse
import collections
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402

TEXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".json", ".sh", ".pyi", ".txt", ".cfg", ".toml", ".yaml", ".yml", ".md"}


def overlap(members):
    """members: iterable of (path, bytes) -> (totals, by_extension): [count, bytes, unique count, unique bytes]
    for all files and for the text-like ones."""
    seen = set()
    total, text = [0, 0, 0, 0], [0, 0, 0, 0]
    by_ext = collections.defaultdict(lambda: [0, 0, 0, 0])
    for path, raw in members:
        digest = hashlib.sha256(raw).digest()
        fresh = digest not in seen
        seen.add(digest)
        ext = os.path.splitext(path)[1].lower()
        rows = [total, by_ext[ext]] + ([text] if ext in TEXT else [])
        for row in rows:
            row[0] += 1
            row[1] += len(raw)
            if fresh:
                row[2] += 1
                row[3] += len(raw)
    return {"all": total, "text": text}, dict(by_ext)


def main(argv=None):
    _common.configure_stdio()
    p = argparse.ArgumentParser(prog="release_overlap.py", description=__doc__.split("\n\n")[0])
    p.add_argument("spec", metavar="ecosystem:name[@version]")
    p.add_argument("--cache", default=None, help="replay and keep the registry's answers here")
    args = p.parse_args(argv)
    try:
        eco, name, version = _common.split_spec(args.spec)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _common.use_source_tree()
    from lazaret.registry import repo
    import contextlib
    cache = (_common.recorded_network(repo, args.cache, record=True, replay=True) if args.cache
             else contextlib.nullcontext())
    with cache:
        res = repo.resolve(eco, name, version)
        refs = getattr(res, "artifacts", None) or [{"url": res[1], "container": res[2], "artifact": res[3]}]

        def members():
            for ref in refs:
                for m in repo.iter_archive(repo.http_bytes(ref["url"]), ref["container"], ref["artifact"]):
                    if m[2] is not None:
                        yield m[0], m[2]
        totals, by_ext = overlap(members())
    print(f"{args.spec}: {len(refs)} release file(s)")
    for label, (n, b, un, ub) in totals.items():
        print(f"{label:5s} {n:7d} files {b / 1e6:9.1f} MB   unique {un:7d} files {ub / 1e6:9.1f} MB"
              f"   -> {100 * un / max(n, 1):.0f}% of files, {100 * ub / max(b, 1):.0f}% of bytes")
    for ext, (n, b, un, ub) in sorted(by_ext.items(), key=lambda kv: -kv[1][1])[:8]:
        print(f"   {ext or '(none)':8s} {n:7d} files {b / 1e6:9.1f} MB   unique {un:7d} {ub / 1e6:9.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
