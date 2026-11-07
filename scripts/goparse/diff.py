#!/usr/bin/env python3
"""Compare Lazaret's Go parser with go/parser, file by file.

    diff.py ORACLE_OUTPUT MINE_OUTPUT [--show N] [--root DIR]

Both files are in the format of `scripts/goparse/astdump.go` (`== path`, then `Kind start end` per node, or `!! message`
for a file that does not parse): the first from the oracle, the second from `cargo run --release --example goparse_dump`.
Per file the two must agree on whether it parses and, when it does, on every node: its kind and its span, in the order
`ast.Inspect` visits them. The summary says how many files fell in each case; the exit status is 1 when any file
disagrees. Standard library only."""
import argparse
import sys


def read(path):
    out, name, lines = {}, None, []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            if raw.startswith("== "):
                if name is not None:
                    out[name] = lines
                name, lines = raw[3:], []
            else:
                lines.append(raw)
    if name is not None:
        out[name] = lines
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("oracle")
    ap.add_argument("mine")
    ap.add_argument("--show", type=int, default=10, help="how many disagreeing files to describe")
    args = ap.parse_args(argv)
    a, b = read(args.oracle), read(args.mine)
    counts = {"same tree": 0, "both refuse": 0, "only go/parser refuses": 0, "only Lazaret refuses": 0,
              "different trees": 0, "missing from one side": 0, "too deep for Lazaret (a limit, not a difference)": 0}
    shown = []
    for name in sorted(set(a) | set(b)):
        if name not in a or name not in b:
            counts["missing from one side"] += 1
            shown.append((name, "missing from %s" % ("the oracle" if name not in a else "Lazaret's output")))
            continue
        x, y = a[name], b[name]
        xr, yr = bool(x) and x[0].startswith("!!"), bool(y) and y[0].startswith("!!")
        if xr and yr:
            counts["both refuse"] += 1
        elif xr:
            counts["only go/parser refuses"] += 1
            shown.append((name, "go/parser: %s; Lazaret accepts" % x[0]))
        elif yr and "exceeded max nesting depth" in y[0]:
            counts["too deep for Lazaret (a limit, not a difference)"] += 1
        elif yr:
            counts["only Lazaret refuses"] += 1
            shown.append((name, "Lazaret: %s; go/parser accepts" % y[0]))
        elif x == y:
            counts["same tree"] += 1
        else:
            counts["different trees"] += 1
            i = next((k for k in range(min(len(x), len(y))) if x[k] != y[k]), min(len(x), len(y)))
            shown.append((name, "node %d: go/parser %r, Lazaret %r (%d and %d nodes)" % (
                i, x[i] if i < len(x) else None, y[i] if i < len(y) else None, len(x), len(y))))
    for k, v in counts.items():
        print("%8d  %s" % (v, k))
    for name, why in shown[:args.show]:
        print("  %s: %s" % (name, why))
    if len(shown) > args.show:
        print("  … and %d more" % (len(shown) - args.show))
    return 1 if shown else 0


if __name__ == "__main__":
    sys.exit(main())
