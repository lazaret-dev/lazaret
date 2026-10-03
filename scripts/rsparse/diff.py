#!/usr/bin/env python3
"""diff.py [--bin PATH] [--jobs N] [--show N] [--list FILE | DIR…]: the item reader against `rustc`, file by file.

For every `.rs` file under the directories (or listed one per line in FILE), `rustc_items.py` gives the items `rustc`
finds (its parser's tree, before macro expansion), `examples/rsparse_dump.rs` the items this crate finds, and the two
are compared: which items are in one and not the other (kind, name, start, end), and for those in both their
visibility, qualifiers, ABI, attributes, parent and the paths of their `use` leaves. A file `rustc` refuses is not
compared (it is counted: the item reader is for what compiles). Exit status 1 if any file differs.

    cargo build --release --example rsparse_dump
    python3 scripts/rsparse/diff.py --bin target/release/examples/rsparse_dump ~/corpus
"""

import argparse
import collections
import concurrent.futures
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rustc_items  # noqa: E402

ORDER = "ucadetsmn"


_ESCAPE = re.compile(r"\\(?:\r?\n\s*|u\{([0-9a-fA-F_]{1,6})\}|x([0-7][0-9a-fA-F])|(.))", re.S)
_SIMPLE = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'"}


def unescape(text):
    """The string a Rust string literal's text (quotes off) holds: `\\n`, `\\x7f`, `\\u{7f}`, a backslash and a line break."""
    def one(m):
        try:
            if m.group(1):
                return chr(int(m.group(1).replace("_", ""), 16))
            if m.group(2):
                return chr(int(m.group(2), 16))
        except (ValueError, OverflowError):
            return m.group(0)
        c = m.group(3)
        return "" if c is None else _SIMPLE.get(c, m.group(0))
    return _ESCAPE.sub(one, text)


def unpercent(text):
    """`text` with each `%XX` read as a byte of UTF-8 (a `%` not followed by two hex digits stays as it is)."""
    raw = re.sub(rb"%([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), text.encode("utf-8"))
    return raw.decode("utf-8", "replace")


def norm_abi(a, rustc=False):
    """The ABI as the string it holds (`-` for none). Ours is the literal as written in the source, quotes and all, with a space,
    a control character and `%` written `%XX` (`rsparse/out.rs`); rustc's is its `symbol`, the string in `Debug` form, written the same
    way (`rustc_items.word`)."""
    if a == "-":
        return a
    a = unpercent(a)
    body = re.sub(r'^r?#*"|"#*$', "", a)
    return body if not rustc and re.match(r'r#*"', a) else unescape(body)


def edition_for(path):
    d = os.path.dirname(os.path.abspath(path))
    while True:
        cargo = os.path.join(d, "Cargo.toml")
        if os.path.exists(cargo):
            try:
                with open(cargo, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                text = ""
            m = re.search(r'^edition\s*=\s*"(\d+)"', text, re.M)
            if m:
                return m.group(1)
            # a manifest with no edition is Cargo's 2015; one that takes its edition from the workspace is read as 2021
            return "2021" if re.search(r'^edition\.workspace\s*=\s*true', text, re.M) else "2015"
        parent = os.path.dirname(d)
        if parent == d:
            return "2021"
        d = parent


def find_files(dirs):
    out = []
    for d in dirs:
        if os.path.isfile(d):
            out.append(d)
            continue
        for root, subdirs, files in os.walk(d):
            subdirs[:] = [s for s in subdirs if s not in ("target", ".git")]
            out += [os.path.join(root, f) for f in files if f.endswith(".rs")]
    return sorted(out)


def mine(binary, files):
    """path -> list of lines (or ['!! …'])."""
    p = subprocess.run([binary], input="\n".join(files).encode(), capture_output=True, timeout=3600)
    got, cur = {}, None
    for line in p.stdout.decode("utf-8", "replace").split("\n"):
        if line.startswith("== "):
            cur = line[3:]
            got[cur] = []
        elif line and cur is not None:
            got[cur].append(line)
    return got


def theirs(path):
    return path, rustc_items.items_for_file(path, edition_for(path))


def parse_lines(lines, rustc=False):
    items, uses, crate, problems = [], [], None, 0
    for l in lines:
        if l.startswith("item "):
            f = l.split(" ")
            _, n, kind, name, start, end, vis, parent, flags, abi, attrs, inner = f[:12]
            items.append(dict(n=int(n), kind=kind, name=name, start=int(start), end=int(end), vis=vis, parent=None if parent == "-" else int(parent),
                              flags="".join(sorted(flags.replace("-", ""), key=ORDER.index)), abi=norm_abi(abi, rustc), attrs=attrs, inner=inner))
        elif l.startswith("use "):
            _, n, rest = l.split(" ", 2)
            uses.append((int(n), rest))
        elif l.startswith("crate "):
            crate = l[6:]
        elif l.startswith("problems "):
            problems = int(l.split()[1])
    return items, uses, crate, problems


def compare(a_lines, b_lines):
    """a = rustc, b = ours -> list of difference strings."""
    ai, au, ac, _ = parse_lines(a_lines, rustc=True)
    bi, bu, bc, bp = parse_lines(b_lines)
    diffs = []
    key = lambda it: (it["kind"], it["start"], it["end"])
    akeys = collections.defaultdict(list)
    bkeys = collections.defaultdict(list)
    for it in ai:
        akeys[key(it)].append(it)
    for it in bi:
        bkeys[key(it)].append(it)
    for k, v in akeys.items():
        if k not in bkeys:
            diffs.append(f"missing {k[0]} {v[0]['name']} {k[1]}-{k[2]}")
    for k, v in bkeys.items():
        if k not in akeys:
            diffs.append(f"extra {k[0]} {v[0]['name']} {k[1]}-{k[2]}")
    # an item in both: the rest of its fields, and its parent (by position)
    amap = {key(it): it for it in ai}
    bmap = {key(it): it for it in bi}
    for k in amap.keys() & bmap.keys():
        x, y = amap[k], bmap[k]
        for field in ("name", "vis", "flags", "abi", "attrs", "inner"):
            if x[field] != y[field]:
                diffs.append(f"{k[0]} {x['name']} {k[1]}-{k[2]}: {field}: rustc {x[field]!r}, ours {y[field]!r}")
        px = key(ai[x["parent"]]) if x["parent"] is not None else None
        py = key(bi[y["parent"]]) if y["parent"] is not None else None
        if px != py:
            diffs.append(f"{k[0]} {x['name']} {k[1]}-{k[2]}: parent: rustc {px}, ours {py}")
    # order of items
    if not diffs and [key(i) for i in ai] != [key(i) for i in bi]:
        diffs.append("items are the same but not in the same order")
    # uses, by the item that holds them (its position)
    def by_item(items, uses):
        out = collections.defaultdict(list)
        for n, rest in uses:
            out[key(items[n])].append(rest)
        return out
    ua, ub = by_item(ai, au), by_item(bi, bu)
    for k in set(ua) | set(ub):
        if ua.get(k) != ub.get(k):
            diffs.append(f"use {k[1]}-{k[2]}: rustc {ua.get(k)}, ours {ub.get(k)}")
    if (ac or None) != (bc or None):
        diffs.append(f"crate attributes: rustc {ac!r}, ours {bc!r}")
    if bp and not diffs:
        diffs.append(f"ours reports {bp} problems in a file rustc accepts")
    return diffs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="*")
    ap.add_argument("--bin", default="target/release/examples/rsparse_dump")
    ap.add_argument("--jobs", type=int, default=4)
    ap.add_argument("--show", type=int, default=20)
    ap.add_argument("--list")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--refused", action="store_true", help="name the files rustc refused (or the reader could not read)")
    args = ap.parse_args()
    files = [l.rstrip("\n") for l in open(args.list)] if args.list else find_files(args.dirs)
    ours = mine(args.bin, files)
    stats = collections.Counter()
    shown = 0
    refused = collections.Counter()
    with concurrent.futures.ProcessPoolExecutor(args.jobs) as pool:
        for path, (lines, err) in pool.map(theirs, files, chunksize=4):
            stats["files"] += 1
            if err:
                stats["refused"] += 1
                refused[err[:60]] += 1
                if args.refused:
                    print(f"refused {path}: {err[:200]}")
                continue
            stats["items"] += sum(1 for l in lines if l.startswith("item "))
            d = compare(lines, ours.get(path, []))
            if d:
                stats["differ"] += 1
                if shown < args.show:
                    shown += 1
                    print(f"--- {path}")
                    for x in d[:12]:
                        print("   ", x)
                    if len(d) > 12:
                        print(f"    … {len(d) - 12} more")
            else:
                stats["same"] += 1
    print(dict(stats))
    if refused and not args.quiet:
        for e, c in refused.most_common(8):
            print(f"  rustc refused {c}: {e}")
    sys.exit(1 if stats["differ"] else 0)


if __name__ == "__main__":
    main()
