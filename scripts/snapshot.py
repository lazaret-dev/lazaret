#!/usr/bin/env python3
"""Record the engine's outputs, and show how two recordings differ.

Since the Rust-first refactor the engine is held to its own recorded
outputs (tests/architecture/_snapshots.py), not to a second engine. This
script is how a change in those outputs is reviewed:

    scripts/snapshot.py record SET --out before.jsonl.gz      # the engine before
    ... change the engine, rebuild ...
    scripts/snapshot.py record SET --out after.jsonl.gz       # and after
    scripts/snapshot.py diff before.jsonl.gz after.jsonl.gz   # every case that moved

SET is a snapshot test's input set (`scripts/snapshot.py sets` lists them),
or `files:LIST`, a file naming one source file per line: each file's
dependency-mode scan_file, import-time test, spawned scripts, string-array
line, data flow and decoded view (by hash). The library is the one
LAZARET_NATIVE_LIB names, else the installed package's. Recordings hold the
inputs' first characters, so keep those of malicious corpora outside the
repository.
"""
import argparse
import gzip
import hashlib
import importlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [os.path.join(ROOT, "python", "src"), os.path.join(ROOT, "python")]

from lazaret.scanner import _native  # noqa: E402

# the snapshot tests' input sets: name -> module (its snapshot_sets() gives {name: calls})
MODULES = ("tests.architecture.test_snapshot_hooks", "tests.architecture.test_snapshot_signs",
           "tests.architecture.test_snapshot_scanfile", "tests.architecture.test_snapshot_lexer",
           "tests.architecture.test_snapshot_hook_commands", "tests.architecture.test_snapshot_small",
           "tests.architecture.test_snapshot_crossfile")
EXCERPT = 300                    # characters of each input a recording keeps
LANGS = {".py": "py", ".pyw": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js",
         ".tsx": "js", ".mts": "js", ".cts": "js"}


def sets():
    """{name: a function giving the set's calls}."""
    out = {}
    for name in MODULES:
        module = importlib.import_module(name)
        for key, make in module.snapshot_sets().items():
            out[key] = make
    return out


def file_calls(list_path):
    """The calls a list of source files gets (see the module's docstring)."""
    calls = []
    with open(list_path, encoding="utf-8") as f:
        paths = [line.rstrip("\n") for line in f if line.strip()]
    for path in paths:
        lang = LANGS.get(os.path.splitext(path)[1].lower())
        if lang is None:
            continue
        try:
            with open(path, "rb") as f:
                text = f.read().decode("utf-8", errors="replace")
        except OSError:
            continue
        jsx = path.endswith((".jsx", ".tsx", ".js", ".mjs", ".cjs"))
        scan = {"lang": lang, "jsx": jsx, "dep": True, "redact": True, "neumaier": sys.version_info >= (3, 12)}
        for call, args in (("scan_file", scan), ("import_time_risk", {"lang": lang}), ("spawned_scripts", {}),
                           ("string_array_line", {}), ("local_data_sent_at", {}), ("decoded_view", {})):
            calls.append((call, args, text, path))
    return calls


def run(calls):
    out = []
    for i in range(0, len(calls), 500):
        part = calls[i:i + 500]
        out.extend(_native.call("batch", {"calls": [[c[0], c[1], c[2]] for c in part], "threads": 2}))
    return out


def record(set_name, out_path):
    if set_name.startswith("files:"):
        calls = file_calls(set_name[len("files:"):])
    else:
        found = sets()
        if set_name not in found:
            sys.exit(f"no set {set_name!r} (scripts/snapshot.py sets)")
        calls = [(c, a, t, None) for c, a, t in found[set_name]()]
    answers = run(calls)
    with gzip.open(out_path, "wt", encoding="utf-8") as f:
        for k, ((call, args, text, label), answer) in enumerate(zip(calls, answers)):
            if call == "decoded_view" and isinstance(answer, dict) and isinstance(answer.get("ok"), str):
                answer = {"ok": "sha256:" + hashlib.sha256(answer["ok"].encode("utf-8", "surrogatepass")).hexdigest()}
            row = {"k": k, "call": call, "args": args, "input": label or text[:EXCERPT],
                   "sha": hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16], "out": answer}
            f.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"{out_path}: {len(calls)} outputs")


def load(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


def clip(value, width=400):
    text = json.dumps(value, sort_keys=True)
    return text if len(text) <= width else text[:width] + " …"


def diff(a_path, b_path, show):
    a, b = load(a_path), load(b_path)
    if len(a) != len(b) or any(x["sha"] != y["sha"] or x["call"] != y["call"] for x, y in zip(a, b)):
        sys.exit("the recordings are not of the same inputs")
    moved = [(x, y) for x, y in zip(a, b) if x["out"] != y["out"]]
    by_call = {}
    for x, _y in moved:
        by_call[x["call"]] = by_call.get(x["call"], 0) + 1
    print(f"{len(moved)} of {len(a)} outputs differ" + (": " + ", ".join(f"{c} {n}" for c, n in sorted(by_call.items()))
                                                      if moved else ""))
    for x, y in moved[:show]:
        print(f"\n#{x['k']} {x['call']} {json.dumps(x['args'], sort_keys=True)}\n  input:  {clip(x['input'], 300)}"
              f"\n  before: {clip(x['out'])}\n  after:  {clip(y['out'])}")


def _configure_stdio():
    """Redirected output is UTF-8 unless PYTHONIOENCODING says otherwise, and
    never raises on a character the stream can't encode (STRUCTURE.md,
    "Cross-platform rules")."""
    explicit = bool(os.environ.get("PYTHONIOENCODING"))
    for stream in (sys.stdout, sys.stderr):
        try:
            encoding = (getattr(stream, "encoding", None) or "").lower().replace("_", "-")
            if not explicit and not stream.isatty() and encoding not in ("utf-8", "utf8"):
                stream.reconfigure(encoding="utf-8", errors="replace")
            else:
                stream.reconfigure(errors="replace")
        except (AttributeError, OSError, ValueError):
            pass


def main(argv=None):
    _configure_stdio()
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("sets", help="list the snapshot tests' input sets")
    r = sub.add_parser("record", help="record a set's outputs")
    r.add_argument("set")
    r.add_argument("--out", required=True)
    d = sub.add_parser("diff", help="show the outputs two recordings differ in")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--show", type=int, default=20, help="cases shown (default 20)")
    args = ap.parse_args(argv)
    if args.cmd == "sets":
        for name, make in sorted(sets().items()):
            print(f"{name}\t{len(make())} calls")
    elif args.cmd == "record":
        if not _native.available():
            sys.exit(f"the native engine is not available ({_native.load_error()})")
        record(args.set, args.out)
    else:
        diff(args.before, args.after, args.show)


if __name__ == "__main__":
    main()
