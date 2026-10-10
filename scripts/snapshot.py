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
dependency-mode scan_file, project-mode scan_file, import-time test, spawned
scripts, string-array line, data flow and decoded view (by hash); for a Go or
Rust file, its dependency-mode scan_file and project mode's scan_rules. A parser's answer (js_parse,
py_parse) is recorded as its JSON text, and a difference in it is shown
where the two texts part. The library is the one LAZARET_NATIVE_LIB names,
else the installed package's. Recordings hold the inputs' first characters,
so keep those of malicious corpora outside the repository.
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
           "tests.architecture.test_snapshot_crossfile", "tests.architecture.test_snapshot_js_flow",
           "tests.architecture.test_snapshot_js_parse", "tests.architecture.test_snapshot_py_flow",
           "tests.architecture.test_snapshot_project")
# calls answering a parsed tree, which may be deeper than json.loads reads:
# recorded as the answer's JSON text ({"ok_text": …})
RAW_CALLS = ("js_parse", "js_parse_file", "py_parse")
EXCERPT = 300                    # characters of each input a recording keeps
LANGS = {".py": "py", ".pyw": "py", ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js",
         ".tsx": "js", ".mts": "js", ".cts": "js", ".go": "go", ".rs": "rs"}


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
        if lang in ("go", "rs"):             # (a project's Go and Rust files: their rules and families only)
            rules = {"lang": lang, "jsx": False, "redact": True, "neumaier": False}
            calls += [("scan_file", scan, text, path), ("scan_rules", rules, text, path)]
            continue
        project = dict(scan, dep=False, jsx=not path.lower().endswith((".ts", ".mts", ".cts")))
        for call, args in (("scan_file", scan), ("scan_file", project), ("import_time_risk", {"lang": lang}),
                           ("spawned_scripts", {}), ("string_array_line", {}), ("local_data_sent_at", {}),
                           ("decoded_view", {})):
            calls.append((call, args, text, path))
    return calls


def run(calls):
    out = [None] * len(calls)
    plain = [k for k, c in enumerate(calls) if c[0] not in RAW_CALLS]
    for i in range(0, len(plain), 500):
        part = plain[i:i + 500]
        batch = [[calls[k][0], calls[k][1], calls[k][2]] for k in part]
        answers = _native.call("batch", {"calls": batch, "threads": 2})
        for k, answer in zip(part, answers):
            out[k] = answer
    for k, c in enumerate(calls):
        if c[0] in RAW_CALLS:
            status, text = _native.call_raw(c[0], c[1], c[2])
            out[k] = {"ok_text": text} if status == _native.STATUS_OK else {"error": text}
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


def clip_pair(a, b, width=400):
    """The two outputs, each clipped; two JSON texts (RAW_CALLS) around where they part."""
    if isinstance(a, dict) and isinstance(b, dict) and "ok_text" in a and "ok_text" in b:
        x, y = a["ok_text"], b["ok_text"]
        i = next((k for k, (p, q) in enumerate(zip(x, y)) if p != q), min(len(x), len(y)))
        lo = max(0, i - width // 3)
        return tuple(("… " if lo else "") + t[lo:lo + width] + (" …" if lo + width < len(t) else "")
                     for t in (x, y))
    return clip(a, width), clip(b, width)


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
        before, after = clip_pair(x["out"], y["out"])
        print(f"\n#{x['k']} {x['call']} {clip(x['args'], 300)}\n  input:  {clip(x['input'], 300)}"
              f"\n  before: {before}\n  after:  {after}")


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
