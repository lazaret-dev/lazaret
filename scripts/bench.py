#!/usr/bin/env python3
"""Lazaret's benchmark harness: registry scans of a labelled set of
releases, and the comparison of two runs.

    python3 scripts/bench.py run MANIFEST OUT.jsonl [--deadline S] [--stop-after S]
    python3 scripts/bench.py compare BEFORE.jsonl AFTER.jsonl [--aggregate-only] [--show N]
    python3 scripts/bench.py summary RUN.jsonl

MANIFEST is JSON lines, one release each: "id"; "artifact_path", the
release file as the registry serves it; "container" (tgz, zip) and "kind"
(npm, sdist, wheel); and "cat", the release's category, where "benign"
marks a package that should pass and anything else a malicious release.
(lz_path, lz_container and lz_kind are read too: the names the corpus
preparation writes.)

`run` scans each release as `lazaret-registry` does (in memory: nothing
in it is unpacked to disk or run), on the engine the package loads
(LAZARET_NATIVE_LIB, or an installed wheel's), each with its own
deadline, and writes one line per release: its id and category, the
verdict, every strong (CRITICAL or BLOCKER) supply-chain finding (rule,
severity, message) and the rules of the MAJOR ones. It appends and skips
the releases OUT holds already, and starts no release after --stop-after
seconds (exit 3), so a caller can loop it under a short timeout until it
prints DONE; a release the caller's timeout kills twice is recorded as a
harness timeout and not retried (OUT.attempts counts the tries).

`compare` reads two runs of the same releases: the verdicts by category in
each, and the releases whose verdict or strong findings differ. With
--aggregate-only it prints counts and nothing that names a release: use it
for a holdout set, whose releases are looked at only in aggregate, so that
no detector is written from them. `summary` prints one run's verdicts by
category.

What a change to detection is checked with (docs/TESTING.md): a run before
it and a run after it, on the benchmark (compare, every difference read)
and on the holdout (compare --aggregate-only).
"""
import argparse
import collections
import json
import os
import pathlib
import sys
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "python" / "src"))

STRONG = ("CRITICAL", "BLOCKER")
VERDICTS = ("SUSPICIOUS", "WARN", "INCOMPLETE", "OK")


def _field(rec, name, alias):
    value = rec.get(name, rec.get(alias))
    if value is None:
        raise ValueError(f"release {rec.get('id')!r} has no {name!r}")
    return value


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def scan_one(rec, deadline_s):
    """The run's line for one release of the manifest."""
    from lazaret.registry import repo
    row = {"id": rec["id"], "cat": rec.get("cat", "")}
    with open(_field(rec, "artifact_path", "lz_path"), "rb") as f:
        data = f.read()
    budget = repo.Budget(deadline=time.monotonic() + min(repo.SCAN_TIMEOUT, deadline_s), deadline_detail="budget")
    res = repo._scan_artifact(data, _field(rec, "container", "lz_container"), _field(rec, "kind", "lz_kind"),
                              False, budget)
    row["verdict"] = res["verdict"]
    row["strong"] = [[i["rule"], i["sev"], i["msg"][:700]] for i in res["issues"]
                     if i["rule"].startswith("SC-") and i["sev"] in STRONG]
    row["weak"] = sorted({i["rule"] for i in res["issues"] if i["rule"].startswith("SC-") and i["sev"] == "MAJOR"})
    return row


def run(manifest, out_path, deadline_s, stop_after):
    from lazaret.scanner import engine
    try:
        engine.require()
    except engine.EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    releases = read_jsonl(manifest)
    out_path = pathlib.Path(out_path)
    done = {r["id"] for r in read_jsonl(out_path)} if out_path.exists() else set()
    attempts_path = out_path.with_name(out_path.name + ".attempts")
    tries = json.loads(attempts_path.read_text(encoding="utf-8")) if attempts_path.exists() else {}
    started = time.monotonic()
    with open(out_path, "a", encoding="utf-8") as out:
        for rec in releases:
            if rec["id"] in done:
                continue
            if time.monotonic() - started > stop_after:
                print(f"PARTIAL {len(done)} of {len(releases)}", flush=True)
                return 3
            tries[rec["id"]] = tries.get(rec["id"], 0) + 1
            attempts_path.write_text(json.dumps(tries), encoding="utf-8")
            if tries[rec["id"]] > 2:            # killed by the caller's timeout twice
                row = {"id": rec["id"], "cat": rec.get("cat", ""), "error": "harness timeout"}
            else:
                try:
                    row = scan_one(rec, deadline_s)
                except Exception as exc:         # noqa: BLE001 -- recorded, the run goes on
                    row = {"id": rec["id"], "cat": rec.get("cat", ""), "error": f"{type(exc).__name__}: {exc}"[:300]}
            out.write(json.dumps(row) + "\n")
            out.flush()
            done.add(rec["id"])
    print(f"DONE {len(done)}", flush=True)
    return 0


def _group(cat):
    return "benign" if cat == "benign" else "malicious"


def verdict_table(rows):
    """{'benign'|'malicious': Counter of verdicts (and 'error')}."""
    table = collections.defaultdict(collections.Counter)
    for r in rows:
        table[_group(r.get("cat"))][r.get("verdict", "error")] += 1
    return table


def _print_table(title, rows):
    print(title)
    for group, counts in sorted(verdict_table(rows).items()):
        total = sum(counts.values())
        cells = ", ".join(f"{v} {counts[v]} ({100 * counts[v] / total:.1f}%)" for v in VERDICTS + ("error",)
                          if counts[v])
        print(f"  {group} ({total}): {cells}")


def _strong_set(row):
    return sorted((s[0], s[1], s[2]) for s in row.get("strong", ()))


def compare(before_path, after_path, aggregate_only, show):
    before = {r["id"]: r for r in read_jsonl(before_path)}
    after = {r["id"]: r for r in read_jsonl(after_path)}
    _print_table(f"before: {before_path}", before.values())
    _print_table(f"after: {after_path}", after.values())
    common = sorted(set(before) & set(after))
    only = len(set(before) ^ set(after))
    verdicts = [k for k in common if before[k].get("verdict") != after[k].get("verdict")]
    findings = [k for k in common if _strong_set(before[k]) != _strong_set(after[k])]
    errors = [k for k in common if ("error" in before[k]) != ("error" in after[k])]
    moved = collections.Counter((before[k].get("verdict", "error"), after[k].get("verdict", "error")) for k in verdicts)
    print(f"{len(common)} releases in both runs ({only} in one only)")
    print(f"  verdict changed: {len(verdicts)}" + "".join(f"; {a} -> {b}: {n}" for (a, b), n in sorted(moved.items())))
    print(f"  strong findings changed: {len(findings)}")
    print(f"  error in one run only: {len(errors)}")
    if aggregate_only:
        return 1 if verdicts or findings or errors else 0
    for k in sorted(set(verdicts) | set(findings) | set(errors))[:show]:
        b, a = before[k], after[k]
        print(f"\n{k}: {b.get('verdict', b.get('error'))} -> {a.get('verdict', a.get('error'))}")
        bs, as_ = set(_strong_set(b)), set(_strong_set(a))
        for rule, sev, msg in sorted(bs - as_):
            print(f"  - {rule} {sev}: {msg[:300]}")
        for rule, sev, msg in sorted(as_ - bs):
            print(f"  + {rule} {sev}: {msg[:300]}")
    return 1 if verdicts or findings or errors else 0


def _configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    _configure_stdio()
    parser = argparse.ArgumentParser(prog="bench.py", description="Registry scans of a labelled set of releases, "
                                                                  "and the comparison of two runs.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run", help="scan the manifest's releases (resumable)")
    p.add_argument("manifest")
    p.add_argument("out")
    p.add_argument("--deadline", type=float, default=28.0, help="seconds each release may take (default 28)")
    p.add_argument("--stop-after", type=float, default=12.0,
                   help="start no release after this many seconds; run again to go on (default 12)")
    p = sub.add_parser("compare", help="two runs of the same releases")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--aggregate-only", action="store_true", help="counts only, nothing that names a release")
    p.add_argument("--show", type=int, default=50, help="releases shown at most (default 50)")
    p = sub.add_parser("summary", help="one run's verdicts by category")
    p.add_argument("run")
    args = parser.parse_args(argv)
    if args.command == "run":
        return run(args.manifest, args.out, args.deadline, args.stop_after)
    if args.command == "compare":
        return compare(args.before, args.after, args.aggregate_only, args.show)
    _print_table(args.run, read_jsonl(args.run))
    return 0


if __name__ == "__main__":
    sys.exit(main())
