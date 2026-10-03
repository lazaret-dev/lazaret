#!/usr/bin/env python3
"""Mutation fuzzer for the readers of untrusted input (0.1.9, X-1). Standard library plus this checkout.

    python3 scripts/fuzz/fuzz.py --list
    python3 scripts/fuzz/fuzz.py [TARGET ...] [--seed N] [--iterations N | --seconds S] [--time-limit S]
                                 [--findings DIR] [--json PATH] [--no-minimize] [--hard-limit S] [--pending PATH]
    python3 scripts/fuzz/fuzz.py --replay FILE TARGET

Each target (`fuzz_targets.py`) is one reader and the inputs it starts from. An input is chosen from the corpus (the
seeds, and the inputs that ran slower than usual), changed by `fuzz_mutate.Mutator`, and run. A **finding** is an
exception the reader does not document, a broken promise (`fuzz_targets.Violation`), or a run over the time limit.
Findings are de-duplicated by kind and the line that raised (a slow one by target), made smaller by deleting what
is not needed to reproduce them, and written to `--findings` as `<target>-<kind>-<hash>.bin` (the input) and
`.txt` (what happened, and how to replay it).

The same `--seed` runs the same inputs (a run limited by `--seconds` is the same stream, cut where time ended).
`--iterations` counts the changed inputs; the seeds are run first, besides. `--hard-limit S` arms `faulthandler`,
so that a run that does not return in S seconds ends the process with the stack of every thread, and `--pending
PATH` writes each input to PATH before it runs, so the one that hung is the file left there: the way to find a
hang, which a time limit measured afterwards cannot.

Exit status: 0 no findings, 1 findings, 2 usage."""

import argparse
import faulthandler
import hashlib
import json
import os
import platform
import sys
import time
import traceback
import warnings

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz_common  # noqa: E402

DEFAULT_SEED = 0
DEFAULT_ITERATIONS = 200
SLOW_KEEP = 4.0              # a run this many times slower than the average joins the corpus
SLOW_FLOOR = 0.005           # ... and at least this much (seconds) over it
MAX_CORPUS = 256
SHRINK_TRIES = 300
SHRINK_SECONDS = 15.0
EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


class Finding:
    def __init__(self, target, kind, signature, data, text, seconds, iteration, seed):
        self.target, self.kind, self.signature, self.data, self.text = target, kind, signature, data, text
        self.seconds, self.iteration, self.seed = seconds, iteration, seed
        self.path = None

    @property
    def digest(self):
        return hashlib.sha256(self.data).hexdigest()

    def as_dict(self):
        return {"target": self.target, "kind": self.kind, "signature": self.signature, "bytes": len(self.data),
                "sha256": self.digest, "seconds": round(self.seconds, 4), "iteration": self.iteration,
                "seed": self.seed, "file": self.path, "text": self.text}


def signature_of(exc):
    """The kind of exception and the line that raised it: the deepest frame in this checkout's `lazaret`
    package (or, failing that, the deepest frame)."""
    frames = traceback.extract_tb(exc.__traceback__)
    ours = [f for f in frames if os.path.abspath(f.filename).startswith(fuzz_common.SRC + os.sep)]
    frame = (ours or frames or [None])[-1]
    where = f"{os.path.basename(frame.filename)}:{frame.lineno}" if frame else "?"
    return f"{type(exc).__name__}@{where}"


def noisy(caught):
    """The first warning a reader printed instead of keeping to itself (a deprecation is the standard library's
    to announce, not the reader's) -> (signature, text) or None."""
    for w in caught:
        if not issubclass(w.category, (DeprecationWarning, PendingDeprecationWarning)):
            return (f"warning:{w.category.__name__}@{os.path.basename(w.filename)}:{w.lineno}",
                    f"{w.category.__name__}: {w.message} ({w.filename}:{w.lineno})")
    return None


def execute(run, data, time_limit):
    """Run one input -> (outcome, seconds); outcome is None, or (kind, signature, text)."""
    from fuzz_targets import Violation
    started = time.perf_counter()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            run(data)
        except Violation as exc:
            return ("invariant", "invariant:" + exc.rule, str(exc)), time.perf_counter() - started
        except (Exception, SystemExit) as exc:
            text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)[-8:])
            return ("exception", signature_of(exc), text), time.perf_counter() - started
    seconds = time.perf_counter() - started
    said = noisy(caught)
    if said:
        return ("warning", said[0], said[1]), seconds
    if seconds > time_limit:
        return ("slow", "slow", f"{seconds:.2f} s for {len(data)} bytes (limit {time_limit:g} s)"), seconds
    return None, seconds


def shrink(run, data, wanted, time_limit, tries=SHRINK_TRIES, seconds=SHRINK_SECONDS):
    """Delete chunks of `data` (halves, then quarters, ... down to single bytes) for as long as the same finding
    (the same kind and signature) still happens -> the smaller input."""
    deadline = time.monotonic() + seconds
    chunk = len(data) // 2
    while chunk >= 1 and tries > 0 and time.monotonic() < deadline:
        at = 0
        while at < len(data) and tries > 0 and time.monotonic() < deadline:
            candidate = data[:at] + data[at + chunk:]
            tries -= 1
            if candidate:
                outcome, _ = execute(run, candidate, time_limit)
                if outcome is not None and outcome[:2] == wanted:
                    data = candidate
                    continue
            at += chunk
        chunk //= 2
    return data


def fuzz_target(target, *, seed=DEFAULT_SEED, iterations=None, seconds=None, time_limit=None, hard_limit=0,
                pending=None, minimize=True, max_len=None, log=None):
    """Fuzz one target -> {"target", "seed", "runs", "seconds", "slowest", "corpus", "findings": [Finding]}."""
    import fuzz_mutate as mutate
    limit = target.time_limit if time_limit is None else time_limit
    rng = mutate.rng_for(seed, target.name)
    mutator = mutate.Mutator(rng, max_len or target.max_len, target.dictionary)
    run, close = target.start()
    seeds = [bytes(s) for s in target.seeds()]
    corpus = list(seeds)
    found = {}                                   # (kind, signature) -> Finding
    runs, mutated, slowest, average = 0, 0, 0.0, None
    started = time.monotonic()
    deadline = None if seconds is None else started + seconds
    wanted = iterations if iterations is not None else (None if seconds is not None else DEFAULT_ITERATIONS)
    queue = list(seeds)                          # the seeds first: one that is a finding is a bug in the reader
    try:
        while True:
            if queue:
                data, base = queue.pop(0), True
            else:
                if wanted is not None and mutated >= wanted:
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
                data, base = mutator.mutate(rng.choice(corpus), corpus), False
                mutated += 1
            if pending:
                with open(pending, "wb") as fh:
                    fh.write(data)
            if hard_limit:
                faulthandler.dump_traceback_later(hard_limit, exit=True)
            outcome, took = execute(run, data, limit)
            if hard_limit:
                faulthandler.cancel_dump_traceback_later()
            runs += 1
            slowest = max(slowest, took)
            if outcome is not None:
                key = outcome[:2]
                if key not in found or (outcome[0] == "slow" and took > found[key].seconds):
                    found[key] = Finding(target.name, *outcome[:2], data, outcome[2], took, runs, seed)
                    if log:
                        log(f"  {target.name}: {outcome[0]} {outcome[1]} (run {runs}, {len(data)} bytes)")
                continue
            if not base and average is not None and len(corpus) < MAX_CORPUS and took > SLOW_KEEP * average + SLOW_FLOOR:
                corpus.append(data)
            average = took if average is None else 0.98 * average + 0.02 * took
        if minimize:
            for finding in found.values():
                finding.data = shrink(run, finding.data, (finding.kind, finding.signature), limit)
    finally:
        close()
    return {"target": target.name, "seed": seed, "runs": runs, "seconds": time.monotonic() - started,
            "slowest": slowest, "corpus": len(corpus), "findings": list(found.values())}


def is_known(finding):
    import fuzz_targets as targets
    return targets.known(finding.target, finding.signature)


def write_finding(finding, directory, command):
    """Save the input and an account of the finding in `directory` -> the input's path."""
    os.makedirs(directory, exist_ok=True)
    stem = os.path.join(directory, f"{finding.target}-{finding.kind}-{finding.digest[:10]}")
    with open(stem + ".bin", "wb") as fh:
        fh.write(finding.data)
    lines = [f"target:     {finding.target}", f"kind:       {finding.kind}", f"signature:  {finding.signature}",
             f"input:      {len(finding.data)} bytes, sha256 {finding.digest}", f"seconds:    {finding.seconds:.3f}",
             f"found:      run {finding.iteration} of seed {finding.seed}",
             f"python:     {platform.python_version()} on {platform.system()}",
             f"replay:     {command} --replay {os.path.basename(stem)}.bin {finding.target}", "", finding.text.rstrip(), "",
             "first bytes:", repr(finding.data[:200])]
    with open(stem + ".txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    finding.path = stem + ".bin"
    return finding.path


def render(results):
    out = [f"{'target':<28}{'runs':>7}{'seconds':>9}{'slowest':>10}{'corpus':>8}  findings"]
    for r in results:
        out.append(f"{r['target']:<28}{r['runs']:>7}{r['seconds']:>9.1f}{r['slowest'] * 1000:>8.0f}ms{r['corpus']:>8}  "
                   f"{len(r['findings']) or '-'}")
        for f in r["findings"]:
            out.append(f"    {f.kind}: {f.signature} ({len(f.data)} bytes)" + (f" -> {f.path}" if f.path else "")
                       + (f"  [known: {is_known(f)}]" if is_known(f) else ""))
    return "\n".join(out)


def build_parser():
    ap = argparse.ArgumentParser(prog="fuzz.py", description=__doc__.split("\n")[0])
    ap.add_argument("targets", nargs="*", help="targets to run (default: all; --list names them)")
    ap.add_argument("--list", action="store_true", help="name the targets and what they run")
    ap.add_argument("--seed", default=str(DEFAULT_SEED), help="the stream of inputs (default %(default)s); 'random' picks one")
    ap.add_argument("--iterations", type=int, help=f"changed inputs per target (default {DEFAULT_ITERATIONS})")
    ap.add_argument("--seconds", type=float, help="run each target this long instead")
    ap.add_argument("--time-limit", type=float, help="seconds one input may take (default: the target's)")
    ap.add_argument("--findings", metavar="DIR", help="write each finding's input and account here")
    ap.add_argument("--json", metavar="PATH", help="write the results as JSON")
    ap.add_argument("--no-minimize", action="store_true", help="keep findings as found")
    ap.add_argument("--hard-limit", type=float, default=0, metavar="S", help="end the process, with stacks, if one input takes S seconds")
    ap.add_argument("--pending", metavar="PATH", help="write each input here before running it")
    ap.add_argument("--replay", metavar="FILE", help="run one saved input against the one target named")
    return ap


def main(argv=None):
    fuzz_common.configure_stdio()
    fuzz_common.use_source_tree()
    args = build_parser().parse_args(argv)
    import fuzz_targets as targets
    if args.list:
        for t in targets.TARGETS.values():
            print(f"{t.name:<28}{t.summary}")
        return EXIT_OK
    unknown = [n for n in args.targets if n not in targets.TARGETS]
    if unknown:
        print(f"unknown target: {', '.join(unknown)} (--list names them)", file=sys.stderr)
        return EXIT_USAGE
    chosen = [targets.TARGETS[n] for n in args.targets] or list(targets.TARGETS.values())
    if args.iterations is not None and args.seconds is not None:
        print("--iterations and --seconds exclude each other", file=sys.stderr)
        return EXIT_USAGE
    if args.replay:
        if len(chosen) != 1 or not args.targets:
            print("--replay needs exactly one target", file=sys.stderr)
            return EXIT_USAGE
        with open(args.replay, "rb") as fh:
            data = fh.read()
        target = chosen[0]
        run, close = target.start()
        try:
            outcome, seconds = execute(run, data, args.time_limit or target.time_limit)
        finally:
            close()
        if outcome is None:
            print(f"no finding ({seconds:.3f} s)")
            return EXIT_OK
        print(f"{outcome[0]}: {outcome[1]}\n{outcome[2]}")
        return EXIT_FINDINGS
    seed = str(int(time.time())) if args.seed == "random" else args.seed
    print(f"seed {seed}", file=sys.stderr)
    results = []
    for target in chosen:
        results.append(fuzz_target(target, seed=seed, iterations=args.iterations, seconds=args.seconds,
                                   time_limit=args.time_limit, hard_limit=args.hard_limit, pending=args.pending,
                                   minimize=not args.no_minimize, log=lambda line: print(line, file=sys.stderr)))
        if args.findings:
            for finding in results[-1]["findings"]:
                write_finding(finding, args.findings, "python3 scripts/fuzz/fuzz.py")
    print(render(results))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"seed": seed, "python": platform.python_version(),
                       "targets": [dict(r, findings=[f.as_dict() for f in r["findings"]]) for r in results]}, fh, indent=2)
    return EXIT_FINDINGS if any(not is_known(f) for r in results for f in r["findings"]) else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
