#!/usr/bin/env python3
"""Lazaret's benchmark harness: registry scans of a labelled set of
releases, and the comparison of two runs.

    python3 scripts/bench.py run MANIFEST OUT.jsonl [--deadline S] [--stop-after S] [--jobs N]
    python3 scripts/bench.py compare BEFORE.jsonl AFTER.jsonl [--aggregate-only] [--show N]
    python3 scripts/bench.py summary RUN.jsonl
    python3 scripts/bench.py prior RUN.jsonl MANIFEST OUT.jsonl [--aggregate-only]
    python3 scripts/bench.py all SETS.json [--jobs N] [--only NAME,...] [--label L] [--baseline L]

MANIFEST is JSON lines, one release each: "id"; "artifact_path", the
release file as the registry serves it; "container" (tgz, zip) and "kind"
(npm, sdist, wheel; gomod, a module zip as Go's proxy serves it, path@version/
inside, container zip; crate, a .crate as crates.io serves it,
name-version/ inside, container tgz; vsix, a VS Code extension's .vsix as
the Marketplace and Open VSX serve it, extension/ inside, container zip);
and "cat", the release's category,
where "benign" marks a package that should pass and anything else a
malicious release. (lz_path, lz_container and lz_kind are read too: the
names the September harness's corpus preparation wrote.) scripts/datadog.py
writes the malicious manifests, the benchmark's and a holdout's, from
DataDog's dataset; scripts/popular/ the benign ones: popular.py the popular
releases (npm, PyPI, crates, Open VSX's extensions), packaged.py the Go
modules and crates Ubuntu packages and Go's own tree.

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

With --jobs N, N releases are scanned at once, each in a worker process of
the guard's pool (registry/scanpool.py: the engine's threads shared out
among the scans running, a worker that dies or hangs recorded as an error
for that release alone). The records are the ones a run with one job
writes: a scan that ran out of time while the others ran beside it is not
written then, but scanned again alone once the rest is done (a busy
machine is not a verdict, T-1), and a run that finishes is written in the
manifest's order.

`prior` takes a run's WARN releases (npm, PyPI and crates.io ones), scans
each again and compares it with its established predecessor as a registry
scan does (registry/prior.py, SC-NEW-INDICATOR: the predecessor is fetched
from the registry, the release read from the manifest's file), one line
each in OUT (going on where it was), and prints how many would have the
finding, by category: what `run`, which scans the files alone, does not
measure.

`compare` reads two runs of the same releases: the verdicts by category in
each, and the releases whose verdict or strong findings differ. With
--aggregate-only it prints counts and nothing that names a release: use it
for a holdout set, whose releases are looked at only in aggregate, so that
no detector is written from them. `summary` prints one run's verdicts by
category.

`all` is every set in one command: a sets file (JSON) names each set's
manifest, the holdout's with "aggregate_only", the folder the runs are kept
in ("results") and the one the comparisons go to ("report"):

    {"results": "runs", "report": "~/Projects/lazaret/Claude outputs/bench",
     "sets": [{"name": "benchmark", "manifest": "benchmark/manifest.jsonl"},
              {"name": "holdout", "manifest": "holdout/manifest.jsonl", "aggregate_only": true},
              {"name": "popular", "manifest": "popular/manifest.jsonl"}]}

(paths relative to the sets file). It checks first that the engine library
is the tree's (its rule set the pack's, and built after the engine's
sources last changed: an editable install that was not rebuilt answers
with the old engine), runs each set with --jobs under a label (the commit,
or the commit and a digest of the uncommitted changes), compares it with
the set's last finished run, and writes each comparison, and a summary,
to REPORT/LABEL/. A holdout's comparison is in counts only, and nothing
`all` prints names one of its releases. Stopped, the same command goes on
where it was; a label's runs are never mixed with another engine library's.

What a change to detection is checked with (docs/TESTING.md): a run before
it and a run after it, on the benchmark (compare, every difference read)
and on the holdout (compare --aggregate-only).
"""
import argparse
import collections
import concurrent.futures
import contextlib
import datetime
import hashlib
import importlib
import io
import json
import math
import os
import pathlib
import re
import subprocess
import sys
import threading
import time

REPO = pathlib.Path(__file__).resolve().parent.parent
HERE = pathlib.Path(__file__).resolve().parent
_SRC = str(REPO / "python" / "src")
if not sys.path or sys.path[0] != _SRC:
    sys.path.insert(0, _SRC)

STRONG = ("CRITICAL", "BLOCKER")
VERDICTS = ("SUSPICIOUS", "WARN", "INCOMPLETE", "OK")
#: The engine's sources: a library built before one of these changed may not be this tree's engine.
ENGINE_SOURCES = ("rust/crates/lazaret-engine", "rust/crates/lazaret-ffi")
RULES = "rust/crates/lazaret-engine/rules/lazaret-rules.json"
SET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
PROGRESS_SECONDS = 30.0


def _field(rec, name, alias):
    value = rec.get(name, rec.get(alias))
    if value is None:
        raise ValueError(f"release {rec.get('id')!r} has no {name!r}")
    return value


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ---------------------------------------------------------------- one release
def record(data, container, kind, timeout, timed=False):
    """One release's record fields (verdict, strong and weak supply-chain findings, what SC-USE-RISK read) and
    whether its scan ran out of time -> {"row": ..., "time": bool}. Module-level: --jobs's workers run it, by
    this module's name (`timed` is the pool's argument; this harness keeps no timings)."""
    from lazaret.registry import repo
    budget = repo.Budget(deadline=time.monotonic() + timeout, deadline_detail="budget")
    res = repo._scan_artifact(data, container, kind, False, budget)
    row = {"verdict": res["verdict"],
           "strong": [[i["rule"], i["sev"], i["msg"][:700]] for i in res["issues"]
                      if i["rule"].startswith("SC-") and i["sev"] in STRONG],
           "weak": sorted({i["rule"] for i in res["issues"] if i["rule"].startswith("SC-") and i["sev"] == "MAJOR"}),
           "useTime": res.get("useTime")}               # how much SC-USE-RISK read (None: not run)
    return {"row": row, "time": "time" in (res.get("incomplete") or ())}


def _timeout(deadline_s):
    from lazaret.registry import repo
    return min(repo.SCAN_TIMEOUT, deadline_s)


def _release(rec):
    """A manifest line's (bytes, container, kind)."""
    with open(_field(rec, "artifact_path", "lz_path"), "rb") as f:
        data = f.read()
    return data, _field(rec, "container", "lz_container"), _field(rec, "kind", "lz_kind")


def _row(rec, fields):
    return {"id": rec["id"], "cat": rec.get("cat", ""), **fields}


def _error_row(rec, text):
    return _row(rec, {"error": text[:300]})


def scan_one(rec, deadline_s):
    """The run's line for one release of the manifest."""
    data, container, kind = _release(rec)
    return _row(rec, record(data, container, kind, _timeout(deadline_s))["row"])


# ---------------------------------------------------------------- a run
class _Attempts:
    """OUT.attempts: how many times each release was started, so that one the caller's timeout keeps killing is
    recorded as a harness timeout (the third start) and not tried again."""

    def __init__(self, out_path):
        self.path = out_path.with_name(out_path.name + ".attempts")
        self.tries = json.loads(self.path.read_text(encoding="utf-8")) if self.path.exists() else {}
        self._lock = threading.Lock()

    def start(self, release_id):
        with self._lock:
            self.tries[release_id] = self.tries.get(release_id, 0) + 1
            self.path.write_text(json.dumps(self.tries), encoding="utf-8")
            return self.tries[release_id]


def run(manifest, out_path, deadline_s, stop_after, jobs=1):
    from lazaret.scanner import engine
    try:
        engine.require()
    except engine.EngineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    done, total = execute(read_jsonl(manifest), pathlib.Path(out_path), deadline_s, stop_after, jobs)
    if done < total:
        print(f"PARTIAL {done} of {total}", flush=True)
        return 3
    print(f"DONE {done}", flush=True)
    return 0


def execute(releases, out_path, deadline_s, stop_after, jobs=1, progress=None, pool_factory=None):
    """Scan the releases OUT does not hold yet -> (releases OUT holds, releases in the manifest). `progress(done,
    total)` is told after each line; `pool_factory(jobs, fn)` makes the worker pool (scanpool.WorkerPool)."""
    done = {r["id"] for r in read_jsonl(out_path)} if out_path.exists() else set()
    ids = {r["id"] for r in releases}
    attempts = _Attempts(out_path)
    todo = [r for r in releases if r["id"] not in done]
    with open(out_path, "a", encoding="utf-8") as out:
        def write(row):
            out.write(json.dumps(row) + "\n")
            out.flush()
            done.add(row["id"])
            if progress is not None:
                progress(len(done & ids), len(ids))
        if jobs > 1 and todo:
            todo = _in_workers(todo, write, attempts, deadline_s, stop_after, jobs, pool_factory)
        _in_process(todo, write, attempts, deadline_s, stop_after)
    finished = len(done & ids)
    if finished == len(ids):
        _in_manifest_order(out_path, releases)          # (--jobs writes the lines as the scans finish)
    return finished, len(ids)


def _in_process(todo, write, attempts, deadline_s, stop_after):
    """The releases one after the other, in this process."""
    started = time.monotonic()
    for rec in todo:
        if time.monotonic() - started > stop_after:
            return
        if attempts.start(rec["id"]) > 2:                # killed by the caller's timeout twice
            write(_error_row(rec, "harness timeout"))
            continue
        try:
            row = scan_one(rec, deadline_s)
        except Exception as exc:                         # noqa: BLE001 -- recorded, the run goes on
            row = _error_row(rec, f"{type(exc).__name__}: {exc}")
        write(row)


def _worker_record():
    """`record` as the worker processes import it: by this module's name, from this folder, which goes at the end
    of sys.path (the workers start with this process's), so that no script here hides another module."""
    here = str(HERE)
    if here not in sys.path:
        sys.path.append(here)
    module = importlib.import_module("bench")
    if pathlib.Path(module.__file__).resolve() != pathlib.Path(__file__).resolve():
        raise RuntimeError(f"another module named bench is on the path: {module.__file__}")
    return module.record


def _in_workers(todo, write, attempts, deadline_s, stop_after, jobs, pool_factory=None):
    """`jobs` releases at a time, each in a worker process; a scan that ran out of time is run again alone at the
    end. -> the releases left for this process (all those not started, when no worker could be started)."""
    from lazaret.registry import scanpool
    work = _WorkerRun((pool_factory or scanpool.WorkerPool)(jobs, _worker_record()), attempts, _timeout(deadline_s),
                      stop_after)
    try:
        left = work.every(todo, write, jobs)
    finally:
        work.pool.close()
    if not work.unavailable:
        return []
    print(f"bench: no worker process could be started ({work.unavailable[0]}); scanning in this process",
          file=sys.stderr)
    order = {r["id"]: i for i, r in enumerate(todo)}
    return sorted(left, key=lambda r: order[r["id"]])


class _WorkerRun:
    """The releases of `run --jobs`, each handed to the worker pool by one of the parent's threads."""

    def __init__(self, pool, attempts, timeout, stop_after):
        self.pool, self.attempts, self.timeout, self.stop_after = pool, attempts, timeout, stop_after
        self.started, self.stop, self.unavailable = time.monotonic(), threading.Event(), []

    def one(self, rec, again=False):
        """-> (rec, its line or None when it was not started, whether its scan ran out of time). `again`: a release
        started already, run again alone (no --stop-after, no new attempt)."""
        if self.stop.is_set() or (not again and time.monotonic() - self.started > self.stop_after):
            return rec, None, False
        if not again and self.attempts.start(rec["id"]) > 2:
            return rec, _error_row(rec, "harness timeout"), False
        try:
            data, container, kind = _release(rec)
            got = self.pool.run(data, container, kind, self.timeout)
        except Exception as exc:                         # noqa: BLE001 -- recorded, the run goes on
            return rec, self._failed(rec, exc), False
        return rec, _row(rec, got["row"]), got["time"]

    def _failed(self, rec, exc):
        """The line for a release whose scan raised `exc`; None when no worker could be started."""
        from lazaret.registry import scanpool
        if isinstance(exc, scanpool.Unavailable):
            self.unavailable.append(str(exc))
            self.stop.set()
            return None
        if isinstance(exc, scanpool.Hung):
            return _error_row(rec, "harness timeout")
        if isinstance(exc, scanpool.Died):
            return _error_row(rec, f"worker lost: {exc}")
        return _error_row(rec, f"{type(exc).__name__}: {exc}")

    def every(self, todo, write, jobs):
        """Run `todo`, then the scans that ran out of time alone. -> the releases not started."""
        late, left = [], []
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as threads:
            try:
                for future in concurrent.futures.as_completed([threads.submit(self.one, rec) for rec in todo]):
                    _route(future.result(), write, late, left)
            except BaseException:                        # Ctrl-C: start nothing more, end the workers
                self.stop.set()
                self.pool.close()
                raise
        for rec in late:                                 # alone: the worker gets every engine thread
            _, row, _ = self.one(rec, again=True)
            if row is None:
                left.append(rec)
            else:
                write(row)
        return left


def _route(result, write, late, left):
    """A release's answer: written, held back to run again alone (it ran out of time), or left (not started)."""
    rec, row, ran_out = result
    if row is None:
        left.append(rec)
    elif ran_out:
        late.append(rec)
    else:
        write(row)


def _in_manifest_order(out_path, releases):
    """Rewrite OUT with its lines in the manifest's order (a run with --jobs writes them as they finish)."""
    order = {r["id"]: i for i, r in enumerate(releases)}
    with open(out_path, encoding="utf-8") as f:
        lines = [line for line in f if line.strip()]
    keyed = sorted(range(len(lines)), key=lambda n: (order.get(json.loads(lines[n])["id"], len(order)), n))
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_text("".join(lines[n] for n in keyed), encoding="utf-8")
    os.replace(tmp, out_path)


# ---------------------------------------------------------------- comparing
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


# ---------------------------------------------------------------- the prior release (SC-NEW-INDICATOR)
PRIOR_ECOSYSTEMS = ("npm", "pypi", "crates")


def release_of(rec):
    """(ecosystem, name, version) of a manifest line: its "eco", "name" and "version", else its id's last two
    `:`-separated parts (`popular:npm:@img/sharp-linux-x64@0.35.5`); None for another registry's release."""
    eco, name, version = rec.get("eco"), rec.get("name"), rec.get("version")
    if not (eco and name and version):
        parts = str(rec.get("id", "")).split(":")
        if len(parts) < 2 or "@" not in parts[-1][1:]:
            return None
        eco, (name, version) = parts[-2], parts[-1].rsplit("@", 1)
    return (eco, name, version) if eco in PRIOR_ECOSYSTEMS else None


def prior_one(rec, deadline_s):
    """A WARN release of a run, scanned again and compared with its established predecessor as a registry scan
    compares it (registry/prior.py: the predecessor fetched from the registry) -> its line of the `prior` file."""
    from lazaret.registry import prior, repo
    release = release_of(rec)
    if release is None:
        return _row(rec, {"prior": {"notCompared": "not a release of npm, PyPI or crates.io"}})
    data, container, kind = _release(rec)
    budget = repo.Budget(deadline=time.monotonic() + _timeout(deadline_s), deadline_detail="budget")
    res = repo._scan_artifact(data, container, kind, False, budget)
    per = [{"filename": rec.get("filename") or str(rec.get("url") or "").rsplit("/", 1)[-1] or None, "kind": kind}]
    _issues, summary = prior.release_issues(*release, None, res["issues"], per)
    return _row(rec, {"prior": summary or {"notCompared": "no weaker indicator it is asked about"}})


def prior_run(run_path, manifest, out_path, aggregate_only, deadline_s=28.0):
    """`prior`: each WARN release of a run compared with its established predecessor, a line each in OUT (which
    goes on where it was), and the counts by category."""
    rows = {r["id"]: r for r in read_jsonl(run_path)}
    done = {r["id"] for r in read_jsonl(out_path)} if os.path.exists(out_path) else set()
    with open(out_path, "a", encoding="utf-8") as out:
        for rec in read_jsonl(manifest):
            if rows.get(rec["id"], {}).get("verdict") != "WARN" or rec["id"] in done:
                continue
            try:
                line = prior_one(rec, deadline_s)
            except Exception as exc:                         # noqa: BLE001 -- recorded, the run goes on
                line = _error_row(rec, f"{type(exc).__name__}: {exc}")
            out.write(json.dumps(line) + "\n")
            out.flush()
    return prior_counts(read_jsonl(out_path), aggregate_only)


def _prior_outcome(line):
    found = line.get("prior") or {}
    if "error" in line:
        return "error"
    if found.get("newRules"):
        return "SC-NEW-INDICATOR"
    return "compared, nothing new" if "newRules" in found else "not compared"


def prior_counts(lines, aggregate_only):
    """Print what `prior` found, by category (and with --aggregate-only nothing that names a release)."""
    table = collections.defaultdict(collections.Counter)
    for line in lines:
        table[_group(line.get("cat", ""))][_prior_outcome(line)] += 1
    for group in sorted(table):
        print(f"{group} WARN releases: " + ", ".join(f"{k} {n}" for k, n in table[group].most_common()))
    for line in [] if aggregate_only else lines:
        if _prior_outcome(line) == "SC-NEW-INDICATOR":
            found = line["prior"]
            print(f"  {line['id']}: {', '.join(found['newRules'])} (against {found['version']})")
    return 0


# ---------------------------------------------------------------- every set, one command
class SetupError(Exception):
    """The sets file, the engine or the results folder is not fit to run on."""


def load_sets(path):
    """The sets file -> {"results": Path, "report": Path, "sets": [{"name", "manifest": Path, "aggregate_only"}]}."""
    path = pathlib.Path(path).expanduser().resolve()
    try:
        conf = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SetupError(f"cannot read the sets file {path}: {exc}") from None
    if not isinstance(conf, dict) or not isinstance(conf.get("sets"), list) or not conf["sets"]:
        raise SetupError(f"{path}: expected an object with a non-empty \"sets\" list")
    results = _where(path, conf.get("results", "runs"), "\"results\"")
    sets, seen = [], set()
    for entry in conf["sets"]:
        sets.append(_set_entry(path, entry, seen))
    report = _where(path, conf["report"], "\"report\"") if "report" in conf else results / "reports"
    return {"results": results, "report": report, "sets": sets}


def _where(sets_path, value, what):
    """A path of the sets file, relative to its folder."""
    if not isinstance(value, str) or not value:
        raise SetupError(f"{sets_path}: {what} must be a path")
    return (sets_path.parent / pathlib.Path(value).expanduser()).resolve()


def _set_entry(sets_path, entry, seen):
    """One set of the sets file, checked (its name new to `seen`, which it joins; its manifest there)."""
    name = entry.get("name") if isinstance(entry, dict) else None
    if not isinstance(name, str) or not SET_NAME.match(name) or name in seen:
        raise SetupError(f"{sets_path}: each set needs a name of its own (letters, digits, '.', '_', '-'): {name!r}")
    seen.add(name)
    manifest = _where(sets_path, entry.get("manifest"), f"set {name}'s \"manifest\"")
    if not manifest.is_file():
        raise SetupError(f"{sets_path}: set {name}'s manifest {manifest} is not there")
    return {"name": name, "manifest": manifest, "aggregate_only": entry.get("aggregate_only") is True}


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def engine_identity():
    """The engine library this process loads: its path, digest, build time, version and rule set."""
    from lazaret.registry import repo
    from lazaret.scanner import _native, engine
    try:
        engine.require()
    except engine.EngineError as exc:
        raise SetupError(str(exc)) from None
    lib = _native.library_path()
    built = os.stat(lib).st_mtime
    return {"library": lib, "sha256": _sha256(lib), "built": built, "version": _native.version(),
            "ruleSet": _native.call("pack.info").get("rule_set"), "pythonRuleSet": repo.ENGINE_VERSION}


def stale_engine(identity, root=REPO):
    """Why the library may not be the engine of the tree at `root` -> a list of reasons (empty: it looks current)."""
    reasons = []
    try:
        tree = json.loads((pathlib.Path(root) / RULES).read_text(encoding="utf-8")).get("rule_set")
    except (OSError, ValueError):
        tree = None
    if tree and identity.get("ruleSet") != tree:
        reasons.append(f"its rule set is {identity.get('ruleSet')}, the tree's {tree}")
    newest = _newest_source(root)
    if newest is not None and newest[0] > identity["built"]:
        reasons.append(f"{newest[1]} changed after it was built")
    return reasons


def _newest_source(root):
    """(mtime, path relative to root) of the newest file of the engine's sources, or None."""
    newest = None
    for part in ENGINE_SOURCES:
        for dirpath, dirnames, filenames in os.walk(pathlib.Path(root) / part):
            dirnames[:] = [d for d in dirnames if d != "target"]
            for name in filenames:
                full = os.path.join(dirpath, name)
                try:
                    mtime = os.stat(full).st_mtime
                except OSError:
                    continue
                if newest is None or mtime > newest[0]:
                    newest = (mtime, os.path.relpath(full, root))
    return newest


def _git(root, *argv):
    done = subprocess.run(["git", "-c", "safe.directory=*", "--no-optional-locks", *argv], cwd=root,
                          capture_output=True, check=False)
    if done.returncode != 0:
        raise OSError(done.stderr.decode("utf-8", "replace").strip() or "git failed")
    return done.stdout


def default_label(root=REPO):
    """The commit's short name, with a digest of the uncommitted changes to tracked files when there are any;
    a time stamp outside a git checkout."""
    try:
        head = _git(root, "rev-parse", "--short=8", "HEAD").decode("ascii").strip()
        diff = _git(root, "diff", "HEAD", "--binary")
    except (OSError, UnicodeDecodeError):
        return "run-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{head}-dirty-{hashlib.sha256(diff).hexdigest()[:8]}" if diff else head


def _read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write_json(path, value):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _claim_label(run_dir, identity, jobs, deadline_s):
    """Make or reopen RESULTS/LABEL; refuse one whose runs were made with another engine library or deadline."""
    run_dir.mkdir(parents=True, exist_ok=True)
    meta_path = run_dir / "engine.json"
    meta = _read_json(meta_path, None)
    if meta is not None:
        if meta.get("sha256") != identity["sha256"] or meta.get("deadline") != deadline_s:
            raise SetupError(f"{run_dir} holds runs made with another engine library or deadline; give this run "
                             "another --label, or remove that folder")
        return
    _write_json(meta_path, {**identity, "jobs": jobs, "deadline": deadline_s,
                            "started": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")})


def _baseline(history, name, label, wanted):
    """The label of the finished run this set's run is compared with, or None."""
    finished = history.get(name, [])
    if wanted:
        return wanted if wanted in finished else None
    earlier = [x for x in finished if x != label]
    return earlier[-1] if earlier else None


class _Progress:
    """A line every PROGRESS_SECONDS while a set runs: counts only, never a release's name."""

    def __init__(self, name):
        self.name, self.started, self.shown = name, time.monotonic(), time.monotonic()

    def __call__(self, done, total):
        now = time.monotonic()
        if now - self.shown >= PROGRESS_SECONDS:
            self.shown = now
            print(f"  {self.name}: {done} of {total} ({_duration(now - self.started)})", flush=True)


def _duration(seconds):
    seconds = int(seconds)
    return f"{seconds // 3600}h{seconds // 60 % 60:02d}m" if seconds >= 3600 else f"{seconds // 60}m{seconds % 60:02d}s"


def _report_set(entry, out, before, show):
    """The set's report text and whether anything moved."""
    text = io.StringIO()
    with contextlib.redirect_stdout(text):
        if before is None:
            _print_table(f"{entry['name']}: no earlier run to compare with; this run is the baseline", read_jsonl(out))
            moved = 0
        else:
            moved = compare(before, out, entry["aggregate_only"], show)
    return text.getvalue(), moved


def run_all(sets_path, jobs, only=None, label=None, baseline=None, deadline_s=28.0, show=50, allow_stale=False):
    """Every set of the sets file (or those `only` names) -> the exit status: 0 nothing moved (or no baseline),
    1 a set moved, 3 stopped before the end."""
    conf = load_sets(sets_path)
    chosen = _chosen(conf["sets"], only)
    identity, stale = _checked_engine(allow_stale)
    label = _checked_label(label or default_label())
    results, report_dir = conf["results"], conf["report"] / label
    _claim_label(results / label, identity, jobs, deadline_s)
    report_dir.mkdir(parents=True, exist_ok=True)
    print(f"bench all: {label}, rule set {identity['ruleSet']}, {jobs} jobs; reports in {report_dir}", flush=True)
    lines, status = [_summary_head(label, identity, jobs, stale)], 0
    for entry in chosen:
        line, moved = _one_set(entry, results, label, baseline, jobs, deadline_s, show, report_dir)
        print(line, flush=True)
        lines.append(line)
        if moved is None:
            status = 3
            break
        status = max(status, moved)
    (report_dir / "summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return status


def _chosen(sets, only):
    """The sets `only` names (all of them without it); SetupError for a name that is no set's."""
    chosen = [s for s in sets if not only or s["name"] in only]
    missing = set(only or ()) - {s["name"] for s in chosen}
    if missing:
        raise SetupError(f"no such set: {', '.join(sorted(missing))}")
    return chosen


def _checked_engine(allow_stale):
    """-> (the engine library's identity, why it may not be the tree's); SetupError when it may not be, unless
    `allow_stale`."""
    identity = engine_identity()
    stale = stale_engine(identity)
    if stale and not allow_stale:
        raise SetupError(f"the engine library {identity['library']} may not be this tree's: {'; '.join(stale)}. "
                         "Rebuild it (pip install -e ./python), or give --allow-stale-engine")
    return identity, stale


def _checked_label(label):
    if not SET_NAME.match(label):
        raise SetupError(f"a label is letters, digits, '.', '_' and '-': {label!r}")
    return label


def _summary_head(label, identity, jobs, stale):
    when = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    head = (f"bench all {label} ({when}): engine {identity['version']}, rule set {identity['ruleSet']}, "
            f"library {identity['sha256'][:12]}, {jobs} jobs")
    return head + (f"\n  run on an engine that may not be the tree's: {'; '.join(stale)}" if stale else "")


def _one_set(entry, results, label, wanted, jobs, deadline_s, show, report_dir):
    """Run one set and write its report -> (its summary line, 0 or 1 for what moved; None when it did not finish)."""
    name = entry["name"]
    out = results / label / f"{name}.jsonl"
    print(f"{name}: {entry['manifest']}", flush=True)
    started = time.monotonic()
    done, total = execute(read_jsonl(entry["manifest"]), out, deadline_s, math.inf, jobs, _Progress(name))
    took = _duration(time.monotonic() - started)
    if done < total:
        return f"{name}: stopped at {done} of {total} after {took}; the same command goes on from there", None
    against, text, moved = _compare_with_last(entry, results, label, wanted, show, out)
    (report_dir / f"{name}.txt").write_text(text, encoding="utf-8")
    errors = sum(1 for r in read_jsonl(out) if "error" in r)
    head = f"{name}: {total} releases in {took}, {errors} harness errors"
    return _set_line(head, against, wanted, text), moved


def _compare_with_last(entry, results, label, wanted, show, out):
    """Compare the set's run with its last finished run (or `wanted`'s) and record this one as finished.
    -> (the label compared with or None, the report's text, 0 or 1 for what moved)."""
    history_path = results / "history.json"
    history = _read_json(history_path, {})
    name = entry["name"]
    against = _baseline(history, name, label, wanted)
    text, moved = _report_set(entry, out, None if against is None else results / against / f"{name}.jsonl", show)
    history[name] = [x for x in history.get(name, []) if x != label] + [label]
    _write_json(history_path, history)
    return against, text, moved


def _set_line(head, against, wanted, text):
    """A set's line of the summary: counts only (a holdout's report is counts too, and only counts are taken)."""
    if against is None and wanted:
        return f"{head}; {wanted} has no finished run of this set to compare with"
    if against is None:
        return f"{head}; the first run, now the baseline"
    counts = [x.strip() for x in text.splitlines()
              if x.startswith(("  verdict changed", "  strong findings", "  error in one"))]
    return f"{head}; against {against}: {'; '.join(counts)}"


# ---------------------------------------------------------------- the command line
def _configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def _default_jobs():
    from lazaret.registry import scanpool
    return max(1, scanpool.cores() // 2)


def _parser():
    parser = argparse.ArgumentParser(prog="bench.py", description="Registry scans of a labelled set of releases, "
                                                                  "and the comparison of two runs.")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("run", help="scan the manifest's releases (resumable)")
    p.add_argument("manifest")
    p.add_argument("out")
    p.add_argument("--deadline", type=float, default=28.0, help="seconds each release may take (default 28)")
    p.add_argument("--stop-after", type=float, default=12.0,
                   help="start no release after this many seconds; run again to go on (default 12)")
    p.add_argument("--jobs", type=int, default=1, help="releases scanned at once, each in a worker (default 1)")
    p = sub.add_parser("compare", help="two runs of the same releases")
    p.add_argument("before")
    p.add_argument("after")
    p.add_argument("--aggregate-only", action="store_true", help="counts only, nothing that names a release")
    p.add_argument("--show", type=int, default=50, help="releases shown at most (default 50)")
    p = sub.add_parser("summary", help="one run's verdicts by category")
    p.add_argument("run")
    p = sub.add_parser("prior", help="a run's WARN releases compared with their predecessors (SC-NEW-INDICATOR)")
    p.add_argument("run")
    p.add_argument("manifest")
    p.add_argument("out")
    p.add_argument("--aggregate-only", action="store_true", help="counts only, nothing that names a release")
    p = sub.add_parser("all", help="every set of a sets file, run and compared with its last run")
    p.add_argument("sets", help="the sets file (JSON; see this script's docstring)")
    p.add_argument("--jobs", type=int, default=None, help="releases scanned at once (default: half the cores)")
    p.add_argument("--only", help="the sets to run, by name, separated by commas")
    p.add_argument("--label", help="this run's name (default: the commit, and a digest of uncommitted changes)")
    p.add_argument("--baseline", help="the run to compare with (default: each set's last finished run)")
    p.add_argument("--deadline", type=float, default=28.0, help="seconds each release may take (default 28)")
    p.add_argument("--show", type=int, default=50, help="releases a comparison names at most (default 50)")
    p.add_argument("--allow-stale-engine", action="store_true",
                   help="run on an engine library that may not be the tree's (the summary says so)")
    return parser


def main(argv=None):
    _configure_stdio()
    args = _parser().parse_args(argv)
    if args.command == "run":
        return run(args.manifest, args.out, args.deadline, args.stop_after, max(1, args.jobs))
    if args.command == "compare":
        return compare(args.before, args.after, args.aggregate_only, args.show)
    if args.command == "prior":
        return prior_run(args.run, args.manifest, args.out, args.aggregate_only)
    if args.command == "all":
        try:
            return run_all(args.sets, max(1, args.jobs or _default_jobs()),
                           [x for x in (args.only or "").split(",") if x] or None, args.label, args.baseline,
                           args.deadline, args.show, args.allow_stale_engine)
        except SetupError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print("stopped; the same command goes on from there", file=sys.stderr)
            return 3
    _print_table(args.run, read_jsonl(args.run))
    return 0


if __name__ == "__main__":
    sys.exit(main())
