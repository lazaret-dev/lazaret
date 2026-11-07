"""The engine's recorded outputs (since the Rust-first refactor).

The Rust engine is Lazaret's only engine. Its answers used to be held to the
Python engine's, case for case; now they are held to the answers recorded
the last time they were reviewed. A snapshot test runs a seeded input set
through the engine and compares its outputs with
tests/architecture/snapshots/<name>.txt, one hash per CHUNK outputs, and
fails with the chunks that changed.

Reviewing a change: `scripts/snapshot.py record <set> --out before.jsonl.gz`
with the engine before the change and `--out after.jsonl.gz` with the engine
after it, then `scripts/snapshot.py diff before.jsonl.gz after.jsonl.gz`
shows each case whose outputs differ. Once the differences are accepted,
rerun the snapshot tests with LAZARET_SNAPSHOT_UPDATE=1 to write the new
hashes, and commit them with the change: the fixture's diff names the
chunks a change moved.
"""
import hashlib
import json
import os

from lazaret.scanner import _native

HERE = os.path.dirname(os.path.abspath(__file__))
DIR = os.path.join(HERE, "snapshots")
CHUNK = 100                      # outputs per hash
BATCH = 1500                     # calls per crossing of the boundary
UPDATE = "LAZARET_SNAPSHOT_UPDATE"


class Refused(AssertionError):
    """The engine built a pattern linre refused (P-16)."""


def run(calls, threads=2):
    """[(call, args, text)] -> the engine's answer to each, in order: the
    batch's own result ({"ok": …}, or {"error": …} where the call failed).

    Every pattern the engine builds on the way must be one linre runs, in
    linear time (P-16): one it refused failed its call closed, is in
    linre.refused, and fails the run that built it."""
    _native.call("linre.refused", {})
    out = []
    for i in range(0, len(calls), BATCH):
        part = [[c, a, t] for c, a, t in calls[i:i + BATCH]]
        out.extend(_native.call("batch", {"calls": part, "threads": threads}))
    refused = _native.call("linre.refused", {})
    if refused:
        raise Refused("patterns linre refused, built while running the set: " + "; ".join(refused[:5]))
    return out


def pack(*names):
    """The rule pack's values of `names` (engine.pack_value)."""
    from lazaret.scanner import engine
    out = [engine.pack_value(n) for n in names]
    return out[0] if len(out) == 1 else out


def canonical(value):
    """The JSON a hash is taken of (sorted keys, ASCII: surrogates escaped)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def hashes(values):
    """A hash per CHUNK values."""
    return [hashlib.sha256(canonical(values[i:i + CHUNK]).encode()).hexdigest()[:16]
            for i in range(0, len(values), CHUNK)]


def fixture(name):
    return os.path.join(DIR, name + ".txt")


def read(name):
    """The recorded hashes of `name`, or None when none are recorded."""
    try:
        with open(fixture(name), encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return None


def write(name, values):
    os.makedirs(DIR, exist_ok=True)
    with open(fixture(name), "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# {name}: {len(values)} outputs, a hash per {CHUNK} (tests/architecture/_snapshots.py)\n")
        f.write("\n".join(hashes(values)) + "\n")


def check(test, name, values):
    """Fail `test` where `values` differ from the recorded outputs of
    `name` (with LAZARET_SNAPSHOT_UPDATE set: record them instead)."""
    if os.environ.get(UPDATE):
        write(name, values)
        return
    want = read(name)
    test.assertIsNotNone(want, f"no snapshot recorded for {name}: run with {UPDATE}=1")
    got = hashes(values)
    changed = [k for k in range(max(len(want), len(got))) if k >= len(want) or k >= len(got) or want[k] != got[k]]
    test.assertEqual(
        changed, [],
        f"{name}: the engine's outputs changed in {len(changed)} of {len(got)} chunks (cases "
        + ", ".join(f"{k * CHUNK}-{k * CHUNK + CHUNK - 1}" for k in changed[:8])
        + f"{' …' if len(changed) > 8 else ''}); review with scripts/snapshot.py, then record with {UPDATE}=1")
