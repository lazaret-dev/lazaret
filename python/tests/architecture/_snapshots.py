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


def run(calls, threads=2):
    """[(call, args, text)] -> the engine's answer to each, in order: the
    batch's own result ({"ok": …}, or {"error": …} where the call failed)."""
    out = []
    for i in range(0, len(calls), BATCH):
        part = [[c, a, t] for c, a, t in calls[i:i + BATCH]]
        out.extend(_native.call("batch", {"calls": part, "threads": threads}))
    return out


def pack(*names):
    """The rule pack's values of `names` (a text, a number, a list for a set
    or a list, a dict for a map, the pattern's text for a pattern)."""
    raw = _native.call("pack.values", {"names": list(names)})
    out = []
    for name in names:
        if raw.get(name) is None:
            raise KeyError(name)
        out.append(_value(raw[name]))
    return out[0] if len(out) == 1 else out


def _value(entry):
    """A pack entry's value (a map's and a list's entries in turn)."""
    if not isinstance(entry, dict):
        return entry
    if "map" in entry:
        return {k: _value(v) for k, v in entry["map"].items()}
    for kind in ("set", "list", "items"):
        if kind in entry:
            return [_value(v) for v in entry[kind]]
    if "re" in entry:
        return entry["re"]
    return entry.get("value")


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
