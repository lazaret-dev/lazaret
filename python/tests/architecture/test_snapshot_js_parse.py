"""The engine's JavaScript parser (the `js_parse` call: rust/crates/
lazaret-engine/src/jsparse/, what the cross-file JavaScript pass reads),
held to its recorded trees (_snapshots.py) — every node, field, value and
line, or the error's line and reason — on jsparse_cases.py's inputs: the
reader's snippets and the snippets for what those do not reach, every
construct that nests at depths around the limit, seeded soups of tokens and
of TypeScript, JSX and Flow pieces, seeded generated projects (jsgen.py)
and mutations of them; and with spans, on the reader's snippets and more
generated projects.

A tree may be deeper than json.loads reads: each answer counts as its
status and the SHA-256 of its JSON text (scripts/snapshot.py records the
texts themselves, for review).

Until phase 3 of the Rust-first refactor the parser was held to jsparse.py,
node for node, on these inputs and on the 24,428 files of 20 installed npm
packages (docs/RUST_ENGINE.md). Inert text only. Skipped where the native
library is not built.
"""
import hashlib
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots, jsgen
from tests.architecture import jsparse_cases as cases

DEPTHS = [1, 2, 83, 84, 85, 124, 125, 126, 127, 128, 129, 250, 251, 252, 253, 254, 255, 256, 257]


def project_files(seed, n):
    return [(f["path"], f["content"]) for files in jsgen.projects(seed, n) for f in files]


def parts():
    """The set's inputs, part by part: (label, [(path, source)])."""
    return [("reader snippets", cases.items_of(cases.READER_SNIPPETS)),
            ("snippets", list(cases.SNIPPETS)),
            ("nestings", [(path, src) for _, path, src in cases.nesting_cases(DEPTHS)]),
            ("token soups", cases.token_soups(20260928, 1500)),
            ("piece soups", cases.soup(20261001, 6000)),
            ("projects", project_files(20260928, 60)),
            ("mutations", cases.mutate(project_files(20261001, 20), 20261001, 800))]


def spans_items():
    return cases.items_of(cases.READER_SNIPPETS) + project_files(20261003, 12)


def calls(items, spans=False):
    out = []
    for path, src in items:
        ts, jsx = cases.dialect(path)
        args = {"ts": ts, "jsx": jsx}
        if spans:
            args["spans"] = True
        out.append(("js_parse", args, src))
    return out


def snapshot_sets():
    return {"js_parse": lambda: calls([item for _, items in parts() for item in items]),
            "js_parse_spans": lambda: calls(spans_items(), spans=True)}


def answers(set_calls):
    """[(status and digest, "tree" | "error" | the raw start)] of each call."""
    out = []
    for name, args, text in set_calls:
        status, answer = _native.call_raw(name, args, text)
        kind = ("tree" if answer.startswith('{"type":"Program"') else
                "error" if answer.startswith('{"error":') else answer[:40])
        out.append((f"{status}:{hashlib.sha256(answer.encode('ascii')).hexdigest()}", kind))
    return out


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class JsParseSnapshotTests(unittest.TestCase):
    def test_trees(self):
        got = answers(snapshot_sets()["js_parse"]())
        self.assertEqual([k for _, k in got if k not in ("tree", "error")], [])
        _snapshots.check(self, "js_parse", [d for d, _ in got])
        # not vacuous: each part reaches what it is there for
        kinds = {}
        at = 0
        for label, items in parts():
            kinds[label] = [k for _, k in got[at:at + len(items)]]
            at += len(items)
        self.assertGreater(kinds["reader snippets"].count("error"), 10)
        self.assertGreater(kinds["reader snippets"].count("tree"), 35)
        self.assertEqual(kinds["projects"].count("error"), 0)                  # all of it reads
        for label in ("token soups", "piece soups", "mutations"):           # mostly errors, some trees
            self.assertGreaterEqual(kinds[label].count("tree"), 15, label)
            self.assertGreater(kinds[label].count("error"), len(kinds[label]) // 2, label)
        deepest = dict(zip([(name, k) for name, _, _ in cases.NESTINGS for k in DEPTHS], kinds["nestings"]))
        for name, _, _ in cases.NESTINGS:
            self.assertEqual((deepest[(name, 84)], deepest[(name, 257)]), ("tree", "error"), name)

    def test_trees_with_spans(self):
        got = answers(snapshot_sets()["js_parse_spans"]())
        _snapshots.check(self, "js_parse_spans", [d for d, _ in got])
        self.assertGreater(sum(k == "tree" for _, k in got), 60)


if __name__ == "__main__":
    unittest.main()
