"""The engine's port of the cross-file JavaScript taint pass (rust
crates/lazaret-engine/src/jsflow/, the `js_flow` call) against its
reference, lazaret.scanner.jsflow (phase 3 of the Rust-first refactor):
every output of the pass, in order — X-FLOW-SKIPPED, each issue's category,
file, line, source, sink and chain, each note's fields — on the corpus
test_js_parity_flow.py holds the npm engine to (the review's cases, the
engine's own cases, the caps, seeded generated projects and token soups),
with the default model and with a configured one (sources, sinks, full and
partial sanitizers, as taintspec validates them).

All content is inert: nothing is executed.
"""
import random
import unittest

from lazaret.scanner import _native, jsflow, taintspec
from tests.architecture import jsgen
from tests.architecture import test_js_parity_flow as tpf

CONFIG = {"javascript": {
    "sources": [r"\bctx\.input\b", r"(?<![\w$.])getQ\($", r"\bt\b"],
    "sinks": [{"pattern": r"\.dangerous\($", "category": "command injection"},
              {"pattern": r"(?<![\w$.])h\($", "category": "SQL injection"},
              {"pattern": r"\.innerText =$", "category": "cross-site scripting"}],
    "sanitizers": {"full": ["isOk", "k", "m.f"],
                   "partial": {"escapeHtml": ["SQL injection"], "g": ["cross-site scripting", "open redirect"]}},
}}


def corpus():
    rnd = random.Random(20260927)
    sets = tpf.review_cases()
    sets.extend(jsgen.projects(20260928, 100))
    for _ in range(150):
        sets.append([{"path": f"p{k}.js", "content": tpf.soup(rnd) + "\n" + tpf.soup(rnd) + "\n" + tpf.soup(rnd)}
                     for k in range(rnd.randint(1, 4))])
    return sets


def reference(files, spec=None):
    """jsflow.analyze's outputs as the engine gives them."""
    out = []
    cfg = None
    if spec is not None:
        cfg = jsflow.config(taintspec.extend_pattern(jsflow.SOURCE_RE, spec.sources), spec.sinks, spec.full,
                            spec.partial)

    def issue(cat, caller_file, line, lines, source_loc, sink_loc, chain):
        return ["issue", cat, caller_file, line, source_loc, sink_loc, chain]

    def note(rule, name, fname, line, msg, why, fix):
        return ["note", rule, name, fname, line, msg, why, fix]

    jsflow.analyze([{"path": f["path"], "content": f["content"]} for f in files], out, issue, note, cfg)
    res = []
    for x in out:
        if isinstance(x, dict):            # X-FLOW-SKIPPED: its path and size
            res.append(["skipped_size", x["file"], int(x["msg"].split(" is ", 1)[1].split(" characters", 1)[0])])
        else:
            res.append(x)
    return res


def engine(files, spec=None):
    args = {"files": [[f["path"], len(f["content"])] for f in files]}
    if spec is not None:
        args.update(sources=[g.pattern for g in spec.sources], sinks=[[g.pattern, c] for g, c in spec.sinks],
                    full=sorted(spec.full), partial=[[n, sorted(c)] for n, c in sorted(spec.partial.items())])
    return _native.call("js_flow", args, "".join(f["content"] for f in files))


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class JsFlowParityTests(unittest.TestCase):
    maxDiff = None

    def check(self, spec):
        total = 0
        kinds = set()
        for files in corpus():
            want = reference(files, spec)
            total += len(want)
            kinds.update((x[0], x[1] if x[0] != "skipped_size" else "") for x in want)
            self.assertEqual(engine(files, spec), want, str(files)[:300])
        return total, kinds

    def test_the_default_model(self):
        total, kinds = self.check(None)
        self.assertGreater(total, 2000)
        # not vacuous: every category, both notes, the size skip
        self.assertTrue({("issue", c) for c in jsflow.CATS} | {("note", "Q-FLOW-SKIPPED"),
                                                               ("note", "Q-FLOW-INCOMPLETE"),
                                                               ("skipped_size", "")} <= kinds, kinds)

    def test_a_configured_model(self):
        spec = taintspec.validate(CONFIG).javascript
        self.assertTrue(spec.sources and spec.sinks and spec.full and spec.partial)
        total, _ = self.check(spec)
        self.assertGreater(total, 2000)

    def test_bad_arguments_are_refused(self):
        for args in ({"files": [["a.js", 5]]}, {"files": [["a.js", 1]]}, {"files": "x"},
                     {"files": [["a.js", 3]], "sinks": [["x", "not a category"]]}):
            with self.subTest(args=args), self.assertRaises(_native.NativeError):
                _native.call("js_flow", args, "abc")


if __name__ == "__main__":
    unittest.main()
