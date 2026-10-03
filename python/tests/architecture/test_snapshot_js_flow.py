"""The engine's cross-file JavaScript taint pass (the `js_flow` call: rust/
crates/lazaret-engine/src/jsflow/, where both packages' project-mode X-*
flows and Q-FLOW-* notes for JavaScript come from), held to its recorded
outputs (_snapshots.py) — every output, in order: X-FLOW-SKIPPED's path,
size and limit; each issue's category, file, line, source, sink, chain and
the index of its file; each note's fields — on the corpus the pass was held
to jsflow.py on: the review's cases (test_js_parity_flow.review_cases:
routes, modules and returned values, sanitizers, classes, TypeScript, JSX,
the caps, the fixpoint's cap and the work budget, files the reader
rejects), seeded generated projects (jsgen.py) and token soups, with the
default model and with a configured one (sources, sinks, full and partial
sanitizers, as taintspec validates them); and on the call's own cases:
files that are not text, a lowered limit for one function's reading.

Until phase 3 of the Rust-first refactor the pass was jsflow.py's (and its
npm twin's); the port was held to it output for output on this corpus and
on 1,490 installed npm packages read as projects (docs/RUST_ENGINE.md).
All content is inert: nothing is executed.
"""
import collections
import random
import unittest

from lazaret.scanner import _native, taintspec
from tests.architecture import _snapshots, jsgen
from tests.architecture import test_js_parity_flow as tpf

CATS = ("SQL injection", "command injection", "code injection", "template injection", "path traversal",
        "server-side request forgery", "open redirect", "cross-site scripting")
CONFIG = {"javascript": {
    "sources": [r"\bctx\.input\b", r"(?<![\w$.])getQ\($", r"\bt\b"],
    "sinks": [{"pattern": r"\.dangerous\($", "category": "command injection"},
              {"pattern": r"(?<![\w$.])h\($", "category": "SQL injection"},
              {"pattern": r"\.innerText =$", "category": "cross-site scripting"}],
    "sanitizers": {"full": ["isOk", "k", "m.f"],
                   "partial": {"escapeHtml": ["SQL injection"], "g": ["cross-site scripting", "open redirect"]}},
}}
LIB = "function runIt(list) {\n  for (const c of list) {\n    if (c) exec(c);\n  }\n}\nmodule.exports = { runIt };\n"
APP = "const { runIt } = require('./lib');\napp.get('/', (req) => {\n  runIt(req.query.q);\n});\n"


def corpus():
    rnd = random.Random(20260927)
    sets = tpf.review_cases()
    sets.extend(jsgen.projects(20260928, 100))
    for _ in range(150):
        sets.append([{"path": f"p{k}.js", "content": tpf.soup(rnd) + "\n" + tpf.soup(rnd) + "\n" + tpf.soup(rnd)}
                     for k in range(rnd.randint(1, 4))])
    return sets


def model(spec):
    """The call's arguments for a validated taintspec section."""
    return {"sources": [g.pattern for g in spec.sources], "sinks": [[g.pattern, c] for g, c in spec.sinks],
            "full": sorted(spec.full), "partial": [[n, sorted(c)] for n, c in sorted(spec.partial.items())]}


def call(files, extra=None):
    """The js_flow call for files ({"path", "content"}: content None is not text)."""
    text = [f["content"] for f in files if isinstance(f["content"], str)]
    args = {"files": [[f["path"], len(f["content"]) if isinstance(f["content"], str) else None] for f in files]}
    args.update(extra or {})
    return ("js_flow", args, "".join(text))


def own_cases():
    two = [{"path": "lib.js", "content": LIB}, {"path": "app.js", "content": APP}]
    out = [call(two), call(two, {"run_limit": [0, 1]}), call(two, {"run_limit": [10 ** 12, 10 ** 12]}),
           call([{"path": "c.js", "content": "function (\n"}, {"path": "a.js", "content": None},
                 {"path": "b.d.ts", "content": None}] + two)]
    # the review's cases with a low limit for each reading
    out += [call(files, {"run_limit": [300, 4]}) for files in tpf.review_cases()]
    return out


def snapshot_sets():
    return {"js_flow": lambda: [call(files) for files in corpus()],
            "js_flow_configured": lambda: [call(files, model(taintspec.validate(CONFIG).javascript))
                                           for files in corpus()],
            "js_flow_calls": own_cases}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class JsFlowSnapshotTests(unittest.TestCase):
    maxDiff = None

    def check(self, name):
        calls = snapshot_sets()[name]()
        answers = _snapshots.run(calls)
        self.assertEqual([a for a in answers if "ok" not in a][:5], [])
        _snapshots.check(self, name, answers)
        outs = [a["ok"] for a in answers]
        for (_, args, _), out in zip(calls, outs):          # an issue names its file and the file's index
            for o in out:
                if o[0] == "issue":
                    self.assertEqual(args["files"][o[7]][0], o[2], o)
        return outs

    def test_the_default_model(self):
        outs = self.check("js_flow")
        kinds = collections.Counter((o[0], o[1] if o[0] != "skipped_size" else "") for out in outs for o in out)
        self.assertGreater(sum(kinds.values()), 2000)
        # not vacuous: every category, both notes, the size skip
        self.assertTrue({("issue", c) for c in CATS} | {("note", "Q-FLOW-SKIPPED"), ("note", "Q-FLOW-INCOMPLETE"),
                                                        ("skipped_size", "")} <= set(kinds), kinds)

    def test_a_configured_model(self):
        spec = taintspec.validate(CONFIG).javascript
        self.assertTrue(spec.sources and spec.sinks and spec.full and spec.partial)
        outs = self.check("js_flow_configured")
        default = [a["ok"] for a in _snapshots.run(snapshot_sets()["js_flow"]())]
        self.assertGreater(sum(len(o) for o in outs), 2000)
        self.assertGreater(sum(a != b for a, b in zip(outs, default)), 10)     # the model changes what is found

    def test_the_calls_own_cases(self):
        plain, low, high, not_text = self.check("js_flow_calls")[:4]
        self.assertEqual([o[:4] for o in plain], [["issue", "command injection", "app.js", 3]])
        self.assertEqual(high, plain)                       # a limit is lowered, never raised
        (note,) = low
        self.assertEqual(note[:5], ["note", "Q-FLOW-INCOMPLETE", "Flow analysis incomplete (size budget)", "lib.js", 1])
        self.assertIn("stopped reading runIt() in 'lib.js' at its limit of 0 + 1 steps per syntax tree node", note[5])
        self.assertEqual([(o[3], o[5]) for o in not_text if o[0] == "note"],
                         [("a.js", "Cross-file taint analysis skipped 'a.js': its content is not text."),
                          ("c.js", "Cross-file taint analysis skipped 'c.js': it could not be read as JavaScript "
                                   "(line 2: unexpected end of input).")])

    def test_bad_arguments_are_refused(self):
        for args in ({"files": [["a.js", 5]]}, {"files": [["a.js", 1]]}, {"files": "x"},
                     {"files": [["a.js", 3]], "sinks": [["x", "not a category"]]},
                     {"files": [["a.js", 3]], "run_limit": [1]}, {"files": [["a.js", 3]], "run_limit": [-1, 2]},
                     {"files": [["a.js", 3]], "run_limit": "x"}, {"files": [["a.js", None], ["b.js", 2]]}):
            with self.subTest(args=args), self.assertRaises(_native.NativeError):
                _native.call("js_flow", args, "abc")


if __name__ == "__main__":
    unittest.main()
