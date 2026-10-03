"""The cross-file JavaScript taint pass in the WebAssembly build the npm
package ships (js/native/lazaret.wasm) against the native library, call for
call, byte for byte: `js_flow` on test_snapshot_js_flow.py's sets (its
corpus with the default and with a configured model, the call's own cases)
and on the deepest nesting of every construct the parser reads, in a file
whose request data the pass follows through it to a sink — the deepest
stack the pass takes, which the module's (8 MiB, rust/.cargo/config.toml)
must hold without trapping.

The calls go through test_wasm_parity_jsparse.py's Node script (each
answer's SHA-256). Skipped where node, the WebAssembly build (npm run build
in js/) or the native library is missing.
"""
import re
import unittest

from lazaret.scanner import _native
from tests.architecture import jsparse_cases as cases
from tests.architecture import test_snapshot_js_flow as snap
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_wasm_parity_jsparse import native_digests, wasm_digests

HEAD = "function run(c) { exec(c); }\napp.get('/x', (req, res) => { run(req.query.q); });\n"
X_RE = re.compile(r"\bx\b")


def deepest():
    """js_flow calls: each construct at the deepest depth the parser reads it
    (and one deeper), with request data at the bottom where the construct
    allows an expression there, after a route whose request data reaches a
    project function's sink."""
    calls = []
    for _name, path, make in cases.NESTINGS:
        ts, jsx = cases.dialect(path)

        def reads(src):
            return cases.native_json(src, ts, jsx).startswith('{"type"')
        data = reads(HEAD + X_RE.sub("req.query.q", make(1)))
        source = (lambda k: HEAD + X_RE.sub("req.query.q", make(k))) if data else (lambda k: HEAD + make(k))
        k = 1
        while k < 300 and reads(source(k + 1)):
            k += 1
        for depth in (k, k + 1):
            calls.append(snap.call([{"path": path, "content": source(depth)}]))
    return calls


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmFlowParityTests(unittest.TestCase):
    maxDiff = None

    def compare(self, calls):
        calls = [[name, args, text] for name, args, text in calls]
        wasm = wasm_digests(calls)
        native = native_digests(calls)
        self.assertEqual(len(wasm), len(calls))
        found = [(c[1].get("files"), c[2][:120], w, n) for c, w, n in zip(calls, wasm, native) if w != n][:5]
        self.assertEqual(found, [])
        return wasm

    def test_the_snapshot_sets(self):
        for name in ("js_flow", "js_flow_configured", "js_flow_calls"):
            with self.subTest(set=name):
                answers = self.compare(snap.snapshot_sets()[name]())
                self.assertFalse([a for a in answers if not a.startswith("0:")])

    def test_the_deepest_nesting_of_each_construct(self):
        calls = deepest()
        answers = self.compare(calls)
        self.assertFalse([a for a in answers if not a.startswith("0:")])
        # the pass read them: each deepest file has the route's flow, and none is skipped
        flows = [_native.call(*call) for call in calls[::2]]
        self.assertEqual([f for f in flows if not any(o[0] == "issue" for o in f)
                          or any(o[0] == "note" and o[1] == "Q-FLOW-SKIPPED" for o in f)], [])


if __name__ == "__main__":
    unittest.main()
