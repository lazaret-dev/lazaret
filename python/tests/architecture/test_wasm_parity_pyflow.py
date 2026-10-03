"""The cross-file Python taint pass in the WebAssembly build the npm package
ships (js/native/lazaret.wasm) against the native library, call for call,
byte for byte: `py_flow` on test_snapshot_py_flow.py's sets (its corpus with
the default and with a configured model, the call's own cases) and on the
deepest nesting of every construct the parser reads (pyparse_cases.NESTINGS)
as a module's code beside a flow across two files — the deepest stacks the
parser and the pass take, which the module's (8 MiB, rust/.cargo/
config.toml) must hold without trapping.

The calls go through test_wasm_parity_jsparse.py's Node script (each
answer's SHA-256). Skipped where node, the WebAssembly build (npm run build
in js/) or the native library is missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture import pyparse_cases as cases
from tests.architecture import test_snapshot_py_flow as snap
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_wasm_parity_jsparse import native_digests, wasm_digests


ELIF = lambda k: "if a: pass\n" + "elif b: pass\n" * k      # noqa: E731


def deepest():
    """py_flow calls: each construct at the deepest depth the parser reads it
    and one deeper, and `elif` chains at the frames the pass holds (as
    flow.py from the `lazaret` command: 493 are read, a reading of 494 stops;
    a module of 991 has its definitions collected, one of 992 does not), as
    the code of a module beside a flow from a route into another file's
    sink."""
    flow = snap.files(("runner.py", snap.RUNNER), ("view.py", snap.VIEW))
    sources = [make(k) for _name, make, depth in cases.NESTINGS for k in (depth, depth + 1)]
    sources += [ELIF(k) for k in (493, 494, 991, 992)]
    return [snap.call(flow + snap.files(("deep.py", src + "\n"))) for src in sources]


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmPyFlowParityTests(unittest.TestCase):
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
        for name in ("py_flow", "py_flow_configured", "py_flow_calls"):
            with self.subTest(set=name):
                answers = self.compare(snap.snapshot_sets()[name]())
                self.assertFalse([a for a in answers if not a.startswith("0:")])

    def test_the_deepest_nesting_of_each_construct(self):
        calls = deepest()
        answers = self.compare(calls)
        self.assertFalse([a for a in answers if not a.startswith("0:")])
        # the pass read them: every set has the route's flow, and the deepest
        # file is never skipped as unreadable at the depth the parser reads
        outs = [_native.call(*call) for call in calls]
        self.assertEqual([k for k, out in enumerate(outs) if not any(o[0] == "issue" for o in out)], [])
        self.assertEqual([k for k, out in enumerate(outs[:2 * len(cases.NESTINGS):2])
                          if any(o[0] == "note" and o[1] == "Q-FLOW-SKIPPED" for o in out)], [])
        # the chains: read, then the module's code past its frames, then its definitions too
        notes = [[(o[1], o[3], o[4]) for o in out if o[0] == "note"] for out in outs[2 * len(cases.NESTINGS):]]
        self.assertEqual(notes, [[]] + [[("Q-FLOW-RECURSION", "deep.py", 1)]] * 3)


if __name__ == "__main__":
    unittest.main()
