"""The Python parser in the WebAssembly build the npm package ships
(js/native/lazaret.wasm) against the native library, call for call, byte
for byte: `py_parse` (and with spans) on pyparse_cases.py's snippets, the
repository's Python, seeded programs and soups, and every construct that
nests at the deepest depth the parser reads and one deeper — the deepest
stack it takes, which the module's (8 MiB, rust/.cargo/config.toml) must
hold without trapping.

The calls go through test_wasm_parity_jsparse.py's Node script (answers
compared by their SHA-256, so that neither side parses JSON deeper than a
JSON reader allows). Python 3.13 is not needed: the two builds of the engine
are compared with each other. Skipped where node, the WebAssembly build (npm
run build in js/) or the native library is missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture import pyparse_cases as cases
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_wasm_parity_jsparse import native_digests, wasm_digests


def calls(sources, spans=False):
    return [["py_parse", {"spans": True} if spans else {}, src] for src in sources]


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmPythonParseParityTests(unittest.TestCase):
    maxDiff = None

    def compare(self, batch):
        wasm = wasm_digests(batch)
        native = native_digests(batch)
        self.assertEqual(len(wasm), len(batch))
        found = [(c[0], c[1], c[2][:120], w, n) for c, w, n in zip(batch, wasm, native) if w != n][:5]
        self.assertEqual(found, [])
        return wasm

    def test_every_nesting_at_its_deepest(self):
        """Each construct at the deepest depth the parser reads (the deepest
        stack) and one deeper, read the same, no trap."""
        sources = []
        for name, make, deepest in cases.NESTINGS:
            sources += [make(deepest), make(deepest + 1)]
        for name, make, engine, python in cases.STRICTER:
            sources += [make(engine), make(engine + 1)]
        answers = self.compare(calls(sources))
        self.assertFalse([a for a in answers if not a.startswith("0:")])
        self.compare(calls(sources[::2], spans=True))

    def test_snippets_and_sources(self):
        sources = cases.items() + cases.own_sources()
        self.compare(calls(sources))
        self.compare(calls(cases.items() + cases.own_sources()[:40], spans=True))

    def test_programs_and_soups(self):
        self.compare(calls(cases.programs(20261002, 120) + cases.soups(20261002, 3000)))


if __name__ == "__main__":
    unittest.main()
