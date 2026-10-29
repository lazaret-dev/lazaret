"""The npm package's engine is the native engine (see test_wasm_parity): the
WebAssembly build against the native library on the package readers'
findings, every call of test_snapshot_readers' set (modules and crates read,
and their findings made, as a module's, a crate's and an sdist's, redacted
and not). Skipped where node, the WebAssembly build or the native library is
missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_snapshot_readers import snapshot_sets
from tests.architecture.test_wasm_parity import both, differences


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmReadersParityTests(unittest.TestCase):
    maxDiff = None

    def test_every_set(self):
        calls = [[c, a, t] for make in snapshot_sets().values() for c, a, t in make()]
        wasm, native = both(calls)
        self.assertEqual(len(wasm), len(calls))
        self.assertEqual(differences(calls, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))                          # every call answered


if __name__ == "__main__":
    unittest.main()
