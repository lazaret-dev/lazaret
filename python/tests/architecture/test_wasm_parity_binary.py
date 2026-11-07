"""The npm package's engine is the native engine (see test_wasm_parity): the
WebAssembly build against the native library on binaries, bytecode and .pth
files, every call of test_snapshot_binary's sets (byte samples tested for
text, transport streams and programs, classified and checked for a program
under a source file's name, bytecode headers, .pth files redacted and not).
Skipped where node, the WebAssembly build or the native library is missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_snapshot_binary import snapshot_sets
from tests.architecture.test_wasm_parity import both, differences


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmBinaryParityTests(unittest.TestCase):
    maxDiff = None

    def test_every_set(self):
        calls = [[c, a, t] for make in snapshot_sets().values() for c, a, t in make()]
        wasm, native = both(calls)
        self.assertEqual(len(wasm), len(calls))
        self.assertEqual(differences(calls, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))                          # every call answered


if __name__ == "__main__":
    unittest.main()
