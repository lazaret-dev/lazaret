"""The npm package's engine is the native engine (see test_wasm_parity): the
WebAssembly build against the native library on the manifest readers, every
call of test_snapshot_manifest's sets (package.json and gyp files scanned with
their snippets redacted and not; json.loads, ast.literal_eval, where a key
is, the dependency-URL test and an expansion's command on their own; the data
--deps reads). Skipped where node, the WebAssembly build or the native library
is missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_snapshot_manifest import snapshot_sets
from tests.architecture.test_wasm_parity import both, differences


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmManifestParityTests(unittest.TestCase):
    maxDiff = None

    def test_every_set(self):
        calls = [[c, a, t] for make in snapshot_sets().values() for c, a, t in make()]
        wasm, native = both(calls)
        self.assertEqual(len(wasm), len(calls))
        self.assertEqual(differences(calls, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))                          # every call answered


if __name__ == "__main__":
    unittest.main()
