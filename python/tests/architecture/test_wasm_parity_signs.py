"""The npm package's engine is the native engine (see test_wasm_parity):
the WebAssembly build against the native library on every case of the hooks
corpus through signs_view, and on every file of the scan_file corpus and
half of this repository's through scan_file in dependency mode and
scan_rules. Skipped where node, the WebAssembly build or the native library
is missing.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture.hooks_corpus import corpus as hook_cases, shard
from tests.architecture.scanfile_corpus import corpus as file_cases
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP
from tests.architecture.test_rust_parity_scanfile import call_args, real_files
from tests.architecture.test_wasm_parity import both, differences


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmSignsParityTests(unittest.TestCase):
    maxDiff = None

    def test_the_hooks_corpus(self):
        calls = [["signs_view", {}, text] for text in shard(hook_cases())]
        wasm, native = both(calls)
        self.assertEqual(len(wasm), len(calls))
        self.assertEqual(differences(calls, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))                          # every call answered

    def test_files_in_both_modes(self):
        files = file_cases() + real_files()[::2]
        calls = []
        for path, text in files:
            args = call_args(path)
            calls.append(["scan_file", args, text])
            calls.append(["scan_rules", {k: v for k, v in args.items() if k != "dep"}, text])
        wasm, native = both(calls)
        self.assertEqual(len(wasm), len(calls))
        self.assertEqual(differences(calls, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))
        self.assertGreater(len(set(wasm)), len(files) // 2)                       # findings, not only silence


if __name__ == "__main__":
    unittest.main()
