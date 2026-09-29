"""Engine parity for following install hooks and the install-script and
import-time tests: the Rust engine (crates/lazaret-engine: hooks.rs,
signs.rs, received.rs, lexer.rs) against lazaret.scanner.core, on the hooks
parity corpus (hooks_corpus.py: ~29,800 hand-written and seeded cases, the
same the npm engine is held to), every field of core_view compared case by
case: shlex's tokens, _hook_tokens, follow_hook, install_script_risk,
import_time_risk (as written, and read as Python and as JavaScript),
node_candidates, the `node -e` codes, shebang_lang, self_publish_at,
runs_dll, join_string_pieces, decoded_view and spawned_scripts.

The Rust engine runs in a thread while core reads the cases (ctypes lets go
of the GIL during a call), so the suite takes the slower engine's time.
Skipped where the native library is not built.
"""
import threading
import unittest

from lazaret.scanner import _native
from tests.architecture.hooks_corpus import FIELDS, core_view, corpus

CHUNK = 1500                       # cases per call across the boundary


def rust_views(cases, box):
    """Each case's view from the Rust engine, into box["views"] (a thread)."""
    views = []
    try:
        for i in range(0, len(cases), CHUNK):
            calls = [["hooks_view", {}, text] for text in cases[i:i + CHUNK]]
            for r in _native.call("batch", {"calls": calls}):
                views.append(r.get("ok", r))
    except Exception as e:                            # reported by the test, not lost in the thread
        box["error"] = repr(e)
    box["views"] = views


def mismatches(cases, want, got, limit=20):
    """[(case, field, core's, Rust's)] for the first `limit` differences."""
    found = []
    for text, a, b in zip(cases, want, got):
        if not isinstance(b, list):
            found.append((text, "(call)", None, b))
        else:
            for field, x, y in zip(FIELDS, a, b):
                if x != y:
                    found.append((text, field, x, y))
        if len(found) >= limit:
            break
    return found


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RustHookParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus()
        box = {}
        worker = threading.Thread(target=rust_views, args=(cls.cases, box))
        worker.start()
        # as JSON carries them (tuples as lists)
        cls.want = [[list(x) if isinstance(x, tuple) else x for x in core_view(text)] for text in cls.cases]
        worker.join()
        cls.error = box.get("error")
        cls.got = box.get("views", [])

    def test_every_case_agrees(self):
        self.assertIsNone(self.error)
        self.assertEqual(len(self.got), len(self.cases))
        self.assertEqual(mismatches(self.cases, self.want, self.got), [])


if __name__ == "__main__":
    unittest.main()
