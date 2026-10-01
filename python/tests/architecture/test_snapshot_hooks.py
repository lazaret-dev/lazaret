"""The engine's answers on the hooks corpus (hooks_corpus.py: ~44,900
hand-written and seeded cases), held to their recorded outputs
(_snapshots.py): every field of hooks_view — shlex's tokens, the hook's
tokens, follow_hook, install_script_risk, import_time_risk (as written, and
read as Python and as JavaScript), node_candidates, the `node -e` codes,
shebang_lang, self_publish_at, runs_dll, join_string_pieces, decoded_view
and spawned_scripts.
"""
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots
from tests.architecture.hooks_corpus import corpus


def snapshot_sets():
    return {"hooks": lambda: [("hooks_view", {}, text) for text in corpus()]}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class HooksSnapshotTests(unittest.TestCase):
    def test_the_outputs_are_the_recorded_ones(self):
        answers = _snapshots.run(snapshot_sets()["hooks"]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, "hooks", answers)


if __name__ == "__main__":
    unittest.main()
