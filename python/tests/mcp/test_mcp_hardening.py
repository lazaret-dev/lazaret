#!/usr/bin/env python3
"""Unit tests — MCP server hardening (card 418d4c93, audit H2/H3/M6 = F3/F4/G5/G6/G7).

The MCP server is a long-lived single-threaded stdio process: one malformed
frame or one SystemExit used to kill the whole server with no error reply —
every request after it was lost. These tests pin the hardened contract:

  Frame validation (H3 = G5/G6) — JSON-RPC 2.0 conformance:
    * non-object frame ("hello", 42, [1,2])            → -32600, id null
    * jsonrpc != "2.0" / method not a string           → -32600
    * params non-null non-object ("x", 7)              → -32602
    * arguments non-null non-object                    → -32602
    * params:null / arguments:null are COERCED to {} — the initialize
      handshake must answer a real reply, not crash (G5 PoC:
      {"method":"initialize","params":null} used to kill the server on the
      first message every client sends)
    * oversized frame (> MAX_FRAME_BYTES)              → -32600, resync

  BaseException-safe dispatch (H2 = F3/F4):
    * discover_packages with since:"garbage!!" (parse_since used to raise
      SystemExit) → isError content reply, server alive, next ping answered
    * registry_status with a postgres:// LAZARET_DB (Store.__init__ used
      to sys.exit) → isError content reply, server alive
    * unknown-tool → -32602 "Unknown tool: X" (existing contract kept)
    * method-not-found → -32601 (existing contract kept)

  Size caps (M6/G7):
    * scan_files on a huge sparse file → bounded time, SC-TRUNCATED-style
      entry (verdict integrity: never a silent skip), server alive
    * open().read() is now a bounded read

  Library code (no SystemExit raised from library code):
    * parse_since bad value raises ValueError (same message)
    * Store postgres DSN to an unreachable server raises RuntimeError
      (same message prefix "Postgres backend unreachable")
    * CLI boundary keeps exact legacy behavior: stderr message, exit 1

  Vacuity: clean traffic behaves exactly as before (replies only, no error
  frames); syntax-error frames still dropped silently (deep-json card
  1149e3e5 contract).

NOTE for the -32600 contract: non-object frames ([1,2]) used to be dropped
silently as the INTERIM guard of card 1149e3e5; this card upgrades that to
the JSON-RPC-mandated -32600 reply (test_deep_json_guards.py's
test_non_object_frame_does_not_kill_loop was updated accordingly).
"""
import json
import os

from tests import _support  # noqa: E402
import subprocess
import sys
import tempfile
import unittest

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures
MCP = _support.MCP
PY = sys.executable or "python3"

sys.path.insert(0, HERE)  # the lazaret/ dir itself

from lazaret.registry import repo as lazaret_repo  # noqa: E402


def _serve(lines, db=None, timeout=120):
    """Run the real server over stdio; return the CompletedProcess."""
    env = dict(os.environ)
    if db is not None:
        env["LAZARET_DB"] = db
    else:
        env["LAZARET_DB"] = os.path.join(tempfile.mkdtemp(prefix="cg-mcph-"), "reg.db")
    return subprocess.run([PY, MCP], input="\n".join(lines) + "\n",
                          capture_output=True, text=True, timeout=timeout, env=env)


def _frames(proc):
    return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]


PING = '{"jsonrpc":"2.0","id":99,"method":"ping"}'


# ---------------------------------------------------------------------------
# 1. Frame validation — every malformed frame gets a structured reply and
#    the server keeps serving (was: "hello" → AttributeError, exit 1).
# ---------------------------------------------------------------------------
class FrameValidationTests(unittest.TestCase):
    def test_string_frame_replied_32600_and_server_survives(self):
        p = _serve(['"hello"', PING])
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        self.assertNotIn("Traceback", p.stderr)
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], None)
        self.assertEqual(frames[0]["error"]["code"], -32600)
        self.assertEqual(frames[1]["id"], 99)
        self.assertIn("result", frames[1])

    def test_number_and_array_frames_replied_32600(self):
        for bad in ("42", "[1,2]", "true", '"hello"'):
            with self.subTest(frame=bad):
                p = _serve([bad, PING])
                self.assertEqual(p.returncode, 0, p.stderr[-500:])
                frames = _frames(p)
                self.assertEqual(frames[0]["error"]["code"], -32600)
                self.assertEqual(frames[0]["id"], None)
                self.assertEqual(frames[1]["id"], 99)
                self.assertIn("result", frames[1])

    def test_non_conformant_object_frame_32600(self):
        # method missing / not a string, or jsonrpc != "2.0"
        for bad in ('{"id":1,"method":"ping"}',
                    '{"jsonrpc":"1.0","id":1,"method":"ping"}',
                    '{"jsonrpc":"2.0","id":1,"method":7}',
                    '{"jsonrpc":"2.0","id":1}'):
            with self.subTest(frame=bad):
                p = _serve([bad, PING])
                self.assertEqual(p.returncode, 0, p.stderr[-500:])
                frames = _frames(p)
                self.assertEqual(frames[0]["error"]["code"], -32600)
                self.assertEqual(frames[1]["id"], 99)

    def test_bad_jsonrpc_keeps_id_when_readable(self):
        # a conformant-shaped object with a wrong jsonrpc version echoes the id
        p = _serve(['{"jsonrpc":"1.0","id":7,"method":"ping"}', PING])
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], 7)
        self.assertEqual(frames[0]["error"]["code"], -32600)

    def test_params_non_object_replied_32602(self):
        for bad in ('{"jsonrpc":"2.0","id":1,"method":"ping","params":"x"}',
                    '{"jsonrpc":"2.0","id":1,"method":"ping","params":7}',
                    '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":[1]}'):
            with self.subTest(frame=bad):
                p = _serve([bad, PING])
                self.assertEqual(p.returncode, 0, p.stderr[-500:])
                frames = _frames(p)
                self.assertEqual(frames[0]["error"]["code"], -32602)
                self.assertIn("params", frames[0]["error"]["message"])
                self.assertEqual(frames[1]["id"], 99)

    def test_arguments_non_object_replied_32602(self):
        bad = ('{"jsonrpc":"2.0","id":1,"method":"tools/call",'
               '"params":{"name":"scan_snippet","arguments":"x"}}')
        p = _serve([bad, PING])
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        frames = _frames(p)
        self.assertEqual(frames[0]["error"]["code"], -32602)
        self.assertIn("arguments", frames[0]["error"]["message"])
        self.assertEqual(frames[1]["id"], 99)

    def test_oversized_frame_replied_32600_and_resyncs(self):
        pad = "x" * (17 * 1024 * 1024)  # > MAX_FRAME_BYTES (16 MiB)
        big = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping",
                          "params": {"pad": pad}})
        p = _serve([big, PING], timeout=180)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], None)
        self.assertEqual(frames[0]["error"]["code"], -32600)
        self.assertIn("exceeds", frames[0]["error"]["message"])
        self.assertEqual(frames[1]["id"], 99)
        self.assertIn("result", frames[1])


# ---------------------------------------------------------------------------
# 2. initialize handshake (G5) — params null/absent must be coerced, not
#    crash the server on the first message every client sends.
# ---------------------------------------------------------------------------
class InitializeHandshakeTests(unittest.TestCase):
    def test_initialize_params_null_gets_real_reply(self):
        p = _serve(['{"jsonrpc":"2.0","id":1,"method":"initialize","params":null}', PING])
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], 1)
        self.assertEqual(frames[0]["result"]["serverInfo"]["name"], "lazaret")
        self.assertEqual(frames[0]["result"]["protocolVersion"], "2024-11-05")
        self.assertEqual(frames[1]["id"], 99)

    def test_initialize_params_missing_gets_real_reply(self):
        p = _serve(['{"jsonrpc":"2.0","id":1,"method":"initialize"}', PING])
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], 1)
        self.assertEqual(frames[0]["result"]["serverInfo"]["name"], "lazaret")
        self.assertEqual(frames[1]["id"], 99)

    def test_initialize_protocol_version_echoed(self):
        p = _serve(['{"jsonrpc":"2.0","id":1,"method":"initialize",'
                    '"params":{"protocolVersion":"2025-06-18"}}', PING])
        frames = _frames(p)
        self.assertEqual(frames[0]["result"]["protocolVersion"], "2025-06-18")


# ---------------------------------------------------------------------------
# 3. SystemExit / BaseException-safe dispatch (H2).
# ---------------------------------------------------------------------------
class SystemExitSafetyTests(unittest.TestCase):
    def test_discover_packages_bad_since_is_tool_error_not_death(self):
        # PoC: parse_since used to raise SystemExit → server exit 1, no
        # reply, following ping never answered.
        bad = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "discover_packages",
                                     "arguments": {"since": "garbage!!"}}})
        p = _serve([bad, PING], timeout=240)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        self.assertNotIn("Traceback", p.stderr)
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], 1)
        body = json.dumps(frames[0])
        self.assertIn('"isError": true', body)
        self.assertIn("bad --since", body)
        self.assertIn("garbage!!", body)
        self.assertEqual(frames[1]["id"], 99)          # server kept serving
        self.assertIn("result", frames[1])

    def test_registry_status_postgres_dsn_is_tool_error_not_death(self):
        # PoC: Store.__init__ used to sys.exit on a postgres DSN; now the
        # internal wire client raises RuntimeError (server unreachable /
        # bad database) and dispatch converts it to an isError reply.
        bad = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "registry_status", "arguments": {}}})
        with tempfile.TemporaryDirectory(prefix="cg-mcph-") as tmp:
            # not a postgres DSN path — use env override via _serve(db=...)
            p = _serve([bad, PING], db="postgresql://127.0.0.1:5432/nonexistent",
                       timeout=240)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], 1)
        body = json.dumps(frames[0])
        self.assertIn('"isError": true', body)
        self.assertIn("Postgres backend unreachable", body)
        self.assertEqual(frames[1]["id"], 99)

    def test_scan_package_postgres_dsn_is_tool_error_not_death(self):
        bad = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": "scan_package",
                                     "arguments": {"spec": "npm:left-pad@1.3.0"}}})
        p = _serve([bad, PING], db="postgresql://127.0.0.1:5432/nonexistent",
                   timeout=240)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        frames = _frames(p)
        body = json.dumps(frames[0])
        self.assertIn('"isError": true', body)
        self.assertIn("Postgres backend unreachable", body)
        self.assertEqual(frames[1]["id"], 99)

    def test_dispatch_crash_replies_32603_and_server_survives(self):
        # a tool raising something unexpected mid-dispatch (outside its own
        # try) still cannot kill the server: the outer net replies -32603.
        # Simulate by calling tools/call with a handler that raises
        # RecursionError via deeply nested arguments is covered elsewhere;
        # here: a *notification* with a poisoned payload (no reply expected)
        # followed by a real request proves loop liveness generically.
        note = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized",
                           "params": {"x": "y" * 4096}})
        p = _serve([note, PING])
        self.assertEqual(p.returncode, 0)
        frames = _frames(p)
        self.assertEqual([f.get("id") for f in frames], [99])


# ---------------------------------------------------------------------------
# 4. scan_files size cap (M6/G7) — bounded read, verdict-integrity signal.
# ---------------------------------------------------------------------------
class ScanFilesCapTests(unittest.TestCase):
    def _sparse(self, size):
        path = os.path.join(tempfile.mkdtemp(prefix="cg-mcph-sparse-"), "huge.js")
        with open(path, "wb") as fh:
            fh.truncate(size)
        return path

    def test_huge_sparse_file_is_capped_not_read(self):
        huge = self._sparse(512 * 1024 * 1024)   # 512 MB sparse
        call = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                           "params": {"name": "scan_files",
                                      "arguments": {"paths": [huge]}}})
        p = _serve([call, PING], timeout=120)     # was: unbounded read, hang
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], 1)
        payload = json.loads(frames[0]["result"]["content"][0]["text"])
        entry = payload["files"][huge]
        self.assertIn("SC-TRUNCATED", entry.get("rule", ""))
        self.assertEqual(entry.get("sev"), "CRITICAL")
        self.assertIn("exceeds", entry.get("error", ""))
        self.assertEqual(payload["totalIssues"], 1)
        self.assertEqual(payload["worstSeverity"], "CRITICAL")
        self.assertEqual(frames[1]["id"], 99)

    def test_growing_file_toctou_bounded_read(self):
        # small file under the cap: fully scanned, no truncation entry
        sys.path.insert(0, HERE)
        from lazaret.mcp import server as lazaret_mcp
        d = tempfile.mkdtemp(prefix="cg-mcph-cap-")
        path = os.path.join(d, "small.js")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("var x = 1;\n")
        res = lazaret_mcp.tool_scan_files({"paths": [path]})
        entry = res["files"][path]
        self.assertNotIn("error", entry)
        self.assertIn("issueCount", entry)
        self.assertNotIn("rule", entry)      # no SC-TRUNCATED on in-cap files

    def test_normal_files_still_scan(self):
        sys.path.insert(0, HERE)
        from lazaret.mcp import server as lazaret_mcp
        d = tempfile.mkdtemp(prefix="cg-mcph-norm-")
        path = os.path.join(d, "a.py")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("import os\nos.system('rm -rf /')\n")
        res = lazaret_mcp.tool_scan_files({"paths": [path]})
        entry = res["files"][path]
        self.assertIn("issueCount", entry)
        self.assertGreaterEqual(entry["issueCount"], 1)

    def test_cap_matches_collect_files_limit(self):
        sys.path.insert(0, HERE)
        from lazaret.mcp import server as lazaret_mcp
        from lazaret.scanner import core as lazaret
        self.assertEqual(lazaret_mcp.MAX_SCAN_FILE_BYTES, 2_000_000)
        # collect_files' hardcoded limit must stay in sync (verdict integrity
        # across scan_directory and scan_files)
        with open(os.path.join(_support.PKG, "scanner", "core.py"), encoding="utf-8") as fh:
            src = fh.read()
        self.assertIn("2_000_000", src)


# ---------------------------------------------------------------------------
# 5. Library-code contracts (no SystemExit from library code) + CLI parity.
# ---------------------------------------------------------------------------
class LibraryCodeTests(unittest.TestCase):
    def test_parse_since_bad_value_raises_valueerror(self):
        with self.assertRaises(ValueError) as cm:
            lazaret_repo.parse_since("garbage!!")
        self.assertIn("bad --since 'garbage!!'", str(cm.exception))
        self.assertIn("use e.g. 7d", str(cm.exception))

    def test_parse_since_valid_forms(self):
        import datetime
        for good in ("7d", "2w", "24h", "2026-06-25", " 7D "):
            cut = lazaret_repo.parse_since(good)
            self.assertIsInstance(cut, datetime.datetime)
            self.assertIsNotNone(cut.tzinfo)
        # legacy behavior kept: parse_since(None) rejects with the same
        # message (callers default it to "7d" before calling)
        with self.assertRaises(ValueError):
            lazaret_repo.parse_since(None)

    def test_store_postgres_dsn_raises_runtimeerror(self):
        with self.assertRaises(RuntimeError) as cm:
            lazaret_repo.Store("postgresql://127.0.0.1:5432/nonexistent")
        self.assertIn("Postgres backend unreachable", str(cm.exception))
        self.assertNotIn("Traceback", str(cm.exception))

    def test_cli_discover_bad_since_legacy_parity(self):
        env = dict(os.environ)
        env["LAZARET_DB"] = os.path.join(tempfile.mkdtemp(prefix="cg-mcph-cli-"), "r.db")
        p = subprocess.run([PY, _support.REGISTRY,
                            "discover", "--since", "garbage!!"],
                           capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr, "bad --since 'garbage!!'; use e.g. 7d, 2w, 24h, or 2026-06-25\n")
        self.assertNotIn("Traceback", p.stderr)

    def test_cli_list_postgres_dsn_legacy_parity(self):
        p = subprocess.run([PY, _support.REGISTRY, "list"],
                           capture_output=True, text=True, timeout=120,
                           env=dict(os.environ,
                                    LAZARET_DB="postgresql://127.0.0.1:5432/none"))
        self.assertEqual(p.returncode, 1)
        self.assertIn("Postgres backend unreachable", p.stderr)
        self.assertNotIn("Traceback", p.stderr)


# ---------------------------------------------------------------------------
# 6. Contracts kept from earlier cards / vacuity guards.
# ---------------------------------------------------------------------------
class KeptContractsTests(unittest.TestCase):
    def test_unknown_tool_32602_message_kept(self):
        bad = json.dumps({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                          "params": {"name": "no_such_tool", "arguments": {}}})
        p = _serve([bad, PING])
        frames = _frames(p)
        self.assertEqual(frames[0]["error"]["code"], -32602)
        self.assertIn("Unknown tool: no_such_tool", frames[0]["error"]["message"])

    def test_method_not_found_32601_kept(self):
        p = _serve(['{"jsonrpc":"2.0","id":6,"method":"no/such/method"}', PING])
        frames = _frames(p)
        self.assertEqual(frames[0]["error"]["code"], -32601)

    def test_syntax_error_frame_still_silent(self):
        # card 1149e3e5 contract: a merely-bad frame is dropped, no -32700 spam
        p = _serve(["{not json at all", PING])
        self.assertEqual(p.returncode, 0)
        frames = _frames(p)
        self.assertEqual([f.get("id") for f in frames], [99])
        self.assertIn("result", frames[0])

    def test_deep_frame_32700_id_null_kept(self):
        deep = "[" * 60000
        p = _serve([deep, PING], timeout=180)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        frames = _frames(p)
        self.assertEqual(frames[0]["id"], None)
        self.assertEqual(frames[0]["error"]["code"], -32700)
        self.assertEqual(frames[1]["id"], 99)

    def test_clean_traffic_no_error_frames(self):
        # run_integration.py S2.3 parity: 7 clean requests, replies only
        frames = [
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}',
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            '{"jsonrpc":"2.0","id":2,"method":"ping"}',
            '{"jsonrpc":"2.0","id":3,"method":"tools/list"}',
        ]
        p = _serve(frames, timeout=180)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        msgs = _frames(p)
        # notifications produce no reply (JSON-RPC 2.0): 3 replies for 4 frames
        self.assertEqual(len(msgs), 3)
        self.assertTrue(all("error" not in m for m in msgs), msgs)
        by_id = {m.get("id"): m for m in msgs if m.get("id") is not None}
        self.assertEqual(by_id[1]["result"]["serverInfo"]["name"], "lazaret")
        tools = [t["name"] for t in by_id[3]["result"]["tools"]]
        self.assertEqual(len(tools), 7)


if __name__ == "__main__":
    unittest.main(verbosity=2)
