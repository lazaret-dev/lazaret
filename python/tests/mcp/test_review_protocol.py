"""Review finding 18 b-e: the MCP server's protocol handling.

b. One request at a time on the reader thread: scan_directory on a big tree,
   then notifications/cancelled + ping -> no reply for 30 s. Tool calls now
   run on a worker thread; ping is answered while a scan runs, and a
   cancelled call stops between files and gets no response (MCP).
c. Malformed JSON got no reply (now -32700, id null); notifications were
   answered and an id-less tools/call executed (now: never answered, never
   executed); initialize echoed any protocolVersion (now negotiated); the
   frame-depth regex was quadratic on an unterminated string.
d. serverInfo.version is lazaret.__version__, not "1.0.0".
e. stdout carries protocol frames only.
"""

import io
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import lazaret
from lazaret.mcp import server
from tests import _support

PY = sys.executable


def run(lines, env=None, timeout=40, cmd=None):
    base = dict(os.environ)
    base["LAZARET_DB"] = os.path.join(tempfile.mkdtemp(prefix="lz-mcp-review-"), "r.db")
    base.update(env or {})
    p = subprocess.run(cmd or [PY, _support.MCP], input="\n".join(lines) + "\n", capture_output=True,
                       encoding="utf-8", errors="replace", timeout=timeout, env=base)
    return p, [json.loads(l) for l in p.stdout.splitlines() if l.strip()]


def req(msg_id, method, params=None):
    frame = {"jsonrpc": "2.0", "id": msg_id, "method": method}
    if params is not None:
        frame["params"] = params
    return json.dumps(frame)


def note(method, params=None):
    frame = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        frame["params"] = params
    return json.dumps(frame)


class FramingTests(unittest.TestCase):
    def test_malformed_json_gets_32700_with_null_id(self):
        p, frames = run(['{"jsonrpc":"2.0","id":2,"method":"ping"', req(3, "ping")])
        self.assertEqual(frames[0], {"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32700,
                                               "message": "Parse error: the frame is not valid JSON"}})
        self.assertEqual(frames[1]["id"], 3)

    def test_notifications_are_never_answered_or_executed(self):
        db = os.path.join(tempfile.mkdtemp(prefix="lz-mcp-review-"), "r.db")
        p, frames = run([note("ping"), note("tools/call", {"name": "registry_status", "arguments": {}}),
                         note("notifications/whatever", {"x": 1}), note("notifications/initialized"),
                         note("notifications/cancelled", {"requestId": 99}), req(7, "ping")],
                        env={"LAZARET_DB": db})
        self.assertEqual([f["id"] for f in frames], [7])
        self.assertFalse(os.path.exists(db), "an id-less tools/call must not run the tool")

    def test_invalid_ids_are_rejected(self):
        for frame in ('{"jsonrpc":"2.0","id":null,"method":"ping"}',
                      '{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}',
                      '{"jsonrpc":"2.0","id":true,"method":"ping"}'):
            with self.subTest(frame=frame):
                p, frames = run([frame, req(1, "ping")])
                self.assertEqual(frames[0]["error"]["code"], -32600)
                self.assertIsNone(frames[0]["id"])
                self.assertEqual(frames[1]["id"], 1)

    def test_string_ids_round_trip(self):
        p, frames = run([req("abc", "ping")])
        self.assertEqual(frames, [{"jsonrpc": "2.0", "id": "abc", "result": {}}])

    def test_depth_scan_is_linear(self):
        for line in ('["' + "a" * 41_000, "[" * 600 + '"' + "x[" * 200_000,
                     '[' + ",".join(['"\\"["'] * 100_000) + "]" + "[" * 600):
            t = time.perf_counter()
            server._frame_depth_exceeds(line)
            self.assertLess(time.perf_counter() - t, 1.0)
        self.assertFalse(server._frame_depth_exceeds('{"s":"' + '\\\\' * 3 + '"}' + "[" * 10))


class InitializeTests(unittest.TestCase):
    def init(self, version):
        params = {"capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}
        if version is not None:
            params["protocolVersion"] = version
        p, frames = run([req(1, "initialize", params)])
        return frames[0]["result"]

    def test_negotiation(self):
        self.assertEqual(self.init("2099-12-31")["protocolVersion"], server.SUPPORTED_PROTOCOL_VERSIONS[0])
        for v in server.SUPPORTED_PROTOCOL_VERSIONS:
            self.assertEqual(self.init(v)["protocolVersion"], v)
        self.assertEqual(self.init(None)["protocolVersion"], "2024-11-05")
        self.assertEqual(server.negotiate_protocol(7), server.SUPPORTED_PROTOCOL_VERSIONS[0])

    def test_server_version(self):
        self.assertEqual(self.init("2025-06-18")["serverInfo"],
                         {"name": "lazaret", "version": lazaret.__version__})


class StdoutTests(unittest.TestCase):
    def test_library_prints_never_reach_stdout(self):
        boot = ("import sys\nfrom lazaret.mcp import server\n"
                "def noisy(args):\n    print('noise from a tool')\n    return {'ok': True}\n"
                "server.HANDLERS['scan_snippet'] = noisy\nserver.main()\n")
        p, frames = run([req(1, "tools/call", {"name": "scan_snippet", "arguments": {}}), req(2, "ping")],
                        cmd=[PY, "-c", boot])
        self.assertEqual(sorted(f["id"] for f in frames), [1, 2])
        self.assertIn("noise from a tool", p.stderr)


class _Collector(io.StringIO):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()

    def frames(self):
        with self.lock:
            return [json.loads(l) for l in self.getvalue().splitlines() if l.strip()]


class WorkerTests(unittest.TestCase):
    """In process: a slow tool that checks for cancellation between steps."""

    def setUp(self):
        self.out = _Collector()
        patcher = mock.patch.object(server, "_OUT", self.out)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.started = threading.Event()

        def slow(args):
            self.started.set()
            for _ in range(400):
                server._ctx().check()
                time.sleep(0.01)
            return {"finished": True}
        patcher = mock.patch.dict(server.HANDLERS, {"slow": slow})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.srv = server.Server()
        self.addCleanup(self.srv.close, 10)

    def call(self, msg_id):
        self.srv.handle_line(req(msg_id, "tools/call", {"name": "slow", "arguments": {}}))

    def wait_for(self, msg_id, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for f in self.out.frames():
                if f.get("id") == msg_id:
                    return f
            time.sleep(0.01)
        return None

    def test_ping_is_answered_while_a_tool_runs(self):
        self.call(1)
        self.assertTrue(self.started.wait(5))
        t = time.monotonic()
        self.srv.handle_line(req(2, "ping"))
        self.assertIsNotNone(self.wait_for(2, 1))
        self.assertLess(time.monotonic() - t, 1)
        self.assertIsNone(self.wait_for(1, 0.05))          # still running

    def test_cancelled_call_stops_and_gets_no_reply(self):
        self.call(1)
        self.assertTrue(self.started.wait(5))
        self.srv.handle_line(note("notifications/cancelled", {"requestId": 1, "reason": "user"}))
        self.srv.close(5)
        self.assertFalse(self.srv.worker.is_alive(), "the cancelled call kept running")
        self.assertIsNone(self.wait_for(1, 0.1))

    def test_cancel_while_queued(self):
        self.call(1)
        self.call(2)
        self.srv.handle_line(note("notifications/cancelled", {"requestId": 2}))
        self.assertIsNotNone(self.wait_for(1, 10))
        self.srv.close(5)
        self.assertEqual([f.get("id") for f in self.out.frames()], [1])


class EndToEndCancelTests(unittest.TestCase):
    def test_scan_directory_cancel_and_ping(self):
        tree = tempfile.mkdtemp(prefix="lz-mcp-big-")
        self.addCleanup(shutil.rmtree, tree, True)
        body = "".join(f"def f{i}(x):\n    y = x + {i}\n    return str(y)\n" for i in range(100))
        for i in range(4000):
            with open(os.path.join(tree, f"m{i}.py"), "w", encoding="utf-8") as fh:
                fh.write(body)
        env = dict(os.environ, LAZARET_DB=os.path.join(tree, "r.db"))
        p = subprocess.Popen([PY, _support.MCP], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env)
        try:
            def send(line):
                p.stdin.write(line + "\n")
                p.stdin.flush()

            # a reader thread, not select(): select() takes only sockets on
            # Windows, where this test failed with WinError 10038
            lines = queue.Queue()

            def pump():
                try:
                    for line in p.stdout:
                        lines.put(line)
                except (OSError, ValueError):
                    pass
                lines.put(None)                   # EOF
            threading.Thread(target=pump, daemon=True).start()

            def recv(timeout):
                try:
                    line = lines.get(timeout=timeout)
                except queue.Empty:
                    return None
                return json.loads(line) if line else None

            send(req(1, "tools/call", {"name": "scan_directory", "arguments": {"path": tree}}))
            time.sleep(0.5)
            send(note("notifications/cancelled", {"requestId": 1, "reason": "test"}))
            send(req(2, "ping"))
            first = recv(10)
            self.assertEqual(first and first.get("id"), 2, first)
            t = time.monotonic()
            p.stdin.close()                       # the cancelled scan must stop, so we exit fast
            p.wait(timeout=15)
            self.assertLess(time.monotonic() - t, 15)
            rest = []
            while True:
                line = lines.get(timeout=15)
                if line is None:
                    break
                if line.strip():
                    rest.append(json.loads(line))
            self.assertEqual(rest, [], "a cancelled request must not be answered")
        finally:
            if p.poll() is None:
                p.kill()
            p.stdout.close()


if __name__ == "__main__":
    unittest.main()
