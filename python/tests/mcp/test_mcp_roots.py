"""Audit I1: the MCP server's path tools default to the client's roots.

With LAZARET_MCP_ROOTS unset, scan_directory / scan_files / quality_gate
used to read any path the server's user could read, on the say-so of a
model that may have been steered by what it read. Now the server reads only
inside LAZARET_MCP_ROOTS or, when that is unset, inside the roots the client
shares (roots/list, asked after notifications/initialized and again on
notifications/roots/list_changed); a client that shares none gets a tool
error that says how to allow a directory. Tools that take no path, and
direct in-process calls, are unchanged.

Fixtures are inert text files in temporary directories.
"""
import atexit
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from lazaret.mcp import server
from tests import _support

PY = sys.executable


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-mcp-roots-")
    atexit.register(shutil.rmtree, root, True)
    for rel, body in files.items():
        with open(os.path.join(root, rel), "w", encoding="utf-8") as fh:
            fh.write(body)
    return root


def real(path):
    return os.path.normcase(os.path.realpath(path))


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


def init_params(roots):
    caps = {"roots": {"listChanged": True}} if roots else {}
    return {"protocolVersion": "2025-11-25", "capabilities": caps,
            "clientInfo": {"name": "roots-test", "version": "0"}}


def text_of(frame):
    return frame["result"]["content"][0]["text"]


class RootUriTests(unittest.TestCase):
    def test_file_uris_name_their_directory(self):
        spaced = tempfile.mkdtemp(prefix="lz mcp roots ")      # %20 in the URI
        self.addCleanup(shutil.rmtree, spaced, True)
        for path in (tree({}), spaced):
            uri = pathlib.Path(path).as_uri()
            self.assertEqual(server.root_path_of_uri(uri), real(path))
            if os.name != "nt":
                self.assertEqual(server.root_path_of_uri("file://localhost" + uri[7:]), real(path))

    def test_anything_else_is_not_a_root(self):
        bad = [None, 42, {"uri": "file:///"}, "", "file:", "file:relative/dir",
               "https://example.invalid/project", "git+file:///tmp", "file:///tmp/\x00x",
               "file:///" + "a" * 9000, "file://[::1/tmp"]
        if os.name != "nt":
            bad.append("file://fileserver.invalid/share")        # a remote host
        for uri in bad:
            with self.subTest(uri=str(uri)[:40]):
                self.assertIsNone(server.root_path_of_uri(uri))


class _Collector(io.StringIO):
    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()

    def write(self, s):
        with self.lock:
            return super().write(s)

    def frames(self):
        with self.lock:
            return [json.loads(l) for l in self.getvalue().splitlines() if l.strip()]


class ServerRootsTests(unittest.TestCase):
    """In process, against a Server whose stdout is captured."""

    def setUp(self):
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("LAZARET_MCP_ROOTS", None)
        self.out = _Collector()
        out = mock.patch.object(server, "_OUT", self.out)
        out.start()
        self.addCleanup(out.stop)
        self.a = tree({"a.py": "x = 1\n"})
        self.b = tree({"b.py": "y = 2\n"})
        self.srv = server.Server()
        self.addCleanup(self.srv.close, 10)

    # ---- helpers ----
    def send(self, line):
        self.srv.handle_line(line)

    def initialize(self, roots=True, initialized=True):
        self.send(req(0, "initialize", init_params(roots)))
        self.assertIsNotNone(self.wait_for(lambda f: f.get("id") == 0))
        if initialized:
            self.send(note("notifications/initialized"))

    def wait_for(self, pred, timeout=10):
        end = time.monotonic() + timeout
        while True:
            for f in self.out.frames():
                if pred(f):
                    return f
            if time.monotonic() >= end:
                return None
            time.sleep(0.01)

    def roots_request(self, seen=(), timeout=10):
        return self.wait_for(lambda f: f.get("method") == "roots/list" and f["id"] not in seen,
                             timeout)

    def answer(self, request, *paths, error=False):
        if error:
            frame = {"jsonrpc": "2.0", "id": request["id"],
                     "error": {"code": -32601, "message": "Method not found"}}
        else:
            frame = {"jsonrpc": "2.0", "id": request["id"], "result": {"roots": [
                {"uri": p if "://" in p else pathlib.Path(p).as_uri(), "name": "r"} for p in paths]}}
        self.send(json.dumps(frame))

    def call(self, msg_id, name, args, timeout=20):
        self.send(req(msg_id, "tools/call", {"name": name, "arguments": args}))
        frame = self.wait_for(lambda f: f.get("id") == msg_id, timeout)
        self.assertIsNotNone(frame, f"no reply to {name}")
        return frame

    def assertAllowed(self, frame):
        self.assertNotIn("isError", frame["result"], text_of(frame)[:300])
        self.assertIn("qualityGate", text_of(frame))

    def assertRefused(self, frame, *needles):
        self.assertTrue(frame["result"].get("isError"), text_of(frame)[:300])
        for needle in needles:
            self.assertIn(needle, text_of(frame))

    # ---- tests ----
    def test_client_roots_allow_their_directories_only(self):
        self.initialize()
        self.answer(self.roots_request(), self.a)
        self.assertAllowed(self.call(1, "quality_gate", {"path": self.a}))
        self.assertAllowed(self.call(2, "scan_directory", {"path": self.a}))
        outside = "outside the allowed roots (the roots your MCP client shared)"
        self.assertRefused(self.call(3, "quality_gate", {"path": self.b}), outside)
        self.assertRefused(self.call(4, "scan_directory", {"path": self.b}), outside)
        self.assertRefused(self.call(5, "scan_files", {"paths": [
            os.path.join(self.a, "a.py"), os.path.join(self.b, "b.py")]}), outside)

    def test_a_change_of_roots_is_followed(self):
        self.initialize()
        first = self.roots_request()
        self.answer(first, self.a)
        self.assertAllowed(self.call(1, "quality_gate", {"path": self.a}))
        self.send(note("notifications/roots/list_changed"))
        second = self.roots_request(seen={first["id"]})
        self.assertIsNotNone(second, "list_changed must ask again")
        self.answer(second, self.b)
        self.assertAllowed(self.call(2, "quality_gate", {"path": self.b}))
        self.assertRefused(self.call(3, "quality_gate", {"path": self.a}), "outside the allowed roots")

    def test_a_client_that_shares_no_roots_gets_path_tools_refused(self):
        self.initialize(roots=False)
        refused = ("no directory may be scanned",
                   "the MCP client does not share its workspace roots", "Set LAZARET_MCP_ROOTS")
        self.assertRefused(self.call(1, "scan_directory", {"path": self.a}), *refused)
        self.assertRefused(self.call(2, "quality_gate", {"path": self.a}), *refused)
        self.assertRefused(self.call(3, "scan_files", {"paths": [os.path.join(self.a, "a.py")]}),
                           *refused)
        snippet = self.call(4, "scan_snippet", {"code": "x = 1\n", "language": "py"})
        self.assertNotIn("isError", snippet["result"])       # no path: unaffected
        self.assertIsNone(self.roots_request(timeout=0), "roots/list sent to a client without roots")

    def test_no_handshake_at_all_is_refused_too(self):
        self.assertRefused(self.call(1, "quality_gate", {"path": self.a}),
                           "does not share its workspace roots")

    def test_an_error_or_an_answer_with_no_file_roots_refuses(self):
        self.initialize()
        first = self.roots_request()
        self.answer(first, error=True)
        self.assertRefused(self.call(1, "quality_gate", {"path": self.a}),
                           "answered roots/list with an error", "Set LAZARET_MCP_ROOTS")
        self.send(note("notifications/roots/list_changed"))
        second = self.roots_request(seen={first["id"]})
        self.answer(second, "https://example.invalid/project")
        self.assertRefused(self.call(2, "quality_gate", {"path": self.a}),
                           "shared no file: roots")
        self.send(note("notifications/roots/list_changed"))
        third = self.roots_request(seen={first["id"], second["id"]})
        self.send(json.dumps({"jsonrpc": "2.0", "id": third["id"], "result": {"roots": "nope"}}))
        self.assertRefused(self.call(3, "quality_gate", {"path": self.a}),
                           "answered roots/list with an error")

    def test_an_unanswered_request_is_waited_for_once(self):
        with mock.patch.object(server, "ROOTS_WAIT_SECONDS", 0.3):
            self.initialize()
            request = self.roots_request()
            t = time.monotonic()
            self.assertRefused(self.call(1, "quality_gate", {"path": self.a}),
                               "did not answer roots/list within 0.3 s")
            self.assertGreaterEqual(time.monotonic() - t, 0.3)
            t = time.monotonic()
            self.assertRefused(self.call(2, "quality_gate", {"path": self.a}), "did not answer")
            self.assertLess(time.monotonic() - t, 0.3, "a second call waited again")
            self.answer(request, self.a)                      # a late answer still counts
            self.assertAllowed(self.call(3, "quality_gate", {"path": self.a}))

    def test_only_the_latest_request_counts(self):
        with mock.patch.object(server, "ROOTS_WAIT_SECONDS", 0.3):
            self.initialize()
            first = self.roots_request()
            self.send(note("notifications/roots/list_changed"))
            second = self.roots_request(seen={first["id"]})
            self.answer(first, self.a)                        # stale: ignored
            self.assertRefused(self.call(1, "quality_gate", {"path": self.a}), "did not answer")
            self.answer(second, self.b)
            self.assertAllowed(self.call(2, "quality_gate", {"path": self.b}))
            self.assertRefused(self.call(3, "quality_gate", {"path": self.a}), "outside")

    def test_the_first_path_asks_when_initialized_never_came(self):
        self.initialize(initialized=False)
        self.assertIsNone(self.roots_request(timeout=0.2))
        self.send(req(1, "tools/call", {"name": "quality_gate", "arguments": {"path": self.a}}))
        request = self.roots_request()
        self.assertIsNotNone(request, "the call must ask for roots")
        self.answer(request, self.a)
        frame = self.wait_for(lambda f: f.get("id") == 1)
        self.assertAllowed(frame)

    def test_a_call_waiting_for_roots_can_be_cancelled(self):
        self.initialize()
        self.assertIsNotNone(self.roots_request())
        self.send(req(1, "tools/call", {"name": "quality_gate", "arguments": {"path": self.a}}))
        time.sleep(0.2)
        self.send(note("notifications/cancelled", {"requestId": 1, "reason": "test"}))
        self.send(req(2, "ping"))
        self.assertEqual(self.wait_for(lambda f: f.get("id") == 2)["result"], {})
        t = time.monotonic()
        self.srv.close(5)
        self.assertFalse(self.srv.worker.is_alive())
        self.assertLess(time.monotonic() - t, 5)
        self.assertIsNone(self.wait_for(lambda f: f.get("id") == 1, 0.1),
                          "a cancelled call must not be answered")

    def test_lazaret_mcp_roots_wins_and_nothing_is_asked(self):
        os.environ["LAZARET_MCP_ROOTS"] = self.b
        self.initialize()
        self.assertAllowed(self.call(1, "quality_gate", {"path": self.b}))
        self.assertRefused(self.call(2, "quality_gate", {"path": self.a}),
                           "outside the allowed roots (LAZARET_MCP_ROOTS)")
        self.send(note("notifications/roots/list_changed"))
        self.assertIsNone(self.roots_request(timeout=0.2), "roots/list sent though the variable is set")

    def test_responses_are_never_answered(self):
        self.initialize()
        request = self.roots_request()
        before = len(self.out.frames())
        for frame in ({"jsonrpc": "2.0", "id": "someone-else", "result": {}},
                      {"jsonrpc": "2.0", "id": 7, "error": {"code": 1, "message": "x"}},
                      {"jsonrpc": "2.0", "id": None, "result": {"roots": []}}):
            self.send(json.dumps(frame))
        self.send(req(9, "ping"))
        self.assertIsNotNone(self.wait_for(lambda f: f.get("id") == 9))
        self.assertEqual(len(self.out.frames()), before + 1, "a response frame was answered")
        self.answer(request, self.a)                          # still pending, still counts
        self.assertAllowed(self.call(1, "quality_gate", {"path": self.a}))
        before = len(self.out.frames())
        self.answer(request, self.b)                          # answered twice: ignored
        self.assertRefused(self.call(2, "quality_gate", {"path": self.b}), "outside")
        self.assertEqual(len(self.out.frames()), before + 1)


class StdioRootsTests(unittest.TestCase):
    """The real server over stdio, as a client that shares roots drives it."""

    def test_the_server_asks_the_client_for_its_roots(self):
        inside, outside = tree({"a.py": "x = 1\n"}), tree({"b.py": "y = 2\n"})
        env = dict(os.environ, LAZARET_DB=os.path.join(inside, "r.db"))
        env.pop("LAZARET_MCP_ROOTS", None)
        p = subprocess.Popen([PY, _support.MCP], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, bufsize=1, env=env,
                             encoding="utf-8", errors="replace")
        lines = []

        def pump():
            for line in p.stdout:
                if line.strip():
                    lines.append(json.loads(line))
        reader = threading.Thread(target=pump, daemon=True)
        reader.start()

        def send(line):
            p.stdin.write(line + "\n")
            p.stdin.flush()

        def wait_for(pred, timeout=30):
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                for f in list(lines):
                    if pred(f):
                        return f
                time.sleep(0.02)
            self.fail(f"no matching frame in {lines}")

        try:
            send(req(0, "initialize", init_params(roots=True)))
            wait_for(lambda f: f.get("id") == 0)
            send(note("notifications/initialized"))
            request = wait_for(lambda f: f.get("method") == "roots/list")
            send(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": {
                "roots": [{"uri": pathlib.Path(inside).as_uri(), "name": "project"}]}}))
            send(req(1, "tools/call", {"name": "quality_gate", "arguments": {"path": inside}}))
            send(req(2, "tools/call", {"name": "quality_gate", "arguments": {"path": outside}}))
            ok, refused = wait_for(lambda f: f.get("id") == 1), wait_for(lambda f: f.get("id") == 2)
            self.assertNotIn("isError", ok["result"], text_of(ok)[:300])
            self.assertTrue(refused["result"].get("isError"))
            self.assertIn("outside the allowed roots", text_of(refused))
            p.stdin.close()
            p.wait(timeout=30)
            self.assertEqual(p.returncode, 0)
        finally:
            if p.poll() is None:
                p.kill()
            reader.join(5)
            p.stdout.close()


if __name__ == "__main__":
    unittest.main()
