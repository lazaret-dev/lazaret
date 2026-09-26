"""Audit findings — lazaret.safexml.

8  xmlrpc: _discard_error_body trusted Content-Length, but http.client
   ignores it for a chunked body. A 500 reply declaring "Content-Length: 5"
   with a chunked body was read to its end (64 MiB in the audit) although
   ERROR_BODY_LIMIT is 8 KiB.

Servers are local (127.0.0.1) and send inert filler.
"""

import socket
import threading
import unittest
import xmlrpc.client

from lazaret.safexml import xmlrpc as safe_xmlrpc
from tests.safexml.test_review_xmlrpc_transport import RESPONSE, SENT_BOUND, Server

TOTAL = 32 * 1024 * 1024
CHUNK = 64 * 1024


class ChunkedLiar:
    """One-shot HTTP server: a 500 whose headers say Content-Length: 5 but
    whose body is chunked, TOTAL bytes of filler and then the last chunk.
    `sent` counts the bytes the client took before it hung up."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.url = "http://127.0.0.1:%d/RPC2" % self.sock.getsockname()[1]
        self.sent = 0
        self.done = threading.Event()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        conn, _ = self.sock.accept()
        try:
            buf = b""
            while b"\r\n\r\n" not in buf:
                buf += conn.recv(65536)
            head, body = buf.split(b"\r\n\r\n", 1)
            length = next(int(line.split(b":")[1]) for line in head.split(b"\r\n")
                          if line.lower().startswith(b"content-length"))
            while len(body) < length:
                body += conn.recv(65536)
            conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n"
                         b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n")
            chunk = b"%x\r\n" % CHUNK + b"A" * CHUNK + b"\r\n"
            while self.sent < TOTAL:
                conn.sendall(chunk)
                self.sent += CHUNK
            conn.sendall(b"0\r\n\r\n")
        except OSError:
            pass                              # the client hung up: expected
        finally:
            conn.close()
            self.sock.close()
            self.done.set()


class ErrorBodyTests(unittest.TestCase):
    def test_chunked_error_body_is_bounded_whatever_content_length_says(self):
        server = ChunkedLiar()
        proxy = safe_xmlrpc.ServerProxy(server.url)
        self.addCleanup(proxy("close"))
        with self.assertRaises(xmlrpc.client.ProtocolError) as info:
            proxy.system.listMethods()
        self.assertEqual(info.exception.errcode, 500)
        self.assertTrue(server.done.wait(20), "the server never finished sending")
        self.assertLess(server.sent, SENT_BOUND)

    def test_the_read_itself_is_bounded(self):
        class Response:
            calls = []

            def getheader(self, name, default=None):
                return "5" if name.lower() == "content-length" else default

            def read(self, amt=None):
                self.calls.append(amt)
                return b"A" * (amt if amt is not None else 1 << 20)

            def isclosed(self):
                return False
        response = Response()
        self.assertFalse(safe_xmlrpc._discard_error_body(response))
        self.assertEqual(response.calls, [safe_xmlrpc.ERROR_BODY_LIMIT + 1])

    def test_small_chunked_error_body_keeps_the_connection(self):
        server = Server([(500, [("Content-Length", "4"), ("Transfer-Encoding", "chunked")],
                          b"4\r\nnope\r\n0\r\n\r\n"),
                         (200, [("Content-Length", str(len(RESPONSE)))], RESPONSE)])
        self.addCleanup(server.close)
        proxy = safe_xmlrpc.ServerProxy(server.url)
        self.addCleanup(proxy("close"))
        with self.assertRaises(xmlrpc.client.ProtocolError):
            proxy.anything()
        self.assertEqual(proxy.anything(), xmlrpc.client.loads(RESPONSE)[0][0])
        self.assertEqual(server.ports[0], server.ports[1])


if __name__ == "__main__":
    unittest.main()
