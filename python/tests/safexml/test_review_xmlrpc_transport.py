"""The XML-RPC transports must not read unbounded response bodies.

Review finding: Transport/SafeTransport inherited the stdlib's
parse_response() and single_request(). A gzip-encoded reply went through
GzipDecodedResponse, which reads the whole compressed body into memory before
decompressing, and a non-200 reply's body was read in full to reuse the
connection. A 400 MB body took the client to 564 MB RSS with max_bytes=1 MB.
Now gzip bodies are decompressed as they are read, with the compressed size
capped too, and large or unknown-length error bodies are not read at all.
"""

import gzip
import http.server
import os
import threading
import unittest
import xmlrpc.client

import lazaret.safexml as sx
from lazaret.safexml import xmlrpc as safe_xmlrpc

RESPONSE = xmlrpc.client.dumps(({"name": "requests", "versions": ["2.32.3", "2.32.2"], "n": 7},),
                               methodresponse=True).encode()
CHUNK = 64 * 1024
CLAIMED = 64 * 1024 * 1024          # what the hostile server says it will send
SENT_BOUND = 16 * 1024 * 1024       # more than loopback socket buffers ever hold


class Server:
    """An HTTP/1.1 server that answers the n-th request with replies[n]:
    (status, headers, body), where body is bytes or a chunk to repeat until
    `CLAIMED` bytes are sent or the client goes away."""

    def __init__(self, replies):
        self.sent = []
        self.ports = []
        self.done = threading.Event()
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                outer.ports.append(self.client_address[1])
                status, headers, body = replies[min(len(outer.ports), len(replies)) - 1]
                self.send_response(status)
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
                sent = 0
                try:
                    if isinstance(body, bytes):
                        self.wfile.write(body)
                        sent = len(body)
                    else:
                        repeated = body()
                        while sent < CLAIMED:
                            self.wfile.write(repeated)
                            sent += len(repeated)
                except OSError:
                    self.close_connection = True
                finally:
                    outer.sent.append(sent)
                    outer.done.set()

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def empty_members():
    return gzip.compress(b"", mtime=0) * (CHUNK // 20)


def junk():
    return os.urandom(CHUNK)


class TransportTests(unittest.TestCase):
    def serve(self, *replies):
        server = Server(replies)
        self.addCleanup(server.close)
        return server

    def proxy(self, url, stdlib=False, **options):
        proxy = xmlrpc.client.ServerProxy(url) if stdlib else safe_xmlrpc.ServerProxy(url, **options)
        self.addCleanup(proxy("close"))
        return proxy

    def assert_stopped_early(self, server):
        self.assertTrue(server.done.wait(10), "the server never finished sending")
        self.assertLess(server.sent[0], SENT_BOUND)

    def test_large_error_body_is_not_read(self):
        server = self.serve((500, [("Content-Length", str(CLAIMED))], junk))
        proxy = self.proxy(server.url, max_bytes=1_000_000)
        with self.assertRaises(xmlrpc.client.ProtocolError) as info:
            proxy.anything()
        self.assertEqual(info.exception.errcode, 500)
        self.assert_stopped_early(server)

    def test_error_body_of_unknown_length_is_not_read(self):
        server = self.serve((502, [("Transfer-Encoding", "chunked")], b"4\r\nnope\r\n0\r\n\r\n"),
                            (200, [("Content-Length", str(len(RESPONSE)))], RESPONSE))
        proxy = self.proxy(server.url)
        with self.assertRaises(xmlrpc.client.ProtocolError):
            proxy.anything()
        self.assertEqual(proxy.anything(), xmlrpc.client.loads(RESPONSE)[0][0])  # reconnects

    def test_small_error_body_keeps_the_connection(self):
        server = self.serve((500, [("Content-Length", "4")], b"nope"),
                            (200, [("Content-Length", str(len(RESPONSE)))], RESPONSE))
        proxy = self.proxy(server.url)
        with self.assertRaises(xmlrpc.client.ProtocolError):
            proxy.anything()
        self.assertEqual(proxy.anything(), xmlrpc.client.loads(RESPONSE)[0][0])
        self.assertEqual(server.ports[0], server.ports[1])  # same connection, as with the stdlib

    def test_gzip_body_that_never_decompresses_is_capped(self):
        """Endless empty gzip members: nothing decompressed, so only the
        compressed-size cap can stop it."""
        server = self.serve((200, [("Content-Encoding", "gzip"), ("Content-Length", str(CLAIMED))], empty_members))
        with self.assertRaisesRegex(sx.LimitExceeded, "compressed response is larger"):
            self.proxy(server.url, max_bytes=1_000_000).anything()
        self.assert_stopped_early(server)

    def test_gzip_junk_is_refused_without_reading_it_all(self):
        server = self.serve((200, [("Content-Encoding", "gzip"), ("Content-Length", str(CLAIMED))], junk))
        with self.assertRaises(gzip.BadGzipFile):
            self.proxy(server.url, max_bytes=1_000_000).anything()
        self.assert_stopped_early(server)

    def test_gzip_responses_match_stdlib(self):
        packed = gzip.compress(RESPONSE, mtime=0)
        half = len(RESPONSE) // 2
        bodies = {
            "one member": packed,
            "two members": gzip.compress(RESPONSE[:half], mtime=0) + gzip.compress(RESPONSE[half:], mtime=0),
            "zero padding": packed + b"\0" * 100,
            "empty": b"",
            "truncated": packed[:-5],
            "trailing junk": packed + b"junk",
            "not gzip": RESPONSE,
        }
        for name, body in bodies.items():
            with self.subTest(body=name):
                reply = (200, [("Content-Encoding", "gzip"), ("Content-Length", str(len(body)))], body)
                server = self.serve(reply, reply)
                outcomes = []
                for proxy in (self.proxy(server.url), self.proxy(server.url, stdlib=True)):
                    try:
                        outcomes.append(("ok", proxy.anything()))
                    except Exception as exc:
                        outcomes.append(("error", type(exc)))
                self.assertEqual(outcomes[0], outcomes[1])
        self.assertEqual(outcomes[0][0], "error")


if __name__ == "__main__":
    unittest.main()
