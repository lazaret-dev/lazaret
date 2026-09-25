import gzip
import http.server
import threading
import unittest
import xmlrpc.client
import xmlrpc.server
from datetime import datetime

import lazaret.safexml as sx
from lazaret.safexml import xmlrpc as safe_xmlrpc

from .payloads import BILLION_LAUGHS, XXE_FILE

RESPONSE = xmlrpc.client.dumps(({"name": "requests", "versions": ["2.32.3", "2.32.2"], "n": 7},),
                               methodresponse=True).encode()
ZIP_BOMB = (b"<methodResponse><params><param><value><string>" + b"A" * (40 * 1024 * 1024)
            + b"</string></value></param></params></methodResponse>")


def serve(server):
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}/"


def hostile_server(body, gzipped=False):
    payload = gzip.compress(body) if gzipped else body

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "text/xml")
            if gzipped:
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    return server, serve(server)


class LoadsTests(unittest.TestCase):
    def test_loads_matches_stdlib(self):
        self.assertEqual(safe_xmlrpc.loads(RESPONSE), xmlrpc.client.loads(RESPONSE))
        request = xmlrpc.client.dumps((1, "two"), "search")
        self.assertEqual(safe_xmlrpc.loads(request), xmlrpc.client.loads(request))

    def test_loads_refuses_attacks(self):
        for doc in (BILLION_LAUGHS, XXE_FILE):
            with self.subTest(doc=doc[:30]), self.assertRaises(sx.EntitiesForbidden):
                safe_xmlrpc.loads(doc)

    def test_loads_limits(self):
        deep = b"<methodResponse>" + b"<a>" * 600 + b"</a>" * 600 + b"</methodResponse>"
        with self.assertRaises(sx.LimitExceeded):
            safe_xmlrpc.loads(deep)
        with self.assertRaises(sx.LimitExceeded):
            safe_xmlrpc.loads(RESPONSE, max_bytes=50)
        self.assertEqual(safe_xmlrpc.DEFAULT_MAX_BYTES, 32 * 1024 * 1024)


class ServerProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.real = xmlrpc.server.SimpleXMLRPCServer(("127.0.0.1", 0), logRequests=False, allow_none=True)
        cls.real.register_function(lambda name: {"name": name, "releases": [1, 2, 3]}, "package_info")
        cls.real.register_function(lambda: datetime(2026, 9, 24, 12, 0), "now")
        cls.url = serve(cls.real)

    @classmethod
    def tearDownClass(cls):
        cls.real.shutdown()
        cls.real.server_close()

    def hostile(self, body, gzipped=False):
        server, url = hostile_server(body, gzipped)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return url

    def test_server_proxy_against_real_server(self):
        proxy = safe_xmlrpc.ServerProxy(self.url)
        self.assertEqual(proxy.package_info("requests"), {"name": "requests", "releases": [1, 2, 3]})
        self.assertEqual(safe_xmlrpc.ServerProxy(self.url, use_builtin_types=True).now(), datetime(2026, 9, 24, 12, 0))
        self.assertIsInstance(proxy._ServerProxy__transport, safe_xmlrpc.Transport)
        https = safe_xmlrpc.ServerProxy("https://pypi.org/pypi")
        self.assertIsInstance(https._ServerProxy__transport, safe_xmlrpc.SafeTransport)

    def test_server_proxy_refuses_entity_bomb(self):
        with self.assertRaises(sx.EntitiesForbidden):
            safe_xmlrpc.ServerProxy(self.hostile(BILLION_LAUGHS)).anything()

    def test_server_proxy_caps_decompressed_size(self):
        self.assertLess(len(gzip.compress(ZIP_BOMB)), 100_000)  # ~40 KB on the wire, 40 MB decompressed
        url = self.hostile(ZIP_BOMB, gzipped=True)
        with self.assertRaises(sx.LimitExceeded):
            safe_xmlrpc.ServerProxy(url, max_bytes=1_000_000).anything()
        with self.assertRaises(sx.LimitExceeded):
            safe_xmlrpc.ServerProxy(url).anything()  # default 32 MiB cap

    def test_server_proxy_argument_checks(self):
        with self.assertRaises(TypeError):
            safe_xmlrpc.ServerProxy(self.url, bogus=1)
        with self.assertRaises(TypeError):
            safe_xmlrpc.ServerProxy(self.url, transport=xmlrpc.client.Transport(), max_depth=5)
        with self.assertRaises(ValueError):
            safe_xmlrpc.Transport(max_depth=0)

    def test_monkey_patch_protects_stdlib(self):
        original = xmlrpc.client.ExpatParser
        try:
            safe_xmlrpc.monkey_patch()
            with self.assertRaises(sx.EntitiesForbidden):
                xmlrpc.client.loads(BILLION_LAUGHS)
            self.assertEqual(xmlrpc.client.ServerProxy(self.url).package_info("x")["name"], "x")
        finally:
            safe_xmlrpc.unmonkey_patch()
        self.assertIs(xmlrpc.client.ExpatParser, original)


if __name__ == "__main__":
    unittest.main()
