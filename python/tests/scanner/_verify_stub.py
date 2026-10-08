"""A stub provider for the secret-verification tests (0.1.9, V-1 stage 1): one TLS server on 127.0.0.1 that answers as scripted
for any of the providers' hosts, and a CONNECT proxy in front of it.

The tests make no call to a real service. The server's certificate is made when a test class starts, with the `openssl`
command (a throw-away key, valid two days, in a temporary folder, for the providers' hosts); where there is no `openssl` the
tests that need the server are skipped. The client trusts that certificate and connects to the stub's port in place of 443, the
host's name still being what the certificate is checked for, so what is tested is the code a real call runs: https, the host
checked, the headers, no redirect, the size and time limits.

    stub = ProviderStub()           # (in setUpClass)
    stub.script["api.github.com", "/user"] = Answer(200, b'{"login": "octocat"}')
    send = stub.transport()         # a `secretverify_http` transport that reaches the stub
    stub.requests                   # what it was asked: [Seen(method, host, path, headers, body)]
"""

import collections
import http.server
import os
import shutil
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time

from lazaret.scanner import secretverify as verify
from lazaret.scanner import secretverify_http as http_mod

Seen = collections.namedtuple("Seen", "method host path headers body")


class Answer:
    """What the stub says: a status, headers, a body; `delay` seconds before it answers; `drip` seconds between the bytes of it
    (a server that is too slow); `huge` bytes of body in place of `body`; `close` to hang up with no answer; `claim` a Content-Length
    that is not the body's (a server that hangs up before it has sent what it promised); `pause` (bytes, seconds): stops for that
    long once it has sent that many bytes of the body (a server that goes quiet in the middle)."""

    def __init__(self, status=200, body=b"", headers=None, delay=0.0, drip=0.0, huge=0, close=False, claim=None, pause=None):
        self.status, self.body, self.headers = status, body, dict(headers or {})
        self.delay, self.drip, self.huge, self.close, self.claim, self.pause = delay, drip, huge, close, claim, pause


def hosts():
    """The providers' hosts (the engine's table: secretverify.PROVIDERS)."""
    return sorted({p["host"] for p in verify.PROVIDERS})


def have_openssl():
    return shutil.which("openssl") is not None


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _serve(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        host = (self.headers.get("Host") or "").lower()
        stub = self.server.stub
        seen = Seen(self.command, host, self.path, {k.lower(): v for k, v in self.headers.items()}, body)
        with stub.lock:
            stub.requests.append(seen)
        answer = stub.script.get((host, self.path.split("?")[0])) or stub.script.get(host) or Answer(404, b"not found")
        if callable(answer):
            answer = answer(seen)
        if answer.delay:
            time.sleep(answer.delay)
        if answer.close:
            self.close_connection = True
            return
        body = b"x" * answer.huge if answer.huge else answer.body
        self.send_response(answer.status)
        for name, value in answer.headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body) if answer.claim is None else answer.claim))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            if answer.drip:
                for i in range(len(body)):
                    self.wfile.write(body[i:i + 1])
                    self.wfile.flush()
                    time.sleep(answer.drip)
            elif answer.pause:
                after, seconds = answer.pause
                self.wfile.write(body[:after])
                self.wfile.flush()
                time.sleep(seconds)
                self.wfile.write(body[after:])
            else:
                self.wfile.write(body)
        except OSError:
            pass

    do_GET = do_POST = _serve


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    context = None

    def get_request(self):
        sock, address = self.socket.accept()
        return self.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address   # (shaken hands in its own thread)

    def handle_error(self, request, client_address):
        pass                                              # (a client that hangs up is part of what is tested)


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        proxy = self.server.proxy
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            block = self.request.recv(4096)
            if not block:
                return
            data += block
        head = data.split(b"\r\n\r\n")[0].decode("latin-1")
        line, *header_lines = head.split("\r\n")
        headers = {h.split(":", 1)[0].lower(): h.split(":", 1)[1].strip() for h in header_lines if ":" in h}
        with proxy.lock:
            proxy.requests.append((line, headers))
        method, target, _ = line.split(" ", 2)
        if method != "CONNECT":
            self.request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            return
        if proxy.require and headers.get("proxy-authorization") != proxy.require:
            self.request.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            return
        if proxy.refuse:
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        upstream = socket.create_connection(("127.0.0.1", proxy.port), 5)
        self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        done = threading.Event()

        def pump(src, dst):
            try:
                while True:
                    block = src.recv(8192)
                    if not block:
                        break
                    dst.sendall(block)
            except OSError:
                pass
            finally:
                done.set()

        for pair in ((self.request, upstream), (upstream, self.request)):
            threading.Thread(target=pump, args=pair, daemon=True).start()
        done.wait(15)
        upstream.close()


class _ProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        pass


class StubProxy:
    """A CONNECT proxy that tunnels to the stub. `require` is the Proxy-Authorization value it wants; `refuse` makes it answer 403."""

    def __init__(self, port, require=None):
        self.port, self.require, self.refuse = port, require, False
        self.requests, self.lock = [], threading.Lock()
        self._server = _ProxyServer(("127.0.0.1", 0), _ProxyHandler)
        self._server.proxy = self
        self.address = self._server.server_address
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class ProviderStub:
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="lazaret-stub-")
        self.cert, key = os.path.join(self.dir, "cert.pem"), os.path.join(self.dir, "key.pem")
        san = ",".join(f"DNS:{h}" for h in hosts())
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", key,
                        "-out", self.cert, "-days", "2", "-subj", "/CN=lazaret-stub", "-addext", f"subjectAltName={san}",
                        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,digitalSignature,keyCertSign"],
                       check=True, capture_output=True, timeout=30)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(self.cert, key)
        self.script, self.requests, self.lock = {}, [], threading.Lock()
        self._server = _Server(("127.0.0.1", 0), _Handler)
        self._server.context = server_ctx
        self._server.stub = self
        self.address = self._server.server_address
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self._proxies = []

    def client_context(self):
        return ssl.create_default_context(cafile=self.cert)

    def transport(self, environ=None, direct=True):
        """A transport that reaches this stub: straight to its port (`direct`), or, with `environ` holding proxy settings, through them."""
        return http_mod.https_transport(self.client_context(), self.address if direct else None, environ if environ is not None else {})

    def proxy(self, require=None):
        proxy = StubProxy(self.address[1], require)
        self._proxies.append(proxy)
        return proxy

    def reset(self):
        with self.lock:
            self.requests.clear()
        self.script.clear()

    def close(self):
        for proxy in self._proxies:
            proxy.close()
        self._server.shutdown()
        self._server.server_close()
        shutil.rmtree(self.dir, ignore_errors=True)
