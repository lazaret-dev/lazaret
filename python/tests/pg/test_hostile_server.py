"""A scripted fake server that misbehaves in specific ways. Each test checks
that the client refuses to continue rather than trusting the server."""

import base64
import socket
import struct
import threading
import unittest

from lazaret import pg


def msg(kind, payload=b""):
    return kind + struct.pack("!i", len(payload) + 4) + payload


def auth(code, extra=b""):
    return msg(b"R", struct.pack("!i", code) + extra)


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


class FakeServer:
    """Accepts one connection and runs script(conn, server)."""

    def __init__(self, script):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.received = []
        self.thread = threading.Thread(target=self._run, args=(script,), daemon=True)
        self.thread.start()

    def _run(self, script):
        conn, _ = self.sock.accept()
        conn.settimeout(5)
        try:
            script(conn, self)
        except OSError:
            pass
        finally:
            conn.close()
            self.sock.close()

    def read_startup(self, conn):
        length = struct.unpack("!i", recv_exact(conn, 4))[0]
        return recv_exact(conn, length - 4)

    def read_message(self, conn):
        kind = recv_exact(conn, 1)
        length = struct.unpack("!i", recv_exact(conn, 4))[0]
        body = recv_exact(conn, length - 4)
        self.received.append(kind)
        return kind, body


def connect(server, **kw):
    kw.setdefault("sslmode", "disable")
    return pg.connect(host="127.0.0.1", port=server.port, user="u", password="pw",
                      dbname="d", connect_timeout=5, **kw)


def scram_server(final_step):
    """Runs SCRAM up to the server-final stage, then calls final_step."""
    def script(conn, srv):
        srv.read_startup(conn)
        conn.sendall(auth(10, b"SCRAM-SHA-256\x00\x00"))
        _, body = srv.read_message(conn)
        client_first = body[body.index(b"\x00") + 5:].decode()
        client_nonce = client_first.split("r=")[1]
        salt = base64.b64encode(b"saltsalt").decode()
        conn.sendall(auth(11, f"r={client_nonce}SERVER,s={salt},i=4096".encode()))
        srv.read_message(conn)
        final_step(conn, srv)
    return script


def read_one_then_close(conn, srv):
    try:
        srv.read_message(conn)
    except OSError:
        pass


class HostileServerTests(unittest.TestCase):
    def test_auth_ok_without_scram_final_is_rejected(self):
        # A server that doesn't know the password skips proving it and just says "OK".
        srv = FakeServer(scram_server(lambda conn, srv: conn.sendall(auth(0))))
        with self.assertRaisesRegex(pg.AuthenticationError, "before completing SCRAM"):
            connect(srv)

    def test_forged_server_signature_is_rejected(self):
        forged = b"v=" + base64.b64encode(b"\x00" * 32)
        srv = FakeServer(scram_server(lambda conn, srv: conn.sendall(auth(12, forged) + auth(0))))
        with self.assertRaisesRegex(pg.AuthenticationError, "signature mismatch"):
            connect(srv)

    def test_cleartext_password_is_not_sent_without_tls(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(auth(3))  # AuthenticationCleartextPassword
            read_one_then_close(conn, srv)
        srv = FakeServer(script)
        with self.assertRaisesRegex(pg.AuthenticationError, "cleartext"):
            connect(srv)
        srv.thread.join(5)
        self.assertNotIn(b"p", srv.received)  # the password never left the client

    def test_require_auth_refuses_downgrade_to_md5(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(auth(5, b"salt"))
            read_one_then_close(conn, srv)
        srv = FakeServer(script)
        with self.assertRaisesRegex(pg.AuthenticationError, "require_auth"):
            connect(srv, require_auth="scram-sha-256")
        srv.thread.join(5)
        self.assertNotIn(b"p", srv.received)

    def test_require_auth_refuses_trust(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(auth(0))
        with self.assertRaisesRegex(pg.AuthenticationError, "'none'"):
            connect(FakeServer(script), require_auth="scram-sha-256")

    def test_channel_binding_require_without_tls(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(auth(10, b"SCRAM-SHA-256\x00\x00"))
        with self.assertRaisesRegex(pg.AuthenticationError, "channel_binding=require"):
            connect(FakeServer(script), channel_binding="require")

    def test_ssl_required_but_refused_by_server(self):
        def script(conn, srv):
            recv_exact(conn, 8)  # SSLRequest
            conn.sendall(b"N")
        with self.assertRaisesRegex(pg.OperationalError, "does not support SSL"):
            connect(FakeServer(script), sslmode="require")

    def test_absurd_message_length_is_rejected(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(b"R" + struct.pack("!i", 2**31 - 1))
        with self.assertRaisesRegex(pg.OperationalError, "invalid message length"):
            connect(FakeServer(script))

    def test_server_hangs_up_mid_message(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(b"R\x00\x00")
        with self.assertRaisesRegex(pg.OperationalError, "closed the connection"):
            connect(FakeServer(script))

    def test_unsupported_auth_method(self):
        def script(conn, srv):
            srv.read_startup(conn)
            conn.sendall(auth(7))  # GSSAPI
        with self.assertRaisesRegex(pg.AuthenticationError, "GSSAPI"):
            connect(FakeServer(script))


if __name__ == "__main__":
    unittest.main()
