"""LZ-02 (the external security report of Oct 27; CWE-918, server-side request forgery): where a redirect off the hosts
a fetch was given may lead. A Go module proxy may send a zip on to its storage, any https host, so the Go guard's
fetcher (`https_redirects`) let a redirect go anywhere: to this machine (`https://127.0.0.1:…`), its network
(`https://10.…`) or the cloud's metadata service (`https://169.254.169.254/…`); and so did the SCA feeds' download
(`lazaret-sca --update-bundle`: a feed may move). Such a hop is now judged by the address it connects to
(scanner/netaddr.py: guard._Hops, sca_feeds._feed_hops): a public one always, a private one only from a proxy (a feed's
host) on a private or loopback address, a loopback one only from one on loopback, a link-local, multicast, reserved or
unspecified one never, nor a cloud's metadata address. Hops to the configured hosts are made as before. After the
review: a configured host reached through an outbound proxy counts as on a public address (a lookup made here never
grants: RelayedProxyTests), the connection to a forward proxy is no hop (PlainProxyThroughAForwardProxyTests), the
clouds' metadata addresses outside link-local are never reached, and NAT64's local-use prefix is read at every length.

The servers are this machine's (127.0.0.1, a root made for the test: tests/_pki.py). `Fetcher.lookup` (and
`sca_feeds._LOOKUP`) points the test's names (`*.test`) at them, and `Fetcher.peer` (`sca_feeds._PEER`) says which
address a connection stands for, so that 127.0.0.1 can stand in for a public proxy or feed (8.8.8.8 here), its CDN
(1.1.1.1), a company's proxy or mirror (10.20.0.2) or its storage (10.30.0.3): the addresses are labels, nothing is sent
to them. Nothing leaves the machine."""

import http.server
import io
import ipaddress
import os
import re
import socket
import ssl
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from unittest import mock

from lazaret.registry import guard, repo
from lazaret.scanner import nativenet, netaddr, sca_feeds
from tests import _pki
from tests.scanner.test_nativenet import NO_PROXY_ENV

NAMES = ("localhost", "proxy.test", "other.test", "storage.test", "cdn.test", "rebind.test", "intranet.test",
         "gone.test", "feed.test")
PUBLIC_PROXY, PUBLIC_CDN = "8.8.8.8", "1.1.1.1"
PRIVATE_PROXY, PRIVATE_STORAGE = "10.20.0.2", "10.30.0.3"
BODY = b"module zip bytes"


def read_as_an_address(host):
    """The addresses this system's resolver gives for `host`, an address written as a number (2130706433, 0x7f000001,
    127.1, 0177.0.0.1); none where it gives none. glibc's reads each as 127.0.0.1, macOS's 0177.0.0.1 as 177.0.0.1,
    and Windows' none of them as an address: it looks them up as names, and finds none (11001, CI's windows-2025)."""
    try:
        return {a[4][0] for a in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        return set()


# ---------------------------------------------------------------- the classes
class AddressClassTests(unittest.TestCase):
    def assertClass(self, text, rank, word=None):
        got = netaddr.classify(text)
        self.assertEqual(got.rank, rank, f"{text}: {got}")
        if word is not None:
            self.assertEqual(got.word, word, text)

    def test_each_class(self):
        cases = {
            netaddr.NEVER: [("0.0.0.0", "unspecified"), ("::", "unspecified"), ("0.1.2.3", "reserved"),
                            ("255.255.255.255", "broadcast"), ("240.0.0.1", "reserved"), ("224.0.0.251", "multicast"),
                            ("ff02::1", "multicast"), ("169.254.169.254", "link-local"), ("169.254.0.1", "link-local"),
                            ("fe80::1", "link-local"), ("fe80::1%eth0", "link-local"), ("fec0::1", "site-local"),
                            ("192.0.2.1", "documentation"), ("2001:db8::1", "documentation"),
                            ("192.0.0.9", "special-purpose"), ("100::1", "special-purpose"),
                            ("not an address", "unreadable")],
            netaddr.LOOPBACK: [("127.0.0.1", "loopback"), ("127.255.0.9", "loopback"), ("::1", "loopback")],
            netaddr.PRIVATE: [("10.0.0.1", "private"), ("172.16.0.1", "private"), ("172.31.255.254", "private"),
                              ("192.168.1.1", "private"), ("fd12:3456::1", "unique-local"), ("fc00::1", "unique-local"),
                              ("100.64.0.1", "carrier-grade NAT"), ("100.127.255.254", "carrier-grade NAT"),
                              ("198.18.0.1", "benchmarking"), ("198.19.255.254", "benchmarking")],
            netaddr.PUBLIC: [(PUBLIC_PROXY, "public"), (PUBLIC_CDN, "public"), ("172.32.0.1", "public"),
                             ("100.128.0.1", "public"), ("2606:4700::1111", "public")],
        }
        for rank, rows in cases.items():
            for text, word in rows:
                with self.subTest(text=text):
                    self.assertClass(text, rank, word)

    def test_an_ipv4_address_inside_an_ipv6_one_is_judged_as_that_ipv4_address(self):
        # mapped, translated, compatible, NAT64 (well-known and local-use), 6to4, Teredo (its server's and its client's,
        # the client's written inverted): 127.0.0.1 is 7f00:0001, 10.0.0.1 0a00:0001, 169.254.169.254 a9fe:a9fe
        cases = [
            ("::ffff:127.0.0.1", netaddr.LOOPBACK), ("::ffff:7f00:1", netaddr.LOOPBACK),
            ("::ffff:10.0.0.1", netaddr.PRIVATE), ("::ffff:169.254.169.254", netaddr.NEVER),
            ("::ffff:0.0.0.0", netaddr.NEVER), ("::ffff:8.8.8.8", netaddr.PUBLIC),
            ("::ffff:0:127.0.0.1", netaddr.LOOPBACK), ("::ffff:0:8.8.8.8", netaddr.PUBLIC),
            ("::127.0.0.1", netaddr.LOOPBACK), ("::10.0.0.1", netaddr.PRIVATE), ("::8.8.8.8", netaddr.PUBLIC),
            ("64:ff9b::127.0.0.1", netaddr.LOOPBACK), ("64:ff9b::a9fe:a9fe", netaddr.NEVER),
            ("64:ff9b::8.8.8.8", netaddr.PUBLIC),
            # NAT64's local-use prefix: every reading counts (test_nat64_local_use_is_read_at_each_length), private at
            # best: 10.10.10.10 at every length; 10.10.10.10 at /96 but 0.0.0.0 at /48; 127.0.0.1 at /48 (and 0.0.1.0
            # at /56); 8.8.8.8 at every length
            ("64:ff9b:1:a0a:a:a0a:a0a:a0a", netaddr.PRIVATE), ("64:ff9b:1::a0a:a0a", netaddr.NEVER),
            ("64:ff9b:1:7f00:0:100::", netaddr.NEVER), ("64:ff9b:1:808:8:808:808:808", netaddr.PRIVATE),
            ("64:ff9b:1:a9fe:a9:fe00::", netaddr.NEVER),
            ("2002:7f00:1::1", netaddr.LOOPBACK), ("2002:a9fe:a9fe::1", netaddr.NEVER),
            ("2002:a00:1::1", netaddr.PRIVATE), ("2002:808:808::1", netaddr.PUBLIC),
            ("2001:0:808:808::80ff:fffe", netaddr.LOOPBACK),                 # (client ~0x80fffffe = 127.0.0.1)
            ("2001:0:808:808::5601:5601", netaddr.NEVER),                    # (client 169.254.169.254)
            ("2001:0:7f00:1::f7f7:f7f7", netaddr.LOOPBACK),                  # (server 127.0.0.1, client 8.8.8.8)
            ("2001:0:808:808::f7f7:f7f7", netaddr.PUBLIC),                   # (both 8.8.8.8)
        ]
        for text, rank in cases:
            with self.subTest(text=text):
                self.assertClass(text, rank)

    def test_nat64_local_use_is_read_at_each_length(self):
        # (RFC 8215's 64:ff9b:1::/48 may be cut into a translation prefix of any of RFC 6052's lengths from /48 to /96,
        # and the address does not say which: the review's 64:ff9b:1:a00:0:100:7f00:1 is 10.0.0.1 as a /48 and
        # 127.0.0.1 as a /96)
        def readings(text):
            return [str(a) for a in netaddr.nat64_local_readings(ipaddress.ip_address(text))]
        self.assertEqual(readings("64:ff9b:1:a00:0:100:7f00:1"), ["10.0.0.1", "0.0.1.0", "0.1.0.127", "127.0.0.1"])
        self.assertEqual(readings("64:ff9b:1:c0a8:1:200::"), ["192.168.1.2", "168.1.2.0", "1.2.0.0", "0.0.0.0"])
        self.assertEqual(readings("64:ff9b:1:c0:a8:102::"), ["0.192.168.1", "192.168.1.2", "168.1.2.0", "0.0.0.0"])
        self.assertEqual(readings("64:ff9b:1:0:c0:a801:200::"), ["0.0.192.168", "0.192.168.1", "192.168.1.2", "2.0.0.0"])
        self.assertEqual(readings("64:ff9b:1::c0a8:102"), ["0.0.0.0", "0.0.0.0", "0.0.0.192", "192.168.1.2"])
        self.assertEqual(netaddr.classify("64:ff9b:1:a00:0:100:7f00:1").rank, netaddr.NEVER)   # (0.0.1.0, the strictest)
        self.assertEqual(netaddr.classify("64:ff9b:1:7f7f:7f:7f7f:7f7f:7f7f").rank, netaddr.LOOPBACK)
        self.assertEqual(netaddr.classify("64:ff9b:1:a0a:a:a0a:7f00:1").rank, netaddr.LOOPBACK)  # (127.0.0.1 at /96)

    def test_the_clouds_metadata_addresses_outside_link_local_are_never_reached(self):
        cases = [  # (the address, its word): Alibaba's metadata service (in carrier-grade NAT), Azure's WireServer
            # (public), AWS's IMDS, DNS and time server and EKS Pod Identity Agent over IPv6 and Google's metadata
            # server over IPv6 (unique-local)
            ("100.100.100.200", "metadata"), ("168.63.129.16", "cloud platform"), ("fd00:ec2::254", "metadata"),
            ("fd00:ec2::253", "cloud platform"), ("fd00:ec2::123", "cloud platform"),
            ("fd00:ec2::23", "cloud credentials"), ("fd20:ce::254", "metadata"),
            # the link-local ones, never already: AWS, Azure, Google, Oracle, DigitalOcean, IBM's VPC, Hetzner,
            # OpenStack (169.254.169.254), Tencent (169.254.0.23), IBM's Power Virtual Server (169.254.169.253),
            # OpenStack over IPv6 (fe80::a9fe:a9fe)
            ("169.254.169.254", "link-local"), ("169.254.0.23", "link-local"), ("169.254.169.253", "link-local"),
            ("fe80::a9fe:a9fe", "link-local"),
            # inside an IPv6 address (mapped, NAT64, 6to4)
            ("::ffff:100.100.100.200", "metadata"), ("64:ff9b::6464:64c8", "metadata"),
            ("2002:a83f:8110::1", "cloud platform"),
        ]
        for text, word in cases:
            with self.subTest(text=text):
                self.assertClass(text, netaddr.NEVER, word)
                for proxy in (PUBLIC_PROXY, PRIVATE_PROXY, "127.0.0.1"):
                    self.assertFalse(netaddr.allowed(netaddr.classify(text), netaddr.classify(proxy)))
        for text, rank in [("100.100.100.199", netaddr.PRIVATE), ("100.100.100.201", netaddr.PRIVATE),
                           ("168.63.129.15", netaddr.PUBLIC), ("168.63.129.17", netaddr.PUBLIC),
                           ("fd00:ec2::1", netaddr.PRIVATE), ("fd00:ec2::255", netaddr.PRIVATE),
                           ("fd00:ec2::22", netaddr.PRIVATE), ("fd00:ec2::24", netaddr.PRIVATE),
                           ("fd20:ce::253", netaddr.PRIVATE)]:                 # (their neighbours: as before)
            with self.subTest(text=text):
                self.assertClass(text, rank)
        self.assertEqual(netaddr.refusal(netaddr.classify("100.100.100.200"), "100.100.100.200", None),
                         "redirect to a metadata address (100.100.100.200) refused: a redirect never leads to such an "
                         "address")
        self.assertEqual(netaddr.refusal(netaddr.classify("fd00:ec2::23"), "fd00:ec2::23", None),
                         "redirect to a cloud credentials address (fd00:ec2::23) refused: a redirect never leads to "
                         "such an address")

    def test_the_rule(self):
        public, private, loopback, never = (netaddr.classify(a) for a in (PUBLIC_CDN, PRIVATE_STORAGE, "127.0.0.1",
                                                                          "169.254.169.254"))
        proxies = {"public": netaddr.classify(PUBLIC_PROXY), "private": netaddr.classify(PRIVATE_PROXY),
                   "loopback": netaddr.classify("127.0.0.1"), "unknown": None, "link-local": never,
                   "relayed": netaddr.RELAYED}
        allowed = {  # hop -> the proxies it may come from
            "public": {"public", "private", "loopback", "unknown", "link-local", "relayed"},
            "private": {"private", "loopback"},
            "loopback": {"loopback"},
            "never": set(),
        }
        for hop_name, hop in (("public", public), ("private", private), ("loopback", loopback), ("never", never)):
            for proxy_name, proxy in proxies.items():
                with self.subTest(hop=hop_name, proxy=proxy_name):
                    self.assertEqual(netaddr.allowed(hop, proxy), proxy_name in allowed[hop_name])

    def test_a_proxy_is_what_the_least_granting_of_its_addresses_grants(self):
        c = netaddr.classify
        self.assertEqual(netaddr.least_granting([c("127.0.0.1"), c("::1")]).rank, netaddr.LOOPBACK)
        self.assertEqual(netaddr.least_granting([c("127.0.0.1"), c(PRIVATE_PROXY)]).rank, netaddr.PRIVATE)
        self.assertEqual(netaddr.least_granting([c(PRIVATE_PROXY), c(PUBLIC_PROXY)]).rank, netaddr.PUBLIC)
        self.assertEqual(netaddr.least_granting([c("127.0.0.1"), c("169.254.1.1")]).rank, netaddr.NEVER)
        self.assertIsNone(netaddr.least_granting([]))

    def test_the_messages(self):
        c = netaddr.classify
        self.assertEqual(netaddr.refusal(c("10.1.2.3"), "10.1.2.3", c(PUBLIC_PROXY)),
                         "redirect to a private address (10.1.2.3) refused: the proxy is on a public address")
        self.assertEqual(netaddr.refusal(c("127.0.0.1"), "127.0.0.1", c(PRIVATE_PROXY), "storage.test"),
                         "redirect to storage.test, a loopback address (127.0.0.1), refused: the proxy is on a "
                         "private address")
        self.assertEqual(netaddr.refusal(c("169.254.169.254"), "169.254.169.254", c("127.0.0.1")),
                         "redirect to a link-local address (169.254.169.254) refused: a redirect never leads to such "
                         "an address")
        self.assertEqual(netaddr.refusal(c("::1"), "::1", None),
                         "redirect to a loopback address (::1) refused: the proxy's own address is not known")
        self.assertIn("an unspecified address (0.0.0.0)", netaddr.refusal(c("0.0.0.0"), "0.0.0.0", None))
        self.assertEqual(netaddr.refusal(c("10.1.2.3"), "10.1.2.3", netaddr.RELAYED, "intranet.example"),
                         "redirect to intranet.example, a private address (10.1.2.3), refused: the proxy is reached "
                         "through an outbound proxy, so it counts as on a public address")

    def test_a_configured_host_reached_through_an_outbound_proxy_is_not_classed_by_a_lookup_made_here(self):
        # (LZ-02's review, H1: its name's operator answers this machine's lookup and the outbound proxy's alike, so a
        # lookup made here never grants; an address its URL names is that address's class)
        class Conn:
            def __init__(self, host, port, tunnel=None):
                self.host, self.port = host, port
                if tunnel:
                    self._tunnel_host, self._tunnel_port = tunnel
        asked = []

        def lookup(host, port, *rest):
            asked.append(host)
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        hops = netaddr.Hops(lambda host, port: host in ("proxy.example", "10.20.0.2", "127.0.0.1", "::1"),
                            lookup=lookup)
        for conn, forward, expected in [
                (Conn("outbound.example", 3128, ("proxy.example", 443)), None, netaddr.RELAYED),
                (Conn("outbound.example", 3128, ("10.20.0.2", 443)), None, netaddr.classify("10.20.0.2")),
                (Conn("outbound.example", 3128, ("127.0.0.1", 443)), None, netaddr.classify("127.0.0.1")),
                (Conn("outbound.example", 3128, ("::1", 443)), None, netaddr.classify("::1")),
                (Conn("fwd.example", 3128), ("proxy.example", 80), netaddr.RELAYED),
                (Conn("fwd.example", 3128), ("10.20.0.2", 80), netaddr.classify("10.20.0.2"))]:
            with self.subTest(tunnel=getattr(conn, "_tunnel_host", None), forward=forward):
                hops.proxy = None
                target = netaddr.HopTarget(hops, conn, forward)
                self.assertTrue(target.relayed and target.configured)
                target.before([(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 3128))])
                if expected is netaddr.RELAYED:
                    self.assertIs(hops.proxy, netaddr.RELAYED)
                else:
                    self.assertEqual(hops.proxy, expected)
                target.after(None)                          # (the peer is the outbound proxy: neither judged nor learned)
        self.assertEqual(asked, [], "no lookup is made of a configured host reached through an outbound proxy")
        # a hop through it is still looked up here and every address judged (127.0.0.1: refused from a relayed host)
        hops.proxy = netaddr.RELAYED
        with self.assertRaises(netaddr.Refused) as caught:
            netaddr.HopTarget(hops, Conn("outbound.example", 3128, ("storage.example", 443))).before(())
        self.assertIn("redirect to storage.example, a loopback address (127.0.0.1), refused: the proxy is reached "
                      "through an outbound proxy", str(caught.exception))
        self.assertEqual(asked, ["storage.example"])


# ---------------------------------------------------------------- the report's repro: Fetcher.check
class CheckTests(unittest.TestCase):
    LITERALS = [  # (redirect target, from a public proxy, a private one, one on loopback)
        ("https://127.0.0.1:8443/internal-admin", False, False, True),
        ("https://[::1]:8443/internal-admin", False, False, True),
        ("https://[::ffff:127.0.0.1]:8443/internal-admin", False, False, True),
        ("https://10.0.0.1/internal-admin", False, True, True),
        ("https://[fd00::1]/internal-admin", False, True, True),
        ("https://169.254.169.254/latest/meta-data/", False, False, False),
        ("https://[::ffff:169.254.169.254]/latest/meta-data/", False, False, False),
        ("https://0.0.0.0:8443/internal-admin", False, False, False),
        (f"https://{PUBLIC_CDN}/blob", True, True, True),
    ]

    def hops(self, f, proxy):
        hops = guard._Hops(f)
        hops.proxy = None if proxy is None else netaddr.classify(proxy)
        return hops

    def test_the_reports_repro(self):
        f = guard.Fetcher({"proxy.example"}, https_redirects=True)
        target = "https://127.0.0.1:8443/internal-admin"
        with self.assertRaises(repo.FetchError) as direct:
            f.check(target)
        self.assertEqual(str(direct.exception), "host not allowed for this install: '127.0.0.1:8443'")
        with self.assertRaises(guard.HopRefused) as redirect:
            f.check(target, redirect=True)
        self.assertEqual(str(redirect.exception),
                         "redirect to a loopback address (127.0.0.1) refused: the proxy's own address is not known")

    def test_an_address_a_redirect_names_is_judged_against_the_proxy_it_came_from(self):
        f = guard.Fetcher({"proxy.example"}, https_redirects=True)
        for url, *expected in self.LITERALS:
            with self.subTest(url=url, how="direct"), self.assertRaises(repo.FetchError) as caught:
                f.check(url)
            self.assertIn("host not allowed for this install", str(caught.exception))
            for proxy, ok in zip((PUBLIC_PROXY, PRIVATE_PROXY, "127.0.0.1"), expected):
                with self.subTest(url=url, proxy=proxy):
                    if ok:
                        self.assertEqual(f.check(url, redirect=True, hops=self.hops(f, proxy)), url)
                    else:
                        with self.assertRaises(guard.HopRefused):
                            f.check(url, redirect=True, hops=self.hops(f, proxy))
            with self.subTest(url=url, proxy="not known"):                # (as a public proxy's)
                if expected[0]:
                    self.assertEqual(f.check(url, redirect=True), url)
                else:
                    with self.assertRaises(guard.HopRefused):
                        f.check(url, redirect=True)

    def test_a_name_is_judged_by_the_address_it_connects_to_and_a_configured_host_as_before(self):
        f = guard.Fetcher({"proxy.example", "127.0.0.1:8443"}, https_redirects=True)
        self.assertEqual(f.check("https://storage.example/blob", redirect=True), "https://storage.example/blob")
        self.assertEqual(f.check("https://127.0.0.1:8443/x", redirect=True), "https://127.0.0.1:8443/x")
        self.assertEqual(f.check("https://127.0.0.1:8443/x"), "https://127.0.0.1:8443/x")
        with self.assertRaises(repo.FetchError):
            f.check("http://storage.example/blob", redirect=True)                # (https only, as before)

    def test_without_https_redirects_nothing_changes(self):
        f = guard.Fetcher({"proxy.example"})
        for url in ("https://storage.example/blob", "https://127.0.0.1:8443/x", f"https://{PUBLIC_CDN}/blob"):
            with self.subTest(url=url), self.assertRaises(repo.FetchError) as caught:
                f.check(url, redirect=True)
            self.assertNotIsInstance(caught.exception, guard.HopRefused)
            self.assertIn("host not allowed for this install", str(caught.exception))


# ---------------------------------------------------------------- servers of this machine
class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):                                      # noqa: N802 (http.server's name)
        server = self.server
        with server.lock:
            server.requests.append((self.headers.get("Host", ""), self.path))
        if self.path.startswith("/hop/"):                  # /hop/HOST/REST: to https://HOST:PORT/REST
            host, _, rest = self.path[len("/hop/"):].partition("/")
            self._send(302, b"", [("Location", f"https://{host}:{server.server_address[1]}/{rest}")])
        elif self.path == "/blob":
            self._send(200, BODY)
        else:
            self._send(404, b"no")

    def _send(self, status, body, headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _Server(http.server.ThreadingHTTPServer):
    """An HTTPS server on 127.0.0.1 that counts the connections it accepts (before TLS: a hop refused after it
    connected sends nothing) and keeps the requests it got as (Host, path)."""
    daemon_threads = True

    def __init__(self, context):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.context, self.lock, self.connections, self.requests = context, threading.Lock(), 0, []

    def get_request(self):
        sock, address = self.socket.accept()
        with self.lock:
            self.connections += 1
        return self.context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address

    def handle_error(self, request, client_address):
        pass                                               # (a client that left: the test says what it saw)

    def hosts(self):
        with self.lock:
            return [h.rsplit(":", 1)[0] for h, _ in self.requests]


class _ConnectProxy:
    """An outbound http proxy on 127.0.0.1 (HTTPS_PROXY): each CONNECT is kept, and tunnelled to 127.0.0.1 on the port it
    names, whatever host it names."""

    def __init__(self):
        self.lock, self.connects = threading.Lock(), []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        upstream = None
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                data += chunk
            target = data.split(b"\r\n", 1)[0].decode("latin-1").split()[1]
            with self.lock:
                self.connects.append(target)
            upstream = socket.create_connection(("127.0.0.1", int(target.rsplit(":", 1)[1])), timeout=10)
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            def pipe(a, b):
                try:
                    while True:
                        chunk = a.recv(65536)
                        if not chunk:
                            break
                        b.sendall(chunk)
                except OSError:
                    pass
                finally:
                    for s in (a, b):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
            threading.Thread(target=pipe, args=(conn, upstream), daemon=True).start()
            pipe(upstream, conn)
        except OSError:
            pass
        finally:
            if upstream is not None:
                upstream.close()
            conn.close()

    def hosts(self):
        with self.lock:
            return [t.rsplit(":", 1)[0] for t in self.connects]

    def close(self):
        self.sock.close()


def _peers(table):
    """Fetcher.peer: the address a connection to `host` (or the address itself, for a URL that names one) at `ip`
    stands for: the table's for (host, ip), else for host; a host the table does not name is its real address."""
    return lambda host, ip: table.get((host, ip), table.get(host, ip))


class _ServerCase(unittest.TestCase):
    """The server, a root the client trusts (Python's transport: PEP 476's hook, which nativenet.tls_context builds
    on), no proxy from the environment."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        pki = _pki.Pki(cls.tmp.name, dns=NAMES, ips=("127.0.0.1",))
        cls.root = pki.root_pem
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(pki.cert, pki.key)
        cls.server = _Server(context)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        for patch in (mock.patch.dict(os.environ, NO_PROXY_ENV, clear=True),
                      mock.patch.object(ssl, "_create_default_https_context",
                                        lambda: ssl.create_default_context(cadata=self.root))):
            patch.start()
            self.addCleanup(patch.stop)
        with self.server.lock:
            self.server.connections, self.server.requests = 0, []
        self.names = {name: ["127.0.0.1"] for name in NAMES if name != "localhost"}
        self.names["gone.test"] = None

    def lookup(self, host, port, family=0, kind=0, *rest):
        """socket.getaddrinfo, with the test's names (`names`: host -> its addresses; None: no such name)."""
        if host.lower() not in self.names:
            return socket.getaddrinfo(host, port, family, kind, *rest)
        found = self.names[host.lower()]
        if found is None:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", (a, port, 0, 0)) if ":" in a else
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in found]

    def url(self, host, path):
        return f"https://{host}:{self.port}{path}"


class _PythonFetchCase(_ServerCase):
    """Fetches of the Go guard's fetcher on Python's transport (`keepalive`: the pool's path; else urllib's)."""
    keepalive = False

    def setUp(self):
        super().setUp()
        patch = mock.patch.dict(os.environ, {nativenet.ENV: "python"})
        patch.start()
        self.addCleanup(patch.stop)

    def fetcher(self, peers=None, proxy="proxy.test"):
        f = guard.Fetcher({f"{proxy}:{self.port}"}, keepalive=self.keepalive, https_redirects=True)
        f.lookup, f.peer = self.lookup, _peers(peers or {})
        self.addCleanup(f.close)
        return f

    def refused(self, f, path, message, proxy="proxy.test"):
        """A fetch through the hop at `path` is HopRefused with `message` (a part of it), naming the URL asked for."""
        with self.assertRaises(guard.HopRefused) as caught:
            f.get(self.url(proxy, path), max_bytes=1000)
        self.assertIn(message, str(caught.exception))
        self.assertTrue(str(caught.exception).startswith(f"URL error fetching {self.url(proxy, path)}: "))
        return caught.exception


class _RedirectTests:
    """The Go guard's redirects on one transport (a mixin: `_PythonFetchCase` and the transport)."""

    def test_a_public_proxy_may_send_the_fetch_to_a_public_host(self):
        f = self.fetcher({"proxy.test": PUBLIC_PROXY, "cdn.test": PUBLIC_CDN})
        self.assertEqual(f.get(self.url("proxy.test", "/hop/cdn.test/blob"), max_bytes=1000), BODY)
        self.assertEqual(self.server.hosts(), ["proxy.test", "cdn.test"])

    def test_the_reports_addresses_from_a_public_proxy_are_refused_before_anything_is_sent(self):
        cases = [  # (the hop, the message)
            ("127.0.0.1", "redirect to a loopback address (127.0.0.1) refused: the proxy is on a public address"),
            ("[::1]", "redirect to a loopback address (::1) refused: the proxy is on a public address"),
            ("[::ffff:127.0.0.1]",
             "redirect to a loopback address (::ffff:127.0.0.1) refused: the proxy is on a public address"),
            ("10.0.0.1", "redirect to a private address (10.0.0.1) refused: the proxy is on a public address"),
            ("169.254.169.254", "redirect to a link-local address (169.254.169.254) refused: a redirect never leads"),
            ("0.0.0.0", "redirect to an unspecified address (0.0.0.0) refused: a redirect never leads"),
        ]
        for hop, message in cases:
            with self.subTest(hop=hop):
                f = self.fetcher({"proxy.test": PUBLIC_PROXY})
                with self.server.lock:
                    self.server.connections, self.server.requests = 0, []
                self.refused(f, f"/hop/{hop}/blob", message)
                self.assertEqual(self.server.hosts(), ["proxy.test"], "only the proxy was asked")

    def test_a_name_that_leads_to_loopback_is_refused_before_it_is_connected_to(self):
        f = self.fetcher({"proxy.test": PUBLIC_PROXY})              # (intranet.test: 127.0.0.1, really)
        self.refused(f, "/hop/intranet.test/blob",
                     "redirect to intranet.test, a loopback address (127.0.0.1), refused: the proxy is on a public "
                     "address")
        self.assertEqual(self.server.hosts(), ["proxy.test"])
        self.assertEqual(self.server.connections, 1, "nothing was connected to for intranet.test")

    def test_an_address_written_as_a_number_is_judged_by_the_address_it_connects_to(self):
        # (2130706433, 0x7f000001, 127.1 and 0177.0.0.1 are names to the URL and addresses to the resolver: judged
        # by the address the lookup gives, before anything is connected. Resolvers differ on them: glibc's reads
        # 0177.0.0.1 as octal, 127.0.0.1, and macOS's as decimal, 177.0.0.1, a public address that is connected to
        # there, as it may be, and a test must not reach out to; Windows' reads none of them as an address. A form
        # this system's resolver reads as no address (Windows': it looks it up as a name and finds none) is a hop that
        # fails, there being nothing to judge or to connect to, and nothing past the proxy asked; one it reads as
        # another address (macOS's 0177.0.0.1) is skipped here, never fetched)
        f = self.fetcher({"proxy.test": PUBLIC_PROXY})
        asked = 0
        for host in ("2130706433", "0x7f000001", "127.1", "0177.0.0.1"):
            with self.subTest(host=host):
                read = read_as_an_address(host)
                if read and read != {"127.0.0.1"}:
                    self.skipTest(f"this system's resolver reads {host} as {', '.join(sorted(read))}")
                with self.server.lock:
                    self.server.connections, self.server.requests = 0, []
                asked += 1
                if not read:
                    url = self.url("proxy.test", f"/hop/{host}/blob")
                    with self.assertRaises(repo.FetchError) as caught:
                        f.get(url, max_bytes=1000)
                    self.assertNotIsInstance(caught.exception, guard.HopRefused)    # (no address: nothing judged)
                    self.assertRegex(str(caught.exception), rf"^(URL|network) error fetching {re.escape(url)}: ")
                else:
                    self.refused(f, f"/hop/{host}/blob", f"redirect to {host}, a loopback address (127.0.0.1), "
                                                         f"refused: the proxy is on a public address")
                self.assertEqual(self.server.hosts(), ["proxy.test"], "only the proxy was asked")
        self.assertTrue(asked, "every form was skipped")

    def test_a_name_with_one_address_it_may_not_reach_is_refused(self):
        self.names["cdn.test"] = ["127.0.0.1", "10.9.9.9"]           # (every address the name gives is judged)
        f = self.fetcher({"proxy.test": PUBLIC_PROXY, ("cdn.test", "127.0.0.1"): PUBLIC_CDN})
        with self.assertRaises(guard.HopRefused) as caught:
            f.get(self.url("proxy.test", "/hop/cdn.test/blob"), max_bytes=1000)
        self.assertIn("redirect to cdn.test, a private address (10.9.9.9), refused", str(caught.exception))
        self.assertEqual(self.server.hosts(), ["proxy.test"])

    def test_a_name_that_rebinds_is_judged_by_the_address_connected_to(self):
        # (DNS rebinding: a name that answers a public address and then a private one, TTL 0.) The first fetch
        # connects to the public one; the second is judged by the address it would connect to now, and refused
        # before anything is connected; and an address that differs from the one judged when the connection is made
        # (the peer, getpeername) is refused too, before a byte of the request is sent
        answers = [PUBLIC_CDN, PUBLIC_CDN, "10.9.9.9"]

        def peer(host, ip):
            if host == "rebind.test":
                return answers.pop(0) if len(answers) > 1 else answers[0]
            return {"proxy.test": PUBLIC_PROXY}.get(host, ip)
        f = self.fetcher()
        f.peer = peer
        self.assertEqual(f.get(self.url("proxy.test", "/hop/rebind.test/blob"), max_bytes=1000), BODY)
        connections = self.server.connections
        self.refused(f, "/hop/rebind.test/blob",
                     "redirect to rebind.test, a private address (10.9.9.9), refused: the proxy is on a public address")
        self.assertEqual(self.server.hosts().count("rebind.test"), 1)
        self.assertLessEqual(self.server.connections - connections, 1, "the proxy, at most: not rebind.test")
        # judged public before the connection, private once connected (getpeername)
        seen = iter([PUBLIC_CDN, "10.9.9.9"])
        f2 = self.fetcher()
        f2.peer = lambda host, ip: next(seen) if host == "rebind.test" else {"proxy.test": PUBLIC_PROXY}.get(host, ip)
        with self.server.lock:
            self.server.connections, self.server.requests = 0, []
        self.refused(f2, "/hop/rebind.test/blob", "redirect to rebind.test, a private address (10.9.9.9), refused")
        self.assertEqual(self.server.hosts(), ["proxy.test"], "no request reached rebind.test")

    def test_a_companys_private_proxy_may_send_the_fetch_to_its_private_storage(self):
        f = self.fetcher({"proxy.test": PRIVATE_PROXY, "storage.test": PRIVATE_STORAGE})
        self.assertEqual(f.get(self.url("proxy.test", "/hop/storage.test/blob"), max_bytes=1000), BODY)
        f = self.fetcher({"proxy.test": PRIVATE_PROXY, "cdn.test": PUBLIC_CDN})
        self.assertEqual(f.get(self.url("proxy.test", "/hop/cdn.test/blob"), max_bytes=1000), BODY, "and public")

    def test_a_private_proxy_may_not_send_it_to_this_machine_or_the_metadata_service(self):
        f = self.fetcher({"proxy.test": PRIVATE_PROXY})
        self.refused(f, "/hop/storage.test/blob",
                     "redirect to storage.test, a loopback address (127.0.0.1), refused: the proxy is on a private "
                     "address")
        f = self.fetcher({"proxy.test": PRIVATE_PROXY, "storage.test": "169.254.169.254"})
        self.refused(f, "/hop/storage.test/blob", "a link-local address (169.254.169.254), refused")

    def test_a_proxy_on_loopback_may_send_it_to_loopback_and_a_public_proxy_may_not(self):
        f = self.fetcher()                                          # (proxy.test and storage.test: 127.0.0.1, really)
        self.assertEqual(f.get(self.url("proxy.test", "/hop/storage.test/blob"), max_bytes=1000), BODY)
        f = self.fetcher({"proxy.test": PUBLIC_PROXY})
        self.refused(f, "/hop/storage.test/blob",
                     "redirect to storage.test, a loopback address (127.0.0.1), refused: the proxy is on a public "
                     "address")

    def test_the_hop_is_judged_against_the_configured_host_it_came_from(self):
        # (a public proxy may send the fetch to its CDN, and the CDN on to anything public, but not to the network)
        f = self.fetcher({"proxy.test": PUBLIC_PROXY, "cdn.test": PUBLIC_CDN, "storage.test": PRIVATE_STORAGE})
        self.refused(f, "/hop/cdn.test/hop/storage.test/blob",
                     "redirect to storage.test, a private address (10.30.0.3), refused: the proxy is on a public "
                     "address")
        self.assertEqual(self.server.hosts(), ["proxy.test", "cdn.test"])

    def test_a_hop_to_a_configured_host_is_made_as_before(self):
        f = self.fetcher({"proxy.test": PUBLIC_PROXY})
        f.allow(self.url("storage.test", "/"))                     # (configured: not judged, whatever its address)
        self.assertEqual(f.get(self.url("proxy.test", "/hop/storage.test/blob"), max_bytes=1000), BODY)

    def test_a_direct_url_to_these_addresses_is_not_fetched_at_all(self):
        f = self.fetcher({"proxy.test": PUBLIC_PROXY})
        for host in ("127.0.0.1", "[::1]", "10.0.0.1", "169.254.169.254", "0.0.0.0", "storage.test"):
            with self.subTest(host=host), self.assertRaises(repo.FetchError) as caught:
                f.get(f"https://{host}:{self.port}/blob", max_bytes=1000)
            self.assertIn("host not allowed for this install", str(caught.exception))
        self.assertEqual(self.server.connections, 0)

    def test_the_relay_s_fetches_too(self):
        # (open() without a deadline: the relays of a stream)
        f = self.fetcher({"proxy.test": PUBLIC_PROXY})
        with self.assertRaises(guard.HopRefused):
            f.open(self.url("proxy.test", "/hop/10.0.0.1/blob")).close()
        f = self.fetcher({"proxy.test": PRIVATE_PROXY, "storage.test": PRIVATE_STORAGE})
        with f.open(self.url("proxy.test", "/hop/storage.test/blob")) as r:
            self.assertEqual(r.read(), BODY)


class UrllibRedirectTests(_RedirectTests, _PythonFetchCase):
    keepalive = False


class PoolRedirectTests(_RedirectTests, _PythonFetchCase):
    keepalive = True

    def test_a_kept_connection_is_judged_for_each_fetch(self):
        # (a connection to storage.test kept from a private proxy's fetch is not one a public proxy's may use)
        f = guard.Fetcher({f"proxy.test:{self.port}", f"other.test:{self.port}"}, keepalive=True, https_redirects=True)
        self.addCleanup(f.close)
        f.lookup = self.lookup
        f.peer = _peers({"proxy.test": PRIVATE_PROXY, "other.test": PUBLIC_PROXY, "storage.test": PRIVATE_STORAGE})
        self.assertEqual(f.get(self.url("proxy.test", "/hop/storage.test/blob"), max_bytes=1000), BODY)
        self.assertGreater(f.pool.idle(), 0)
        with self.assertRaises(guard.HopRefused) as caught:
            f.get(f"https://other.test:{self.port}/hop/storage.test/blob", max_bytes=1000)
        self.assertIn("redirect to storage.test, a private address (10.30.0.3), refused: the proxy is on a public "
                      "address", str(caught.exception))
        self.assertEqual(self.server.hosts(), ["proxy.test", "storage.test", "other.test"])


class _Outbound:
    """An outbound CONNECT proxy (`_ConnectProxy`) as HTTPS_PROXY for the test (a mixin of a `_ServerCase`)."""

    def setUp(self):
        super().setUp()
        self.outbound = _ConnectProxy()
        self.addCleanup(self.outbound.close)
        patch = mock.patch.dict(os.environ, {"HTTPS_PROXY": f"http://127.0.0.1:{self.outbound.port}",
                                             "https_proxy": f"http://127.0.0.1:{self.outbound.port}"})
        patch.start()
        self.addCleanup(patch.stop)

    def no_proxy(self, value):
        """NO_PROXY (and no_proxy) set to `value` for the rest of the test."""
        patch = mock.patch.dict(os.environ, {"NO_PROXY": value, "no_proxy": value})
        patch.start()
        self.addCleanup(patch.stop)


RELAYED = "the proxy is reached through an outbound proxy, so it counts as on a public address"


class OutboundProxyTests(_Outbound, _PythonFetchCase):
    """Through an outbound proxy (HTTPS_PROXY) the peer is that proxy, and the names are looked up there. A lookup made
    here only ever refuses: the hop's name is looked up here and every address it gives judged (a name that cannot be
    is refused), and the configured proxy's is not looked up at all: it counts as on a public address (RELAYED, below)."""

    def test_each_path(self):
        for keepalive in (False, True):
            self.keepalive = keepalive
            with self.subTest(keepalive=keepalive):
                with self.outbound.lock:
                    self.outbound.connects = []
                f = self.fetcher({"proxy.test": PUBLIC_PROXY, "cdn.test": PUBLIC_CDN})
                self.assertEqual(f.get(self.url("proxy.test", "/hop/cdn.test/blob"), max_bytes=1000), BODY)
                self.assertEqual(self.outbound.hosts(), ["proxy.test", "cdn.test"], "through the outbound proxy")
                self.names["intranet.test"] = ["10.9.9.9"]           # (looked up here: never connected to from here)
                self.refused(f, "/hop/intranet.test/blob",
                             f"redirect to intranet.test, a private address (10.9.9.9), refused: {RELAYED}")
                self.refused(f, "/hop/gone.test/blob",
                             "redirect to gone.test refused: it is reached through a proxy, and its address could not "
                             "be looked up here to be judged")
                self.assertNotIn("intranet.test", self.outbound.hosts())
                self.assertNotIn("gone.test", self.outbound.hosts())

    def test_a_companys_private_proxy_reaches_its_storage_when_it_is_reached_directly(self):
        # (the precision LZ-02's review traded: a private GOPROXY reached through the outbound proxy counts as a public
        # one, so it may send go to public addresses only; one in NO_PROXY, as a company's internal hosts normally are,
        # is reached directly and judged by its peer, and may send it to its private storage, through the outbound
        # proxy or not)
        for keepalive in (False, True):
            self.keepalive = keepalive
            with self.subTest(keepalive=keepalive, no_proxy=""):
                f = self.fetcher({"proxy.test": PRIVATE_PROXY, "intranet.test": PRIVATE_STORAGE})
                self.refused(f, "/hop/intranet.test/blob",
                             f"redirect to intranet.test, a private address (10.30.0.3), refused: {RELAYED}")
        self.no_proxy("proxy.test")
        for keepalive in (False, True):
            self.keepalive = keepalive
            with self.subTest(keepalive=keepalive, no_proxy="proxy.test"):
                with self.outbound.lock:
                    self.outbound.connects = []
                f = self.fetcher({"proxy.test": PRIVATE_PROXY, "intranet.test": PRIVATE_STORAGE})
                self.assertEqual(f.get(self.url("proxy.test", "/hop/intranet.test/blob"), max_bytes=1000), BODY)
                self.assertEqual(self.outbound.hosts(), ["intranet.test"], "the proxy directly, the storage through it")
                f = self.fetcher({"proxy.test": PRIVATE_PROXY})
                self.refused(f, "/hop/intranet.test/blob", "redirect to intranet.test, a loopback address (127.0.0.1), "
                                                           "refused: the proxy is on a private address")


class RelayedProxyTests(_Outbound, _PythonFetchCase):
    """LZ-02's review, H1: through an outbound proxy, the configured proxy's class was learned from this machine's lookup
    of its name, which is not where the tunnel goes (the outbound proxy looks the name up itself). The proxy's operator
    answers both lookups: 127.0.0.1 (or 10.x) to the developer's resolver and its real address to the outbound proxy,
    and its redirect to this machine (or the network) was followed. A lookup made here never grants now: through the
    outbound proxy the proxy counts as on a public address, unless its URL names an address. Both paths, with and
    without NO_PROXY for the hop, and LocalGoProxy's own fetcher."""

    def attempt(self, local_answer, hop, peers=None):
        self.names["proxy.test"] = [local_answer]            # (the GOPROXY's DNS, as this machine's resolver sees it)
        f = self.fetcher(peers or {})
        with self.server.lock:
            self.server.requests, self.server.connections = [], 0
        return f

    def test_a_lookup_here_does_not_make_the_proxy_a_loopback_one(self):
        for no_proxy in ("", "127.0.0.1,localhost,intranet.test"):
            for keepalive in (False, True):
                self.keepalive = keepalive
                with self.subTest(keepalive=keepalive, no_proxy=no_proxy), \
                        mock.patch.dict(os.environ, {"NO_PROXY": no_proxy, "no_proxy": no_proxy}):
                    f = self.attempt("127.0.0.1", "127.0.0.1")
                    self.refused(f, "/hop/127.0.0.1/blob", f"redirect to a loopback address (127.0.0.1) refused: {RELAYED}")
                    self.assertEqual(self.server.hosts(), ["proxy.test"], "only the proxy was asked")
                    f = self.attempt("127.0.0.1", "intranet.test")      # (intranet.test: 127.0.0.1 here)
                    self.refused(f, "/hop/intranet.test/blob",
                                 f"redirect to intranet.test, a loopback address (127.0.0.1), refused: {RELAYED}")
                    self.assertEqual(self.server.hosts(), ["proxy.test"])

    def test_a_lookup_here_does_not_make_the_proxy_a_private_one(self):
        for no_proxy in ("", "intranet.test"):
            for keepalive in (False, True):
                self.keepalive = keepalive
                with self.subTest(keepalive=keepalive, no_proxy=no_proxy), \
                        mock.patch.dict(os.environ, {"NO_PROXY": no_proxy, "no_proxy": no_proxy}):
                    f = self.attempt(PRIVATE_PROXY, "intranet.test", {"intranet.test": PRIVATE_STORAGE})
                    self.refused(f, "/hop/intranet.test/blob",
                                 f"redirect to intranet.test, a private address (10.30.0.3), refused: {RELAYED}")
                    self.assertEqual(self.server.hosts(), ["proxy.test"])
                    f = self.attempt(PRIVATE_PROXY, "10.1.2.3")
                    self.refused(f, "/hop/10.1.2.3/blob", f"redirect to a private address (10.1.2.3) refused: {RELAYED}")

    def test_a_public_redirect_is_still_followed(self):
        for keepalive in (False, True):
            self.keepalive = keepalive
            with self.subTest(keepalive=keepalive):
                f = self.attempt("127.0.0.1", "cdn.test", {"cdn.test": PUBLIC_CDN})
                self.assertEqual(f.get(self.url("proxy.test", "/hop/cdn.test/blob"), max_bytes=1000), BODY)
                self.assertEqual(self.server.hosts(), ["proxy.test", "cdn.test"])

    def test_a_proxy_named_by_its_address_is_that_addresss(self):
        # (GOPROXY=https://127.0.0.1:PORT through the outbound proxy: its URL says where it is; the loopback rule of
        # _opener and the pool keep a loopback host off the outbound proxy, so this is the tunnel only a test makes)
        f = guard.Fetcher({f"10.20.0.2:{self.port}"}, https_redirects=True)
        hops = guard._Hops(f)

        class Conn:
            host, port, _tunnel_host, _tunnel_port = "127.0.0.1", self.outbound.port, "10.20.0.2", self.port
        netaddr.HopTarget(hops, Conn).before(())
        self.assertEqual(hops.proxy, netaddr.classify(PRIVATE_PROXY))
        self.assertEqual(f.check(f"https://10.1.2.3:{self.port}/blob", redirect=True, hops=hops),
                         f"https://10.1.2.3:{self.port}/blob")

    def test_the_go_guards_own_fetcher(self):
        from lazaret.registry import goproxy, pmsettings
        from tests.registry.test_guard import options
        for no_proxy in ("", "127.0.0.1,localhost"):
            for keepalive in (False, True):
                ctx = guard.Context(options(tool="go"), out=io.StringIO())
                ctx.keepalive = keepalive
                self.addCleanup(ctx.close)
                with self.subTest(keepalive=keepalive, no_proxy=no_proxy), \
                        mock.patch.dict(os.environ, {"NO_PROXY": no_proxy, "no_proxy": no_proxy}), \
                        guard.LocalGoProxy(ctx, [goproxy.Proxy(self.url("proxy.test", ""), False)],
                                           pmsettings.Credentials()) as lp:
                    self.names["proxy.test"] = ["127.0.0.1"]
                    lp.fetcher.lookup, lp.fetcher.peer = self.lookup, _peers({})
                    with self.server.lock:
                        self.server.requests = []
                    with self.assertRaises(guard.HopRefused) as caught:
                        lp.fetcher.fetch(self.url("proxy.test", "/hop/127.0.0.1/blob"))
                    self.assertIn(f"redirect to a loopback address (127.0.0.1) refused: {RELAYED}", str(caught.exception))
                    self.assertEqual(self.server.hosts(), ["proxy.test"])


# ---------------------------------------------------------------- a plain-http GOPROXY behind an HTTP_PROXY
class _ForwardProxy(http.server.ThreadingHTTPServer):
    """A plain-http forward proxy (HTTP_PROXY: an absolute-URI GET) on 127.0.0.1 that sends each request on to
    127.0.0.1 at the port its URI names, whatever host it names; keeps the URIs."""
    daemon_threads = True

    def __init__(self):
        outer, self.uris = self, []

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):                                  # noqa: N802
                outer.uris.append(self.path)
                parts = urllib.parse.urlsplit(self.path)
                with socket.create_connection(("127.0.0.1", parts.port), timeout=10) as upstream:
                    upstream.sendall(f"GET {parts.path} HTTP/1.0\r\nHost: {parts.netloc}\r\n\r\n".encode())
                    data = b""
                    while True:
                        chunk = upstream.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                self.wfile.write(data)
                self.close_connection = True

            def log_message(self, *args):
                pass
        super().__init__(("127.0.0.1", 0), Handler)


class _PlainOrigin(http.server.ThreadingHTTPServer):
    """A plain-http module proxy on 127.0.0.1 (GOPROXY=http://athens.test:PORT): BODY for every GET."""
    daemon_threads = True

    def __init__(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):                                  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", str(len(BODY)))
                self.end_headers()
                self.wfile.write(BODY)

            def log_message(self, *args):
                pass
        super().__init__(("127.0.0.1", 0), Handler)


class PlainProxyThroughAForwardProxyTests(unittest.TestCase):
    """LZ-02's review, M1: GOPROXY=http://athens.corp:PORT (an http_hosts entry) reached through HTTP_PROXY: urllib
    sends the request whole to the forward proxy (no CONNECT), and the connection to that proxy was judged as a hop off
    the configured hosts against a proxy class not yet known, so a forward proxy on a private or loopback address
    (a company's, px or cntlm on 127.0.0.1:3128) refused the guard's first request, which fetched before LZ-02. The
    connection to the outbound proxy is no hop: the request's own host is what the rule holds to, as through a
    tunnel. Both the pool's setting and urllib's (the pool hands a plain-http proxy to urllib)."""

    def setUp(self):
        self.origin, self.forward = _PlainOrigin(), _ForwardProxy()
        for server in (self.origin, self.forward):
            threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        self.loc = f"athens.test:{self.origin.server_address[1]}"
        forward = f"http://fwdproxy.test:{self.forward.server_address[1]}"
        names = {"athens.test": "127.0.0.1", "fwdproxy.test": "127.0.0.1"}
        real = socket.getaddrinfo

        def lookup(host, port, *args, **kwargs):            # (the test's names, for urllib and the rule alike)
            if host in names:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (names[host], port))]
            return real(host, port, *args, **kwargs)
        self.lookup = lookup
        env = dict(NO_PROXY_ENV, HTTP_PROXY=forward, http_proxy=forward, **{nativenet.ENV: "python"})
        for patch in (mock.patch.dict(os.environ, env, clear=True), mock.patch.object(socket, "getaddrinfo", lookup)):
            patch.start()
            self.addCleanup(patch.stop)

    def fetch(self, forward_class, keepalive, redirects):
        f = guard.Fetcher({self.loc}, http_hosts={self.loc}, keepalive=keepalive, https_redirects=redirects)
        self.addCleanup(f.close)
        f.lookup, f.peer = self.lookup, _peers({"fwdproxy.test": forward_class, "athens.test": PRIVATE_PROXY})
        return f.get(f"http://{self.loc}/mod/@v/list", max_bytes=1000)

    def test_the_first_request_is_sent_through_a_forward_proxy_on_any_address(self):
        for forward_class in (PRIVATE_PROXY, "127.0.0.1", PUBLIC_PROXY):
            for keepalive in (False, True):
                for redirects in (False, True):
                    with self.subTest(forward=forward_class, keepalive=keepalive, go_mode=redirects):
                        self.forward.uris.clear()
                        self.assertEqual(self.fetch(forward_class, keepalive, redirects), BODY)
                        self.assertEqual(self.forward.uris, [f"http://{self.loc}/mod/@v/list"])

    def test_the_proxy_reached_through_it_counts_as_on_a_public_address(self):
        f = guard.Fetcher({self.loc}, http_hosts={self.loc}, https_redirects=True)
        hops = guard._Hops(f)
        req = urllib.request.Request(f"http://{self.loc}/mod/@v/list")
        req.set_proxy(f"fwdproxy.test:{self.forward.server_address[1]}", "http")
        self.assertTrue(req.has_proxy())
        conn = guard._DeadlineHTTPConnection(req.host, hops=hops, forward=("athens.test", self.origin.server_address[1]))
        conn.connect()
        conn.close()
        self.assertIs(hops.proxy, netaddr.RELAYED)


class GoGuardFetcherTests(_ServerCase):
    def test_the_go_guards_fetcher_is_held_to_the_rule(self):
        # (LocalGoProxy's own fetcher: the GOPROXY's hosts, https_redirects; the transport the environment chooses)
        from lazaret.registry import goproxy, pmsettings
        from tests.registry.test_guard import options
        ctx = guard.Context(options(tool="go"), out=io.StringIO())
        self.addCleanup(ctx.close)
        with mock.patch.dict(os.environ, {nativenet.ENV: "python"}), \
                guard.LocalGoProxy(ctx, [goproxy.Proxy(self.url("proxy.test", ""), False)],
                                   pmsettings.Credentials()) as lp:
            self.assertTrue(lp.fetcher.https_redirects)
            lp.fetcher.lookup, lp.fetcher.peer = self.lookup, _peers({"proxy.test": PUBLIC_PROXY})
            with self.assertRaises(guard.HopRefused) as caught:
                lp.fetcher.fetch(self.url("proxy.test", "/hop/169.254.169.254/latest/meta-data/"))
            self.assertIn("redirect to a link-local address (169.254.169.254) refused", str(caught.exception))
            lp.fetcher.peer = _peers({"proxy.test": PUBLIC_PROXY, "cdn.test": PUBLIC_CDN})
            self.assertEqual(lp.fetcher.fetch(self.url("proxy.test", "/hop/cdn.test/blob"))[0], BODY)


# ---------------------------------------------------------------- the SCA feeds' download
class FeedDownloadTests(_ServerCase):
    """`lazaret-sca --update-bundle`'s download of a feed (sca_feeds.fetch) followed a redirect to any https host on
    both transports (hosts=None). The feed's own host is the configured one now: OSV's, CISA's and EPSS's are public, so
    a redirect from them may lead to a public address only; a mirror on a private or loopback address (--osv-url,
    --kev-url, --epss-url) may send it to one of its class, as a Go proxy may."""

    def setUp(self):
        super().setUp()
        for patch in (mock.patch.dict(os.environ, {nativenet.ENV: "python"}),
                      mock.patch.object(sca_feeds, "_LOOKUP", self.lookup)):
            patch.start()
            self.addCleanup(patch.stop)
        self.opener()

    def opener(self):
        """sca_feeds' opener, built again in this test's environment: urllib's ProxyHandler reads the proxy settings
        when it is made, and the module's was made with the environment the tests started in; its HTTPS handler keeps
        the context its first request made (this test's root)."""
        opener = urllib.request.build_opener(sca_feeds._HttpsRedirects, sca_feeds._HTTPSHandler())
        patch = mock.patch.object(sca_feeds, "_OPENER", opener)
        patch.start()
        self.addCleanup(patch.stop)

    def fetch(self, path, peers=None, host="feed.test"):
        with mock.patch.object(sca_feeds, "_PEER", _peers(peers or {})):
            buf = io.BytesIO()
            size = sca_feeds.fetch(self.url(host, path), buf, 1 << 20)
            return size, buf.getvalue()

    def refused(self, path, message, peers=None, host="feed.test"):
        with self.assertRaises(sca_feeds.FeedError) as caught:
            self.fetch(path, peers, host)
        self.assertIn(message, str(caught.exception))
        self.assertTrue(str(caught.exception).startswith(f"cannot fetch {self.url(host, path)}: "))

    def test_a_public_feed_may_be_sent_to_a_public_host(self):
        self.assertEqual(self.fetch("/hop/cdn.test/blob", {"feed.test": PUBLIC_PROXY, "cdn.test": PUBLIC_CDN}),
                         (len(BODY), BODY))
        self.assertEqual(self.server.hosts(), ["feed.test", "cdn.test"])

    def test_a_public_feed_may_not_send_it_to_this_machine_its_network_or_the_metadata_service(self):
        public = {"feed.test": PUBLIC_PROXY}
        cases = [
            ("127.0.0.1", "redirect to a loopback address (127.0.0.1) refused: the feed's host is on a public address"),
            ("[::ffff:127.0.0.1]", "redirect to a loopback address (::ffff:127.0.0.1) refused"),
            ("10.0.0.1", "redirect to a private address (10.0.0.1) refused: the feed's host is on a public address"),
            ("169.254.169.254", "redirect to a link-local address (169.254.169.254) refused: a redirect never leads"),
            ("0.0.0.0", "redirect to an unspecified address (0.0.0.0) refused"),
            ("intranet.test", "redirect to intranet.test, a loopback address (127.0.0.1), refused: the feed's host is "
                              "on a public address"),
            ("storage.test", "redirect to storage.test, a private address (10.30.0.3), refused"),
            ("2130706433", "redirect to 2130706433, a loopback address (127.0.0.1), refused"),
        ]
        for hop, message in cases:
            with self.subTest(hop=hop):
                if hop.isdigit() and read_as_an_address(hop) != {"127.0.0.1"}:     # (as the redirect tests do)
                    self.skipTest(f"this system's resolver does not read {hop} as 127.0.0.1")
                with self.server.lock:
                    self.server.connections, self.server.requests = 0, []
                self.refused(f"/hop/{hop}/latest/meta-data/", message, dict(public, **{"storage.test": PRIVATE_STORAGE}))
                self.assertEqual(self.server.hosts(), ["feed.test"], "only the feed's host was asked")
                self.assertEqual(self.server.connections, 1, "nothing else was connected to")

    def test_a_mirror_on_a_private_address_may_send_it_to_its_private_storage(self):
        mirror = {"feed.test": PRIVATE_PROXY, "storage.test": PRIVATE_STORAGE}
        self.assertEqual(self.fetch("/hop/storage.test/blob", mirror), (len(BODY), BODY))
        self.refused("/hop/127.0.0.1/blob", "redirect to a loopback address (127.0.0.1) refused: the feed's host is "
                                            "on a private address", mirror)
        self.refused("/hop/169.254.169.254/blob", "a link-local address (169.254.169.254) refused", mirror)

    def test_a_mirror_on_this_machine_may_send_it_to_this_machine(self):
        self.assertEqual(self.fetch("/hop/storage.test/blob"), (len(BODY), BODY))     # (both: 127.0.0.1, really)

    def test_a_redirect_on_the_feeds_own_host_is_followed_as_before(self):
        self.assertEqual(self.fetch("/hop/feed.test/blob", {"feed.test": PUBLIC_PROXY}), (len(BODY), BODY))

    def test_through_an_outbound_proxy_the_name_is_judged_by_its_addresses_here(self):
        outbound = _ConnectProxy()
        self.addCleanup(outbound.close)
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": f"http://127.0.0.1:{outbound.port}",
                                          "https_proxy": f"http://127.0.0.1:{outbound.port}"}):
            self.opener()
            self.assertEqual(self.fetch("/hop/cdn.test/blob", {"feed.test": PUBLIC_PROXY, "cdn.test": PUBLIC_CDN}),
                             (len(BODY), BODY))
            self.names["intranet.test"] = ["10.9.9.9"]
            self.refused("/hop/intranet.test/blob", "redirect to intranet.test, a private address (10.9.9.9), refused",
                         {"feed.test": PUBLIC_PROXY})
            self.refused("/hop/gone.test/blob", "its address could not be looked up here to be judged",
                         {"feed.test": PUBLIC_PROXY})
        self.assertEqual(outbound.hosts(), ["feed.test", "cdn.test", "feed.test", "feed.test"])

    def test_through_an_outbound_proxy_a_lookup_here_does_not_make_the_feeds_host_local(self):
        # (LZ-02's review, H1, for a mirror named by --osv-url, --kev-url or --epss-url: its operator answers this
        # machine's lookup of its name 127.0.0.1 or 10.x and the outbound proxy its real address; through the outbound
        # proxy it counts as on a public address now, with NO_PROXY for the hop or without)
        relayed = "the feed's host is reached through an outbound proxy, so it counts as on a public address"
        outbound = _ConnectProxy()
        self.addCleanup(outbound.close)
        for no_proxy in ("", "127.0.0.1,localhost,intranet.test"):
            with self.subTest(no_proxy=no_proxy), \
                    mock.patch.dict(os.environ, {"HTTPS_PROXY": f"http://127.0.0.1:{outbound.port}",
                                                 "https_proxy": f"http://127.0.0.1:{outbound.port}",
                                                 "NO_PROXY": no_proxy, "no_proxy": no_proxy}):
                self.opener()
                with self.server.lock:
                    self.server.requests = []
                self.names["feed.test"] = ["127.0.0.1"]
                self.refused("/hop/127.0.0.1/blob", f"redirect to a loopback address (127.0.0.1) refused: {relayed}")
                self.refused("/hop/intranet.test/blob",
                             f"redirect to intranet.test, a loopback address (127.0.0.1), refused: {relayed}")
                self.names["feed.test"] = [PRIVATE_PROXY]
                self.refused("/hop/intranet.test/blob",
                             f"redirect to intranet.test, a private address (10.30.0.3), refused: {relayed}",
                             {"intranet.test": PRIVATE_STORAGE})
                self.assertEqual(self.server.hosts(), ["feed.test"] * 3, "only the feed's host was asked")
                self.assertEqual(self.fetch("/hop/cdn.test/blob", {"cdn.test": PUBLIC_CDN}), (len(BODY), BODY))

    def test_the_feeds_opener_states_the_floor_and_its_handler_holds_the_rule(self):
        https = [h for h in sca_feeds._OPENER.handlers if isinstance(h, urllib.request.HTTPSHandler)]
        self.assertEqual([type(h) for h in https], [sca_feeds._HTTPSHandler])
        self.assertTrue(issubclass(sca_feeds._HTTPSHandler, nativenet.HTTPSHandler))


class FeedNativeTransportTests(_ServerCase):
    """The native transport gets the feed's host as its rule: a redirect elsewhere is refused there and the download is
    made again on Python's transport, which judges it; both give the same answer."""

    @classmethod
    def setUpClass(cls):
        if os.environ.get(nativenet.ENV, "").strip().lower() == "python":
            raise unittest.SkipTest("LAZARET_NETWORK=python")
        if not nativenet.available():
            raise unittest.SkipTest(f"no native transport here ({nativenet.why_not()})")
        super().setUpClass()
        nativenet.configure_roots(cls.root)

    @classmethod
    def tearDownClass(cls):
        nativenet.configure_roots(None)
        super().tearDownClass()

    def setUp(self):
        super().setUp()
        FeedDownloadTests.opener(self)

    def fetch(self, path, peers, python):
        with mock.patch.object(sca_feeds, "_PEER", _peers(peers)), \
                mock.patch.dict(os.environ, {nativenet.ENV: "python"} if python else {}):
            try:
                buf = io.BytesIO()
                sca_feeds.fetch(self.url("localhost", path), buf, 1 << 20)
                return "body", buf.getvalue()
            except sca_feeds.FeedError as exc:
                return "refused", str(exc)

    def test_both_transports_give_the_same_answer(self):
        cases = [  # (the feed's host, the other host, the answer)
            (PUBLIC_PROXY, PUBLIC_CDN, ("body", BODY)),
            (PUBLIC_PROXY, "10.1.2.3", ("refused", "redirect to 127.0.0.1, a private address (10.1.2.3), refused: "
                                                   "the feed's host is on a public address")),
            (PUBLIC_PROXY, "127.0.0.1", ("refused", "redirect to a loopback address (127.0.0.1) refused")),
            (PUBLIC_PROXY, "169.254.169.254", ("refused", "a link-local address (169.254.169.254), refused")),
            (PRIVATE_PROXY, PRIVATE_STORAGE, ("body", BODY)),
        ]
        for feed, other, (kind, answer) in cases:
            for python in (False, True):
                with self.subTest(feed=feed, other=other, python=python):
                    got_kind, got = self.fetch("/hop/127.0.0.1/blob", {"localhost": feed, "127.0.0.1": other}, python)
                    self.assertEqual(got_kind, kind, got)
                    self.assertIn(answer, got)

    def test_a_redirect_on_the_feeds_host_stays_native_and_one_elsewhere_is_not_followed_there(self):
        with mock.patch.object(sca_feeds._OPENER, "open", side_effect=AssertionError("urllib was used")):
            self.assertEqual(self.fetch("/hop/localhost/blob", {"localhost": PUBLIC_PROXY}, False), ("body", BODY))
        with self.server.lock:
            self.server.requests = []
        kind, _ = self.fetch("/hop/127.0.0.1/blob", {"localhost": PUBLIC_PROXY, "127.0.0.1": "10.1.2.3"}, False)
        self.assertEqual(kind, "refused")
        self.assertEqual(self.server.hosts(), ["localhost", "localhost"], "the other host got no request")


# ---------------------------------------------------------------- the native transport
class NativeTransportTests(_ServerCase):
    """The native transport follows a redirect to the configured hosts only (pratique cannot judge the address a hop
    connects to: its rules are of names, its resolver its own); a fetch it would take elsewhere is made again on
    Python's path, where the rule holds. So both transports give the same answer. The hosts are `localhost` (the
    configured proxy) and `127.0.0.1` (another host), which the native client looks up itself."""

    @classmethod
    def setUpClass(cls):
        if os.environ.get(nativenet.ENV, "").strip().lower() == "python":
            raise unittest.SkipTest("LAZARET_NETWORK=python")
        if not nativenet.available():
            raise unittest.SkipTest(f"no native transport here ({nativenet.why_not()})")
        super().setUpClass()
        nativenet.configure_roots(cls.root)

    @classmethod
    def tearDownClass(cls):
        nativenet.configure_roots(None)
        super().tearDownClass()

    def fetch(self, peers, path, python):
        f = guard.Fetcher({f"localhost:{self.port}"}, https_redirects=True)
        self.addCleanup(f.close)
        f.peer = _peers(peers)
        with mock.patch.dict(os.environ, {nativenet.ENV: "python"} if python else {}):
            try:
                return "body", f.get(self.url("localhost", path), max_bytes=1000)
            except repo.FetchError as exc:
                return type(exc).__name__, str(exc)

    def test_both_transports_give_the_same_answer(self):
        cases = [  # (the proxy, the other host, the hop, the answer)
            (PUBLIC_PROXY, PUBLIC_CDN, "127.0.0.1", ("body", BODY)),
            (PUBLIC_PROXY, PRIVATE_STORAGE, "127.0.0.1", ("HopRefused", "redirect to 127.0.0.1, a private address "
                                                          "(10.30.0.3), refused: the proxy is on a public address")),
            (PRIVATE_PROXY, PRIVATE_STORAGE, "127.0.0.1", ("body", BODY)),
            (PRIVATE_PROXY, "127.0.0.1", "127.0.0.1", ("HopRefused", "redirect to a loopback address (127.0.0.1) "
                                                       "refused: the proxy is on a private address")),
            ("127.0.0.1", "127.0.0.1", "127.0.0.1", ("body", BODY)),
            ("127.0.0.1", "169.254.169.254", "127.0.0.1", ("HopRefused", "redirect to 127.0.0.1, a link-local address "
                                                           "(169.254.169.254), refused: a redirect never leads")),
            (PUBLIC_PROXY, PUBLIC_CDN, "localhost", ("body", BODY)),        # (a configured host: native, as before)
        ]
        for proxy, other, hop, (kind, answer) in cases:
            peers = {"localhost": proxy, "127.0.0.1": other}
            for python in (False, True):
                with self.subTest(proxy=proxy, other=other, hop=hop, python=python):
                    got_kind, got = self.fetch(peers, f"/hop/{hop}/blob", python)
                    self.assertEqual(got_kind, kind, got)
                    if kind == "body":
                        self.assertEqual(got, answer)
                    else:
                        self.assertIn(answer, got)

    def test_a_redirect_to_another_host_is_not_followed_by_the_native_client(self):
        f = guard.Fetcher({f"localhost:{self.port}"}, https_redirects=True)
        self.addCleanup(f.close)
        f.peer = _peers({"localhost": PUBLIC_PROXY, "127.0.0.1": "10.0.0.7"})
        with self.assertRaises(guard.HopRefused):
            f.get(self.url("localhost", "/hop/127.0.0.1/blob"), max_bytes=1000)
        # the native client asked the proxy and stopped at its redirect; Python's path asked it again, and refused
        # the hop by its address before connecting: the other host got no request
        self.assertEqual(self.server.hosts(), ["localhost", "localhost"])
        with self.server.lock:
            self.server.requests = []
        with mock.patch.object(f, "_opener", side_effect=AssertionError("urllib was used")):
            self.assertEqual(f.get(self.url("localhost", "/hop/localhost/blob"), max_bytes=1000), BODY)
        self.assertEqual(self.server.hosts(), ["localhost", "localhost"])


if __name__ == "__main__":
    unittest.main()
