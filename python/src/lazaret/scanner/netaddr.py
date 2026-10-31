"""Where a redirect off the hosts a fetch was given may lead, judged by the address it connects to (LZ-02, the
external security report of Oct 27: CWE-918, server-side request forgery).

Two fetchers follow a redirect to a host they were not given: the Go guard's (a module proxy may send a zip on to its
storage: registry/guard.py's Fetcher with `https_redirects`) and the SCA feeds' download (a feed may move:
scanner/sca_feeds.py). Such a hop is judged by the address it connects to, never by its name and never by a list of
hosts, against the class of the configured host it came from (the proxy, the feed's host):

    class      a redirect off the configured hosts may lead to it
    ---------  ---------------------------------------------------------------------------------------------------
    never      never: unspecified (0.0.0.0, ::), multicast, broadcast, reserved (240/4, and the rest of 0/8, which
               Linux connects to this machine), link-local (169.254/16, where most clouds' metadata services are;
               fe80::/10), site-local (fec0::/10), the clouds' metadata and platform addresses outside link-local
               (`_V4`, `_V6`: Alibaba's 100.100.100.200, AWS's fd00:ec2::254 and its DNS and time servers, Google's
               fd20:ce::254, Azure's 168.63.129.16), documentation and every other address that is neither globally
               routable nor one of the two classes below
    loopback   only from a configured host that is on loopback itself (127/8, ::1)
    private    only from a configured host on a private or loopback address: private (10/8, 172.16/12, 192.168/16),
               unique-local (fc00::/7), carrier-grade NAT (100.64/10), benchmarking (198.18/15)
    public     always (globally routable), as before

so that a company's Athens or Artifactory on 10.x may send go to its own MinIO or S3 gateway on 10.y, and a proxy or
a feed on the internet may send the fetch to its CDN, but none can send it to this machine, the network it is on or
a cloud's metadata service.

The class of the configured host is the address it was reached at (the peer, getpeername), when it is reached
directly. Through an outbound proxy (HTTPS_PROXY's tunnel, or HTTP_PROXY's forward request for a plain-http host) the
address it was reached at is the outbound proxy's own lookup, which cannot be seen here, and a lookup made here proves
nothing about it (the host's operator answers both): so there a configured host grants what a public one does
(`RELAYED`), unless its URL names an address, whose class it is. A company proxy on a private address is normally in
NO_PROXY and reached directly, where its peer is judged.

An IPv4 address carried inside an IPv6 one is classed by that IPv4 address: mapped (::ffff:a.b.c.d), translated
(::ffff:0:a.b.c.d), compatible (::a.b.c.d), NAT64's well-known prefix (64:ff9b::/96) and its local-use one
(64:ff9b:1::/48, RFC 8215: private at best, and read at each length a network may give its translation prefix within
it, RFC 6052's /48, /56, /64 and /96, the strictest reading counting, since the address does not say which length is in
use), 6to4 (2002::/16), and Teredo (2001::/32: its server's and its client's address, the stricter). Each form is read
here rather than left to `ipaddress`, whose answers for them differ between Python versions; `ipaddress.is_global` is
the last word only on what is public (an address no table here names is public when it says so, and `never`
otherwise).

The rule of one fetch is a `Hops` (`open_socket` makes each connection of Python's transport under it: the name looked
up once, every address it gives judged before any is tried, the peer judged again); `HeldHTTPSConnection` is an
http.client connection held to one. The native transport cannot judge an address (pratique's host rules are of
names, its resolver is its own): its callers give it the configured hosts as its rule and make a fetch it refuses for
a redirect elsewhere (`refused_elsewhere`) again on Python's transport.
"""
import http.client
import ipaddress
import re
import socket
import urllib.parse
from typing import NamedTuple

__all__ = ["NEVER", "LOOPBACK", "PRIVATE", "PUBLIC", "Address", "RELAYED", "classify", "allowed", "least_granting",
           "refusal", "Refused", "Hops", "HopTarget", "open_socket", "HeldHTTPSConnection", "named",
           "refused_elsewhere"]

NEVER, LOOPBACK, PRIVATE, PUBLIC = 0, 1, 2, 3


class Address(NamedTuple):
    """An address's class (`NEVER` ... `PUBLIC`) and the word a message calls it by ("link-local", "private", ...)."""
    rank: int
    word: str


#: The class of a configured host reached through an outbound proxy (HopTarget, `relayed`): the address it was reached
#: at is the outbound proxy's lookup, which is not seen here, so it grants what a public one does (LZ-02's review: a
#: lookup made here is the host's own operator's answer, and must not grant).
RELAYED = Address(PUBLIC, "reached through an outbound proxy")


def _table(rows):
    return tuple((ipaddress.ip_network(net), Address(rank, word)) for net, rank, word in rows)


# The clouds' metadata services are on link-local addresses (169.254.169.254: AWS, Azure, Google, Oracle, DigitalOcean,
# IBM's VPC, Hetzner, OpenStack; 169.254.0.23: Tencent's metadata.tencentyun.com; 169.254.169.253: IBM's Power Virtual
# Server; fe80::a9fe:a9fe: OpenStack's over IPv6), which are `never` already. The rows marked "metadata", "cloud
# credentials" and "cloud platform" are the ones the clouds document outside link-local, in ranges that are otherwise
# private or public.
_V4 = _table([                                  # (the first that holds the address answers)
    ("0.0.0.0/32", NEVER, "unspecified"),
    ("255.255.255.255/32", NEVER, "broadcast"),
    ("0.0.0.0/8", NEVER, "reserved"),           # ("this network": Linux connects 0.x.x.x to this machine)
    ("127.0.0.0/8", LOOPBACK, "loopback"),
    ("169.254.0.0/16", NEVER, "link-local"),    # (169.254.169.254 and the others above: the metadata services)
    ("224.0.0.0/4", NEVER, "multicast"),
    ("240.0.0.0/4", NEVER, "reserved"),
    ("100.100.100.200/32", NEVER, "metadata"),        # Alibaba Cloud ECS's metadata service (in carrier-grade NAT)
    ("168.63.129.16/32", NEVER, "cloud platform"),    # Azure's WireServer: the VM agent's channel, DHCP, DNS (public)
    ("10.0.0.0/8", PRIVATE, "private"),
    ("172.16.0.0/12", PRIVATE, "private"),
    ("192.168.0.0/16", PRIVATE, "private"),
    ("100.64.0.0/10", PRIVATE, "carrier-grade NAT"),
    ("198.18.0.0/15", PRIVATE, "benchmarking"),
    ("192.0.0.0/24", NEVER, "special-purpose"),  # (the IETF's protocol assignments)
    ("192.0.2.0/24", NEVER, "documentation"),
    ("198.51.100.0/24", NEVER, "documentation"),
    ("203.0.113.0/24", NEVER, "documentation"),
])

_V6 = _table([
    ("::/128", NEVER, "unspecified"),
    ("::1/128", LOOPBACK, "loopback"),
    ("fe80::/10", NEVER, "link-local"),
    ("fec0::/10", NEVER, "site-local"),
    ("fd00:ec2::254/128", NEVER, "metadata"),         # AWS's instance metadata service (IMDS) over IPv6
    ("fd00:ec2::253/128", NEVER, "cloud platform"),   # AWS's DNS (Route 53 Resolver) over IPv6
    ("fd00:ec2::123/128", NEVER, "cloud platform"),   # AWS's time server (Amazon Time Sync) over IPv6
    # AWS's EKS Pod Identity Agent over IPv6, the twin of 169.254.170.23: a pod's AWS credentials ("Set up the Amazon
    # EKS Pod Identity Agent", docs.aws.amazon.com/eks/latest/userguide/pod-id-agent-setup.html: "the localhost IP
    # address [fd00:ec2::23] for IPv6")
    ("fd00:ec2::23/128", NEVER, "cloud credentials"),
    ("fd20:ce::254/128", NEVER, "metadata"),          # Google Compute Engine's metadata server over IPv6
    ("fc00::/7", PRIVATE, "unique-local"),
    ("ff00::/8", NEVER, "multicast"),
    ("100::/64", NEVER, "special-purpose"),     # (discard-only)
    ("2001:db8::/32", NEVER, "documentation"),
    ("3fff::/20", NEVER, "documentation"),
    ("5f00::/16", NEVER, "special-purpose"),    # (SRv6 segment identifiers)
])

_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")
_COMPATIBLE = ipaddress.ip_network("::/96")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")


def _v4(value):
    return ipaddress.IPv4Address(value & 0xFFFFFFFF)


def _stricter(*addresses):
    return min(addresses, key=lambda a: a.rank)


def nat64_local_readings(ip):
    """The IPv4 addresses an address in NAT64's local-use prefix (64:ff9b:1::/48, RFC 8215) carries, read at each
    length a network may give its translation prefix within that /48, by RFC 6052's formats (bits 64-71 are skipped):
    /48 (bits 48-63 and 72-87), /56 (bits 56-63 and 72-95), /64 (bits 72-103) and /96 (bits 96-127). The address does
    not say which length its network uses, so each reading counts (`_classify`: the strictest)."""
    b = int(ip).to_bytes(16, "big")
    return tuple(ipaddress.IPv4Address(bytes(r)) for r in (b[6:8] + b[9:11], b[7:8] + b[9:12], b[9:13], b[12:16]))


def _classify(ip):
    if ip.version == 4:
        for net, address in _V4:
            if ip in net:
                return address
        return Address(PUBLIC, "public") if ip.is_global else Address(NEVER, "special-purpose")
    value = int(ip)
    if ip in _MAPPED or ip in _TRANSLATED or ip in _NAT64:
        return _classify(_v4(value))
    if ip in _COMPATIBLE and value > 1:                     # (:: and ::1 are IPv6's own)
        return _classify(_v4(value))
    if ip in _NAT64_LOCAL:                                  # (private at best, and every reading counts)
        return _stricter(Address(PRIVATE, "private"), *(_classify(v4) for v4 in nat64_local_readings(ip)))
    if ip in _SIX_TO_FOUR:
        return _classify(_v4(value >> 80))
    if ip in _TEREDO:                                       # the server's address, and the client's (inverted)
        return _stricter(_classify(_v4(value >> 64)), _classify(_v4(~value)))
    for net, address in _V6:
        if ip in net:
            return address
    return Address(PUBLIC, "public") if ip.is_global else Address(NEVER, "special-purpose")


def classify(text):
    """The `Address` of an IP address as a socket gives it ("10.1.2.3", "::ffff:127.0.0.1", "fe80::1%eth0", or an
    `ipaddress` object). A text that is not an address is `never` (nothing can be judged of it)."""
    try:
        ip = text if isinstance(text, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else \
            ipaddress.ip_address(str(text).split("%", 1)[0].strip("[]"))
    except ValueError:
        return Address(NEVER, "unreadable")
    return _classify(ip)


def allowed(hop, proxy):
    """May a redirect off the configured hosts connect to `hop` (an `Address`) when the configured proxy it came from is
    on `proxy` (an `Address`; None when that is not known, which grants what a public one does)?"""
    if hop.rank == PUBLIC:
        return True
    rank = proxy.rank if proxy is not None else PUBLIC
    if hop.rank == PRIVATE:
        return rank in (LOOPBACK, PRIVATE)
    if hop.rank == LOOPBACK:
        return rank == LOOPBACK
    return False


def least_granting(addresses):
    """Of a proxy's addresses (`Address`es), the one that lets a redirect reach the least: a name that gives a public
    and a private address is a public proxy's. None for none."""
    grants = {LOOPBACK: 2, PRIVATE: 1}
    return min(addresses, key=lambda a: grants.get(a.rank, 0), default=None)


def _a(word):
    return f"an {word}" if word[:1] in "aeiou" else f"a {word}"


def refusal(hop, ip, proxy, name=None, origin="the proxy"):
    """Why a redirect to `ip` (its `Address` `hop`; reached by the host `name`, when that is not the address itself)
    is refused, for a configured host (`origin`: "the proxy", "the feed's host") on `proxy` (None: not known):
    "redirect to a private address (10.1.2.3) refused: the proxy is on a public address"."""
    where = f"{_a(hop.word)} address ({ip})"
    what = f"redirect to {name}, {where}, refused" if name and name != str(ip) else f"redirect to {where} refused"
    if hop.rank == NEVER:
        return f"{what}: a redirect never leads to such an address"
    if proxy is None:
        return f"{what}: {origin}'s own address is not known"
    if proxy is RELAYED:
        return f"{what}: {origin} is reached through an outbound proxy, so it counts as on a public address"
    return f"{what}: {origin} is on {_a(proxy.word)} address"


# ---------------------------------------------------------------- one fetch's rule
class Refused(Exception):
    """A hop `Hops` refuses (its `error` when the caller gives none): the message says why."""


#: lazaret-net's refusal of a redirect by the host rule (pratique's `Refused`: "redirect 2 refused: host not allowed: x is
#: not in the allowed hosts")
_OFF_THE_HOSTS = re.compile(r"redirect \d+ refused: host not allowed: ")


def refused_elsewhere(exc):
    """Is `exc` (nativenet.NetError) the native transport's refusal of a redirect to a host its rule does not name? Its
    caller makes the fetch again on Python's transport, where `Hops` judges the hop by its address."""
    return getattr(exc, "kind", None) == "refused" and bool(_OFF_THE_HOSTS.match(str(exc)))


def named(hosts, host, port):
    """Is host:port one of `hosts` (netlocs, lower case: "host", "host:port", "[v6]:port"), as a URL's netloc is read:
    the host with its port, or the host alone?"""
    host = (host or "").strip("[]").lower()
    shown = f"[{host}]" if ":" in host else host
    return f"{shown}:{port}" in hosts or shown in hosts or host in hosts


class Hops:
    """Where the hops of one fetch may connect. `configured(host, port)` says whether a host is one the fetch was given:
    a hop to it is made as before, and the class of the address it reached is kept (`proxy`: directly, the peer's;
    through an outbound proxy, `RELAYED`, a public one's, or the class of the address its URL names). A hop to any
    other host is judged by the address it connects to against the configured host the fetch reached last (`allowed`),
    and refused with `error` (Refused, or the caller's exception class: it is raised with the message alone; `origin`
    names the configured host in it).

    Directly, every address the hop's name gives is judged before any is tried, and the address connected to once more
    (getpeername), so a name that answers otherwise when it is asked again cannot get past it. Through an outbound proxy
    (HTTPS_PROXY's tunnel, HTTP_PROXY's forward request, the system's), the peer is that proxy, which is no hop, and the
    names are looked up there. A lookup made here only ever refuses: the hop's name is looked up here too and every
    address it gives judged (a name that cannot be looked up here is refused), and the configured host's name is not
    (it counts as a public one's: `RELAYED`). What the outbound proxy's own lookup gives is not seen (docs/DESIGN.md:
    the gap that remains).

    `lookup` (socket.getaddrinfo's arguments and answer) and `peer` ((the host, an address it was found at or connected
    to) -> the address to judge in its place) are the tests', so that a server on 127.0.0.1 can stand in for a public or
    a private one."""

    def __init__(self, configured, error=Refused, origin="the proxy", lookup=None, peer=None):
        self.configured, self.error, self.origin = configured, error, origin
        self._lookup, self._peer = lookup, peer
        self.proxy = None                   # the Address of the configured host reached last; None: not known

    def lookup(self, host, port, family=0, kind=0, *rest):
        return (self._lookup or socket.getaddrinfo)(host, port, family, kind, *rest)

    def address(self, host, ip):
        """(the address judged for `ip`, at which `host` was found or reached, as text; its Address)."""
        ip = str(ip).split("%", 1)[0]
        if self._peer is not None:
            ip = self._peer(host, ip)
        return ip, classify(ip)

    def addresses(self, host, port):
        """The addresses `lookup` gives for host here, or [] when it gives none."""
        try:
            return [where[0] for *_, where in self.lookup(host, port, 0, socket.SOCK_STREAM)]
        except (OSError, UnicodeError, ValueError):
            return []

    def learn(self, host, ips):
        """The configured host `host` was reached at these addresses: its class is the least any of them grants (None
        for none: as a public one's)."""
        self.proxy = least_granting([self.address(host, ip)[1] for ip in ips])

    def learn_relayed(self, host):
        """The configured host `host` was reached through an outbound proxy, whose own lookup of its name decides where
        the tunnel goes: a lookup here proves nothing of that (the name's operator may answer this machine 127.0.0.1
        and the proxy its real address), so it grants what a public one does (`RELAYED`), unless `host` is written as
        an address, whose class is then that address's."""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            self.proxy = RELAYED
            return
        self.proxy = self.address(host, host)[1]

    def judge(self, host, ip):
        """`error` unless a hop off the configured hosts may connect to `ip` (the host `host`'s, which is the address
        itself where the URL names one)."""
        ip, hop = self.address(host, ip)
        if not allowed(hop, self.proxy):
            raise self.error(refusal(hop, ip, self.proxy, host, self.origin))

    def judge_url(self, url):
        """A redirect's URL: one that names an address, not a host, off the configured hosts is judged already."""
        parts = urllib.parse.urlsplit(url)
        host = (parts.hostname or "").lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return                                  # (a name: judged by the address it connects to)
        if not self.configured(host, parts.port or {"https": 443, "http": 80}.get(parts.scheme, 0)):
            self.judge(host, host)

    def connector(self, conn, deadline=None):
        """The function the http.client connection `conn` makes its socket with (its `_create_connection`; keepalive.Pool's
        `connect` hook)."""
        def make(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
            return open_socket(address, timeout, source_address, deadline, HopTarget(self, conn))
        return make

    def reused(self, conn):
        """A kept connection (keepalive.Pool's `reuse` hook), before it carries a request of this fetch: judged, or
        learned from, as a new one is, by the address it is connected to (through an outbound proxy, as `before`)."""
        target = HopTarget(self, conn)
        if target.relayed:
            target.before(())
        else:
            target.after(conn.sock)


class HopTarget:
    """One connection of a fetch held to its `Hops`: the host and port it is for, and whether they are configured ones.
    Through an outbound proxy (`relayed`) that is not the host the socket goes to, the outbound proxy, which is no hop:
    it is the tunnel's (HTTPS_PROXY: CONNECT), or `forward`'s, the request's own host and port where `conn` is the
    connection to a forward proxy that is sent the request whole (HTTP_PROXY, for a plain-http URL)."""

    def __init__(self, hops, conn, forward=None):
        tunnel = getattr(conn, "_tunnel_host", None)
        self.hops = hops
        self.relayed = bool(tunnel) or forward is not None
        if tunnel:
            host, self.port = tunnel, conn._tunnel_port
        elif forward is not None:
            host, self.port = forward
        else:
            host, self.port = conn.host, conn.port
        self.host = (host or "").strip("[]").lower()
        self.configured = hops.configured(self.host, self.port)

    def before(self, found):
        """Before anything is connected: directly, every address of `found` (the lookup of the host: the addresses
        that may be tried) is judged; through an outbound proxy (whose own addresses `found` then are: no hop), the
        host's addresses as looked up here (a host that cannot be is refused). A configured host's are learned instead
        (through a proxy, `learn_relayed`: a public one's, unless its URL names an address; directly, the address
        reached, `after`)."""
        if self.relayed:
            if self.configured:
                self.hops.learn_relayed(self.host)
                return
            ips = self.hops.addresses(self.host, self.port)
            if not ips:
                raise self.hops.error(f"redirect to {self.host} refused: it is reached through a proxy, and its address "
                                      f"could not be looked up here to be judged")
            for ip in ips:
                self.hops.judge(self.host, ip)
        elif not self.configured:
            for *_, where in found:
                self.hops.judge(self.host, where[0])

    def after(self, sock):
        """The address connected to (directly: the peer), learned for a configured host and judged for another."""
        if self.relayed:
            return
        ip = sock.getpeername()[0]
        if self.configured:
            self.hops.learn(self.host, [ip])
        else:
            self.hops.judge(self.host, ip)


def open_socket(address, timeout, source_address=None, deadline=None, target=None):
    """socket.create_connection for an http.client connection (its `_create_connection`). With a `HopTarget`: the name
    is looked up by the rule's `lookup`, every address it gives is judged before any is tried (`before`), and the
    address connected to (getpeername) once more (`after`), so the address judged is the one connected to, whatever
    the name answers the next time it is asked (DNS rebinding); a refusal closes the socket and is not taken for one
    address's failure. With a deadline (registry/guard.py's `_Deadline`: `wait`, `watch`, `ran_out`): nothing once its
    time is up, not even the name's lookup; each address's attempt gets its `wait`'s timeout, and the socket made is
    watched."""
    host, port = address
    error = None
    if deadline is not None:
        deadline.wait(timeout)
    lookup = target.hops.lookup if target is not None else socket.getaddrinfo
    found = lookup(host, port, 0, socket.SOCK_STREAM)
    if target is not None:
        target.before(found)
    for family, kind, proto, _, where in found:
        wait, cut = deadline.wait(timeout) if deadline is not None else (timeout, False)
        sock = socket.socket(family, kind, proto)
        try:
            if wait is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(wait)
            if source_address:
                sock.bind(source_address)
            sock.connect(where)
            if target is not None:
                target.after(sock)
            if deadline is not None:
                deadline.watch(sock)
        except OSError as exc:
            sock.close()
            if target is not None and isinstance(exc, target.hops.error):
                raise
            if cut and isinstance(exc, socket.timeout):
                deadline.ran_out()
            error = exc
            continue
        except BaseException:
            sock.close()
            raise
        return sock
    raise error if error is not None else OSError("getaddrinfo returns an empty list")


class HeldHTTPSConnection(http.client.HTTPSConnection):
    """http.client's HTTPS connection held to a fetch's `Hops` (`hops=`): its socket made by `open_socket`. (urllib's
    handler gives it its context: nativenet.tls_context, the TLS floor.)"""

    def __init__(self, *args, hops, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = hops.connector(self)
