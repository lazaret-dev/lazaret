"""Connection parameters: DSN parsing (URL and key=value forms), environment
variables, and ~/.pgpass lookup, following libpq conventions."""

from __future__ import annotations

import getpass
import ipaddress
import logging
import os
import re
import stat
import warnings
from dataclasses import dataclass, field
from urllib.parse import unquote

from .errors import InterfaceError

_log = logging.getLogger("lazaret.pg")

SSLMODES = ("disable", "prefer", "require", "verify-ca", "verify-full")
CHANNEL_BINDING = ("disable", "prefer", "require")
AUTH_METHODS = ("password", "md5", "gss", "sspi", "scram-sha-256", "none")

TARGET_SESSION_ATTRS = ("any", "read-write", "read-only", "primary", "standby", "prefer-standby")
TLS_VERSIONS = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")

# libpq parameters that lazaret.pg implements.
_KEYS = {
    "host", "hostaddr", "port", "user", "password", "dbname", "passfile", "options",
    "application_name", "fallback_application_name", "client_encoding", "connect_timeout",
    "sslmode", "requiressl", "sslrootcert", "sslcert", "sslkey", "sslpassword", "sslcertmode",
    "sslcrl", "sslcrldir", "sslsni", "ssl_min_protocol_version", "ssl_max_protocol_version",
    "channel_binding", "require_auth", "gssencmode", "target_session_attrs", "requirepeer",
    "keepalives", "keepalives_idle", "keepalives_interval", "keepalives_count", "tcp_user_timeout",
}
# libpq parameters that are accepted but have no effect here (GSSAPI, multiple
# hosts, newer protocol features). A warning names them unless the value is
# the no-op default.
_IGNORED = {
    "sslcompression": {"0"}, "load_balance_hosts": {"disable"}, "gssdelegation": {"0"},
    "sslnegotiation": {"postgres"}, "min_protocol_version": {"3.0"}, "max_protocol_version": {"3.0"},
    "krbsrvname": set(), "gsslib": set(), "sslkeylogfile": set(),
    "scram_client_key": set(), "scram_server_key": set(),
    "oauth_issuer": set(), "oauth_client_id": set(), "oauth_client_secret": set(), "oauth_scope": set(),
}
# libpq parameters that would change where or how we connect, so ignoring
# them silently would be wrong: refused unless they are off.
_REFUSED = {
    "service": "service files (pg_service.conf) are not supported; give the connection parameters directly",
    "replication": "replication connections are not supported",
}
_KNOWN = _KEYS | set(_IGNORED) | set(_REFUSED)
_ALIASES = {"database": "dbname"}
_ENV = {
    "host": "PGHOST", "hostaddr": "PGHOSTADDR", "port": "PGPORT", "user": "PGUSER",
    "password": "PGPASSWORD", "dbname": "PGDATABASE", "sslmode": "PGSSLMODE",
    "requiressl": "PGREQUIRESSL", "sslrootcert": "PGSSLROOTCERT", "sslcert": "PGSSLCERT",
    "sslkey": "PGSSLKEY", "sslcertmode": "PGSSLCERTMODE", "sslcrl": "PGSSLCRL",
    "sslcrldir": "PGSSLCRLDIR", "sslsni": "PGSSLSNI",
    "ssl_min_protocol_version": "PGSSLMINPROTOCOLVERSION",
    "ssl_max_protocol_version": "PGSSLMAXPROTOCOLVERSION", "connect_timeout": "PGCONNECT_TIMEOUT",
    "application_name": "PGAPPNAME", "channel_binding": "PGCHANNELBINDING",
    "require_auth": "PGREQUIREAUTH", "options": "PGOPTIONS", "passfile": "PGPASSFILE",
    "gssencmode": "PGGSSENCMODE", "target_session_attrs": "PGTARGETSESSIONATTRS",
    "requirepeer": "PGREQUIREPEER",
}
# Unix-socket directories that libpq builds use by default (upstream: /tmp;
# Debian/Ubuntu and Red Hat: /var/run/postgresql). For ~/.pgpass, only these
# count as "localhost"; any other socket directory matches its own path.
DEFAULT_SOCKET_DIRS = ("/tmp", "/var/run/postgresql", "/run/postgresql")


@dataclass(frozen=True)
class ConnectParams:
    host: str
    port: int
    user: str
    database: str
    password: str | None = field(default=None, repr=False)
    sslmode: str = "prefer"
    sslrootcert: str | None = None
    sslcert: str | None = None
    sslkey: str | None = None
    connect_timeout: float | None = 30.0
    application_name: str | None = "lazaret"
    channel_binding: str = "prefer"
    require_auth: tuple[bool, frozenset[str]] | None = None  # (negated, methods)
    options: str | None = None
    passfile: str | None = None
    keepalives: bool = True                 # TCP keepalives, as in libpq
    keepalives_idle: int | None = None      # seconds; None: the system default
    keepalives_interval: int | None = None  # seconds
    keepalives_count: int | None = None
    tcp_user_timeout: int | None = None     # milliseconds (Linux)
    hostaddr: str | None = None             # numeric address to connect to; host still names the server
    sslpassword: str | None = field(default=None, repr=False)
    sslcertmode: str = "allow"
    sslcrl: str | None = None
    sslcrldir: str | None = None
    sslsni: bool = True
    ssl_min_protocol_version: str = "TLSv1.2"
    ssl_max_protocol_version: str | None = None
    target_session_attrs: str = "any"
    requirepeer: str | None = None

    @property
    def is_unix_socket(self) -> bool:
        return not self.hostaddr and self.host.startswith("/")

    @property
    def unix_socket_path(self) -> str:
        return os.path.join(self.host, f".s.PGSQL.{self.port}")


def parse_dsn(dsn: str) -> dict[str, str]:
    """Parse a postgresql:// URL or a libpq key=value string into a dict.

    Error messages never include parsed values, because a malformed string
    may put part of the password where another value was expected."""
    dsn = dsn.strip()
    for prefix in ("postgresql://", "postgres://"):
        if dsn.startswith(prefix):
            return _parse_url(dsn[len(prefix):])
    return _parse_keyvalue(dsn)


_PCT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _pct(text: str) -> str:
    """Percent-decode one URI component the way libpq does: '+' stays '+',
    malformed escapes and %00 are errors, and bytes that are not UTF-8 are
    kept (as surrogate escapes) so they reach the server unchanged."""
    if "%" not in text:
        return text
    if _PCT_RE.search(text):
        raise InterfaceError("invalid percent-encoded token in connection URI")
    if re.search(r"%00", text):
        raise InterfaceError("forbidden value %00 in percent-encoded value in connection URI")
    return unquote(text, errors="surrogateescape")


def _parse_url(rest: str) -> dict[str, str]:
    """Parse the part after postgresql:// by hand, like libpq (not urlsplit):
    there are no fragments, so '#' and '?' may appear unencoded in the
    password; the credentials end at the last '@' before the first '/';
    and query values are percent-decoded without turning '+' into a space."""
    out: dict[str, str] = {}
    slash = rest.find("/")
    at = (rest if slash < 0 else rest[:slash]).rfind("@")
    if at >= 0:
        user, sep, password = rest[:at].partition(":")
        if user:
            out["user"] = _pct(user)
        if sep and password:
            out["password"] = _pct(password)
        rest = rest[at + 1:]
    end = min((i for i in (rest.find("/"), rest.find("?")) if i >= 0), default=len(rest))
    hostport, rest = rest[:end], rest[end:]
    if "," in hostport:
        raise InterfaceError("multiple hosts in one connection string are not supported")
    if hostport.startswith("["):  # [IPv6]:port
        close = hostport.find("]")
        if close < 0:
            raise InterfaceError("missing ']' after an IPv6 host address in connection URI")
        host, after = hostport[1:close], hostport[close + 1:]
        if after and not after.startswith(":"):
            raise InterfaceError("unexpected character after an IPv6 host address in connection URI")
        port = after[1:]
    else:
        host, _, port = hostport.partition(":")
    if host:
        out["host"] = _pct(host)
    if port:
        out["port"] = _pct(port)
    query = ""
    if rest.startswith("/"):
        path, _, query = rest[1:].partition("?")
        if path:
            out["dbname"] = _pct(path)
    elif rest.startswith("?"):
        query = rest[1:]
    for item in query.split("&"):
        if not item:
            continue
        key, sep, value = item.partition("=")
        if not sep:
            raise InterfaceError("missing key/value separator '=' in connection URI query parameter")
        key, value = _pct(key), _pct(value)
        if key == "ssl" and value == "true":  # libpq's JDBC-compatible spelling
            key, value = "sslmode", "require"
        out[_ALIASES.get(key, key)] = value
    _check_keys(out)
    return out


def _parse_keyvalue(s: str) -> dict[str, str]:
    out: dict[str, str] = {}
    i, n = 0, len(s)
    while i < n:
        while i < n and s[i].isspace():
            i += 1
        if i >= n:
            break
        start = i
        while i < n and s[i] not in "= \t\n\r\f\v":
            i += 1
        key = s[start:i]
        while i < n and s[i].isspace():
            i += 1
        if i >= n or s[i] != "=" or not key:
            # Don't name the word: after "password=two words" it is part of the password.
            raise InterfaceError("missing '=' after a parameter name in connection string "
                                 "(quote values that contain spaces: password='two words')")
        i += 1
        while i < n and s[i].isspace():
            i += 1
        value = []
        if i < n and s[i] == "'":
            i += 1
            while True:
                if i >= n:
                    raise InterfaceError("unterminated quoted value in connection string")
                if s[i] == "\\" and i + 1 < n:
                    value.append(s[i + 1])
                    i += 2
                elif s[i] == "'":
                    i += 1
                    break
                else:
                    value.append(s[i])
                    i += 1
        else:
            while i < n and not s[i].isspace():
                if s[i] == "\\" and i + 1 < n:
                    value.append(s[i + 1])
                    i += 2
                else:
                    value.append(s[i])
                    i += 1
        out[_ALIASES.get(key, key)] = "".join(value)
    _check_keys(out)
    return out


def _check_keys(d: dict[str, str]) -> None:
    unknown = set(d) - _KNOWN
    if unknown:
        if "password" in d:
            # A misquoted password can turn into "keys": don't echo them.
            raise InterfaceError("unknown connection parameter in connection string "
                                 "(names not shown because the string contains a password)")
        raise InterfaceError(f"unknown connection parameter(s): {', '.join(sorted(unknown))}")


def _parse_require_auth(value: str) -> tuple[bool, frozenset[str]]:
    items = [v.strip() for v in value.split(",") if v.strip()]
    if not items:
        raise InterfaceError("require_auth is empty")
    negated = {v.startswith("!") for v in items}
    if len(negated) != 1:
        raise InterfaceError("require_auth cannot mix negated and non-negated methods")
    methods = frozenset(v.lstrip("!") for v in items)
    bad = methods - set(AUTH_METHODS)
    if bad:
        raise InterfaceError(f"unknown require_auth method(s): {', '.join(sorted(bad))}")
    return negated.pop(), methods


def _nonnegative_int(merged: dict[str, str], key: str) -> int | None:
    """libpq-style integer setting: unset or 0 means "system default" (None)."""
    raw = merged.get(key)
    if raw is None or raw == "":
        return None
    try:
        value = int(raw)
    except ValueError:
        raise InterfaceError(f"{key} must be a whole number") from None
    if value < 0:
        raise InterfaceError(f"{key} must not be negative")
    return value or None


def _default_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no login name available (e.g. some containers)
        return "postgres"


def resolve(dsn: str | None = None, **kwargs: object) -> ConnectParams:
    """Merge keyword arguments > DSN > PG* environment variables > defaults."""
    merged: dict[str, str] = {}
    for key, env in _ENV.items():
        if os.environ.get(env):
            merged[key] = os.environ[env]
    if dsn:
        merged.update(parse_dsn(dsn))
    for key, value in kwargs.items():
        key = _ALIASES.get(key, key)
        if key not in _KNOWN:
            raise InterfaceError(f"unknown connection parameter: {key}")
        if value is not None:
            merged[key] = value if isinstance(value, str) else str(value)
    for key, default in _IGNORED.items():
        value = merged.get(key)
        if value and value not in default:
            warnings.warn(f"lazaret.pg does not support the connection parameter {key!r}; ignoring it",
                          stacklevel=3)
    for key, message in _REFUSED.items():
        if merged.get(key, "").lower() not in ("", "0", "false", "off", "no"):
            raise InterfaceError(message)

    user = merged.get("user") or _default_user()
    try:
        port = int(merged.get("port") or "5432")
        if not 0 < port < 65536:
            raise ValueError
    except ValueError:
        # The value is not shown: in a malformed URL it can be part of the password.
        raise InterfaceError("invalid port number in connection parameters") from None
    if "sslmode" not in merged:
        if merged.get("sslrootcert") == "system":
            merged["sslmode"] = "verify-full"  # libpq 16: the default with the system CA store
        elif merged.get("requiressl") == "1":
            merged["sslmode"] = "require"      # deprecated libpq spelling
    sslmode = merged.get("sslmode", "prefer")
    if sslmode not in SSLMODES:
        raise InterfaceError(f"sslmode must be one of {', '.join(SSLMODES)}")
    channel_binding = merged.get("channel_binding", "prefer")
    if channel_binding not in CHANNEL_BINDING:
        raise InterfaceError(f"channel_binding must be one of {', '.join(CHANNEL_BINDING)}")
    if merged.get("sslrootcert") == "system" and sslmode != "verify-full":
        raise InterfaceError("sslrootcert=system requires sslmode=verify-full")
    _check_choice(merged, "sslcertmode", ("disable", "allow"),
                  {"require": "sslcertmode=require is not supported"})
    _check_choice(merged, "gssencmode", ("disable", "prefer"),
                  {"require": "gssencmode=require: GSSAPI encryption is not supported"})
    _check_choice(merged, "target_session_attrs", TARGET_SESSION_ATTRS)
    _check_choice(merged, "ssl_min_protocol_version", TLS_VERSIONS)
    _check_choice(merged, "ssl_max_protocol_version", TLS_VERSIONS)
    _check_choice(merged, "sslsni", ("0", "1"))
    encoding = merged.get("client_encoding", "UTF8")
    if encoding.upper().replace("-", "").replace("_", "") not in ("UTF8", "UNICODE", "AUTO"):
        raise InterfaceError("lazaret.pg only supports client_encoding UTF8")
    min_tls = merged.get("ssl_min_protocol_version") or "TLSv1.2"
    if TLS_VERSIONS.index(min_tls) < TLS_VERSIONS.index("TLSv1.2"):
        warnings.warn("lazaret.pg requires TLS 1.2 or newer; ignoring ssl_min_protocol_version="
                      f"{min_tls}", stacklevel=2)
        min_tls = "TLSv1.2"
    max_tls = merged.get("ssl_max_protocol_version") or None
    if max_tls and TLS_VERSIONS.index(max_tls) < TLS_VERSIONS.index(min_tls):
        raise InterfaceError("ssl_max_protocol_version is lower than ssl_min_protocol_version")
    hostaddr = merged.get("hostaddr") or None
    if hostaddr:
        try:
            ipaddress.ip_address(hostaddr)
        except ValueError:
            raise InterfaceError("hostaddr must be a numeric IPv4 or IPv6 address") from None
    timeout = merged.get("connect_timeout")
    try:
        connect_timeout = float(timeout) if timeout else 30.0
    except ValueError:
        raise InterfaceError("connect_timeout must be a number of seconds") from None
    if connect_timeout <= 0:
        connect_timeout = None

    if "application_name" in merged:
        application_name = merged["application_name"]
    else:
        application_name = merged.get("fallback_application_name") or "lazaret"

    return ConnectParams(
        host=merged.get("host") or hostaddr or "localhost",
        port=port,
        user=user,
        database=merged.get("dbname") or user,
        password=merged.get("password"),
        sslmode=sslmode,
        sslrootcert=merged.get("sslrootcert"),
        sslcert=merged.get("sslcert"),
        sslkey=merged.get("sslkey"),
        connect_timeout=connect_timeout,
        application_name=application_name,
        channel_binding=channel_binding,
        require_auth=_parse_require_auth(merged["require_auth"]) if merged.get("require_auth") else None,
        options=merged.get("options"),
        passfile=merged.get("passfile"),
        keepalives=(_nonnegative_int(merged, "keepalives") or 0) != 0 if merged.get("keepalives") else True,
        keepalives_idle=_nonnegative_int(merged, "keepalives_idle"),
        keepalives_interval=_nonnegative_int(merged, "keepalives_interval"),
        keepalives_count=_nonnegative_int(merged, "keepalives_count"),
        tcp_user_timeout=_nonnegative_int(merged, "tcp_user_timeout"),
        hostaddr=hostaddr,
        sslpassword=merged.get("sslpassword") or None,
        sslcertmode=merged.get("sslcertmode") or "allow",
        sslcrl=merged.get("sslcrl") or None,
        sslcrldir=merged.get("sslcrldir") or None,
        sslsni=merged.get("sslsni", "1") != "0",
        ssl_min_protocol_version=min_tls,
        ssl_max_protocol_version=max_tls,
        target_session_attrs=merged.get("target_session_attrs") or "any",
        requirepeer=merged.get("requirepeer") or None,
    )


def _check_choice(merged: dict[str, str], key: str, allowed: tuple[str, ...],
                  refused: dict[str, str] | None = None) -> None:
    value = merged.get(key)
    if not value or value in allowed:
        return
    if refused and value in refused:
        raise InterfaceError(refused[value])
    raise InterfaceError(f"{key} must be one of {', '.join(allowed + tuple(refused or ()))}")


def default_passfile() -> str:
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA", ""), "postgresql", "pgpass.conf")
    return os.path.expanduser("~/.pgpass")


def default_ssl_dir() -> str:
    """Where libpq looks for root.crt, root.crl, postgresql.crt and postgresql.key."""
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA", ""), "postgresql")
    return os.path.expanduser("~/.postgresql")


def default_root_cert() -> str:
    return os.path.join(default_ssl_dir(), "root.crt")


def default_ssl_file(name: str) -> str | None:
    """libpq's default root.crl / postgresql.crt / postgresql.key, if it exists."""
    path = os.path.join(default_ssl_dir(), name)
    return path if os.path.exists(path) else None


def _split_pgpass_line(line: str) -> list[str]:
    fields, cur, i = [], [], 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if c == ":" and len(fields) < 4:
            fields.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    fields.append("".join(cur))
    return fields


def lookup_pgpass(params: ConnectParams) -> str | None:
    """Find a password in the pgpass file, ignoring it (like libpq) if it is
    readable by group or others."""
    path = params.passfile or default_passfile()
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return None
    if os.name == "posix" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        _log.warning("password file %s has group or world access; ignoring it (chmod 0600 to fix)", path)
        return None
    host = params.host
    if params.is_unix_socket and (host.rstrip("/") or "/") in DEFAULT_SOCKET_DIRS:
        host = "localhost"  # libpq: only the default socket directory counts as localhost
    wanted = (host, str(params.port), params.database, params.user)
    try:
        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            for raw in f:
                line = raw.rstrip("\r\n")
                if not line or line.startswith("#"):
                    continue
                parts = _split_pgpass_line(line)
                if len(parts) != 5:
                    continue
                if all(p == "*" or p == w for p, w in zip(parts[:4], wanted)):
                    return parts[4]
    except OSError:
        return None
    return None
