"""Connection parameters: DSN parsing (URL and key=value forms), environment
variables, and ~/.pgpass lookup, following libpq conventions."""

from __future__ import annotations

import getpass
import logging
import os
import re
import stat
from dataclasses import dataclass, field
from urllib.parse import unquote

from .errors import InterfaceError

_log = logging.getLogger("lazaret.pg")

SSLMODES = ("disable", "prefer", "require", "verify-ca", "verify-full")
CHANNEL_BINDING = ("disable", "prefer", "require")
AUTH_METHODS = ("password", "md5", "gss", "sspi", "scram-sha-256", "none")

_KEYS = {
    "host", "port", "user", "password", "dbname", "sslmode", "sslrootcert", "sslcert", "sslkey",
    "connect_timeout", "application_name", "channel_binding", "require_auth", "options", "passfile",
}
_ALIASES = {"database": "dbname"}
_ENV = {
    "host": "PGHOST", "port": "PGPORT", "user": "PGUSER", "password": "PGPASSWORD",
    "dbname": "PGDATABASE", "sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT",
    "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "connect_timeout": "PGCONNECT_TIMEOUT",
    "application_name": "PGAPPNAME", "channel_binding": "PGCHANNELBINDING",
    "require_auth": "PGREQUIREAUTH", "options": "PGOPTIONS", "passfile": "PGPASSFILE",
}


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

    @property
    def is_unix_socket(self) -> bool:
        return self.host.startswith("/")

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
    unknown = set(d) - _KEYS
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
        if key not in _KEYS:
            raise InterfaceError(f"unknown connection parameter: {key}")
        if value is not None:
            merged[key] = value if isinstance(value, str) else str(value)

    user = merged.get("user") or _default_user()
    try:
        port = int(merged.get("port") or "5432")
        if not 0 < port < 65536:
            raise ValueError
    except ValueError:
        # The value is not shown: in a malformed URL it can be part of the password.
        raise InterfaceError("invalid port number in connection parameters") from None
    sslmode = merged.get("sslmode", "prefer")
    if sslmode not in SSLMODES:
        raise InterfaceError(f"sslmode must be one of {', '.join(SSLMODES)}")
    channel_binding = merged.get("channel_binding", "prefer")
    if channel_binding not in CHANNEL_BINDING:
        raise InterfaceError(f"channel_binding must be one of {', '.join(CHANNEL_BINDING)}")
    if merged.get("sslrootcert") == "system" and sslmode != "verify-full":
        raise InterfaceError("sslrootcert=system requires sslmode=verify-full")
    timeout = merged.get("connect_timeout")
    try:
        connect_timeout = float(timeout) if timeout else 30.0
    except ValueError:
        raise InterfaceError("connect_timeout must be a number of seconds") from None
    if connect_timeout <= 0:
        connect_timeout = None

    return ConnectParams(
        host=merged.get("host") or "localhost",
        port=port,
        user=user,
        database=merged.get("dbname") or user,
        password=merged.get("password"),
        sslmode=sslmode,
        sslrootcert=merged.get("sslrootcert"),
        sslcert=merged.get("sslcert"),
        sslkey=merged.get("sslkey"),
        connect_timeout=connect_timeout,
        application_name=merged.get("application_name", "lazaret"),
        channel_binding=channel_binding,
        require_auth=_parse_require_auth(merged["require_auth"]) if merged.get("require_auth") else None,
        options=merged.get("options"),
        passfile=merged.get("passfile"),
    )


def default_passfile() -> str:
    if os.name == "nt":
        return os.path.join(os.environ.get("APPDATA", ""), "postgresql", "pgpass.conf")
    return os.path.expanduser("~/.pgpass")


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
    host = "localhost" if params.is_unix_socket else params.host
    wanted = (host, str(params.port), params.database, params.user)
    try:
        with open(path, encoding="utf-8") as f:
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
