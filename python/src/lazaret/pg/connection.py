"""PostgreSQL frontend/backend protocol 3.0 client, standard library only.

Queries always use the extended protocol: SQL text and parameter values travel
in separate messages, so values are never spliced into SQL and cannot cause
SQL injection. Placeholders are PostgreSQL's native $1, $2, ...
"""

from __future__ import annotations

import collections
import hashlib
import logging
import os
import selectors
import socket
import ssl
import struct
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Iterator, NoReturn, Sequence

from . import _types
from ._dsn import ConnectParams, default_root_cert, lookup_pgpass, resolve
from ._scram import ScramClient, tls_server_end_point
from .errors import (
    AuthenticationError,
    DatabaseError,
    Error,
    InterfaceError,
    Notice,
    OperationalError,
    error_from_fields,
)

_log = logging.getLogger("lazaret.pg")

PROTOCOL_3_0 = 196608
SSL_REQUEST = 80877103
CANCEL_REQUEST = 80877102
MAX_MESSAGE = 1 << 30  # refuse absurd lengths from a broken or hostile server
MAX_PARAMS = 65535
EXECUTEMANY_CHUNK = 500             # rows per pipelined chunk...
EXECUTEMANY_CHUNK_BYTES = 1 << 20   # ...and bytes (a single larger row is sent alone)
_RECV_SIZE = 65536

_I32 = struct.Struct("!i")
_KINDS = [bytes((i,)) for i in range(256)]
_I16 = struct.Struct("!h")
_SYNC = b"S\x00\x00\x00\x04"
_FLUSH = b"H\x00\x00\x00\x04"
_EXECUTE_ALL = b"E\x00\x00\x00\x09\x00\x00\x00\x00\x00"  # unnamed portal, no row limit
_TERMINATE = b"X\x00\x00\x00\x04"
_COUNTED_TAGS = {"INSERT", "UPDATE", "DELETE", "SELECT", "MOVE", "FETCH", "COPY", "MERGE"}
_ISOLATION = {"read committed", "repeatable read", "serializable"}


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a statement: the server's command tag (e.g. "INSERT 0 3")
    and the affected row count when the command reports one."""

    tag: str
    rowcount: int | None

    @classmethod
    def from_tag(cls, tag: str) -> CommandResult:
        words = tag.split()
        count = int(words[-1]) if words and words[0] in _COUNTED_TAGS and words[-1].isdigit() else None
        return cls(tag, count)


@dataclass(frozen=True)
class Notification:
    """A LISTEN/NOTIFY message."""

    pid: int
    channel: str
    payload: str


def _msg(kind: bytes, payload: bytes) -> bytes:
    return kind + _I32.pack(len(payload) + 4) + payload


# A Parse the server always rejects (syntax error): sent before Sync to make
# the implicit transaction of a pipelined batch fail rather than commit.
_ABORT_BATCH = _msg(b"P", b"\x00lazaret.pg: abandon this batch\x00\x00\x00")


def _cstr(s: str, errors: str = "strict") -> bytes:
    # errors="surrogateescape" for connection values and passwords: bytes that
    # are not UTF-8 (from a percent-encoded URL or the environment) are sent as is.
    b = s.encode("utf-8", errors)
    if b"\x00" in b:
        raise InterfaceError("strings sent to the server cannot contain NUL characters")
    return b + b"\x00"


# Exceptions that mean a server message could not be parsed. Raised while the
# connection is mid-protocol they become OperationalError and close it.
_MALFORMED = (struct.error, ValueError, IndexError)


def _malformed(what: str) -> OperationalError:
    return OperationalError(f"protocol violation: malformed {what} from server")


def _parse_fields(body: bytes) -> dict[str, str]:
    fields: dict[str, str] = {}
    pos = 0
    while pos < len(body) and body[pos] != 0:
        code = chr(body[pos])
        end = body.find(b"\x00", pos + 1)
        if end < 0:
            raise _malformed("error or notice message")
        fields[code] = body[pos + 1:end].decode("utf-8", "replace")
        pos = end + 1
    return fields


def _tag(body: bytes) -> str:
    return body[:-1].decode("utf-8", "replace")


def _default_notice_handler(notice: Notice) -> None:
    level = logging.WARNING if notice.severity == "WARNING" else logging.INFO
    _log.log(level, "%s: %s", notice.severity, notice.message)


def connect(dsn: str | None = None, /, *, timeout: float | None = None,
            allow_cleartext_password: bool = False, allow_md5_over_unverified_tls: bool = False,
            **params: Any) -> Connection:
    """Open a connection.

    dsn: a postgresql:// URL or libpq "key=value" string (optional).
    params: libpq-style keywords that override the DSN: host, port, user,
        password, dbname (or database), sslmode, sslrootcert, sslcert, sslkey,
        connect_timeout, application_name, channel_binding, require_auth,
        options, passfile, keepalives, keepalives_idle, keepalives_interval,
        keepalives_count. Unset values fall back to PG* environment variables.
    timeout: socket timeout in seconds for each network operation after
        connecting. If it expires mid-query, the connection is closed.
    allow_cleartext_password: permit the server's "password" method (the
        plaintext password) over TCP when the server is not authenticated:
        without TLS, or with TLS but no certificate verification (sslmode
        prefer or require). Off by default, because a man-in-the-middle that
        terminates TLS could otherwise ask for the password and read it.
        Unix sockets and sslmode verify-ca/verify-full don't need it.
    allow_md5_over_unverified_tls: permit MD5 password authentication over
        TLS whose certificate was not verified (sslmode prefer or require). Off
        by default: an attacker terminating TLS could relay the MD5 response to
        log in as you, or crack it offline. SCRAM-SHA-256 is unaffected (with
        channel binding it can't be relayed). MD5 without TLS is still allowed,
        as before; use require_auth=scram-sha-256 to refuse MD5 everywhere.
    """
    conn = Connection(resolve(dsn, **params), timeout=timeout,
                      allow_cleartext_password=allow_cleartext_password,
                      allow_md5_over_unverified_tls=allow_md5_over_unverified_tls)
    conn._connect()
    return conn


def _set_keepalive(sock: socket.socket, idle: int | None, interval: int | None, count: int | None) -> None:
    """Apply libpq's keepalives_idle/_interval/_count where the platform allows."""
    options = ((idle, getattr(socket, "TCP_KEEPIDLE", None) or getattr(socket, "TCP_KEEPALIVE", None)),
               (interval, getattr(socket, "TCP_KEEPINTVL", None)),
               (count, getattr(socket, "TCP_KEEPCNT", None)))
    missing = False
    for value, option in options:
        if value is None:
            continue
        if option is None:
            missing = True
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
        except OSError as exc:
            _log.debug("could not set TCP keepalive option %s: %s", option, exc)
    if missing and (idle or interval) and hasattr(socket, "SIO_KEEPALIVE_VALS"):
        # Older Windows: idle time and interval in milliseconds, in one call.
        try:
            sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, (idle or 7200) * 1000, (interval or 1) * 1000))
        except (OSError, ValueError) as exc:
            _log.debug("could not set TCP keepalive values: %s", exc)


class Connection:
    """A single PostgreSQL session. Not safe for concurrent use from multiple
    threads, except cancel(), which is designed to be called from another thread."""

    def __init__(self, params: ConnectParams, *, timeout: float | None = None,
                 allow_cleartext_password: bool = False, allow_md5_over_unverified_tls: bool = False):
        self._params = params
        self._timeout = timeout
        self._allow_cleartext = allow_cleartext_password
        self._allow_md5_unverified = allow_md5_over_unverified_tls
        self._tls_verified = False  # the server's certificate chain was checked (verify-ca/full)
        self._sock: socket.socket | None = None
        self._rbuf = bytearray()  # bytes received from the server but not yet parsed
        self._closed = True
        self._synced = True
        self._stream: object | None = None  # the iterate() that owns the connection, if any
        self._tx_status = b"I"
        self._tx_depth = 0
        self._backend_key: tuple[int, bytes] | None = None
        self._last_error: DatabaseError | None = None  # server error seen in the current exchange
        self._lock = threading.Lock()
        self._decoders: dict[int, Callable[[str], Any]] = dict(_types.DECODERS)
        self._decoder_cache: dict[int, Callable[[bytes], Any]] = {}
        self.parameters: dict[str, str] = {}
        self.notifications: collections.deque[Notification] = collections.deque(maxlen=10_000)
        self.notice_handler: Callable[[Notice], None] = _default_notice_handler
        self.ssl_in_use = False
        self.auth_method: str | None = None
        self.channel_binding_used = False

    # --- public properties ---------------------------------------------------

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def in_transaction(self) -> bool:
        return self._tx_status in (b"T", b"E")

    @property
    def backend_pid(self) -> int | None:
        return self._backend_key[0] if self._backend_key else None

    @property
    def server_version(self) -> tuple[int, ...]:
        """e.g. (16, 4). Parsed from the server_version parameter."""
        raw = (self.parameters.get("server_version") or "0").split()[0]
        parts = []
        for piece in raw.split("."):
            digits = "".join(ch for ch in piece if ch.isdigit())
            if not digits:
                break
            parts.append(int(digits))
        return tuple(parts)

    def __repr__(self) -> str:
        p = self._params
        where = p.host if p.is_unix_socket else f"{p.host}:{p.port}"
        state = "closed" if self._closed else "open"
        return f"<lazaret.pg.Connection {p.user}@{where}/{p.database} {state}>"

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- queries ---------------------------------------------------------------

    def execute(self, sql: str, *args: Any) -> CommandResult:
        """Run one statement and discard any rows. Returns the command tag and row count."""
        with self._io():
            _, _, tags = self._run_extended(sql, args, keep_rows=False)
        return CommandResult.from_tag(tags[-1] if tags else "")

    def fetch(self, sql: str, *args: Any) -> _types.Rows:
        """Run one statement and return all rows."""
        with self._io():
            columns, rows, _ = self._run_extended(sql, args, keep_rows=True)
        out = _types.Rows(rows)
        out.columns = columns
        return out

    def fetchrow(self, sql: str, *args: Any) -> Any:
        """Return the first row, or None. Add LIMIT 1 to avoid transferring extra rows."""
        rows = self.fetch(sql, *args)
        return rows[0] if rows else None

    def fetchval(self, sql: str, *args: Any, column: int = 0) -> Any:
        """Return one value from the first row, or None if there are no rows."""
        row = self.fetchrow(sql, *args)
        return None if row is None else row[column]

    def executemany(self, sql: str, args_seq: Iterable[Sequence[Any]]) -> CommandResult:
        """Run one statement once per parameter tuple, pipelined, in a single
        implicit transaction: outside a transaction() block, either all rows
        succeed or none do. Returns the total row count."""
        encoded = [self._encode_args(args) for args in args_seq]
        if not encoded:
            return CommandResult("", 0)
        sql_b = _cstr(sql)
        total, counted = 0, False
        with self._io():
            self._synced = False
            last_oids = None
            start = 0
            while start < len(encoded):
                # The first row goes alone: if the statement turns out to be COPY FROM
                # STDIN, any message pipelined behind it makes the server drop the
                # connection ("protocol synchronization was lost"). Later chunks are
                # capped by rows and by bytes.
                limit = 1 if start == 0 else EXECUTEMANY_CHUNK
                out = bytearray()
                stop = start
                while stop < len(encoded) and stop - start < limit and len(out) < EXECUTEMANY_CHUNK_BYTES:
                    oids, formats, values = encoded[stop]
                    if oids != last_oids:  # re-prepare when parameter types change
                        out += self._parse_msg(sql_b, oids)
                        last_oids = oids
                    out += self._bind_msg(formats, values)
                    out += _EXECUTE_ALL
                    stop += 1
                out += _FLUSH
                self._send_pipelined(out)
                expected, start = stop - start, stop
                done = 0
                while done < expected:
                    kind, body = self._read_message()
                    if kind == b"C":
                        result = CommandResult.from_tag(_tag(body))
                        if result.rowcount is not None:
                            total += result.rowcount
                            counted = True
                        done += 1
                    elif kind == b"E":
                        error = self._server_error(body)
                        self._send(_SYNC)
                        self._drain_until_ready()
                        raise error
                    elif kind in (b"1", b"2", b"n", b"I", b"T", b"D"):
                        done += kind == b"I"  # rows (e.g. from RETURNING) are discarded
                    elif kind in (b"G", b"H", b"W"):
                        message = self._handle_copy(kind, extended=True)  # CopyIn: CopyFail + Sync
                        if kind == b"H":
                            # COPY TO finishes by itself, and the rows pipelined after it would
                            # still run and commit at Sync: make the batch fail first.
                            self._send(_ABORT_BATCH + _SYNC)
                        self._drain_until_ready()
                        raise InterfaceError(f"{message} (in executemany; nothing was committed)")
                    elif kind in (b"d", b"c"):
                        pass
                    elif not self._handle_async(kind, body):
                        self._unexpected(kind)
            self._send(_SYNC)  # commits the implicit transaction...
            error = self._drain_until_ready()
            if error is not None:  # ...which can still fail (deferred constraint, serialization)
                raise error
        return CommandResult(f"executemany {len(encoded)}", total if counted else None)

    def execute_script(self, sql: str) -> list[CommandResult]:
        """Run one or more semicolon-separated statements with the simple query
        protocol (useful for migrations). Takes no parameters. Unless the script
        contains its own BEGIN/COMMIT, all statements run in one transaction."""
        with self._io():
            self._synced = False
            self._send(_msg(b"Q", _cstr(sql)))
            results, error, unsupported = [], None, None
            while True:
                kind, body = self._read_message()
                if kind == b"C":
                    results.append(CommandResult.from_tag(_tag(body)))
                elif kind == b"E":
                    reported = self._server_error(body)
                    error = error or reported
                elif kind == b"Z":
                    self._ready(body)
                    break
                elif kind in (b"T", b"D", b"I"):
                    pass
                elif kind in (b"G", b"H", b"W", b"d", b"c"):
                    unsupported = unsupported or self._handle_copy(kind, extended=False)
                elif not self._handle_async(kind, body):
                    self._unexpected(kind)
            if unsupported:
                raise InterfaceError(unsupported)
            if error:
                raise error
        return results

    def iterate(self, sql: str, *args: Any, batch_size: int = 1000) -> Iterator[Any]:
        """Stream rows in batches instead of loading them all into memory.
        No other query can run on this connection until the iterator is
        exhausted or closed (use it in a for loop, or call .close()). Leaving
        a transaction() block, or closing the connection, ends a stream that is
        still open; resuming that iterator then raises InterfaceError."""
        if batch_size < 1:
            raise InterfaceError("batch_size must be at least 1")
        oids, formats, values = self._encode_args(args)
        execute = _msg(b"E", b"\x00" + _I32.pack(batch_size))
        request = (self._parse_msg(_cstr(sql), oids) + self._bind_msg(formats, values)
                   + _msg(b"D", b"P\x00") + execute + _FLUSH)
        stream = object()  # identifies this iterate() while it owns the connection
        with self._io():
            self._synced = False
            self._stream = stream
            self._send(request)
        # The lock is only held while talking to the server, not while the
        # consumer handles a batch: close() and transaction() can end the stream.
        try:
            decode, finished = None, False
            while not finished:
                with self._io(stream):
                    batch, finished, decode = self._read_batch(decode)
                yield from batch
                if not finished:
                    with self._io(stream):
                        self._send(execute + _FLUSH)
            with self._io(stream):
                self._stream = None
                self._send(_SYNC)  # commits an implicit transaction, which can still fail
                error = self._drain_until_ready()
            if error is not None:
                raise error
        except GeneratorExit:
            # The consumer stopped early: end the portal. Sync also commits an
            # implicit transaction (e.g. an INSERT ... RETURNING), which can fail.
            if self._stream is stream:
                error = self._end_stream()
                if error is not None:
                    raise error from None
            raise
        finally:
            if self._stream is stream:
                try:
                    self._end_stream()
                except Error:
                    pass  # an exception is already propagating

    def _read_batch(self, decode):
        """Read one batch of an iterate(): (rows, finished, decode)."""
        batch = []
        while True:
            kind, body = self._read_message()
            if kind == b"D":
                if decode is None:
                    raise _malformed("data row before row description")
                batch.append(decode(body))
            elif kind == b"T":
                _, decode = self._row_decoder(body)
            elif kind in (b"C", b"I"):
                return batch, True, decode
            elif kind == b"s":  # PortalSuspended: batch complete
                return batch, False, decode
            elif kind == b"E":
                error = self._server_error(body)
                self._stream = None
                self._send(_SYNC)
                self._drain_until_ready()
                raise error
            elif kind in (b"1", b"2", b"n"):
                # NoData: nothing to stream, but keep reading. The server has
                # already started executing, and may be entering COPY mode.
                pass
            elif kind in (b"G", b"H", b"W"):
                message = self._handle_copy(kind, extended=True)
                self._stream = None
                if kind == b"H":
                    self._send(_SYNC)
                self._drain_until_ready()
                raise InterfaceError(message)
            elif not self._handle_async(kind, body):
                self._unexpected(kind)

    def _end_stream(self) -> DatabaseError | None:
        """End an iterate() whose rows were not all read: Sync closes its
        portal (and commits an implicit transaction). Returns the error the
        server reported at that point, if any."""
        stream = self._stream
        if stream is None or self._closed:
            return None
        with self._io(stream):
            self._stream = None
            if self._synced:
                return None
            self._send(_SYNC)
            return self._drain_until_ready()

    # --- transactions ------------------------------------------------------------

    @contextmanager
    def transaction(self, *, isolation: str | None = None, readonly: bool = False) -> Iterator[Connection]:
        """Commit on success, roll back on exception. Nested blocks use savepoints.

        isolation: "read committed", "repeatable read", or "serializable"
        (outermost block only). Serialization failures raise
        TransactionRollbackError, which is safe to retry.
        """
        if self._tx_depth == 0:
            if self.in_transaction:
                raise InterfaceError("a transaction was started with plain SQL; commit or roll it back first")
            begin = "BEGIN"
            if isolation:
                if isolation.lower() not in _ISOLATION:
                    raise InterfaceError(f"unknown isolation level: {isolation!r}")
                begin += " ISOLATION LEVEL " + isolation.upper()
            if readonly:
                begin += " READ ONLY"
            self.execute(begin)
            savepoint = None
        else:
            if isolation or readonly:
                raise InterfaceError("isolation and readonly apply only to the outermost transaction")
            savepoint = f"lazaret_sp_{self._tx_depth}"
            self.execute(f"SAVEPOINT {savepoint}")
        self._tx_depth += 1
        try:
            yield self
            # An iterate() still open inside the block ends with it.
            error = self._end_stream()
            if error is not None:
                raise error
        except BaseException:
            self._tx_depth -= 1
            self._rollback(savepoint)
            raise
        self._tx_depth -= 1
        if savepoint:
            self.execute(f"RELEASE SAVEPOINT {savepoint}")
        elif self.execute("COMMIT").tag == "ROLLBACK":
            raise InterfaceError(
                "the transaction was rolled back, not committed, because a statement "
                "inside it failed and the error was caught")

    def _rollback(self, savepoint: str | None) -> None:
        if self._closed:
            return
        try:
            self._end_stream()  # an iterate() left open would block the ROLLBACK
            if savepoint:
                self.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
                self.execute(f"RELEASE SAVEPOINT {savepoint}")
            else:
                self.execute("ROLLBACK")
        except Error as exc:
            # The session state is unknown now; closing is the only safe option.
            _log.warning("rollback failed, closing connection: %s", exc)
            self._abort()

    # --- other operations ----------------------------------------------------------

    def register_decoder(self, oid: int, func: Callable[[str], Any]) -> None:
        """Decode columns of type `oid` (e.g. an enum or extension type) with func(text)."""
        self._decoders[oid] = func
        self._decoder_cache.clear()

    def cancel(self) -> None:
        """Ask the server to cancel the query currently running on this
        connection. Safe to call from another thread. The running query then
        raises QueryCanceledError."""
        if self._backend_key is None:
            raise InterfaceError("connection is not open")
        pid, key = self._backend_key
        sock = self._socket_connect()
        try:
            if self.ssl_in_use:
                sock = self._negotiate_ssl(sock)
            sock.sendall(_I32.pack(12 + len(key)) + _I32.pack(CANCEL_REQUEST) + _I32.pack(pid) + key)
            try:
                sock.recv(1)  # server closes the socket once the request is processed
            except OSError:
                pass
        finally:
            sock.close()

    def close(self) -> None:
        """Close the connection. Safe to call more than once."""
        if self._closed:
            return
        # Say goodbye unless another thread is in the middle of a query. A
        # suspended iterate() is fine: the server is waiting for a message, and
        # Terminate rolls back its uncommitted work.
        if self._lock.acquire(blocking=False):
            try:
                self._sock.sendall(_TERMINATE)
            except OSError:
                pass
            finally:
                self._lock.release()
        self._abort()

    # --- connection setup -------------------------------------------------------------

    def reconnect(self) -> None:
        """Close this connection if it is still open, then open a new session
        with the same parameters (for example after the server ended the
        session: ServerOperationalError 57P01, idle session timeout, a network
        failure). Session state such as SET values, temporary tables and LISTEN
        is not carried over; registered decoders, the notice handler and unread
        notifications are kept. Not allowed inside a transaction() block: the
        whole block has to be retried after leaving it."""
        if self._tx_depth:
            raise InterfaceError("cannot reconnect inside a transaction() block; "
                                 "leave the block, then reconnect and retry it")
        self.close()
        self._tx_status = b"I"
        self._decoder_cache.clear()
        self.parameters = {}
        self.ssl_in_use = False
        self._tls_verified = False
        self.auth_method = None
        self.channel_binding_used = False
        self._connect()

    def _connect(self) -> None:
        try:
            self._open()
        except BaseException as exc:
            self._abort()
            if isinstance(exc, _MALFORMED) and not isinstance(exc, Error):
                raise OperationalError(f"protocol violation during connection setup: {exc}") from exc
            raise

    def _open(self) -> None:
        p = self._params
        self._last_error = None
        sock = self._socket_connect()
        self._sock = sock
        self._closed = False
        if not p.is_unix_socket and p.sslmode != "disable":
            sock = self._negotiate_ssl(sock)
            self._sock = sock
        self._rbuf = bytearray()

        startup = {
            "user": p.user,
            "database": p.database,
            "client_encoding": "UTF8",
            "DateStyle": "ISO, YMD",
            "IntervalStyle": "iso_8601",
            "extra_float_digits": "3",
        }
        if p.application_name:
            startup["application_name"] = p.application_name
        if p.options:
            startup["options"] = p.options
        payload = (_I32.pack(PROTOCOL_3_0)
                   + b"".join(_cstr(k) + _cstr(v, "surrogateescape") for k, v in startup.items()) + b"\x00")
        self._send(_I32.pack(len(payload) + 4) + payload)
        self._synced = False
        self._authenticate()
        self._drain_until_ready(startup=True)
        sock.settimeout(self._timeout)

    def _socket_connect(self) -> socket.socket:
        p = self._params
        try:
            if p.is_unix_socket:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(p.connect_timeout)
                sock.connect(p.unix_socket_path)
            else:
                sock = socket.create_connection((p.host, p.port), timeout=p.connect_timeout)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if p.keepalives:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    _set_keepalive(sock, p.keepalives_idle, p.keepalives_interval, p.keepalives_count)
        except (OSError, ValueError) as exc:  # ValueError: e.g. a host name IDNA can't encode
            where = p.unix_socket_path if p.is_unix_socket else f"{p.host}:{p.port}"
            raise OperationalError(f"could not connect to {where}: {exc}") from exc
        return sock

    def _negotiate_ssl(self, sock: socket.socket) -> socket.socket:
        p = self._params
        try:
            sock.sendall(_I32.pack(8) + _I32.pack(SSL_REQUEST))
            # Read exactly one byte straight from the socket: nothing the server
            # (or an attacker) sends before the TLS handshake may be buffered
            # and later mistaken for protected data.
            answer = sock.recv(1)
        except OSError as exc:
            raise OperationalError(f"SSL negotiation failed: {exc}") from exc
        if answer == b"S":
            try:
                context = self._ssl_context()
            except OperationalError:
                raise
            except (OSError, ValueError) as exc:  # missing or unreadable cert/key/CA file
                raise OperationalError(f"could not set up TLS: {exc}") from exc
            try:
                wrapped = context.wrap_socket(sock, server_hostname=p.host)
            except ssl.SSLCertVerificationError as exc:
                raise OperationalError(f"server certificate verification failed: {exc.verify_message}") from exc
            except (ssl.SSLError, OSError) as exc:
                raise OperationalError(f"TLS handshake failed: {exc}") from exc
            self.ssl_in_use = True
            self._tls_verified = context.verify_mode == ssl.CERT_REQUIRED
            return wrapped
        if answer == b"N":
            if p.sslmode in ("require", "verify-ca", "verify-full"):
                raise OperationalError(f"server does not support SSL, but sslmode={p.sslmode}")
            return sock
        raise OperationalError(f"unexpected response to SSL request: {answer!r}")

    def _ssl_context(self) -> ssl.SSLContext:
        p = self._params
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        mode = p.sslmode
        root = p.sslrootcert or default_root_cert()
        if mode == "require" and root != "system" and (p.sslrootcert or os.path.exists(root)):
            # libpq: a root certificate (sslrootcert, or the default ~/.postgresql/root.crt
            # or %APPDATA%\postgresql\root.crt when it exists) upgrades require to verify-ca
            mode = "verify-ca"
        if mode in ("prefer", "require"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.check_hostname = mode == "verify-full"
            ctx.verify_mode = ssl.CERT_REQUIRED
            if root == "system":
                ctx.load_default_certs()
            else:
                if not os.path.exists(root):
                    raise OperationalError(
                        f"sslmode={p.sslmode} needs a root certificate: {root} does not exist "
                        "(set sslrootcert to a CA file, or sslrootcert=system with verify-full)")
                try:
                    ctx.load_verify_locations(cafile=root)
                except (OSError, ValueError) as exc:
                    raise OperationalError(f"could not load root certificate {root}: {exc}") from exc
        if p.sslcert:
            try:
                ctx.load_cert_chain(p.sslcert, p.sslkey)
            except (OSError, ValueError) as exc:
                raise OperationalError(f"could not load client certificate {p.sslcert}: {exc}") from exc
        return ctx

    # --- authentication ----------------------------------------------------------

    def _auth_permitted(self, method: str) -> bool:
        rule = self._params.require_auth
        if rule is None:
            return True
        negated, methods = rule
        return (method not in methods) if negated else (method in methods)

    def _server_authenticated(self) -> bool:
        """True if nobody can be between us and the server: a Unix socket, or
        TLS with a verified certificate chain (verify-ca or verify-full)."""
        return self._params.is_unix_socket or (self.ssl_in_use and self._tls_verified)

    def _password(self) -> str:
        password = self._params.password
        if password is None:
            password = lookup_pgpass(self._params)
        if password is None:
            raise AuthenticationError("the server requested a password, but none was provided "
                                      "(password parameter, PGPASSWORD, or ~/.pgpass)")
        return password

    def _authenticate(self) -> None:
        p = self._params
        scram: ScramClient | None = None
        method: str | None = None
        while True:
            kind, body = self._read_message()
            if kind == b"E":
                raise self._server_error(body)
            if kind == b"v":  # NegotiateProtocolVersion; 3.0 is always supported
                continue
            if kind != b"R":
                raise OperationalError(f"unexpected message {kind!r} during authentication")
            if len(body) < 4:
                raise _malformed("authentication request")
            code = _I32.unpack_from(body)[0]

            if code == 0:  # AuthenticationOk
                if scram is not None and not scram.verified:
                    raise AuthenticationError("server reported success before completing SCRAM authentication")
                method = method or "none"
                if not self._auth_permitted(method):
                    raise AuthenticationError(f"server authenticated with method '{method}', "
                                              f"which require_auth does not allow")
                if p.channel_binding == "require" and not (scram and scram.uses_channel_binding):
                    raise AuthenticationError("channel_binding=require, but the server did not use channel binding")
                self.auth_method = method
                self.channel_binding_used = bool(scram and scram.uses_channel_binding)
                return

            if code in (3, 5, 10):
                method = {3: "password", 5: "md5", 10: "scram-sha-256"}[code]
                if not self._auth_permitted(method):
                    raise AuthenticationError(f"server requested '{method}' authentication, "
                                              f"which require_auth does not allow")
                if code != 10 and p.channel_binding == "require":
                    raise AuthenticationError("channel_binding=require, but the server requested "
                                              f"'{method}' authentication, which cannot use it")

            if code == 3:
                if not (self._server_authenticated() or self._allow_cleartext):
                    where = ("TLS without certificate verification (sslmode=%s)" % p.sslmode
                             if self.ssl_in_use else "an unencrypted connection")
                    raise AuthenticationError(
                        f"server requested a cleartext password over {where}; refusing, since a "
                        "man-in-the-middle could read it (use sslmode=verify-full or verify-ca with "
                        "sslrootcert, or pass allow_cleartext_password=True)")
                self._send(_msg(b"p", _cstr(self._password(), "surrogateescape")))
            elif code == 5:
                if len(body) != 8:
                    raise _malformed("MD5 authentication request")
                if self.ssl_in_use and not self._tls_verified and not self._allow_md5_unverified:
                    raise AuthenticationError(
                        f"server requested MD5 password authentication over TLS without certificate "
                        f"verification (sslmode={p.sslmode}); refusing, since a man-in-the-middle "
                        "could relay or crack it (use sslmode=verify-full or verify-ca with "
                        "sslrootcert, switch the role to SCRAM, or pass allow_md5_over_unverified_tls=True)")
                salt = body[4:8]
                inner = hashlib.md5((self._password() + p.user).encode("utf-8", "surrogateescape")).hexdigest()
                outer = hashlib.md5(inner.encode("ascii") + salt).hexdigest()
                self._send(_msg(b"p", _cstr("md5" + outer)))
            elif code == 10:
                mechanisms = [m.decode("ascii", "replace") for m in body[4:].split(b"\x00") if m]
                scram = self._start_scram(mechanisms)
                first = scram.client_first()
                self._send(_msg(b"p", _cstr(scram.mechanism) + _I32.pack(len(first)) + first))
            elif code == 11:
                if scram is None:
                    raise OperationalError("unexpected SASL continue message")
                self._send(_msg(b"p", scram.client_final(body[4:])))
            elif code == 12:
                if scram is None:
                    raise OperationalError("unexpected SASL final message")
                scram.verify_server_final(body[4:])
            else:
                names = {2: "Kerberos V5", 7: "GSSAPI", 8: "GSSAPI", 9: "SSPI"}
                raise AuthenticationError(
                    f"server requested unsupported authentication method: {names.get(code, code)}")

    def _start_scram(self, mechanisms: list[str]) -> ScramClient:
        p = self._params
        cbind_data = None
        if self.ssl_in_use and p.channel_binding != "disable" and "SCRAM-SHA-256-PLUS" in mechanisms:
            cert = self._sock.getpeercert(binary_form=True)
            cbind_data = tls_server_end_point(cert) if cert else None
        if cbind_data is not None:
            return ScramClient(self._password(), cbind_data=cbind_data)
        if p.channel_binding == "require":
            raise AuthenticationError("channel_binding=require, but channel binding is not available "
                                      "(needs TLS and a server that offers SCRAM-SHA-256-PLUS)")
        if "SCRAM-SHA-256" not in mechanisms:
            raise AuthenticationError(f"no supported SASL mechanism offered: {', '.join(mechanisms)}")
        # "y" tells the server we support channel binding but it didn't offer it,
        # so a man-in-the-middle that strips -PLUS from the list is detected.
        supports = self.ssl_in_use and p.channel_binding != "disable" and "SCRAM-SHA-256-PLUS" not in mechanisms
        return ScramClient(self._password(), client_supports_cb=supports)

    # --- protocol plumbing -------------------------------------------------------------

    @contextmanager
    def _io(self, stream: object | None = None) -> Iterator[None]:
        """Guard one exchange with the server. stream: the iterate() doing it."""
        if self._closed:
            raise InterfaceError("connection is closed")
        if self._stream is not stream:
            if stream is None:
                raise InterfaceError("an iterate() is still in progress on this connection; "
                                     "finish or close it first")
            raise InterfaceError("this iterate() was ended early, by leaving its transaction() block "
                                 "or by an error")
        if not self._lock.acquire(blocking=False):
            raise InterfaceError("connection is already in use by another thread")
        try:
            yield
        except BaseException as exc:
            # Any failure that leaves the protocol out of sync makes the
            # connection unusable; errors raised after ReadyForQuery do not.
            if not self._synced:
                self._abort()
                if isinstance(exc, _MALFORMED) and not isinstance(exc, Error):
                    raise OperationalError(f"protocol violation: malformed message from server ({exc})") from exc
            raise
        finally:
            self._lock.release()

    def _encode_args(self, args: Sequence[Any]) -> tuple[tuple[int, ...], tuple[int, ...], tuple[bytes | None, ...]]:
        if len(args) > MAX_PARAMS:
            raise InterfaceError(f"too many parameters ({len(args)}; the maximum is {MAX_PARAMS})")
        if not args:
            return (), (), ()
        oids, formats, values = zip(*(_types.encode_param(a) for a in args))
        return oids, formats, values

    @staticmethod
    def _parse_msg(sql: bytes, oids: tuple[int, ...]) -> bytes:
        return _msg(b"P", b"\x00" + sql + struct.pack(f"!H{len(oids)}I", len(oids), *oids))

    @staticmethod
    def _bind_msg(formats: tuple[int, ...], values: tuple[bytes | None, ...]) -> bytes:
        parts = [b"\x00\x00", struct.pack(f"!H{len(formats)}h", len(formats), *formats),
                 struct.pack("!H", len(values))]
        for v in values:
            parts.append(b"\xff\xff\xff\xff" if v is None else _I32.pack(len(v)) + v)
        parts.append(b"\x00\x01\x00\x00")  # one result format code: text
        return _msg(b"B", b"".join(parts))

    def _run_extended(self, sql: str, args: Sequence[Any], *, keep_rows: bool):
        oids, formats, values = self._encode_args(args)
        message = (self._parse_msg(_cstr(sql), oids) + self._bind_msg(formats, values)
                   + _msg(b"D", b"P\x00") + _msg(b"E", b"\x00" + _I32.pack(0)) + _SYNC)
        self._synced = False
        self._send(message)
        columns: tuple[str, ...] = ()
        decode = None
        rows: list = []
        tags: list[str] = []
        error: DatabaseError | None = None
        unsupported: str | None = None
        while True:
            kind, body = self._read_message()
            if kind == b"D":
                if keep_rows and error is None:
                    rows.append(decode(body))
            elif kind == b"T":
                columns, decode = self._row_decoder(body)
            elif kind == b"C":
                tags.append(_tag(body))
            elif kind == b"Z":
                self._ready(body)
                break
            elif kind == b"E":
                reported = self._server_error(body)
                error = error or reported
            elif kind in (b"1", b"2", b"n", b"I", b"s"):
                pass
            elif kind in (b"G", b"H", b"W", b"d", b"c"):
                unsupported = unsupported or self._handle_copy(kind, extended=True)
            elif not self._handle_async(kind, body):
                self._unexpected(kind)
        if unsupported:
            raise InterfaceError(unsupported)
        if error:
            raise error
        return columns, rows, tags

    def _row_decoder(self, body: bytes):
        count = _I16.unpack_from(body)[0]
        pos = 2
        names, decoders = [], []
        for _ in range(count):
            end = body.index(b"\x00", pos)
            names.append(body[pos:end].decode("utf-8", "replace"))
            pos = end + 1
            type_oid = struct.unpack_from("!IhI", body, pos)[2]
            pos += 18
            fn = self._decoder_cache.get(type_oid)
            if fn is None:
                fn = self._decoder_cache[type_oid] = _types.decoder_for(type_oid, self._decoders)
            decoders.append(fn)
        columns = tuple(names)
        row_cls = _types.row_class(columns)
        unpack_i32 = _I32.unpack_from

        def decode(data: bytes, decoders=decoders, row_cls=row_cls):
            pos, values = 2, []
            for fn in decoders:
                length = unpack_i32(data, pos)[0]
                pos += 4
                if length < 0:
                    values.append(None)
                else:
                    if pos + length > len(data):
                        raise _malformed("data row")
                    values.append(fn(data[pos:pos + length]))
                    pos += length
            return row_cls(values)

        return columns, decode

    def _handle_copy(self, kind: bytes, *, extended: bool) -> str | None:
        if kind == b"G":  # CopyInResponse: tell the server we won't send data
            fail = _msg(b"f", _cstr("COPY is not supported by lazaret.pg"))
            # In the extended protocol the server ignores Sync during copy-in and
            # needs a fresh one after CopyFail; the simple protocol must not get one.
            self._send(fail + _SYNC if extended else fail)
            return "COPY FROM STDIN is not supported"
        if kind == b"H":  # CopyOutResponse: the data that follows is discarded
            return "COPY TO STDOUT is not supported"
        if kind == b"W":
            self._abort()
            raise InterfaceError("replication (COPY BOTH) is not supported")
        return None  # CopyData / CopyDone: ignore

    def _handle_async(self, kind: bytes, body: bytes) -> bool:
        if kind == b"N":
            notice = Notice.from_fields(_parse_fields(body))  # a malformed notice is a protocol error
            try:
                self.notice_handler(notice)
            except Exception:
                _log.exception("notice handler raised")
            return True
        if kind == b"S":
            parts = body.split(b"\x00")
            if len(parts) < 3:
                raise _malformed("parameter status message")
            name, value = parts[0].decode("utf-8", "replace"), parts[1].decode("utf-8", "replace")
            self.parameters[name] = value
            if name == "client_encoding" and value != "UTF8":
                _log.warning("client_encoding changed to %s; lazaret.pg only supports UTF8", value)
            return True
        if kind == b"A":
            parts = body[4:].split(b"\x00")
            if len(body) < 4 or len(parts) < 3:
                raise _malformed("notification message")
            pid = _I32.unpack_from(body)[0]
            self.notifications.append(Notification(pid, parts[0].decode("utf-8", "replace"),
                                                   parts[1].decode("utf-8", "replace")))
            return True
        if kind == b"K":
            if len(body) < 8:
                raise _malformed("backend key message")
            self._backend_key = (_I32.unpack_from(body)[0], bytes(body[4:]))
            return True
        return False

    def _ready(self, body: bytes) -> None:
        self._tx_status = body[:1]
        self._synced = True
        self._last_error = None

    def _server_error(self, body: bytes) -> DatabaseError:
        """Parse an ErrorResponse, and remember it: if the server closes the
        connection next (a FATAL error), that is the reason to report."""
        error = error_from_fields(_parse_fields(body))
        if self._last_error is None or error.severity in ("FATAL", "PANIC"):
            self._last_error = error
        return error

    def _lost(self, message: str, cause: BaseException | None = None) -> NoReturn:
        """The connection is gone: close it and raise OperationalError. If the
        server sent an error first (e.g. FATAL 57P01 from pg_terminate_backend
        or 57P05 idle_session_timeout), raise that, with its SQLSTATE."""
        error = self._last_error
        self._abort()
        if isinstance(error, OperationalError):
            raise error from cause
        if error is not None:
            raise OperationalError(f"{message}; the server reported: {error}") from error
        raise OperationalError(message) from cause

    def _salvage_error(self) -> None:
        """After a failed send, look for an ErrorResponse the server sent
        before it closed the connection."""
        sock = self._sock
        if sock is None:
            return
        try:
            sock.setblocking(False)
            self._recv_available(sock, isinstance(sock, ssl.SSLSocket))
        except (OSError, ValueError):
            pass
        buf, pos = self._rbuf, 0
        while len(buf) - pos >= 5:
            length = _I32.unpack_from(buf, pos + 1)[0]
            if length < 4 or pos + 1 + length > len(buf):
                break
            if buf[pos] == ord("E"):
                try:
                    self._server_error(bytes(buf[pos + 5:pos + 1 + length]))
                except Error:
                    break
            pos += 1 + length

    def _drain_until_ready(self, *, startup: bool = False) -> DatabaseError | None:
        """Read until ReadyForQuery, discarding results of an abandoned query.
        Returns the first error the server reported on the way, such as a
        deferred constraint or serialization failure raised when Sync committed
        the implicit transaction. Callers that finished their work successfully
        must raise it; cleanup paths that already have an error ignore it."""
        error = None
        while True:
            kind, body = self._read_message()
            if kind == b"Z":
                self._ready(body)
                return error
            if kind == b"E":
                if startup:
                    # e.g. "database does not exist": the server closes the socket next
                    raise self._server_error(body)
                reported = self._server_error(body)
                error = error or reported
            elif kind == b"G":  # never leave the server waiting in copy-in mode
                self._handle_copy(kind, extended=True)
            else:
                self._handle_async(kind, body)

    def _unexpected(self, kind: bytes) -> None:
        self._abort()
        raise OperationalError(f"protocol violation: unexpected message type {kind!r}")

    def _send(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except OSError as exc:
            if isinstance(exc, TimeoutError):
                self._abort()
                raise OperationalError("timed out sending to the server; connection closed") from exc
            self._salvage_error()
            self._lost(f"connection lost while sending: {exc}", exc)

    def _send_pipelined(self, data: bytes | bytearray) -> None:
        """sendall() for a pipelined batch that keeps reading the server's
        replies into the read buffer while it writes. With a plain sendall(),
        a server that sends a lot per row (e.g. a NOTICE from a trigger) fills
        its socket buffers and stops reading our input while we are still
        writing, and both sides wait forever."""
        sock = self._sock
        view = memoryview(data)
        timeout = sock.gettimeout()
        tls = isinstance(sock, ssl.SSLSocket)
        both = selectors.EVENT_READ | selectors.EVENT_WRITE
        selector = selectors.DefaultSelector()
        try:
            sock.setblocking(False)
            selector.register(sock, both)
            events = both
            while view:
                if tls and sock.pending():
                    ready = selectors.EVENT_READ
                else:
                    ready = 0
                    for _, mask in selector.select(timeout):
                        ready |= mask
                    if not ready:
                        raise TimeoutError("timed out")
                if ready & selectors.EVENT_READ:
                    self._recv_available(sock, tls)
                wanted = both
                if ready & selectors.EVENT_WRITE:
                    try:
                        view = view[sock.send(view[:1 << 18]):]
                    except (BlockingIOError, InterruptedError, ssl.SSLWantWriteError):
                        pass
                    except ssl.SSLWantReadError:  # TLS must read first: don't spin on "writable"
                        wanted = selectors.EVENT_READ
                if wanted != events:
                    selector.modify(sock, wanted)
                    events = wanted
        except OSError as exc:  # TimeoutError and ssl.SSLError are OSErrors
            if isinstance(exc, TimeoutError):
                self._abort()
                raise OperationalError("timed out sending to the server; connection closed") from exc
            self._salvage_error()  # the replies read so far may explain why
            self._lost(f"connection lost while sending: {exc}", exc)
        finally:
            selector.close()
            if self._sock is sock:
                sock.settimeout(timeout)

    def _recv_available(self, sock: socket.socket, tls: bool) -> None:
        """Move whatever the server has sent into the read buffer, without blocking."""
        while True:
            try:
                chunk = sock.recv(_RECV_SIZE)
            except (BlockingIOError, InterruptedError, ssl.SSLWantReadError, ssl.SSLWantWriteError):
                return
            if not chunk:
                raise ConnectionResetError("server closed the connection")
            self._rbuf += chunk
            if not (tls and sock.pending()):
                return

    def _read_exact(self, n: int) -> bytes:
        buf = self._rbuf
        if len(buf) < n:
            try:
                if n - len(buf) > _RECV_SIZE:  # a large message: read straight into place
                    out = bytearray(n)
                    got = len(buf)
                    out[:got] = buf
                    buf.clear()
                    view = memoryview(out)
                    while got < n:
                        count = self._sock.recv_into(view[got:], n - got)
                        if not count:
                            break
                        got += count
                    if got == n:
                        return bytes(out)
                    buf += view[:got]
                else:
                    while len(buf) < n:
                        chunk = self._sock.recv(_RECV_SIZE)
                        if not chunk:
                            break
                        buf += chunk
            except (OSError, ValueError, AttributeError) as exc:  # AttributeError: closed meanwhile
                if isinstance(exc, TimeoutError):
                    self._abort()
                    raise OperationalError("timed out waiting for the server; connection closed") from exc
                self._lost(f"connection lost while reading: {exc}", exc)
            if len(buf) < n:
                self._lost("server closed the connection unexpectedly")
        data = bytes(buf[:n])
        del buf[:n]
        return data

    def _read_message(self) -> tuple[bytes, bytes]:
        buf = self._rbuf
        if len(buf) >= 5:  # fast path: the whole message is already buffered
            length = _I32.unpack_from(buf, 1)[0]
            if 4 <= length < len(buf):
                kind = _KINDS[buf[0]]
                body = bytes(buf[5:length + 1])
                del buf[:length + 1]
                return kind, body
        header = self._read_exact(5)
        length = _I32.unpack_from(header, 1)[0]
        if length < 4 or length > MAX_MESSAGE:
            self._abort()
            raise OperationalError(f"invalid message length {length} from server")
        return header[:1], self._read_exact(length - 4) if length > 4 else b""

    def _abort(self) -> None:
        self._closed = True
        self._synced = True
        self._stream = None
        self._last_error = None
        self._backend_key = None
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        self._rbuf = bytearray()
        self._sock = None
