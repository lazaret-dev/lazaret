"""lazaret.pg: a PostgreSQL client in pure Python, with no dependencies
outside the standard library.

    from lazaret import pg

    with pg.connect("postgresql://lazaret@db.example.com/lazaret",
                    sslmode="verify-full", sslrootcert="system") as conn:
        conn.execute("INSERT INTO scans (package, verdict) VALUES ($1, $2)", "requests", "ok")
        for row in conn.fetch("SELECT package, verdict FROM scans WHERE verdict <> $1", "ok"):
            print(row.package, row["verdict"])

Supports TLS (sslmode disable/prefer/require/verify-ca/verify-full), SCRAM-SHA-256
with channel binding, MD5 and password authentication, ~/.pgpass and PG*
environment variables, transactions with savepoints, streaming results,
pipelined executemany, LISTEN/NOTIFY messages, and query cancellation.
"""

from ._types import Json, Rows
from .connection import CommandResult, Connection, Notification, connect
from .errors import (
    AuthenticationError,
    DatabaseError,
    DataError,
    Error,
    IntegrityError,
    InterfaceError,
    InvalidAuthorization,
    Notice,
    OperationalError,
    ProgrammingError,
    QueryCanceledError,
    ServerOperationalError,
    TransactionRollbackError,
)

__all__ = [
    "connect", "Connection", "CommandResult", "Notification", "Notice", "Json", "Rows",
    "Error", "InterfaceError", "OperationalError", "AuthenticationError", "DatabaseError",
    "DataError", "IntegrityError", "InvalidAuthorization", "TransactionRollbackError",
    "ProgrammingError", "QueryCanceledError", "ServerOperationalError",
]
