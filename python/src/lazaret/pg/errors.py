"""Exception hierarchy for lazaret.pg.

    Error
    ├── InterfaceError          misuse of the API or an unsupported feature (client side)
    ├── OperationalError        network, TLS, or protocol failure; the connection is unusable
    │   └── AuthenticationError the client refused or failed to complete authentication
    └── DatabaseError           an error reported by the server (has .sqlstate, .detail, ...)
        ├── DataError               SQLSTATE class 22 (bad value, overflow, ...)
        ├── IntegrityError          class 23 (unique, foreign key, not null, check)
        ├── InvalidAuthorization    class 28 (server rejected the credentials)
        ├── TransactionRollbackError class 40 (serialization failure, deadlock): safe to retry
        ├── ProgrammingError        class 42 (syntax error, undefined table, privileges)
        └── QueryCanceledError      57014 (statement timeout or cancel())

All DatabaseError subclasses can be pickled and copied (they carry only the
server's error fields).
"""

from __future__ import annotations

from dataclasses import dataclass, field


class Error(Exception):
    """Base class for all lazaret.pg errors."""


class InterfaceError(Error):
    """The API was used incorrectly, or the feature is not supported."""


class OperationalError(Error):
    """Network, TLS, or protocol failure. The connection is closed afterwards."""


class AuthenticationError(OperationalError):
    """Authentication could not be completed, or was refused by client policy."""


class DatabaseError(Error):
    """An error reported by the PostgreSQL server."""

    def __init__(self, fields: dict[str, str]):
        self.fields = fields
        self.severity = fields.get("V") or fields.get("S", "ERROR")
        self.sqlstate = fields.get("C", "")
        self.message = fields.get("M", "")
        self.detail = fields.get("D")
        self.hint = fields.get("H")
        self.position = fields.get("P")
        self.schema = fields.get("s")
        self.table = fields.get("t")
        self.column = fields.get("c")
        self.constraint = fields.get("n")
        super().__init__(f"{self.severity}: {self.message} (SQLSTATE {self.sqlstate})")

    def __reduce__(self):
        # args holds the formatted message, but __init__ takes the fields dict:
        # rebuild from the fields so pickle and copy work.
        return (self.__class__, (dict(self.fields),))


class DataError(DatabaseError):
    pass


class IntegrityError(DatabaseError):
    pass


class InvalidAuthorization(DatabaseError):
    pass


class TransactionRollbackError(DatabaseError):
    pass


class ProgrammingError(DatabaseError):
    pass


class QueryCanceledError(DatabaseError):
    pass


_BY_CLASS = {
    "22": DataError,
    "23": IntegrityError,
    "28": InvalidAuthorization,
    "40": TransactionRollbackError,
    "42": ProgrammingError,
}


def error_from_fields(fields: dict[str, str]) -> DatabaseError:
    code = fields.get("C", "")
    if code == "57014":
        return QueryCanceledError(fields)
    return _BY_CLASS.get(code[:2], DatabaseError)(fields)


@dataclass(frozen=True)
class Notice:
    """A NOTICE / WARNING / INFO message sent by the server."""

    severity: str
    message: str
    sqlstate: str = ""
    detail: str | None = None
    hint: str | None = None
    fields: dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def from_fields(cls, fields: dict[str, str]) -> Notice:
        return cls(
            severity=fields.get("V") or fields.get("S", "NOTICE"),
            message=fields.get("M", ""),
            sqlstate=fields.get("C", ""),
            detail=fields.get("D"),
            hint=fields.get("H"),
            fields=fields,
        )
