"""Shared pieces: exceptions, options, and the Expat handlers that enforce them.

Every API in lazaret.safexml (ElementTree, minidom, SAX, pulldom, XML-RPC) is
built on the stdlib's Expat binding. The protections are applied by
installing handlers on the Expat parser before any input is read:

- entity declarations raise EntitiesForbidden (blocks billion laughs,
  quadratic blowup, and XXE, all of which need a declared entity);
- external entity references raise ExternalReferenceForbidden;
- DOCTYPE declarations optionally raise DTDForbidden;
- external DTDs and parameter entities are never loaded, in every API;
- nesting depth and input size are bounded.
"""

from __future__ import annotations

import pyexpat
from dataclasses import dataclass

DEFAULT_MAX_DEPTH = 500

# libexpat 2.4.1+ limits entity amplification ("billion laughs") by itself.
# Declared entities are only ever allowed on top of that protection.
EXPAT_HAS_AMPLIFICATION_LIMIT = pyexpat.version_info >= (2, 4, 1)


class SafeXMLError(ValueError):
    """Base class: the document was refused for security reasons."""


class DTDForbidden(SafeXMLError):
    def __init__(self, name: str, sysid: str | None, pubid: str | None):
        super().__init__(name, sysid, pubid)
        self.name, self.sysid, self.pubid = name, sysid, pubid

    def __str__(self) -> str:
        return f"DOCTYPE declaration is forbidden (name={self.name!r}, system_id={self.sysid!r}, public_id={self.pubid!r})"


class EntitiesForbidden(SafeXMLError):
    def __init__(self, name: str, value: str | None, base: str | None, sysid: str | None,
                 pubid: str | None, notation_name: str | None):
        super().__init__(name, value, base, sysid, pubid, notation_name)
        self.name, self.value, self.base = name, value, base
        self.sysid, self.pubid, self.notation_name = sysid, pubid, notation_name

    def __str__(self) -> str:
        return f"entity declarations are forbidden (entity {self.name!r})"


class ExternalReferenceForbidden(SafeXMLError):
    def __init__(self, context: str | None, base: str | None, sysid: str | None, pubid: str | None):
        super().__init__(context, base, sysid, pubid)
        self.context, self.base, self.sysid, self.pubid = context, base, sysid, pubid

    def __str__(self) -> str:
        return f"reference to an external resource is forbidden (system_id={self.sysid!r}, public_id={self.pubid!r})"


class LimitExceeded(SafeXMLError):
    """The document is larger or more deeply nested than allowed."""


class NotSupportedError(SafeXMLError):
    """The requested combination of options cannot be provided safely."""


@dataclass(frozen=True)
class Options:
    """forbid_dtd: refuse any DOCTYPE declaration.
    forbid_entities: refuse entity declarations (the root of entity bombs and XXE).
    forbid_external: refuse references to external entities.
    max_depth: maximum element nesting (None for no limit).
    max_bytes: maximum input size, in bytes, or characters for str input (None for no limit).
    """

    forbid_dtd: bool = False
    forbid_entities: bool = True
    forbid_external: bool = True
    max_depth: int | None = DEFAULT_MAX_DEPTH
    max_bytes: int | None = None

    def __post_init__(self) -> None:
        if not self.forbid_entities and not EXPAT_HAS_AMPLIFICATION_LIMIT:
            raise NotSupportedError(
                "forbid_entities=False requires libexpat 2.4.1 or later (found "
                f"{'.'.join(map(str, pyexpat.version_info))}), which limits entity expansion")
        for name in ("max_depth", "max_bytes"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, int) or value < 1):
                raise ValueError(f"{name} must be a positive integer or None")


def _forbid_dtd(name, sysid, pubid, has_internal_subset):
    raise DTDForbidden(name, sysid, pubid)


def _forbid_entity(name, is_parameter_entity, value, base, sysid, pubid, notation_name):
    raise EntitiesForbidden(name, value, base, sysid, pubid, notation_name)


def _forbid_unparsed_entity(name, base, sysid, pubid, notation_name):
    raise EntitiesForbidden(name, None, base, sysid, pubid, notation_name)


def _forbid_external(context, base, sysid, pubid):
    raise ExternalReferenceForbidden(context, base, sysid, pubid)


def install_handlers(parser, options: Options) -> None:
    """Apply the protections to a pyexpat parser. Must run before parsing starts."""
    # Never read an external DTD subset or external parameter entities. The
    # stdlib SAX reader turns this on; we turn it off everywhere, so a DOCTYPE
    # with a SYSTEM or PUBLIC id is inert in every API.
    parser.SetParamEntityParsing(pyexpat.XML_PARAM_ENTITY_PARSING_NEVER)
    if options.forbid_dtd:
        parser.StartDoctypeDeclHandler = _forbid_dtd
    if options.forbid_entities:
        parser.EntityDeclHandler = _forbid_entity
        parser.UnparsedEntityDeclHandler = _forbid_unparsed_entity
    if options.forbid_external:
        parser.ExternalEntityRefHandler = _forbid_external


def depth_exceeded(limit: int) -> LimitExceeded:
    return LimitExceeded(f"document nesting exceeds max_depth={limit}")


def size_exceeded(limit: int) -> LimitExceeded:
    return LimitExceeded(f"document is larger than max_bytes={limit}")


class LimitedReader:
    """Wraps a file object and raises LimitExceeded once more than `limit`
    bytes (or characters) have been read. Also bounds decompressed streams."""

    def __init__(self, file, limit: int):
        self._file = file
        self._limit = limit
        self._count = 0

    def read(self, size: int = -1):
        data = self._file.read(size)
        self._count += len(data)
        if self._count > self._limit:
            raise size_exceeded(self._limit)
        return data

    def __getattr__(self, name):
        return getattr(self._file, name)
