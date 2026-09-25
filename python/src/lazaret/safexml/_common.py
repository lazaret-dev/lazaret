"""Shared pieces: exceptions, options, and the Expat handlers that enforce them.

Every API in lazaret.safexml (ElementTree, minidom, SAX, pulldom, XML-RPC) is
built on the stdlib's Expat binding. The protections are applied by
installing handlers on the Expat parser before any input is read:

- entity declarations raise EntitiesForbidden (blocks billion laughs,
  quadratic blowup, and XXE, all of which need a declared entity);
- external entity references raise ExternalReferenceForbidden;
- DOCTYPE declarations optionally raise DTDForbidden;
- external DTDs and parameter entities are never loaded, in every API;
- attribute defaults declared in the DTD are budgeted (AttlistGuard), because
  Expat copies each one onto every element of that type;
- element content models are never converted to Python (pyexpat does that
  recursively in C, so a deeply nested model overflows the C stack);
- nesting depth and input size are bounded.
"""

from __future__ import annotations

import pyexpat
from dataclasses import dataclass

DEFAULT_MAX_DEPTH = 500
DEFAULT_MAX_ATTLIST_DEFAULTS = 64 * 1024

# Attribute defaults (<!ATTLIST a x CDATA "AAAA...">) are copied by Expat onto
# every <a> element, with no entity involved, so a small document can put
# gigabytes of attribute values in memory. Two checks bound this:
# - the declarations: the lengths of all declared default values, plus
#   ATTRIBUTE_COST per declaration, must fit in max_attlist_defaults;
# - the attributes reported, once any default has been declared: like
#   libexpat's own amplification limit, their total size (values plus
#   ATTRIBUTE_COST each) may not exceed AMPLIFICATION_FACTOR times the input
#   read so far, once past AMPLIFICATION_THRESHOLD.
ATTRIBUTE_COST = 64
AMPLIFICATION_THRESHOLD = 8 * 1024 * 1024
AMPLIFICATION_FACTOR = 100

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
    max_attlist_defaults: budget for attribute defaults declared in the DTD: the
        total length of the default values, plus 64 per declaration (None for no
        limit, which also turns off the attribute amplification check).
    """

    forbid_dtd: bool = False
    forbid_entities: bool = True
    forbid_external: bool = True
    max_depth: int | None = DEFAULT_MAX_DEPTH
    max_bytes: int | None = None
    max_attlist_defaults: int | None = DEFAULT_MAX_ATTLIST_DEFAULTS

    def __post_init__(self) -> None:
        if not self.forbid_entities and not EXPAT_HAS_AMPLIFICATION_LIMIT:
            raise NotSupportedError(
                "forbid_entities=False requires libexpat 2.4.1 or later (found "
                f"{'.'.join(map(str, pyexpat.version_info))}), which limits entity expansion")
        for name in ("max_depth", "max_bytes", "max_attlist_defaults"):
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


class AttlistGuard:
    """Budget for attribute defaults declared in the DTD (see ATTRIBUTE_COST).

    install_handlers() makes one per Expat parser and installs attlist_decl as
    its AttlistDeclHandler, chaining to any handler already there (minidom has
    its own). APIs whose start-element handler receives the defaulted
    attributes call check() there while `active` is true."""

    def __init__(self, limit: int | None, previous=None):
        self.limit = limit
        self.previous = previous
        self.active = False  # a default has been declared, and there is a limit
        self._declared = 0
        self._reported = 0

    def attlist_decl(self, elname, attname, type_, default, required):
        if default is not None and self.limit is not None:
            self.active = True
            self._declared += len(default) + ATTRIBUTE_COST
            if self._declared > self.limit:
                raise LimitExceeded(
                    f"attribute defaults declared in the DTD exceed max_attlist_defaults={self.limit}")
        if self.previous is not None:
            self.previous(elname, attname, type_, default, required)

    def check(self, values, consumed: int) -> None:
        """Account for one element's attribute values; `consumed` is the size
        of the input fed to the parser so far."""
        total = self._reported
        for value in values:
            total += len(value) + ATTRIBUTE_COST
        self._reported = total
        if total > AMPLIFICATION_THRESHOLD and total > AMPLIFICATION_FACTOR * consumed:
            raise LimitExceeded(
                "attribute defaults declared in the DTD expand to more than "
                f"{AMPLIFICATION_FACTOR} times the size of the document")


def install_handlers(parser, options: Options) -> AttlistGuard:
    """Apply the protections to a pyexpat parser. Must run before parsing
    starts, after the API has installed its own handlers. Returns the parser's
    AttlistGuard."""
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
    # With an ElementDeclHandler installed, pyexpat converts every <!ELEMENT>
    # content model to nested tuples, recursively in C: a model nested a few
    # hundred thousand deep crashes the interpreter (stack overflow). Without a
    # handler Expat never builds the model. minidom installs one; nothing it
    # does by default needs it.
    parser.ElementDeclHandler = None
    guard = AttlistGuard(options.max_attlist_defaults, parser.AttlistDeclHandler)
    parser.AttlistDeclHandler = guard.attlist_decl
    return guard


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
