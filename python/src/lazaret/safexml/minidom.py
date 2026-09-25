"""Safe drop-in for xml.dom.minidom.parse / parseString.

    from lazaret.safexml import minidom
    doc = minidom.parseString(untrusted_bytes)

Returns ordinary xml.dom.minidom Document objects.
"""

from __future__ import annotations

import os
from typing import Any
from xml.dom import expatbuilder as _expatbuilder  # lazaret-ignore: S-XML (this module is the hardening layer)

from ._common import (
    DEFAULT_MAX_ATTLIST_DEFAULTS,
    DEFAULT_MAX_DEPTH,
    LimitedReader,
    Options,
    depth_exceeded,
    install_handlers,
    size_exceeded,
)

__all__ = ["parse", "parseString", "SafeExpatBuilder", "SafeExpatBuilderNS"]


class _SafeBuilderMixin:
    def __init__(self, options=None, *, safe: Options):
        self._safe = safe
        super().__init__(options)

    def reset(self) -> None:
        super().reset()
        self._depth = 0

    def install(self, parser) -> None:
        super().install(parser)
        # The builder sets specified_attributes, so Expat never reports
        # defaulted attributes to it: only the declarations need a budget, and
        # install_handlers() chains that to the builder's AttlistDeclHandler.
        install_handlers(parser, self._safe)

    def start_element_handler(self, name, attributes):
        self._depth += 1
        limit = self._safe.max_depth
        if limit is not None and self._depth > limit:
            raise depth_exceeded(limit)
        return super().start_element_handler(name, attributes)

    def end_element_handler(self, name):
        self._depth -= 1
        return super().end_element_handler(name)

    def parseFile(self, file):
        limit = self._safe.max_bytes
        return super().parseFile(LimitedReader(file, limit) if limit is not None else file)

    def parseString(self, string):
        limit = self._safe.max_bytes
        if limit is not None and len(string) > limit:
            raise size_exceeded(limit)
        return super().parseString(string)


class SafeExpatBuilder(_SafeBuilderMixin, _expatbuilder.ExpatBuilder):
    """minidom builder without namespace processing."""


class SafeExpatBuilderNS(_SafeBuilderMixin, _expatbuilder.ExpatBuilderNS):
    """minidom builder with namespace processing (the stdlib default)."""


def _builder(namespaces: bool, safe: dict[str, Any]):
    cls = SafeExpatBuilderNS if namespaces else SafeExpatBuilder
    return cls(safe=Options(**safe))


def parse(file: Any, *, namespaces: bool = True, forbid_dtd: bool = False, forbid_entities: bool = True,
          forbid_external: bool = True, max_depth: int | None = DEFAULT_MAX_DEPTH,
          max_bytes: int | None = None, max_attlist_defaults: int | None = DEFAULT_MAX_ATTLIST_DEFAULTS):
    """Parse a file path or binary file object into a minidom Document."""
    builder = _builder(namespaces, dict(forbid_dtd=forbid_dtd, forbid_entities=forbid_entities,
                                        forbid_external=forbid_external, max_depth=max_depth, max_bytes=max_bytes,
                                        max_attlist_defaults=max_attlist_defaults))
    if isinstance(file, (str, bytes, os.PathLike)):
        with open(file, "rb") as fp:
            return builder.parseFile(fp)
    return builder.parseFile(file)


def parseString(string: bytes | str, *, namespaces: bool = True, forbid_dtd: bool = False,
                forbid_entities: bool = True, forbid_external: bool = True,
                max_depth: int | None = DEFAULT_MAX_DEPTH, max_bytes: int | None = None,
                max_attlist_defaults: int | None = DEFAULT_MAX_ATTLIST_DEFAULTS):
    """Parse a string or bytes into a minidom Document."""
    builder = _builder(namespaces, dict(forbid_dtd=forbid_dtd, forbid_entities=forbid_entities,
                                        forbid_external=forbid_external, max_depth=max_depth, max_bytes=max_bytes,
                                        max_attlist_defaults=max_attlist_defaults))
    return builder.parseString(string)
