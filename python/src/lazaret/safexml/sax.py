"""Safe drop-in for xml.sax.parse / parseString / make_parser.

    from lazaret.safexml import sax
    sax.parseString(untrusted_bytes, MyHandler())
"""

from __future__ import annotations

import io
from typing import Any
from xml.sax import expatreader as _expatreader  # lazaret-ignore: S-XML (this module is the hardening layer)
from xml.sax import handler as _handler  # lazaret-ignore: S-XML (this module is the hardening layer)
from xml.sax import xmlreader as _xmlreader  # lazaret-ignore: S-XML (this module is the hardening layer)

from ._common import (
    DEFAULT_MAX_ATTLIST_DEFAULTS,
    DEFAULT_MAX_DEPTH,
    Options,
    depth_exceeded,
    install_handlers,
    size_exceeded,
)

__all__ = ["make_parser", "parse", "parseString", "SafeExpatParser"]


class SafeExpatParser(_expatreader.ExpatParser):
    """The stdlib Expat SAX reader with the safexml protections applied.

    With forbid_external=True (the default), external entities are refused
    even if feature_external_ges is switched on, so nothing is ever fetched."""

    def __init__(self, namespaceHandling: int = 0, bufsize: int = 2**16 - 20, *,
                 forbid_dtd: bool = False, forbid_entities: bool = True, forbid_external: bool = True,
                 max_depth: int | None = DEFAULT_MAX_DEPTH, max_bytes: int | None = None,
                 max_attlist_defaults: int | None = DEFAULT_MAX_ATTLIST_DEFAULTS):
        super().__init__(namespaceHandling, bufsize)
        self.options = Options(forbid_dtd, forbid_entities, forbid_external, max_depth, max_bytes,
                               max_attlist_defaults)
        self._depth = 0
        self._fed = 0

    def reset(self) -> None:
        super().reset()
        self._depth = 0
        self._attlist = install_handlers(self._parser, self.options)

    def feed(self, data, isFinal: bool = False) -> None:
        if not self._parsing:
            self._fed = 0  # a new document is starting
        self._fed += len(data)
        limit = self.options.max_bytes
        if limit is not None and self._fed > limit:
            raise size_exceeded(limit)
        super().feed(data, isFinal)

    def _enter(self, attrs) -> None:
        self._depth += 1
        limit = self.options.max_depth
        if limit is not None and self._depth > limit:
            raise depth_exceeded(limit)
        if self._attlist.active:
            self._attlist.check(attrs.values(), self._fed)

    def start_element(self, name, attrs):
        self._enter(attrs)
        super().start_element(name, attrs)

    def end_element(self, name):
        self._depth -= 1
        super().end_element(name)

    def start_element_ns(self, name, attrs):
        self._enter(attrs)
        super().start_element_ns(name, attrs)

    def end_element_ns(self, name):
        self._depth -= 1
        super().end_element_ns(name)


def make_parser(parser_list: Any = (), **options: Any) -> SafeExpatParser:
    """Return a SafeExpatParser. parser_list is accepted for compatibility and ignored."""
    return SafeExpatParser(**options)


def parse(source: Any, handler: _handler.ContentHandler, errorHandler: _handler.ErrorHandler | None = None,
          **options: Any) -> None:
    parser = make_parser(**options)
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler or _handler.ErrorHandler())
    parser.parse(source)


def parseString(string: bytes | str, handler: _handler.ContentHandler,
                errorHandler: _handler.ErrorHandler | None = None, **options: Any) -> None:
    parser = make_parser(**options)
    parser.setContentHandler(handler)
    parser.setErrorHandler(errorHandler or _handler.ErrorHandler())
    source = _xmlreader.InputSource()
    if isinstance(string, str):
        source.setCharacterStream(io.StringIO(string))
    else:
        source.setByteStream(io.BytesIO(string))
    parser.parse(source)
