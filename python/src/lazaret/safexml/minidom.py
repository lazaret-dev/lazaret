"""Safe drop-in for xml.dom.minidom.parse / parseString.

    from lazaret.safexml import minidom
    doc = minidom.parseString(untrusted_bytes)

Returns ordinary xml.dom.minidom Document objects. The signatures match the
stdlib's (parse(file, parser=None, bufsize=None), parseString(string,
parser=None)), plus keyword options.
"""

from __future__ import annotations

import os
from typing import Any
from xml.dom import expatbuilder as _expatbuilder  # lazaret-ignore: S-XML (this module is the hardening layer)

from . import pulldom as _pulldom
from ._common import (
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


def _pulldom_document(events: Any):
    # What xml.dom.minidom does when it is given a parser or a bufsize.
    toktype, root = events.getEvent()
    events.expandNode(root)
    events.clear()
    return root


def _check_namespaces(namespaces: bool) -> None:
    if not namespaces:
        raise TypeError("namespaces=False needs the default builder; with a parser or bufsize, "
                        "minidom builds through pulldom, which always processes namespaces")


def parse(file: Any, parser: Any = None, bufsize: int | None = None, *, namespaces: bool = True,
          **options: Any):
    """Parse a file path or binary file object into a minidom Document.

    Options: forbid_dtd, forbid_entities, forbid_external, max_depth,
    max_bytes, max_attlist_defaults. As with xml.dom.minidom, a parser or a
    bufsize makes it build through pulldom; the parser must then come from
    lazaret.safexml.sax.make_parser(), and the options go there."""
    if parser is None and not bufsize:
        builder = _builder(namespaces, options)
        if isinstance(file, (str, bytes, os.PathLike)):
            with open(file, "rb") as fp:
                return builder.parseFile(fp)
        return builder.parseFile(file)
    _check_namespaces(namespaces)
    if isinstance(file, (str, bytes, os.PathLike)):
        # opened (and closed) here: pulldom would leave a file it opens open
        # until garbage collection, so after a parse error a traceback kept
        # the file open, and Windows can't delete an open file
        with open(file, "rb") as fp:
            return _pulldom_document(_pulldom.parse(fp, parser, bufsize, **options))
    return _pulldom_document(_pulldom.parse(file, parser, bufsize, **options))


def parseString(string: bytes | str, parser: Any = None, *, namespaces: bool = True, **options: Any):
    """Parse a string or bytes into a minidom Document. Options and the
    parser argument work as for parse()."""
    if parser is None:
        return _builder(namespaces, options).parseString(string)
    _check_namespaces(namespaces)
    return _pulldom_document(_pulldom.parseString(string, parser, **options))
