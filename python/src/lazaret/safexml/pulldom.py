"""Safe drop-in for xml.dom.pulldom.parse / parseString.

A parser, if given, must come from lazaret.safexml.sax.make_parser();
otherwise pass the safexml keyword options and one is made for you.
"""

from __future__ import annotations

from typing import Any
from xml.dom import pulldom as _pulldom  # lazaret-ignore: S-XML (this module is the hardening layer)

from .sax import SafeExpatParser, make_parser

__all__ = ["parse", "parseString"]


def _parser_for(parser: Any, options: dict[str, Any], caller: str) -> SafeExpatParser:
    if parser is None:
        return make_parser(**options)
    if options:
        raise TypeError(f"pass options to sax.make_parser(), not to {caller}(), when giving a parser")
    if not isinstance(parser, SafeExpatParser):
        kind = f"{type(parser).__module__}.{type(parser).__qualname__}"
        raise TypeError(f"parser must come from lazaret.safexml.sax.make_parser(), not {kind}, "
                        "which would parse without the safexml protections")
    return parser


def parse(stream_or_string: Any, parser: Any = None, bufsize: int | None = None, **options: Any):
    return _pulldom.parse(stream_or_string, _parser_for(parser, options, "parse"), bufsize)


def parseString(string: str, parser: Any = None, **options: Any):
    return _pulldom.parseString(string, _parser_for(parser, options, "parseString"))
