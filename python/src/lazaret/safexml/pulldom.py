"""Safe drop-in for xml.dom.pulldom.parse / parseString."""

from __future__ import annotations

from typing import Any
from xml.dom import pulldom as _pulldom  # lazaret-ignore: S-XML (this module is the hardening layer)

from .sax import make_parser

__all__ = ["parse", "parseString"]


def parse(stream_or_string: Any, parser: Any = None, bufsize: int | None = None, **options: Any):
    if parser is None:
        parser = make_parser(**options)
    elif options:
        raise TypeError("pass options to sax.make_parser(), not to parse(), when giving a parser")
    return _pulldom.parse(stream_or_string, parser, bufsize)


def parseString(string: str, parser: Any = None, **options: Any):
    if parser is None:
        parser = make_parser(**options)
    elif options:
        raise TypeError("pass options to sax.make_parser(), not to parseString(), when giving a parser")
    return _pulldom.parseString(string, parser)
