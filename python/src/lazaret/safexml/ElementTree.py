"""Safe drop-in for the parsing half of xml.etree.ElementTree.

    from lazaret.safexml import ElementTree as ET
    root = ET.fromstring(untrusted_bytes)

Parsing functions return ordinary xml.etree.ElementTree objects, so the rest of
your ElementTree code is unchanged. Each accepts the keyword options
forbid_dtd, forbid_entities, forbid_external, max_depth, max_bytes, and
max_attlist_defaults.
"""

from __future__ import annotations

import collections
from typing import Any, Iterable, Iterator
from xml.etree.ElementTree import ElementTree as _ElementTree  # lazaret-ignore: S-XML (this module is the hardening layer)
from xml.etree.ElementTree import ParseError, TreeBuilder, tostring  # lazaret-ignore: S-XML (this module is the hardening layer)
from xml.parsers import expat

from ._common import (
    DEFAULT_MAX_ATTLIST_DEFAULTS,
    DEFAULT_MAX_DEPTH,
    Options,
    depth_exceeded,
    install_handlers,
    size_exceeded,
)

__all__ = ["ParseError", "XML", "XMLParser", "XMLParse", "XMLTreeBuilder", "fromstring",
           "fromstringlist", "iterparse", "parse", "tostring"]

_EVENTS = ("start", "end", "start-ns", "end-ns", "comment", "pi")


class XMLParser:
    """Expat-based parser with the same feed()/close() protocol as
    xml.etree.ElementTree.XMLParser, and the safexml protections applied."""

    def __init__(self, *, target: Any = None, encoding: str | None = None,
                 forbid_dtd: bool = False, forbid_entities: bool = True, forbid_external: bool = True,
                 max_depth: int | None = DEFAULT_MAX_DEPTH, max_bytes: int | None = None,
                 max_attlist_defaults: int | None = DEFAULT_MAX_ATTLIST_DEFAULTS):
        self.options = Options(forbid_dtd, forbid_entities, forbid_external, max_depth, max_bytes,
                               max_attlist_defaults)
        parser = expat.ParserCreate(encoding, "}")
        self.target = target if target is not None else TreeBuilder()
        self.parser = parser
        self.entity: dict[str, str] = {}  # same escape hatch as the stdlib parser
        self._names: dict[str, str] = {}
        self._depth = 0
        self._fed = 0
        self.version = "Expat %d.%d.%d" % expat.version_info

        parser.buffer_text = 1
        parser.ordered_attributes = 1
        parser.DefaultHandlerExpand = self._default
        target = self.target
        # Nesting depth is counted on every element, whether or not the
        # target implements start() and end().
        self._target_start = getattr(target, "start", None)
        self._target_end = getattr(target, "end", None)
        parser.StartElementHandler = self._start
        parser.EndElementHandler = self._end
        if hasattr(target, "start_ns"):
            parser.StartNamespaceDeclHandler = self._start_ns
        if hasattr(target, "end_ns"):
            parser.EndNamespaceDeclHandler = self._end_ns
        if hasattr(target, "data"):
            parser.CharacterDataHandler = target.data
        if hasattr(target, "comment"):
            parser.CommentHandler = target.comment
        if hasattr(target, "pi"):
            parser.ProcessingInstructionHandler = target.pi
        self._attlist = install_handlers(parser, self.options)

    # --- expat callbacks ---------------------------------------------------

    def _fixname(self, key: str) -> str:
        name = self._names.get(key)
        if name is None:
            name = "{" + key if "}" in key else key
            self._names[key] = name
        return name

    def _start(self, tag: str, attr_list: list[str]) -> Any:
        self._depth += 1
        limit = self.options.max_depth
        if limit is not None and self._depth > limit:
            raise depth_exceeded(limit)
        if self._attlist.active:
            self._attlist.check(attr_list[1::2], self._fed)
        start = self._target_start
        if start is None:
            return None
        fixname = self._fixname
        attrib = {fixname(attr_list[i]): attr_list[i + 1] for i in range(0, len(attr_list), 2)}
        return start(fixname(tag), attrib)

    def _end(self, tag: str) -> Any:
        self._depth -= 1
        end = self._target_end
        if end is None:
            return None
        return end(self._fixname(tag))

    def _start_ns(self, prefix: str | None, uri: str | None) -> Any:
        return self.target.start_ns(prefix or "", uri or "")

    def _end_ns(self, prefix: str | None) -> Any:
        return self.target.end_ns(prefix or "")

    def _default(self, text: str) -> None:
        # Expat passes references to undeclared entities here when the
        # document has an external DTD it will not load.
        if text[:1] == "&":
            name = text[1:-1]
            if name in self.entity and hasattr(self.target, "data"):
                self.target.data(self.entity[name])
                return
            err = expat.error(f"undefined entity {text}: line {self.parser.ErrorLineNumber}, "
                              f"column {self.parser.ErrorColumnNumber}")
            err.code = 11  # XML_ERROR_UNDEFINED_ENTITY
            err.lineno = self.parser.ErrorLineNumber
            err.offset = self.parser.ErrorColumnNumber
            raise err

    def _enable_events(self, queue: collections.deque, events: Iterable[str]) -> None:
        """Report parse events to `queue`, as ElementTree's pull parser does."""
        append = queue.append
        parser = self.parser
        target = self.target
        for event in events:
            if event == "start":
                parser.StartElementHandler = lambda tag, attrs: append(("start", self._start(tag, attrs)))
            elif event == "end":
                parser.EndElementHandler = lambda tag: append(("end", self._end(tag)))
            elif event == "start-ns":
                parser.StartNamespaceDeclHandler = lambda prefix, uri: append(("start-ns", (prefix or "", uri or "")))
            elif event == "end-ns":
                parser.EndNamespaceDeclHandler = lambda prefix: append(("end-ns", None))
            elif event == "comment":
                parser.CommentHandler = lambda text: append(("comment", target.comment(text)))
            elif event == "pi":
                parser.ProcessingInstructionHandler = lambda name, data: append(("pi", target.pi(name, data)))
            else:
                raise ValueError(f"unknown event {event!r}")

    # --- public protocol ---------------------------------------------------

    def feed(self, data: bytes | str) -> None:
        self._fed += len(data)
        limit = self.options.max_bytes
        if limit is not None and self._fed > limit:
            raise size_exceeded(limit)
        try:
            self.parser.Parse(data, False)
        except expat.error as exc:
            self._raise_parse_error(exc)

    def close(self) -> Any:
        try:
            self.parser.Parse(b"", True)
        except expat.error as exc:
            self._raise_parse_error(exc)
        try:
            close = self.target.close
        except AttributeError:
            return None
        finally:
            del self.parser
        return close()

    def flush(self) -> None:
        """Present for compatibility; data is never buffered beyond Expat itself."""

    @staticmethod
    def _raise_parse_error(exc: expat.error) -> None:
        err = ParseError(exc)
        err.code = exc.code
        err.position = exc.lineno, exc.offset
        raise err from None


# defusedxml-compatible aliases
XMLParse = XMLTreeBuilder = XMLParser


def fromstring(text: bytes | str, **options: Any):
    """Parse a document from a string or bytes and return the root Element."""
    parser = XMLParser(**options)
    parser.feed(text)
    return parser.close()


XML = fromstring


def fromstringlist(sequence: Iterable[bytes | str], **options: Any):
    parser = XMLParser(**options)
    for text in sequence:
        parser.feed(text)
    return parser.close()


def parse(source: Any, parser: XMLParser | None = None, **options: Any) -> _ElementTree:
    """Parse a file path or binary file object and return an ElementTree."""
    if parser is not None and options:
        raise TypeError("pass options to the XMLParser, not to parse(), when giving a parser")
    tree = _ElementTree()
    tree.parse(source, parser if parser is not None else XMLParser(**options))
    return tree


class _IterParseIterator(Iterator):
    """Iterator returned by iterparse(); .root is set once parsing finishes."""

    def __init__(self, source: Any, events: Iterable[str] | None, options: dict[str, Any]):
        self.root = None
        self._gen = self._run(source, tuple(events) if events is not None else ("end",), options)

    def __next__(self):
        return next(self._gen)

    def close(self) -> None:
        self._gen.close()

    def _run(self, source, events, options):
        parser = XMLParser(**options)
        queue: collections.deque = collections.deque()
        parser._enable_events(queue, events)
        close_source = not hasattr(source, "read")
        if close_source:
            source = open(source, "rb")
        try:
            while True:
                while queue:
                    yield queue.popleft()
                data = source.read(16 * 1024)
                if not data:
                    break
                parser.feed(data)
            root = parser.close()
            while queue:
                yield queue.popleft()
            self.root = root
        finally:
            if close_source:
                source.close()


def iterparse(source: Any, events: Iterable[str] | None = None, **options: Any) -> _IterParseIterator:
    """Incrementally parse a file path or binary file object, yielding
    (event, element) pairs. Events: start, end, start-ns, end-ns, comment, pi."""
    for event in events or ():
        if event not in _EVENTS:
            raise ValueError(f"unknown event {event!r}")
    return _IterParseIterator(source, events, options)
