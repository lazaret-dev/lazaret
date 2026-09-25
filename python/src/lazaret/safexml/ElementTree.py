"""Safe drop-in for xml.etree.ElementTree.

    from lazaret.safexml import ElementTree as ET   # instead of xml.etree.ElementTree
    root = ET.fromstring(untrusted_bytes)

Every public name of xml.etree.ElementTree is here. The ones that parse
(XMLParser, XMLPullParser, XML/fromstring, fromstringlist, XMLID, parse,
iterparse, canonicalize, and ElementTree, whose parse() method uses the safe
parser) apply the safexml protections; the rest (Element, SubElement, tostring,
TreeBuilder, ...) are the stdlib's own objects, so parsed trees are ordinary
ElementTree objects and the rest of your code is unchanged.

The parsing functions accept the keyword options forbid_dtd, forbid_entities,
forbid_external, max_depth, max_bytes, and max_attlist_defaults. Where the
stdlib takes a `parser` argument, it must be an XMLParser from this module
(then the options go to it); any other parser raises TypeError rather than
parsing unprotected.
"""

from __future__ import annotations

import collections
import collections.abc
import dataclasses
import io
import weakref
from typing import Any, Iterable, Iterator
import xml.etree.ElementTree as _std  # lazaret-ignore: S-XML (this module is the hardening layer)
from xml.etree.ElementTree import (  # lazaret-ignore: S-XML (non-parsing names, re-exported unchanged)
    PI,
    VERSION,
    C14NWriterTarget,
    Comment,
    Element,
    ParseError,
    ProcessingInstruction,
    QName,
    SubElement,
    TreeBuilder,
    dump,
    indent,
    iselement,
    register_namespace,
    tostring,
    tostringlist,
)
from xml.parsers import expat

from ._common import (
    DEFAULT_MAX_ATTLIST_DEFAULTS,
    DEFAULT_MAX_DEPTH,
    Options,
    SafeXMLError,
    depth_exceeded,
    install_handlers,
    size_exceeded,
)

__all__ = [
    # xml.etree.ElementTree's public names
    "Comment", "dump", "Element", "ElementTree", "fromstring", "fromstringlist", "indent", "iselement",
    "iterparse", "parse", "ParseError", "PI", "ProcessingInstruction", "QName", "SubElement", "tostring",
    "tostringlist", "TreeBuilder", "VERSION", "XML", "XMLID", "XMLParser", "XMLPullParser",
    "register_namespace", "canonicalize", "C14NWriterTarget",
    # defusedxml aliases
    "XMLParse", "XMLTreeBuilder",
]

class XMLParser:
    """Expat-based parser with the protocol of xml.etree.ElementTree.XMLParser
    (feed, close, flush, and the internal _setevents used by pull parsers),
    and the safexml protections applied."""

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

    def _setevents(self, events_queue: Any, events_to_report: Iterable[str] | None) -> None:
        """Report parse events to events_queue (anything with append()). The
        same internal API as the stdlib parser's, so the stdlib's
        XMLPullParser and iterparse() can drive this parser too."""
        events = ("end",) if events_to_report is None else tuple(events_to_report)
        for event in events:
            if event not in _EVENT_HANDLERS:
                raise ValueError(f"unknown event {event!r}")
        append = events_queue.append
        for event in events:
            handler_name, make_handler = _EVENT_HANDLERS[event]
            setattr(self.parser, handler_name, make_handler(self, append))

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
        """Make Expat report everything fed so far. Expat 2.6+ may hold back
        a token until more input arrives (reparse deferral); like the stdlib's
        flush(), this parses with deferral off once, then restores it."""
        parser = self.parser
        try:
            was_enabled = parser.GetReparseDeferralEnabled()
        except AttributeError:  # this Python cannot control deferral
            return
        try:
            parser.SetReparseDeferralEnabled(False)
            parser.Parse(b"", False)
        except expat.error as exc:
            self._raise_parse_error(exc)
        finally:
            parser.SetReparseDeferralEnabled(was_enabled)

    @staticmethod
    def _raise_parse_error(exc: expat.error) -> None:
        err = ParseError(exc)
        err.code = exc.code
        err.position = exc.lineno, exc.offset
        raise err from None


# Event handlers for XMLParser._setevents(), as in the stdlib parser. The
# element ones go through _start/_end, so depth is still counted.

def _on_start(parser: XMLParser, append):
    start = parser._start
    return lambda tag, attrs: append(("start", start(tag, attrs)))


def _on_end(parser: XMLParser, append):
    end = parser._end
    return lambda tag: append(("end", end(tag)))


def _on_start_ns(parser: XMLParser, append):
    if hasattr(parser.target, "start_ns"):
        start_ns = parser._start_ns
        return lambda prefix, uri: append(("start-ns", start_ns(prefix, uri)))
    return lambda prefix, uri: append(("start-ns", (prefix or "", uri or "")))


def _on_end_ns(parser: XMLParser, append):
    if hasattr(parser.target, "end_ns"):
        end_ns = parser._end_ns
        return lambda prefix: append(("end-ns", end_ns(prefix)))
    return lambda prefix: append(("end-ns", None))


def _on_comment(parser: XMLParser, append):
    target = parser.target
    return lambda text: append(("comment", target.comment(text)))


def _on_pi(parser: XMLParser, append):
    target = parser.target
    return lambda pi_target, data: append(("pi", target.pi(pi_target, data)))


_EVENT_HANDLERS = {
    "start": ("StartElementHandler", _on_start),
    "end": ("EndElementHandler", _on_end),
    "start-ns": ("StartNamespaceDeclHandler", _on_start_ns),
    "end-ns": ("EndNamespaceDeclHandler", _on_end_ns),
    "comment": ("CommentHandler", _on_comment),
    "pi": ("ProcessingInstructionHandler", _on_pi),
}

# defusedxml-compatible aliases
XMLParse = XMLTreeBuilder = XMLParser


def _check_parser(parser: Any) -> None:
    if not isinstance(parser, XMLParser):
        kind = f"{type(parser).__module__}.{type(parser).__qualname__}"
        raise TypeError(f"parser must be a lazaret.safexml.ElementTree.XMLParser, not {kind}, "
                        "which would parse without the safexml protections")


def _parser_for(parser: Any, options: dict[str, Any], caller: str) -> XMLParser:
    if parser is None:
        return XMLParser(**options)
    if options:
        raise TypeError(f"pass options to the XMLParser, not to {caller}(), when giving a parser")
    _check_parser(parser)
    return parser


def XML(text: bytes | str, parser: XMLParser | None = None, **options: Any):
    """Parse a document from a string or bytes and return the root Element."""
    parser = _parser_for(parser, options, "XML")
    parser.feed(text)
    return parser.close()


fromstring = XML


def fromstringlist(sequence: Iterable[bytes | str], parser: XMLParser | None = None, **options: Any):
    """Parse a document from a sequence of string or bytes fragments."""
    parser = _parser_for(parser, options, "fromstringlist")
    for text in sequence:
        parser.feed(text)
    return parser.close()


def XMLID(text: bytes | str, parser: XMLParser | None = None, **options: Any):
    """Parse a document; return (root Element, {id attribute: Element})."""
    tree = XML(text, parser, **options)
    ids = {}
    for elem in tree.iter():
        id_ = elem.get("id")
        if id_:
            ids[id_] = elem
    return tree, ids


class ElementTree(_std.ElementTree):
    """xml.etree.ElementTree.ElementTree, except that parse() (and the file
    argument of the constructor) uses the safe XMLParser."""

    def parse(self, source: Any, parser: XMLParser | None = None):
        if parser is None:
            parser = XMLParser()
        else:
            _check_parser(parser)
        return super().parse(source, parser)


def parse(source: Any, parser: XMLParser | None = None, **options: Any) -> ElementTree:
    """Parse a file path or binary file object and return an ElementTree."""
    tree = ElementTree()
    tree.parse(source, _parser_for(parser, options, "parse"))
    return tree


class XMLPullParser:
    """Non-blocking parser: feed() data, then read_events(). Same interface
    as xml.etree.ElementTree.XMLPullParser; accepts the safexml options.

    Like the stdlib's, feed() does not raise ParseError: the error is queued
    and raised by read_events() after the events that preceded it. safexml
    refusals (SafeXMLError) are queued the same way."""

    def __init__(self, events: Iterable[str] | None = None, *, _parser: XMLParser | None = None,
                 **options: Any):
        self._events_queue: collections.deque = collections.deque()
        self._parser = _parser_for(_parser, options, "XMLPullParser")
        self._parser._setevents(self._events_queue, ("end",) if events is None else events)

    def feed(self, data: bytes | str) -> None:
        """Feed encoded data to the parser."""
        if self._parser is None:
            raise ValueError("feed() called after end of stream")
        if data:
            try:
                self._parser.feed(data)
            except (SyntaxError, SafeXMLError) as exc:
                self._events_queue.append(exc)

    def _close_and_return_root(self):
        root = self._parser.close()
        self._parser = None
        return root

    def close(self) -> None:
        """Finish feeding data. Unlike XMLParser.close(), returns nothing; use
        read_events() for the remaining events."""
        self._close_and_return_root()

    def read_events(self) -> Iterator[tuple[str, Any]]:
        """Yield the (event, element) pairs available so far, removing them
        from the queue. Raises a queued error when it reaches it."""
        events = self._events_queue
        while events:
            event = events.popleft()
            if isinstance(event, Exception):
                raise event
            yield event

    def flush(self) -> None:
        if self._parser is None:
            raise ValueError("flush() called after end of stream")
        self._parser.flush()


def _iterparse_events(pullparser: XMLPullParser, source: Any, close_source: bool, iterator_ref):
    try:
        while True:
            yield from pullparser.read_events()
            data = source.read(16 * 1024)
            if not data:
                break
            pullparser.feed(data)
        root = pullparser._close_and_return_root()
        yield from pullparser.read_events()
        iterator = iterator_ref()
        if iterator is not None:
            iterator.root = root
    finally:
        if close_source:
            source.close()


class _IterParseIterator(collections.abc.Iterator):
    """Iterator returned by iterparse(); .root is set once parsing finishes."""

    def __init__(self, pullparser: XMLPullParser, source: Any, close_source: bool):
        self.root = None
        self._source = source
        self._close_source = close_source
        # The generator holds only a weak reference to this iterator, so an
        # abandoned iterator is freed (and its file closed) right away.
        self._gen = _iterparse_events(pullparser, source, close_source, weakref.ref(self))

    def __next__(self):
        return next(self._gen)

    def close(self) -> None:
        if self._close_source:
            self._source.close()
        self._gen.close()

    def __del__(self):
        if self._close_source:
            self._source.close()


def iterparse(source: Any, events: Iterable[str] | None = None, parser: XMLParser | None = None,
              **options: Any) -> _IterParseIterator:
    """Incrementally parse a file path or binary file object, yielding
    (event, element) pairs. Events: start, end, start-ns, end-ns, comment, pi
    (default: end). As with the stdlib, bad events raise ValueError and a
    path is opened at once; a parse error is raised after the events before it."""
    pullparser = XMLPullParser(events, _parser=_parser_for(parser, options, "iterparse"))
    close_source = not hasattr(source, "read")
    if close_source:
        source = open(source, "rb")
    return _IterParseIterator(pullparser, source, close_source)


_SAFE_OPTIONS = tuple(field.name for field in dataclasses.fields(Options))


def canonicalize(xml_data: bytes | str | None = None, *, out: Any = None, from_file: Any = None,
                 **options: Any) -> str | None:
    """Convert XML to its C14N 2.0 serialised form, as the stdlib's
    canonicalize() does, parsing with the safe XMLParser. Takes the
    C14NWriterTarget options and the safexml options."""
    safe = {key: options.pop(key) for key in _SAFE_OPTIONS if key in options}
    if xml_data is None and from_file is None:
        raise ValueError("Either 'xml_data' or 'from_file' must be provided as input")
    sio = None
    if out is None:
        sio = out = io.StringIO()
    parser = XMLParser(target=C14NWriterTarget(out.write, **options), **safe)
    if xml_data is not None:
        parser.feed(xml_data)
        parser.close()
    elif from_file is not None:
        parse(from_file, parser=parser)
    return sio.getvalue() if sio is not None else None
