"""Safe XML-RPC client and parser (e.g. for PyPI's XML-RPC API).

    from lazaret.safexml import xmlrpc
    proxy = xmlrpc.ServerProxy("https://pypi.org/pypi")

Responses are parsed with the safexml protections, and their size is capped
(max_bytes, 32 MiB by default). The cap applies after gzip decompression, so
a compressed "zip bomb" response is cut off too.

monkey_patch() applies the same parser to the stdlib's xmlrpc.client and
xmlrpc.server globally
"""

from __future__ import annotations

import xmlrpc.client as _client
from typing import Any
from urllib.parse import urlsplit

from ._common import DEFAULT_MAX_DEPTH, Options, depth_exceeded, install_handlers, size_exceeded

__all__ = ["SafeXMLRPCParser", "Transport", "SafeTransport", "ServerProxy", "loads",
           "monkey_patch", "unmonkey_patch", "DEFAULT_MAX_BYTES"]

DEFAULT_MAX_BYTES = 32 * 1024 * 1024

_SAFE_KEYS = ("forbid_dtd", "forbid_entities", "forbid_external", "max_depth", "max_bytes")


class SafeXMLRPCParser(_client.ExpatParser):
    """Replacement for xmlrpc.client.ExpatParser."""

    def __init__(self, target: Any, *, forbid_dtd: bool = False, forbid_entities: bool = True,
                 forbid_external: bool = True, max_depth: int | None = DEFAULT_MAX_DEPTH,
                 max_bytes: int | None = DEFAULT_MAX_BYTES):
        self.options = Options(forbid_dtd, forbid_entities, forbid_external, max_depth, max_bytes)
        super().__init__(target)
        self._depth = 0
        self._fed = 0
        self._parser.StartElementHandler = self._start
        self._parser.EndElementHandler = self._end
        install_handlers(self._parser, self.options)

    def _start(self, tag, attrs):
        self._depth += 1
        limit = self.options.max_depth
        if limit is not None and self._depth > limit:
            raise depth_exceeded(limit)
        self._target.start(tag, attrs)

    def _end(self, tag):
        self._depth -= 1
        self._target.end(tag)

    def feed(self, data) -> None:
        limit = self.options.max_bytes
        if limit is not None:
            self._fed += len(data)
            if self._fed > limit:
                raise size_exceeded(limit)
        super().feed(data)


def _split_safe(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {key: kwargs.pop(key) for key in _SAFE_KEYS if key in kwargs}


class _SafeParserMixin:
    def _init_safe(self, safe: dict[str, Any]) -> None:
        SafeXMLRPCParser(_client.Unmarshaller(), **safe)  # validate options now, not per request
        self._safe = safe

    def getparser(self):
        unmarshaller = _client.Unmarshaller(use_datetime=self._use_datetime,
                                            use_builtin_types=self._use_builtin_types)
        return SafeXMLRPCParser(unmarshaller, **self._safe), unmarshaller


class Transport(_SafeParserMixin, _client.Transport):
    """HTTP transport that parses responses safely. Accepts the safexml options
    as keywords in addition to the stdlib Transport arguments."""

    def __init__(self, *args: Any, **kwargs: Any):
        safe = _split_safe(kwargs)
        super().__init__(*args, **kwargs)
        self._init_safe(safe)


class SafeTransport(_SafeParserMixin, _client.SafeTransport):
    """HTTPS transport that parses responses safely."""

    def __init__(self, *args: Any, **kwargs: Any):
        safe = _split_safe(kwargs)
        super().__init__(*args, **kwargs)
        self._init_safe(safe)


class ServerProxy(_client.ServerProxy):
    """xmlrpc.client.ServerProxy that uses a safe transport unless you pass
    your own. Accepts the safexml options as keywords."""

    def __init__(self, uri: str, transport: Any = None, encoding: str | None = None, verbose: bool = False,
                 allow_none: bool = False, use_datetime: bool = False, use_builtin_types: bool = False,
                 *, headers: Any = (), context: Any = None, **safe: Any):
        unknown = set(safe) - set(_SAFE_KEYS)
        if unknown:
            raise TypeError(f"unexpected keyword argument(s): {', '.join(sorted(unknown))}")
        if transport is None:
            if urlsplit(uri).scheme == "https":
                transport = SafeTransport(use_datetime, use_builtin_types, headers=headers, context=context, **safe)
            else:
                transport = Transport(use_datetime, use_builtin_types, headers=headers, **safe)
        elif safe:
            raise TypeError("safexml options only apply to the default transport")
        super().__init__(uri, transport, encoding, verbose, allow_none, use_datetime, use_builtin_types,
                         headers=headers, context=context)


def loads(data: bytes | str, use_datetime: bool = False, use_builtin_types: bool = False, **safe: Any):
    """Safe xmlrpc.client.loads(): returns (params, methodname)."""
    unmarshaller = _client.Unmarshaller(use_datetime=use_datetime, use_builtin_types=use_builtin_types)
    parser = SafeXMLRPCParser(unmarshaller, **safe)
    parser.feed(data)
    parser.close()
    return unmarshaller.close(), unmarshaller.getmethodname()


_original = {"ExpatParser": _client.ExpatParser, "FastParser": _client.FastParser}


def monkey_patch() -> None:
    """Make the stdlib xmlrpc.client (and xmlrpc.server, which uses it) parse
    safely, process-wide, with default options."""
    _client.FastParser = None
    _client.ExpatParser = SafeXMLRPCParser


def unmonkey_patch() -> None:
    _client.ExpatParser = _original["ExpatParser"]
    _client.FastParser = _original["FastParser"]
