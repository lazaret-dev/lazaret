"""Safe XML-RPC client and parser (e.g. for PyPI's XML-RPC API).

    from lazaret.safexml import xmlrpc
    proxy = xmlrpc.ServerProxy("https://pypi.org/pypi")

Responses are parsed with the safexml protections, and their size is capped
(max_bytes, 32 MiB by default). The cap applies after gzip decompression, so
a compressed "zip bomb" response is cut off too; gzip responses are
decompressed as they are read, and their compressed size is capped as well.
Error replies (non-200) are read only when small, otherwise the connection is
closed. XML-RPC messages never have a DOCTYPE, so forbid_dtd defaults to True.

monkey_patch() applies the same parser to the stdlib's xmlrpc.client and
xmlrpc.server globally
"""

from __future__ import annotations

import gzip
import xmlrpc.client as _client
from typing import Any
from urllib.parse import urlsplit

from ._common import (
    DEFAULT_MAX_ATTLIST_DEFAULTS,
    DEFAULT_MAX_DEPTH,
    LimitedReader,
    Options,
    depth_exceeded,
    install_handlers,
    size_exceeded,
)

__all__ = ["SafeXMLRPCParser", "Transport", "SafeTransport", "ServerProxy", "loads",
           "monkey_patch", "unmonkey_patch", "DEFAULT_MAX_BYTES"]

DEFAULT_MAX_BYTES = 32 * 1024 * 1024

# An error reply's body is only read (to keep the connection reusable, as the
# stdlib does) when it declares at most this length; otherwise the connection
# is closed without reading it.
ERROR_BODY_LIMIT = 8 * 1024

_SAFE_KEYS = ("forbid_dtd", "forbid_entities", "forbid_external", "max_depth", "max_bytes",
              "max_attlist_defaults")


class SafeXMLRPCParser(_client.ExpatParser):
    """Replacement for xmlrpc.client.ExpatParser. XML-RPC never uses a
    DOCTYPE, so unlike the other APIs, forbid_dtd defaults to True."""

    def __init__(self, target: Any, *, forbid_dtd: bool = True, forbid_entities: bool = True,
                 forbid_external: bool = True, max_depth: int | None = DEFAULT_MAX_DEPTH,
                 max_bytes: int | None = DEFAULT_MAX_BYTES,
                 max_attlist_defaults: int | None = DEFAULT_MAX_ATTLIST_DEFAULTS):
        self.options = Options(forbid_dtd, forbid_entities, forbid_external, max_depth, max_bytes,
                               max_attlist_defaults)
        super().__init__(target)
        # The stdlib's close() deletes self._target before its final Parse(),
        # which can still report elements (Expat 2.6+ defers small chunks).
        self._safe_target = target
        self._depth = 0
        self._fed = 0
        self._parser.StartElementHandler = self._start
        self._parser.EndElementHandler = self._end
        self._attlist = install_handlers(self._parser, self.options)

    def _start(self, tag, attrs):
        self._depth += 1
        limit = self.options.max_depth
        if limit is not None and self._depth > limit:
            raise depth_exceeded(limit)
        if self._attlist.active:
            self._attlist.check(attrs.values(), self._fed)
        self._safe_target.start(tag, attrs)

    def _end(self, tag):
        self._depth -= 1
        self._safe_target.end(tag)

    def feed(self, data) -> None:
        self._fed += len(data)
        limit = self.options.max_bytes
        if limit is not None and self._fed > limit:
            raise size_exceeded(limit)
        super().feed(data)


def _split_safe(kwargs: dict[str, Any]) -> dict[str, Any]:
    return {key: kwargs.pop(key) for key in _SAFE_KEYS if key in kwargs}


def _compressed_limit(max_bytes: int) -> int:
    # Deflate can grow incompressible data very slightly (stored blocks,
    # gzip header and trailer); anything much larger than max_bytes cannot
    # decompress to an acceptable response.
    return max_bytes + max_bytes // 100 + 64 * 1024


def _gzip_stream(response: Any, max_bytes: int | None) -> gzip.GzipFile:
    """Decompress a gzip-encoded response as it is read. The stdlib's
    GzipDecodedResponse reads the whole compressed body into memory first.
    The compressed size is capped too: a stream of empty gzip members
    decompresses to nothing, so the decompressed cap alone never stops it."""
    source = response
    if max_bytes is not None:
        limit = _compressed_limit(max_bytes)
        source = LimitedReader(response, limit, f"compressed response is larger than {limit} bytes "
                                                f"(max_bytes={max_bytes})")
    return gzip.GzipFile(mode="rb", fileobj=source)


def _discard_error_body(response: Any) -> bool:
    """Read a small error body so the connection can be reused. Returns False
    (the caller closes the connection) when its length is unknown or large."""
    try:
        length = int(response.getheader("content-length", ""))
    except ValueError:
        return False
    if not 0 <= length <= ERROR_BODY_LIMIT:
        return False
    response.read()
    return True


class _SafeTransportMixin:
    def _init_safe(self, safe: dict[str, Any]) -> None:
        # validate options now, not per request
        self._safe_options = SafeXMLRPCParser(_client.Unmarshaller(), **safe).options
        self._safe = safe

    def getparser(self):
        unmarshaller = _client.Unmarshaller(use_datetime=self._use_datetime,
                                            use_builtin_types=self._use_builtin_types)
        return SafeXMLRPCParser(unmarshaller, **self._safe), unmarshaller

    def single_request(self, host, handler, request_body, verbose=False):
        # Same as the stdlib's, except for how the body of an error reply is
        # discarded: the stdlib reads all of it, however large.
        try:
            http_conn = self.send_request(host, handler, request_body, verbose)
            resp = http_conn.getresponse()
            if resp.status == 200:
                self.verbose = verbose
                return self.parse_response(resp)
        except _client.Fault:
            raise
        except Exception:
            # All unexpected errors leave the connection in a strange state.
            self.close()
            raise
        headers = dict(resp.getheaders())
        if not _discard_error_body(resp):
            self.close()
        raise _client.ProtocolError(host + handler, resp.status, resp.reason, headers)

    def parse_response(self, response):
        # Same as the stdlib's, except that a gzip body is streamed (see
        # _gzip_stream). SafeXMLRPCParser.feed() caps the decompressed size.
        if hasattr(response, "getheader") and response.getheader("Content-Encoding", "") == "gzip":
            stream = _gzip_stream(response, self._safe_options.max_bytes)
        else:
            stream = response
        p, u = self.getparser()
        while True:
            data = stream.read(1024)
            if not data:
                break
            if self.verbose:
                print("body:", repr(data))
            p.feed(data)
        if stream is not response:
            stream.close()
        p.close()
        return u.close()


class Transport(_SafeTransportMixin, _client.Transport):
    """HTTP transport that parses responses safely. Accepts the safexml options
    as keywords in addition to the stdlib Transport arguments."""

    def __init__(self, *args: Any, **kwargs: Any):
        safe = _split_safe(kwargs)
        super().__init__(*args, **kwargs)
        self._init_safe(safe)


class SafeTransport(_SafeTransportMixin, _client.SafeTransport):
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
