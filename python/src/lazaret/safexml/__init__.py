"""lazaret.safexml: parse untrusted XML safely, using only the standard library.

A layer over the stdlib parsers. It guards against:

- entity expansion bombs (billion laughs, quadratic blowup);
- XML external entities (XXE): local file disclosure and server-side requests;
- external DTD and parameter-entity loading (never done, in any API);
- deeply nested documents (max_depth) and oversized input (max_bytes).

Modules mirror both the stdlib and others, so switching is one import line:

    from lazaret.safexml import ElementTree as ET   # instead of xml.etree.ElementTree
    from lazaret.safexml import minidom, sax, pulldom, xmlrpc

Every parsing function accepts these keyword options:

    forbid_dtd=False       refuse any <!DOCTYPE>
    forbid_entities=True   refuse entity declarations
    forbid_external=True   refuse external entity references
    max_depth=500          maximum element nesting (None: unlimited)
    max_bytes=None         maximum input size (32 MiB for xmlrpc; None: unlimited)

Refusals raise subclasses of SafeXMLError (itself a ValueError). Malformed XML
raises the same errors as the stdlib (e.g. xml.etree.ElementTree.ParseError).
"""

from ._common import (
    DEFAULT_MAX_DEPTH,
    EXPAT_HAS_AMPLIFICATION_LIMIT,
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
    LimitExceeded,
    NotSupportedError,
    Options,
    SafeXMLError,
)

# defusedxml name for the base class
DefusedXmlException = SafeXMLError

__all__ = [
    "SafeXMLError", "DefusedXmlException", "DTDForbidden", "EntitiesForbidden",
    "ExternalReferenceForbidden", "LimitExceeded", "NotSupportedError", "Options",
    "DEFAULT_MAX_DEPTH", "EXPAT_HAS_AMPLIFICATION_LIMIT",
]
