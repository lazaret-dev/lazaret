"""Shared machinery for the safexml tests: every parsing API, and a canary
HTTP server that records any request a parser makes."""

import http.server
import io
import threading
import xml.etree.ElementTree as StdET
import xml.sax.handler
import xmlrpc.client as rpc_client
from xml.sax.handler import ContentHandler

from lazaret.safexml import ElementTree as ET
from lazaret.safexml import minidom, pulldom, sax, xmlrpc

ALL_EVENTS = ("start", "end", "start-ns", "end-ns", "comment", "pi")


def _feed_in_chunks(data, **o):
    parser = ET.XMLParser(**o)
    for i in range(0, len(data), 7):
        parser.feed(data[i:i + 7])
    return parser.close()


def _sax_ns(data, **o):
    parser = sax.make_parser(**o)
    parser.setFeature(xml.sax.handler.feature_namespaces, True)
    parser.setContentHandler(ContentHandler())
    parser.parse(io.BytesIO(data))


def _pulldom_all(data, **o):
    for _ in pulldom.parse(io.BytesIO(data), **o):
        pass


def _pull_parser(data, **o):
    parser = ET.XMLPullParser(ALL_EVENTS, **o)
    events = []
    for i in range(0, len(data), 7):
        parser.feed(data[i:i + 7])
        events.extend(parser.read_events())
    parser.close()
    events.extend(parser.read_events())
    return events


def _element_tree(data, **o):
    if not o:
        return ET.ElementTree(file=io.BytesIO(data))  # the default parser
    return ET.ElementTree().parse(io.BytesIO(data), ET.XMLParser(**o))


def _xmlrpc_parser(data, **o):
    o.setdefault("forbid_dtd", False)  # XML-RPC refuses any DOCTYPE by default (test_review_attlist)
    parser = xmlrpc.SafeXMLRPCParser(rpc_client.Unmarshaller(), **o)
    for i in range(0, len(data), 7):
        parser.feed(data[i:i + 7])
    parser.close()


# Every way to parse a document with lazaret.safexml. Each parses fully.
APIS = {
    "ET.fromstring": lambda data, **o: ET.fromstring(data, **o),
    "ET.parse": lambda data, **o: ET.parse(io.BytesIO(data), **o),
    "ET.iterparse": lambda data, **o: list(ET.iterparse(io.BytesIO(data), ("start", "end"), **o)),
    "ET.XMLParser": _feed_in_chunks,
    "minidom.parseString": lambda data, **o: minidom.parseString(data, **o),
    "minidom.parse": lambda data, **o: minidom.parse(io.BytesIO(data), **o),
    "sax.parseString": lambda data, **o: sax.parseString(data, ContentHandler(), **o),
    "sax.parse": lambda data, **o: sax.parse(io.BytesIO(data), ContentHandler(), **o),
    "sax.ns": _sax_ns,
    "pulldom.parse": _pulldom_all,
    "ET.XMLPullParser": _pull_parser,
    "ET.ElementTree": _element_tree,
    "ET.XMLID": lambda data, **o: ET.XMLID(data, **o),
    "ET.canonicalize": lambda data, **o: ET.canonicalize(data, **o),
    "stdlib iterparse, safe parser": lambda data, **o: list(
        StdET.iterparse(io.BytesIO(data), ALL_EVENTS, parser=ET.XMLParser(**o))),
    "xmlrpc parser": _xmlrpc_parser,
}


class _CountingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        body = b'<!ENTITY leaked "SECRET-FROM-SERVER">' if self.path.endswith(".dtd") else b"SECRET-FROM-SERVER"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Canary:
    """An HTTP server on 127.0.0.1 that records every request. Any hit means a
    parser fetched an external resource."""

    def __init__(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CountingHandler)
        self.server.hits = []
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    @property
    def hits(self):
        return self.server.hits

    def reset(self):
        self.server.hits.clear()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
