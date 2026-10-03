"""Fuzz finding F-1 (audits/lazaret-fuzz-findings-2026-10-03.md): an XML
declaration naming an encoding Expat can't read ended the parse with
LookupError ("T7": no such codec) or ValueError ("UTF32": a multi-byte
codec), out of every API: the standard library does the same, but safexml's
job is to turn hostile XML into the one error type each API raises for a
malformed document. Now ElementTree raises ParseError, minidom and XML-RPC
ExpatError, SAX a fatal SAXParseException, and none of them repeats the
encoding's name (the document's text). Refusals stay what they were.
"""
import unittest
import xml.sax.handler
from xml.parsers import expat
from xml.sax import SAXParseException

from lazaret import safexml as sx
from lazaret.safexml import ElementTree as ET
from lazaret.safexml import minidom, sax, xmlrpc

DOCS = {"T7": b'<?xml version="1.0" encoding="T7"?><a/>',
        "UTF32": b'<?xml version="1.0" encoding="UTF32"?><a/>'}


def pull(data):
    parser = ET.XMLPullParser()
    parser.feed(data)
    return list(parser.read_events())


APIS = (("ElementTree.fromstring", lambda d: ET.fromstring(d, forbid_dtd=True), ET.ParseError),
        ("ElementTree.XMLPullParser", pull, ET.ParseError),
        ("minidom.parseString", minidom.parseString, expat.ExpatError),
        ("sax.parseString", lambda d: sax.parseString(d, xml.sax.handler.ContentHandler()), SAXParseException),
        ("xmlrpc.loads", xmlrpc.loads, expat.ExpatError))


class EncodingTests(unittest.TestCase):
    def test_each_api_raises_its_parse_error(self):
        for (label, parse, error), (enc, doc) in ((api, d) for api in APIS for d in DOCS.items()):
            with self.subTest(api=label, encoding=enc):
                with self.assertRaises(error) as caught:
                    parse(doc)
                self.assertIn("unknown encoding", str(caught.exception))
                self.assertNotIn(enc, str(caught.exception))

    def test_the_parse_errors_code(self):
        with self.assertRaises(ET.ParseError) as caught:
            ET.fromstring(DOCS["T7"])
        self.assertEqual(caught.exception.code, expat.errors.codes[expat.errors.XML_ERROR_UNKNOWN_ENCODING])
        self.assertEqual(caught.exception.position, (1, 0))

    def test_refusals_are_not_parse_errors(self):
        dtd = b'<!DOCTYPE a [<!ENTITY x "y">]><a>&x;</a>'
        with self.assertRaises(sx.DTDForbidden):
            ET.fromstring(dtd, forbid_dtd=True)
        with self.assertRaises(sx.EntitiesForbidden):
            minidom.parseString(dtd)
        with self.assertRaises(sx.SafeXMLError):
            ET.fromstring(b"<a>" + b" " * 64 + b"</a>", max_bytes=16)

    def test_a_known_encoding_still_parses(self):
        self.assertEqual(ET.fromstring('<?xml version="1.0" encoding="latin-1"?><a>\xe9</a>'.encode("latin-1")).text,
                         "\xe9")


if __name__ == "__main__":
    unittest.main()
