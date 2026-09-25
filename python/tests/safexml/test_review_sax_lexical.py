"""forbid_dtd must survive a SAX lexical handler set during parsing.

Found while fixing the review: the stdlib Expat reader reinstalls its own
StartDoctypeDeclHandler (or None) whenever property_lexical_handler is set
mid-parse, so a ContentHandler doing that in startDocument() turned
forbid_dtd off and the DOCTYPE was accepted.
"""

import io
import unittest
import xml.sax.handler

import lazaret.safexml as sx
from lazaret.safexml import sax


class Lexical:
    def __init__(self):
        self.dtds = []

    def startDTD(self, name, pubid, sysid):
        self.dtds.append(name)

    def endDTD(self):
        pass

    def comment(self, text):
        pass

    def startCDATA(self):
        pass

    def endCDATA(self):
        pass


class SetsLexicalHandler(xml.sax.handler.ContentHandler):
    def __init__(self, parser, lexical):
        super().__init__()
        self.parser, self.lexical = parser, lexical

    def startDocument(self):
        self.parser.setProperty(xml.sax.handler.property_lexical_handler, self.lexical)


class LexicalHandlerTests(unittest.TestCase):
    def parse(self, doc, **options):
        parser = sax.make_parser(**options)
        lexical = Lexical()
        parser.setContentHandler(SetsLexicalHandler(parser, lexical))
        parser.parse(io.BytesIO(doc))
        return lexical

    def test_forbid_dtd_survives_lexical_handler_set_mid_parse(self):
        with self.assertRaises(sx.DTDForbidden):
            self.parse(b"<!DOCTYPE r><r/>", forbid_dtd=True)

    def test_lexical_handler_still_sees_doctype_when_allowed(self):
        self.assertEqual(self.parse(b"<!DOCTYPE r><r/>").dtds, ["r"])


if __name__ == "__main__":
    unittest.main()
