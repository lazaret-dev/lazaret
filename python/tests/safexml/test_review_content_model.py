"""A deeply nested <!ELEMENT> content model must not crash any API.

Review finding: the stdlib minidom builder installs an ElementDeclHandler, and
pyexpat converts each content model to nested tuples recursively in C, so a
model nested ~200,000 deep overflowed the C stack and killed the interpreter
(exit 139). Each case runs in a subprocess, on a thread with a small stack (as
on Windows), so a regression shows up as a failed test, not a crashed runner.
"""

import subprocess
import sys
import unittest
import xml.dom.minidom

from lazaret.safexml import minidom

DEPTH = 200_000

CHILD = r'''
import io, sys, threading
import xml.sax.handler
import xmlrpc.client as rpc_client
from lazaret.safexml import ElementTree as ET, minidom, pulldom, sax, xmlrpc

depth = int(sys.argv[2])
doc = b"<!DOCTYPE r [<!ELEMENT r " + b"(" * depth + b"a" + b")" * depth + b">]><r/>"


class Lexical:
    def startDTD(self, *args): pass
    def endDTD(self): pass
    def comment(self, text): pass
    def startCDATA(self): pass
    def endCDATA(self): pass


def sax_lexical(data):
    parser = sax.make_parser()
    parser.setContentHandler(xml.sax.handler.ContentHandler())
    parser.setProperty(xml.sax.handler.property_lexical_handler, Lexical())
    parser.parse(io.BytesIO(data))


def pulldom_all(data):
    for _ in pulldom.parse(io.BytesIO(data)):
        pass


def xmlrpc_parse(data):
    parser = xmlrpc.SafeXMLRPCParser(rpc_client.Unmarshaller(), forbid_dtd=False)
    parser.feed(data)
    parser.close()


APIS = {
    "minidom.parseString": minidom.parseString,
    "minidom.parse": lambda d: minidom.parse(io.BytesIO(d)),
    "ET.fromstring": ET.fromstring,
    "ET.iterparse": lambda d: list(ET.iterparse(io.BytesIO(d), ("start", "end"))),
    "sax.parseString": lambda d: sax.parseString(d, xml.sax.handler.ContentHandler()),
    "sax.lexical-handler": sax_lexical,
    "pulldom.parse": pulldom_all,
    "xmlrpc": xmlrpc_parse,
}


def run():
    APIS[sys.argv[1]](doc)
    print("parsed", flush=True)


threading.stack_size(512 * 1024)
thread = threading.Thread(target=run)
thread.start()
thread.join()
'''

APIS = ("minidom.parseString", "minidom.parse", "ET.fromstring", "ET.iterparse", "sax.parseString",
        "sax.lexical-handler", "pulldom.parse", "xmlrpc")


class ContentModelTests(unittest.TestCase):
    def test_deep_content_model_does_not_crash(self):
        for api in APIS:
            with self.subTest(api=api):
                proc = subprocess.run([sys.executable, "-c", CHILD, api, str(DEPTH)],
                                      capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace")
                self.assertEqual(proc.returncode, 0, f"exit {proc.returncode}: {proc.stderr[-400:]}")
                self.assertEqual(proc.stdout.strip(), "parsed", proc.stderr[-400:])

    def test_minidom_output_unchanged_by_dropping_content_models(self):
        doc = (b'<!DOCTYPE r [<!ELEMENT r (a, b*)><!ELEMENT a (#PCDATA)><!ELEMENT b EMPTY>'
               b'<!ATTLIST b id ID #IMPLIED>]>\n<r>\n  <a>t</a>\n  <b id="x"/>\n</r>')
        ours, theirs = minidom.parseString(doc), xml.dom.minidom.parseString(doc)
        self.assertEqual(ours.toxml(), theirs.toxml())
        self.assertEqual(ours.doctype.internalSubset, theirs.doctype.internalSubset)
        self.assertIs(ours.getElementById("x"), ours.getElementsByTagName("b")[0])


if __name__ == "__main__":
    unittest.main()
