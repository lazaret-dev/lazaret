"""Attribute defaults declared in the DTD must not amplify memory.

Review finding: Expat copies each <!ATTLIST a x CDATA "AAAA..."> default onto
every <a> element, with no entity involved, so entity refusal did not stop the
"quadratic blowup": 105 KB of input produced 200 MB of attribute values, and
1 MB used ~2.9 GB, through ElementTree, SAX, pulldom and XML-RPC. Now the
declared defaults have a budget (max_attlist_defaults), and the attributes
reported once a default is declared may not exceed 100 times the input.
"""

import io
import subprocess
import sys
import unittest
import xml.dom.minidom
import xml.etree.ElementTree as StdET
import xml.sax
import xml.sax.handler
import xmlrpc.client

import lazaret.safexml as sx
from lazaret.safexml import ElementTree as ET
from lazaret.safexml import minidom, sax
from lazaret.safexml import xmlrpc as safe_xmlrpc

from ._harness import APIS


def attlist_doc(default_len, elements, attrs=1):
    decls = "".join(f'<!ATTLIST a x{i} CDATA "{"A" * default_len}">' for i in range(attrs))
    return f"<!DOCTYPE r [{decls}]><r>".encode() + b"<a/>" * elements + b"</r>"


def xmlrpc_attlist_doc(default_len, values):
    return (b'<!DOCTYPE methodResponse [<!ATTLIST value x CDATA "' + b"A" * default_len + b'">]>'
            b"<methodResponse><params><param><value><array><data>" + b"<value/>" * values
            + b"</data></array></value></param></params></methodResponse>")


def all_apis():
    apis = dict(APIS)
    apis["xmlrpc.loads"] = lambda data, **o: safe_xmlrpc.loads(data, **{"forbid_dtd": False, **o})
    return apis


class Recorder(xml.sax.handler.ContentHandler):
    def __init__(self):
        super().__init__()
        self.events = []

    def startElement(self, name, attrs):
        self.events.append((name, dict(attrs)))

    def startElementNS(self, name, qname, attrs):
        self.events.append((name, dict(attrs)))


class AttlistBudgetTests(unittest.TestCase):
    def test_large_declared_default_refused(self):
        doc = attlist_doc(100_000, 3)
        rpc = xmlrpc_attlist_doc(100_000, 3)
        for name, api in all_apis().items():
            with self.subTest(api=name):
                with self.assertRaisesRegex(sx.LimitExceeded, "max_attlist_defaults=65536"):
                    api(rpc if name == "xmlrpc.loads" else doc)

    def test_many_declarations_refused(self):
        """Each declaration counts 64 on top of its value, so empty defaults
        cannot be multiplied instead."""
        doc = attlist_doc(0, 2, attrs=1100)
        for name, api in all_apis().items():
            if name == "xmlrpc.loads":
                continue
            with self.subTest(api=name):
                with self.assertRaisesRegex(sx.LimitExceeded, "max_attlist_defaults"):
                    api(doc)
        api = all_apis()["ET.fromstring"]
        self.assertEqual(len(api(attlist_doc(0, 2, attrs=1000))[0].attrib), 1000)  # within budget

    def test_amplification_within_budget_refused(self):
        """60 KB of default is within the declaration budget, but copied onto
        thousands of elements it would be ~100 MB: refused once past 100x the
        input. minidom's own builder never receives defaulted attributes, so
        it parses (minidom with a SAX parser builds through pulldom, which does)."""
        doc = attlist_doc(60_000, 2_000)
        rpc = xmlrpc_attlist_doc(60_000, 2_000)
        for name, api in all_apis().items():
            with self.subTest(api=name):
                if name in ("minidom.parseString", "minidom.parse"):
                    document = api(doc)
                    self.assertEqual(document.getElementsByTagName("a")[0].getAttribute("x0"), "")
                    continue
                with self.assertRaisesRegex(sx.LimitExceeded, "more than 100 times"):
                    api(rpc if name == "xmlrpc.loads" else doc)

    def test_option_is_tunable(self):
        doc = attlist_doc(100_000, 3)
        root = ET.fromstring(doc, max_attlist_defaults=200_000)
        self.assertEqual([len(a.get("x0")) for a in root], [100_000] * 3)
        parser = sax.make_parser(max_attlist_defaults=None)
        handler = Recorder()
        parser.setContentHandler(handler)
        parser.parse(io.BytesIO(attlist_doc(60_000, 200)))  # no limit: no amplification check either
        self.assertEqual(len(handler.events), 201)
        self.assertEqual(safe_xmlrpc.loads(xmlrpc_attlist_doc(10, 2), forbid_dtd=False),
                         xmlrpc.client.loads(xmlrpc_attlist_doc(10, 2)))
        for bad in (0, -5, 2.5):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                sx.Options(max_attlist_defaults=bad)

    @staticmethod
    def ordinary(repeat):
        return (b'<!DOCTYPE r [<!ATTLIST a kind CDATA "plain" fixed CDATA #FIXED "f" mode (u|v) "u"'
                b' note CDATA #IMPLIED><!ATTLIST r xmlns:p CDATA #FIXED "urn:p">]><r>'
                + b'<a/><a kind="given"/><p:a p:x="1"/>' * repeat + b"</r>")

    def test_many_ordinary_defaults_are_not_refused(self):
        """Past the 8 MiB threshold (the check is running), but far below
        100 times the input."""
        doc = self.ordinary(20_000)
        self.assertEqual(ET.tostring(ET.fromstring(doc)), StdET.tostring(StdET.fromstring(doc)))
        handler = Recorder()
        sax.parseString(doc, handler)
        self.assertEqual(len(handler.events), 60_001)

    def test_ordinary_defaults_match_stdlib(self):
        doc = self.ordinary(200)
        self.assertEqual(ET.tostring(ET.fromstring(doc)), StdET.tostring(StdET.fromstring(doc)))
        for namespaces in (False, True):
            with self.subTest(namespaces=namespaces):
                ours, theirs = Recorder(), Recorder()
                for make_parser, handler in ((sax.make_parser, ours), (xml.sax.make_parser, theirs)):
                    parser = make_parser()
                    parser.setFeature(xml.sax.handler.feature_namespaces, namespaces)
                    parser.setContentHandler(handler)
                    parser.parse(io.BytesIO(doc))
                self.assertEqual(ours.events, theirs.events)
        self.assertEqual(minidom.parseString(doc).toxml(), xml.dom.minidom.parseString(doc).toxml())

    def test_minidom_keeps_its_own_attlist_handler(self):
        doc = b'<!DOCTYPE r [<!ATTLIST b id ID #IMPLIED kind CDATA "k">]><r><b id="x"/></r>'
        document = minidom.parseString(doc)
        self.assertIs(document.getElementById("x"), document.getElementsByTagName("b")[0])


class XmlRpcDoctypeTests(unittest.TestCase):
    def test_xmlrpc_refuses_any_doctype_by_default(self):
        response = xmlrpc.client.dumps((1,), methodresponse=True).encode()
        with_doctype = response.replace(b"<methodResponse>", b"<!DOCTYPE methodResponse><methodResponse>")
        with self.assertRaises(sx.DTDForbidden):
            safe_xmlrpc.loads(with_doctype)
        with self.assertRaises(sx.DTDForbidden):
            safe_xmlrpc.loads(xmlrpc_attlist_doc(10, 2))
        self.assertEqual(safe_xmlrpc.loads(with_doctype, forbid_dtd=False), ((1,), None))
        self.assertTrue(safe_xmlrpc.SafeXMLRPCParser(xmlrpc.client.Unmarshaller()).options.forbid_dtd)


MEMORY_CHILD = r'''
import io, resource, sys
import xml.sax.handler
resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
from lazaret.safexml import ElementTree as ET, pulldom, sax, xmlrpc
import lazaret.safexml as sx
api = sys.argv[1]
doc = b'<!DOCTYPE r [<!ATTLIST a x CDATA "' + b"A" * 65_000 + b'">]><r>' + b"<a/>" * 250_000 + b"</r>"
rpc = (b'<!DOCTYPE methodResponse [<!ATTLIST value x CDATA "' + b"A" * 65_000 + b'">]><methodResponse>'
       b"<params><param><value><array><data>" + b"<value/>" * 250_000 + b"</data></array></value></param></params></methodResponse>")
class Keep(xml.sax.handler.ContentHandler):
    kept = []
    def startElement(self, name, attrs):
        self.kept.append(dict(attrs))
try:
    if api == "ET":
        ET.fromstring(doc)
    elif api == "sax":
        sax.parseString(doc, Keep())
    elif api == "pulldom":
        kept = [node for event, node in pulldom.parse(io.BytesIO(doc)) if event == "START_ELEMENT"]
    elif api == "xmlrpc":
        xmlrpc.loads(rpc, forbid_dtd=False)
    print("parsed")
except sx.LimitExceeded:
    # VmHWM is this process's own peak RSS; ru_maxrss would include the parent's.
    with open("/proc/self/status") as status:
        peak_kib = next(line.split()[1] for line in status if line.startswith("VmHWM:"))
    print("refused", peak_kib)
'''


@unittest.skipUnless(sys.platform.startswith("linux"), "needs an enforced RLIMIT_AS (Linux)")
class AttlistMemoryTests(unittest.TestCase):
    def test_reviewer_scale_document_stays_small(self):
        """1 MB of input used ~2.9 GB before; now it is refused well under the
        1 GiB address-space limit the child runs with."""
        for api in ("ET", "sax", "pulldom", "xmlrpc"):
            with self.subTest(api=api):
                proc = subprocess.run([sys.executable, "-c", MEMORY_CHILD, api],
                                      capture_output=True, text=True, timeout=30)
                self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
                verdict, rss_kib = proc.stdout.split()
                self.assertEqual(verdict, "refused")
                self.assertLess(int(rss_kib), 400 * 1024)


if __name__ == "__main__":
    unittest.main()
