"""On ordinary documents, lazaret.safexml must produce exactly what the stdlib does."""

import io
import os
import tempfile
import unittest
import xml.dom.minidom
import xml.dom.pulldom
import xml.etree.ElementTree as StdET
import xml.sax
import xml.sax.handler
from xml.dom import expatbuilder

from lazaret.safexml import ElementTree as ET
from lazaret.safexml import minidom, pulldom, sax

DOC = """<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet href="s.css"?>
<!-- leading comment -->
<bom:bom xmlns:bom="http://cyclonedx.org/schema/bom/1.5" xmlns="urn:default" version="1" serialNumber="urn:uuid:3e67">
  <bom:components>
    <component type="library" bom:ref="pkg:pypi/requests@2.32.3">
      <name>requests</name><version>2.32.3</version>
      <description>HTTP for Humans &amp; friends &#169; &lt;tag&gt; — ünïcödé</description>
      <![CDATA[raw <cdata> & stuff]]>
      <!-- inner comment --><?pi data?>tail text
      <empty/>
    </component>
  </bom:components>
</bom:bom>
""".encode("utf-8")

WITH_DOCTYPE = b'<!DOCTYPE note SYSTEM "note.dtd"><note><to>T</to></note>'


def summarize(events):
    out = []
    for event, item in events:
        if event in ("start", "end"):
            out.append((event, item.tag, dict(item.attrib), item.text))
        elif event in ("comment", "pi"):
            out.append((event, item.tag, item.text))
        else:
            out.append((event, item))
    return out


def merge_text(calls):
    """Parsers may split character data into chunks differently (the stdlib's
    own C and Python parsers do); the concatenated text is what matters."""
    out = []
    for call in calls:
        if call[0] == "data" and out and out[-1][0] == "data":
            out[-1] = ("data", out[-1][1] + call[1])
        else:
            out.append(call)
    return out


class Recorder:
    def __init__(self):
        self.calls = []

    def start(self, tag, attrib):
        self.calls.append(("start", tag, attrib))

    def end(self, tag):
        self.calls.append(("end", tag))

    def data(self, text):
        self.calls.append(("data", text))

    def comment(self, text):
        self.calls.append(("comment", text))

    def pi(self, target, text):
        self.calls.append(("pi", target, text))

    def close(self):
        return self.calls


class SaxRecorder(xml.sax.handler.ContentHandler):
    def __init__(self):
        super().__init__()
        self.events = []

    def startElement(self, name, attrs):
        self.events.append(("start", name, dict(attrs)))

    def endElement(self, name):
        self.events.append(("end", name))

    def startElementNS(self, name, qname, attrs):
        self.events.append(("startNS", name, qname, dict(attrs)))

    def endElementNS(self, name, qname):
        self.events.append(("endNS", name, qname))

    def startPrefixMapping(self, prefix, uri):
        self.events.append(("prefix", prefix, uri))

    def characters(self, content):
        self.events.append(("chars", content))

    def processingInstruction(self, target, data):
        self.events.append(("pi", target, data))


class CompatTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "bom.xml")
        with open(self.path, "wb") as f:
            f.write(DOC)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp)

    def test_fromstring_matches_stdlib(self):
        for doc in (DOC, WITH_DOCTYPE, DOC.decode()):
            with self.subTest(doc=doc[:20]):
                self.assertEqual(ET.tostring(ET.fromstring(doc)), StdET.tostring(StdET.fromstring(doc)))
        self.assertIs(ET.XML, ET.fromstring)

    def test_parse_path_and_file(self):
        import pathlib
        expected = StdET.tostring(StdET.parse(self.path).getroot())
        for source in (self.path, pathlib.Path(self.path)):
            tree = ET.parse(source)
            self.assertIsInstance(tree, StdET.ElementTree)
            self.assertEqual(StdET.tostring(tree.getroot()), expected)
        with open(self.path, "rb") as f:
            self.assertEqual(StdET.tostring(ET.parse(f).getroot()), expected)
        self.assertTrue(ET.parse(self.path, parser=ET.XMLParser(max_depth=10)).getroot().tag.endswith("bom"))
        with self.assertRaises(TypeError):
            ET.parse(self.path, parser=ET.XMLParser(), max_depth=3)

    def test_stdlib_elementtree_accepts_our_parser(self):
        root = StdET.fromstring(DOC, parser=ET.XMLParser())
        self.assertEqual(StdET.tostring(root), StdET.tostring(StdET.fromstring(DOC)))

    def test_iterparse_matches_stdlib(self):
        for events in (None, ("start", "end"), ("start", "end", "start-ns", "end-ns", "comment", "pi")):
            with self.subTest(events=events):
                ours = ET.iterparse(self.path, events)
                theirs = StdET.iterparse(self.path, events)
                self.assertEqual(summarize(ours), summarize(theirs))
                self.assertEqual(StdET.tostring(ours.root), StdET.tostring(theirs.root))

    def test_iterparse_early_close_and_bad_event(self):
        it = ET.iterparse(self.path)
        next(it)
        it.close()
        with self.assertRaises(ValueError):
            ET.iterparse(self.path, events=("bogus",))

    def test_custom_target_matches_stdlib(self):
        ours = ET.XMLParser(target=Recorder())
        ours.feed(DOC)
        theirs = StdET.XMLParser(target=Recorder())
        theirs.feed(DOC)
        self.assertEqual(merge_text(ours.close()), merge_text(theirs.close()))

    def test_parse_errors_match_stdlib(self):
        for bad in (b"<a><b></a>", b"<a>", b"", b"<a>&undefined;</a>", b"<a x='1' x='2'/>",
                    b'<!DOCTYPE a SYSTEM "a.dtd"><a>&undefined;</a>'):
            with self.subTest(bad=bad):
                with self.assertRaises(StdET.ParseError) as ours:
                    ET.fromstring(bad)
                with self.assertRaises(StdET.ParseError) as theirs:
                    StdET.fromstring(bad)
                self.assertEqual((ours.exception.code, ours.exception.position),
                                 (theirs.exception.code, theirs.exception.position))
                self.assertEqual(str(ours.exception), str(theirs.exception))

    def test_encodings(self):
        latin = '<?xml version="1.0" encoding="ISO-8859-1"?><a>caf\xe9</a>'.encode("latin-1")
        self.assertEqual(ET.fromstring(latin).text, "café")
        parser = ET.XMLParser(encoding="ISO-8859-1")
        parser.feed("<a>caf\xe9</a>".encode("latin-1"))
        self.assertEqual(parser.close().text, "café")

    def test_entity_escape_hatch_matches_stdlib(self):
        doc = b'<!DOCTYPE a SYSTEM "a.dtd"><a>&custom;</a>'
        ours, theirs = ET.XMLParser(), StdET.XMLParser()
        ours.entity["custom"] = theirs.entity["custom"] = "value"
        ours.feed(doc)
        theirs.feed(doc)
        self.assertEqual(ours.close().text, theirs.close().text)

    def test_minidom_matches_stdlib(self):
        for namespaces in (True, False):
            with self.subTest(namespaces=namespaces):
                expected = expatbuilder.parseString(DOC, namespaces=namespaces).toxml()
                self.assertEqual(minidom.parseString(DOC, namespaces=namespaces).toxml(), expected)
                self.assertEqual(minidom.parse(self.path, namespaces=namespaces).toxml(), expected)
                self.assertEqual(minidom.parse(io.BytesIO(DOC), namespaces=namespaces).toxml(), expected)
        self.assertEqual(xml.dom.minidom.parseString(DOC).toxml(), minidom.parseString(DOC).toxml())

    def test_sax_matches_stdlib(self):
        def run(make_parser, namespaces):
            handler = SaxRecorder()
            parser = make_parser()
            parser.setFeature(xml.sax.handler.feature_namespaces, namespaces)
            parser.setContentHandler(handler)
            parser.parse(io.BytesIO(DOC))
            return handler.events
        for namespaces in (False, True):
            with self.subTest(namespaces=namespaces):
                self.assertEqual(run(sax.make_parser, namespaces), run(xml.sax.make_parser, namespaces))
        ours, theirs = SaxRecorder(), SaxRecorder()
        sax.parseString(DOC, ours)
        xml.sax.parseString(DOC, theirs)
        self.assertEqual(ours.events, theirs.events)

    def test_sax_parse_errors_still_use_error_handler(self):
        with self.assertRaises(xml.sax.SAXParseException):
            sax.parseString(b"<a><b></a>", xml.sax.handler.ContentHandler())

    def test_pulldom_matches_stdlib(self):
        def run(events):
            out = []
            for event, node in events:
                if event == xml.dom.pulldom.START_ELEMENT and node.localName == "component":
                    events.expandNode(node)
                    out.append(("expanded", node.toxml()))
                else:
                    out.append((event, node.nodeName))
            return out
        self.assertEqual(run(pulldom.parse(io.BytesIO(DOC))), run(xml.dom.pulldom.parse(io.BytesIO(DOC))))
        text = DOC.decode()
        self.assertEqual(run(pulldom.parseString(text)), run(xml.dom.pulldom.parseString(text)))
        with self.assertRaises(TypeError):
            pulldom.parseString(text, parser=sax.make_parser(), max_depth=3)


if __name__ == "__main__":
    unittest.main()
