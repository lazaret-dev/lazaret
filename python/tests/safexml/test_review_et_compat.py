"""lazaret.safexml.ElementTree must be a real drop-in for xml.etree.ElementTree.

Review findings:
- not a drop-in: no XMLPullParser, no _setevents (so the stdlib's iterparse
  could not use the safe parser), no stdlib `parser` arguments, iterparse
  opened its path lazily, most non-parsing names missing, and
  ElementTree().parse() used the unprotected stdlib parser;
- iterparse dropped the events queued before a ParseError in the same chunk
  (the stdlib yields them first);
- iterparse consumed a generator `events` argument while validating it, then
  reported no events.
Every comparison here is against the stdlib on the same input.
"""

import io
import os
import shutil
import tempfile
import unittest
import xml.dom.minidom
import xml.etree.ElementTree as StdET
import xml.sax

import lazaret.safexml as sx
from lazaret.safexml import ElementTree as ET
from lazaret.safexml import minidom, pulldom, sax

from . import payloads

DOC = """<?xml version="1.0" encoding="UTF-8"?>
<?xml-stylesheet href="s.css"?>
<!-- leading comment -->
<bom:bom xmlns:bom="http://cyclonedx.org/schema/bom/1.5" xmlns="urn:default" version="1">
  <bom:components>
    <component type="library" bom:ref="pkg:pypi/requests@2.32.3" id="c1">
      <name>requests</name><version id="v1">2.32.3</version>
      <description>HTTP for Humans &amp; friends &#169; — ünïcödé</description>
      <![CDATA[raw <cdata> & stuff]]>
      <!-- inner comment --><?pi data?>tail text
      <empty xmlns:x="urn:x" x:a="1"/>
    </component>
  </bom:components>
</bom:bom>
""".encode("utf-8")

ALL = ("start", "end", "start-ns", "end-ns", "comment", "pi")
PARSING = {"XMLParser", "XMLPullParser", "XML", "fromstring", "fromstringlist", "XMLID", "parse", "iterparse",
           "canonicalize", "ElementTree"}
BAD_DOCS = (b"<r><a/><b>t</b><c></r>", b"<r><a/></r><junk/>", b"<r><a/>&undefined;</r>", b"<r><a/><b",
            b"<r><a x='1' x='2'/></r>")


def summarize(events):
    out = []
    for event, item in events:
        if event in ("start", "end"):
            out.append((event, item.tag, dict(item.attrib), item.text, item.tail))
        elif event in ("comment", "pi"):
            out.append((event, item.tag, item.text))
        else:
            out.append((event, item))
    return out


def collect(iterator):
    """Events up to and including the error, as comparable tuples."""
    out = []
    try:
        for event, item in iterator:
            out.append((event, getattr(item, "tag", item)))
    except StdET.ParseError as exc:
        out.append(("ParseError", exc.code, exc.position))
    except sx.SafeXMLError as exc:
        out.append((type(exc).__name__, str(exc)))
    return out


def pull(module, doc, events, chunk):
    parser = module.XMLPullParser(events)
    out = []
    try:
        for i in range(0, len(doc), chunk):
            parser.feed(doc[i:i + chunk])
            out.extend(summarize(parser.read_events()))
        parser.close()
        out.extend(summarize(parser.read_events()))
    except StdET.ParseError as exc:
        out.append(("ParseError", exc.code, exc.position))
    except sx.SafeXMLError as exc:
        out.append((type(exc).__name__, str(exc)))
    return out


class ModuleTests(unittest.TestCase):
    def test_every_stdlib_name_is_there(self):
        for name in StdET.__all__:
            with self.subTest(name=name):
                self.assertTrue(hasattr(ET, name))
                self.assertIn(name, ET.__all__)
                if name in PARSING:
                    self.assertIsNot(getattr(ET, name), getattr(StdET, name))
                else:
                    self.assertIs(getattr(ET, name), getattr(StdET, name))
        namespace = {}
        exec("from lazaret.safexml.ElementTree import *", namespace)
        self.assertIs(namespace["XMLParser"], ET.XMLParser)
        self.assertIs(ET.XML, ET.fromstring)

    def test_foreign_parsers_are_refused(self):
        stdlib_parser = StdET.XMLParser
        calls = {
            "fromstring": lambda: ET.fromstring(DOC, stdlib_parser()),
            "XML": lambda: ET.XML(DOC, parser=stdlib_parser()),
            "fromstringlist": lambda: ET.fromstringlist([DOC], stdlib_parser()),
            "XMLID": lambda: ET.XMLID(DOC, stdlib_parser()),
            "parse": lambda: ET.parse(io.BytesIO(DOC), stdlib_parser()),
            "ElementTree.parse": lambda: ET.ElementTree().parse(io.BytesIO(DOC), stdlib_parser()),
            "iterparse": lambda: ET.iterparse(io.BytesIO(DOC), parser=stdlib_parser()),
            "XMLPullParser": lambda: ET.XMLPullParser(_parser=stdlib_parser()),
            "minidom.parse": lambda: minidom.parse(io.BytesIO(DOC), xml.sax.make_parser()),
            "minidom.parseString": lambda: minidom.parseString(DOC.decode(), xml.sax.make_parser()),
            "pulldom.parse": lambda: pulldom.parse(io.BytesIO(DOC), xml.sax.make_parser()),
            "pulldom.parseString": lambda: pulldom.parseString(DOC.decode(), xml.sax.make_parser()),
        }
        for name, call in calls.items():
            with self.subTest(call=name):
                with self.assertRaisesRegex(TypeError, "without the safexml protections"):
                    call()

    def test_options_and_a_parser_are_exclusive(self):
        for call in (lambda: ET.fromstring(DOC, ET.XMLParser(), max_depth=3),
                     lambda: ET.iterparse(io.BytesIO(DOC), None, ET.XMLParser(), max_depth=3),
                     lambda: ET.XMLPullParser(_parser=ET.XMLParser(), max_depth=3),
                     lambda: minidom.parseString(DOC, sax.make_parser(), max_depth=3)):
            with self.subTest(call=call), self.assertRaises(TypeError):
                call()


class ParseFunctionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "bom.xml")
        with open(self.path, "wb") as f:
            f.write(DOC)
        self.bomb = os.path.join(self.tmp, "bomb.xml")
        with open(self.bomb, "wb") as f:
            f.write(payloads.BILLION_LAUGHS)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_stdlib_signatures(self):
        expected = StdET.tostring(StdET.fromstring(DOC))
        self.assertEqual(StdET.tostring(ET.fromstring(DOC, None)), expected)
        self.assertEqual(StdET.tostring(ET.XML(DOC, parser=ET.XMLParser())), expected)
        self.assertEqual(StdET.tostring(ET.fromstringlist([DOC[:50], DOC[50:]], None)), expected)
        with self.assertRaises(sx.LimitExceeded):
            ET.fromstring(DOC, ET.XMLParser(max_depth=2))

    def test_elementtree_class_parses_safely(self):
        with self.assertRaises(sx.EntitiesForbidden):
            ET.ElementTree(file=self.bomb)
        with self.assertRaises(sx.EntitiesForbidden):
            ET.ElementTree().parse(self.bomb)
        tree = ET.ElementTree(file=self.path)
        self.assertIsInstance(tree, StdET.ElementTree)
        self.assertEqual(StdET.tostring(tree.getroot()), StdET.tostring(StdET.parse(self.path).getroot()))
        self.assertIsInstance(ET.parse(self.path), ET.ElementTree)
        with self.assertRaises(sx.LimitExceeded):
            ET.ElementTree().parse(self.path, ET.XMLParser(max_depth=2))

    def test_xmlid_matches_stdlib(self):
        ours, theirs = ET.XMLID(DOC), StdET.XMLID(DOC)
        self.assertEqual(StdET.tostring(ours[0]), StdET.tostring(theirs[0]))
        self.assertEqual({k: StdET.tostring(v) for k, v in ours[1].items()},
                         {k: StdET.tostring(v) for k, v in theirs[1].items()})
        with self.assertRaises(sx.EntitiesForbidden):
            ET.XMLID(payloads.BILLION_LAUGHS)

    def test_canonicalize_matches_stdlib(self):
        self.assertEqual(ET.canonicalize(DOC), StdET.canonicalize(DOC))
        for options in ({"with_comments": True}, {"strip_text": True, "rewrite_prefixes": True}):
            with self.subTest(options=options):
                self.assertEqual(ET.canonicalize(from_file=self.path, **options),
                                 StdET.canonicalize(from_file=self.path, **options))
        ours, theirs = io.StringIO(), io.StringIO()
        self.assertIsNone(ET.canonicalize(DOC, out=ours))
        StdET.canonicalize(DOC, out=theirs)
        self.assertEqual(ours.getvalue(), theirs.getvalue())
        with self.assertRaises(sx.EntitiesForbidden):
            ET.canonicalize(from_file=self.bomb)
        with self.assertRaises(sx.LimitExceeded):
            ET.canonicalize(DOC, with_comments=True, max_depth=2)
        with self.assertRaises(ValueError):
            ET.canonicalize()

    def test_minidom_stdlib_signatures(self):
        text = DOC.decode()
        expected = xml.dom.minidom.parseString(DOC).toxml()
        self.assertEqual(minidom.parseString(DOC, None).toxml(), expected)
        self.assertEqual(minidom.parse(self.path, None).toxml(), expected)
        for ours, theirs in (
                (minidom.parseString(text, sax.make_parser()), xml.dom.minidom.parseString(text, xml.sax.make_parser())),
                (minidom.parse(self.path, None, 64), xml.dom.minidom.parse(self.path, None, 64)),
                (minidom.parse(io.BytesIO(DOC), sax.make_parser()),
                 xml.dom.minidom.parse(io.BytesIO(DOC), xml.sax.make_parser()))):
            self.assertEqual(ours.toxml(), theirs.toxml())
        with self.assertRaises(sx.EntitiesForbidden):
            minidom.parse(self.bomb, None, 64)
        with self.assertRaises(sx.LimitExceeded):
            minidom.parse(io.BytesIO(DOC), sax.make_parser(max_depth=2))
        with self.assertRaises(TypeError):
            minidom.parse(self.path, sax.make_parser(), namespaces=False)

    def test_minidom_pulldom_path_is_protected(self):
        def via_pulldom(data, **options):
            return minidom.parse(io.BytesIO(data), sax.make_parser(**options))
        for name, doc in payloads.ENTITY_ATTACKS.items():
            with self.subTest(doc=name), self.assertRaises(sx.EntitiesForbidden):
                via_pulldom(doc)
        with self.assertRaises(sx.ExternalReferenceForbidden):
            via_pulldom(payloads.XXE_FILE, forbid_entities=False)
        with self.assertRaises(sx.DTDForbidden):
            via_pulldom(payloads.DOCTYPE_ONLY, forbid_dtd=True)
        with self.assertRaises(sx.LimitExceeded):
            via_pulldom(b"<a>" * 501 + b"</a>" * 501)
        with self.assertRaises(sx.LimitExceeded):
            via_pulldom(DOC, max_bytes=100)
        self.assertEqual(via_pulldom(DOC).toxml(), xml.dom.minidom.parse(io.BytesIO(DOC), xml.sax.make_parser()).toxml())


class PullParserTests(unittest.TestCase):
    def test_pull_parser_matches_stdlib(self):
        for events in (None, ("start",), ("end", "start-ns", "end-ns"), ALL):
            for chunk in (1, 7, 4096):
                with self.subTest(events=events, chunk=chunk):
                    self.assertEqual(pull(ET, DOC, events, chunk), pull(StdET, DOC, events, chunk))

    def test_pull_parser_errors_match_stdlib(self):
        for doc in BAD_DOCS:
            for chunk in (1, 5, 4096):
                with self.subTest(doc=doc, chunk=chunk):
                    self.assertEqual(pull(ET, doc, ALL, chunk), pull(StdET, doc, ALL, chunk))

    def test_pull_parser_api(self):
        for module in (ET, StdET):
            with self.subTest(module=module.__name__):
                parser = module.XMLPullParser()
                parser.feed(b"")
                parser.feed(b"<r/>")
                parser.close()
                self.assertEqual([event for event, _ in parser.read_events()], ["end"])
                with self.assertRaises(ValueError):
                    parser.feed(b"<r/>")
                with self.assertRaises(ValueError):
                    module.XMLPullParser(("start", "bogus"))

    def test_pull_parser_options_and_refusals(self):
        parser = ET.XMLPullParser()
        parser.feed(payloads.XXE_FILE)
        with self.assertRaises(sx.EntitiesForbidden):
            list(parser.read_events())
        parser = ET.XMLPullParser(("start",), max_depth=3)
        parser.feed(b"<a><b><c><d>")  # the refusal is queued after the events before it, like a ParseError
        events = parser.read_events()
        self.assertEqual([elem.tag for _, elem in (next(events), next(events), next(events))], ["a", "b", "c"])
        with self.assertRaisesRegex(sx.LimitExceeded, "max_depth=3"):
            next(events)

    @unittest.skipUnless(hasattr(StdET.XMLPullParser, "flush"), "this Python's ElementTree has no flush()")
    def test_pull_parser_flush_matches_stdlib(self):
        def steps(module):
            parser = module.XMLPullParser(("start", "end"))
            out = []
            for step in (b"<doc", b">", None, b"<a", b"/", b">", None, b"</doc>"):
                if step is None:
                    parser.flush()
                else:
                    parser.feed(step)
                out.append([(event, elem.tag) for event, elem in parser.read_events()])
            parser.close()
            with self.assertRaises(ValueError):
                parser.flush()
            return out
        self.assertEqual(steps(ET), steps(StdET))


class IterparseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "bom.xml")
        with open(self.path, "wb") as f:
            f.write(DOC)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_stdlib_iterparse_accepts_the_safe_parser(self):
        for events in (None, ALL):
            with self.subTest(events=events):
                ours = StdET.iterparse(self.path, events, parser=ET.XMLParser())
                theirs = StdET.iterparse(self.path, events)
                self.assertEqual(summarize(ours), summarize(theirs))
                self.assertEqual(StdET.tostring(ours.root), StdET.tostring(theirs.root))
        with self.assertRaises(sx.EntitiesForbidden):
            list(StdET.iterparse(io.BytesIO(payloads.BILLION_LAUGHS), parser=ET.XMLParser()))

    def test_iterparse_with_a_safe_parser(self):
        ours = ET.iterparse(self.path, ALL, ET.XMLParser(max_depth=10))
        self.assertEqual(summarize(ours), summarize(StdET.iterparse(self.path, ALL)))
        with self.assertRaises(sx.LimitExceeded):
            list(ET.iterparse(self.path, parser=ET.XMLParser(max_depth=2)))

    def test_iterparse_opens_the_path_at_once(self):
        missing = os.path.join(self.tmp, "missing.xml")
        with self.assertRaises(FileNotFoundError):
            ET.iterparse(missing)
        with self.assertRaises(FileNotFoundError):
            StdET.iterparse(missing)

    def test_iterparse_accepts_a_generator_of_events(self):
        ours = ET.iterparse(self.path, (event for event in ("start", "end", "comment")))
        theirs = StdET.iterparse(self.path, (event for event in ("start", "end", "comment")))
        self.assertEqual(summarize(ours), summarize(theirs))
        with self.assertRaises(ValueError):
            ET.iterparse(self.path, (event for event in ("start", "bogus")))
        pull_parser = ET.XMLPullParser(event for event in ("start",))
        pull_parser.feed(b"<r><a/></r>")
        self.assertEqual([elem.tag for _, elem in pull_parser.read_events()], ["r", "a"])

    def test_iterparse_reports_events_before_an_error(self):
        for doc in BAD_DOCS:
            for events in (None, ALL):
                with self.subTest(doc=doc, events=events):
                    ours = collect(ET.iterparse(io.BytesIO(doc), events))
                    self.assertEqual(ours, collect(StdET.iterparse(io.BytesIO(doc), events)))
        self.assertEqual(collect(ET.iterparse(io.BytesIO(BAD_DOCS[0])))[:2], [("end", "a"), ("end", "b")])

    def test_iterparse_refusal_comes_after_earlier_events(self):
        doc = b"<r><a/>" + b"<b>" * 600
        events = collect(ET.iterparse(io.BytesIO(doc), ("start",)))
        self.assertEqual(len(events), 502)  # r, a, 499 <b> (depth 500), then the refusal
        self.assertEqual(events[:2], [("start", "r"), ("start", "a")])
        self.assertEqual(events[-1], ("LimitExceeded", "document nesting exceeds max_depth=500"))

    def test_iterparse_root_and_close(self):
        it = ET.iterparse(self.path)
        for _ in it:
            self.assertIsNone(it.root)
        self.assertTrue(it.root.tag.endswith("bom"))
        it = ET.iterparse(self.path)
        next(it)
        it.close()
        with self.assertRaises(StopIteration):
            next(it)


if __name__ == "__main__":
    unittest.main()
