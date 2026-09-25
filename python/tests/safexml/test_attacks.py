"""The classic XML attacks, against every parsing API."""

import io
import time
import unittest
import xml.sax
import xml.sax.handler
from unittest import mock
from xml.sax.handler import ContentHandler

import lazaret.safexml as sx
from lazaret.safexml import ElementTree as ET
from lazaret.safexml import sax as safe_sax

from . import payloads
from ._harness import APIS, Canary


class EntityAttackTests(unittest.TestCase):
    def test_entity_declarations_refused_by_default(self):
        for api_name, api in APIS.items():
            for doc_name, doc in payloads.ENTITY_ATTACKS.items():
                with self.subTest(api=api_name, doc=doc_name):
                    with self.assertRaises(sx.EntitiesForbidden) as info:
                        api(doc)
                    self.assertIsInstance(info.exception, ValueError)

    def test_external_entity_refused_even_when_entities_allowed(self):
        for api_name, api in APIS.items():
            with self.subTest(api=api_name):
                with self.assertRaises(sx.ExternalReferenceForbidden) as info:
                    api(payloads.XXE_FILE, forbid_entities=False)
                self.assertEqual(info.exception.sysid, "file:///etc/passwd")

    def test_forbid_dtd(self):
        for api_name, api in APIS.items():
            with self.subTest(api=api_name):
                api(payloads.DOCTYPE_ONLY)  # allowed by default
                with self.assertRaises(sx.DTDForbidden) as info:
                    api(payloads.DOCTYPE_ONLY, forbid_dtd=True)
                self.assertEqual(info.exception.name, "r")

    @unittest.skipUnless(sx.EXPAT_HAS_AMPLIFICATION_LIMIT, "needs libexpat >= 2.4.1")
    def test_allowed_entities_are_still_bounded_by_expat(self):
        """With forbid_entities=False, libexpat's amplification limit stops the bomb."""
        for api_name, api in APIS.items():
            with self.subTest(api=api_name):
                start = time.monotonic()
                with self.assertRaises(Exception) as info:
                    api(payloads.BILLION_LAUGHS, forbid_entities=False)
                self.assertNotIsInstance(info.exception, sx.SafeXMLError)
                self.assertIn("amplification", str(info.exception))
                self.assertLess(time.monotonic() - start, 10)

    def test_harmless_internal_entity_when_allowed(self):
        self.assertEqual(ET.fromstring(payloads.INTERNAL_ENTITY, forbid_entities=False).text, "Lazaret")

    def test_entities_need_expat_protection(self):
        with mock.patch.object(sx._common, "EXPAT_HAS_AMPLIFICATION_LIMIT", False):
            with self.assertRaises(sx.NotSupportedError):
                sx.Options(forbid_entities=False)
            sx.Options()  # the default (entities forbidden) is always available


class NothingIsFetchedTests(unittest.TestCase):
    """A local canary server must receive zero requests, for every API, every
    external-reference document, and every combination of options."""

    OPTIONS = {
        "defaults": {},
        "entities-allowed": {"forbid_entities": False},
        "external-allowed": {"forbid_external": False},
        "both-allowed": {"forbid_entities": False, "forbid_external": False},
    }

    @classmethod
    def setUpClass(cls):
        cls.canary = Canary()

    @classmethod
    def tearDownClass(cls):
        cls.canary.close()

    def setUp(self):
        self.canary.reset()

    def test_nothing_is_ever_fetched(self):
        docs = payloads.external_reference_docs(self.canary.url)
        for api_name, api in APIS.items():
            for doc_name, doc in docs.items():
                for opt_name, options in self.OPTIONS.items():
                    with self.subTest(api=api_name, doc=doc_name, options=opt_name):
                        try:
                            result = api(doc, **options)
                        except Exception:
                            result = None
                        self.assertEqual(self.canary.hits, [])
                        self.assertNotIn("SECRET", repr(result))

    def test_harness_detects_fetching(self):
        """Control: the plain stdlib SAX parser with external entities enabled
        does fetch. If this fails, the canary test above proves nothing."""
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        parser.setContentHandler(ContentHandler())
        parser.parse(io.BytesIO(payloads.external_reference_docs(self.canary.url)["external-entity"]))
        self.assertEqual(self.canary.hits, ["/secret"])

    def test_sax_external_feature_cannot_override_forbid_external(self):
        parser = safe_sax.make_parser(forbid_entities=False)
        parser.setFeature(xml.sax.handler.feature_external_ges, True)
        parser.setContentHandler(ContentHandler())
        with self.assertRaises(sx.ExternalReferenceForbidden):
            parser.parse(io.BytesIO(payloads.external_reference_docs(self.canary.url)["external-entity"]))
        self.assertEqual(self.canary.hits, [])

    def test_every_api_is_covered(self):
        self.assertEqual(len(APIS), 16)


if __name__ == "__main__":
    unittest.main()
