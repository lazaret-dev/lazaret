"""SafeXMLRPCParser must work when fed in small pieces.

Found while extending the attack harness: the stdlib ExpatParser.close()
deletes self._target before its final Parse(b"", True), and with Expat 2.6+
reparse deferral that final parse can still report the last end tags. The
safe parser's start/end handlers used self._target, so a response fed a few
bytes at a time failed with AttributeError in close().
"""

import unittest
import xmlrpc.client

from lazaret.safexml import xmlrpc as safe_xmlrpc

RESPONSE = xmlrpc.client.dumps(({"name": "requests", "versions": ["2.32.3"]},), methodresponse=True).encode()


class ChunkedFeedTests(unittest.TestCase):
    def test_small_chunks_parse_like_the_stdlib(self):
        expected = xmlrpc.client.loads(RESPONSE)
        for size in (1, 3, 7, 64, len(RESPONSE)):
            with self.subTest(size=size):
                unmarshaller = xmlrpc.client.Unmarshaller()
                parser = safe_xmlrpc.SafeXMLRPCParser(unmarshaller)
                for i in range(0, len(RESPONSE), size):
                    parser.feed(RESPONSE[i:i + size])
                parser.close()
                self.assertEqual((unmarshaller.close(), unmarshaller.getmethodname()), expected)


if __name__ == "__main__":
    unittest.main()
