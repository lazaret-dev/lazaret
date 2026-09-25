"""max_depth must count nesting for any ElementTree target.

Review finding: the safe XMLParser only installed its depth-counting
start/end handlers when the target had start() (and end()). A target with
start() but no end() never decremented, so a wide document such as <r> with
600 <a/> children was refused as too deep; a target with no start() got no
max_depth check at all.
"""

import unittest

import lazaret.safexml as sx
from lazaret.safexml import ElementTree as ET

WIDE = b"<r>" + b"<a/>" * 600 + b"</r>"
DEEP = b"<a>" * 600 + b"</a>" * 600


class StartOnly:
    def __init__(self):
        self.tags = []

    def start(self, tag, attrib):
        self.tags.append(tag)

    def close(self):
        return self.tags


class EndOnly:
    def __init__(self):
        self.tags = []

    def end(self, tag):
        self.tags.append(tag)

    def close(self):
        return self.tags


class DataOnly:
    def __init__(self):
        self.text = []

    def data(self, text):
        self.text.append(text)

    def close(self):
        return "".join(self.text)


def parse(target, doc, **options):
    parser = ET.XMLParser(target=target, **options)
    parser.feed(doc)
    return parser.close()


class TargetDepthTests(unittest.TestCase):
    def test_wide_document_with_start_only_target(self):
        self.assertEqual(len(parse(StartOnly(), WIDE)), 601)

    def test_deep_document_refused_whatever_the_target(self):
        for target in (StartOnly, EndOnly, DataOnly, object):
            with self.subTest(target=target.__name__):
                with self.assertRaisesRegex(sx.LimitExceeded, "max_depth=500"):
                    parse(target(), DEEP)
                parse(target(), DEEP, max_depth=None)
                parse(target(), WIDE, max_depth=2)

    def test_targets_receive_what_they_implement(self):
        self.assertEqual(parse(EndOnly(), b"<r><a/>x</r>"), ["a", "r"])
        self.assertEqual(parse(DataOnly(), b"<r><a/>x<b>y</b></r>"), "xy")


if __name__ == "__main__":
    unittest.main()
