"""XMLParser.flush() must release events Expat is holding back.

Review finding: flush() was a no-op, but Expat 2.6+ defers reparsing an
incomplete token until more input arrives, so events for data already fed
were withheld. flush() now works like the stdlib's: one parse with reparse
deferral turned off, then the previous setting is restored.
"""

import unittest
import xml.etree.ElementTree as StdET

from lazaret.safexml import ElementTree as ET


class Recorder:
    def __init__(self):
        self.calls = []

    def start(self, tag, attrib):
        self.calls.append(("start", tag))

    def end(self, tag):
        self.calls.append(("end", tag))

    def close(self):
        return self.calls


class HidesDeferralAPI:
    """A pyexpat parser as seen on a Python without the reparse-deferral API."""

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        if name in ("GetReparseDeferralEnabled", "SetReparseDeferralEnabled"):
            raise AttributeError(name)
        return getattr(self._real, name)


@unittest.skipUnless(hasattr(StdET.XMLParser(), "flush"), "this Python's ElementTree has no flush()")
class FlushTests(unittest.TestCase):
    def steps(self, module):
        recorder = Recorder()
        parser = module.XMLParser(target=recorder)
        seen = []
        for step in (b"<doc", b">", None, b"<a", b"/", b">", None, b"</doc>"):
            if step is None:
                parser.flush()
            else:
                parser.feed(step)
            seen.append(list(recorder.calls))
        seen.append(parser.close())
        return seen

    def test_flush_matches_stdlib(self):
        ours = self.steps(ET)
        self.assertEqual(ours, self.steps(StdET))
        expat = ET.XMLParser().parser
        if getattr(expat, "GetReparseDeferralEnabled", lambda: False)():  # Expat 2.6+: "<doc>" waits for flush()
            self.assertEqual(ours[1:3], [[], [("start", "doc")]])

    def test_flush_restores_deferral_setting(self):
        parser = ET.XMLParser()
        if not hasattr(parser.parser, "GetReparseDeferralEnabled"):
            self.skipTest("no reparse-deferral API")
        before = parser.parser.GetReparseDeferralEnabled()
        parser.feed(b"<doc>")
        parser.flush()
        self.assertEqual(parser.parser.GetReparseDeferralEnabled(), before)

    def test_flush_without_deferral_api(self):
        parser = ET.XMLParser()
        parser.feed(b"<doc>")
        real = parser.parser
        parser.parser = HidesDeferralAPI(real)
        parser.flush()
        parser.parser = real
        parser.feed(b"</doc>")
        self.assertEqual(parser.close().tag, "doc")

    def test_flush_reports_errors_like_stdlib(self):
        errors = []
        for module in (ET, StdET):
            parser = module.XMLParser()
            try:
                parser.feed(b"<doc x")
                parser.feed(b"=1>")  # an error Expat 2.6+ only reports on the next parse
                parser.flush()
                errors.append(None)
            except StdET.ParseError as exc:
                errors.append((exc.code, exc.position, str(exc)))
        self.assertEqual(errors[0], errors[1])
        self.assertIsNotNone(errors[0])


if __name__ == "__main__":
    unittest.main()
