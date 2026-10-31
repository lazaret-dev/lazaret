"""The dashboard's size limit, and its render cap.

The page scans on the tab's thread, so it keeps the 2,000,000-byte limit the CLIs had before their default became
16,000,000 bytes (core.SOURCE_SIZE_CAP): a file over it is not read but gets the CLI's SC-TRUNCATED finding, which
fails the gate, and the CLI with that limit reports the same (the limit counts bytes: a paste's in UTF-8). The page
reads no more of an upload over the limit than the collection looks at (its first bytes: what it is, a program
under a source file's name). Its issue list renders 500 cards at a time (G19: 10k+ cards froze the tab).
Inert content.
"""

import unittest
from unittest import mock

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

PAGE_LIMIT = 2_000_000


def cli_result(files):
    with mock.patch.object(core, "SOURCE_SIZE_CAP", PAGE_LIMIT):
        return dash.cli_result(files)


def same(test, page, cli):
    test.assertNotIn("error", page, page.get("error"))
    test.assertEqual(dash.comparable(page, dash.PAGE_ONLY), dash.comparable(cli, dash.CLI_ONLY))


@dash.requires_node
class SizeLimitTests(unittest.TestCase):
    def test_the_limit_is_the_clis_with_the_pages_size(self):
        files = [("big.js", "x" * (PAGE_LIMIT + 1)), ("ok.js", "x" * PAGE_LIMIT), ("wide.py", "é" * 1_000_001)]
        page = dash.scan(files)
        same(self, page, cli_result(files))
        self.assertEqual(sorted((i["file"], i["rule"]) for i in page["issues"]),
                         [("big.js", "SC-TRUNCATED"), ("ok.js", "Q-LONGLINE"), ("wide.py", "SC-TRUNCATED")])
        (wide,) = [i for i in page["issues"] if i["file"] == "wide.py"]
        self.assertEqual(wide["msg"], "File not fully scanned: 2,000,002 bytes exceeds the 2,000,000-byte file limit.")
        self.assertFalse(page["pass"])

    def test_a_paste_counts_its_utf8_bytes(self):
        page = dash.scan(paste="é" * 1_000_001, lang="py")
        same(self, page, cli_result([("pasted-code.py", "é" * 1_000_001)]))
        self.assertEqual([i["rule"] for i in page["issues"]], ["SC-TRUNCATED"])

    def test_an_oversize_upload_is_read_only_as_far_as_its_head(self):
        """Uploads of which the page can read only the first 4,096 bytes (the harness fails a read of more): the
        result is the CLI's for the whole files."""
        size = PAGE_LIMIT + 100
        head = b"\x7fELF\x02\x01\x01" + bytes(4089)
        text = b"x = 1\n" * (size // 6 + 1)
        files = [("prog.py", head + bytes(size - len(head))), ("big.py", text[:size])]
        page = dash.scan([(rel, data[:4096], len(data)) for rel, data in files])
        same(self, page, cli_result(files))
        self.assertEqual(sorted((i["file"], i["rule"]) for i in page["issues"]),
                         [("big.py", "SC-TRUNCATED"), ("prog.py", "SC-BINARY"), ("prog.py", "SC-TRUNCATED")])
        # reading one whole fails here: it is not scanned, and the page says so
        (shown,) = dash.run([{"op": "upload", "files": [dash.upload("small.py", b"x = 1\n", size=100)]}])
        self.assertIn("could not be read", shown)
        self.assertIn("small.py", shown)

    def test_a_config_file_over_its_limit(self):
        files = [("settings.json", '{"a": "' + "x" * PAGE_LIMIT + '"}\n')]
        page = dash.scan(files)
        same(self, page, cli_result(files))
        self.assertEqual([i["rule"] for i in page["issues"]], ["Q-SKIPPED-CONFIG"])


@dash.requires_node
class RenderCapTests(unittest.TestCase):
    def test_the_issue_list_renders_500_cards_at_a_time(self):
        got = dash.run([dash.scan_request(paste="eval(x)\n" * 600, lang="py"),
                        {"op": "html", "id": "countNote"}, {"op": "html", "id": "issueList"},
                        {"op": "html", "id": "gateBadge"}])
        page, note, cards, gate = got
        self.assertEqual(len(page["issues"]), 600)                            # security findings: never capped
        self.assertEqual(note["text"], "600 of 600 issues shown — showing 1–500 (page 1/2; rendering capped at 500 "
                                       "to keep the tab responsive)")
        self.assertEqual(cards["html"].count('<div class="issue"'), 500)
        self.assertEqual(gate["text"], "Quality Gate: Failed")


if __name__ == "__main__":
    unittest.main()
