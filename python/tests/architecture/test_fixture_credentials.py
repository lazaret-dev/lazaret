"""No file of the repository writes a provider's credential format whole (FIXTURE-PIECES).

A test or a script that needs a made-up credential writes it with one character escaped (`\\x41` for an `A`) or in
pieces, so that the string keeps its value while no line of the source holds the format. GitHub's push protection,
the secret scanners that read a public repository and Lazaret's own rules read the source, not the values: on Oct 9
GitHub refused a push of the 0.1.9 line for made-up AWS and Stripe keys written whole in two test files.

pratique's sources (rust/crates/pratique) are upstream's, synced byte for byte, and are not read here."""

import os
import re
import unittest

from tests import _support

#: (what it is, the pattern of its format as the scanners read it)
FORMATS = (
    ("an AWS access key id", r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    ("a Slack token", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    ("a GitHub token", r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,}"),
    ("a Stripe key", r"[sr]k_live_[0-9A-Za-z]{10,}"),
    ("an npm token", r"(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"),
    ("an Anthropic key", r"sk-ant-(?:[a-z]{3,5}[0-9]{2}|usr)-[A-Za-z0-9_\-]{40,}"),
    ("an OpenAI key", r"sk-[A-Za-z0-9_\-]{20,90}T3BlbkFJ[A-Za-z0-9_\-]{20,74}"),
    ("a Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("AWS's example secret key", r"wJalrXUtnFEMI[A-Za-z0-9/+]{27}"),
)
_ANY = re.compile("|".join(f"(?P<f{k}>{rx})" for k, (_, rx) in enumerate(FORMATS)))
SKIP_DIRS = {".git", "node_modules", "target", "__pycache__"}
VENDORED = ("rust/crates/pratique/",)


def _texts():
    """(path from the repository's root, text) of every text file of the repository, pratique's aside."""
    root = _support.REPO_ROOT
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if rel.startswith(VENDORED) or os.path.islink(path):
                continue
            with open(path, "rb") as fh:
                data = fh.read()
            if b"\0" in data[:8192]:
                continue
            try:
                yield rel, data.decode("utf-8")
            except UnicodeDecodeError:
                continue


def found_in(text):
    """[(line, what)] for each credential format written whole in `text`."""
    return [(text.count("\n", 0, m.start()) + 1, FORMATS[int(m.lastgroup[1:])][0]) for m in _ANY.finditer(text)]


class FixtureCredentialsTests(unittest.TestCase):
    def test_no_file_writes_a_credential_format_whole(self):
        found = [f"{rel}:{line}: {what}" for rel, text in _texts() for line, what in found_in(text)]
        self.assertEqual(found, [], "write each made-up credential in pieces, or with one character escaped (\\x41 for "
                                    "an A), so that no line holds the format: " + "; ".join(found[:20]))

    def test_each_format_is_caught_written_whole_and_not_with_a_character_escaped(self):
        # a check that cannot fail checks nothing: each format, built here so that this file holds none
        whole = {
            "an AWS access key id": "AKI" + "A" + "QWERTYUIOPASDFGH",
            "a Slack token": "xox" + "b-" + "1234567890-abcdefghij",
            "a GitHub token": "gh" + "p_" + "a1B2" * 9,
            "a Stripe key": "sk_" + "live_" + "a1" * 12,
            "an npm token": "np" + "m_" + "A1b2" * 9,
            "an Anthropic key": "sk-" + "ant-api03-" + "a1B2" * 12,
            "an OpenAI key": "sk-" + "proj-" + "a1B2" * 5 + "T3Blbk" + "FJ" + "a1B2" * 5,
            "a Google API key": "AI" + "za" + "a1B2c3D4e5" * 3 + "a1B2c",
            "AWS's example secret key": "wJalr" + "XUtnFEMI" + "/K7MDENG/bPxRfiCY" + "EXAMPLEKEY",
        }
        self.assertEqual(sorted(whole), sorted(what for what, _ in FORMATS))
        for what, value in whole.items():
            with self.subTest(what):
                self.assertEqual(found_in(f'x = "{value}"\n'), [(1, what)])
                escaped = value[:3] + "\\x%02x" % ord(value[3]) + value[4:]
                self.assertEqual(found_in(f'x = "{escaped}"\n'), [])


if __name__ == "__main__":
    unittest.main()
