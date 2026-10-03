"""The engine's comment and string lexer (lex_comment_spans: the comment
spans, the string spans and the literal spans of a text, for Python,
JavaScript with and without JSX, SQL and plain text), held to its recorded
outputs (_snapshots.py) on a seeded stream of texts made of the pieces
that decide a lexer's state: quotes, escapes, prefixes, comment openers,
template holes, regex literals, JSX.
"""
import random
import unittest

from lazaret.scanner import _native
from tests.architecture import _snapshots

PIECES = ["'", "'", '"', '"', "`", "\\", "\\", "\n", "\n", "\r\n", "/", "/", "*", "#", "-", "--", "[", "]", "{", "}",
          "(", ")", "<", ">", "=", " ", " ", "a", "x", "1", "f", "r", "b", "rb", "f'", 'f"', "rf'", "'''", '"""',
          "${", "/*", "*/", "//", "/*!", "M!", "=>", "return ", "typeof ", ":", ",", ";", "!", "\t", "é",
          " ", "<div>", "</div>", "<a href=", "/>", "{x}", "\\n", "\\'", '\\"', "\\\\", "/[", "\\/", "]/",
          "/a/g", "N{", "{{", "}}", "\\{"]
LANGS = (("py", True), ("js", True), ("js", False), ("sql", True), (None, True))


def cases(seed=1113, count=12000):
    rnd = random.Random(seed)
    return ["".join(rnd.choice(PIECES) for _ in range(rnd.randint(1, 30))) for _ in range(count)]


def snapshot_sets():
    def calls():
        texts = cases()
        out = []
        for lang, jsx in LANGS:
            args = {"jsx": jsx, "strings": True, "literals": True}
            if lang is not None:
                args["lang"] = lang
            out.extend(("lex_comment_spans", args, t) for t in texts)
        return out
    return {"lexer": calls}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class LexerSnapshotTests(unittest.TestCase):
    def test_the_outputs_are_the_recorded_ones(self):
        answers = _snapshots.run(snapshot_sets()["lexer"]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, "lexer", answers)


if __name__ == "__main__":
    unittest.main()
