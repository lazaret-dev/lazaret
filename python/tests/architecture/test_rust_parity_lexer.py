"""Engine parity for the comment lexer (core._lex_comment_spans): the
native engine (crates/lazaret-engine/src/lexer.rs, whose literals are
matched by hand loops written for the lexer's patterns) against core, on
dense random text of what the lexer turns on — quotes of every kind and
length, backslashes at every place (the end of the text included), line
ends, comment openers and closers, regular-expression literals and their
classes, f-string prefixes and fields, JSX tags, template fields — read as
Python, JavaScript with and without JSX, SQL and a language it does not
know. Compared: the comment spans, the '…' / "…" spans and every literal's
span. Skipped where the native library is not built.
"""
import random
import threading
import unittest

from lazaret.scanner import _native, core

PIECES = ["'", "'", '"', '"', "`", "\\", "\\", "\n", "\n", "\r\n", "/", "/", "*", "#", "-", "--", "[", "]", "{", "}",
          "(", ")", "<", ">", "=", " ", " ", "a", "x", "1", "f", "r", "b", "rb", "f'", 'f"', "rf'", "'''", '"""',
          "${", "/*", "*/", "//", "/*!", "M!", "=>", "return ", "typeof ", ":", ",", ";", "!", "\t", "é",
          " ", "<div>", "</div>", "<a href=", "/>", "{x}", "\\n", "\\'", '\\"', "\\\\", "/[", "\\/", "]/",
          "/a/g", "N{", "{{", "}}", "\\{"]
LANGS = (("py", True), ("js", True), ("js", False), ("sql", True), (None, True))
CHUNK = 2000


def cases(seed=1113, count=12000):
    rnd = random.Random(seed)
    return ["".join(rnd.choice(PIECES) for _ in range(rnd.randint(1, 30))) for _ in range(count)]


def core_view(text, lang, jsx):
    strings, literals = [], []
    comments = core._lex_comment_spans(text, lang, strings, jsx, literals)
    return [[list(s) for s in comments], [list(s) for s in strings], [list(s) for s in literals]]


def native_views(texts, box):
    views = []
    try:
        for lang, jsx in LANGS:
            args = {"jsx": jsx, "strings": True, "literals": True}
            if lang is not None:
                args["lang"] = lang
            for i in range(0, len(texts), CHUNK):
                calls = [["lex_comment_spans", args, t] for t in texts[i:i + CHUNK]]
                for r in _native.call("batch", {"calls": calls, "threads": 2}):
                    ok = r.get("ok", r)
                    views.append([ok.get("comments"), ok.get("strings"), ok.get("literals")] if "comments" in ok else ok)
    except Exception as e:                            # reported by the test, not lost in the thread
        box["error"] = repr(e)
    box["views"] = views


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RustLexerParityTests(unittest.TestCase):
    maxDiff = None

    def test_every_text_lexes_the_same(self):
        texts = cases()
        box = {}
        worker = threading.Thread(target=native_views, args=(texts, box))
        worker.start()
        want = [core_view(t, lang, jsx) for lang, jsx in LANGS for t in texts]
        worker.join()
        self.assertIsNone(box.get("error"))
        got = box.get("views", [])
        self.assertEqual(len(got), len(want))
        found = []
        labels = [(lang, jsx, t) for lang, jsx in LANGS for t in texts]
        for (lang, jsx, t), a, b in zip(labels, want, got):
            if a != b:
                found.append((lang, jsx, t, a, b))
                if len(found) >= 5:
                    break
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
