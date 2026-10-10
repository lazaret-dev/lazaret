"""Review fix: rule patterns that backtracked quadratically inside ONE regex
call, where the 30 s per-file time budget (checked between lines and passes)
cannot interrupt them.

* B-EMPTY-CATCH `catch\\s*(\\([^()]*\\))?\\s*\\{\\s*\\}`: the two \\s* around the
  optional parameter list split a whitespace run every way ('catch' + 150,000
  newlines: 21.7 s);
* S-JWT-NONE `…[:=]\\s*\\[?\\s*["']none…`: the same with the optional '['
  ('algorithm=' + 60,000 spaces: 16.7 s);
* the dependency-mode decode flow's sink pattern (_DECODE_SINK_RE): its
  optional receiver had no left boundary, so every position inside a long
  identifier retried the rest of it ('a' * 20,000 after a decode: 4.8 s);
* S-TOKEN's JWT alternative `eyJ[…]{10,}\\.eyJ…`, also the first secret
  redaction pattern: on a run of "eyJeyJ…" every "eyJ" rescanned the run
  ('//' + 'eyJ' * 60,000: 21.2 s to scan, ~10 s more to redact it in any
  neighbouring finding's snippet). Those now run through core._TokenPattern,
  which must give exactly what the regex gives (a left boundary would have
  missed a JWT glued to the characters before it).

Each input below took 15-20 s before the fix and now takes well under a
second; the bound is loose on purpose (shared CI machines). The rewritten
patterns match exactly the same spans as the old ones (checked on a fixed
sample), except that a sink receiver can no longer start in the middle of an
identifier (`\u00e9cp.exec(` has the receiver `\u00e9cp`, not `cp`)."""

import random
import re
import time
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

PER_CASE_LIMIT = 8.0

CASES = {
    # 0.1.8: a blank run that no code follows (SC-OFFSCREEN-CODE's pattern starts only at a run's start),
    # a long name before the self-publishing needles, a long name before '.dll'
    "js 'x;' + 200,000 spaces (SC-OFFSCREEN-CODE)": ("x.js", "x;" + " " * 200000, "js", False),
    "py ')' + 200,000 spaces + code (SC-OFFSCREEN-CODE)": ("x.py", ")" + " " * 200000 + ";exec(1)", "py", False),
    "js self-publishing needles + 'a' x 200,000 (SC-SELF-PUBLISH)":
        ("x.js", "exec('npm publish'); w('package.json'); " + "a" * 200000 + ".nam = 1", "js", True),
    "js 'rundll32 ' + 'a' x 200,000 (install-script DLL test)":
        ("x.js", "rundll32 " + "a" * 200000 + ".dl", "js", True),
    "js 'catch' + 150,000 newlines (B-EMPTY-CATCH)":
        ("x.js", "try { f() } catch" + "\n" * 150000, "js", False),
    "py 'algorithm=' + 60,000 spaces (S-JWT-NONE)":
        ("x.py", "opts = dict(algorithm=" + " " * 60000, "py", False),
    "js 'algorithm:' + 60,000 spaces (S-JWT-NONE)":
        ("x.js", "opts = {algorithm:" + " " * 60000, "js", False),
    "js dependency: a decode, then 'a' * 40,000 (decode flow sink)":
        ("x.js", "const d = atob(x);\n" + "a" * 40000, "js", True),
    "py dependency: a decode, then 'a' * 40,000 (decode flow sink)":
        ("x.py", "d = base64.b64decode(x)\n" + "a" * 40000, "py", True),
    "js '//' + 'eyJ' * 60,000 (S-TOKEN)": ("x.js", "// " + "eyJ" * 60000, "js", False),
    "py 'eyJ' * 60,000 in a string (S-TOKEN)": ("x.py", "x = '" + "eyJ" * 60000 + "'\n", "py", False),
    "js dependency: 'eyJ' * 60,000 (S-TOKEN)": ("x.js", "// " + "eyJ" * 60000, "js", True),
    "js a finding next to 'eyJ' * 60,000 (snippet redaction)":
        ("x.js", "eval(x)\n// " + "eyJ" * 60000 + "\n", "js", False),
}

RULE = {r["id"]: r for r in core.RULES + core.TEXT_RULES}
OLD = {
    "B-EMPTY-CATCH": re.compile(r"catch\s*(\([^()]*\))?\s*\{\s*\}"),
    "S-JWT-NONE": re.compile(r"algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']", re.I),
}
FRAGMENTS = {
    "B-EMPTY-CATCH": ["catch", " ", "\n", "\t", "(", ")", "e", "{", "}", "x", "catch(", ") {", "\u2028", "\x0b"],
    "S-JWT-NONE": ["algorithm", "algorithms", "ALGORITHM", " ", "\n", ":", "=", "[", "]", "'", '"',
                   "none", "NONE", "x", "\u3000"],
}


class LinearPatternTests(unittest.TestCase):
    def test_each_case_is_fast(self):
        for label, (name, content, lang, dep) in CASES.items():
            with self.subTest(case=label):
                t = time.monotonic()
                issues = core.scan_file(name, content, lang, dep=dep)
                elapsed = time.monotonic() - t
                self.assertLess(elapsed, PER_CASE_LIMIT, f"{label}: {elapsed:.1f}s")
                self.assertNotIn("SC-TRUNCATED", {i["rule"] for i in issues})


class SameMatchesTests(unittest.TestCase):
    def test_rewritten_patterns_match_the_same_spans(self):
        rnd = random.Random(5)
        for rid, old in OLD.items():
            new = RULE[rid]["re"]
            samples = ["try { f() } catch (e) { }", "catch {}", "catch(e)\n{\n}", "catch ( a, b ) {\t}",
                       "catch (e) { log(e) }", "catch (f(x)) {}", "algorithms: ['none']",
                       'algorithm="none"', "algorithms = [ \"none\" ]", "ALGORITHMS:[\n'NONE']",
                       "algorithm = ['HS256']", "algorithm =  [  'none'"]
            samples += ["".join(rnd.choice(FRAGMENTS[rid]) for _ in range(rnd.randint(1, 12)))
                        for _ in range(20000)]
            for s in samples:
                self.assertEqual([m.span() for m in new.finditer(s)], [m.span() for m in old.finditer(s)],
                                 f"{rid}: {s!r}")

    def test_findings_unchanged(self):
        def rules(src, lang, dep=False):
            return [(i["rule"], i["line"]) for i in core.scan_file("x." + lang, src, lang, dep=dep)
                    if i["rule"] in ("B-EMPTY-CATCH", "S-JWT-NONE", "SC-EVAL-DECODE")]
        self.assertEqual(rules("try { f() } catch (e) {}\ntry { g() } catch\n{\n}\n", "js"),
                         [("B-EMPTY-CATCH", 1), ("B-EMPTY-CATCH", 2)])
        self.assertEqual(rules("jwt.verify(t, k, {algorithms: [ 'none' ]})\n", "js"), [("S-JWT-NONE", 1)])
        self.assertEqual(rules("jwt.decode(t, algorithms=['none'])\n", "py"), [("S-JWT-NONE", 1)])
        flow = ("const cp = require('child_process');\nconst d = atob(p);\n"
                "cp.exec(d);\nwindow.eval(d);\nre.exec(d);\n")
        self.assertEqual(rules(flow, "js", dep=True), [("SC-EVAL-DECODE", 3), ("SC-EVAL-DECODE", 4)])

    def test_sink_receiver_is_a_whole_identifier(self):
        # `\u00e9cp` is not the child_process alias `cp` (the old pattern took
        # the receiver `cp` from the middle of the identifier)
        issues = core.scan_file("x.js", "const cp = require('child_process');\nconst d = atob(p);\n"
                                "\u00e9cp.exec(d);\n", "js", dep=True)
        self.assertEqual([i["rule"] for i in issues], [])


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"        # {"alg":"HS256"}.{"sub":"1234567890"}
TOKEN_FRAGMENTS = ["AKIA", "AIza", "gh", "ghp_", "gho_", "github_pat_", "xox", "xoxb-", "sk_live_",
                   "-----BEGIN ", "-----END ", "PRIVATE KEY-----", "RSA ", "eyJ", ".", ".eyJ", "a", "B",
                   "0123456789", "ABCDEFGHIJKLMNOP", "_", "-", " ", "\n", "\u00e9", "Q" * 20, "a1B2" * 9,
                   # V-2's formats: npm's, Anthropic's (a kind, 40 more), OpenAI's (20, the marker, 20)
                   "cio", "npm_", "sk-", "sk-ant-", "api03-", "oat01-", "usr-", "proj-", "T3Blbk" + "FJ", "Ab1_-" * 8,
                   "x" * 20]


class TokenPatternTests(unittest.TestCase):
    """core._TokenPattern gives what its pattern text gives, as a regex."""

    def test_same_matches_as_the_regex(self):
        rnd = random.Random(7)
        samples = [JWT, "x" + JWT, "AKIA" + "Q" * 16 + JWT, "eyJ" * 40, "eyJ" * 5 + ".eyJ" + "a" * 10,
                   "eyJaaaaaaaaaaeyJbbbbbbbbbbb.eyJcccccccccc", "-----BEGIN RSA PRIVATE KEY-----x-----END RSA "
                   "PRIVATE KEY----- tail", "t = 'AKI\x41IOSFODNN7ABCDEFG' + 'ghp_" + "a1B2" * 9 + "'"]
        samples += ["".join(rnd.choice(TOKEN_FRAGMENTS) for _ in range(rnd.randint(1, 25))) for _ in range(20000)]
        for pat in (core._TOKEN_PATTERN, core._TOKEN_REDACT_PATTERN):
            ref = re.compile(pat.pattern)
            for s in samples:
                self.assertEqual([m.span() for m in pat.finditer(s)], [m.span() for m in ref.finditer(s)], repr(s))
                for pos in (0, len(s) // 3, len(s) // 2):
                    got, want = pat.search(s, pos), ref.search(s, pos)
                    self.assertEqual(got and (got.span(), got.group(0)), want and (want.span(), want.group(0)),
                                     (repr(s), pos))
                self.assertEqual(pat.sub(core.REDACTED, s), ref.sub(core.REDACTED, s), repr(s))

    def test_tables_keep_the_pattern_text(self):
        rule = next(r for r in core.RULES if r["id"] == "S-TOKEN")
        self.assertIs(rule["re"], core._TOKEN_PATTERN)
        self.assertIs(core._SECRET_LINE_PATTERNS[0], core._TOKEN_REDACT_PATTERN)
        self.assertTrue(rule["re"].pattern.endswith(r"|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}"))

    def test_a_glued_jwt_is_still_found_and_redacted(self):
        issues = core.scan_file("k.js", "const t = 'x" + JWT + "';\n", "js")
        self.assertEqual([(i["rule"], i["line"]) for i in issues], [("S-TOKEN", 1)])
        self.assertEqual(core._redact_context_line("k = 'AKIA" + "Q" * 16 + JWT + ".sig'"), "k = '[redacted][redacted].sig'")


if __name__ == "__main__":
    unittest.main()
