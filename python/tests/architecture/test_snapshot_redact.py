"""The one redactor, held to its recorded outputs (_snapshots.py): the findings the packages still build, made and
redacted by the engine (rust/crates/lazaret-engine/src/redact.rs: the `issue_make`, `redact_text`, `pem_lines`,
`clip_line`, `redact_issues` and `redact_file` calls) on seeded corpora.

Until BR-7's step 3 c (0.1.9) both packages redacted those findings themselves (core.mk_issue, redact_result,
redact_file_issues and _redact_text with _SecretLiterals and _pem_block_lines; js/src/lib/issue.js and redact.js),
the npm package's token matcher held to core's pattern by test_js_parity_tokens. The engine took them over, as it
redacts the findings it makes; these sets were built for the move, and their hashes were recorded from the Python
the engine replaced, which answered every case alike.

The corpora: files put together from lines that hold provider tokens, password assignments, SQL credentials,
credentials in URLs, PEM private keys (whole, cut short, on one line), high-entropy literals and their reuse,
documentation words, long lines, non-ASCII text, lone surrogates and control characters; findings of secret rules
and others at every line of them (and past their ends), centred on columns or not, made with the file's entropy
literals and without, redacted and not (`issue_make`); results swept with snippets cut from them, some redacted
already, and a rule, line, message and command of every kind (`redact_issues`); the findings of a file built
outside its scan given the file's redaction (`redact_file`); and the helpers on their own: free text redacted with
a file's literals and without, a line by the patterns, a text's PEM blocks and a line clipped around a column.

All content is inert text: hosts are .invalid, every credential is made up and built in pieces
(test_fixture_credentials), and nothing is executed or contacted.
"""
import random
import unittest

from lazaret.scanner import _native, core
from tests.architecture import _snapshots

A36 = "a1B2" * 9
PIECES = [
    "AKI" + "AIOSFODNN7" + "ABCDEFG", "gh" + "p_" + A36, "github" + "_pat_" + "11ABCDEFG0" * 4, "xox" + "b-1234567890",
    "sk" + "_live_" + "a1" * 8, "AI" + "za" + "B" * 35, "npm" + "_" + A36,
    "ey" + "JhbGciOiJIUzI1NiJ9.ey" + "JzdWIiOiIxIn0.sig",
    "sk-" + "ant-" + "api03-" + "Ab1_-" * 18 + "Ab1" + "AA",
    "sk-" + "proj-" + "Ab1_-" * 14 + "Ab1_" + "T3Blbk" + "FJ" + "Cd2-_" * 14 + "Cd2-",
]
PASSES = ["hunter" + "22", "Zq8!" + "vN3pL0wX7r", "p@" + "ss w0rd"]
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
PEM_NAMES = ["RSA ", "EC ", "", "OPENSSH ", "ENCRYPTED "]
ODD = ["\u00e9", "\U0001F600", "\t", "\u2028", "\u00a0", "\ud800", "\udc00", "\x00", "\u2026", "\U000E01F0"]
SECRET_RULES = ["S-SECRET", "S-TOKEN", "SQL-CRED", "S-ENTROPY"]
OTHER_RULES = ["X-SQL", "SC-INSTALL-HOOK", "B-EMPTY-CATCH", "Q-ENCODING", "SC-AGENT-HIJACK"]


def literal(rnd, n=None):
    return "".join(rnd.choice(ALNUM) for _ in range(n or rnd.randint(18, 64)))


def line(rnd, lits):
    """One line of a file whose entropy literals are `lits`."""
    c = rnd.choice
    r = rnd.random()
    if r < 0.12:
        return f"{c(['key', 'token', 'x', 'SEED'])}{c(['=', ':', ' = '])}\"{c(lits)}\"{c(['', ';', ',', '  # n'])}"
    if r < 0.2:
        return f"use({c(lits)}) + {c(lits)}" if rnd.random() < 0.5 else f"f('{c(lits)[:rnd.randint(5, 30)]}')"
    if r < 0.32:
        return f"t = '{c(PIECES)}' {c(['', '+ x', c(PIECES)])}"
    if r < 0.4:
        quote = c(["\"", "'"])
        return (f"{c(['password', 'api_key', 'secret', 'pwd', 'PRIVATE-KEY', 'auth_token'])}"
                f"{c([' = ', '=', ': ', ' := ', ': &str = '])}{c(['', 'b', 'r'])}{quote}{c(PASSES)}{quote}")
    if r < 0.45:
        return f"create user u identified by '{c(PASSES)}'" if rnd.random() < 0.5 else f"PASSWORD = '{c(PASSES)}'"
    if r < 0.5:
        return f"u = '{c(['https', 'ftp', 'postgres'])}://{c(['bob', 'x'])}:{c(PASSES)}@host.invalid/x'"
    if r < 0.56:
        # (each choice made in the order it was, outside the f-string: Python 3.10 and 3.11 refuse a backslash there)
        lead = c(['k = "', '', '  '])
        pem = c(PEM_NAMES)
        tail = c(['', 'MIIE' + literal(rnd), '\\\\nMIIE' + literal(rnd) + '\\\\n-----END PRIVATE KEY-----'])
        return f"{lead}-----BEGIN {pem}PRIVATE KEY-----{tail}"
    if r < 0.6:
        pem = c(PEM_NAMES)
        return f"-----END {pem}PRIVATE KEY-----" + c(['', '";', ' tail'])
    if r < 0.65:
        return "x = " + "".join(c(["a", "b", " ", c(ODD), c(PIECES), "try{}catch(e){}", c(lits)])
                                for _ in range(rnd.randint(50, 700)))
    if r < 0.7:
        return f"os.environ['{c(lits)}'] # example placeholder {c(PIECES)}"
    if r < 0.75:
        return "".join(c(ODD + ["a", " "]) for _ in range(rnd.randint(0, 12)))
    if r < 0.8:
        return ""
    return c(["import os", "x = 1", "def f(a, b):", "    return a", "}", "os.system(cmd)", "eval(atob(p))",
              "MIIE" + literal(rnd, 60), "# comment " + literal(rnd, 10)])


def text_of(rnd, cr=True):
    lits = [literal(rnd) for _ in range(rnd.randint(1, 4))]
    lines = [line(rnd, lits) for _ in range(rnd.randint(0, 30))]
    if cr and rnd.random() < 0.1:
        lines = [x + "\r" for x in lines]
    return "\n".join(lines)


def rule(rnd):
    c = rnd.choice
    rid = c(SECRET_RULES + OTHER_RULES)
    msg = c(["m", f"Install hook runs {c(PIECES)}", f"cmd: {c(PASSES)} password = '{c(PASSES)}'",
             "a\n-----BEGIN RSA PRIVATE KEY-----\nMIIEab\nc", f"x {literal(rnd)} y", "", "\u00e9\U0001F600 m"])
    return {"id": rid, "name": "n " + rid, "type": c(["BUG", "VULN", "HOTSPOT"]), "sev": c(["MAJOR", "CRITICAL"]),
            "msg": msg, "why": "w", "fix": "f", "ref": "r"}


def make_calls(seed=20261017, count=1200):
    """issue_make: a file's findings, made and redacted."""
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        text = text_of(rnd)
        lines = text.split("\n")
        n = len(lines)
        items = []
        for _ in range(rnd.randint(1, 8)):
            ln = rnd.choice([0, 1, n, n + 1, n + 2, n + 3, rnd.randint(1, max(1, n))])
            flag = lines[ln - 1] if 0 < ln <= n else ""
            col = rnd.choice([None, None, 0, rnd.randint(0, len(flag) + 5), len(flag)])
            items.append([rule(rnd), ln, col])
        args = {"items": items, "redact": rnd.random() < 0.8, "context": rnd.random() < 0.5, "neumaier": False}
        out.append(("issue_make", args, text))
    return out


def sweep_calls(seed=20261018, count=1200):
    """redact_issues: a result swept; redact_file: a file's findings built outside its scan."""
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        text = text_of(rnd)
        lines = text.split("\n")
        rows = []
        for _ in range(rnd.randint(1, 6)):
            ln = rnd.randint(1, max(1, len(lines)))
            start = max(1, ln - rnd.randint(0, 3))
            snip = lines[start - 1:start - 1 + rnd.randint(0, 5)]
            if snip and rnd.random() < 0.3:
                k = rnd.randrange(len(snip))
                snip[k] = rnd.choice(["[redacted]", "[redacted: secret rule S-SECRET] (12 chars)", snip[k][:250]])
            if rnd.random() < 0.08:
                snip = snip + [None, 3]
            rows.append([rnd.choice(SECRET_RULES + OTHER_RULES + [None]), ln,
                         start if rnd.random() < 0.9 else None,
                         snip if rnd.random() < 0.95 else None,
                         rnd.choice([rule(rnd)["msg"], None]), rnd.choice([rule(rnd)["msg"], None, None])])
        out.append(("redact_issues", {"issues": rows, "redact": rnd.random() < 0.8}, ""))
    for _ in range(count):
        text = text_of(rnd, cr=False)
        lines = text.split("\n")
        rows = []
        for _ in range(rnd.randint(1, 6)):
            ln = rnd.randint(1, max(1, len(lines)))
            start = max(1, ln - 2)
            snip = lines[start - 1:start + 4]
            if snip and rnd.random() < 0.3:
                k = rnd.randrange(len(snip))
                snip[k] = rnd.choice(["[redacted]", snip[k][:240], snip[k] + " "])
            # the lines the snippet still shows raw, as the packages find them (core.redact_file_issues)
            at = [start - 1 + k for k, x in enumerate(snip) if x == lines[start - 1 + k]]
            if rnd.random() < 0.05:
                at.append(len(lines) + rnd.randrange(3))
            rows.append([at if rnd.random() < 0.95 else None,
                         rnd.choice([rule(rnd)["msg"], None]), rnd.choice([rule(rnd)["msg"], None, None])])
        out.append(("redact_file", {"issues": rows, "neumaier": False}, text))
    return out


def helper_calls(seed=20261019, count=1500):
    """The helpers: free text and a line redacted, a file's literals alone, its PEM blocks, a line clipped."""
    rnd = random.Random(seed)
    out = []
    for _ in range(count):
        text = text_of(rnd)
        context = text_of(rnd) if rnd.random() < 0.5 else text
        probe = rnd.choice(text.split("\n"))
        out += [("redact_text", {"mode": "text", "neumaier": False}, text),
                ("redact_text", {"mode": "text", "context": context, "neumaier": False}, rnd.choice([text, probe])),
                ("redact_text", {"mode": "line"}, probe),
                ("redact_text", {"mode": "literals", "context": context, "neumaier": False}, probe),
                ("pem_lines", {}, text),
                ("clip_line", {"col": rnd.choice([None, 0, 70, 300, len(probe), len(probe) + 9])}, probe),
                ("clip_line", {"col": rnd.choice([None, 0, 300, len(text)])}, text)]
    return out


def snapshot_sets():
    return {"redact_make": make_calls, "redact_sweep": sweep_calls, "redact_helpers": helper_calls}


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class RedactSnapshotTests(unittest.TestCase):
    def answers(self, name):
        answers = _snapshots.run(snapshot_sets()[name]())
        self.assertFalse([a for a in answers if "ok" not in a][:5])
        _snapshots.check(self, name, answers)
        return [a["ok"] for a in answers]

    def test_findings_made(self):
        calls = make_calls()
        got = self.answers("redact_make")
        issues = [(args, i) for (_c, args, _t), a in zip(calls, got) for i in a["issues"]]
        self.assertGreater(sum(1 for _a, i in issues if any("[redacted: secret rule " in s for s in i[9])), 600)
        self.assertGreater(sum(1 for _a, i in issues if any("[redacted]" in s for s in i[9])), 1100)
        self.assertGreater(sum(1 for _a, i in issues if any(s.startswith("\u2026") for s in i[9])), 50)
        # a redacted secret finding's flagged line is the placeholder, wherever its snippet shows it
        flagged = [(i[0], i[9][i[8] - i[10]]) for args, i in issues
                   if args["redact"] and i[0] in SECRET_RULES and 0 <= i[8] - i[10] < len(i[9])]
        self.assertGreater(len(flagged), 600)
        self.assertEqual([(r, s) for r, s in flagged if not s.startswith(f"[redacted: secret rule {r}] (")], [])

    def test_results_swept(self):
        calls = sweep_calls()
        got = self.answers("redact_sweep")
        swept = shown = 0
        for (c, args, text), a in zip(calls, got):
            lines = text.split("\n")
            for row, out in zip(args["issues"], a["issues"]):
                if c == "redact_issues":
                    swept += out[0] != row[3]
                else:
                    shown += sum(1 for j, line in zip(row[0] or [], out[0] or []) if line is not None and line != lines[j])
                    self.assertEqual(len(out[0] or []), len(row[0] or []))
        self.assertGreater(swept, 1700)
        self.assertGreater(shown, 8000)

    def test_helpers(self):
        calls = helper_calls()
        got = self.answers("redact_helpers")
        by = {}
        for (c, args, text), answer in zip(calls, got):
            by.setdefault((c, args.get("mode")), []).append((text, answer))
        self.assertGreater(sum(1 for t, a in by[("redact_text", "text")] if t != a), 1900)
        self.assertGreater(sum(1 for t, a in by[("redact_text", "line")] if t != a), 500)
        self.assertGreater(sum(1 for t, a in by[("redact_text", "literals")] if t != a), 90)
        self.assertGreater(sum(1 for _t, a in by[("pem_lines", None)] if a), 450)
        self.assertGreater(sum(1 for t, a in by[("clip_line", None)] if t != a), 1000)

    def test_the_package_wrappers(self):
        """core's wrappers hand the engine what it reads: mk_issues' findings are mk_issue's, the file's literals
        come with a _Redactor over the same lines only, and redact_result leaves an issue with no snippet alone."""
        lit = "Zq8vN3pL0wX7rT2mK9sB4hF6jD1xQ"
        lines = ["import os", f'SEED = "{lit}"', f"os.system('{lit}')"]
        r = {"id": "X-1", "name": "n", "type": "BUG", "sev": "MAJOR", "msg": f"runs {lit}", "why": "w", "fix": "f",
             "ref": "r"}
        red = core._Redactor(lines)
        one = core.mk_issue(r, "a.py", 3, lines, col=11, redactor=red)
        self.assertEqual(core.mk_issues("a.py", lines, [(r, 3, 11)], red), [one])
        self.assertEqual(one["snippet"], ["import os", 'SEED = "[redacted]"', "os.system('[redacted]')"])
        self.assertEqual(one["msg"], "runs [redacted]")
        self.assertEqual(list(one), ["rule", "name", "type", "sev", "msg", "why", "fix", "ref", "file", "line",
                                     "snippet", "snipStart"])
        other = core.mk_issue(r, "a.py", 3, lines, redactor=core._Redactor(list(lines)))
        self.assertIn(lit, other["snippet"][2])
        res = {"issues": [{"rule": "S-SECRET", "line": 1, "msg": "m"}, dict(one, snippet=["password = 'hunter22'"])]}
        core.redact_result(res)
        self.assertEqual(res["issues"][0], {"rule": "S-SECRET", "line": 1, "msg": "m"})
        self.assertEqual(res["issues"][1]["snippet"], ["[redacted]"])


if __name__ == "__main__":
    unittest.main()
