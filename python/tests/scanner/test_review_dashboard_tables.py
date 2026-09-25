"""The dashboard's tables are the CLI's, field by field.

Before: the page's rule table had drifted from lazaret.scanner.core (no
S-BIDI, an older S-SECRET / SQL-CRED skip list, different S-EVAL-JS text,
JavaScript regex semantics for \\w/\\b/\\s, the quadratic SQL and except-pass
patterns) and nothing compared them. The page now compiles every pattern
from its Python text with Python `re` semantics (pyRe, which keeps the text
on the RegExp as .pySource); this test compares that text and every other
field with core: RULES / TEXT_RULES (id, name, type, sev, langs, pattern,
flags, skip, need, msg, why, fix, ref), the taint tables, the suppression
grammar, the entropy / secret-skip / obfuscation patterns, the redaction
pattern list (_SECRET_LINE_PATTERNS, FIX-SPEC 6) and the limits. The
redaction list's first entry runs through a linear-time matcher in the page;
test_token_redaction_matches checks it redacts exactly what core does."""

import json
import re
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

PAGE_TABLES = r"""(() => {
  const pat = (re) => re ? {src: re.pySource, i: re.flags.includes("i"), s: re.flags.includes("s"),
                             m: re.flags.includes("m")} : null;
  const rule = (r) => ({id: r.id, name: r.name, type: r.type, sev: r.sev, langs: r.langs, re: pat(r.re),
                        skip: pat(r.skip), need: pat(r.need), msg: r.msg, why: r.why, fix: r.fix, ref: r.ref});
  const map = (o, f) => Object.fromEntries(Object.entries(o).map(([k, v]) => [k, f(v)]));
  return {
    rules: RULES.map(rule), textRules: TEXT_RULES.map(rule),
    sources: map(TAINT_SOURCES, pat),
    sinks: map(TAINT_SINKS, (rows) => rows.map(([suf, re, cat, sev, cwe, fix]) => [suf, pat(re), cat, sev, cwe, fix])),
    assign: map(ASSIGN_RE, pat), fullSan: map(FULL_SAN, pat), partialSan: map(PARTIAL_SAN, (o) => map(o, pat)),
    stringLit: pat(STRING_LIT_RE), suppress: pat(SUPPRESS_RE), secretSkip: pat(SECRET_SKIP_RE),
    entropy: pat(ENTROPY_VALUE_RE), b64: pat(B64_BLOB_RE), obf: pat(OBF_IDENT_RE),
    hiddenDanger: pat(HIDDEN_TEXT_DANGER_RE), secretLines: SECRET_LINE_PATTERNS,
    secretRules: [...SECRET_RULES].sort(), placeholder: REDACT_PLACEHOLDER, redacted: REDACTED,
    neverCapped: NEVER_CAPPED_PREFIXES, unsuppressible: UNSUPPRESSIBLE_PREFIXES,
    commentLineRules: [...COMMENT_LINE_RULES].sort(), sevOrder: SEV_ORDER, types: TYPES,
    limits: {CAP_PER_RULE, SNIPPET_MAX, SNIPPET_LEAD, LONG_LINE, FN_LEN_LIMIT, FN_CX_LIMIT,
             FN_HEADER_SCAN_LIMIT, SC_JOIN_MAX_LINES, SC_JOIN_MAX_CHARS, SQL_CALLS_PER_LINE, SQL_ARG_MAX,
             MAX_FILE_BYTES, SCAN_TIME_BUDGET_MS},
  };
})()"""


def pat(rx):
    if rx is None:
        return None
    return {"src": rx.pattern, "i": bool(rx.flags & re.I), "s": bool(rx.flags & re.S), "m": bool(rx.flags & re.M)}


def rule(r):
    return {"id": r["id"], "name": r["name"], "type": r["type"], "sev": r["sev"], "langs": list(r["langs"]),
            "re": pat(r["re"]), "skip": pat(r["skip"]), "need": pat(r["need"]), "msg": r["msg"],
            "why": r["why"], "fix": r["fix"], "ref": r["ref"]}


@dash.requires_node
class DashboardTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (cls.page,) = dash.run([{"op": "eval", "expr": PAGE_TABLES}])

    def test_rule_tables(self):
        for key, table in (("rules", core.RULES), ("textRules", core.TEXT_RULES)):
            page = {r["id"]: r for r in self.page[key]}
            cli = {r["id"]: rule(r) for r in table}
            self.assertEqual(list(page), list(cli), f"{key}: rule ids / order")
            for rid in cli:
                with self.subTest(rule=rid):
                    self.assertEqual(page[rid], cli[rid])

    def test_taint_tables(self):
        self.assertEqual(self.page["sources"], {k: pat(v) for k, v in core.TAINT_SOURCES.items()})
        self.assertEqual(self.page["sinks"], {k: [[suf, pat(rx), cat, sev, cwe, fix] for suf, rx, cat, sev, cwe, fix in rows]
                                              for k, rows in core.TAINT_SINKS.items()})
        self.assertEqual(self.page["assign"], {k: pat(v) for k, v in core.ASSIGN_RE.items()})
        self.assertEqual(self.page["fullSan"], {k: pat(v) for k, v in core._FULL_SAN.items()})
        self.assertEqual(self.page["partialSan"],
                         {k: {s: pat(v) for s, v in d.items()} for k, d in core._PARTIAL_SAN.items()})
        self.assertEqual(self.page["stringLit"], pat(core.STRING_LIT_RE))

    def test_heuristic_and_suppression_patterns(self):
        for key, rx in (("suppress", core.SUPPRESS_RE), ("secretSkip", core.SECRET_SKIP_RE),
                        ("entropy", core.ENTROPY_VALUE_RE), ("b64", core.B64_BLOB_RE),
                        ("obf", core.OBF_IDENT_RE), ("hiddenDanger", core.HIDDEN_TEXT_DANGER_RE)):
            with self.subTest(pattern=key):
                self.assertEqual(self.page[key], pat(rx))
        self.assertEqual(self.page["unsuppressible"], list(core.UNSUPPRESSIBLE_PREFIXES))
        self.assertEqual(self.page["commentLineRules"], sorted(core._COMMENT_LINE_RULES))

    def test_redaction_patterns(self):
        self.assertEqual(self.page["secretLines"],
                         [[p.pattern, "i" if p.flags & re.I else ""] for p in core._SECRET_LINE_PATTERNS])
        self.assertEqual(self.page["secretRules"], sorted(core.SECRET_RULES))
        self.assertEqual((self.page["placeholder"], self.page["redacted"]), (core.REDACT_PLACEHOLDER, core.REDACTED))

    def test_limits_and_labels(self):
        self.assertEqual(self.page["limits"], {
            "CAP_PER_RULE": core.CAP_PER_RULE, "SNIPPET_MAX": core.SNIPPET_MAX, "SNIPPET_LEAD": core.SNIPPET_LEAD,
            "LONG_LINE": core.LONG_LINE, "FN_LEN_LIMIT": core.FN_LEN_LIMIT, "FN_CX_LIMIT": core.FN_CX_LIMIT,
            "FN_HEADER_SCAN_LIMIT": core.FN_HEADER_SCAN_LIMIT, "SC_JOIN_MAX_LINES": core.SC_JOIN_MAX_LINES,
            "SC_JOIN_MAX_CHARS": core.SC_JOIN_MAX_CHARS, "SQL_CALLS_PER_LINE": core.SQL_CALLS_PER_LINE,
            "SQL_ARG_MAX": core.SQL_ARG_MAX, "MAX_FILE_BYTES": core.SOURCE_SIZE_CAP,
            "SCAN_TIME_BUDGET_MS": int(core.SCAN_TIME_BUDGET * 1000)})
        self.assertEqual(self.page["neverCapped"], list(core._NEVER_CAPPED_PREFIXES))
        self.assertEqual(self.page["sevOrder"], core.SEV_ORDER)
        self.assertEqual(self.page["types"], core.TYPE_LABEL)

    def test_token_redaction_matches(self):
        """The page's linear token matcher redacts exactly what core's pattern does."""
        a36 = "a1B2" * 9
        lines = [
            "AKIAIOSFODNN7ABCDEFG", "AKIAIOSFODNN7ABCDEF", "xAKIAIOSFODNN7ABCDEFGH", "akiaIOSFODNN7ABCDEFG",
            "ghp_" + a36, "ghp_" + a36[:-1], "gho_" + a36 + "XYZ", "ghq_" + a36, "gh_" + a36,
            "github_pat_" + "A_b1" * 6, "github_pat_" + "A" * 21, "xoxb-1234567890", "xoxb-123456789", "xoxz-1234567890",
            "sk_live_" + "a1" * 8, "sk_live_" + "a" * 15, "AIza" + "B" * 35, "AIza" + "B" * 34, "AIza" + "B-_" * 13,
            "-----BEGIN RSA PRIVATE KEY-----", "x = '-----BEGIN PRIVATE KEY-----MIIE'  # tail",
            "-----BEGIN EC PRIVATE KEY-----abc-----END EC PRIVATE KEY----- after",
            "-----BEGIN OPENSSH PRIVATE KEY----- -----END RSA PRIVATE KEY-----x-----END RSA PRIVATE KEY-----",
            "-----BEGIN rsa PRIVATE KEY-----", "-----BEGIN  PRIVATE KEY----", "-----BEGIN PRIVATE KEY-----",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig", "eyJshort.eyJhbGciOiJIUzI1NiJ9",
            "eyJ" + "eyJ" * 40, "eyJ" * 5 + ".eyJ" + "a" * 10, "eyJaaaaaaaaaaeyJbbbbbbbbbbb.eyJcccccccccc",
            "t = 'AKIAIOSFODNN7ABCDEFG' + 'ghp_" + a36 + "' + 'xoxp-abcdefghijk'",
            "url = 'https://user:pa55w0rd@192.0.2.1/x'; password = 'hunter22'; IDENTIFIED BY 'x'",
            "api-key: \"abcd1234\" and secret='zz'", "PASSWORD='p' identified by password",
            "https://tok@host.invalid and ftp://a:b@c", "", "plain text, nothing secret",
            "éAKIAIOSFODNN7ABCDEFGé \U0001F600ghp_" + a36,
        ]
        (page,) = dash.run([{"op": "eval", "expr": f"{json.dumps(lines)}.map(redactContextLine)"}])
        for line, got in zip(lines, page):
            with self.subTest(line=line[:60]):
                self.assertEqual(got, core._redact_context_line(line))


if __name__ == "__main__":
    unittest.main()
