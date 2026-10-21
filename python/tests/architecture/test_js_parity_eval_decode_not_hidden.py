"""Engine parity for SC-EVAL-DECODE's matches that run nothing hidden (FP-PDFJS-DECODE; the expectations are in
tests/scanner/test_eval_decode_not_hidden.py and js/test/eval-decode-not-hidden.test.js): a RegExp's own exec and a
script the file writes, encoded on the way to a child process, beside what still counts. Both CLIs scan the shapes —
as first-party files and, with --deps, as a dependency's — and must report the same findings, metrics, gate and
exit code. All content is inert text. Skipped where the npm engine is not built (node, and npm run build in js/).
"""
import os
import tempfile
import unittest

from tests.architecture import test_js_parity as parity
from tests.scanner import test_eval_decode_not_hidden as shapes


def corpus():
    s = shapes
    out = [s.PDFJS_MIN, s.PDFJS, "module.exports = (s) => /x(\\d+)/.<exec>(<duc>(s));\n",
           "function f(s) {\n  const re = new RegExp('^a');\n  return re.<exec>(<atob>(s));\n}\n",
           "let r = /x/;\nr = require('<cp>');\nr.<exec>(<atob>('aWQ='));\n",
           "const re = /x/;\nfunction g(re) {\n  return re.<exec>(<atob>('aWQ='));\n}\ng(require('<cp>'));\n",
           "RegExp.prototype.<exec> = (s) => require('<cp>').execSync(s);\nconst re = /x/;\nre.<exec>(<atob>('aWQ='));\n",
           "function g(t){const i=/x/i;let a=i.<exec>(<duc>(t));return a}const c=require('<cp>');c.<exec>(<atob>('aWQ='));\n",
           "const re = /x/;\nconst m = re.<exec>(\n  <duc>(s));\n"]
    for script in (s.SCRIPT, s.PIPE, s.NPMRC):
        for where in ("top", "object", "function"):
            out.append(s.round_trip(script, where))
    lit = f"node -e \"<eval>(<from>('{s.B64}','base64').toString('utf8'))\""
    out += [s.RUN + f"execSync(`{lit}`);\n",
            s.RUN + f"const encodedScript = process.env.CHILD_SCRIPT;\nexecSync(`{s.NODE_E}`);\n",
            s.RUN + f"function run(encodedScript) {{\n  return execSync(`{s.NODE_E}`);\n}}\nmodule.exports = run;\n"]
    return [shapes.text(t) for t in out]


@unittest.skipUnless(parity.NPM_READY, parity.NPM_SKIP)
class NotHiddenParityTests(unittest.TestCase):
    maxDiff = None
    assert_same = parity.EngineParityTests.assert_same

    def test_the_engines_agree(self):
        with tempfile.TemporaryDirectory() as root:
            for n, body in enumerate(corpus()):
                for rel in (f"src/c{n}.js", f"node_modules/p/c{n}.js"):
                    path = os.path.join(root, *rel.split("/"))
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8", newline="") as f:
                        f.write(body)
            js, py = parity.both(root, deps=True)
            self.assert_same(js, py, label="not hidden")
            found = [(i["rule"], i["sev"]) for i in js[1]["issues"] if i["rule"] == "SC-EVAL-DECODE"]
            self.assertEqual(found.count(("SC-EVAL-DECODE", "INFO")), 4, found)          # the benign script, twice 3
            self.assertGreaterEqual(found.count(("SC-EVAL-DECODE", "CRITICAL")), 8, found)
            self.assertGreaterEqual(found.count(("SC-EVAL-DECODE", "BLOCKER")), 14, found)


@unittest.skipUnless(parity.NPM_READY, parity.NPM_SKIP)
class ExternalReviewParityTests(unittest.TestCase):
    maxDiff = None
    assert_same = parity.EngineParityTests.assert_same

def _review_parity(cases):
    def test(self):
        with tempfile.TemporaryDirectory() as root:
            for n, case in enumerate(cases):
                for rel in (f"src/c{n}.js", f"node_modules/p/c{n}.js"):
                    path = shapes.Path(root) / rel
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(shapes.review_source(case))
            js, py = parity.both(root, deps=True)
            self.assert_same(js, py, label="external review")
    return test
_regular = [c for c in shapes.REVIEW_CASES if "size" not in c]
for _start in range(0, len(_regular), 12):
    setattr(ExternalReviewParityTests, f"test_acceptance_{_start}", _review_parity(_regular[_start:_start+12]))
for _case in shapes.REVIEW_CASES:
    if "size" in _case:
        setattr(ExternalReviewParityTests, "test_" + _case["id"].replace("-", "_"), _review_parity([_case]))


if __name__ == "__main__":
    unittest.main()
