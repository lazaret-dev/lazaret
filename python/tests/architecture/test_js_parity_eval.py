"""Engine parity for decode-then-run through indirect eval (SC-EVAL-DECODE's
indirect sinks and the dependency decode flow's; the expectations are in
tests/scanner/test_review_indirect_eval.py and
js/test/review-indirect-eval.test.js). Both CLIs scan a tree of curated and
seeded random lines — as first-party files and, with --deps, as a
dependency's — and must report the same findings, metrics, gate and exit
code. All content is inert text. Skipped where the npm engine is not built (node, and npm run build in js/).
"""
import os
import random
import tempfile
import unittest

from tests.architecture import test_js_parity as parity
from tests.scanner import test_review_indirect_eval as indirect

PIECES = ["(", ")", "(", ")", "0", ",", ", ", " ", " ", "\t", "void ", "eval", "eval", "Function", "window.", "globalThis.",
          "self.", "x.", "module_1.", ".", ".call", ".apply", ".bind", "(null)", "null", "this", "[", "]", "'", '"', "`",
          " + ", "+", "e", "v", "a", "l", "ev", "al", "Func", "tion", "Reflect.apply(", "(0, eval)(", "eval.call(null, ",
          "eval.apply(this, [", "window['eval'](", "self[\"ev\" + \"al\"](", "[`Function`](", "d", "d)", "atob(p)",
          "Buffer.from(p, 'base64')", indirect.DECODE, ";", "\n", "// ", "/* ", " */", "=", "const e = ", "é", "\U0001F600"]


def corpus(seed=20260927, count=600):
    rnd = random.Random(seed)
    calls = indirect.IndirectEvalTests.CALLS
    cases = [call % indirect.DECODE for call in calls] + [call % "d" for call in calls]
    for _ in range(count):
        cases.append("".join(rnd.choice(PIECES) for _ in range(rnd.randint(1, 16))))
    return cases


@unittest.skipUnless(parity.NPM_READY, parity.NPM_SKIP)
class IndirectEvalParityTests(unittest.TestCase):
    maxDiff = None
    assert_same = parity.EngineParityTests.assert_same

    def test_the_engines_agree(self):
        with tempfile.TemporaryDirectory() as root:
            for n, text in enumerate(corpus()):
                flow = "const d = atob(p);\n" + text + "\n"
                for rel, body in ((f"src/c{n}.js", text + "\n"), (f"node_modules/p/c{n}.js", flow)):
                    path = os.path.join(root, *rel.split("/"))
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w", encoding="utf-8", newline="") as f:
                        f.write(body)
            js, py = parity.both(root, deps=True)
            self.assert_same(js, py, label="indirect eval")
            found = [(i["rule"], i["file"].replace("\\", "/").split("/")[0]) for i in js[1]["issues"]]
            self.assertGreater(found.count(("SC-EVAL-DECODE", "src")), 40, found.count(("SC-EVAL-DECODE", "src")))
            self.assertGreater(found.count(("SC-EVAL-DECODE", "node_modules")), 80,
                               found.count(("SC-EVAL-DECODE", "node_modules")))


if __name__ == "__main__":
    unittest.main()
