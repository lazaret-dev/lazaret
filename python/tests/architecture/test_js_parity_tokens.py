"""The npm package's token matcher against core's pattern (V-2).

The provider token formats (S-TOKEN's, and the first pattern of secret
redaction) are core's `_TOKEN_PATTERN` and `_TOKEN_REDACT_PATTERN`, which the
engine runs from the rule pack. The npm package matches them with a
hand-written twin, `findSecretToken` (js/src/lib/redact.js: the S-TOKEN of
config files, and the redaction of every snippet line), in linear time and
without a regex; the dashboard keeps a copy of it
(test_review_dashboard_perf_regex). This holds the npm package's to core's
regex, match by match, in both modes, on texts built from the formats' pieces
(test_review_perf_regex's TOKEN_FRAGMENTS: every format and its near misses,
glued, cut and run together). Skipped without node.
"""
import json
import os
import random
import re
import shutil
import subprocess
import unittest

from lazaret.scanner import core
from tests import _support
from tests.scanner.test_review_perf_regex import TOKEN_FRAGMENTS

NODE = shutil.which("node")
REDACT_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "redact.js")
SPANS = r"""
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const { findSecretToken } = await import(pathToFileURL(process.argv[1]).href);
const spans = (s, redact) => {
  const out = [];
  let pos = 0, t;
  while ((t = findSecretToken(s, pos, { redact }))) { out.push([t.index, t.end]); pos = t.end; }
  return out;
};
const texts = JSON.parse(readFileSync(0, "utf8"));
process.stdout.write(JSON.stringify(texts.map((s) => [spans(s, false), spans(s, true)])));
"""


def texts(n=6000, seed=11):
    """Texts of one to 25 of the formats' pieces, and each format whole in a line of code."""
    rnd = random.Random(seed)
    out = ["".join(rnd.choice(TOKEN_FRAGMENTS) for _ in range(rnd.randint(1, 25))) for _ in range(n)]
    pieces = {"npm": "npm" + "_" + "a1B2" * 9, "anthropic": "sk-ant-" + "api03-" + "Ab1_-" * 18 + "Ab1" + "AA",
              "anthropic usr": "sk-ant-" + "usr-" + "1a2B3c4D5e6F" + "-" + "Gh7Ij8Kl9Mn0" * 6 + "Op1Q" + "-" + "Rs2Tu",
              "openai": "sk-" + "proj-" + "Ab1_-" * 14 + "Ab1_" + "T3Blbk" + "FJ" + "Cd2-_" * 14 + "Cd2-"}
    # each length at and around each format's limits, after and before each kind of neighbour
    run = "aB3_-"
    edges = ["npm" + "_" + "a1B2c3"[:1] * n for n in (35, 36, 37)]
    kinds = ("ab01", "abc01", "abcde01", "abcdef01", "abc1", "abc012", "usr", "usra", "ust", "usr01")  # S-TOKEN-USR
    edges += ["sk-ant-" + kind + "-" + (run * 41)[:n] for kind in kinds for n in (39, 40, 41, 199, 200, 201)]
    edges += ["sk-" + (run * 19)[:a] + "T3Blbk" + "FJ" + (run * 15)[:b] for a in (19, 20, 21, 89, 90, 91)
              for b in (19, 20, 21, 73, 74, 75)]
    edges += ["sk-" + "x" * 20 + ("T3Blbk" + "FJ") * 3 + "y" * n for n in (4, 12, 20, 66, 74, 82)]
    for e in edges:
        out += [e, f"={e}=", f"a{e}", f"_{e}", f"-{e}", f"{e}a", f"{e}_", f"{e}-", f" {e} {e}."]
    for tok in pieces.values():
        out += [f'key = "{tok}"', f"KEY={tok}\n", f"x{tok}", f"{tok}!", tok[:-1], tok + tok]
        # near each format's edges: cut short or run on, behind and before other pieces
        for _ in range(400):
            cut = tok[:rnd.randint(len(tok) - 140 if len(tok) > 140 else 4, len(tok))]
            more = "".join(rnd.choice("aZ9_-.") for _ in range(rnd.choice((0, 0, 1, 2, 30, 120))))
            out.append("".join(rnd.choice(TOKEN_FRAGMENTS) for _ in range(rnd.randint(0, 2))) + cut + more
                       + "".join(rnd.choice(TOKEN_FRAGMENTS) for _ in range(rnd.randint(0, 2))))
    return out


@unittest.skipUnless(NODE, "node is not installed")
class NpmTokenMatcherTests(unittest.TestCase):
    maxDiff = None

    def test_the_same_matches_as_cores_pattern(self):
        cases = texts()
        p = subprocess.run([NODE, "--input-type=module", "-e", SPANS, REDACT_JS], input=json.dumps(cases),
                           capture_output=True, encoding="utf-8", errors="replace", timeout=40)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        detect = re.compile(core._TOKEN_PATTERN.pattern)
        redact = re.compile(core._TOKEN_REDACT_PATTERN.pattern)
        for s, (d, r) in zip(cases, got):
            self.assertEqual(d, [list(m.span()) for m in detect.finditer(s)], repr(s))
            self.assertEqual(r, [list(m.span()) for m in redact.finditer(s)], repr(s))
        self.assertEqual(len(got), len(cases))


if __name__ == "__main__":
    unittest.main()
