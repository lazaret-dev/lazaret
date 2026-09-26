"""Review follow-up: terminal sanitizing is identical in both engines.

core.sanitize_term mapped only the C0 controls (except TAB/LF) and DEL to
'·'. The npm engine's sanitizeTerm also maps the C1 controls U+0080-U+009F
(0x9b is a one-byte CSI introducer on many terminals, 0x9d an OSC) and the
bidi controls U+202A-U+202E, U+2066-U+2069, so a hostile file name or
message could still drive a terminal through the Python CLI and the
registry/print paths. sanitize_term (and flow.py's local twin) now map the
same set, and safe_excerpt names the bidi controls explicitly as the JS
twin does. Where Node is installed, the two engines' sanitizers are
compared over every code point up to U+2FFF.
"""
import json
import os
import pathlib
import shutil
import subprocess
import unittest

from tests import _support

from lazaret.scanner import core
from lazaret.scanner import flow

C1 = [chr(n) for n in range(0x80, 0xA0)]
BIDI = [chr(n) for n in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))]
NODE = shutil.which("node")
REPORT_JS = os.path.join(_support.REPO_ROOT, "js", "src", "report.js")


class SanitizeTermC1Bidi(unittest.TestCase):
    def test_c1_controls_map(self):
        for ch in C1:
            self.assertEqual(core.sanitize_term("a" + ch + "b"), "a·b", hex(ord(ch)))
        # a C1 CSI clear-screen and an OSC title hijack
        self.assertEqual(core.sanitize_term("x\x9b2J\x9d0;PWNED\x9cy"), "x·2J·0;PWNED·y")

    def test_bidi_controls_map(self):
        for ch in BIDI:
            self.assertEqual(core.sanitize_term("a" + ch + "b"), "a·b", hex(ord(ch)))

    def test_neighbours_and_text_untouched(self):
        keep = "".join(chr(n) for n in (0xA0, 0xA9, 0xE9, 0x2029, 0x200F, 0x202F, 0x2065,
                                         0x206A, 0x4E2D)) + "a\nb\tc"
        self.assertEqual(core.sanitize_term(keep), keep)

    def test_flow_twin_is_identical(self):
        for n in range(0x3000):
            self.assertEqual(flow.sanitize_term(chr(n)), core.sanitize_term(chr(n)), hex(n))

    def test_safe_excerpt_maps_c1_and_bidi(self):
        rlo, lri = chr(0x202E), chr(0x2066)
        self.assertEqual(core.safe_excerpt(f'eval("\x9b31m") // {rlo} }} {lri}'),
                         'eval("·31m") // · } ·')
        self.assertEqual(core.safe_excerpt("a\xa0caf\xe9\x85b\x9b"), "a·caf\xe9·b·")


_NODE_SCRIPT = r"""
import { sanitizeTerm, safeExcerpt } from %s;
import { readFileSync } from "node:fs";
const cps = JSON.parse(readFileSync(0, "utf8"));   // stdin: 12k code points overflow a Windows command line
const out = { term: [], excerpt: [] };
for (const n of cps) {
  const s = "a" + String.fromCodePoint(n) + "b";
  out.term.push(sanitizeTerm(s));
  out.excerpt.push(safeExcerpt(s));
}
process.stdout.write(JSON.stringify(out));
"""


@unittest.skipUnless(NODE, "node is not installed")
class SameAsTheNpmEngine(unittest.TestCase):
    def _js(self, cps):
        url = pathlib.Path(REPORT_JS).resolve().as_uri()   # file:///C:/... on Windows
        p = subprocess.run([NODE, "--input-type=module", "-e", _NODE_SCRIPT % json.dumps(url)],
                           input=json.dumps(cps), capture_output=True, encoding="utf-8",
                           errors="replace", timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_sanitize_term_identical_up_to_u2fff(self):
        cps = [n for n in range(0x3000) if not 0xD800 <= n <= 0xDFFF]
        got = self._js(cps)["term"]
        for n, js in zip(cps, got):
            self.assertEqual(core.sanitize_term("a" + chr(n) + "b"), js, hex(n))

    def test_safe_excerpt_identical_on_controls(self):
        # the ranges that matter for terminal safety (the rest of safe_excerpt
        # follows each runtime's Unicode database for str.isprintable)
        cps = [*range(0x00, 0x100), *range(0x2000, 0x2070)]
        got = self._js(cps)["excerpt"]
        for n, js in zip(cps, got):
            self.assertEqual(core.safe_excerpt("a" + chr(n) + "b"), js, hex(n))


if __name__ == "__main__":
    unittest.main()
