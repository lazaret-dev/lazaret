"""The browser dashboard (lazaret/web/lazaret.html) is fully self-contained and is what its sources make.

It loads nothing from the network, and its content-security policy forbids doing so, so pasting code into it
can't leak that code anywhere. Its CSP allows exactly its own script, by hash, and 'wasm-unsafe-eval', which lets
it compile the engine it carries: injected markup can't run code (no 'unsafe-inline', no inline event handlers).
The engine is a data block the page reads and never runs. scripts/make_dashboard.py builds the page (BR-7 step 5:
its script is the npm package's modules and js/dashboard/, its engine a build of the Rust engine), and the page
committed is what the script makes of the sources committed: the same script, notices and engine sources.
"""

import base64
import hashlib
import os
import re
import tempfile
import unittest
from unittest import mock

from tests import _support

HTML = os.path.join(_support.PKG, "web", "lazaret.html")
PAGE_JS = os.path.join(_support.REPO_ROOT, "js", "dashboard", "page.js")
BUILD = os.path.join(_support.REPO_ROOT, "scripts", "make_dashboard.py")
CDN_HOSTS = ["unpkg.com", "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
             "fonts.googleapis.com", "fonts.gstatic.com", "maxcdn.bootstrapcdn.com",
             "stackpath.bootstrapcdn.com", "cdn.tailwindcss.com", "esm.sh", "raw.githack.com"]

SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)


def csp_policy(html):
    match = re.search(r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=(["\'])(.*?)\1',
                      html, re.I | re.S)
    return match.group(2) if match else None


def script_hash(body):
    """CSP hash of an inline script: sha256 over its UTF-8 text after the HTML
    parser's newline normalization (so a CRLF checkout hashes the same)."""
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    return "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + "'"


_BUILD = []


def build():
    """scripts/make_dashboard.py, loaded once."""
    if not _BUILD:
        _BUILD.append(_support.load_script(BUILD, "make_dashboard"))
    return _BUILD[0]


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(HTML, encoding="utf-8", newline="") as f:
            cls.html = f.read()
        cls.scripts = SCRIPT_RE.findall(cls.html)
        cls.markup = SCRIPT_RE.sub("", cls.html)

    def test_no_external_subresources(self):
        external = re.findall(r"""<(?:script|link|img|iframe|source|audio|video)\b[^>]*\b(?:src|href)\s*=\s*["']?(?:https?:)?//""",
                              self.html, re.I)
        self.assertEqual(external, [])

    def test_no_cdn_hosts_or_web_fonts(self):
        self.assertEqual([h for h in CDN_HOSTS if h in self.html], [])
        self.assertNotRegex(self.html, r"@import\s+url\(\s*['\"]?https?:")

    def test_csp_forbids_external_sources(self):
        policy = csp_policy(self.html)
        self.assertIsNotNone(policy, "dashboard has no Content-Security-Policy")
        self.assertIn("default-src 'none'", policy)
        self.assertNotRegex(policy, r"https?:|\*")  # no remote origins, no wildcards
        # fetch/XHR/WebSocket: an absent connect-src falls back to default-src 'none'
        connect = re.search(r"connect-src([^;]*)", policy)
        self.assertTrue(connect is None or connect.group(1).strip() == "'none'", policy)

    def test_csp_allows_only_the_page_script_by_hash_and_the_engine(self):
        policy = csp_policy(self.html)
        run = [(attrs, body) for attrs, body in self.scripts if not re.search(r"\btype\s*=", attrs, re.I)]
        self.assertEqual(len(run), 1, "the dashboard has exactly one script")
        attrs, body = run[0]
        self.assertNotRegex(attrs, r"\bsrc\s*=")
        script_src = re.search(r"script-src([^;]*)", policy).group(1).split()
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertNotIn("'unsafe-eval'", script_src)
        self.assertEqual(script_src, [script_hash(body), "'wasm-unsafe-eval'"],
                         "the script changed but the CSP hash didn't: run python3 scripts/make_dashboard.py")
        # the same hash from a CRLF checkout (browsers normalize before hashing)
        self.assertEqual(script_hash(body.replace("\n", "\r\n")), script_hash(body))

    def test_the_engine_is_data_the_page_never_runs(self):
        data = [(attrs, body) for attrs, body in self.scripts if re.search(r"\btype\s*=", attrs, re.I)]
        self.assertEqual(len(data), 1)
        attrs, body = data[0]
        self.assertRegex(attrs, r'^ type="application/octet-stream" id="lazaret-engine" data-sha256="[0-9a-f]{64}" '
                                r'data-bytes="\d+" data-sources="[0-9a-f]{64}"$')
        self.assertRegex(body, r"^\n[A-Za-z0-9+/=\n]+\n$")                   # base64: nothing the parser reads
        # before the script, which reads it as the page opens
        self.assertLess(self.html.index('id="lazaret-engine"'), self.html.index("<script>"))
        gen = build()
        _attrs, values, text = gen.read_engine_block(self.html)
        wasm = gen.check_engine_block(values, text)
        self.assertEqual(wasm[:4], b"\0asm")

    def test_the_page_is_what_its_sources_make(self):
        self.assertEqual(build().main(["--check"]), 0,
                         "run python3 scripts/make_dashboard.py (and, when the engine's sources changed, build the "
                         "engine first: cd js && npm run build; then --engine)")

    def test_no_inline_event_handlers_or_javascript_urls(self):
        # CSP blocks both, so any would be a dead control (and a sign that 'unsafe-inline' is about to come back).
        # Checked in the markup and in the HTML the page's own module builds.
        with open(PAGE_JS, encoding="utf-8") as f:
            page_js = f.read()
        for where, text in (("markup", self.markup), ("js/dashboard/page.js", page_js)):
            with self.subTest(where):
                self.assertEqual(re.findall(r"<[a-zA-Z][^<>]*?\son[a-z]+\s*=", text), [])
                self.assertEqual(re.findall(r"\.setAttribute\(\s*[\"']on[a-z]+", text), [])
                self.assertNotRegex(text, r"(?i)javascript\s*:")


class BuildTests(unittest.TestCase):
    """What the page's build refuses: a module that uses Node or a loader, and a cycle."""

    def build_from(self, modules):
        gen = build()
        with tempfile.TemporaryDirectory() as d:
            for name, text in modules.items():
                with open(os.path.join(d, name), "w", encoding="utf-8") as f:
                    f.write(text)
            return gen.build_script(os.path.join(d, "entry.js"))

    def test_a_module_tree_becomes_one_script(self):
        script = self.build_from({
            "entry.js": 'import { twice, NAME as label } from "./lib.js";\nimport * as more from "./more.js";\n'
                        "console.log(label, twice(more.ONE));\n",
            "lib.js": 'export const NAME = "lib";\nexport function twice(n) { return 2 * n; }\n'
                      'export { ONE as UNIT } from "./more.js";\n',
            "more.js": "export const ONE = 1;\n"})
        self.assertTrue(script.startswith('"use strict";\n'))
        self.assertNotRegex(script, r"(?m)^(?:import|export)\b")
        self.assertLess(script.index("more.js ===="), script.index("lib.js ===="))
        self.assertLess(script.index("lib.js ===="), script.index("entry.js ===="))
        self.assertIn("return { UNIT: M$0.ONE, NAME, twice };", script)
        self.assertIn("const { twice, NAME: label } = M$1;", script)
        self.assertIn("const more = M$0;", script)

    def test_refused(self):
        gen = build()
        for name, modules in {
            "node": {"entry.js": 'import { readFileSync } from "node:fs";\n'},
            "a package": {"entry.js": 'import x from "left-pad";\n'},
            "a default import": {"entry.js": 'import x from "./lib.js";\n', "lib.js": "export const y = 1;\n"},
            "import.meta": {"entry.js": "const here = import.meta.url;\n"},
            "a dynamic import": {"entry.js": 'const m = await import("./lib.js");\n', "lib.js": ""},
            "export let": {"entry.js": "export let n = 1;\n"},
            "export default": {"entry.js": "export default 1;\n"},
            "a cycle": {"entry.js": 'import { a } from "./lib.js";\nexport const b = 1;\n',
                        "lib.js": 'import { b } from "./entry.js";\nexport const a = 1;\n'},
        }.items():
            with self.subTest(name), self.assertRaises(gen.BuildError):
                self.build_from(modules)

    def test_modules_on_another_drive_than_the_repository(self):
        # (Windows: the temporary folder may be on another drive than the checkout, and os.path.relpath has no answer
        # there: such a module is named by its whole path, and what the build refuses is still its BuildError)
        gen = build()
        drives = ValueError("path is on mount 'C:', start on mount 'D:'")
        with mock.patch.object(os.path, "relpath", side_effect=drives):
            script = self.build_from({"entry.js": 'import { ONE } from "./lib.js";\nconsole.log(ONE);\n',
                                      "lib.js": "export const ONE = 1;\n"})
            with self.assertRaisesRegex(gen.BuildError, "entry.js imports 'node:fs'"):
                self.build_from({"entry.js": 'import { readFileSync } from "node:fs";\n'})
        self.assertLess(script.index("/lib.js ======== */"), script.index("/entry.js ======== */"))


if __name__ == "__main__":
    unittest.main()
