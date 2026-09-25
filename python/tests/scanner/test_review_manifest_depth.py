"""Review follow-up: the manifest nesting limit is explicit and the same in
both engines and on every interpreter.

SC-MANIFEST-DEPTH used to come from json.loads hitting the interpreter's
recursion limit: near 995 levels on Python 3.10/3.11 and near 10,000 on
3.12/3.13, while the npm engine stops at 500. A package.json nested 700
deep was a CRITICAL finding (and a forced exit 1) in the npm engine and
parsed silently in Python, and one between ~1,000 and ~10,000 levels was a
finding on 3.11 and not on 3.12. load_manifest (package.json and
binding.gyp) now measures the depth first (json_depth_exceeds: brackets
outside JSON strings, linear) against MAX_MANIFEST_DEPTH = 500, the npm
engine's MAX_JSON_DEPTH, and both report the same message. The registry
still gives such a package its documented SUSPICIOUS verdict.
"""
import time
import unittest

from lazaret.scanner import core
from tests.registry._review_support import manifest, rules, scan_npm


def nested(depth):
    """A valid package.json whose deepest value sits `depth` levels down
    (the top-level object counts as one)."""
    return '{"name": "x", "a": ' + "[" * (depth - 1) + "]" * (depth - 1) + "}"


class DepthLimit(unittest.TestCase):
    def test_limit_is_500_with_one_message(self):
        self.assertEqual(core.MAX_MANIFEST_DEPTH, 500)
        self.assertEqual(core.MANIFEST_DEPTH_MSG,
                         "Manifest is too deeply nested to parse (more than 500 levels).")

    def test_500_parses_501_and_700_are_findings(self):
        data, issues = core.load_manifest("package.json", nested(500))
        self.assertEqual((data["name"], issues), ("x", []))
        for depth in (501, 700, 2_000, 12_000):
            with self.subTest(depth=depth):
                data, issues = core.load_manifest("package.json", nested(depth))
                self.assertIsNone(data)
                self.assertEqual([(i["rule"], i["sev"], i["line"], i["msg"]) for i in issues],
                                 [("SC-MANIFEST-DEPTH", "CRITICAL", 1, core.MANIFEST_DEPTH_MSG)])

    def test_nested_and_dependency_manifests_too(self):
        for path in ("sub/package.json", "node_modules/x/package.json"):
            with self.subTest(path=path):
                self.assertEqual([i["rule"] for i in core.scan_manifest(path, nested(700))],
                                 ["SC-MANIFEST-DEPTH"])

    def test_binding_gyp_shares_the_limit(self):
        self.assertEqual([i["rule"] for i in core.scan_gyp("binding.gyp", nested(700))],
                         ["SC-MANIFEST-DEPTH"])
        gyp = "# comment\n{'targets': [{'target_name': 'x', 'sources': ['a.cc']}]}\n"
        self.assertEqual(core.scan_gyp("binding.gyp", gyp), [])

    def test_brackets_inside_strings_do_not_count(self):
        text = manifest(description="[" * 1_000 + "{" * 1_000, note='\\"' + "[" * 800)
        data, issues = core.load_manifest("package.json", text)
        self.assertEqual(issues, [])
        self.assertEqual(data["description"], "[" * 1_000 + "{" * 1_000)

    def test_depth_wins_over_a_syntax_error_anywhere(self):
        # json.loads would stop at `x` first; the explicit check does not
        # depend on where the parser gives up (the npm engine agrees)
        text = '{"a": x, "b": ' + "[" * 700 + "]" * 700 + "}"
        self.assertEqual([i["rule"] for i in core.scan_manifest("package.json", text)],
                         ["SC-MANIFEST-DEPTH"])

    def test_json_depth_exceeds(self):
        f = core.json_depth_exceeds
        self.assertFalse(f("[" * 500))
        self.assertTrue(f("[" * 501))
        self.assertTrue(f("{" * 250 + "[" * 251))
        self.assertFalse(f('"' + "[" * 1_000))                 # unterminated string
        self.assertFalse(f('["\\\\", "' + "[" * 1_000 + '"]'))  # escaped backslash, then a string
        self.assertTrue(f('["\\\\"' + "[" * 600))                # the string ended at the quote
        self.assertFalse(f("[]" * 10_000))
        self.assertTrue(f("[" * 3, limit=2))

    def test_linear_time(self):
        for text in ("[]" * 1_000_000, '"\\"[' * 500_000, '"' + "\\\\" * 1_000_000,
                     "[" * 400 + "]" * 400 + "[{" * 500_000):
            start = time.monotonic()
            core.json_depth_exceeds(text)
            self.assertLess(time.monotonic() - start, 5.0)


class RegistryVerdict(unittest.TestCase):
    def test_too_deep_manifest_is_suspicious(self):
        res = scan_npm({"package.json": nested(700), "index.js": "module.exports = 1;\n"})
        self.assertIn("SC-MANIFEST-DEPTH", rules(res))
        self.assertEqual(res["verdict"], "SUSPICIOUS")

    def test_500_levels_is_just_a_manifest(self):
        res = scan_npm({"package.json": nested(500), "index.js": "module.exports = 1;\n"})
        self.assertNotIn("SC-MANIFEST-DEPTH", rules(res))
        self.assertEqual(res["verdict"], "OK")


if __name__ == "__main__":
    unittest.main()
