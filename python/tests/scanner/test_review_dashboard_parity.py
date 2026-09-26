"""Dashboard <-> CLI parity: the same input gives the same findings.

The dashboard (lazaret/web/lazaret.html) carries its own copy of the scan
engine — a port of the npm engine, which tests/architecture/test_js_parity.py
keeps in step with the Python engine — and it drifted from the CLI
unnoticed before (per-file budget, no size limit, no review fixes). This runs
the page's script in node:vm (_dashboard_vm.py) and lazaret.scanner.core on
the same inputs and compares EVERY field of every finding (rule, line,
severity, type, name, message, why/fix/ref, snippet, snipStart):

* every fixture source file (walked, so a new fixture is compared without
  being listed) and the page's own "Load sample" inputs;
* ADVERSARIAL text inputs for the review fixes (FIX-SPEC 1 comment lexer,
  2 suppression markers, 5 Unicode and S-BIDI, 6 redaction, 7 caps and
  snippets, 12 taint idioms, 13 multi-line decode->execute, the linear
  rewrites of the quadratic SQL / except-pass / function-header patterns,
  the obfuscation heuristics);
* UPLOADS: raw bytes through the page's upload path (FIX-SPEC 4 BOM / UTF-16
  sniff with the plausibility check for a BOM-less guess, 15 PEP 263
  cookies incl. UTF-7 -> SC-UTF7) against core.decode_source +
  encoding_issues + scan_file;
* the report for a set of files (metrics, counts, ratings, gate) against
  core.build_result.

Out of scope: what the page doesn't do (manifests, binaries, directory
walking, dependency mode, the cross-file flow engine). One known difference:
a cookie naming a codec the browser's TextDecoder lacks (EBCDIC cp037, …)
is decoded as UTF-8 by the page (as by the npm engine), so only its
Q-ENCODING note is compared (test_undecodable_codec_is_still_reported).
All content is inert: nothing is executed, hosts are TEST-NET or .invalid,
credentials are dummies.
"""

import base64
import collections
import json
import os
import tempfile
import unittest

from lazaret.scanner import core
from tests import _support
from tests.scanner import _dashboard_vm as dash

LANGS = {".py": "py", ".js": "js", ".sql": "sql"}


def fixture_files():
    """Every .py / .js / .sql file under tests/fixtures, as posix paths."""
    out = []
    for root, dirs, files in os.walk(_support.FIXTURES):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(files):
            if os.path.splitext(name)[1] in LANGS:
                out.append(os.path.relpath(os.path.join(root, name), _support.FIXTURES).replace(os.sep, "/"))
    return out


def read_fixture(rel):
    with open(os.path.join(_support.FIXTURES, *rel.split("/")), encoding="utf-8") as f:
        return f.read()


# The page's own "Load sample" inputs: (page constant, file name, language).
SAMPLES = [("SAMPLE_PY", "sample.py", "py"), ("SAMPLE_JS", "sample.js", "js"),
           ("SAMPLE_SQL", "sample.sql", "sql")]

PEM_LINE = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n"

# (file name, language, content) — text as pasted.
ADVERSARIAL = [
    # FIX-SPEC 1: comment state across lines; U+2028/U+2029 end JS lines
    ("blockcomment.js", "js", "/*\n eval(x)\n*/\n/**/eval(y)\n"),
    ("comments.js", "js", "/* start\n * eval(a)\n */ eval(b)\n  * eval(c)\nconst r = /\\/*/; eval(d)\n"
     "x = a / b; eval(e) // ok */\nvar q = /[/*]/;\neval(f)\n// */\n"),
    ("template.js", "js", "const q = `${a}\n/* not a comment */ eval(x)\n`;\neval(y)\n"),
    ("banner.js", "js", '/*! lib v1 | MIT */!function(){var k="A";eval(atob("Y29uc29sZS5sb2coMSk="));'
     'require("child_process").exec(process.argv[2]);}();\n'),
    ("separators.js", "js", "a = 1\u2029eval(b)\u2028// c\n// note\u2028eval(atob(p))\n"),
    ("separators.py", "py", "a = 1\u2028eval(b)\n"),
    ("comments.sql", "sql", "SELECT '-- nosec' FROM t; GRANT ALL ON x TO y;\n/* multi\nGRANT ALL ON z TO PUBLIC; */\n"
     "SELECT \"a\n-- b\" FROM t;\n/* x */ GRANT ALL ON db.* TO PUBLIC;\n"),
    ("comments.py", "py", 'HELP = """Usage:\n# not a comment"""\nx = 1  # trailing\n  # full\ns = "#"; eval(s)\n'),
    ("untokenizable.py", "py", 'def f(:\n    HELP = """\n# in string\neval(x)\n"""\n  # real\n'),
    # FIX-SPEC 2: suppression markers
    ("suppressed.py", "py", "import os\nos.system(cmd)  # nosec - reviewed\n"),
    ("tricks.js", "js", "eval(atob(p)); // nosec\neval(y); const s = '// nosec';\n-- nosec\neval(z)\n"
     "eval(w); // lazaret-ignore: S-NEWFUNC, S-EVAL-JS\n/**/eval(v)\n// c\u2028eval(u)\n"
     "const t = `\n// nosec\n`; eval(t)\neval(r) // NOSONAR: reason\n"),
    ("tricks.py", "py", 'x = "# nosec"; eval(y)\ns = """\n# nosec\n"""\neval(z)\neval(w)  # nosec - reviewed\n'
     "os.system(a) --nosec\nos.system(b)  # lazaret-ignore: S-OSCMD-PY\nos.system(c)  # lazaret-ignore: S-EVAL-PY\n"
     "# nosec: S-OSCMD-PY, T-CMD\nos.system(d)\nexec(compile(s))  # nosec\n"),
    ("tricks.sql", "sql", "-- nosec\nGRANT ALL ON t TO PUBLIC;\nGRANT SELECT ON t TO PUBLIC;\n"
     "SELECT '-- nosec'; GRANT ALL ON u TO v;\n"),
    ("crlf.py", "py", "eval(a)  # nosec\r\neval(b)\r\n# nosec\r\neval(c)\r\n"),
    ("cr.js", "js", "eval(a) // NOSONAR\reval(b)\r"),
    # FIX-SPEC 5 and 12: Unicode, S-BIDI, taint idioms
    ("bidi.js", "js", 'const s = "\u202e";\nconst ok = 1; // \u202e } \u2066\n'),
    ("bidi.py", "py", "s = '\u2067'\n# \u202a\n"),
    ("bidi.sql", "sql", "SELECT 1; -- \u2069\n"),
    ("unicode.py", "py", "caf\u00e9 = request.args['x']\nos.system(caf\u00e9)\nx: str = request.args['q']\nos.system(x)\n"
     "\uff45val(n)\nimport os\nos.\uff53ystem(y)\n"),
    ("unicode.js", "js", "const na\u00efve = req.query.q;\nexec(na\u00efve);\nconst { a, b: c } = req.query;\nexec(c);\n"
     "\\u0065val(x)\neval\ufeff(y)\nconst [d, , e = 1, ...f] = req.body;\nexec(f);\n\\u{65}val(z)\n'\\u0065val(s)'\n"),
    ("annotated.py", "py", "match: int = request.args['m']\ncase = 1\n_ : str = input()\nos.system(_)\n"
     "if x: y = request.form['a']\nos.system(y)\nos.system(match)\n"),
    ("emoji.js", "js", "const s = '" + "\U0001F600" * 150 + "'; eval(x)\n"),
    # FIX-SPEC 7: caps (Q-CAPPED at the first omitted line) and snippets
    ("capped.js", "js", "".join(f"var a{n} = 1;\n" for n in range(250))),
    ("many.js", "js", "// TODO x\n" * 500 + "console.log(a)\n" * 250 + "eval(a)\n" * 600
     + 'Function(Buffer.from(p,"base64").toString())()\n'),
    ("interleaved.py", "py", "".join(f"x{n} = 1  # TODO {n}\n" for n in range(210)) + "import xml.etree\n" * 3),
    ("long.js", "js", "x = 1; " * 700 + "eval(q);" + " y = 2;" * 700 + "\n" + "z" * 300 + "\n"),
    ("functions.js", "js", "".join("function f%d(a) {\n%s}\n" % (n, "  if (a) { b(); }\n" * 14) for n in range(3))
     + "const g = async (x) => {\n" + "  x && y || z;\n" * 70 + "};\n"),
    ("functions.py", "py", "def outer():\n" + "    if x and y or z:\n        pass\n" * 40
     + "    def inner():\n        return 1\n" + "    x = 1\n" * 30 + "async def h():\n    try:\n        a()\n    except:\n        pass\n"),
    # FIX-SPEC 6: redaction of every snippet line and the message
    ("keys.py", "py", 'token = "gho_' + "a1B2" * 9 + '"\napi_key = "Zq8vN3pL0wX7rT2mK9sB"  # example_user\n'
     'tok = "Zq8vN3pL0wX7rT2mK9sB4hF6"  # latest\nu = "https://admin:s3cretPassw0rd@192.0.2.10/db"\neval(u)\n'),
    ("creds.sql", "sql", "create user bob identified by 'hunter2hunter2';\nGRANT ALL ON t TO PUBLIC;\n"
     "alter user x password = 'abcd1234';\nGRANT SELECT ON t TO PUBLIC;\n"),
    ("markup.jsx", "js", '<Input password="hunter2hunter2" />\neval(x)\n'),
    ("pem.py", "py", 'K = """-----BEGIN RSA PRIVATE KEY-----\n' + PEM_LINE * 3 + '-----END RSA PRIVATE KEY-----"""\n'
     'eval(x)\nH = "-----BEGIN OPENSSH PRIVATE KEY-----"\neval(y)\n'),
    ("pem.js", "js", 'k = "-----BEGIN EC PRIVATE KEY-----' + PEM_LINE.strip() + '-----END EC PRIVATE KEY-----"; eval(k)\n'),
    ("tokens.js", "js", 'const t = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc";\neval(t)\n'
     'const g = "github_pat_' + "A1b2" * 7 + '";\neval(g)\nconst s = "' + "eyJ" * 50 + '";\n'),
    ("tokens.py", "py", 'a = "AKIAIOSFODNN7ABCDEFG"\nb = "xoxb-1234567890-abcdef"\nc = "sk_live_' + "a1" * 10 + '"\n'
     'd = "AIza' + "B" * 35 + '"\ne = "ghp_' + "x" * 36 + '"\nlit = "Aq3vN5mR1tY7wK2pL9xB4cJ6hF0dS"\n'
     'print("Aq3vN5mR1tY7wK2pL9xB4cJ6hF0dS")\n'),
    ("entropy.js", "js", 'const k = "q8Z3vN5mR1tY7wK2pL9xB4cJ6hF0dS"; // test\nconst path = "/usr/local/lib/node_modules/x";\n'
     'const ok = "CamelCaseIdentifierOnlyLetters";\nconst sample = "q8Z3vN5mR1tY7wK2pL9xB4cJ6hF0dT";\n'),
    # the linear rewrites of the quadratic patterns
    ("nowhere.sql", "sql", "DELETE FROM a;\nDELETE FROM b WHERE x = 1;\nUPDATE c SET d = 1;\nUPDATE e SET f = 1 WHERE g;\n"
     "DELETE FROM h\n  -- comment\n;\nupdate [i] set j = 2;\nDELETE FROM k WHERE\n" + "DELETE FROM x " * 50 + "\n"),
    ("dynamic.sql", "sql", "EXEC(@sql + @x);\nEXECUTE IMMEDIATE 'SELECT ' || v;\nEXEC sp_executesql N'x' + @y;\n"
     "EXEC('SELECT ' + @z);\nSET @q = 'a' + @b;\nSET @r = @s;\nSET @t = 'x'; SET @u = 1 + 2;\n"
     + "SET @a = '" * 30 + "\n"),
    ("grant.sql", "sql", "GRANT SELECT ON a TO bob; GRANT ALL ON b TO PUBLIC;\nGRANT SELECT\nON c TO PUBLIC;\n"
     "REVOKE x FROM y TO PUBLIC;\n" + "GRANT " * 40 + "\n"),
    ("misc.sql", "sql", "SELECT * FROM t WITH (NOLOCK);\nSET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;\n"
     "SET FOREIGN_KEY_CHECKS = 0;\nALTER DATABASE d SET TRUSTWORTHY ON;\nSELECT * FROM OPENROWSET('x');\n"
     "LOAD DATA INFILE 'f';\nEXEC xp_cmdshell 'dir';\n-- TODO: fix\n"),
    ("except.py", "py", "try:\n    x()\nexcept:\n    pass\ntry:\n    y()\nexcept ValueError as e:  \n\n    pass\n"
     "except " * 30 + "\n" + "except:" + "\n" * 20 + "pass\n"),
    ("headers.js", "js", "a(" * 50 + "\n" + "x" * 3000 + "(b) {\n}\nfoo(a) {\n  if (a) {}\n}\n"),
    ("yaml.py", "py", "yaml.load(s)\nyaml.load(s, Loader=yaml.SafeLoader)\n" + "yaml.load(" * 20 + "SafeLoader\n"
     "os.chmod(p, 0o777)\nos.chmod(p, 0o644)\n" + "chmod(" * 20 + "\n"),
    # obfuscation and decode -> execute (FIX-SPEC 13, project mode)
    ("hex.py", "py", "s = '\\x65\\x76\\x61\\x6c\\x28\\x61\\x74\\x6f\\x62\\x28\\x78\\x29\\x29'\n"
     "b = b'\\x00\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08'\np = '\\x21\\x24\\x2a\\x2d\\x3a\\x3d\\x3f\\x5b\\x5d'\n"
     "t = '\\x68\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64'\n"),
    ("obfuscated.js", "js", "String.fromCharCode(101,118,97,108,40,97,116,111,98,40,120,41,41)\n"
     "const _0x1a2b = 1, _0x3c4d = 2, _0x5e6f = 3, _0x7a8b = 4, _0x9c0d = 5;\n"
     "const b = '" + "QUJD" * 60 + "';\n//# sourceMappingURL=data:application/json;base64," + "QUJD" * 60 + "\n"
     "eval(function(p,a,c,k,e,d){return p})\n"),
    ("decode.js", "js", "eval(\n  atob(p))\nFunction(globalThis.atob(q))()\nvm.runInThisContext(Buffer.from(z, 'base64'))\n"
     "eval( // x\n  unescape(y)\n)\n"),
    ("decode.py", "py", "exec(\n    base64.b64decode(s))\nexec(  # nosec\n    codecs.decode(t, 'rot13'))\n"
     "exec(marshal.loads(b))\nexec(compile(src, 'x', 'exec'))\neval(bytes.fromhex(h))\n"),
    # false positives from real registry scans: char codes counted per call,
    # exec(compile(<source>)) is not bytecode, decode -> compile -> exec is
    ("charcode.js", "js", "n+=String.fromCharCode(255&e),e>>>=8;x=12,y=34,z=56,w=78,v=90,u=11,q=22,r=33,s=44;\n"
     "t+=String.fromCharCode(e>>>10&1023|55296);a=[10,20,30,40,50,60,70,80,90,99,11]\n"
     "var s=String.fromCharCode(104,116,116,112,115,58,47,47,101,120,97);\n"
     "var k=[104,116,116,112,115,58,47,47,101,120,97];x=String.fromCharCode.apply(null,k);\n"
     "a=String.fromCharCode(e);" + "f(x);" * 600 + "b=String.fromCharCode(...[104,116,116,112,115,58,47,47,101,120,97]);\n"),
    ("charcode-table.js", "js", "var T=[104,116,116,112,115,58,47,47,101,120,97];s+=String.fromCharCode(e>>>10&1023|55296);"
     "x=12,y=34,z=56,w=78,v=90,u=11,q=22,r=33,s=44,t=55,o=66;\n"
     "var k=[104,116,116,112,115,58,47,47,101,120,97];x=String.fromCharCode(...k.map(c=>c^1));\n"
     'x=String.fromCharCode(f("' + "\U0001F600" * 3000 + '"),104,116,116,112,115,58,47,47,101,120,97);\n'),
    ("compile.py", "py", "exec(compile(path.read_bytes(), str(path), 'exec'), ns)\n"
     "exec(compile(base64.b64decode(x), '<s>', 'exec'))\nexec(compile(zlib.decompress(b), 'f', 'exec'))\n"
     "code = marshal.load(fh)\nexec(__import__('marshal').loads(b))\nc = types.CodeType(0)\n"
     "m = imp.load_compiled('x', 'x.pyc')\n"),
    # taint, sanitizers, the SQL-sink analyzer
    ("taint.py", "py", "import os, shlex\nx = request.args['x']\nos.system(shlex.quote(x))\nos.system(x)\n"
     "n = int(request.args['n'])\ncur.execute('SELECT %s' % n)\nopen(os.path.basename(x))\nredirect(x)\n"
     "requests.get(x)\nrender_template_string(x)\nq = 'SELECT * FROM t WHERE a = %s' % x\ncur.execute(q)\n"
     "cur.execute('SELECT 1 WHERE a=%s', (x,))\ns = 'SELECT ' + x\ns += ' FROM t'\ncur.execute(s)\n"
     "f = f'SELECT {x}'\ncur.executemany(f)\ncur.execute(\"x\".format(y))\n"),
    ("taint.js", "js", "const x = req.query.x;\nexec(shellQuote(x));\nexec(x);\nconst n = parseInt(req.query.n);\n"
     "db.query('SELECT ' + n);\ndb.query(db.escape(x));\nres.sendFile(path.basename(x));\nfetch(x);\nres.redirect(x);\n"
     "el.innerHTML = DOMPurify.sanitize(x);\nel.innerHTML = x;\ndocument.write(location.hash);\nnew Function(x)();\n"
     "fs.readFileSync(x);\nlet a = req.body.a, b = 2;\nconst c = a + '1';\neval(`${c}`);\nvar e = process.argv[2];\nspawn(e);\n"),
    # the other rules, per language
    ("rules.js", "js", "if (a == b) {}\nif (a != null) {}\nconst s = 'a == b';\nsetTimeout(\"alert(1)\", 10);\n"
     "localStorage.setItem('jwt', t);\njwt.verify(t, k, { algorithms: ['none'] });\n"
     "res.set('Access-Control-Allow-Origin', '*');\nconst u = 'http://example.invalid';\ncrypto.createHash('md5');\n"
     "crypto.createCipheriv('des-ede3', k, iv);\nobj['__proto__'] = 1;\ndb.find({ $where: 'x' });\nrequire('vm');\n"
     "spawn('ls', [], { shell: true });\nel.outerHTML = s;\n<div dangerouslySetInnerHTML={x} />\n"
     "const token = Math.random();\nvar z = 1;\ntry { a() } catch (e) {}\ntry { b() } catch {\n}\n"),
    ("rules.py", "py", "import pickle, yaml, hashlib, tempfile, os\nfrom xml.etree import ElementTree\nimport telnetlib\n"
     "pickle.loads(d)\nhashlib.md5(b)\ntempfile.mktemp()\nrequests.get(u, verify=False)\n"
     "app.run(debug=True, host='0.0.0.0')\nsubprocess.run(c, shell=True)\nmark_safe(s)\nEnvironment(autoescape=False)\n"
     "client.set_missing_host_key_policy(AutoAddPolicy())\nDES.new(k)\nAES.new(k, AES.MODE_ECB)\n"
     "secret_key = random.randint(0, 9)\nssl._create_unverified_context()\n" + "z = 1 " * 30 + "\n"),
    ("empty.py", "py", ""),
    ("blank.js", "js", "\n\n   \n" + " " * 200 + "\n"),
]

# (file name, raw bytes) — uploads; the language comes from the extension.
UPLOADS = [
    ("le_bom.js", b"\xff\xfe" + "eval(a)\n".encode("utf-16-le")),
    ("be_bom.js", b"\xfe\xff" + "eval(b)\n".encode("utf-16-be")),
    ("le_nobom.js", "eval(c)\n".encode("utf-16-le")),
    ("be_nobom.py", "eval(c)\nimport os\n".encode("utf-16-be")),
    ("u8bom.py", b"\xef\xbb\xbf" + b"eval(d)\n"),
    ("utf7.py", b"# -*- coding: utf-7 -*-\n# harmless comment +AAo-eval(e)\n"),
    ("utf7_line2.py", b"#!/usr/bin/env python\n# vim: set fileencoding=UTF_7 :\nx = 1 # +AAo-os.system(x)\n"),
    ("latin1.py", b"# coding: latin-1\ns = '\xe9'\neval(f)\n"),
    ("cp1252.py", b"# coding=cp1252\ns = '\x93quoted\x94'\neval(f)\n"),
    ("sjis.py", "# coding: shift_jis\ns = '\u65e5\u672c'\neval(i)\n".encode("shift_jis")),
    ("unknown.py", b"# coding: no-such-codec\neval(g)\n"),
    ("utf8_cookie.py", b"# coding: utf-8\neval(g)\n"),
    ("cookie_line3.py", b"x = 1\ny = 2\n# coding: latin-1\neval(h)\n"),
    ("cookie_in_js.js", b"// coding: latin-1\neval('\xe9')\n"),
    ("nul_utf8.js", b"/*\x00*/eval(x)\n" + b"const a = 1;\n" * 5),     # not UTF-16: implausible
    ("nul_only.js", b"\x00"),
    ("crlf.py", b"eval(a)  # nosec\r\neval(b)\r\n"),
    ("invalid_utf8.js", b"eval(\xff\xfe)\nconst s = '\xc3\x28';\n"),
    ("odd_length.js", b"\xff\xfe" + "eval(q)\n".encode("utf-16-le") + b"\x00"),
    ("utf16_sql.sql", b"\xff\xfe" + "GRANT ALL ON t TO PUBLIC;\n".encode("utf-16-le")),
]


def issue_key(issue):
    return json.dumps(issue, sort_keys=True, ensure_ascii=False)


def short(issue):
    rest = {k: v for k, v in issue.items() if k not in ("rule", "line", "file")}
    return f"{issue['rule']}@{issue['line']} {json.dumps(rest, sort_keys=True, ensure_ascii=False)[:300]}"


def cli_upload(name, data):
    """What the CLI reports for a source file with these bytes."""
    lang = core.EXTS[os.path.splitext(name)[1].lower()]
    text, info = core.decode_source(data, lang)
    return core.encoding_issues(name, text, info) + core.scan_file(name, text, lang)


@dash.requires_node
class DashboardParityTests(unittest.TestCase):
    def assert_same_findings(self, name, cli, page):
        a, b = collections.Counter(map(issue_key, cli)), collections.Counter(map(issue_key, page))
        if a == b:
            return
        only_cli = [json.loads(k) for k in (a - b).elements()]
        only_page = [json.loads(k) for k in (b - a).elements()]
        self.fail(f"{name}: findings differ\n  only in the CLI:\n    "
                  + "\n    ".join(map(short, only_cli[:8])) + "\n  only in the dashboard:\n    "
                  + "\n    ".join(map(short, only_page[:8])))

    def compare(self, cases, html=dash.HTML):
        """cases: [(name, lang, content)]; one page instance for all of them."""
        page = dash.run([{"op": "scanFile", "file": {"name": n, "lang": lang, "content": c}}
                         for n, lang, c in cases], html=html)
        for (name, lang, content), page_issues in zip(cases, page):
            with self.subTest(file=name):
                self.assert_same_findings(name, core.scan_file(name, content, lang), page_issues)
        return page

    def test_fixtures(self):
        files = fixture_files()
        self.assertGreater(len(files), 30)
        self.compare([(rel, LANGS[os.path.splitext(rel)[1]], read_fixture(rel)) for rel in files])

    def test_dashboard_samples(self):
        sources = dash.run([{"op": "eval", "expr": const} for const, _, _ in SAMPLES])
        page = self.compare([(name, lang, src) for (_, name, lang), src in zip(SAMPLES, sources)])
        self.assertTrue(all(len(issues) >= 10 for issues in page))

    def test_adversarial_inputs(self):
        page = self.compare(ADVERSARIAL)
        # not vacuous: the inputs exercise most of the rule set
        self.assertGreater(len({i["rule"] for issues in page for i in issues}), 70)

    def test_uploads(self):
        (page,) = dash.run([{"op": "uploadScan", "files": [
            {"name": n, "b64": base64.b64encode(data).decode("ascii")} for n, data in UPLOADS]}])
        self.assertEqual(len(page), len(UPLOADS))
        for (name, data), page_issues in zip(UPLOADS, page):
            with self.subTest(file=name):
                self.assert_same_findings(name, cli_upload(name, data), page_issues)

    def test_undecodable_codec_is_still_reported(self):
        data = b"# coding: cp037\neval(x)\n"
        (page,) = dash.run([{"op": "uploadScan", "files": [{"name": "ebcdic.py", "b64": base64.b64encode(data).decode()}]}])
        text, info = core.decode_source(data, "py")
        self.assertEqual(info["encoding"], "cp037")
        (cli_note,) = core.encoding_issues("ebcdic.py", text, info)
        (page_note,) = [i for i in page[0] if i["rule"] == "Q-ENCODING"]
        self.assertEqual(page_note["msg"], cli_note["msg"])     # "... (detected cp037) ..."

    def test_report_matches_build_result(self):
        sets = {
            "mixed": ["testproj/app.py", "testproj/secrets.py", "testproj/utils/web.js", "sqlproj/schema.sql"],
            "clean": ["cleanproj/clean.py", "sqlclean/clean.sql"],
        }
        dup = "".join(f"v{i} = compute({i})\n" for i in range(8))
        for label, rels in sets.items():
            files = [(rel, LANGS[os.path.splitext(rel)[1]], read_fixture(rel)) for rel in rels]
            if label == "clean":
                files += [("dup/a.py", "py", dup), ("dup/b.py", "py", dup)]
            with self.subTest(set=label):
                (page,) = dash.run([{"op": "runScan", "files": [
                    {"name": n, "lang": lang, "content": c} for n, lang, c in files]}])
                issues = []
                for n, lang, c in files:
                    issues += core.scan_file(n, c, lang)
                cli = core.build_result(".", [{"path": n, "lang": lang, "content": c} for n, lang, c in files], issues)
                for key in ("metrics", "counts", "ratings", "supplyChain", "pass"):
                    self.assertEqual(page[key], cli[key], key)
                # the CLI's last condition is its cross-file flow engine, which the page doesn't have
                self.assertEqual(cli["conditions"][-1], {"label": "No cross-file taint flows", "ok": True})
                self.assertEqual(page["conds"], cli["conditions"][:-1])
                self.assert_same_findings(label, cli["issues"], page["issues"])
                self.assertEqual([(i["sev"], i["file"], i["line"]) for i in page["issues"]],
                                 [(i["sev"], i["file"], i["line"]) for i in cli["issues"]])
        self.assertGreater(page["metrics"]["dupPct"], 0)

    def test_the_comparison_can_fail(self):
        """Control: a page that drops a rule, or words a finding differently, is caught."""
        with open(dash.HTML, encoding="utf-8", newline="") as f:
            html = f.read()
        src = "import pickle\npickle.loads(d)\n"
        cli = core.scan_file("sample.py", src, "py")
        for old, new in (('id:"S-PICKLE"', 'id:"S-PICKLE-OFF"'),
                         ('msg:"pickle.load(s) executes code', 'msg:"pickle.load(s) runs code')):
            with self.subTest(change=new):
                broken = html.replace(old, new, 1)
                self.assertNotEqual(broken, html)
                with tempfile.TemporaryDirectory() as d:
                    path = os.path.join(d, "lazaret.html")
                    with open(path, "w", encoding="utf-8", newline="") as f:
                        f.write(broken)
                    (page,) = dash.run([{"op": "scanFile", "file": {"name": "sample.py", "lang": "py", "content": src}}],
                                       html=path)
                self.assertNotEqual(collections.Counter(map(issue_key, page)), collections.Counter(map(issue_key, cli)))


if __name__ == "__main__":
    unittest.main()
