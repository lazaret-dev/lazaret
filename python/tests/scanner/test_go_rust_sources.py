"""S-4: a project's Go and Rust files are read (.go, .rs).

Before 0.1.9 a project scan never read them: they were classified by their
bytes, as any data file is, so a Go or Rust repository scanned as "0 files"
and passed whatever it held. Now they are source: their comments and
literals as each language's lexer reads them (lex/go.rs, lex/rs.rs: Rust's
nested block comments, raw strings in both, a Rust lifetime is not a
character), and the rules that list the two languages (S-SECRET outside
comments, S-TOKEN, S-BIDI and Q-TODO), with the families every text gets
(hidden text in hex escapes, invisible characters, base64 blobs, high-entropy
literals, long lines) and the suppression markers (`// lazaret-ignore`).

A package's Go and Rust files (registry and guard scans) and a Go or cargo
vendor tree's (--deps) are read with the engine's readers since Part C
(tests/registry/test_package_code.py, tests/scanner/test_vendored_code.py);
another dependency tree's are not. The duplication measure counts Python,
JavaScript and SQL lines (core.DUP_LANGS). Credentials are fakes built by
concatenation; nothing is executed.
"""
import io
import json
import os
import tarfile
import tempfile
import time
import unittest

from lazaret.registry import repo
from lazaret.scanner import _native, core

AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GHP = "gh" + "p_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
PEM_BEGIN = "-----BEGIN RSA " + "PRIVATE KEY-----"
PEM_END = "-----END RSA " + "PRIVATE KEY-----"
PEM_BODY = "MIIEow" + "IBAAKCAQEAx3k9Qm2Zp7Lw4Yb8Nc1Rt5Vs6Ug0Hj2Kd3Fe4" + "Ab" * 8
RLO = "‮"
MAIN_GO = (
    "package main\n"                                            # 1
    "\n"                                                        # 2
    "import \"os\"\n"                                           # 3
    "\n"                                                        # 4
    "// TODO: rotate the key\n"                                 # 5 Q-TODO
    "var password = \"hunter22hunter\"\n"                       # 6 S-SECRET
    f"var awsKey = \"{AWS}\"\n"                                 # 7 S-TOKEN
    "\n"                                                        # 8
    "func main() {\n"                                           # 9
    "\tpw := os.Getenv(\"PASSWORD\")\n"                         # 10 nothing
    f"\ts := \"user{RLO}nimda\"\n"                              # 11 S-BIDI
    f"\tk := `{PEM_BEGIN}\n{PEM_BODY}\n{PEM_END}`\n"            # 12-14 S-TOKEN (key material)
    "\t// password = \"in a comment only\"\n"                   # 15 nothing: S-SECRET skips comments
    f"\t// {GHP}\n"                                             # 16 S-TOKEN: comments too
    f"\tg := \"{GHP}\" // lazaret-ignore: S-TOKEN\n"            # 17 suppressed
    f"\th := \"// nosec\"; t := \"{AWS}\"\n"                    # 18 S-TOKEN: a marker in a string is none
    "\t_, _, _, _, _, _ = pw, s, k, g, h, t\n"                  # 19
    "}\n")                                                      # 20
LIB_RS = (
    "//! A crate. FIXME: docs\n"                                # 1 Q-TODO
    "/* outer /* nested */ let password = \"still a comment\"; */\n"   # 2 nothing
    "pub fn f<'a>(x: &'a str) -> String {\n"                    # 3 a lifetime, not a character
    "    let password = \"hunter22hunter\";\n"                  # 4 S-SECRET
    f"    let raw = r#\"{AWS}\"#;\n"                            # 5 S-TOKEN
    "    let c = '\"'; let lt: &'static str = \"ok\";\n"        # 6 nothing: a character holding a quote
    f"    let b = \"{RLO}\";\n"                                 # 7 S-BIDI
    "    format!(\"{}{}{}{}{}\", x, password, raw, c, lt) + b\n"   # 8
    "}\n")                                                      # 9
TREE = {"cmd/app/main.go": MAIN_GO, "src/lib.rs": LIB_RS}
WANT = [("Q-TODO", "cmd/app/main.go", 5), ("Q-TODO", "src/lib.rs", 1), ("S-BIDI", "cmd/app/main.go", 11),
        ("S-BIDI", "src/lib.rs", 7), ("S-SECRET", "cmd/app/main.go", 6), ("S-SECRET", "src/lib.rs", 4),
        ("S-TOKEN", "cmd/app/main.go", 7), ("S-TOKEN", "cmd/app/main.go", 12), ("S-TOKEN", "cmd/app/main.go", 16),
        ("S-TOKEN", "cmd/app/main.go", 18), ("S-TOKEN", "src/lib.rs", 5)]


def write_tree(root, tree):
    for rel, text in tree.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


def found(res):
    return sorted((i["rule"], i["file"].replace(os.sep, "/"), i["line"]) for i in res["issues"]
                  if not i["rule"].startswith("Q-SKIPPED"))


def tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in sorted(files.items()):
            data = text.encode("utf-8")
            info = tarfile.TarInfo("package/" + name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class LanguageTableTests(unittest.TestCase):
    def test_extensions(self):
        self.assertEqual((core.EXTS[".go"], core.EXTS[".rs"]), ("go", "rs"))
        self.assertEqual(core.DEP_LANGS, frozenset({"py", "js", "sql"}))
        self.assertEqual([core.dep_source_lang(e) for e in (".go", ".rs", ".py", ".ts", ".sql", ".txt")],
                         [None, None, "py", "js", "sql", None])
        self.assertEqual(core.DUP_LANGS, frozenset({"py", "js", "sql"}))

    def test_the_rules_that_list_them(self):
        langs = {r["id"]: r["langs"] for r in core.RULES}
        for rule in ("S-SECRET", "S-TOKEN", "S-BIDI", "Q-TODO"):
            with self.subTest(rule=rule):
                self.assertIn("go", langs[rule])
                self.assertIn("rs", langs[rule])
        self.assertEqual(sorted(r["id"] for r in core.RULES if "go" in r["langs"] or "rs" in r["langs"]),
                         ["Q-TODO", "S-BIDI", "S-SECRET", "S-TOKEN"])


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class ProjectScanTests(unittest.TestCase):
    def scan(self, tree, **kw):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, tree)
            return core.scan_project(root, **kw)

    def test_go_and_rust_files_are_read(self):
        res = self.scan(TREE)
        self.assertEqual(found(res), WANT)
        self.assertEqual((res["metrics"]["files"], res["metrics"]["ncloc"], res["metrics"]["comments"]), (2, 21, 5))
        self.assertFalse(res["pass"])

    def test_collection(self):
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, dict(TREE, **{"node_modules/dep/x.go": "package x\n", "vendor/y.rs": "fn y() {}\n"}))
            files, _manifests, _ = core.collect_files(root, [], include_deps=True)
        self.assertEqual(sorted((f["path"].replace(os.sep, "/"), f["lang"], f["dep"]) for f in files),
                         [("cmd/app/main.go", "go", False), ("src/lib.rs", "rs", False), ("vendor/y.rs", "rs", False)])

    def test_a_dependency_trees_go_and_rust_files_are_not_read(self):
        dep = {"node_modules/dep/package.json": json.dumps({"name": "dep", "version": "1.0.0"}),
               "node_modules/dep/native/x.go": f"package x\nvar awsKey = \"{AWS}\"\n",
               "node_modules/dep/native/y.rs": f"let k = \"{AWS}\";\n"}
        res = self.scan(dict(TREE, **dep), include_deps=True)
        self.assertEqual([f for f in found(res) if "node_modules" in f[1]], [])
        self.assertEqual(found(res), WANT)

    def test_duplication_is_measured_on_python_javascript_and_sql(self):
        block = "".join(f"    let v{k} = compute({k}, \"step {k}\");\n" for k in range(8))
        go_rs = {"a.rs": "fn a() {\n" + block + "}\n", "b.rs": "fn b() {\n" + block + "}\n"}
        res = self.scan(go_rs)
        self.assertEqual((res["metrics"]["ncloc"], res["metrics"]["dupPct"]), (20, 0.0))
        py = "".join(f"v{k} = compute({k}, 'step {k}')\n" for k in range(8))
        res = self.scan(dict(go_rs, **{"a.py": py, "b.py": py}))
        self.assertEqual((res["metrics"]["ncloc"], res["metrics"]["dupPct"]), (36, 100.0))

    def test_suppression_markers_in_go_and_rust_comments(self):
        res = self.scan({"m.go": f"package m\n// nosec\nvar a = \"{AWS}\"\nvar b = \"{AWS}\" // NOSONAR\n",
                         "m.rs": f"/// nosec\nlet a = \"{AWS}\";\nlet b = \"{AWS}\"; // lazaret-ignore: S-TOKEN\n"
                                 f"let c = \"{AWS}\"; /* nosec */\n"})
        # (a marker is a line comment's, `//` here, as in JavaScript)
        self.assertEqual(found(res), [("S-TOKEN", "m.rs", 4)])

    def test_a_scan_of_a_single_language_repository(self):
        res = self.scan({"go.mod": "module example.invalid/m\n\ngo 1.22\n", "m.go": "package m\n\nfunc F() int { return 1 }\n"})
        self.assertEqual(found(res), [])
        self.assertEqual((res["metrics"]["files"], res["metrics"]["ncloc"]), (1, 2))
        self.assertTrue(res["pass"])


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class EngineTests(unittest.TestCase):
    def test_comment_spans_by_each_language(self):
        rs = "let a = 1; /* x /* y */ still */ let b = 'q'; // z\n"
        got = _native.call("lex_comment_spans", {"lang": "rs", "strings": False, "literals": False, "jsx": False}, rs)
        self.assertEqual([rs[s:e] for s, e in got["comments"]], ["/* x /* y */ still */", "// z"])
        go = "s := `/* not a comment */` // yes\nr := '\"'; t := \"// no\"\n"
        got = _native.call("lex_comment_spans", {"lang": "go", "strings": False, "literals": False, "jsx": False}, go)
        self.assertEqual([go[s:e] for s, e in got["comments"]], ["// yes"])

    def test_tokens_by_each_language(self):
        toks = _native.call("lex.tokens", {"lang": "rs"}, "fn f<'a>() { 'x' }")
        self.assertIn(["name", 5, 7], toks)                       # a lifetime, not a character
        self.assertEqual([t for t in toks if t[1] == 13][0][2], 16)   # 'x' is one token
        toks = _native.call("lex.tokens", {"lang": "go"}, "x := `a\nb`")
        self.assertEqual(toks[-1][1:], [5, 10])                   # a raw string over two lines
        with self.assertRaises(_native.NativeError):
            _native.call("lex.tokens", {"lang": "sh"}, "x")


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class McpTests(unittest.TestCase):
    def test_scan_files_reads_a_go_and_a_rust_file(self):
        from lazaret.mcp import server
        with tempfile.TemporaryDirectory() as root:
            write_tree(root, TREE)
            paths = [os.path.join(root, "cmd", "app", "main.go"), os.path.join(root, "src", "lib.rs")]
            out = server.tool_scan_files({"paths": paths})
        got = sorted((i["rule"], os.path.basename(p), i["line"]) for p in paths for i in out["files"][p]["issues"])
        self.assertEqual(got, sorted((r, os.path.basename(f), n) for r, f, n in WANT))
        self.assertNotIn(AWS, json.dumps(out))                     # (redacted, as for any secret)


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class PackageTests(unittest.TestCase):
    def test_a_packages_go_and_rust_files_are_not_read_yet(self):
        files = {"package.json": json.dumps({"name": "x", "version": "1.0.0", "main": "index.js"}),
                 "index.js": "module.exports = 1;\n",
                 "native/x.go": f"package x\nvar awsKey = \"{AWS}\"\n",
                 "native/src/lib.rs": f"let k = \"{AWS}\";\n"}
        budget = repo.Budget(deadline=time.monotonic() + 60, deadline_detail="the test's budget")
        res = repo._scan_artifact(tgz(files), "tgz", "npm", False, budget)
        self.assertEqual([i for i in res["issues"] if i["file"].endswith((".go", ".rs"))], [])
        self.assertNotIn("S-TOKEN", {i["rule"] for i in res["issues"]})
        self.assertEqual(res["filesScanned"], 1)                  # (index.js)


if __name__ == "__main__":
    unittest.main()
