"""Dashboard <-> CLI parity: the page reports what the CLI reports for the same files.

Since BR-7 step 5 the dashboard (lazaret/web/lazaret.html) runs the npm package's collection, scan and grading on
the engine it carries, the CLIs' own (until then it carried a port of the npm engine, kept in step by tests of
every rule, its tables and its decoding, and it drifted all the same). So what is held here is the page as a whole:
the files picked in its upload control (or the code pasted into it) give the result `lazaret` gives for a directory
holding them, lazaret.scanner.core's project scan, every field of it and of every finding (but the page's file
list and time, and the CLI's project path and time):

* the fixture projects (tests/fixtures: each a scan, its tree uploaded as paths; the trees the CLI's walk prunes
  are left out, as the page has no walk) and the page's own "Load sample" inputs, pasted;
* uploads the CLI's collection reads each its own way: encodings (UTF-16 with and without a BOM, coding cookies,
  CRLF), a .pth file, a .pyw script, Go and Rust sources (N-14), a script without an extension, a program under a
  source file's name, an image, a video named .ts, an AppleDouble file, a config file holding a credential, an
  empty file, a name outside ASCII;
* a control: a page that grades differently is caught.

Not compared: what the page does not do (a directory walk: links, unreadable entries, pruned trees, dependency
trees; following a package.json's install hooks into the files they run), and its size limit
(test_review_dashboard_limits). All content is inert: nothing is executed, hosts are TEST-NET or .invalid, the
credential is a dummy built in pieces (test_fixture_credentials).
"""

import os
import tempfile
import unittest

from tests import _support
from tests.scanner import _dashboard_vm as dash

#: the trees of the fixture projects the CLI's walk prunes (core.OPTIN_SKIP_DIRS, dot-directories), left out here
PRUNED = {"dist", "migrations", "build", "node_modules", "venv", ".venv", "env"}


def fixture_projects():
    """[(name, [(rel, bytes)])]: each fixture project's files, and the files at the fixtures' top as one more."""
    out = []
    top = []
    for entry in sorted(os.listdir(_support.FIXTURES)):
        path = os.path.join(_support.FIXTURES, entry)
        if os.path.isfile(path):
            top.append((entry, _read(path)))
            continue
        files = []
        for root, dirs, names in os.walk(path):
            dirs[:] = sorted(d for d in dirs if d not in PRUNED and not d.startswith(".") and d != "__pycache__")
            for name in sorted(names):
                full = os.path.join(root, name)
                files.append((os.path.relpath(full, path).replace(os.sep, "/"), _read(full)))
        out.append((entry, files))
    out.append(("fixtures", top))
    return out


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def cookie(name, body):
    return f"# coding: {name}\n".encode("ascii") + body.encode(name)


SECRET = "Tq8vN3pL0wX7rT2mK9sB" + "4hF6jD1aE5cGzY0uWx3R"              # a made-up key, in pieces

#: (name, [(rel, bytes or text)]): uploads the CLI's collection reads each its own way
UPLOADS = [
    ("utf-16 with a BOM", [("u16.py", "\ufeffimport os\nos.system(input())\n".encode("utf-16-le"))]),
    ("utf-16 without one", [("u16n.py", "import os\nos.system(input())\n".encode("utf-16-le"))]),
    ("utf-7 cookie", [("u7.py", b"# coding: utf-7\nx = 1  # +AAo-eval(input())\n")]),
    ("escape cookie", [("esc.py", b"# -*- coding: unicode_escape -*-\nx = 1  # \\u000aeval(input())\n")]),
    ("latin-1 cookie", [("l1.py", cookie("latin-1", "s = 'caf\xe9'\neval(s)\n"))]),
    ("euc_jis_2004 cookie", [("j.py", cookie("euc_jis_2004", "# \u6f22\u5b57\nx = eval(y)\n"))]),
    ("an undecoded codec", [("i.py", b"# coding: idna\nx = eval(y)\n")]),
    ("crlf", [("crlf.py", b"import os\r\nos.system(input())\r\n"), ("crlf.js", b"eval(a)\r\nx = 1\r\n")]),
    (".pth", [("hook.pth", b"import sys\nimport os; exec(bytes.fromhex('7072696e74283129').decode())\n"
                           b"/opt/lib\n")]),
    (".pyw", [("tool.pyw", "import os\nos.system(user_cmd)\n")]),
    ("go and rust", [("main.go", 'package main\n\nimport "os/exec"\n\nfunc run(c string) {\n'
                                 '\texec.Command("sh", "-c", c).Run()\n}\n'),
                     ("src/lib.rs", 'use std::process::Command;\n\npub fn run(c: &str) {\n'
                                    '    Command::new("sh").arg("-c").arg(c).status().unwrap();\n}\n')]),
    ("scripts without an extension", [("tool", "#!/usr/bin/env python3\nimport os\nos.system(input())\n"),
                                      ("cli", "#!/usr/bin/env node\nrequire('child_process').exec(process.argv[2]);\n"),
                                      ("notes", "just some notes\n")]),
    ("binaries", [("lib.py", b"\x7fELF\x02\x01\x01" + bytes(200)), ("logo.png", b"\x89PNG\r\n\x1a\n" + bytes(64)),
                  ("clip.ts", b"".join([b"\x47" + bytes(187)] * 4)), ("._x.py", b"\x00\x05\x16\x07" + bytes(60))]),
    ("a config file", [("config.yaml", f"aws_secret_access_key: {SECRET}\nregion: us-east-1\n"),
                       ("app.py", "import yaml\ncfg = yaml.safe_load(open('config.yaml'))\n")]),
    ("manifests", [("package.json", '{"name": "x", "version": "1.0.0", "scripts": {"test": "node t.js"}}\n'),
                   ("binding.gyp", "{'targets': [{'target_name': 'x', 'sources': ['x.cc']}]}\n")]),
    ("empty and named", [("empty.py", b""), ("caf\u00e9.py", "eval(x)\n")]),
]


@dash.requires_node
class ParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.projects = fixture_projects() + UPLOADS
        # the samples, as the page shows them: each button's text, then each scanned as pasted
        got = dash.run([r for button in ("samplePy", "sampleJs", "sampleSql")
                        for r in ({"op": "click", "id": button}, {"op": "html", "id": "code"},
                                  {"op": "html", "id": "lang"})])
        cls.samples = [(got[k + 1]["value"], got[k + 2]["value"]) for k in range(0, len(got), 3)]
        cls.pages = dash.run([dash.scan_request(files) for _, files in cls.projects]
                             + [dash.scan_request(paste=text, lang=lang) for text, lang in cls.samples], timeout=40)

    def same(self, page, cli, files):
        self.assertNotIn("error", page, page.get("error"))
        self.assertEqual(page["generatedBy"], "lazaret-dashboard-2")
        self.assertEqual(page["files"], sorted(rel for rel, _ in files))
        self.assertEqual(cli.get("warnings", []), [])
        page, cli = dash.comparable(page, dash.PAGE_ONLY), dash.comparable(cli, dash.CLI_ONLY)
        self.assertEqual(sorted(page), sorted(cli))
        for key in page:
            if key != "issues":
                self.assertEqual(page[key], cli[key], key)
        self.assertEqual(len(page["issues"]), len(cli["issues"]))
        for mine, theirs in zip(page["issues"], cli["issues"]):
            self.assertEqual(mine, theirs)

    def test_fixtures_and_uploads(self):
        self.assertGreater(len(self.projects), 20)
        for (name, files), page in zip(self.projects, self.pages):
            with self.subTest(name):
                self.same(page, dash.cli_result(files), files)

    def test_some_findings_are_compared(self):
        """The inputs reach the collection's paths: decoded, classified, the .pth check, Go and Rust, a config
        file's credential, the cross-file pass."""
        rules = {i["rule"] for page in self.pages for i in page.get("issues", [])}
        for rule in ("Q-ENCODING", "SC-UTF7", "SC-ESCAPE-CODEC", "SC-TRUNCATED", "SC-PTH-EXEC", "S-OSCMD-PY",
                     "S-EVAL-PY", "SC-INSTALL-HOOK", "SC-BINARY", "S-SECRET"):
            with self.subTest(rule):
                self.assertIn(rule, rules)
        self.assertTrue(any(page.get("crossFile") for page in self.pages))
        go_rust = self.pages[[n for n, _ in self.projects].index("go and rust")]
        self.assertEqual(go_rust["metrics"]["files"], 2)                    # both read as source (N-14)
        config = self.pages[[n for n, _ in self.projects].index("a config file")]
        self.assertEqual(config["metrics"]["configFiles"], 1)

    def test_the_samples(self):
        self.assertEqual([lang for _, lang in self.samples], ["py", "js", "sql"])
        pages = self.pages[len(self.projects):]
        for (text, lang), page in zip(self.samples, pages):
            with self.subTest(lang):
                files = [(f"pasted-code.{lang}", text)]
                self.same(page, dash.cli_result(files), files)
                self.assertFalse(page["pass"])

    def test_the_comparison_can_fail(self):
        """Control: a page that counts the config files wrongly, or drops a finding, is caught."""
        with open(dash.HTML, encoding="utf-8") as f:
            page = f.read()
        files = dict(UPLOADS)["a config file"]
        broken = [page.replace("res.metrics.configFiles = col.configs.length;",
                               "res.metrics.configFiles = col.configs.length + 1;"),
                  page.replace("const res = redactResult(gradeResult(col.files, collectionIssues(col)));",
                               "const res = redactResult(gradeResult(col.files, collectionIssues(col).slice(1)));")]
        for k, html in enumerate(broken):
            with self.subTest(k):
                self.assertNotEqual(html, page)
                with tempfile.TemporaryDirectory() as d:
                    path = os.path.join(d, "lazaret.html")
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(html)
                    got = dash.scan(files, html=path)
                with self.assertRaises(AssertionError):
                    self.same(got, dash.cli_result(files), files)


if __name__ == "__main__":
    unittest.main()
