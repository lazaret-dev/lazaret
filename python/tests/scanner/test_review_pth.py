"""Final review: .pth files were never checked in project or --deps scans.

site.py executes every line of a .pth file in site-packages that starts with
'import' at EVERY interpreter start, so a committed .pth (or one inside a
scanned venv with --deps) is a real execution/persistence vector — but the
project walk treated it as an unknown file, and a directory holding only
evil.pth exited 2 ("nothing to scan"). The walk now runs the registry's
SC-PTH-EXEC check on every .pth file it meets (CRITICAL when an import line
also executes or decodes code, MAJOR otherwise); a .pth file is not a source
file (no other rule runs on it, it is not in the metrics), the size cap
applies, and a directory containing only a .pth file is a valid scan target.
The dashboard accepts .pth uploads and runs the same check. The helper is
core.pth_issues; the registry's copy must stay identical (drift guard below).
All content is inert: nothing is imported or executed.
"""
import base64
import json
import os
import tempfile
import unittest

from lazaret.registry import repo
from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

EVIL = 'import os, base64; exec(base64.b64decode("cHJpbnQoMSk="))\n'
SHIM = "import _distutils_hack; _distutils_hack.do()\n"         # setuptools' shape: listed for review
PATHS_ONLY = "./src\n# a comment\n../lib\n"
CORPUS = [EVIL, SHIM, PATHS_ONLY, "\ufeffimport sys\n./x\n", "import\tsite\r\n./a\r\nimport x; y = 'x'.decode('rot13')\r\n",
          "  import os\nimportlib\nimport os; os.system('\\x69d')\n", "", "import zlib, marshal; marshal.loads(z)\n"]


def write(root, rel, data):
    path = os.path.join(root, *rel.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))


def pth_findings(res):
    return sorted((i["file"].replace(os.sep, "/"), i["line"], i["sev"]) for i in res["issues"] if i["rule"] == "SC-PTH-EXEC")


class ProjectScanTests(unittest.TestCase):
    def scan(self, tree, **kw):
        with tempfile.TemporaryDirectory() as root:
            for rel, data in tree.items():
                write(root, rel, data)
            return core.scan_project(root, **kw)

    def test_a_directory_with_only_a_pth_file_is_scanned(self):
        res = self.scan({"evil.pth": EVIL})
        self.assertEqual(pth_findings(res), [("evil.pth", 1, "CRITICAL")])
        (issue,) = [i for i in res["issues"] if i["rule"] == "SC-PTH-EXEC"]
        self.assertEqual(issue["msg"], ".pth line runs code at every Python start and executes or decodes a payload.")
        self.assertFalse(res["pass"])

    def test_a_pth_file_without_import_lines_is_a_valid_target(self):
        res = self.scan({"paths.pth": PATHS_ONLY})
        self.assertEqual(pth_findings(res), [])
        self.assertEqual(res["metrics"]["ncloc"], 0)

    def test_pth_files_are_not_source_files(self):
        res = self.scan({"sub/boot.pth": "import os; os.system(cmd)\n", "app.py": "x = 1\n"})
        self.assertEqual(pth_findings(res), [("sub/boot.pth", 1, "MAJOR")])
        self.assertEqual({i["rule"] for i in res["issues"]}, {"SC-PTH-EXEC"})   # no S-OSCMD-PY on it
        self.assertEqual(res["metrics"]["ncloc"], 1)                            # app.py only

    def test_bom_and_crlf(self):
        res = self.scan({"a.pth": b"\xef\xbb\xbfimport sys\r\n./x\r\nimport os; exec(s)\r\n"})
        self.assertEqual(pth_findings(res), [("a.pth", 1, "MAJOR"), ("a.pth", 3, "CRITICAL")])

    def test_site_packages_with_deps(self):
        tree = {"app.py": "x = 1\n", "venv/pyvenv.cfg": "home = /usr\n",
                "venv/lib/python3.11/site-packages/ns.pth": SHIM,
                "venv/lib/python3.11/site-packages/evil.pth": EVIL}
        self.assertEqual(pth_findings(self.scan(tree)), [])                      # pruned without --deps
        self.assertEqual(pth_findings(self.scan(tree, include_deps=True)), [
            ("venv/lib/python3.11/site-packages/evil.pth", 1, "CRITICAL"),
            ("venv/lib/python3.11/site-packages/ns.pth", 1, "MAJOR")])

    def test_size_cap_applies(self):
        res = self.scan({"big.pth": EVIL + "#" * (core.SOURCE_SIZE_CAP + 1)})
        self.assertEqual(pth_findings(res), [])
        (t,) = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(t["file"], "big.pth")

    def test_the_registry_check_is_the_same(self):
        for text in CORPUS:
            with self.subTest(text=text[:30]):
                self.assertEqual(repo.pth_issues("m.pth", text), core.pth_issues("m.pth", text))
        self.assertEqual(repo._PTH_EXEC_RE.pattern, core._PTH_EXEC_RE.pattern)


def cli_pth(name, data):
    return core.pth_issues(name, data.decode("utf-8-sig", "replace"))


@dash.requires_node
class DashboardTests(unittest.TestCase):
    def test_uploaded_pth_files_get_the_same_check(self):
        uploads = [(f"f{n}.pth", text.encode("utf-8")) for n, text in enumerate(CORPUS)]
        uploads.append(("latin.pth", b"import os; exec(b'\xe9')\n"))
        (page,) = dash.run([{"op": "uploadScan", "files": [
            {"name": n, "b64": base64.b64encode(d).decode("ascii")} for n, d in uploads]}])
        key = lambda i: json.dumps(i, sort_keys=True, ensure_ascii=False)
        for (name, data), got in zip(uploads, page):
            with self.subTest(file=name):
                self.assertEqual(sorted(map(key, got)), sorted(map(key, cli_pth(name, data))))
        self.assertEqual([i["sev"] for i in page[0]], ["CRITICAL"])

    def test_oversize_pth_upload_and_metrics(self):
        accepted, result = dash.run([
            {"op": "upload", "files": [{"name": "big.pth", "content": "", "size": 3_000_000},
                                       {"name": "evil.pth", "content": EVIL}, {"name": "a.py", "content": "x = 1\n"}]},
            {"op": "runScan", "files": [{"name": "big.pth", "content": "", "size": 3_000_000, "pth": True},
                                        {"name": "evil.pth", "content": EVIL, "pth": True},
                                        {"name": "a.py", "content": "x = 1\n"}]},
        ])
        self.assertEqual([f["name"] for f in accepted], ["big.pth", "evil.pth", "a.py"])
        rules = sorted((i["rule"], i["file"]) for i in result["issues"])
        self.assertEqual(rules, [("SC-PTH-EXEC", "evil.pth"), ("SC-TRUNCATED", "big.pth")])
        cli = core.build_result(".", [{"path": "a.py", "lang": "py", "content": "x = 1\n"}], [])
        self.assertEqual(result["metrics"], cli["metrics"])                     # .pth files are not source
        self.assertFalse(result["pass"])


if __name__ == "__main__":
    unittest.main()
