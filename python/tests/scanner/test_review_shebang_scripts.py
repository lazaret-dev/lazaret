"""Scripts with no source extension, read by their #! line (analyst gap:
extensionless scripts).

A project or --deps scan read only files with a source extension: every
other file was classified by magic bytes and never read, so a package's
`bin/cli` (`#!/usr/bin/env node`) or the `./setup` an install hook runs
(`#!/usr/bin/env python3`) hid anything, while the registry already read
such archive members as source. Now a file without a source extension whose
#! line names Node (or bun, deno, ts-node, tsx) or Python is scanned as
JavaScript or Python in both walks; shell scripts are not (no rule reads
shell), and a file that is not text stays a binary to classify.

The #! line is the first line only: `#!/usr/bin/env` followed by a newline
took its interpreter from the next line. And the registry decodes such a
Python script as Python reads it: a UTF-7 coding cookie on an extensionless
script hid code in comments (it was read as UTF-8).

The npm engine's twins: js/src/lib/hooks.js shebangLang and js/src/lib/fs.js
scriptSourceLang (tests/architecture/test_js_parity_hooks.py and
test_js_parity.py compare them). Fixtures are inert text.
"""
import json
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import core
from tests.registry._review_support import issues, scan_npm


def make_tree(files):
    root = tempfile.mkdtemp(prefix="lz-shebang-")
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
    return root


class ShebangLangTests(unittest.TestCase):
    def test_interpreters(self):
        cases = {
            "#!/usr/bin/env node\n": "js", "#!/usr/bin/node --harmony\n": "js", "#!/usr/bin/nodejs": "js",
            "#! /usr/bin/env -S deno run --allow-read\n": "js", "#!/usr/bin/env bun\n": "js",
            "#!/usr/local/bin/ts-node\n": "js", "#!/usr/bin/env tsx\r\n": "js", "#!/usr/bin/env NODE\n": "js",
            "#!/usr/bin/python3.11 -u\n": "py", "#!/usr/bin/env python\n": "py", "#!/usr/bin/env -S python3 -X dev\n": "py",
            "#!/bin/sh\n": "sh", "#!/usr/bin/env bash\n": "sh", "#!/bin/zsh -f\n": "sh",
            "#!/usr/bin/perl -w\n": None, "#!/usr/bin/env ruby\n": None, "#!\n": None, "#!/usr/bin/env\n": None,
            # the first line only
            "#!/usr/bin/env\nnode x\n": None, "#!\n/usr/bin/node\n": None, "#!/usr/bin/env \npython\n": None,
            "": None, "node\n": None, " #!/usr/bin/node\n": None, "\ufeff#!/usr/bin/node\n": None,
        }
        for text, want in cases.items():
            with self.subTest(text=text):
                self.assertEqual(core.shebang_lang(text), want)

    def test_script_source_lang(self):
        self.assertEqual(core.script_source_lang(b"#!/usr/bin/env node\nx()\n"), "js")
        self.assertEqual(core.script_source_lang(b"#!/usr/bin/python3\n"), "py")
        self.assertIsNone(core.script_source_lang(b"#!/bin/sh\nls\n"))                 # shell: not source
        self.assertIsNone(core.script_source_lang(b"#!/usr/bin/node\n" + bytes(range(32)) * 12))   # not text
        self.assertIsNone(core.script_source_lang(b"\x7fELF#!/usr/bin/node\n"))
        self.assertIsNone(core.script_source_lang(b""))


class WalkTests(unittest.TestCase):
    FILES = {
        "index.js": "console.log(1);\n",
        "bin/cli": "#!/usr/bin/env node\nconst cp = require('child_process');\ncp.exec(process.argv[2]);\neval(atob(p));\n",
        "bin/tool": b"#!/usr/bin/python3\n# -*- coding: utf-7 -*-\n# harmless +AAo-eval(e)\n",
        "bin/dtool": "#!/usr/bin/env -S deno run\neval(x)\n",
        "bin/run": "#!/bin/sh\neval \"$1\"\n",
        "bin/next-line": "#!/usr/bin/env\nnode\neval(x)\n",
        "bin/blob": b"#!\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f",
        "node_modules/dep/package.json": json.dumps({"name": "dep", "version": "1.0.0"}),
        "node_modules/dep/bin/setup": "#!/usr/bin/env node\neval(atob('Y29uc29sZS5sb2coMSk='));\n",
    }

    def setUp(self):
        self.root = make_tree(self.FILES)
        self.addCleanup(shutil.rmtree, self.root, True)

    def found(self, **kw):
        res = core.scan_project(self.root, **kw)
        return res, {(i["rule"], i["file"].replace(os.sep, "/")) for i in res["issues"]}

    def test_node_and_python_scripts_are_scanned(self):
        res, found = self.found()
        for want in [("S-EVAL-JS", "bin/cli"), ("SC-EVAL-DECODE", "bin/cli"), ("T-CMD", "bin/cli"),
                     ("S-EVAL-JS", "bin/dtool"), ("SC-UTF7", "bin/tool"), ("S-EVAL-PY", "bin/tool")]:
            self.assertIn(want, found)
        self.assertFalse({f for _, f in found} & {"bin/run", "bin/next-line", "bin/blob"}, found)
        self.assertEqual(res["metrics"]["files"], 4)             # index.js, cli, tool, dtool
        self.assertEqual(res["perFile"].get(os.path.join("bin", "cli")) is not None, True)

    def test_a_dependency_script_is_scanned_with_deps(self):
        _, found = self.found()
        self.assertNotIn(("SC-EVAL-DECODE", "node_modules/dep/bin/setup"), found)     # pruned
        res, found = self.found(include_deps=True)
        self.assertIn(("SC-EVAL-DECODE", "node_modules/dep/bin/setup"), found)
        self.assertEqual(res["metrics"]["depFiles"], 1)

    def test_an_oversize_script_is_truncated(self):
        with open(os.path.join(self.root, "bin", "big"), "w", encoding="utf-8") as fh:
            fh.write("#!/usr/bin/env node\n" + "var x = 1;\n" * 2000)
        saved = core.SOURCE_SIZE_CAP
        core.SOURCE_SIZE_CAP = 10_000
        try:
            res = core.scan_project(self.root)
        finally:
            core.SOURCE_SIZE_CAP = saved
        (trunc,) = [i for i in res["issues"] if i["rule"] == "SC-TRUNCATED"]
        self.assertEqual(trunc["file"], os.path.join("bin", "big"))


class RegistryTests(unittest.TestCase):
    def test_a_python_script_keeps_its_coding_cookie(self):
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0", "bin": {"x": "bin/x"}}),
                        "bin/x": "#!/usr/bin/env python3\n# coding: utf-7\n# harmless +AAo-exec(input())\n"})
        (utf7,) = issues(res, "SC-UTF7")
        self.assertEqual((utf7["file"], utf7["line"]), ("bin/x", 2))
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_bun_and_deno_scripts_are_read_as_javascript(self):
        for line in ("#!/usr/bin/env bun", "#!/usr/bin/env -S deno run"):
            with self.subTest(line=line):
                res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0"}),
                                "tool": line + "\neval(atob('Y29uc29sZS5sb2coMSk='));\n"})
                self.assertIn("tool", {i["file"] for i in issues(res, "SC-EVAL-DECODE")})


if __name__ == "__main__":
    unittest.main()
