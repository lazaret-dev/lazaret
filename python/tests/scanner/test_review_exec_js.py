"""Final review: S-EXEC-JS flagged method names as CRITICAL shell execution.

`this.exec(args)`, `async exec (args) {` and a class-body `exec(args) {` all
matched `\\b(exec|execSync)\\s*\\(`: 56 CRITICAL false positives in npm's own
lib/ (now 2, both calls on another object: `npm.exec(command, args)`,
`command.exec(args)` — a receiver name cannot tell a command object from
`cp`). The rule (identical pattern text in all three engines) now excludes
a receiver of this. / self. / super. or a #private name, a definition prefix
(async / static / get / set / function) and a definition shape — the
parameter list followed by a block (`name(params) {`, class bodies and
object literals). Real sinks stay flagged: free calls (`exec(cmd)`, a
destructured `const { exec } = require('child_process')`), and calls on any
other receiver (`cp.exec`, `child_process.exec`, `require('child_process')
.exec`). Python engine and dashboard here; the npm engine in
js/test/review-exec-js.test.js. Inert: nothing runs.
"""
import json
import unittest

from lazaret.scanner import core
from tests.scanner import _dashboard_vm as dash

SINKS = [
    "exec(cmd);",
    "execSync(cmd);",
    "const out = execSync(`git ${args}`);",
    "exec('ls ' + dir, cb);",
    "child_process.exec(cmd, cb);",
    "cp.exec(cmd);",
    "require('child_process').exec(cmd);",
    "const { exec } = require('child_process'); exec(x);",
    "if (exec(cmd)) {",
    "cp.exec(cmd, (err) => {",
    "cp.exec(cmd, function (err) {",
    "return exec(cmd)",
]
METHODS = [
    "return this.exec(args)",
    "await this.exec(args, { path, workspace })",
    "self.exec(args)",
    "return super.exec(args)",
    "await this.#exec(cmd, args)",
    "async exec (args) {",
    "async #exec (cmd, args) {",
    "  exec(args) {",
    "  exec (args, { path = this.npm.localPrefix, workspace } = {}) {",
    "static exec(args) {",
    "set exec(v) {",
    "function exec(cmd) {",
    "function exec(cmd)",
    "const o = { exec(cmd) { return run(cmd) } };",
    "exec: function (cmd) {",
    "$exec(x);",
]

# the shape of npm's command classes (lib/commands/*.js, lib/npm.js)
NPM_LIKE = """class LL extends LS {
  async exec (args) {
    return super.exec(args)
  }
}
class Pack extends BaseCommand {
  async exec (args, { localPrefix } = {}) {
    await this.#exec(args)
  }
  async execWorkspaces (args) {
    return this.exec(args)
  }
  async #exec (cmd, args) {
    return child_process.exec(cmd)
  }
}
"""


def flagged(issues):
    return [i["line"] for i in issues if i["rule"] == "S-EXEC-JS"]


class PythonEngineTests(unittest.TestCase):
    def test_real_sinks_are_flagged(self):
        for src in SINKS:
            with self.subTest(src=src):
                self.assertEqual(flagged(core.scan_file("a.js", src + "\n", "js")), [1])

    def test_methods_and_definitions_are_not(self):
        for src in METHODS:
            with self.subTest(src=src):
                self.assertEqual(flagged(core.scan_file("a.js", src + "\n", "js")), [])

    def test_npm_like_command_classes(self):
        self.assertEqual(flagged(core.scan_file("cmd.js", NPM_LIKE, "js")), [14])

    def test_a_sink_after_a_method_on_the_same_line(self):
        self.assertEqual(flagged(core.scan_file("a.js", "this.exec(a); cp.exec(b);\n", "js")), [1])


@dash.requires_node
class DashboardTests(unittest.TestCase):
    def test_same_findings_as_the_cli(self):
        cases = [(f"f{n}.js", src + "\n") for n, src in enumerate(SINKS + METHODS)] + [("cmd.js", NPM_LIKE)]
        page = dash.run([{"op": "scanFile", "file": {"name": n, "lang": "js", "content": c}} for n, c in cases])
        key = lambda i: json.dumps(i, sort_keys=True, ensure_ascii=False)
        for (name, content), got in zip(cases, page):
            with self.subTest(file=name):
                self.assertEqual(sorted(map(key, got)), sorted(map(key, core.scan_file(name, content, "js"))))
        self.assertEqual(sum(bool(flagged(got)) for got in page), len(SINKS) + 1)


if __name__ == "__main__":
    unittest.main()
