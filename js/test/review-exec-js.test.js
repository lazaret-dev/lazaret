// Final review: S-EXEC-JS flagged method names — `this.exec(args)`,
// `async exec (args) {`, class-body `exec(args) {` — as CRITICAL shell
// execution: 56 false positives in npm's own lib/. Twin of core's S-EXEC-JS
// (same pattern text; tests/scanner/test_review_exec_js.py): receivers
// this. / self. / super. / #private, definition prefixes (async, static,
// get, set, function) and definition shapes (`name(params) {`) are
// excluded; free calls and calls on any other receiver stay flagged. Inert.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";

const SINKS = [
  "exec(cmd);", "execSync(cmd);", "const out = execSync(`git ${args}`);", "exec('ls ' + dir, cb);",
  "child_process.exec(cmd, cb);", "cp.exec(cmd);", "require('child_process').exec(cmd);",
  "const { exec } = require('child_process'); exec(x);", "if (exec(cmd)) {", "cp.exec(cmd, (err) => {",
  "cp.exec(cmd, function (err) {", "return exec(cmd)",
];
const METHODS = [
  "return this.exec(args)", "await this.exec(args, { path, workspace })", "self.exec(args)",
  "return super.exec(args)", "await this.#exec(cmd, args)", "async exec (args) {", "async #exec (cmd, args) {",
  "  exec(args) {", "  exec (args, { path = this.npm.localPrefix, workspace } = {}) {", "static exec(args) {",
  "set exec(v) {", "function exec(cmd) {", "function exec(cmd)", "const o = { exec(cmd) { return run(cmd) } };",
  "exec: function (cmd) {", "$exec(x);",
];
const flagged = (content) => scanFile({ name: "a.js", lang: "js", content }).filter((i) => i.rule === "S-EXEC-JS").map((i) => i.line);

test("real child_process sinks are flagged", () => {
  for (const src of SINKS) assert.deepEqual(flagged(src + "\n"), [1], src);
});

test("methods, private names and definitions are not", () => {
  for (const src of METHODS) assert.deepEqual(flagged(src + "\n"), [], src);
});

test("npm-like command classes: only the real sink", () => {
  const src = [
    "class LL extends LS {", "  async exec (args) {", "    return super.exec(args)", "  }", "}",
    "class Pack extends BaseCommand {", "  async exec (args, { localPrefix } = {}) {", "    await this.#exec(args)", "  }",
    "  async execWorkspaces (args) {", "    return this.exec(args)", "  }", "  async #exec (cmd, args) {",
    "    return child_process.exec(cmd)", "  }", "}", ""].join("\n");
  assert.deepEqual(flagged(src), [14]);
  assert.deepEqual(flagged("this.exec(a); cp.exec(b);\n"), [1]);
});
