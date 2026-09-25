import { test } from "node:test";
import assert from "node:assert/strict";
import { run, version } from "../src/cli.js";

function capture(argv) {
  const out = [];
  const err = [];
  const code = run(argv, { out: (s) => out.push(s), err: (s) => err.push(s) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

test("default prints tagline", () => {
  const r = capture([]);
  assert.equal(r.code, 0);
  assert.match(r.out, /quarantine for your dependencies/);
});

test("--version prints version", () => {
  const r = capture(["--version"]);
  assert.equal(r.code, 0);
  assert.match(r.out, new RegExp(version.replaceAll(".", "\\.")));
});

test("check is stubbed", () => {
  const r = capture(["check", "some/dir"]);
  assert.equal(r.code, 2);
  assert.match(r.err, /not implemented/);
});

test("unknown command fails", () => {
  assert.equal(capture(["bogus"]).code, 1);
});

test("package entry point re-exports the CLI", async () => {
  const pkg = await import("../src/index.js");
  assert.equal(typeof pkg.run, "function");
  assert.equal(pkg.version, version);
});
