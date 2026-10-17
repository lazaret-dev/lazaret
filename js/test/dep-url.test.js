// SC-DEP-URL: a dependency npm fetches over plain http or from a raw IP address (D-14, 0.1.9; src/lib/supplychain.js
// dependencyUrlIssues, twin of core's section of the name; python/tests/scanner/test_dep_url.py has the same cases,
// and tests/architecture/test_js_parity_dep_url.py compares the two CLIs). Inert manifests only: hosts are .invalid
// or TEST-NET addresses, nothing is fetched.

import { test } from "node:test";
import assert from "node:assert/strict";
import { dependencyUrlRisk, scanManifest } from "../src/lib/supplychain.js";

const RISKY = {
  "http:\x2f/registry.invalid/b-1.0.0.tgz": ["a plain-http URL"],
  "  HTTP:\x2f/registry.invalid/b.tgz": ["a plain-http URL"],
  "git+http:\x2f/git.invalid/d.git": ["a plain-http URL"],
  "https://203.0.113.7/c.tgz": ["a raw IP address (203.0.113.7)"],
  "http:\x2f/203.0.113.7/c.tgz": ["a plain-http URL", "a raw IP address (203.0.113.7)"],
  "https://3405803783/e.tgz": ["a raw IP address (3405803783)"],
  "https://0xcb.0.113.7/e.tgz": ["a raw IP address (0xcb.0.113.7)"],
  "https://203.0.113.7./e.tgz": ["a raw IP address (203.0.113.7.)"],
  "https://[2001:db8::1]/f.tgz": ["a raw IP address ([2001:db8::1])"],
  "git+ssh://git@198.51.100.4/u/k.git": ["a raw IP address (198.51.100.4)"],
};
const QUIET = ["^1.2.3", "~2", "latest", "npm:other@^1", "file:../h", "link:../h", "github:u/i", "u/i",
  "https://registry.invalid/j.tgz", "git+https://git.invalid/u/g.git", "git+ssh://git@git.invalid/u/g.git",
  "https://1.2.3.example/l.tgz", "https://registry.invalid./j.tgz", "", 12, null, ["x"]];

const manifest = (fields) => JSON.stringify({ name: "app", version: "1.0.0", ...fields }, null, 2);
const found = (path, text, registry) => scanManifest(path, text, { registry })
  .filter((i) => i.rule === "SC-DEP-URL").map((i) => [i.line, i.msg]);

test("what is risky, and what is not", () => {
  for (const [spec, why] of Object.entries(RISKY)) assert.deepEqual(dependencyUrlRisk(spec), why, spec);
  for (const spec of QUIET) assert.deepEqual(dependencyUrlRisk(spec), [], String(spec));
});

test("the fields npm installs from, and where", () => {
  const text = manifest({ dependencies: { a: "^1", b: "http:\x2f/registry.invalid/b.tgz" },
    optionalDependencies: { c: "https://203.0.113.7/c.tgz" },
    peerDependencies: { d: "git+http:\x2f/git.invalid/d.git" },
    devDependencies: { z: "http:\x2f/dev.invalid/z.tgz" } });
  assert.deepEqual(found("package.json", text, true), [
    [6, `Dependency "b" (dependencies) is fetched from a plain-http URL: 'http:\x2f/registry.invalid/b.tgz'.`],
    [9, `Dependency "c" (optionalDependencies) is fetched from a raw IP address (203.0.113.7): 'https://203.0.113.7/c.tgz'.`],
    [12, `Dependency "d" (peerDependencies) is fetched from a plain-http URL: 'git+http:\x2f/git.invalid/d.git'.`]]);
  // a project's own install takes its devDependencies too
  const own = found("package.json", text, false);
  assert.equal(own.length, 4);
  assert.deepEqual(own[3], [15, `Dependency "z" (devDependencies) is fetched from a plain-http URL: 'http:\x2f/dev.invalid/z.tgz'.`]);
  // a registry or --deps scan: a package's root manifest only
  assert.equal(found("node_modules/x/package.json", text, true).length, 3);
  assert.equal(found("node_modules/@s/x/package.json", text, true).length, 3);
  assert.deepEqual(found("test/fixtures/package.json", text, true), []);
  assert.deepEqual(found("node_modules/x/test/package.json", text, true), []);
});

test("the key on its line, credentials redacted", () => {
  const word = "hun" + "ter2val";
  const text = manifest({ dependencies: { b: "^1" }, optionalDependencies: { b: `https://ci:${word}@203.0.113.7/b.tgz` } });
  const [[line, msg], ...rest] = found("package.json", text, true);
  assert.equal(rest.length, 0);
  assert.equal(line, 8);
  assert.ok(!msg.includes(word) && msg.includes("203.0.113.7"), msg);
});
