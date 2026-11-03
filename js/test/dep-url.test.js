// SC-DEP-URL: a dependency npm fetches over plain http or from a raw IP address (D-14, 0.1.9; src/lib/supplychain.js
// dependencyUrlIssues, twin of core's section of the name; python/tests/scanner/test_dep_url.py has the same cases,
// and tests/architecture/test_js_parity_dep_url.py compares the two CLIs). Inert manifests only: hosts are .invalid
// or TEST-NET addresses, nothing is fetched.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
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

// WIN-DEP-PATHS: on Windows the walk names a dependency's fixture node_modules\dep\test\package.json, which the
// engine read '/'-separated as a manifest at the top of a package: `--deps` reported the fixture's dependencies
// there alone (test_js_parity_dep_url, PR #17's windows-latest job). `windows` reads a backslash as a separator.
const TEXT = manifest({ dependencies: { f: "http:\x2f/fixture.invalid/f.tgz" },
  devDependencies: { z: "https://3405803783/z.tgz" } });
const deps = (path, registry, windows) => scanManifest(path, TEXT, { registry, windows })
  .filter((i) => i.rule === "SC-DEP-URL").length;

test("a Windows walk's path is read with its separators", () => {
  assert.equal(deps("node_modules\\dep\\test\\package.json", true, true), 0);      // a dependency's fixture
  assert.equal(deps("node_modules\\@s\\dep\\test\\package.json", true, true), 0);
  assert.equal(deps("node_modules\\dep\\package.json", true, true), 1);            // its root: not devDependencies
  assert.equal(deps("a\\node_modules\\@s\\dep\\package.json", true, true), 1);
  assert.equal(deps("package.json", false, true), 2);                              // the project's own, a workspace's
  assert.equal(deps("packages\\web\\package.json", false, true), 2);
  // elsewhere a backslash is a file name's, as on POSIX: one file at the top of the tree, or one folder's name
  assert.equal(deps("node_modules\\dep\\test\\package.json", true, false), 1);
  assert.equal(deps("node_modules/a\\b/package.json", true, false), 1);
  assert.equal(deps("node_modules/a\\b/package.json", true, true), 0);
  assert.equal(deps("node_modules\\dep\\test\\package.json", true, undefined), 1); // (none given: POSIX's reading)
});

// The walk's manifests go to the engine with the host's separator (scancollection.js: collect.js WINDOWS). A child
// with process.platform set to "win32" stands in for Windows on any system; this process is the host's own.
const SCAN_COLLECTION = new URL("../src/scancollection.js", import.meta.url).href;
const COLLECTION = `
  const { collectionIssues } = await import(${JSON.stringify(SCAN_COLLECTION)});
  const content = ${JSON.stringify(TEXT)};
  const manifests = ["node_modules\\\\dep\\\\test\\\\package.json", "node_modules\\\\dep\\\\package.json"]
    .map((path) => ({ kind: "package.json", path, content, dep: true }))
    .concat([{ kind: "package.json", path: "package.json", content, dep: false }]);
  const issues = collectionIssues({ files: [], manifests, configs: [], binaryIssues: [], skippedIssues: [] });
  process.stdout.write(JSON.stringify(issues.filter((i) => i.rule === "SC-DEP-URL").map((i) => i.file).sort()));
`;
const WIN32 = "data:text/javascript,Object.defineProperty(process,'platform',{value:'win32'})";

test("the walk's manifests are read with the host's separator", () => {
  const run = (preload) => {
    const p = spawnSync(process.execPath, [...preload, "--input-type=module", "-e", COLLECTION],
      { encoding: "utf8", timeout: 30_000 });
    assert.equal(p.status, 0, p.stderr);
    return JSON.parse(p.stdout);
  };
  const windows = ["node_modules\\dep\\package.json", "package.json", "package.json"];
  assert.deepEqual(run(["--import", WIN32]), windows);
  assert.deepEqual(run([]), process.platform === "win32" ? windows
    : ["node_modules\\dep\\package.json", "node_modules\\dep\\test\\package.json", "package.json", "package.json"]);
});
