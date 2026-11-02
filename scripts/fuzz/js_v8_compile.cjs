// V8 as an oracle for the engine's JavaScript parser (python/tests/architecture/test_jsparse_v8.py; X-1, F-12): does
// V8 COMPILE this source — as a script (Node's CommonJS: a `.cjs`, and a `.js` whose package.json does not say
// "type": "module") or as a module (`.mjs`)? JSON lines in ({"src": "<source>"}), one JSON line out per input
// ({"script": bool, "module": bool}). Compiles only: the code is never run, and no module is linked or evaluated, so
// a source that would do something on load does nothing here. Run with --experimental-vm-modules so
// SourceTextModule exists; without it, "module" is reported false and the script answer still stands.
"use strict";
const vm = require("node:vm");
const readline = require("node:readline");

let HAVE_MODULE = true;
try { void vm.SourceTextModule; HAVE_MODULE = typeof vm.SourceTextModule === "function"; } catch { HAVE_MODULE = false; }

function compilesAsScript(src) {
  try { new vm.Script(src); return true; } catch { return false; }
}
function compilesAsModule(src) {
  if (!HAVE_MODULE) return false;
  try { new vm.SourceTextModule(src); return true; } catch { return false; }
}

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
rl.on("line", (line) => {
  let src;
  try { src = JSON.parse(line).src; } catch { process.stdout.write('{"script":false,"module":false}\n'); return; }
  if (typeof src !== "string") { process.stdout.write('{"script":false,"module":false}\n'); return; }
  const out = { script: compilesAsScript(src), module: compilesAsModule(src) };
  process.stdout.write(JSON.stringify(out) + "\n");
});
