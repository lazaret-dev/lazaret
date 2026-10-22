// Where the engine comes from (native.js): native/lazaret.wasm, built by `npm run build`, read and compiled in
// this thread. The browser dashboard's build puts its own module in this one's place (js/dashboard/wasmload.js),
// which hands over the engine the page carries.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const WASM = new URL("../../native/lazaret.wasm", import.meta.url);

/** The engine, compiled (WebAssembly.Module); throws when native/lazaret.wasm is missing. */
export function compileEngine() {
  let bytes;
  try {
    bytes = readFileSync(WASM);
  } catch (e) {
    throw new Error(`the native engine is missing (${fileURLToPath(WASM)}: ${e.code ?? e.message}); `
      + "build it with `npm run build` (Rust and its wasm32-unknown-unknown target)");
  }
  return new WebAssembly.Module(bytes);
}

/** A new instance of `module`: its exports. */
export function newEngine(module) {
  return new WebAssembly.Instance(module, {}).exports;
}
