// Where the dashboard's engine comes from: the page carries it (scripts/make_dashboard.py), gzipped and in base64,
// in a data block (<script type="application/octet-stream" id="lazaret-engine">, never run). The page's build puts
// this module in the place of the npm package's src/lib/wasmload.js, which reads native/lazaret.wasm from disk.
//
// A browser compiles and instantiates a module this size only asynchronously on the page's thread (Chrome refuses
// the synchronous forms over 4 KB), and native.js asks for its instance synchronously: loadEngine() compiles the
// engine and makes SPARES instances ahead, and newEngine hands one over and makes another. native.js asks for a new
// instance only after a trap or a call that left the memory over 512 MB, and the page waits for loadEngine() before
// each scan, so a scan finds SPARES instances ready; one that needed more gets an error from newEngine, which its
// file reports as SC-TRUNCATED (its scan failed).

const SPARES = 2;

let module = null;        // the WebAssembly.Module
let loading = null;       // loadEngine's promise
const spares = [];        // instances made ahead (their exports)
let making = 0;           // instances being made

/** The engine's bytes: the data block's base64, gunzipped. */
async function engineBytes() {
  const block = document.getElementById("lazaret-engine");
  if (!block) throw new Error("this page carries no engine (lazaret-engine)");
  const text = atob(block.textContent.replace(/\s+/g, ""));
  const gz = new Uint8Array(text.length);
  for (let k = 0; k < text.length; k++) gz[k] = text.charCodeAt(k);
  const stream = new Blob([gz]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function makeSpares() {
  while (module && spares.length + making < SPARES) {
    making++;
    WebAssembly.instantiate(module, {}).then(
      (inst) => { making--; spares.push(inst.exports); },
      () => { making--; });
  }
}

/** Compile the engine (once) and have SPARES instances ready; resolves when they are. */
export async function loadEngine() {
  if (!loading) {
    loading = (async () => {
      module = await WebAssembly.compile(await engineBytes());
    })();
  }
  await loading;
  makeSpares();
  while (spares.length < SPARES && making) await new Promise((done) => setTimeout(done, 0));
}

/** The engine, compiled (native.js wasmModule); throws until loadEngine() has. */
export function compileEngine() {
  if (!module) throw new Error("the engine is still loading");
  return module;
}

/** An instance made ahead: its exports (native.js asks for one; another is made). */
export function newEngine() {
  const exports = spares.shift();
  makeSpares();
  if (!exports) throw new Error("no engine instance was ready (the page makes them between scans)");
  return exports;
}
