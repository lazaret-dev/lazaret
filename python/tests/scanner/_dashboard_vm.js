// Runs the dashboard's inline <script> (python/src/lazaret/web/lazaret.html)
// in node:vm with a minimal DOM stub, so tests can call its scanner and UI
// handlers without a browser. Not a test itself; driven by _dashboard_vm.py.
//
//   node _dashboard_vm.js <lazaret.html>  < requests.json  > results.json
//
// requests.json: [{op, ...}, ...], each answered in order:
//   {op: "scanFile", file: {name, content, lang?, size?}} -> issues
//   {op: "runScan", files: [...]}                         -> lastResult
//   {op: "export"}                                        -> {filename, text} of the export download
//   {op: "upload", files: [{name, content|b64, size?}]}   -> files the page accepted (name, lang, size, contentLength)
//   {op: "uploadScan", files: [{name, content|b64}]}       -> each accepted file's findings (analyzeFile)
//   (content is sent as UTF-8 bytes; b64 is the file's raw bytes, base64)
//   {op: "eval", expr}                                    -> value of expr in the page's scope
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");

const html = fs.readFileSync(process.argv[2], "utf8").replace(/\r\n?/g, "\n");
const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)];
if (scripts.length !== 1) throw new Error(`expected one inline script, found ${scripts.length}`);

function element(selector) {
  const listeners = {};
  return {
    selector, listeners, textContent: "", className: "", innerHTML: "", value: "", files: [],
    disabled: false, style: {}, dataset: {}, href: "", download: "", clicked: 0,
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    querySelectorAll() { return []; },
    scrollIntoView() {},
    click() { this.clicked++; },
  };
}
const elements = new Map();
const created = [];
const blobs = new Map();
const document = {
  querySelector(sel) {
    if (!elements.has(sel)) elements.set(sel, element(sel));
    return elements.get(sel);
  },
  createElement(tag) { const el = element(tag); created.push(el); return el; },
};
class Blob {
  constructor(parts, opts) { this.text = parts.join(""); this.type = (opts || {}).type; }
}
let blobSeq = 0;
const URL_ = {
  createObjectURL(blob) { const id = `blob:vm/${++blobSeq}`; blobs.set(id, blob); return id; },
  revokeObjectURL() {},
};
const context = vm.createContext({
  document, Blob, URL: URL_, alert() {}, console, TextEncoder, TextDecoder, setTimeout, clearTimeout,
});
vm.runInContext(scripts[0][1], context, { filename: "lazaret.html#script" });
const inPage = (expr) => vm.runInContext(expr, context);

/** Pick `files` in the page's upload control (File-like objects: name, size, arrayBuffer()). */
async function upload(reqFiles) {
  const input = document.querySelector("#files");
  const files = reqFiles.map((f) => {
    const bytes = f.b64 !== undefined ? Buffer.from(f.b64, "base64") : Buffer.from(f.content, "utf8");
    return {
      name: f.name,
      size: f.size !== undefined ? f.size : bytes.length,
      arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length),
    };
  });
  for (const fn of input.listeners.change || []) await fn({ target: { files } });
}

async function handle(req) {
  switch (req.op) {
    case "scanFile": {
      const f = Object.assign({}, req.file);
      if (!f.lang) f.lang = inPage("detectLang")(f.name, f.content);
      return JSON.parse(JSON.stringify(inPage("scanFile")(f)));
    }
    case "runScan": {
      const files = req.files.map((f) => Object.assign({ lang: inPage("detectLang")(f.name, f.content) }, f));
      inPage("runScan")(files);
      return JSON.parse(inPage("JSON.stringify(lastResult)"));
    }
    case "export": {
      const before = created.length;
      for (const fn of document.querySelector("#exportBtn").listeners.click || []) fn();
      const a = created.slice(before).find((el) => el.selector === "a" && el.clicked);
      if (!a) return null;
      return { filename: a.download, text: blobs.get(a.href).text };
    }
    case "upload":
    case "uploadScan": {
      await upload(req.files);
      return JSON.parse(inPage(req.op === "upload"
        ? "JSON.stringify(uploaded.map(f=>({name:f.name, lang:f.lang, size:f.size, contentLength:f.content.length})))"
        : "JSON.stringify(uploaded.map(f=>analyzeFile(f)))"));
    }
    case "eval":
      return JSON.parse(JSON.stringify(inPage(req.expr)));
    default:
      throw new Error(`unknown op ${req.op}`);
  }
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => { input += d; });
process.stdin.on("end", async () => {
  const out = [];
  for (const req of JSON.parse(input)) out.push(await handle(req));
  process.stdout.write(JSON.stringify(out));
});
