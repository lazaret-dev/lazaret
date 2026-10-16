// Runs the dashboard (python/src/lazaret/web/lazaret.html) in node:vm with a minimal DOM stub: its script, on the
// engine the page carries, as a browser runs it, driven through its controls. Not a test itself; driven by
// _dashboard_vm.py.
//
//   node _dashboard_vm.js <lazaret.html>  < requests.json  > results.json
//
// requests.json: [{op, ...}, ...], each answered in order:
//   {op: "scan", files?: [{name, content|b64, size?}], folder?: [{path, content|b64, size?, unreadable?}],
//    paste?: {text, lang?}}
//       -> the result the page shows ({error} when it shows none): the files picked in its upload control (content
//          as UTF-8 bytes, b64 a file's raw bytes; size: what the file says its size is, when not its length), or the
//          folder picked in its folder control (each file's path in it, the folder's name first, as a browser gives
//          webkitRelativePath; unreadable: reading it fails), and the code pasted, then "Scan code", the result read
//          from the page's export
//   {op: "upload", files: [...]}   -> the file list the page shows (#filelist's HTML) after the files are picked
//   {op: "folder", folder: [...]}  -> the same, after the folder is picked
//   {op: "click", id}              -> clicks the control #id (a sample button, say)
//   {op: "export"}                 -> {filename, text} of the export the page downloads (null when it doesn't)
//   {op: "html", id}               -> {html, text, value} of the element #id
"use strict";
const fs = require("node:fs");
const vm = require("node:vm");

const html = fs.readFileSync(process.argv[2], "utf8").replace(/\r\n?/g, "\n");
const blocks = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)];
const scripts = blocks.filter(([, attrs]) => !/\btype\s*=/i.test(attrs));
if (scripts.length !== 1) throw new Error(`expected one script, found ${scripts.length}`);
const engine = blocks.find(([, attrs]) => /\bid="lazaret-engine"/.test(attrs));
// the script runs where it is in the page: an element after it is not there yet
const parsed = (block) => block && block.index < scripts[0].index;

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
const alerts = [];
const document = {
  querySelector(sel) {
    if (!elements.has(sel)) elements.set(sel, element(sel));
    return elements.get(sel);
  },
  getElementById(id) {
    if (id === "lazaret-engine") return parsed(engine) ? { textContent: engine[2] } : null;
    return document.querySelector(`#${id}`);
  },
  createElement(tag) { const el = element(tag); created.push(el); return el; },
};
let blobSeq = 0;
const URL_ = {
  createObjectURL(blob) { const id = `blob:vm/${++blobSeq}`; blobs.set(id, blob); return id; },
  revokeObjectURL() {},
};
const context = vm.createContext({
  document, Blob, URL: URL_, alert(m) { alerts.push(String(m)); }, console, TextEncoder, TextDecoder,
  setTimeout, clearTimeout, atob, Response, DecompressionStream, WebAssembly,
});
vm.runInContext(scripts[0][2], context, { filename: "lazaret.html#script" });

const fire = async (id, type, event = {}) => {
  for (const fn of document.querySelector(`#${id}`).listeners[type] || []) await fn(event);
};

/** File-like objects (name, size, arrayBuffer(), slice()) for `reqFiles`. A file whose size is more than the bytes
 * sent is one only that much of can be read: reading it all fails, as reading a file that changed under it would. */
function pickFiles(reqFiles) {
  const file = (name, bytes, size, path = "", unreadable = false) => ({
    name, size, webkitRelativePath: path,
    arrayBuffer: async () => {
      if (unreadable) throw new Error("The requested file could not be read");
      if (size > bytes.length) throw new Error(`only ${bytes.length} of its ${size} bytes can be read here`);
      return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length);
    },
    slice: (start, end) => file(name, bytes.subarray(start, end), Math.min(end, size) - start, path, unreadable),
  });
  return reqFiles.map((f) => {
    const bytes = f.b64 !== undefined ? Buffer.from(f.b64, "base64") : Buffer.from(f.content, "utf8");
    const name = f.path !== undefined ? f.path.split("/").pop() : f.name;
    return file(name, bytes, f.size !== undefined ? f.size : bytes.length, f.path || "", !!f.unreadable);
  });
}

async function exported() {
  const before = created.length;
  await fire("exportBtn", "click");
  const a = created.slice(before).find((el) => el.selector === "a" && el.clicked);
  if (!a) return null;
  return { filename: a.download, text: await blobs.get(a.href).text() };
}

async function handle(req) {
  switch (req.op) {
    case "scan": {
      if (req.folder) await fire("folder", "change", { target: { files: pickFiles(req.folder) } });
      else await fire("files", "change", { target: { files: pickFiles(req.files || []) } });
      document.querySelector("#code").value = req.paste ? req.paste.text : "";
      document.querySelector("#lang").value = (req.paste && req.paste.lang) || "auto";
      const before = blobSeq;
      document.querySelector("#status").innerHTML = "";
      alerts.length = 0;
      await fire("scanBtn", "click");
      if (alerts.length) return { error: alerts.join("\n") };
      const out = await exported();
      if (!out || blobSeq === before) return { error: document.querySelector("#status").innerHTML || "no result" };
      const status = document.querySelector("#status").innerHTML;
      if (status) return { error: status };
      return JSON.parse(out.text);
    }
    case "upload":
      await fire("files", "change", { target: { files: pickFiles(req.files) } });
      return document.querySelector("#filelist").innerHTML;
    case "folder":
      await fire("folder", "change", { target: { files: pickFiles(req.folder) } });
      return document.querySelector("#filelist").innerHTML;
    case "click":
      await fire(req.id, "click");
      return null;
    case "export":
      return exported();
    case "html": {
      const el = document.querySelector(`#${req.id}`);
      return { html: el.innerHTML, text: el.textContent, value: el.value };
    }
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
