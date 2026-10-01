"""The JavaScript parser in the WebAssembly build the npm package ships
(js/native/lazaret.wasm) against the native library, call for call, byte
for byte: `js_parse` (and with spans) on the parser's snippets, the
repository's JavaScript, seeded soups, and every construct that nests at
the deepest depth the parser reads and one deeper — the deepest stack it
takes, which the module's (8 MiB, rust/.cargo/config.toml) must hold
without trapping.

A small Node script calls the module the way js/src/lib/native.js does (the
request in the module's memory, the text as WTF-8, the answer read back)
and answers each call's SHA-256, so neither side parses JSON that may be
deeper than a JSON reader allows.

Skipped where node, the WebAssembly build (npm run build in js/) or the
native library is missing.
"""
import hashlib
import json
import os
import subprocess
import unittest

from lazaret.scanner import _native, jsparse
from tests import _support
from tests.architecture import jsgen
from tests.architecture import jsparse_cases as cases
from tests.architecture import test_js_parity_parse as twin
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP

NATIVE_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "native.js")
NPM = r"""
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
const n = await import(pathToFileURL(process.argv[1]).href);
const calls = JSON.parse(readFileSync(0, "utf8"));
const fresh = () => new WebAssembly.Instance(n.wasmModule(), {}).exports;
let e = fresh();
const utf8 = new TextEncoder();
// a lone surrogate as its three bytes (WTF-8), as native.js writes the text
function wtf8(s) {
  if (s.isWellFormed()) return utf8.encode(s);
  const out = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) { c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00); i++; }
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}
function raw(name, args, text) {
  const nb = utf8.encode(name), ab = utf8.encode(JSON.stringify(args)), tb = wtf8(text);
  const len = 8 + nb.length + ab.length + tb.length;
  const req = e.lazaret_alloc(len);
  let view = new DataView(e.memory.buffer);
  const bytes = new Uint8Array(e.memory.buffer);
  view.setUint32(req, nb.length, true);
  bytes.set(nb, req + 4);
  view.setUint32(req + 4 + nb.length, ab.length, true);
  bytes.set(ab, req + 8 + nb.length);
  bytes.set(tb, req + 8 + nb.length + ab.length);
  const out = e.lazaret_call(req, len);
  view = new DataView(e.memory.buffer);
  const status = view.getUint32(out, true), size = view.getUint32(out + 4, true);
  const digest = createHash("sha256").update(new Uint8Array(e.memory.buffer, out + 8, size)).digest("hex");
  e.lazaret_free(out, 8 + size);
  return `${status}:${digest}`;
}
process.stdout.write(JSON.stringify(calls.map(([name, args, text]) => {
  try { return raw(name, args, text); } catch (err) { e = fresh(); return `trap: ${err.message}`; }
})));
"""


def wasm_digests(calls):
    p = subprocess.run([NPM_READY, "--input-type=module", "-e", NPM, NATIVE_JS], input=json.dumps(calls),
                       capture_output=True, encoding="utf-8", timeout=40)
    if p.returncode:
        raise AssertionError(f"node exited {p.returncode}: {p.stderr[-2000:]}")
    return json.loads(p.stdout)


def native_digests(calls):
    out = []
    for name, args, text in calls:
        status, answer = cases.native_raw(name, args, text)
        out.append(f"{status}:{hashlib.sha256(answer.encode('ascii')).hexdigest()}")
    return out


def parse_calls(items, spans=False):
    calls = []
    for path, src in items:
        ts, jsx = jsparse.dialect(path)
        args = {"ts": ts, "jsx": jsx}
        if spans:
            args["spans"] = True
        calls.append(["js_parse", args, src])
    return calls


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmParseParityTests(unittest.TestCase):
    maxDiff = None

    def compare(self, calls):
        wasm = wasm_digests(calls)
        native = native_digests(calls)
        self.assertEqual(len(wasm), len(calls))
        found = [(c[0], c[1], c[2][:120], w, n) for c, w, n in zip(calls, wasm, native) if w != n][:5]
        self.assertEqual(found, [])
        return wasm

    def test_every_nesting_at_its_deepest(self):
        """Each construct at the deepest depth jsparse.py reads (the deepest
        stack) and one deeper, read the same, no trap."""
        items = []
        for name, path, make in cases.NESTINGS:
            ts, jsx = jsparse.dialect(path)
            k = 1
            while k < 300 and cases.oracle_json(make(k + 1), ts, jsx).startswith('{"type"'):
                k += 1
            items += [(path, make(k)), (path, make(k + 1))]
        answers = self.compare(parse_calls(items))
        self.assertFalse([a for a in answers if not a.startswith("0:")])

    def test_snippets_and_sources(self):
        items = twin.items_of(twin.SNIPPETS) + cases.SNIPPETS + twin.own_sources()
        self.compare(parse_calls(items))
        self.compare(parse_calls(twin.items_of(twin.SNIPPETS) + twin.own_sources()[:40], spans=True))

    def test_soups_and_projects(self):
        items = cases.soup(20261002, 1500) + [(f["path"], f["content"]) for files in jsgen.projects(20261002, 30)
                                              for f in files]
        self.compare(parse_calls(items))


if __name__ == "__main__":
    unittest.main()
