"""The npm package's engine is the native engine: the WebAssembly build the
npm package ships (js/native/lazaret.wasm, run by js/src/lib/native.js)
against the platform library the Python package ships (_native), call for
call, on the corpora the native engine is held to the Python engine with
(test_rust_parity_*): every case of the hooks corpus through hooks_view and
signs_view (the install-script and import-time tests and the detectors they
read, shlex, follow_hook, the decoded view …), and every file of the
scan_file corpus and this repository through scan_file in dependency mode
and scan_rules. Both are one Rust source, so they must answer byte for byte
alike: what this holds is the build for wasm32 (32-bit sizes, no threads, an
abort on a panic) and the npm binding (a JavaScript string as the engine
reads a Python str, lone surrogates included; the answer's JSON read back
as the same strings). With the parity tests, the npm engine answers as the
Python reference engine does.

Skipped where node, the WebAssembly build (npm run build in js/) or the
native library is missing. LAZARET_PARITY_SHARD=k/n reads a shard of the
hooks corpus (hooks_corpus.shard).
"""
import hashlib
import json
import os
import re
import subprocess
import threading
import unittest

from lazaret.scanner import _native
from tests import _support
from tests.architecture.hooks_corpus import corpus as hook_cases, shard
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP

NATIVE_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "native.js")
# each answer as a digest of its JSON (JSON.stringify's form; see digest())
NPM = """
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
const n = await import(pathToFileURL(process.argv[1]).href);
const calls = JSON.parse(readFileSync(0, "utf8"));
const sha = (s) => createHash("sha256").update(s).digest("hex");
process.stdout.write(JSON.stringify(calls.map(([name, args, text]) => {
  try { return sha(JSON.stringify(n.call(name, args, text))); } catch (e) { return `${e.name}: ${e.message}`; }
})));
"""
CHUNK = 2000
LONE = re.compile("[\ud800-\udfff]")


def digest(value):
    """The digest node computes for the same answer: JSON as JSON.stringify
    writes it (no spaces, non-ASCII as it is, a lone surrogate as a \\u
    escape), SHA-256."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    text = LONE.sub(lambda m: "\\u%04x" % ord(m.group()), text)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def wasm_answers(calls, box, key):
    """The WebAssembly engine's answers (in a node process), into box[key]."""
    try:
        p = subprocess.run([NPM_READY, "--input-type=module", "-e", NPM, NATIVE_JS], input=json.dumps(calls),
                           capture_output=True, encoding="utf-8", timeout=120)
        if p.returncode:
            box["error"] = f"node exited {p.returncode}: {p.stderr[-2000:]}"
            return
        box[key] = json.loads(p.stdout)
    except Exception as e:                            # reported by the test, not lost in the thread
        box["error"] = repr(e)


def native_answers(calls):
    """The native library's answers, as digests (an error as its text)."""
    out = []
    for i in range(0, len(calls), CHUNK):
        for r in _native.call("batch", {"calls": calls[i:i + CHUNK], "threads": 2}):
            out.append(digest(r["ok"]) if "ok" in r else repr(r))
    return out


def both(calls, procs=2):
    """(wasm's answers, the native library's) for the same calls, run side by
    side: the WebAssembly engine in `procs` node processes (it runs on one
    thread), the library on two threads."""
    box = {}
    size = -(-len(calls) // procs)
    workers = [threading.Thread(target=wasm_answers, args=(calls[k * size:(k + 1) * size], box, k))
               for k in range(procs)]
    for w in workers:
        w.start()
    native = native_answers(calls)
    for w in workers:
        w.join()
    if "error" in box:
        raise AssertionError(box["error"])
    return [a for k in range(procs) for a in box[k]], native


def differences(calls, wasm, native, limit=10):
    """[(call, its text, wasm's answer, the library's)] where the digests differ (the answers read again)."""
    found = []
    for call, a, b in zip(calls, wasm, native):
        if a != b:
            found.append((call[0], call[2][:200], a, _native.call(*call)))
            if len(found) >= limit:
                break
    return found


@unittest.skipUnless(NPM_READY, NPM_SKIP)
@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class WasmParityTests(unittest.TestCase):
    maxDiff = None

    def test_the_hooks_corpus(self):
        """hooks_view of every case (signs_view: test_wasm_parity_signs)."""
        calls = [["hooks_view", {}, text] for text in shard(hook_cases())]
        wasm, native = both(calls)
        self.assertEqual(len(wasm), len(calls))
        self.assertEqual(differences(calls, wasm, native), [])
        self.assertTrue(all(len(a) == 64 for a in wasm))                          # every call answered


if __name__ == "__main__":
    unittest.main()
