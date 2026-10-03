// Review regression: the supply-chain patterns (INSTALL_HOOK_RE, the
// `node -e` / local-require / inline-danger patterns and the gyp ones) were
// plain JS regexes, so \w, \b and \s were ASCII/JS-flavoured and case folding
// was ASCII-only, while core runs the same text with Python semantics. They
// are now compiled with pyRe. Every expectation is core's scan_manifest /
// scan_gyp result on the same text (tests/architecture/test_js_parity_gyp
// compares the two CLIs on these inputs). Commands are inert strings.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanManifest, scanGyp } from "../src/index.js";

// (0.1.8) the download and evaluation tools are a hint in a MAJOR finding's message
const hookHint = (cmd) => scanManifest("package.json", JSON.stringify({ scripts: { postinstall: cmd } }))
  .map((i) => [i.rule, i.sev, i.msg.includes("runs a download or evaluation command")]);

test("install hooks are judged with Python regex semantics", () => {
  // U+017F (long s) folds to "s" under Python's re.I: base64
  assert.deepEqual(hookHint("echo ba\u017fe64"), [["SC-INSTALL-HOOK", "MAJOR", true]]);
  // U+001C is whitespace for Python's \s (not for JavaScript's): node -e
  assert.deepEqual(hookHint("node\x1c-e x"), [["SC-INSTALL-HOOK", "MAJOR", true]]);
  // é is a word character for Python's \b, so "éeval" holds no word "eval"
  assert.deepEqual(hookHint("echo \u00e9eval x"), [["SC-INSTALL-HOOK", "MAJOR", false]]);
  assert.deepEqual(hookHint("echo eval x"), [["SC-INSTALL-HOOK", "MAJOR", true]]);
});

test("a gyp include-path expansion with a non-ASCII module name is the benign form", () => {
  // `[\w@./-]+` in the benign `node -e "require('…')"` pattern: \w matches é in Python
  const gyp = "{'targets': [{'include_dirs': [\"<!(node -e \\\"require('./donn\u00e9es')\\\")\", " +
    "\"<!(node -p \\\"require('caf\u00e9').include\\\")\"]}]}";
  // (not CRITICAL; the one requiring ./données runs a file of the package: INFO inventory)
  assert.deepEqual(scanGyp("binding.gyp", gyp).map((i) => [i.rule, i.sev, i.cmd]),
    [["SC-INSTALL-HOOK", "INFO", "node -e \"require('./donn\u00e9es')\""]]);
  assert.deepEqual(scanGyp("binding.gyp", gyp.replace("./donn\u00e9es", "./x' + 'y")).map((i) => [i.rule, i.sev]),
    [["SC-INSTALL-HOOK", "MAJOR"]]);                                  // (0.1.8: `node -e` is a hint, not a reason)
});
