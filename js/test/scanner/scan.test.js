// Hex-escape decoding and private-key material. Mirrors the Python engine's
// hex_hidden_text / _token_has_material cases (python/tests/registry/test_verdicts.py).
import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile, hexHiddenText } from "../../src/scanner/scan.js";

const rules = (content, lang = "py") =>
  scanFile({ name: `f.${lang}`, path: `f.${lang}`, content, lang }).map((i) => [i.rule, i.sev]);

test("escaped binary data is not hidden text", () => {
  for (const line of [
    String.raw`b'\xff\xfe{\x00"\x00K0"\x00=\x00"\x00\xab0"\x00\r\n'`,   // requests: UTF-16 sample
    String.raw`b"\x00\x00\x01\x7f\x00\x00\x01\xea\x60"`,                  // urllib3: SOCKS bytes
    String.raw`b"\xc3\xa4\xc3\xb6\xc3\xbc\xc3\x9f"`,                      // urllib3: UTF-8
    String.raw`b'\x1B\x5B\x32\x4B\x07\x41\x0A\x08'`,                      // numpy: ANSI escape
    String.raw`'\x21\x24\x2a\x2d\x3a\x3d\x3f\x5b\x5d'`,                   // cryptography: punctuation
    String.raw`b"\x2d\x39\x35\x34\x37\x39\x3a\x33\x37\x39\x30"`,          // pillow: palette bytes
  ]) assert.equal(hexHiddenText(line), null, line);
});

test("hidden words are found, and dangerous ones are CRITICAL", () => {
  assert.equal(hexHiddenText(String.raw`x = "\x65\x76\x61\x6c\x28\x61\x74\x6f\x62"`), "eval(atob");
  assert.equal(hexHiddenText(String.raw`"\x48\x65\x6c\x6c\x6f\x20\x4d\x65\x73\x6f\x6e"`), "Hello Meson");
  assert.deepEqual(rules(String.raw`x = "\x65\x76\x61\x6c\x28\x61\x74\x6f\x62"` + "\n").filter(([r]) => r === "SC-HEXSTR"),
                   [["SC-HEXSTR", "CRITICAL"]]);
  assert.deepEqual(rules(String.raw`y = "\x48\x65\x6c\x6c\x6f\x20\x4d\x65\x73\x6f\x6e"` + "\n").filter(([r]) => r === "SC-HEXSTR"),
                   [["SC-HEXSTR", "MAJOR"]]);
});

test("a PEM header constant is not a key; a header with key material is", () => {
  assert.ok(!rules('_PEM_BEGIN = b"-----BEGIN OPENSSH PRIVATE KEY-----"\n').some(([r]) => r === "S-TOKEN"));
  const key = "KEY = '''-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0000000000000000000000000000000000000000000\n'''\n";
  assert.ok(rules(key).some(([r]) => r === "S-TOKEN"));
});

test("Windows line endings change nothing: nosec still suppresses", () => {
  const lf = "import subprocess\n" +
             "def run(cmd):\n" +
             "    subprocess.run(cmd, shell=True)  # nosec\n" +
             "    subprocess.run(cmd, shell=True)\n";
  const key = (content) => scanFile({ name: "t.py", path: "t.py", content, lang: "py" })
    .map((i) => `${i.rule}:${i.line}`).sort();
  assert.deepEqual(key(lf.replaceAll("\n", "\r\n")), key(lf));
  assert.deepEqual(key(lf.replaceAll("\n", "\r")), key(lf));
  // the finding on line 3 is suppressed, the one on line 4 is not
  assert.ok(!key(lf.replaceAll("\n", "\r\n")).includes("S-SHELL-TRUE:3"));
  assert.ok(key(lf.replaceAll("\n", "\r\n")).includes("S-SHELL-TRUE:4"));
});
