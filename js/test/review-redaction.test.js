// Review regressions: secret redaction through the LIBRARY API (review
// finding 7; shared semantics 6). `import { scanFile } from "lazaret"` used
// to return raw credentials in snippets; the context-line patterns lacked
// gho_/ghu_/ghs_/ghr_, SQL IDENTIFIED BY / PASSWORD and PEM blocks. Snippets
// below equal the Python engine's on the same input. All credentials are
// dummies; hosts are TEST-NET.

import { test } from "node:test";
import assert from "node:assert/strict";
import { scanFile } from "../src/index.js";
import { scanManifest } from "../src/lib/supplychain.js";

const AWS = "AKIA" + "ZZZZ9999ZZZZ9999";
const GH = (p) => `${p}${"a1B2".repeat(9)}`;
const scan = (content, lang) => scanFile({ name: `t.${lang}`, content, lang });
const snip = (issues, rule) => issues.find((i) => i.rule === rule).snippet;

test("scanFile redacts credential lines in every finding's snippet", () => {
  const r = scan(`const k = "${AWS}";\neval(y)\n`, "js");
  assert.deepEqual(snip(r, "S-TOKEN"), ["[redacted: secret rule S-TOKEN] (33 chars)", "eval(y)", ""]);
  assert.deepEqual(snip(r, "S-EVAL-JS"), ['const k = "[redacted]";', "eval(y)", ""]);
  assert.ok(!JSON.stringify(r).includes(AWS));
});

test("every GitHub token prefix is a secret", () => {
  for (const p of ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]) {
    const r = scan(`token = "${GH(p)}"\n`, "py");
    assert.deepEqual(r.map((i) => i.rule), ["S-TOKEN"], p);
    assert.ok(!JSON.stringify(r).includes(GH(p)), p);
  }
});

test("SQL IDENTIFIED BY / PASSWORD are redacted case-insensitively in context lines", () => {
  let r = scan("create user bob identified by 'hunter2hunter2';\nGRANT ALL ON t TO PUBLIC;\n", "sql");
  assert.deepEqual(snip(r, "SQL-GRANT-ALL"), ["create user bob [redacted];", "GRANT ALL ON t TO PUBLIC;", ""]);
  r = scan("ALTER ROLE app WITH PASSWORD 'hunter2hunter2';\nGRANT ALL ON t TO PUBLIC;\n", "sql");
  assert.deepEqual(snip(r, "SQL-GRANT-PUBLIC"), ["ALTER ROLE app WITH [redacted];", "GRANT ALL ON t TO PUBLIC;", ""]);
  assert.ok(!JSON.stringify(r).includes("hunter2"));
});

test("every line of a PEM private-key block is redacted", () => {
  const body = ["MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu",
    "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ=="];
  const pem = ["-----BEGIN RSA PRIVATE KEY-----", ...body, "-----END RSA PRIVATE KEY-----"].join("\n");
  const r = scan(`const k = \`${pem}\`;\neval(y)\n`, "js");
  assert.deepEqual(snip(r, "S-EVAL-JS"), ["[redacted]", "[redacted]", "eval(y)", ""]);
  for (const b of body) assert.ok(!JSON.stringify(r).includes(b));
});

test("an entropy-flagged literal is redacted wherever it appears; URL userinfo too", () => {
  const lit = "Zq8vN3pL0wX7rT2mK9sB4hF6";
  let r = scan(`x = "${lit}"\nprint(x); eval("${lit}")\n`, "py");
  assert.deepEqual(r.map((i) => i.rule).sort(), ["S-ENTROPY", "S-EVAL-PY"]);
  assert.ok(!JSON.stringify(r).includes(lit));
  r = scan('u = "https://admin:s3cretPassw0rd@192.0.2.10/db"\neval(u)\n', "py");
  assert.deepEqual(snip(r, "S-EVAL-PY"), ['u = "https://[redacted]@192.0.2.10/db"', "eval(u)", ""]);
});

test("install-hook msg and cmd are redacted by the library call itself", () => {
  const manifest = JSON.stringify({ scripts: { postinstall: `node x.js --token ${GH("ghp_")}` } }, null, 2);
  const [hook] = scanManifest("package.json", manifest);
  assert.equal(hook.msg, `"postinstall" script runs code at install time: 'node x.js --token [redacted]'.`);
  assert.equal(hook.cmd, "node x.js --token [redacted]");
  assert.ok(!JSON.stringify(hook).includes(GH("ghp_")));
});
