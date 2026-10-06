// Audit P0: credentials in config and data files (twin of
// python/tests/scanner/test_config_secrets.py; the two engines are held to
// each other by tests/architecture/test_js_parity_config.py). Fixtures are
// inert: hosts are .invalid, every credential is made up.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { run, scanConfigFile, isConfigFile } from "../src/index.js";
import {
  configCommentSpans, secretCol, redactConfigValues, documentationToken, keyMaterial, JWT_IO_PAYLOAD,
} from "../src/lib/configsecrets.js";

const PASS = "Zq8!vN3pL0wX7r";
const TOKEN = "ghp_" + "a1B2".repeat(9);

test("config file names", () => {
  for (const n of [".env", ".env.local", "prod.env", "config.json", "app.yaml", "ci.yml", "setup.cfg",
    "server.key", "prod.tfvars", ".npmrc", ".pypirc", "Dockerfile", "Dockerfile.prod", "Containerfile", "id_rsa"]) {
    assert.ok(isConfigFile(n), n);
  }
  for (const n of ["package-lock.json", "pnpm-lock.yaml", "pylock.toml", "pylock.dev.toml", "yarn.lock",
    "app.py", "README.md", "id_rsa.pub", "env"]) {
    assert.ok(!isConfigFile(n), n);
  }
});

test("comments: '#', '// ' and a leading ';', outside quotes", () => {
  const spans = (line) => configCommentSpans(line).map(([a, b]) => line.slice(a, b));
  assert.deepEqual(spans("KEY=value # trailing"), ["# trailing"]);
  assert.deepEqual(spans("KEY=value#not"), []);
  assert.deepEqual(spans("k: 'x # y' # z"), ["# z"]);
  assert.deepEqual(spans("; ini"), ["; ini"]);
  assert.deepEqual(spans("// jsonc"), ["// jsonc"]);
  assert.deepEqual(spans("//registry.invalid/:_authToken=x"), []);
  assert.deepEqual(spans("url: https://x.invalid/a#frag"), []);
});

test("S-SECRET: reported and quiet lines", () => {
  for (const line of [`DB_PASSWORD=${PASS}`, `  "password": "${PASS}",`, `export API_TOKEN="${PASS}"`,
    `GITHUB_PAT=${PASS}`, `//registry.invalid/:_authToken=${PASS}`, "password: cGFzc3dvcmQxMjM=",
    `url: postgres://app:${PASS}@db.prod.invalid:5432/app`]) {
    assert.ok(secretCol(line) >= 0, line);
  }
  for (const line of ["DB_PASSWORD=changeme", "OPENAI_API_KEY=${OPENAI_API_KEY}", "secret: root-ca5",
    "password: Contraseña actual", "access_token: ACCESS_TOKEN", "auth: WPAPSKWPA2PSK",
    "spring.datasource.password=${DB_PASSWORD:Zq8vN3pL0wX7r}", "nextPageToken: Zq8vN3pL0wX7rT2m",
    "url: postgres://postgres:postgres@localhost:5432/app", "DB_PASSWORD=hunter2"]) {
    assert.equal(secretCol(line), -1, line);
  }
});

test("S-SECRET's column is the key's start", () => {
  assert.equal(secretCol(`  db_password: ${PASS}`), 2);
  assert.equal(secretCol(`x = "é" ; db_password = ${PASS}`), 10);
});

test("context lines lose credential-named values, not references", () => {
  assert.equal(redactConfigValues(`A_PASSWORD=${PASS} B=1`), "A_PASSWORD=[redacted] B=1");
  assert.equal(redactConfigValues('"token": "x", "api_key": "${KEY}"'), '"token": [redacted], "api_key": "${KEY}"');
});

test("documentation samples and key material", () => {
  assert.ok(documentationToken("AKIAIOSFODNN7EXAMPLE"));
  assert.ok(!documentationToken("AKIA2345ABCD6789WXYZ"));
  assert.ok(documentationToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + JWT_IO_PAYLOAD));
  assert.ok(keyMaterial("MIIEpAIBAAKCAQEA3Bq7Zq8vN3pL0wX7rT2mK9sBZq8vN3pL0wX7rT2mK9sB"));
  assert.ok(!keyMaterial("privatekey".repeat(6)));
});

test("scanConfigFile: tokens everywhere, secrets outside comments, markers in comments only", () => {
  const found = (text) => scanConfigFile(".env", text).map((i) => [i.rule, i.line]).sort();
  assert.deepEqual(found(`# GITHUB_TOKEN=${TOKEN}\n# DB_PASSWORD=${PASS}\nDB_PASSWORD=${PASS}\n`),
    [["S-SECRET", 3], ["S-TOKEN", 1]]);
  assert.deepEqual(found(`A_TOKEN=${PASS}  # nosec\nB_TOKEN=${TOKEN}  # lazaret-ignore: S-SECRET\n`
    + `D_PASSWORD=${PASS} LABEL="# nosec"\n`), [["S-SECRET", 3], ["S-TOKEN", 2]]);
  const issues = scanConfigFile("c.json", `{\n  "password": "${PASS}",\n  "pw": "hunter2"\n}\n`);
  assert.ok(!JSON.stringify(issues).includes(PASS));
});

test("a .netrc's password tokens (N-12) and crates.io's API tokens (R-4)", () => {
  const found = (path, text) => scanConfigFile(path, text).map((i) => [i.rule, i.line]).sort();
  const netrc = `machine api.example.invalid login alice password ${PASS}\nmachine ftp.example.invalid\n  login bob\n`
    + `  password changeme\ndefault login anon password "${PASS}"\n# password ${PASS}\n`;
  for (const name of [".netrc", "_netrc", "home/.NETRC"]) {
    assert.deepEqual(found(name, netrc), [["S-SECRET", 1], ["S-SECRET", 5]], name);
  }
  assert.deepEqual(found(".netrc", `machine h.invalid login app_password password ${PASS}\n`), [["S-SECRET", 1]]);
  assert.ok(!JSON.stringify(scanConfigFile(".netrc", `login app_password password ${PASS}\n`)).includes(PASS));
  assert.deepEqual(found("notes.cfg", `hint = the password ${PASS} is not this\n`), []);
  assert.ok(!JSON.stringify(scanConfigFile(".netrc", netrc)).includes(PASS));
  assert.equal(secretCol(`machine h login u password ${PASS}`, true), 27);
  assert.equal(secretCol(`machine h login u password ${PASS}`), -1);
  assert.equal(redactConfigValues(`machine h login u password ${PASS} account x`, true),
    "machine h login u password [redacted] account x");
  const tok = "cio" + "Zq8vN3pL0wX7rT2mK9sB4hF6jD1aE5cG";
  assert.deepEqual(found("credentials.toml", `[registry]\ntoken = "${tok}"\n`), [["S-SECRET", 2], ["S-TOKEN", 2]]);
  for (const text of [`x = "A${tok}"\n`, `x = "${tok}9"\n`, `x = "${tok.slice(0, -1)}"\n`]) {
    assert.ok(!found("a.toml", text).some(([r]) => r === "S-TOKEN"), text);
  }
});

test("linear time on hostile lines", () => {
  for (const line of ["a".repeat(2_000_000), "a=".repeat(1_000_000), 'k="'.repeat(700_000),
    "x://".repeat(500_000), "a:b@".repeat(500_000), ("-".repeat(127) + "=").repeat(15_000)]) {
    const t0 = Date.now();
    secretCol(line); redactConfigValues(line); configCommentSpans(line);
    assert.ok(Date.now() - t0 < 10_000, line.slice(0, 12));
  }
});

test("the CLI counts config files and never writes the credential", () => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-cfg-"));
  try {
    writeFileSync(join(d, ".env"), `DB_PASSWORD=${PASS}\n`);
    mkdirSync(join(d, "node_modules", "dep"), { recursive: true });
    writeFileSync(join(d, "node_modules", "dep", ".env"), `DB_PASSWORD=${PASS}\n`);
    writeFileSync(join(d, "package-lock.json"), JSON.stringify({ packages: { "": { token: TOKEN } } }));
    const out = [];
    assert.equal(run(["check", d, "--no-html"], { out: (l) => out.push(l), err: () => {}, env: {} }), 0);
    const rep = readFileSync(join(d, "lazaret-report.json"), "utf8");
    assert.ok(!rep.includes(PASS));
    const res = JSON.parse(rep);
    assert.equal(res.metrics.configFiles, 1);
    assert.deepEqual(res.issues.filter((i) => i.rule.startsWith("S-")).map((i) => [i.rule, i.file, i.line]),
      [["S-SECRET", ".env", 1]]);
    assert.ok(out.some((l) => l.includes("1 config files")), out.join("\n"));
  } finally { rmSync(d, { recursive: true, force: true }); }
});
