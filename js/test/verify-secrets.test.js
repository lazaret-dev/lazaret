// `lazaret --verify-secrets` (src/verify.js, V-1 stage 2, step 4): the npm package's runner of live secret verification,
// against a stub provider over TLS on 127.0.0.1, reached through a CONNECT proxy (no real service is called). The stub's
// root and its certificate for the providers' hosts are made with `openssl` (skipped without it, and without the
// engine's WebAssembly build). The twin of the Python package's test_secretverify_http.py and test_verifyscan.py.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { run } from "../src/index.js";
import { available } from "../src/lib/native.js";
import { Verifier, httpsTransport, TransportError, checkRequest, proxyFor, amzDate, LIVE, REJECTED, UNKNOWN, NOT_THIS_FORMAT }
  from "../src/verify.js";

const HAVE_OPENSSL = (() => {
  try { execFileSync("openssl", ["version"], { stdio: "ignore" }); return true; } catch { return false; }
})();
const SKIP = !HAVE_OPENSSL ? "the stub provider needs the openssl command"
  : !available() ? "the native engine is not built (npm run build)" : false;
const HOSTS = ["api.github.com", "slack.com", "api.stripe.com", "registry.npmjs.org", "api.openai.com", "api.anthropic.com",
  "sts.amazonaws.com"];

const GITHUB = "ghp_" + "a1B2".repeat(9);
const SLACK = "xox\x62-1234567890-abcdefghij";
const STRIPE = "sk_live_" + "a1".repeat(12);
const ANTHROPIC = "sk-ant-api03-" + "Ab1_".repeat(10);
const AWS = { id: "AKI\x41ABCDEFGHIJKLMNOP", secret: "wJalrXUtnFEMI/K7MDEN\x47+bPxRfiCYEXAMPLEKEY" };
const VALUES = [GITHUB, SLACK, STRIPE, ANTHROPIC, AWS.id, AWS.secret];
const APP = `import os\nGITHUB_TOKEN = "${GITHUB}"\nslack = "${SLACK}"\nheaders = {"Authorization": "Bearer ${STRIPE}"}\n`
  + `AWS_ACCESS_KEY_ID = "${AWS.id}"\nAWS_SECRET_ACCESS_KEY = "${AWS.secret}"\npassword = "hunter2hunter2"\n`;
const ENV = `ANTHROPIC_API_KEY=${ANTHROPIC}\n`;
const AWS_LIVE = "<GetCallerIdentityResult><Arn>arn:aws:iam::123456789012:user/alice</Arn></GetCallerIdentityResult>";
const SCRIPT = {
  "api.github.com": { status: 200, body: '{"login": "octocat"}' },
  "slack.com": { status: 200, body: '{"ok": false, "error": "invalid_auth"}' },
  "sts.amazonaws.com": { status: 200, body: AWS_LIVE },
  "api.anthropic.com": { status: 401, body: '{"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}}' },
};

let dir, keys, stub, tunnel;

function openssl(...args) {
  execFileSync("openssl", args, { cwd: dir, stdio: "ignore", timeout: 30_000 });
}

/** A root, and a certificate for the providers' hosts under it. */
function makePki() {
  writeFileSync(join(dir, "leaf.ext"), `subjectAltName=${HOSTS.map((h) => `DNS:${h}`).join(",")}\nbasicConstraints=critical,CA:FALSE\n`
    + "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n");
  openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "root.key", "-out",
    "root.pem", "-days", "2", "-subj", "/CN=lazaret-stub root", "-addext", "basicConstraints=critical,CA:TRUE",
    "-addext", "keyUsage=critical,keyCertSign,cRLSign");
  openssl("req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr",
    "-subj", "/CN=lazaret-stub");
  openssl("x509", "-req", "-in", "leaf.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", "leaf.pem", "-days", "2",
    "-extfile", "leaf.ext");
  return { root: readFileSync(join(dir, "root.pem")), cert: readFileSync(join(dir, "leaf.pem")), key: readFileSync(join(dir, "leaf.key")) };
}

/** The stub provider: answers as scripted for any of the hosts (by "host path", then host; else 404), and what it was asked. */
function makeStub(tlsOptions = {}) {
  const s = { script: new Map(), requests: [] };
  s.server = https.createServer({ key: keys.key, cert: keys.cert, ...tlsOptions }, (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const host = String(req.headers.host ?? "").toLowerCase();
      s.requests.push({ method: req.method, host, path: req.url, headers: req.headers, raw: req.rawHeaders, body: Buffer.concat(chunks) });
      const a = s.script.get(`${host} ${req.url.split("?")[0]}`) ?? s.script.get(host) ?? { status: 404, body: "not found" };
      const send = () => {
        if (a.close) { req.socket.destroy(); return; }
        const body = a.huge ? Buffer.alloc(a.huge, "x") : Buffer.from(a.body ?? "");
        res.writeHead(a.status, { ...(a.headers ?? {}), "Content-Length": String(a.claim ?? body.length), Connection: "close" });
        if (a.drip) {
          let i = 0;
          const t = setInterval(() => {
            if (i >= body.length || res.destroyed) { clearInterval(t); res.end(); return; }
            res.write(body.subarray(i, i + 1)); i++;
          }, a.drip);
          res.on("close", () => clearInterval(t));
        } else if (a.claim !== undefined) {
          res.write(body);
          setTimeout(() => req.socket.destroy(), 50);
        } else res.end(body);
      };
      if (a.delay) setTimeout(send, a.delay); else send();
    });
  });
  s.server.on("tlsClientError", () => {});
  return listening(s);
}

/** A CONNECT proxy in front of `port`: `require` is the Proxy-Authorization it wants; `refuse` answers 403. */
function makeProxy(port, { require = null, refuse = false } = {}) {
  const p = { connects: [] };
  p.server = http.createServer((req, res) => { res.writeHead(405); res.end(); });
  p.server.on("connect", (req, socket, head) => {
    p.connects.push([`${req.method} ${req.url} HTTP/${req.httpVersion}`, req.headers]);
    if (refuse) { socket.end("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"); return; }
    if (require && req.headers["proxy-authorization"] !== require) {
      socket.end("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n");
      return;
    }
    const up = net.connect(port, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection established\r\n\r\n");
      if (head.length) up.write(head);
      up.pipe(socket);
      socket.pipe(up);
    });
    up.on("error", () => socket.destroy());
    socket.on("error", () => up.destroy());
  });
  return listening(p);
}

/** `thing.server` listening on 127.0.0.1 (its port in `thing.port`), never what keeps the test process alive. */
function listening(thing) {
  return new Promise((resolve, reject) => {
    thing.server.once("error", reject);
    thing.server.listen(0, "127.0.0.1", () => {
      thing.port = thing.server.address().port;
      thing.server.unref();
      resolve(thing);
    });
  });
}

function stop(thing) {
  thing.server.closeAllConnections?.();
  thing.server.close();
}

const through = (proxy, auth = "") => httpsTransport({ env: { HTTPS_PROXY: `http://${auth}127.0.0.1:${proxy.port}` }, ca: keys.root });
const GOOD = { method: "GET", host: "api.github.com", path: "/user", headers: [["Authorization", "Bearer abc"]], body: null };
const send = (request, timeoutMs = 5000, maxBytes = 1000) => through(tunnel)(request, timeoutMs, maxBytes);
const reset = (script = {}) => {
  stub.requests.length = 0;
  stub.script = new Map(Object.entries(script));
};
const kind = async (promise) => {
  try { await promise; } catch (e) { assert.ok(e instanceof TransportError, String(e)); return e.kind; }
  return "answered";
};

before(async () => {
  if (SKIP) return;
  dir = mkdtempSync(join(tmpdir(), "lazaret-verify-"));
  keys = makePki();
  stub = await makeStub();
  tunnel = await makeProxy(stub.port);
});

after(() => {
  if (SKIP) return;
  stop(stub);
  stop(tunnel);
  rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------------------------- the request

test("what is not a request this module sends is refused before anything is opened", { skip: SKIP }, () => {
  for (const bad of [{ ...GOOD, method: "PUT" }, { ...GOOD, host: "127.0.0.1" }, { ...GOOD, host: "API.github.com" },
    { ...GOOD, host: "api.github.com:443" }, { ...GOOD, path: "user" }, { ...GOOD, path: "/a b" },
    { ...GOOD, headers: [["X", "a\r\nb"]] }, { ...GOOD, headers: [["Host", "x"]] }, { ...GOOD, headers: { a: "b" } }]) {
    assert.throws(() => checkRequest(bad), (e) => e instanceof TransportError && e.kind === "refused");
  }
  assert.equal(checkRequest(GOOD), GOOD);
});

test("the proxy settings are read as the Python package's transport reads them", { skip: SKIP }, () => {
  assert.equal(proxyFor("api.github.com", {}), null);
  assert.deepEqual(proxyFor("a.example", { HTTPS_PROXY: "http://proxy.example:3128" }), { host: "proxy.example", port: 3128, headers: {} });
  assert.equal(proxyFor("a.example", { https_proxy: "proxy.example" }).port, 80);
  assert.equal(proxyFor("a.example", { HTTPS_PROXY: "http://up:1", https_proxy: "http://low:2" }).host, "up");
  assert.deepEqual(proxyFor("a.example", { https_proxy: "http://user:p%40ss@proxy.example:3128" }).headers,
    { "Proxy-Authorization": "Basic dXNlcjpwQHNz" });
  for (const host of ["api.github.com", "x.internal"]) {
    assert.equal(proxyFor(host, { https_proxy: "http://p:1", no_proxy: "github.com,.internal" }), null);
  }
  assert.notEqual(proxyFor("slack.com", { https_proxy: "http://p:1", no_proxy: "github.com" }), null);
  assert.equal(proxyFor("slack.com", { https_proxy: "http://p:1", NO_PROXY: "*" }), null);
  for (const value of ["https://proxy.example:3128", "socks5://proxy.example:1080"]) {
    assert.throws(() => proxyFor("a.example", { https_proxy: value }), (e) => e.kind === "proxy");
  }
});

test("a request goes as it is asked, through the tunnel, and the proxy sees only the host", { skip: SKIP }, async () => {
  reset({ "api.github.com /user": { status: 200, body: '{"login": "octocat"}', headers: { "X-Thing": "one" } } });
  const got = await send({ ...GOOD, headers: [["Authorization", "Bearer sekrit-token-value"]] });
  assert.deepEqual([got.status, got.body.toString(), got.truncated, got.headers["x-thing"]], [200, '{"login": "octocat"}', false, "one"]);
  const [seen] = stub.requests;
  assert.deepEqual([seen.method, seen.host, seen.path], ["GET", "api.github.com", "/user"]);
  assert.deepEqual(seen.raw.filter((_, k) => k % 2 === 0 && seen.raw[k].toLowerCase() === "authorization").length, 1);
  assert.equal(seen.headers.authorization, "Bearer sekrit-token-value");
  assert.equal(seen.headers["user-agent"], "lazaret-secret-verify");
  assert.equal(seen.headers["accept-encoding"], "identity");
  assert.deepEqual(seen.raw.filter((_, k) => k % 2 === 1 && seen.raw[k - 1].toLowerCase() === "host"), ["api.github.com"]);
  const [line, headers] = tunnel.connects.at(-1);
  assert.equal(line, "CONNECT api.github.com:443 HTTP/1.1");
  assert.equal(headers.authorization, undefined);
  assert.ok(!JSON.stringify(tunnel.connects).includes("sekrit-token-value"));
});

test("a post sends its body; a request's own user agent replaces the default", { skip: SKIP }, async () => {
  reset({ "sts.amazonaws.com": { status: 200, body: "<ok/>" }, "slack.com": { status: 200, body: "{}" } });
  await send({ method: "POST", host: "sts.amazonaws.com", path: "/", headers: [["Content-Type", "application/x-www-form-urlencoded"]], body: "Action=X" });
  await send({ ...GOOD, host: "slack.com", path: "/api/auth.test", headers: [["User-Agent", "mine"]] });
  const [post, mine] = stub.requests;
  assert.deepEqual([post.method, post.body.toString(), post.headers["content-length"]], ["POST", "Action=X", "8"]);
  assert.equal(mine.headers["user-agent"], "mine");
});

test("a redirect is an error and never followed; a status that does not redirect is an answer", { skip: SKIP }, async () => {
  for (const status of [301, 302, 303, 307, 308]) {
    reset({ "api.github.com": { status, body: "", headers: { Location: "https://slack.com/steal" } }, "slack.com": { status: 200, body: "stolen" } });
    assert.equal(await kind(send(GOOD)), "redirect");
    assert.deepEqual(stub.requests.map((r) => r.host), ["api.github.com"]);
  }
  for (const [status, headers] of [[302, {}], [300, { Location: "/elsewhere" }], [304, { Location: "/elsewhere" }]]) {
    reset({ "api.github.com": { status, body: "", headers } });
    assert.equal((await send(GOOD)).status, status);
  }
});

test("an answer is read to the limit and no further, with its status", { skip: SKIP }, async () => {
  reset({ "api.github.com": { status: 401, huge: 3 * 1024 * 1024 } });
  const got = await send(GOOD, 5000, 1000);
  assert.deepEqual([got.status, got.body.length, got.truncated], [401, 1000, true]);
  for (const [size, truncated] of [[999, false], [1000, false], [1001, true]]) {
    reset({ "api.github.com": { status: 200, body: "y".repeat(size) } });
    const r = await send(GOOD, 5000, 1000);
    assert.deepEqual([r.body.length, r.truncated], [Math.min(size, 1000), truncated]);
  }
});

test("a slow, dripping or quiet server is stopped at the deadline; a cut answer or a hang-up is a connection error", { skip: SKIP }, async () => {
  reset({ "api.github.com": { status: 200, body: "{}", delay: 3000 } });
  let started = performance.now();
  assert.equal(await kind(send(GOOD, 500)), "timeout");
  assert.ok(performance.now() - started < 2500);
  reset({ "api.github.com": { status: 200, body: "y".repeat(200), drip: 100 } });
  started = performance.now();
  assert.equal(await kind(send(GOOD, 1000)), "timeout");
  assert.ok(performance.now() - started < 3000);
  reset({ "api.github.com": { status: 200, body: '{"login": "x"', claim: 100 } });
  assert.equal(await kind(send(GOOD)), "connection");
  reset({ "api.github.com": { close: true } });
  assert.equal(await kind(send(GOOD)), "connection");
});

test("a certificate that is not trusted, or for another host, is a TLS error and nothing is sent", { skip: SKIP }, async () => {
  reset({ "api.github.com": { status: 200, body: "{}" } });
  const untrusted = httpsTransport({ env: { HTTPS_PROXY: `http://127.0.0.1:${tunnel.port}` } });
  assert.equal(await kind(untrusted(GOOD, 5000, 1000)), "tls");
  assert.equal(await kind(send({ ...GOOD, host: "not-in-the-certificate.example" })), "tls");
  assert.equal(stub.requests.length, 0);
});

test("nothing older than TLS 1.2: a server that speaks only TLS 1.1 is refused, which a client without the floor reaches", { skip: SKIP }, async (t) => {
  let old;
  try {
    old = await makeStub({ minVersion: "TLSv1", maxVersion: "TLSv1.1", ciphers: "DEFAULT@SECLEVEL=0" });
  } catch (e) {
    t.skip(`no TLS 1.1 server here (${e.message})`);
    return;
  }
  const proxy = await makeProxy(old.port);
  try {
    const control = await new Promise((resolve) => {
      const s = tls.connect({ host: "127.0.0.1", port: old.port, servername: "api.github.com", ca: keys.root, minVersion: "TLSv1",
        ciphers: "DEFAULT@SECLEVEL=0" }, () => { resolve(s.getProtocol()); s.destroy(); });
      s.on("error", (e) => resolve(`error ${e.code}`));
    });
    if (control !== "TLSv1.1") { t.skip(`this OpenSSL does not speak TLS 1.1 (${control})`); return; }
    assert.equal(await kind(through(proxy)(GOOD, 5000, 1000)), "tls");
    assert.equal(old.requests.length, 0);
  } finally {
    stop(old);
    stop(proxy);
  }
});

test("the proxy's credentials go to the proxy alone; a proxy that refuses is a proxy error; an https:// proxy is refused", { skip: SKIP }, async () => {
  reset({ "api.github.com": { status: 200, body: "{}" } });
  const guarded = await makeProxy(stub.port, { require: "Basic dXNlcjpwYXNz" });
  const refusing = await makeProxy(stub.port, { refuse: true });
  try {
    assert.equal((await through(guarded, "user:pass@")(GOOD, 5000, 1000)).status, 200);
    assert.equal(guarded.connects[0][1]["proxy-authorization"], "Basic dXNlcjpwYXNz");
    assert.equal(stub.requests[0].headers["proxy-authorization"], undefined);
    reset({ "api.github.com": { status: 200, body: "{}" } });
    assert.equal(await kind(through(guarded)(GOOD, 5000, 1000)), "proxy");
    assert.equal(await kind(through(refusing)(GOOD, 5000, 1000)), "proxy");
    const https_ = httpsTransport({ env: { HTTPS_PROXY: "https://127.0.0.1:1" }, ca: keys.root });
    assert.equal(await kind(https_(GOOD, 5000, 1000)), "proxy");
    assert.equal(stub.requests.length, 0);
  } finally {
    stop(guarded);
    stop(refusing);
  }
});

// ---------------------------------------------------------------------------------------------- the verifier

/** AWS's Signature Version 4 worked out here over what the stub received: does the signature it was sent hold? */
function sigv4Holds(seen, secretKey) {
  const m = /^AWS4-HMAC-SHA256 Credential=[^/]+\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$/
    .exec(seen.headers.authorization);
  const [, date, region, service, signed, signature] = m;
  let fields = "";
  for (const name of signed.split(";")) {
    const values = seen.raw.filter((_, k) => k % 2 === 1 && seen.raw[k - 1].toLowerCase() === name);
    if (values.length !== 1) return false;
    fields += `${name}:${values[0].split(/\s+/).filter(Boolean).join(" ")}\n`;
  }
  const [path, query = ""] = seen.path.split("?");
  const sha = (s) => createHash("sha256").update(s).digest("hex");
  const canonical = [seen.method, path, query, fields, signed, sha(seen.body)].join("\n");
  const scope = `${date}/${region}/${service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", seen.headers["x-amz-date"], scope, sha(canonical)].join("\n");
  let key = Buffer.from("AWS4" + secretKey);
  for (const part of [date, region, service, "aws4_request"]) key = createHmac("sha256", key).update(part).digest();
  return createHmac("sha256", key).update(toSign).digest("hex") === signature;
}

test("each provider's credential reaches its own host alone; AWS's signature holds over what the stub received", { skip: SKIP }, async () => {
  reset({ ...SCRIPT, "api.stripe.com": { status: 200, body: "{}" }, "registry.npmjs.org": { status: 200, body: '{"username": "n"}' },
    "api.openai.com": { status: 200, body: "{}" } });
  const v = new Verifier({ transport: through(tunnel), now: () => new Date(Date.UTC(2026, 9, 3, 12)) });
  const items = [["github", GITHUB], ["slack", SLACK], ["stripe", STRIPE], ["npm", "npm_" + "A1b2".repeat(9)],
    ["openai", "sk-proj-" + "a1".repeat(20)], ["anthropic", ANTHROPIC], ["aws", AWS]];
  const got = await v.verifyAll(items);
  assert.deepEqual(got.map((r) => r.outcome), [LIVE, REJECTED, LIVE, LIVE, LIVE, REJECTED, LIVE]);
  assert.deepEqual([got[0].who, got[6].who], ["octocat", "arn:aws:iam::123456789012:user/alice"]);
  const own = { "api.github.com": GITHUB, "slack.com": SLACK, "api.stripe.com": STRIPE, "api.anthropic.com": ANTHROPIC, "sts.amazonaws.com": AWS.id };
  for (const seen of stub.requests) {
    const text = JSON.stringify([seen.raw, seen.path, seen.body.toString()]);
    if (own[seen.host]) assert.deepEqual(VALUES.filter((x) => text.includes(x)), [own[seen.host]], seen.host);
    assert.ok(!text.includes(AWS.secret));
  }
  const sts = stub.requests.find((r) => r.host === "sts.amazonaws.com");
  assert.equal(sts.headers["x-amz-date"], "20261003T120000Z");
  assert.ok(sigv4Holds(sts, AWS.secret));
  assert.ok(!sigv4Holds({ ...sts, body: Buffer.concat([sts.body, Buffer.from("&x=1")]) }, AWS.secret));
});

test("a credential asked twice is asked once; one not in the format is never sent", { skip: SKIP }, async () => {
  reset(SCRIPT);
  const v = new Verifier({ transport: through(tunnel) });
  const [a, b] = await v.verifyAll([["github", GITHUB], ["github", GITHUB]]);
  assert.deepEqual([a.outcome, b.outcome, stub.requests.length], [LIVE, LIVE, 1]);
  assert.equal((await v.verify("github", GITHUB)).outcome, LIVE);
  assert.equal(stub.requests.length, 1);
  for (const bad of ["ghp_short", GITHUB + "\n", { token: GITHUB }, 5]) {
    assert.deepEqual([(await v.verify("github", bad)).detail], [NOT_THIS_FORMAT]);
  }
  assert.equal(stub.requests.length, 1);
  await assert.rejects(v.verify("nonesuch", GITHUB));
});

test("the run's limits: calls, time, and two calls at once to one provider", { skip: SKIP }, async () => {
  let inFlight = 0, most = 0, calls = 0;
  const slow = async () => {
    calls++; inFlight++; most = Math.max(most, inFlight);
    await new Promise((r) => setTimeout(r, 30));
    inFlight--;
    return { status: 401, headers: {}, body: Buffer.alloc(0), truncated: false };
  };
  const tokens = Array.from({ length: 8 }, (_, k) => "ghp_" + String(k).repeat(36));
  await new Verifier({ transport: slow }).verifyAll(tokens.map((t) => ["github", t]), 8);
  assert.equal(most, 2);
  calls = 0;
  const capped = await new Verifier({ transport: slow, maxCalls: 3 }).verifyAll(tokens.map((t) => ["github", t]));
  assert.equal(calls, 3);
  assert.equal(capped.filter((r) => r.detail === "the limit on verification calls is reached").length, 5);
  let now = 0;
  const v = new Verifier({ transport: slow, budgetMs: 100, clock: () => now });
  assert.equal((await v.verify("github", tokens[0])).outcome, REJECTED);
  now = 101;
  assert.equal((await v.verify("github", tokens[1])).detail, "the time budget for verification is spent");
});

test("a failed call is unknown, never rejected, and says why", { skip: SKIP }, async () => {
  for (const [k, words] of [["timeout", "the provider did not answer in time"], ["tls", "the provider's certificate could not be checked"],
    ["redirect", "the provider answered with a redirect, which is not followed"], ["connection", "the provider could not be reached"]]) {
    const v = new Verifier({ transport: async () => { throw new TransportError(k); } });
    assert.deepEqual(await v.verify("github", GITHUB), { provider: "github", outcome: UNKNOWN, detail: words, who: null, status: null });
  }
  const odd = new Verifier({ transport: async () => { throw new RangeError("x " + GITHUB); } });
  assert.equal((await odd.verify("github", GITHUB)).detail, "the call failed unexpectedly (RangeError)");
  assert.equal(amzDate(new Date(Date.UTC(2015, 7, 30, 12, 36))), "20150830T123600Z");
});

// ---------------------------------------------------------------------------------------------- the scan

function project(name, app = APP, env = ENV) {
  const root = join(dir, name);
  mkdirSync(root);
  writeFileSync(join(root, "app.py"), app);
  if (env !== null) writeFileSync(join(root, ".env"), env);
  return root;
}

async function scan(root, extra, verifier) {
  const reports = join(dir, `${basename(root)}-reports`);
  mkdirSync(reports, { recursive: true });
  const out = [], err = [];
  const code = await run([root, "--json", join(reports, "r.json"), "--html", join(reports, "r.html"), "--sarif", join(reports, "r.sarif"),
    "--force-overwrite", ...extra], { out: (s) => out.push(s), err: (s) => err.push(s), verifier });
  const written = Object.fromEntries(readdirSync(reports).map((n) => [n, readFileSync(join(reports, n), "utf8")]));
  return { code, out: out.join("\n"), err: err.join("\n"), written };
}

test("without the flag nothing is asked; with it, the note, the outcomes, and no output holds a value", { skip: SKIP }, async () => {
  const root = project("cli");
  reset(SCRIPT);
  const plain = await scan(root, [], new Verifier({ transport: through(tunnel) }));
  assert.equal(stub.requests.length, 0);
  assert.equal(JSON.parse(plain.written["r.json"]).verification, undefined);
  assert.ok(!plain.err.includes("--verify-secrets"));
  const r = await scan(root, ["--verify-secrets"], new Verifier({ transport: through(tunnel) }));
  assert.equal(r.code, 0);
  assert.equal(stub.requests.length, 5);
  assert.match(r.err, /^note: --verify-secrets: asking 5 providers whether 5 credentials are live, each sent to its own provider alone/);
  assert.match(r.out, /Secrets verified {2}2 live, 2 rejected, 1 unknown \(of 5 asked about\); 1 secret finding no provider can be asked about/);
  const report = JSON.parse(r.written["r.json"]);
  assert.deepEqual(report.verification.credentials, { live: 2, rejected: 2, unknown: 1 });
  // (the .env line's two findings, S-SECRET by the name and S-TOKEN by the format, are its one credential's)
  assert.deepEqual(report.verification.findings, { live: 3, rejected: 3, unknown: 1, notVerified: 1 });
  const verified = Object.fromEntries(report.issues.filter((i) => i.file === "app.py" && i.verified).map((i) => [i.line, i.verified.outcome]));
  assert.deepEqual(verified, { 2: LIVE, 3: REJECTED, 4: UNKNOWN, 5: LIVE, 6: LIVE });
  const github = report.issues.find((i) => i.file === "app.py" && i.line === 2);
  assert.ok(github.msg.endsWith("Verified live: the provider accepts this GitHub token (the account: octocat). Revoke it now."));
  const sarif = JSON.parse(r.written["r.sarif"]).runs[0].results;
  assert.deepEqual(sarif.filter((x) => x.properties).map((x) => x.properties.verified.outcome).sort(),
    [LIVE, LIVE, LIVE, REJECTED, REJECTED, REJECTED, UNKNOWN]);
  assert.equal(report.pass, false);
  for (const text of [r.out, r.err, ...Object.values(r.written)]) {
    for (const value of VALUES) assert.ok(!text.includes(value), value);
  }
  assert.equal((await scan(root, ["--verify-secrets", "--ci"], new Verifier({ transport: through(tunnel) }))).code, 1);
});

test("the help names the flag, and the bin waits for a verifying scan", { skip: SKIP }, () => {
  const out = [];
  run(["--help"], { out: (s) => out.push(s) });
  assert.match(out.join("\n"), /--verify-secrets/);
  const bin = readFileSync(new URL("../bin/lazaret.js", import.meta.url), "utf8");
  assert.match(bin, /code\.then/);
});
