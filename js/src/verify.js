// `lazaret --verify-secrets` (0.1.9, V-1 stage 2, step 4): the npm package's runner of live secret verification, the twin
// of the Python package's scanner/verifyscan.py, secretverify.py and secretverify_http.py.
//
// John's decision 4 (Oct 7): "Let's follow trufflehog behavior. Verify is an explicit flag -- detection of secret is
// default without verification it is live." Decision 7: the provider table and the logic are the engine's (the pack's
// _VERIFY_PROVIDERS, rust/crates/lazaret-engine/src/secrets.rs: `secrets.find`, `secrets.request`, `secrets.judge`,
// `secrets.providers`), one copy for both packages; each package makes only the HTTPS call. This module keeps what is
// about a run (the cache, keyed by provider, endpoint and the credential's SHA-256; the budgets, 120 seconds and 500
// calls; two calls at once to one provider) and makes the call over node:https: the provider's host alone, port 443,
// TLS 1.2 at least (Lazaret's floor on every transport), no redirect followed (a 3xx that names a Location is
// "redirect"), the body read to 64 KiB and the rest not read, one deadline for the whole call; HTTPS_PROXY through an
// http:// proxy's CONNECT tunnel (an https:// proxy is refused, and nothing is sent without it). A failed call is
// unknown, never rejected. The values are never kept: not in an issue, a report or a file.

import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { createHash } from "node:crypto";
import { call } from "./lib/native.js";
import { SECRET_RULES } from "./lib/redact.js";
import { regrade } from "./report.js";

export const LIVE = "live", REJECTED = "rejected", UNKNOWN = "unknown";
export const OUTCOMES = [LIVE, REJECTED, UNKNOWN];
export const MAX_ANSWER_BYTES = 64 * 1024;
export const DEFAULT_TIMEOUT_MS = 10_000;
export const USER_AGENT = "lazaret-secret-verify";
export const NOT_THIS_FORMAT = "not this provider's format, so nothing was sent";
const MAX_HEADERS = 64, MAX_HEADER_VALUE = 512, MAX_PATH = 2000;
const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const RANK = { live: 0, unknown: 1, rejected: 2 };
// (secretverify._TRANSPORT_WORDS)
const TRANSPORT_WORDS = {
  timeout: "the provider did not answer in time",
  connection: "the provider could not be reached",
  tls: "the provider's certificate could not be checked",
  proxy: "the proxy could not be used",
  refused: "the request was not allowed",
  redirect: "the provider answered with a redirect, which is not followed",
};
const HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;
const PATH_RE = new RegExp(`^/[\\x21-\\x7e]{0,${MAX_PATH - 1}}$`);
const NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;
const VALUE_RE = new RegExp(`^[\\x20-\\x7e]{0,${MAX_HEADER_VALUE}}$`);
const OWN = new Set(["host", "content-length", "transfer-encoding", "connection"]);

/** The request did not get an answer. `kind`: timeout, connection, tls, proxy, redirect or refused. */
export class TransportError extends Error {
  constructor(kind, message = "") {
    super(message ? `${kind}: ${message}` : kind);
    this.name = "TransportError";
    this.kind = kind;
  }
}

/** `request` if it may be sent (secretverify_http.check_request); a TransportError("refused") if not. */
export function checkRequest(request) {
  const refuse = (m) => { throw new TransportError("refused", m); };
  if (!request || !["GET", "POST"].includes(request.method)) refuse("not a request this module sends");
  if (typeof request.host !== "string" || request.host.length > 253 || !HOST_RE.test(request.host)) refuse("the host is not a lower-case DNS name");
  if (typeof request.path !== "string" || !PATH_RE.test(request.path)) refuse("the path is not printable ASCII that starts with /");
  const headers = request.headers;
  if (!Array.isArray(headers) || headers.length > MAX_HEADERS) refuse("the headers are not a small list");
  for (const pair of headers) {
    const [name, value] = Array.isArray(pair) ? pair : [];
    if (typeof name !== "string" || !NAME_RE.test(name) || typeof value !== "string" || !VALUE_RE.test(value)) refuse("a header is not printable ASCII");
    if (OWN.has(name.toLowerCase())) refuse(`the ${name.toLowerCase()} header is the transport's`);
  }
  if (request.body !== null && request.body !== undefined && typeof request.body !== "string") refuse("the body is not text");
  return request;
}

/** urllib.request.proxy_bypass_environment: does NO_PROXY (`no`) name `host`? */
function bypassed(host, no) {
  if (!no) return false;
  if (no.trim() === "*") return true;
  host = host.toLowerCase();
  for (let name of no.split(",")) {
    name = name.trim().replace(/^\.+/, "").toLowerCase();
    if (!name) continue;
    if (host === name || host.endsWith("." + name)) return true;
  }
  return false;
}

/** The http:// proxy to tunnel through to `host` ({host, port, headers}), or null (secretverify_http._proxy). */
export function proxyFor(host, env) {
  const value = env.HTTPS_PROXY || env.https_proxy;
  if (!value) return null;
  if (bypassed(host, env.NO_PROXY || env.no_proxy)) return null;
  let url;
  try {
    url = new URL(value.includes("//") ? value : "http://" + value);
  } catch {
    throw new TransportError("proxy", "the proxy's address is not one");
  }
  if (url.protocol !== "http:" || !url.hostname) throw new TransportError("proxy", "only an http:// proxy is supported");
  const headers = {};
  if (url.username || url.password) {
    const raw = `${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`;
    headers["Proxy-Authorization"] = "Basic " + Buffer.from(raw, "utf8").toString("base64");
  }
  return { host: url.hostname.replace(/^\[|\]$/g, ""), port: Number(url.port || 80), headers };
}

// (OpenSSL's errors through node:tls: its certificate checks by name, ERR_SSL_* and ERR_TLS_*, and EPROTO, which a
// handshake the server ends with an alert gives a request, as a server below TLS 1.2 does)
const TLS_CODE_RE = /^(?:ERR_SSL_|ERR_TLS_|EPROTO$)|CERT|UNABLE_TO_(?:VERIFY|GET)|SELF_SIGNED|HOSTNAME_MISMATCH/;

/** A socket or TLS failure as a TransportError (its kind; Node's message is not kept: it may name the host). */
function failure(e, { proxy = false, tunnelled = true } = {}) {
  if (e instanceof TransportError) return e;
  const code = String(e && e.code || "");
  if (TLS_CODE_RE.test(code)) return new TransportError("tls", code);
  if (proxy && !tunnelled) return new TransportError("proxy", code || "the proxy could not be reached");
  return new TransportError("connection", code || (e && e.name) || "the connection failed");
}

/**
 * A `send(request, timeoutMs, maxBytes) -> Promise<{status, headers, body, truncated}>` over node:https. `env` is where the
 * proxy settings are read (the process's by default). `ca` (tests) is the trust anchors in place of Node's.
 */
export function httpsTransport({ env = process.env, ca = undefined } = {}) {
  return function send(request, timeoutMs = DEFAULT_TIMEOUT_MS, maxBytes = MAX_ANSWER_BYTES) {
    try {
      checkRequest(request);
      if (!Number.isInteger(maxBytes) || maxBytes < 1) throw new TransportError("refused", "no room for an answer");
    } catch (e) {
      return Promise.reject(e);
    }
    let proxy;
    try { proxy = proxyFor(request.host, env); } catch (e) { return Promise.reject(e); }
    return new Promise((resolve, reject) => {
      let done = false, tunnelled = !proxy, req = null, tunnel = null;
      const finish = (error, value) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        if (req) req.destroy();
        if (tunnel) tunnel.destroy();
        if (error) reject(error); else resolve(value);
      };
      const timer = setTimeout(() => finish(new TransportError("timeout", "no answer in time")), timeoutMs);
      const headers = { "User-Agent": USER_AGENT, "Accept-Encoding": "identity", Connection: "close" };
      for (const [name, value] of request.headers) {
        for (const k of Object.keys(headers)) if (k.toLowerCase() === name.toLowerCase()) delete headers[k];
        headers[name] = value;
      }
      const body = request.body === null || request.body === undefined ? null : Buffer.from(request.body, "utf8");
      if (body !== null) headers["Content-Length"] = String(body.length);
      const tlsOptions = { servername: request.host, minVersion: "TLSv1.2", ALPNProtocols: ["http/1.1"], ...(ca ? { ca } : {}) };
      const start = (socket) => {
        if (done) { if (socket) socket.destroy(); return; }
        // (defaultPort: the Host field is the host alone, as AWS's signature holds it, with or without an agent)
        const options = { host: request.host, port: 443, defaultPort: 443, path: request.path, method: request.method, headers,
          ...tlsOptions };
        // (a request with an agent connects on its own, to the host: a tunnel's socket is given with no agent at all)
        if (socket) options.createConnection = () => tls.connect({ ...tlsOptions, socket });
        else options.agent = false;
        req = https.request(options, (res) => {
          if (REDIRECTS.has(res.statusCode) && res.headers.location !== undefined) {
            finish(new TransportError("redirect", "the provider answered with a redirect, which is not followed"));
            return;
          }
          const chunks = [];
          let total = 0;
          const seen = {};
          const raw = res.rawHeaders;
          for (let k = 0; k + 1 < raw.length && k < 2 * MAX_HEADERS; k += 2) {
            const name = raw[k].toLowerCase();
            if (!Object.hasOwn(seen, name)) seen[name] = raw[k + 1].slice(0, MAX_HEADER_VALUE);
          }
          const answer = (truncated) => finish(null, { status: res.statusCode, headers: seen,
            body: Buffer.concat(chunks, total).subarray(0, maxBytes), truncated });
          res.on("data", (chunk) => {
            if (done) return;
            chunks.push(chunk);
            total += chunk.length;
            if (total > maxBytes) answer(true);
          });
          res.on("end", () => answer(false));
          res.on("close", () => { if (!res.complete) finish(new TransportError("connection", "the answer was cut short")); });
          res.on("error", (e) => finish(failure(e)));
        });
        req.on("error", (e) => finish(failure(e)));
        req.end(body ?? undefined);
      };
      if (!proxy) {
        start(null);
        return;
      }
      tunnel = http.request({ host: proxy.host, port: proxy.port, method: "CONNECT", path: `${request.host}:443`,
        headers: { Host: `${request.host}:443`, ...proxy.headers }, agent: false });
      tunnel.on("connect", (res, socket) => {
        if (res.statusCode !== 200) {
          socket.destroy();
          finish(new TransportError("proxy", `the proxy answered ${res.statusCode}`));
          return;
        }
        tunnelled = true;
        socket.on("error", (e) => finish(failure(e)));
        start(socket);
      });
      tunnel.on("error", (e) => finish(failure(e, { proxy: true, tunnelled })));
      tunnel.end();
    });
  };
}

/** YYYYMMDDTHHMMSSZ of `date` (UTC): the time AWS's signature holds. */
export function amzDate(date) {
  return date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}

/** The providers of the engine's table: [{id, label, host, path, parts}]. */
export function providers() {
  return call("secrets.providers");
}

/** A counting semaphore. */
class Slots {
  constructor(n) { this.free = n; this.waiting = []; }
  async take() {
    if (this.free > 0) { this.free--; return; }
    await new Promise((resolve) => this.waiting.push(resolve));
  }
  give() {
    const next = this.waiting.shift();
    if (next) next(); else this.free++;
  }
}

/** Asks providers whether credentials are live, for one run (secretverify.Verifier). */
export class Verifier {
  constructor({ transport = null, timeoutMs = DEFAULT_TIMEOUT_MS, budgetMs = 120_000, maxCalls = 500, perProvider = 2,
    clock = () => performance.now(), now = () => new Date() } = {}) {
    this.transport = transport ?? httpsTransport();
    this.timeoutMs = timeoutMs;
    this.budgetMs = budgetMs;
    this.maxCalls = maxCalls;
    this.clock = clock;
    this.now = now;
    this.started = null;
    this.calls = 0;
    this.cache = new Map();
    this.byId = new Map(providers().map((p) => [p.id, p]));
    this.slots = new Map([...this.byId.keys()].map((id) => [id, new Slots(perProvider)]));
    this.requests = [];                                  // [provider, host, path] of each call made
  }

  static parts(credential) {
    if (typeof credential === "string") credential = { secret: credential };
    if (!credential || typeof credential !== "object" || Array.isArray(credential)
        || !Object.entries(credential).every(([k, v]) => typeof k === "string" && typeof v === "string")) return null;
    return { ...credential };
  }

  key(provider, parts) {
    const text = Object.keys(parts).sort().map((name) => `${name}=${parts[name]}`).join("\0");
    return `${provider.id}\0${provider.host}${provider.path}\0${createHash("sha256").update(text, "utf8").digest("hex")}`;
  }

  admit() {
    const now = this.clock();
    if (this.started === null) this.started = now;
    if (now - this.started > this.budgetMs) return "the time budget for verification is spent";
    if (this.calls >= this.maxCalls) return "the limit on verification calls is reached";
    this.calls++;
    return null;
  }

  /** One credential (a secret, or a pair's parts) -> {provider, outcome, detail, who, status}. Never rejects but for an unknown provider. */
  async verify(pid, credential) {
    const provider = this.byId.get(pid);
    if (!provider) throw new Error(`no provider ${pid}`);
    const result = (outcome, detail, who = null, status = null) => ({ provider: pid, outcome, detail, who, status });
    const parts = Verifier.parts(credential);
    if (parts === null) return result(UNKNOWN, NOT_THIS_FORMAT);
    let request;
    try {
      const answer = call("secrets.request", { provider: pid, parts, time: amzDate(this.now()) });
      if (answer.refused !== undefined) return result(UNKNOWN, NOT_THIS_FORMAT);
      request = answer;
    } catch (e) {
      return result(UNKNOWN, `the request could not be made (${e && e.name || "Error"})`);
    }
    const key = this.key(provider, parts);
    if (this.cache.has(key)) return this.cache.get(key);
    const refused = this.admit();
    if (refused) return result(UNKNOWN, refused);
    const secrets = Object.values(parts).sort((a, b) => b.length - a.length);
    const slot = this.slots.get(pid);
    let response;
    await slot.take();
    try {
      this.requests.push([pid, request.host, request.path]);
      response = await this.transport(request, this.timeoutMs, MAX_ANSWER_BYTES);
    } catch (e) {
      if (e instanceof TransportError) return result(UNKNOWN, TRANSPORT_WORDS[e.kind] ?? "the call failed");
      return result(UNKNOWN, `the call failed unexpectedly (${e && e.name || "Error"})`);
    } finally {
      slot.give();
    }
    let judged;
    try {
      const body = Buffer.isBuffer(response.body) ? response.body : Buffer.alloc(0);
      judged = call("secrets.judge", { provider: pid, status: Math.trunc(Number(response.status)),
        truncated: Boolean(response.truncated) || body.length > MAX_ANSWER_BYTES, secrets },
        body.subarray(0, MAX_ANSWER_BYTES).toString("latin1"));
    } catch (e) {
      return result(UNKNOWN, `the answer could not be read (${e && e.name || "Error"})`);
    }
    const [outcome, detail, who] = judged;
    const got = result(outcome, detail, who, response.status);
    if (outcome !== UNKNOWN) this.cache.set(key, got);
    return got;
  }

  /** [[provider, credential], …] -> results in the same order; the same credential asked twice is asked once. */
  async verifyAll(items, workers = 4) {
    const ident = ([pid, c]) => JSON.stringify([pid, typeof c === "string" ? c : Object.entries(c ?? {}).sort()]);
    const unique = new Map();
    for (const item of items) if (!unique.has(ident(item))) unique.set(ident(item), item);
    const queue = [...unique.entries()];
    const done = new Map();
    const worker = async () => {
      for (let next = queue.shift(); next; next = queue.shift()) done.set(next[0], await this.verify(...next[1]));
    };
    await Promise.all(Array.from({ length: Math.max(1, Math.min(workers, queue.length)) }, worker));
    return items.map((item) => done.get(ident(item)));
  }
}

/** The note before the first call: which providers will be asked, how many credentials each, and where they go. */
export function notice(asked, err) {
  const total = asked.reduce((n, a) => n + a.credentials, 0);
  const where = asked.map((a) => `${a.label} at ${a.host} (${a.credentials})`).join(", ");
  err(`note: --verify-secrets: asking ${asked.length} provider${asked.length !== 1 ? "s" : ""} whether ${total} `
    + `credential${total !== 1 ? "s are" : " is"} live, each sent to its own provider alone, over HTTPS: ${where}`);
}

function mark(issue, result, label) {
  issue.verified = { outcome: result.outcome, provider: result.provider, label, who: result.who, detail: result.detail };
  if (result.outcome === LIVE) {
    issue.sev = "BLOCKER";
    issue.type = "VULN";
    const whose = result.who ? ` (the account: ${result.who})` : "";
    issue.msg += ` Verified live: the provider accepts this ${label}${whose}. Revoke it now.`;
  } else if (result.outcome === REJECTED) {
    issue.msg += ` Verified rejected: ${result.detail}. Revoke it anyway: the history keeps it.`;
  } else {
    issue.msg += ` Not verified: ${result.detail}.`;
  }
}

/**
 * Verify the secret findings of `res` in place (verifyscan.verify_findings): each finding of a credential a provider names
 * gets `verified`, the result is graded again and gets `verification`. `linesOf(file)` gives a file's lines as the scan
 * numbered them (or null); `err` takes the note before the first call. Resolves to `res.verification`.
 */
export async function verifyFindings(res, linesOf, { verifier = null, err = (s) => console.error(s) } = {}) {
  const findings = res.issues.filter((i) => SECRET_RULES.has(i.rule) && typeof i.file === "string" && Number.isInteger(i.line));
  const byFile = new Map();
  for (const issue of findings) {
    if (!byFile.has(issue.file)) byFile.set(issue.file, []);
    byFile.get(issue.file).push(issue);
  }
  const credentials = [];                                  // [file, {provider, parts, lines}]
  for (const [file, issues] of byFile) {
    const lines = linesOf(file);
    if (!lines) continue;
    const numbers = [...new Set(issues.map((i) => i.line))].filter((n) => n > 0 && n <= lines.length).sort((a, b) => a - b);
    if (!numbers.length) continue;
    for (const found of call("secrets.find", { lines: numbers }, numbers.map((n) => lines[n - 1]).join("\n"))) {
      credentials.push([file, found]);
    }
  }
  const labels = new Map(providers().map((p) => [p.id, [p.label, p.host]]));
  const asked = new Map();
  for (const [, f] of credentials) asked.set(f.provider, (asked.get(f.provider) ?? 0) + 1);
  const summary = {
    providers: [...asked].map(([pid, n]) => ({ provider: pid, label: labels.get(pid)[0], host: labels.get(pid)[1], credentials: n })),
    credentials: { live: 0, rejected: 0, unknown: 0 },
    findings: { live: 0, rejected: 0, unknown: 0, notVerified: 0 },
  };
  let results = [];
  if (credentials.length) {
    notice(summary.providers, err);
    const v = verifier ?? new Verifier();
    results = await v.verifyAll(credentials.map(([, f]) => {
      const names = Object.keys(f.parts);
      return [f.provider, names.length === 1 && names[0] === "secret" ? f.parts.secret : { ...f.parts }];
    }));
  }
  const best = new Map();
  credentials.forEach(([file, found], k) => {
    const result = results[k];
    summary.credentials[result.outcome]++;
    for (const n of found.lines) {
      const key = `${file}\0${n}`;
      const held = best.get(key);
      if (!held || RANK[result.outcome] < RANK[held.outcome]) best.set(key, result);
    }
  });
  for (const issue of findings) {
    const result = best.get(`${issue.file}\0${issue.line}`);
    if (!result) { summary.findings.notVerified++; continue; }
    summary.findings[result.outcome]++;
    mark(issue, result, (labels.get(result.provider) ?? [result.provider])[0]);
  }
  res.verification = summary;
  regrade(res);
  return summary;
}
