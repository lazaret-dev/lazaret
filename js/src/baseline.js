// Baselines (new-code focus) — twin of lazaret.scanner.reports fingerprint /
// sign_fingerprints / verify_signature and core.apply_baseline.
//
// Trust (G17): the engine marker is a public constant, so a hand-written
// "baseline" carrying it could zero `newIssues`. Therefore:
//   * $LAZARET_BASELINE_KEY set: JSON reports carry an HMAC-SHA256 signature
//     over their fingerprints, and a baseline is trusted only if its
//     signature verifies with that key (wherever it lives);
//   * no key: a baseline inside the scanned tree is untrusted (the scanned
//     repository could have planted it); outside it the marker check applies.
// An untrusted baseline counts every finding as new (fail closed).
//
// Signature serialization (shared with the Python engine):
//   HMAC-SHA256(key = UTF-8(LAZARET_BASELINE_KEY),
//               b"lazaret-baseline-v1\n" + json.dumps(sorted(set(fingerprints)),
//                                                    ensure_ascii=True, separators=(",", ":")))
//   stored as {"alg": "HMAC-SHA256", "value": <hex>} under "baselineSignature".

import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, realpathSync } from "node:fs";
import { sep } from "node:path";
import { isOurReport } from "./lib/fs.js";
import { pyStrip, pyStr, cmpCodePoints, MAX_JSON_DEPTH } from "./lib/pycompat.js";
import { pyJsonParse } from "./lib/pyjson.js";

export const BASELINE_KEY_ENV = "LAZARET_BASELINE_KEY";
export const SIGNATURE_FIELD = "baselineSignature";
export const SIGNATURE_ALG = "HMAC-SHA256";
const DOMAIN = "lazaret-baseline-v1\n";

class Malformed extends Error {}
const isNum = (v) => typeof v === "number" || typeof v === "boolean";

/** rule|path|flagged-line fingerprint; throws Malformed where Python raises KeyError/TypeError/AttributeError. */
export function fingerprint(issue) {
  if (issue === null || typeof issue !== "object" || Array.isArray(issue)) throw new Malformed();
  if (!("line" in issue) || !("snipStart" in issue) || !isNum(issue.line) || !isNum(issue.snipStart)) throw new Malformed();
  const idx = Number(issue.line) - Number(issue.snipStart);
  let snippet = issue.snippet;
  if (!snippet || (typeof snippet === "object" && !Array.isArray(snippet) && !Object.keys(snippet).length)) snippet = [];
  if (isNum(snippet)) throw new Malformed();
  let lineText = "";
  const len = typeof snippet === "string" ? Array.from(snippet).length
    : Array.isArray(snippet) ? snippet.length : Object.keys(snippet).length;
  if (idx >= 0 && idx < len) {
    if (!Number.isInteger(idx)) throw new Malformed();
    const v = typeof snippet === "string" ? Array.from(snippet)[idx] : Array.isArray(snippet) ? snippet[idx] : undefined;
    if (typeof v !== "string") throw new Malformed();
    lineText = pyStrip(v);
  }
  if (!("file" in issue) || !("rule" in issue)) throw new Malformed();
  const path = pyStr(issue.file).replace(/\\/g, "/");
  return `${pyStr(issue.rule)}|${path}|${lineText}`;
}

function fingerprints(issues) {
  const out = [];
  let skipped = 0;
  for (const i of Array.isArray(issues) ? issues : []) {
    try { out.push(fingerprint(i)); } catch (e) { if (e instanceof Malformed) skipped++; else throw e; }
  }
  return { out, skipped };
}

/** json.dumps(str, ensure_ascii=True) */
function jsonAscii(s) {
  let out = '"';
  for (let k = 0; k < s.length; k++) {
    const c = s.charCodeAt(k);
    const ch = s[k];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** Hex HMAC-SHA256 over the canonical serialization of `fps` (see the header). */
export function signFingerprints(fps, key) {
  const canon = "[" + [...new Set(fps)].sort(cmpCodePoints).map(jsonAscii).join(",") + "]";
  return createHmac("sha256", Buffer.from(key, "utf8")).update(Buffer.from(DOMAIN + canon, "utf8")).digest("hex");
}

/** The signature object a JSON report carries when a key is configured (else null). */
export function reportSignature(res, key) {
  if (!key) return null;
  return { alg: SIGNATURE_ALG, value: signFingerprints(fingerprints(res.issues).out, key) };
}
/** Back-compatible helper: the signature value for a list of issues. */
export function baselineSignature(issues, key) {
  return signFingerprints(fingerprints(issues).out, key);
}

function verifySignature(doc, key) {
  if (doc === null || typeof doc !== "object" || Array.isArray(doc)) return [false, "not a JSON object"];
  const sig = doc[SIGNATURE_FIELD];
  if (!sig || typeof sig !== "object" || Array.isArray(sig) || typeof sig.value !== "string")
    return [false, "it carries no baseline signature"];
  if (sig.alg !== SIGNATURE_ALG) return [false, "unsupported signature algorithm"];
  const want = Buffer.from(signFingerprints(fingerprints(doc.issues).out, key), "utf8");
  const got = Buffer.from(sig.value, "utf8");
  if (want.length !== got.length || !timingSafeEqual(want, got))
    return [false, `its signature does not verify with $${BASELINE_KEY_ENV} (forged, edited, or signed with another key)`];
  return [true, ""];
}

/** Does `path` resolve (symlinks followed) inside directory `root`? */
export function pathIsInside(path, root) {
  try {
    const p = realpathSync(path), r = realpathSync(root);
    return p === r || p.startsWith(r.endsWith(sep) ? r : r + sep);
  } catch {
    return false;
  }
}

const pyTypeName = (v) => (v === null ? "NoneType" : Array.isArray(v) ? "list" : typeof v === "string" ? "str"
  : typeof v === "boolean" ? "bool" : typeof v === "number" ? (Number.isInteger(v) ? "int" : "float") : "dict");

/**
 * Apply a baseline to a scan result (mutates res): each issue gets `new`,
 * res gets `newIssues` (and `baselineUntrusted` when the baseline was not
 * trusted). `warn` receives warning lines.
 */
export function applyBaseline(res, baselinePath, { root = null, warn = () => {}, env = process.env } = {}) {
  const untrusted = (reason) => {
    warn(`warning: baseline ${baselinePath} ${reason} — treating it as untrusted: all current findings are counted as new`);
    for (const i of res.issues) i.new = true;
    res.newIssues = res.issues.length;
    res.baselineUntrusted = true;
  };
  if (!isOurReport(baselinePath, "json")) {
    untrusted("is not a report produced by this engine (no matching engine marker, or wrong shape)");
    return;
  }
  const key = env[BASELINE_KEY_ENV] || null;
  if (!key && root && pathIsInside(baselinePath, root)) {
    untrusted(`is inside the scanned tree and $${BASELINE_KEY_ENV} is not set (the scanned repository could have planted it) — keep baselines outside the scanned tree (e.g. in $RUNNER_TEMP) or set ${BASELINE_KEY_ENV} so reports are signed`);
    return;
  }
  let prev;
  try {
    const r = pyJsonParse(readFileSync(baselinePath, "utf8"));
    if (r.depth) throw new Error(`JSON nested deeper than ${MAX_JSON_DEPTH} levels`);   // core.JsonTooDeep
    if (!r.ok) throw new Error("the baseline is not valid JSON");
    prev = r.value;
  } catch (e) {
    warn(`warning: could not read baseline ${baselinePath}: ${e.message}`);
    return;
  }
  if (prev === null || typeof prev !== "object" || Array.isArray(prev)) {
    warn(`warning: baseline ${baselinePath}: top level is ${pyTypeName(prev)}, not an object — expected {"issues": [...]}; baseline ignored`);
    return;
  }
  const issues = Object.prototype.hasOwnProperty.call(prev, "issues") ? prev.issues : [];
  if (!Array.isArray(issues)) {
    warn(`warning: baseline ${baselinePath}: 'issues' is ${pyTypeName(issues)}, not a list — baseline ignored`);
    return;
  }
  if (key) {
    const [ok, why] = verifySignature(prev, key);
    if (!ok) { untrusted(`is not trusted: ${why}`); return; }
  }
  const { out, skipped } = fingerprints(issues);
  const known = new Set(out);
  if (skipped) warn(`warning: baseline ${baselinePath}: ${skipped} malformed issue entrie(s) skipped (expected objects with rule/file/line)`);
  let n = 0;
  for (const i of res.issues) {
    let fp = null;
    try { fp = fingerprint(i); } catch { /* our own issues are well-formed */ }
    i.new = !known.has(fp);
    if (i.new) n++;
  }
  res.newIssues = n;
}
