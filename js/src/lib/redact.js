// Secret redaction (audit L1, shared semantics spec 6) — leaf module.
//
// The flagged line of a SECRET-rule finding is replaced by a deterministic
// placeholder, and every other snippet line (and the issue msg, and any
// field that copies source text such as an install hook's `cmd`) has
// credential-shaped substrings replaced by "[redacted]". The pattern list is
// copied verbatim from lazaret.scanner.core._SECRET_LINE_PATTERNS (with the
// SQL credential pattern case-insensitive); PEM private-key blocks are
// redacted line by line from BEGIN through END; high-entropy literals the
// S-ENTROPY heuristic would flag are redacted wherever they appear as a
// whole token in any snippet line. mkIssue() applies all of it, so the
// library API (`import { scanFile } from "lazaret"`) is covered too.

import { pyRe, cpLen } from "./pycompat.js";

export const SECRET_RULES = new Set(["S-SECRET", "S-TOKEN", "SQL-CRED", "S-ENTROPY"]);
export const REDACT_PLACEHOLDER = "[redacted: secret rule {RULE}]";
export const REDACT_FINGERPRINT = "[redacted: secret rule ";

/** Global switch (--no-redact-secrets turns it off for the run). */
export const REDACT = { on: true };
export function setRedactSecrets(on) { REDACT.on = !!on; }

// ---- entropy heuristic (twin of core.shannon_entropy / entropy_secretish) --
export function shannonEntropy(s) {
  if (!s) return 0;
  const f = new Map();
  let n = 0;
  for (const ch of s) { f.set(ch, (f.get(ch) || 0) + 1); n++; }
  let e = 0;
  for (const c of f.values()) e -= (c / n) * Math.log2(c / n);
  return e;
}
export const ENTROPY_VALUE_RE = pyRe(String.raw`[=:]\s*[\"']([A-Za-z0-9+/=_\-]{20,})[\"']`);
const ENTROPY_VALUE_G = new RegExp(ENTROPY_VALUE_RE.source, "gu");

/** A high-entropy literal that looks like a credential, not a path/identifier. */
export function entropySecretish(v) {
  if ((v.match(/\//g) || []).length >= 2 || v.startsWith("/") || v.includes(" ") || v.includes("\\")) return false;
  const core = v.replace(/[_.\-]/g, "");
  if (/^[A-Za-z]+$/.test(core)) return false;
  if (!(/[0-9]/.test(v) || /[+=]/.test(v))) return false;
  return shannonEntropy(v) > 4.0;
}

// ---- provider token signatures, matched in linear time --------------------
// Same language as the S-TOKEN rule regex
//   AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}
//   |sk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_\-]{35}
//   |-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}
// but without the backtracking blow-up of the JWT alternative on a run of
// "eyJeyJeyJ…" (every head rescanned the whole run: quadratic).
const HEAD_RE = /AKIA|gh[pousr]_|xox[baprs]-|sk_live_|AIza|-----BEGIN |eyJ/g;
const HEAD_RE_REDACT = /AKIA|gh[pousr]_|github_pat_|xox[baprs]-|sk_live_|AIza|-----BEGIN |eyJ/g;
const PEM_END_G = /-----END [A-Z ]*PRIVATE KEY-----/g;
const isPat = (c) => isAlnum(c) || c === 95;                     // [A-Za-z0-9_]
const isUpperDigit = (c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90);
const isAlnum = (c) => isUpperDigit(c) || (c >= 97 && c <= 122);
const isJwt = (c) => isAlnum(c) || c === 95 || c === 45;          // [A-Za-z0-9_-]
const isXox = (c) => isAlnum(c) || c === 45;                      // [A-Za-z0-9-]
const isPemName = (c) => (c >= 65 && c <= 90) || c === 32;        // [A-Z ]
function runEnd(s, i, pred) { while (i < s.length && pred(s.charCodeAt(i))) i++; return i; }
function fixedRun(s, i, n, pred) {
  if (i + n > s.length) return false;
  for (let k = i; k < i + n; k++) if (!pred(s.charCodeAt(k))) return false;
  return true;
}

/**
 * Leftmost S-TOKEN match at or after `from`: {index, end, text} or null.
 * `redact` switches to the redaction pattern (core._SECRET_LINE_PATTERNS[0]):
 * gh[pousr]_ takes 36+ characters, github_pat_… tokens count, and a PEM
 * header takes the rest of the line (through a same-line END marker).
 */
export function findSecretToken(s, from = 0, { redact = false } = {}) {
  const head = new RegExp(redact ? HEAD_RE_REDACT.source : HEAD_RE.source, "g");
  head.lastIndex = from;
  let jwtEnd = -1, jwtOk = -1;          // cache per [A-Za-z0-9_-] run
  let m;
  while ((m = head.exec(s))) {
    const p = m.index;
    head.lastIndex = p + 1;
    let end = -1;
    switch (m[0][0]) {
      case "A":
        if (m[0] === "AKIA") { if (fixedRun(s, p + 4, 16, isUpperDigit)) end = p + 20; }
        else if (fixedRun(s, p + 4, 35, isJwt)) end = p + 39;
        break;
      case "g":
        if (m[0] === "github_pat_") { const e = runEnd(s, p + 11, isPat); if (e - (p + 11) >= 22) end = e; }
        else if (redact) { const e = runEnd(s, p + 4, isAlnum); if (e - (p + 4) >= 36) end = e; }
        else if (fixedRun(s, p + 4, 36, isAlnum)) end = p + 40;
        break;
      case "x": { const e = runEnd(s, p + 5, isXox); if (e - (p + 5) >= 10) end = e; break; }
      case "s": { const e = runEnd(s, p + 8, isAlnum); if (e - (p + 8) >= 16) end = e; break; }
      case "-": {
        const r = runEnd(s, p + 11, isPemName);
        if (r - 11 >= p + 11 && s.startsWith("PRIVATE KEY", r - 11) && s.startsWith("-----", r)) {
          end = r + 5;
          if (redact) {                                             // (?:.*?-----END … KEY-----|.*)
            const nl = s.indexOf("\n", end);
            const eol = nl < 0 ? s.length : nl;
            PEM_END_G.lastIndex = end;
            const em = PEM_END_G.exec(s);
            end = em && em.index + em[0].length <= eol ? em.index + em[0].length : eol;
          }
        }
        break;
      }
      case "e": {
        if (p >= jwtEnd) {
          jwtEnd = runEnd(s, p, isJwt);
          jwtOk = -1;
          if (s.charCodeAt(jwtEnd) === 46 && s.startsWith("eyJ", jwtEnd + 1)) {
            const e2 = runEnd(s, jwtEnd + 4, isJwt);
            if (e2 - (jwtEnd + 4) >= 10) jwtOk = e2;
          }
        }
        if (jwtOk >= 0 && jwtEnd - (p + 3) >= 10) end = jwtOk;
        break;
      }
    }
    if (end >= 0) return { index: p, end, text: s.slice(p, end) };
  }
  return null;
}

function redactTokens(s) {
  let out = "", pos = 0, t;
  while ((t = findSecretToken(s, pos, { redact: true }))) {
    out += s.slice(pos, t.index) + "[redacted]";
    pos = t.end;
  }
  return pos === 0 ? s : out + s.slice(pos);
}

// _SECRET_LINE_PATTERNS[1:] (the token pattern is findSecretToken above).
const SQL_CRED_LINE_RE = pyRe(String.raw`(?:IDENTIFIED\s+BY\s+['\"][^'\"]+['\"]|PASSWORD\s*=?\s*['\"][^'\"]+['\"]|IDENTIFIED\s+BY\s+PASSWORD)`, "gi");
const ASSIGN_LINE_RE = pyRe(String.raw`(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)\s*[:=]\s*[\"'][^\"']{4,}[\"']`, "gi");
// credentials in a URL's userinfo: scheme://user:password@host, scheme://token@host
const URL_USERINFO_RE = pyRe(String.raw`(?<=://)[^/\s@'\"]+(?=@)`, "g");
export const REDACTED = "[redacted]";

const PEM_BEGIN_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
const PEM_END_RE = /-----END [A-Z ]*PRIVATE KEY-----/;

/**
 * Indices of the lines of multi-line PEM private keys that FOLLOW the BEGIN
 * line, through the END line — or through the last line when no END
 * follows. Such lines are redacted whole; the BEGIN line itself is handled
 * by the token pattern (twin of core._pem_block_lines).
 */
export function pemBlockLines(lines) {
  const out = new Set();
  let inside = false;
  for (let k = 0; k < lines.length; k++) {
    const line = lines[k];
    if (typeof line !== "string") continue;
    if (inside) {
      out.add(k);
      if (line.includes("-----END") && PEM_END_RE.test(line)) inside = false;
    } else if (line.includes("PRIVATE KEY-----")) {
      const m = PEM_BEGIN_RE.exec(line);
      inside = !!m && !PEM_END_RE.test(line.slice(m.index + m[0].length));
    }
  }
  return out;
}

const SECRET_RUN_RE = /[A-Za-z0-9+/=_-]{20,}/g;
/**
 * The high-entropy literals S-ENTROPY would flag in one file, redacted as
 * substrings wherever they appear (twin of core._SecretLiterals): literals
 * ENTROPY_VALUE_RE finds on any line not matching SECRET_SKIP_RE (comment
 * lines included) that pass entropySecretish().
 */
export class SecretLiterals {
  constructor(lines, skipRe) {
    this.lits = new Set();
    for (const line of lines) {
      if (typeof line !== "string" || (!line.includes("=") && !line.includes(":"))) continue;
      if (skipRe && skipRe.test(line)) continue;
      ENTROPY_VALUE_G.lastIndex = 0;
      let m;
      while ((m = ENTROPY_VALUE_G.exec(line))) if (entropySecretish(m[1])) this.lits.add(m[1]);
    }
    this.byPrefix = new Map();
    for (const lit of this.lits) {
      const k = lit.slice(0, 20);
      if (!this.byPrefix.has(k)) this.byPrefix.set(k, []);
      this.byPrefix.get(k).push(lit);
    }
  }
  redact(text) {
    if (!this.lits.size || typeof text !== "string") return text;
    const hits = [];
    SECRET_RUN_RE.lastIndex = 0;
    let m;
    while ((m = SECRET_RUN_RE.exec(text))) {
      const run = m[0], base = m.index;
      if (this.lits.has(run)) { hits.push([base, base + run.length]); continue; }
      for (let p = 0; p + 20 <= run.length; p++) {
        for (const lit of this.byPrefix.get(run.slice(p, p + 20)) || []) {
          if (run.startsWith(lit, p)) hits.push([base + p, base + p + lit.length]);
        }
      }
    }
    if (!hits.length) return text;
    hits.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
    let out = "", pos = 0;
    for (const [a, b] of hits) {
      if (b <= pos) continue;
      out += text.slice(pos, Math.max(a, pos)) + REDACTED;
      pos = b;
    }
    return out + text.slice(pos);
  }
}

// Per-file redaction contexts, registered by scanFile for the lines it
// scans (the Python engine's scan context): PEM block lines, the file's
// entropy literals, and a per-line cache of redacted text.
const CONTEXTS = new WeakMap();
export function registerScanContext(lines, skipRe) {
  const ctx = { pem: null, secrets: null, cache: new Map(), lines, skipRe };
  CONTEXTS.set(lines, ctx);
  return ctx;
}
export function scanContext(lines) {
  return Array.isArray(lines) ? CONTEXTS.get(lines) ?? null : null;
}
export function contextSecrets(ctx) {
  ctx.secrets ??= new SecretLiterals(ctx.lines, ctx.skipRe);
  return ctx.secrets;
}
/** Line k as any snippet may show it (PEM block → whole line redacted). */
export function contextRedacted(ctx, k) {
  let r = ctx.cache.get(k);
  if (r === undefined) {
    ctx.pem ??= pemBlockLines(ctx.lines);
    r = ctx.pem.has(k) ? REDACTED : contextSecrets(ctx).redact(redactContextLine(ctx.lines[k]));
    ctx.cache.set(k, r);
  }
  return r;
}

/** Replace credential-shaped substrings in one line (twin of core._redact_context_line). */
export function redactContextLine(line) {
  if (typeof line !== "string" || !line) return line;
  let out = redactTokens(line);
  out = out.replace(SQL_CRED_LINE_RE, REDACTED).replace(ASSIGN_LINE_RE, REDACTED);
  if (out.includes("://")) out = out.replace(URL_USERINFO_RE, REDACTED);
  return out;
}

/** Redacted copies of a list of lines: PEM blocks whole, then patterns (and literals). */
export function redactLines(lines, secrets = null) {
  const pem = pemBlockLines(lines);
  return lines.map((l, k) => {
    if (typeof l !== "string") return l;
    if (pem.has(k)) return REDACTED;
    const r = redactContextLine(l);
    return secrets ? secrets.redact(r) : r;
  });
}

/** Redaction for free text that may copy source (issue msg, hook cmd). */
export function redactText(text, secrets = null) {
  if (typeof text !== "string") return text;
  if (text.includes("\n")) return redactLines(text.split("\n"), secrets).join("\n");
  const r = redactContextLine(text);
  return secrets ? secrets.redact(r) : r;
}

export function secretPlaceholder(ruleId, rawLine) {
  return REDACT_PLACEHOLDER.replace("{RULE}", ruleId) + ` (${cpLen(String(rawLine))} chars)`;
}

/**
 * Redact a secret-bearing snippet copy (never mutates the caller's array):
 * PEM blocks whole, credential matches → [redacted], flagged line →
 * placeholder + length.
 */
export function redactSecretSnippet(ruleId, snippet, flaggedIdx, rawLine) {
  const out = redactLines(snippet);
  if (flaggedIdx >= 0 && flaggedIdx < out.length) out[flaggedIdx] = secretPlaceholder(ruleId, rawLine);
  return out;
}

/**
 * Belt-and-braces sweep over a whole result (twin of core.redact_result):
 * msg and cmd redacted, every snippet line redacted and clipped.
 */
export function redactResult(res, clip = (l) => l) {
  for (const i of res.issues ?? []) {
    if (REDACT.on) {
      for (const key of ["msg", "cmd"]) if (typeof i[key] === "string") i[key] = redactText(i[key]);
    }
    const snip = i.snippet;
    if (!Array.isArray(snip)) continue;
    if (!REDACT.on) { i.snippet = snip.map((l) => clip(l)); continue; }
    const idx = i.line - (i.snipStart ?? i.line);
    const secret = SECRET_RULES.has(i.rule);
    if (secret && idx >= 0 && idx < snip.length && typeof snip[idx] === "string"
        && !snip[idx].includes(REDACT_FINGERPRINT)) {
      i.snippet = redactSecretSnippet(i.rule, snip, idx, snip[idx]).map((l) => clip(l));
      continue;
    }
    i.snippet = redactLines(snip).map((l) => clip(l));
  }
  return res;
}
