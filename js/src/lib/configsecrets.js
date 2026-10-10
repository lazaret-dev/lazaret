// Config and data files: which ones are checked for credentials, and how.
// Twin of lazaret/scanner/configsecrets.py (see its docstring): .env, JSON,
// YAML, TOML, INI, .properties, shell, PEM keys, Dockerfiles, .npmrc /
// .pypirc and Terraform variables are read as text and checked by the two
// credential rules only (scanConfigFile in ../scanner/scan.js), never as
// code. The patterns are the Python engine's, compiled with Python semantics
// (pyRe), and run in linear time.
// Never import from ../scanner/ (RESTRUCTURE.md §5).

import { pyRe, cpLen, pyStrip, isPySpace } from "./pycompat.js";
import { pyExt } from "./binary.js";

export const CONFIG_EXTS = new Set([
  ".env", ".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
  ".properties", ".sh", ".bash", ".zsh", ".pem", ".key", ".tfvars",
]);
export const CONFIG_NAMES = new Set([
  ".env", ".envrc", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".dockercfg",
  "dockerfile", "containerfile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
]);
export const CONFIG_SKIP_NAMES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "packages.lock.json", "pylock.toml",
]);
/** Config files larger than this are not read (Q-SKIPPED-CONFIG). */
export const CONFIG_SCAN_CAP = 2_000_000;

// Lazaret's own JSON reports (lazaret-report.json, lazaret-sca.json, a
// baseline) start with the provenance marker; they are not read.
const OWN_REPORT_RE = pyRe(String.raw`^﻿?\s*\{\s*"generatedBy"\s*:\s*"lazaret-`);
export function ownReport(text) { return OWN_REPORT_RE.test(text); }

/** True for a file (by its base name) that is read as config or data. */
export function isConfigFile(name) {
  const low = String(name).toLowerCase();
  if (CONFIG_SKIP_NAMES.has(low) || (low.startsWith("pylock.") && low.endsWith(".toml"))) return false;
  if (CONFIG_NAMES.has(low) || low.startsWith(".env.") || low.startsWith("dockerfile.")
      || low.endsWith(".dockerfile")) return true;
  return CONFIG_EXTS.has(pyExt(low));
}

// ---- comments ----------------------------------------------------------------
// A '#' or '// ' (a space, tab or the end of the line after it: .npmrc's
// `//registry.invalid/:_authToken=…` is a setting) at the start of a line or
// after a space or tab, or a ';' at the start of a line, begins a comment
// that runs to the end of the line — outside '…' and "…" quotes (a
// backslash escapes in "…").
function commentStart(line) {
  if (!line.includes("#") && !line.includes("//") && !line.includes(";")) return -1;
  let quote = null, blank = true;
  for (let i = 0; i < line.length;) {
    const ch = line[i];
    if (quote !== null) {
      if (ch === "\\" && quote === '"') { i += 2; continue; }
      if (ch === quote) quote = null;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if ((ch === "#" || (ch === "/" && line.startsWith("//", i)
                               && (i + 2 >= line.length || line[i + 2] === " " || line[i + 2] === "\t")))
               && (blank || line[i - 1] === " " || line[i - 1] === "\t")) {
      return i;
    } else if (ch === ";" && blank) {
      return i;
    }
    if (ch !== " " && ch !== "\t") blank = false;
    i++;
  }
  return -1;
}

/** Absolute [start, end] spans of the comments of a config file. */
export function configCommentSpans(content) {
  const spans = [];
  let pos = 0;
  for (const line of content.split("\n")) {
    const c = commentStart(line);
    if (c >= 0) spans.push([pos + c, pos + line.length]);
    pos += line.length + 1;
  }
  return spans;
}

// ---- S-SECRET ------------------------------------------------------------------
const KV_SRC = String.raw`(?<![A-Za-z0-9_.\-])["']?([A-Za-z0-9_.\-]{1,128})["']?[ \t]*([:=])[ \t]*("[^"\n]*"|'[^'\n]*'|[^\s"',;#{}\[\]]+)`;
const KV_RE = pyRe(KV_SRC, "gd");
export const SECRET_KEY_RE = pyRe(String.raw`(?:password|passwd|passphrase|secret|token|(?:api|access|account|app|client|encryption|master|private|restricted|secret|signing)[_\-]?key)$|(?:^|[_.\-])(?:pass|pwd|pat|auth)$`, "i");
export const NOT_SECRET_KEY_RE = pyRe(String.raw`(?:page|continuation|next|cursor|sync|csrf|xsrf|idempotency)[_\-]?token$`, "i");
/** True for a key named like a credential (configsecrets.secret_key). */
export function secretKey(key) { return SECRET_KEY_RE.test(key) && !NOT_SECRET_KEY_RE.test(key); }
/** Shannon entropy in bits per character (configsecrets.entropy; code points, in order of first use). */
export function entropy(v) {
  const counts = new Map();
  for (const ch of v) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const n = cpLen(v);
  let h = 0;
  for (const c of counts.values()) h -= c / n * Math.log2(c / n);
  return h;
}
export const PLACEHOLDER_RE = pyRe(String.raw`example|sample|dummy|placeholder|change[_\-.]?(?:me|this|it)|your[_\-.]|xxx|\*\*\*|\.\.\.|redacted|replace|insert[_\-.]|enter[_\-.]|todo|fixme|fake|mock|encoded|secret|passw|p[a@4]ssw[o0]rd|string|123456|654321|abcdef|a1b2c3|<|>|\$\{|\{\{|\}\}|%\(|\$\(`, "i");
// A name or words, not a credential: words (lowercase after their first
// letter) joined by - . _ / or :, or an environment variable's name standing
// in for its value (configsecrets._NAME_RE).
const NAME_RE = pyRe(String.raw`^(?:[A-Za-z][a-z]*[0-9]{0,2}(?:[\-._/:][A-Za-z][a-z]*[0-9]{0,2})+|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)$`);
const ASCII_RE = /^[\x00-\x7f]*$/;
const URL_START_RE = pyRe(String.raw`^[A-Za-z][A-Za-z0-9+.\-]*://`);
const WS_RE = pyRe(String.raw`\s`);
const LETTER_RE = /[A-Za-z]/;
const NOT_LETTER_RE = /[^A-Za-z]/u;
const REFERENCE_FIRST = new Set("$%<{@!(*&~/.\\#[|>");

export function unquote(value) {
  if (value.length >= 2 && value[0] === value[value.length - 1] && (value[0] === '"' || value[0] === "'")) {
    return value.slice(1, -1);
  }
  return value;
}

/** True for a (quoted or bare) value that looks like a credential (configsecrets.secret_value). */
export function secretValue(value) {
  const v = unquote(value);
  if (cpLen(v) < 8 || !ASCII_RE.test(v) || WS_RE.test(v) || REFERENCE_FIRST.has(v[0])) return false;
  if (URL_START_RE.test(v) || PLACEHOLDER_RE.test(v) || NAME_RE.test(v)) return false;
  return LETTER_RE.test(v) && NOT_LETTER_RE.test(v) && entropy(v) >= 2.5;
}

const URL_CRED_RE = pyRe(String.raw`(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{0,31}://([^\s/:@'"]{1,256}):([^\s/@'"]{1,512})@([^\s/:?#'"]{1,256})`, "gd");
export const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"]);
// Webhook URLs that carry their own secret (Slack, Discord).
const WEBHOOK_RE = pyRe(String.raw`https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,32}|https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]{5,20}/[A-Za-z0-9_\-]{20,100}`);

// A .netrc's names, and its password token and value (configsecrets.NETRC_NAMES, NETRC_PASSWORD_RE).
export const NETRC_NAMES = new Set([".netrc", "_netrc"]);
const NETRC_PASSWORD_RE = pyRe(String.raw`(?<![^ \t])password[ \t]+("[^"\n]*"|[^\s"]+)`, "gd");
// A .netrc's tokens, and the logins of anonymous FTP (configsecrets._NETRC_TOKEN_RE, NETRC_ANONYMOUS: N-25).
const NETRC_TOKEN_RE = pyRe(String.raw`"[^"\n]*"|[^\s"]+`, "g");
const NETRC_ANONYMOUS = new Set(["anonymous", "ftp"]);

/**
 * Map line index -> Set of the columns (UTF-16) of the password values of a .netrc's entries whose login is
 * anonymous FTP's, which S-SECRET does not report (configsecrets.netrc_anonymous). `codeLines`: the file's lines,
 * comments removed.
 */
export function netrcAnonymous(codeLines) {
  const skip = new Map();
  let login = null, passwords = [], pending = null, inMacro = false;
  const close = () => {
    if (login !== null && NETRC_ANONYMOUS.has(unquote(login).toLowerCase())) {
      for (const [i, col] of passwords) {
        if (!skip.has(i)) skip.set(i, new Set());
        skip.get(i).add(col);
      }
    }
  };
  for (let i = 0; i < codeLines.length; i++) {
    const line = codeLines[i];
    if (inMacro) {
      inMacro = pyStrip(line) !== "";
      continue;
    }
    NETRC_TOKEN_RE.lastIndex = 0;
    let m;
    while ((m = NETRC_TOKEN_RE.exec(line))) {
      const token = m[0];
      if (pending !== null) {
        if (pending === "login") login = token;
        else if (pending === "password") passwords.push([i, m.index]);
        else if (pending === "macdef") inMacro = true;          // (its body is the lines that follow, to an empty one)
        pending = null;
        if (inMacro) break;
        continue;
      }
      if (token === "machine" || token === "default") {
        close();
        login = null;
        passwords = [];
        pending = token === "machine" ? "machine" : null;
      } else if (token === "login" || token === "password" || token === "account" || token === "macdef") {
        pending = token;
      }
    }
  }
  close();
  return skip;
}

/**
 * Column (UTF-16) of the first credential S-SECRET reports on a config line (comments removed), else -1.
 * `netrc`: the line is a .netrc's; `skip`: the columns of its password values that are not secrets
 * (netrcAnonymous).
 */
export function secretCol(code, netrc = false, skip = null) {
  let m;
  if (netrc) {
    NETRC_PASSWORD_RE.lastIndex = 0;
    while ((m = NETRC_PASSWORD_RE.exec(code))) {
      if (!(skip && skip.has(m.indices[1][0])) && secretValue(m[1])) return m.indices[1][0];
    }
  }
  KV_RE.lastIndex = 0;
  while ((m = KV_RE.exec(code))) {
    const value = m[3], end = m.indices[3][1];
    if (value[0] !== '"' && value[0] !== "'") {
      if (code[end] === "{" || code[end] === "}") continue;              // part of a template: ${VAR:default}
      if (m[2] === ":" && pyStrip(code.slice(end)) !== "") continue;     // a YAML phrase: `key: some words`
    }
    if (secretKey(m[1]) && secretValue(value)) return m.indices[1][0];
  }
  if (code.includes("://")) {
    URL_CRED_RE.lastIndex = 0;
    while ((m = URL_CRED_RE.exec(code))) {
      const [, user, password, host] = m;
      if (password !== user && !LOCAL_HOSTS.has(host.toLowerCase()) && secretValue(password)) return m.indices[2][0];
    }
    const w = WEBHOOK_RE.exec(code);
    if (w) return w.index;
  }
  return -1;
}

/** `line` with the value of every credential-named key replaced by [redacted] (configsecrets.redact_values). */
export function redactConfigValues(line, netrc = false) {
  if (typeof line !== "string") return line;
  if (netrc) {
    NETRC_PASSWORD_RE.lastIndex = 0;
    line = line.replace(NETRC_PASSWORD_RE, (whole, value) => whole.slice(0, whole.length - value.length) + "[redacted]");
  }
  let out = "", pos = 0, any = false, m;
  KV_RE.lastIndex = 0;
  while ((m = KV_RE.exec(line))) {
    const value = unquote(m[3]);
    if (!secretKey(m[1]) || !value || "${<%".includes(value[0])) continue;
    const [a, b] = m.indices[3];
    out += line.slice(pos, a) + "[redacted]";
    pos = b;
    any = true;
  }
  return any ? out + line.slice(pos) : line;
}

// ---- S-TOKEN in config files -----------------------------------------------------
const PEM_BODY_AT = /[A-Za-z0-9+/]{40}[A-Za-z0-9+/]*={0,2}/y;   // {40}…*, not {40,}: see pycompat AT_LEAST_RE
const STRING_PREFIX_AT = /[A-Za-z][A-Za-z0-9]{0,2}#*["']/y;
/** The index past a private-key header's separators (configsecrets._past_pem_separators). */
function pastPemSeparators(s, k, lineStart) {
  while (k < s.length) {
    const c = s[k];
    if (isPySpace(c) || '"\'`+,.#'.includes(c) || (lineStart && "*/".includes(c))) k++;
    else if (c === "\\") {
      let j = k + 1;
      while (s[j] === "\\") j++;
      if (s[j] === "n" || s[j] === "r" || s[j] === "t") { k = j + 1; continue; }
      while (j < s.length && isPySpace(s[j])) j++;   // a line continued
      if (j < s.length) break;
      k = j;
    } else {
      STRING_PREFIX_AT.lastIndex = k;                // a string's prefix and its quote (b" rb' u8" r#")
      if (!STRING_PREFIX_AT.test(s)) break;
      k = STRING_PREFIX_AT.lastIndex;
    }
  }
  return k;
}
/** True when a private key begins at s[k]: mixed key material, or "Proc-Type:" (configsecrets._key_at). */
function keyAt(s, k) {
  PEM_BODY_AT.lastIndex = k;
  const m = PEM_BODY_AT.exec(s);
  return (!!m && /[A-Z]/.test(m[0]) && /[a-z]/.test(m[0]) && /[0-9]/.test(m[0])) || s.startsWith("Proc-Type:", k);
}
/**
 * True when a private-key header's key comes right after it (configsecrets.key_follows): keyAt past the separators
 * on the header's line (`line`, the header ending at `end`, read in place), or, where that line ends with them, at
 * the start of the first of the `following` lines that holds anything.
 */
export function keyFollows(line, end, following) {
  const k = pastPemSeparators(line, end, false);
  if (k < line.length) return keyAt(line, k);
  for (const line of following) {
    const j = pastPemSeparators(line, 0, true);
    if (j < line.length) return keyAt(line, j);
  }
  return false;
}

export const JWT_IO_PAYLOAD = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ";

/** True for a token-rule match that is a documentation sample (configsecrets.documentation_token). */
export function documentationToken(text) {
  if (text.startsWith("AKIA")) return text.endsWith("EXAMPLE");
  if (text.startsWith("eyJ")) {
    const dot = text.indexOf(".");
    return dot >= 0 && text.slice(dot + 1) === JWT_IO_PAYLOAD;
  }
  return false;
}
