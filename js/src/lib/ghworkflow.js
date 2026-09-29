// GitHub Actions workflows the Shai-Hulud worms planted (0.1.7) — twin of
// lazaret.scanner.ghworkflow, rule for rule: a workflow that hands every
// repository secret (`${{ toJSON(secrets) }}`) to a job's environment or a
// script, and one that puts text from an issue, a discussion or a pull request
// into a command on a self-hosted runner. Workflows are YAML; like the Python
// module, this reads only the outline a workflow needs (keys, sequence items,
// block scalars, quoted scalars, comments), not YAML.

import { pyRe, pyRstrip, cpLen } from "./pycompat.js";

const BLOCK_RE = /^[|>][-+0-9]{0,3}$/;
/** Code points between `${{` and `}}` an expression may have (ghworkflow.EXPR_MAX). */
export const EXPR_MAX = 500;
const SECRETS_SRC = String.raw`\btoJSON\s*\(\s*secrets\s*\)`;
const UNTRUSTED_SRC =
  String.raw`\bgithub\.head_ref\b|\bgithub\.event\.(?:discussion|issue|comment|pull_request|review|review_comment` +
  String.raw`|head_commit|commits|pages|workflow_run)\b[\w.\[\]*-]{0,200}?\.(?:title|body|message|name|email|ref` +
  String.raw`|label|head_branch|page_name|default_branch)\b`;
const NETWORK_SRC =
  String.raw`\b(?:curl|wget|nc|ncat|netcat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b|https?://|/dev/tcp/`;
const SECRETS_RE = pyRe(SECRETS_SRC, "i");
const UNTRUSTED_RE = pyRe(UNTRUSTED_SRC);
const NETWORK_RE = pyRe(NETWORK_SRC, "i");
const EVENT_WORD_RE = /[A-Za-z_]+/g;
/** Events that start a workflow with text anyone can write, and who that is (ghworkflow.OUTSIDER_EVENTS). */
export const OUTSIDER_EVENTS = [
  ["discussion", "open a discussion"], ["discussion_comment", "comment on a discussion"],
  ["issues", "open an issue"], ["issue_comment", "comment on an issue"],
  ["pull_request_target", "open a pull request"], ["pull_request", "open a pull request"],
  ["pull_request_review", "review a pull request"],
  ["pull_request_review_comment", "comment on a pull request's code"]];

/** Is path a workflow: .github/workflows/*.yml|yaml (ghworkflow.is_workflow)? */
export function isWorkflow(path) {
  const parts = path.replaceAll("\\", "/").split("/");
  const n = parts.length;
  if (n < 3) return false;
  const name = parts[n - 1].toLowerCase();
  return parts[n - 3].toLowerCase() === ".github" && parts[n - 2].toLowerCase() === "workflows"
    && (name.endsWith(".yml") || name.endsWith(".yaml"));
}

/** Leading spaces of a line (not tabs). */
function indentOf(line) {
  let i = 0;
  while (i < line.length && line[i] === " ") i++;
  return i;
}

/** s without leading spaces and tabs (Python's s.lstrip(" \t")). */
function lstripST(s) {
  let i = 0;
  while (i < s.length && (s[i] === " " || s[i] === "\t")) i++;
  return s.slice(i);
}

/** s without trailing spaces and tabs (Python's s.rstrip(" \t")). */
function rstripST(s) {
  let j = s.length;
  while (j > 0 && (s[j - 1] === " " || s[j - 1] === "\t")) j--;
  return s.slice(0, j);
}

/** Is s only spaces and tabs (Python's not s.strip(" \t"))? */
const blankST = (s) => lstripST(s) === "";

/** End (exclusive) of the quoted scalar that opens s, or -1 (ghworkflow._quoted_end). */
function quotedEnd(s) {
  const q = s[0];
  let j = 1;
  while (j < s.length) {
    const c = s[j];
    if (q === '"' && c === "\\") {
      j += 2;
      continue;
    }
    if (c === q) {
      if (q === "'" && s.startsWith("''", j)) {
        j += 2;
        continue;
      }
      return j + 1;
    }
    j++;
  }
  return -1;
}

/** Where a comment starts in s (a '#' after a space or a tab), or its length. */
function commentAt(s) {
  let best = s.length;
  for (const sep of [" #", "\t#"]) {
    const k = s.indexOf(sep);
    if (k >= 0 && k < best) best = k;
  }
  return best;
}

/** [text, quoted] of a scalar written at the start of s (ghworkflow._value). */
function scalar(s) {
  if (s.startsWith('"') || s.startsWith("'")) {
    const end = quotedEnd(s);
    return [end > 0 ? s.slice(1, end - 1) : s.slice(1), true];
  }
  return [rstripST(s.slice(0, commentAt(s))), false];
}

/** [key, value] of a `key: value` line; key null when the line is not one (ghworkflow._split). */
function split(body) {
  if (body.startsWith('"') || body.startsWith("'")) {
    const end = quotedEnd(body);
    if (end < 0) return [null, body];
    const rest = lstripST(body.slice(end));
    if (rest.startsWith(":") && (rest.length === 1 || rest[1] === " " || rest[1] === "\t")) {
      return [body.slice(1, end - 1), lstripST(rest.slice(1))];
    }
    return [null, body];
  }
  if (body.startsWith("[") || body.startsWith("{") || body.startsWith("#") || body.startsWith("?")) return [null, body];
  const cut = commentAt(body);
  let k = body.indexOf(": ");
  if (k >= 0 && k + 2 > cut) k = -1;
  let kt = body.indexOf(":\t");
  if (kt >= 0 && kt + 2 > cut) kt = -1;
  if (kt >= 0 && (k < 0 || kt < k)) k = kt;
  if (k < 0) {
    const head = pyRstrip(body.slice(0, cut));
    if (head.endsWith(":")) return [pyRstrip(head.slice(0, -1)), ""];
    return [null, body];
  }
  return [pyRstrip(body.slice(0, k)), lstripST(body.slice(k + 2))];
}

/** The text of each `${{ … }}` in a line, in one pass (ghworkflow._expressions). */
function expressions(t) {
  const out = [];
  let i = t.indexOf("${{");
  let close = -1;
  while (i >= 0) {
    if (close < i + 3) {
      close = t.indexOf("}}", i + 3);
      if (close < 0) break;
    }
    const units = close - (i + 3);           // UTF-16 units: at least the code points, at most twice them
    if (units <= EXPR_MAX || (units <= 2 * EXPR_MAX && cpLen(t.slice(i + 3, close)) <= EXPR_MAX)) {
      out.push(t.slice(i + 3, close));
      i = t.indexOf("${{", close + 2);
    } else {
      i = t.indexOf("${{", i + 1);
    }
  }
  return out;
}

/** The workflow's lines as records {line, path, key, value, block} (ghworkflow.outline). */
export function outline(source) {
  const records = [];
  let stack = [];
  let block = null;
  const rows = source.split("\n");
  for (let n = 1; n <= rows.length; n++) {
    const raw = rows[n - 1];
    if (block !== null) {
      if (blankST(raw)) continue;
      if (indentOf(raw) > block[0]) {
        block[1].block.push([n, lstripST(rstripST(raw))]);
        continue;
      }
      block = null;
    }
    let ind = indentOf(raw);
    let body = rstripST(raw.slice(ind));
    if (!body || body.startsWith("#")) continue;
    if (ind === 0 && (body === "---" || body === "..." || body.startsWith("--- "))) {
      stack = [];
      continue;
    }
    while (body === "-" || body.startsWith("- ") || body.startsWith("-\t")) {
      while (stack.length && (stack[stack.length - 1][0] > ind
          || (stack[stack.length - 1][0] === ind && stack[stack.length - 1][1] === "-"))) stack.pop();
      stack.push([ind, "-"]);
      const rest = body.slice(1);
      const stripped = lstripST(rest);
      ind = ind + 1 + (rest.length - stripped.length);
      body = stripped;
    }
    if (!body || body.startsWith("#")) continue;
    const [key, rest] = split(body);
    while (stack.length && stack[stack.length - 1][0] >= ind) stack.pop();
    const path = stack.map(([, name]) => name);
    const [value, quoted] = scalar(rest);
    const rec = { line: n, path, key, value, block: [] };
    records.push(rec);
    if (key !== null) {
      stack.push([ind, key]);
      if (!quoted && BLOCK_RE.test(value)) {
        rec.value = "";
        block = [ind, rec];
      }
    }
  }
  return records;
}

const textOf = (rec) => (rec.value ? [rec.value] : []).concat(rec.block.map(([, t]) => t)).join("\n");
const linesOf = (rec) => (rec.value ? [[rec.line, rec.value]] : []).concat(rec.block);
const last = (path) => (path.length ? path[path.length - 1] : undefined);
const isRun = (r) => r.key === "run" || (r.key === null && last(r.path) === "run");

function events(records) {
  const names = [];
  const words = (s) => s.match(EVENT_WORD_RE) ?? [];
  for (const r of records) {
    if (r.path.length === 0 && (r.key === "on" || r.key === "true")) names.push(...words(r.value));
    else if (r.path.length === 1 && r.path[0] === "on" && r.key !== null) names.push(r.key);
    else if (r.path.length === 2 && r.path[0] === "on" && r.path[1] === "-" && r.key === null) names.push(...words(r.value));
  }
  return names;
}

/** [[kind, line, detail]] for a workflow's text (ghworkflow.findings). */
export function findings(source) {
  const records = outline(source);
  const out = [];
  let sends = null;
  for (const r of records) {
    if (r.key === "uses" && r.value.startsWith("actions/upload-artifact")) sends ??= "an artifact upload";
    else if (isRun(r) && NETWORK_RE.test(textOf(r))) sends ??= "a network command";
  }
  for (const r of records) {
    if (r.path.includes("with")) continue;
    let where;
    if (last(r.path) === "env" && r.key !== null) where = "a job's environment";
    else if (isRun(r)) where = "a script";
    else continue;
    for (const [line, t] of linesOf(r)) {
      if (SECRETS_RE.test(t)) {
        out.push(["secrets", line, { where, how: sends }]);
        break;
      }
    }
  }
  const names = events(records);
  const outsider = OUTSIDER_EVENTS.find(([e]) => names.includes(e));
  if (outsider === undefined) return out;
  const hosted = new Set();
  for (const r of records) {
    const p = r.path;
    if (p.length >= 2 && p[0] === "jobs" && ((p.length === 2 && r.key === "runs-on") || p[2] === "runs-on")) {
      if (textOf(r).toLowerCase().includes("self-hosted")) hosted.add(p[1]);
    }
  }
  for (const r of records) {
    const p = r.path;
    if (p.length < 4 || p[0] !== "jobs" || !hosted.has(p[1]) || p[2] !== "steps" || p[3] !== "-") continue;
    if (!(r.key === "run" && p.length === 4) && !(r.key === null && p.length === 5 && p[4] === "run")) continue;
    for (const [line, t] of linesOf(r)) {
      let m = null;
      for (const e of expressions(t)) {
        m = UNTRUSTED_RE.exec(e);
        if (m !== null) break;
      }
      if (m !== null) {
        out.push(["backdoor", line, { job: p[1], expr: m[0], event: outsider[0], act: outsider[1] }]);
        break;
      }
    }
  }
  return out;
}

/** The module's pattern text, for the parity test. */
export const PY_TWINS = {
  patterns: { _SECRETS_RE: [SECRETS_SRC, "i"], _UNTRUSTED_RE: [UNTRUSTED_SRC, ""], _NETWORK_RE: [NETWORK_SRC, "i"] },
  events: OUTSIDER_EVENTS, limits: { EXPR_MAX },
};
