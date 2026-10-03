// GitHub Actions workflows the Shai-Hulud worms planted (0.1.7) — twin of
// lazaret.scanner.ghworkflow, rule for rule: a workflow that hands every
// repository secret (`${{ toJSON(secrets) }}`) to a job's environment or a
// script, and one that puts text from an issue, a discussion or a pull request
// into a command on a self-hosted runner. Workflows are YAML; like the Python
// module, this reads only the outline a workflow needs (keys, sequence items,
// block scalars, quoted scalars, comments), not YAML.

import { pyRe, pyRstrip, cpLen, cpPrefix } from "./pycompat.js";

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
  return outlineRecords(source, false);
}

/**
 * outline(source); with `items`, each record also says whether it is the
 * first of a sequence item (`item`): hardening() tells one step from the next
 * by it (ghworkflow._outline). outline() leaves the field out.
 */
function outlineRecords(source, items, seqBlocks = false) {
  const records = [];
  let stack = [];
  let block = null;
  let fresh = false;
  const rows = source.split("\n");
  for (let n = 1; n <= rows.length; n++) {
    let raw = rows[n - 1];
    if (raw.endsWith("\r")) raw = raw.slice(0, -1);        // a file with Windows line ends
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
      fresh = false;
      continue;
    }
    while (body === "-" || body.startsWith("- ") || body.startsWith("-\t")) {
      while (stack.length && (stack[stack.length - 1][0] > ind
          || (stack[stack.length - 1][0] === ind && stack[stack.length - 1][1] === "-"))) stack.pop();
      stack.push([ind, "-"]);
      fresh = true;
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
    if (items) rec.item = fresh;
    fresh = false;
    records.push(rec);
    if (key !== null) {
      stack.push([ind, key]);
      if (!quoted && BLOCK_RE.test(value)) {
        rec.value = "";
        block = [ind, rec];
      }
    } else if (seqBlocks && !quoted && BLOCK_RE.test(value) && stack.length && stack[stack.length - 1][1] === "-") {
      rec.value = "";
      block = [stack[stack.length - 1][0], rec];
    }
  }
  return records;
}

/**
 * The outline of the other CI files that are read the same way (gitlabci.js):
 * with `items`, each record's `item` flag; with `seqBlocks`, a block scalar that
 * is a sequence item (`- |`) is one (ghworkflow.records).
 */
export function yamlRecords(source, items = true, seqBlocks = false) {
  return outlineRecords(source, items, seqBlocks);
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

// ---------------- Hardening checks (0.1.9) — twin of ghworkflow.hardening ----------------
const HEX = "0123456789abcdefABCDEF";
const DIGITS = "0123456789";
const PR_HEAD_SRC =
  String.raw`github\.event\.pull_request\.head\.(?:sha|ref|repo)|github\.head_ref|refs/pull/|\bpull/(?:\d|\$\{\{)`;
const PR_CHECKOUT_CMD_SRC = String.raw`\bgit\s+(?:checkout|fetch|switch|pull|merge|cherry-pick)\b`;
const GH_PR_CHECKOUT_SRC = String.raw`\bgh\s+pr\s+checkout\b`;
const WRITE_SCOPE_SRC = String.raw`([A-Za-z-]+)\s*:\s*write\b`;
const CMD_SRC =
  String.raw`(?:^|[;&|(]|\b(?:then|do|else|if|elif|while|until|sudo|time|exec|command)\s)\s*` +
  String.raw`(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|()]*\s+)*`;
/** Where a command can start in a line of a script (ghworkflow.COMMAND_START). */
export const COMMAND_START = CMD_SRC;
const INSTALL_SRC =
  CMD_SRC + String.raw`((?:npm\s+(?:ci|install|i|add)|pnpm\s+(?:install|i|add)|yarn\s+(?:install|add)` +
  String.raw`|bun\s+(?:install|i|add)|pip3?\s+install|python3?\s+-m\s+pip\s+install|uv\s+(?:sync|add|pip\s+install)` +
  String.raw`|poetry\s+install|pipenv\s+install|bundle\s+install|composer\s+(?:install|update)` +
  String.raw`|cargo\s+(?:build|fetch|install)|go\s+(?:get|install|build|mod\s+download))(?![\w-])` +
  String.raw`|yarn(?=\s*(?:$|[;&|)])))`;
const PUBLISH_SRC =
  CMD_SRC + String.raw`((?:npm|pnpm|bun)\s+publish\b|yarn\s+(?:npm\s+)?publish\b|twine\s+upload\b|uv\s+publish\b` +
  String.raw`|poetry\s+publish\b|cargo\s+publish\b|gh\s+release\s+create\b|docker\s+push\b` +
  String.raw`|vsce\s+publish\b|ovsx\s+publish\b|gem\s+push\b|dotnet\s+nuget\s+push\b|helm\s+push\b)`;
const FETCH_SRC = CMD_SRC + String.raw`((?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b)`;
const SCRIPT_HEAD_SRC =
  String.raw`\s*(?:sudo\b(?:\s+-\S+)*\s+)?(?:env\s+)?(?:[A-Za-z_][A-Za-z0-9_]*=[^\s;&|()]*\s+)*(?:[\w./-]*/)?` +
  String.raw`((?:ba|z|da|k|a|c)?sh|python[0-9.]*|node|perl|ruby|iex|Invoke-Expression|pwsh|powershell)\b`;
const FETCHED_ARG_SRC =
  String.raw`(?:\b(?:ba|z|da|k|a|c)?sh|\bsource|(?<![\w.])\.)(?:\s+-[A-Za-z]+)*\s+[\"']?<\(\s*(?:curl|wget|iwr|irm)\b` +
  String.raw`|\b(?:(?:ba|z|da|k|a|c)?sh(?:\s+-[A-Za-z]+)*\s+-[A-Za-z]*c|eval)\s+[\"']?\$\(\s*(?:curl|wget|iwr|irm)\b` +
  String.raw`|\b(?:iex|Invoke-Expression)\b[\s\"'&{($]{0,20}(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod|New-Object\b)`;
const STDIN_ONLY_SRC = String.raw`(?:\s+-[A-Za-z]+)*(?:\s+-)?\s*\Z`;
const PIPELINE_SRC = String.raw`\|\||&&|[;\n]`;
const PR_HEAD_RE = pyRe(PR_HEAD_SRC);
const PR_CHECKOUT_CMD_RE = pyRe(PR_CHECKOUT_CMD_SRC);
const GH_PR_CHECKOUT_RE = pyRe(GH_PR_CHECKOUT_SRC);
const WRITE_SCOPE_RE = pyRe(WRITE_SCOPE_SRC, "g");
const INSTALL_RE = pyRe(INSTALL_SRC);
const PUBLISH_RE = pyRe(PUBLISH_SRC);
const FETCH_RE = pyRe(FETCH_SRC, "i");
const SCRIPT_HEAD_RE = pyRe(SCRIPT_HEAD_SRC, "iy");
const FETCHED_ARG_RE = pyRe(FETCHED_ARG_SRC, "i");
const STDIN_ONLY_RE = pyRe(STDIN_ONLY_SRC, "y");
const PIPELINE_RE = pyRe(PIPELINE_SRC, "g");
/** Actions that publish a release (ghworkflow.PUBLISH_ACTIONS). */
export const PUBLISH_ACTIONS = [
  "pypa/gh-action-pypi-publish", "softprops/action-gh-release", "ncipollo/release-action",
  "goreleaser/goreleaser-action", "actions/create-release", "actions/attest-build-provenance", "actions/attest",
  "rust-lang/crates-io-auth-action", "js-devtools/npm-publish", "slsa-framework/slsa-github-generator",
  "sigstore/gh-action-sigstore-python"];
/** Actions whose job is to restore a cache (ghworkflow.CACHE_ACTIONS). */
export const CACHE_ACTIONS = ["actions/cache", "swatinem/rust-cache"];
/** Setup actions, the input that turns their cache on, and whether it is on unless false (ghworkflow.SETUP_CACHES). */
export const SETUP_CACHES = [
  ["actions/setup-node", "cache", false], ["actions/setup-python", "cache", false],
  ["actions/setup-go", "cache", true], ["actions/setup-java", "cache", false],
  ["actions/setup-dotnet", "cache", false], ["ruby/setup-ruby", "bundler-cache", false],
  ["astral-sh/setup-uv", "enable-cache", true]];
/** Actions of GitHub's own (ghworkflow.FIRST_PARTY). */
export const FIRST_PARTY = ["actions/", "github/"];

const isHex = (s, n) => cpLen(s) === n && [...s].every((c) => HEX.includes(c));
const inActions = (name, names) => names.some((a) => name === a || name.startsWith(a + "/"));
const stripST = (s) => rstripST(lstripST(s));

/** [kind, name, ref, pinned] of a `uses:` value; null for a local path (ghworkflow._action_ref). */
function actionRef(value) {
  const v = stripST(value);
  if (!v || v === "." || v.startsWith("./") || v.startsWith("../")) return null;
  if (v.startsWith("docker://")) {
    const rest = v.slice(9);
    const i = rest.indexOf("@");
    const name = i < 0 ? rest : rest.slice(0, i);
    const digest = i < 0 ? "" : rest.slice(i + 1);
    const pinned = i >= 0 && digest.startsWith("sha256:") && isHex(digest.slice(7), 64);
    return ["docker", name, digest, pinned];
  }
  const i = v.indexOf("@");
  const name = i < 0 ? v : v.slice(0, i);
  const ref = i < 0 ? "" : v.slice(i + 1);
  const kind = name.includes("/.github/workflows/") ? "workflow" : "action";
  return [kind, name, ref, i >= 0 && isHex(ref, 40)];
}

/** Does ref read as a version tag (ghworkflow._tag_like)? */
const tagLike = (ref) => ref !== "" && (DIGITS.includes(ref[0]) || (ref[0] === "v" && ref.slice(1, 2) !== "" && DIGITS.includes(ref[1])));

/** [[job, records]]: the steps of every job (ghworkflow._steps). */
function stepsOf(records) {
  const steps = [];
  for (const r of records) {
    const p = r.path;
    if (p.length >= 4 && p[0] === "jobs" && p[2] === "steps" && p[3] === "-") {
      if ((p.length === 4 && r.item) || steps.length === 0 || steps[steps.length - 1][0] !== p[1]) steps.push([p[1], []]);
      steps[steps.length - 1][1].push(r);
    }
  }
  return steps;
}

/** [value, line] of a step's `uses:`, or null. */
function stepUses(recs) {
  for (const r of recs) if (r.key === "uses" && r.path.length === 4) return [r.value, r.line];
  return null;
}

/** Map input → [value, line] of a step's `with:`. */
function stepWith(recs) {
  const out = new Map();
  for (const r of recs) {
    const p = r.path;
    if (p.length === 5 && p[4] === "with" && r.key !== null && !out.has(r.key)) out.set(r.key, [r.value, r.line]);
  }
  return out;
}

/** [[line, text]] of a step's script. */
function stepRunLines(recs) {
  const out = [];
  for (const r of recs) {
    const p = r.path;
    if ((r.key === "run" && p.length === 4) || (r.key === null && p.length === 5 && p[4] === "run")) out.push(...linesOf(r));
  }
  return out;
}

const samePath = (p, q) => p.length === q.length && p.every((x, i) => x === q[i]);

const NO_GRANTS = [false, [], null];

/** Map of owner (the workflow, `[]`, or a job, `["jobs", id]`, as JSON) to [present, [[scope, line]] granted write, line of an
 *  id-token grant or null], in one pass over the records (ghworkflow._permissions). */
function permissionsTable(records) {
  const table = new Map();
  const entryOf = (owner) => {
    let e = table.get(owner);
    if (e === undefined) table.set(owner, (e = [false, [], null]));
    return e;
  };
  for (const r of records) {
    const p = r.path;
    const key = r.key;
    if (key === "permissions" && (p.length === 0 || (p.length === 2 && p[0] === "jobs"))) {
      const e = entryOf(ownerKey(p));
      e[0] = true;
      if (r.value === "write-all") {
        e[1].push(["all", r.line]);
        e[2] ??= r.line;
      } else if (r.value.startsWith("{")) {
        for (const m of r.value.matchAll(WRITE_SCOPE_RE)) {
          e[1].push([m[1], r.line]);
          if (m[1] === "id-token") e[2] ??= r.line;
        }
      }
    } else if (key !== null && r.value === "write" && p.length > 0 && p[p.length - 1] === "permissions"
        && (p.length === 1 || (p.length === 3 && p[0] === "jobs"))) {
      const e = entryOf(ownerKey(p.slice(0, -1)));
      e[1].push([key, r.line]);
      if (key === "id-token") e[2] ??= r.line;
    }
  }
  return table;
}

const ownerKey = (path) => JSON.stringify(path);
const grantsOf = (table, owner) => table.get(ownerKey(owner)) ?? NO_GRANTS;

function releaseWhy(table, steps, evs) {
  if (evs.includes("release")) return "it runs when a release is published";
  for (const e of table.values()) if (e[2] !== null) return "it asks for an OIDC token";
  for (const [, recs] of steps) {
    const use = stepUses(recs);
    const ref = use !== null ? actionRef(use[0]) : null;
    if (ref !== null && inActions(ref[1].toLowerCase(), PUBLISH_ACTIONS)) return `it uses ${ref[1]}`;
    for (const [, t] of stepRunLines(recs)) {
      const found = publishCommand(t);
      if (found !== null) return `it runs \`${found}\``;
    }
  }
  return null;
}

/** [line, what, explicit] for a step that restores a cache, or null (ghworkflow._cache_of). */
function cacheOf(recs) {
  const use = stepUses(recs);
  const ref = use !== null ? actionRef(use[0]) : null;
  if (ref === null) return null;
  const name = ref[1].toLowerCase();
  if (inActions(name, CACHE_ACTIONS)) return [use[1], ref[1], true];
  const withs = stepWith(recs);
  for (const [action, key, dflt] of SETUP_CACHES) {
    if (name !== action) continue;
    const [value, line] = withs.get(key) ?? ["", use[1]];
    if (value !== "" && value !== "false") return [line, `${ref[1]} with ${key}: ${value}`, true];
    if (value === "" && action === "actions/setup-node") {
      if ((withs.get("package-manager-cache") ?? ["", 0])[0] !== "false") {
        return [use[1], `${ref[1]} (it may cache unless package-manager-cache: false)`, false];
      }
    } else if (value === "" && dflt) {
      return [use[1], `${ref[1]} (it caches unless ${key}: false)`, false];
    }
    return null;
  }
  return null;
}

/** The dependency install in a script line (`npm ci`, `pip install`), or null (ghworkflow.install_command). */
export function installCommand(text) {
  const m = INSTALL_RE.exec(text);
  return m && !text.includes("--ignore-scripts") ? m[1] : null;
}

/** The command in a script line that publishes a release, or null (ghworkflow.publish_command). */
export function publishCommand(text) {
  const m = PUBLISH_RE.exec(text);
  return m ? m[1] : null;
}

const SHELLS = ["sh", "bash", "zsh", "dash", "ksh", "ash", "csh", "iex", "invoke-expression", "pwsh", "powershell"];

/** Python's `pattern.match(text, pos)` for a sticky pattern. */
function matchAt(re, text, pos) {
  re.lastIndex = pos;
  return re.exec(text);
}

/** A script line that fetches a script and runs it unread: `curl … | sh`, `bash <(curl …)`, … (ghworkflow.pipe_to_shell). */
export function pipeToShell(text) {
  for (const pipeline of text.split(PIPELINE_RE)) {
    let fetched = null;
    for (const seg of pipeline.replaceAll("|&", "|").split("|")) {
      if (fetched !== null) {
        const m = matchAt(SCRIPT_HEAD_RE, seg, 0);
        if (m && (SHELLS.some((sh) => m[1].toLowerCase().startsWith(sh)) || matchAt(STDIN_ONLY_RE, seg, m.index + m[0].length))) {
          return `${fetched} … | ${m[1]}`;
        }
      }
      const f = FETCH_RE.exec(seg);
      if (f && fetched === null) fetched = f[1];
    }
  }
  const m = FETCHED_ARG_RE.exec(text);
  return m ? m[0] : null;
}

/** [[line, text]] with a script's continued lines (`… \\` at the end) joined to the line they continue (ghworkflow.logical_lines). */
export function logicalLines(lines) {
  const out = [];
  let first = 0;
  let parts = null;
  for (const [n, t] of lines) {
    if (parts === null) {
      first = n;
      parts = [];
    }
    const continued = t.endsWith("\\");
    parts.push(continued ? t.slice(0, -1) : t);
    if (!continued) {
      out.push([first, parts.join(" ")]);
      parts = null;
    }
  }
  if (parts !== null) out.push([first, parts.join(" ")]);
  return out;
}

/** [[kind, line, detail]] by line for a workflow's text (ghworkflow.hardening). */
export function hardening(source) {
  const records = outlineRecords(source, true);
  const evs = events(records);
  const steps = stepsOf(records);
  const jobs = records.filter((r) => samePath(r.path, ["jobs"]) && r.key !== null).map((r) => r.key);
  const out = [];
  const table = permissionsTable(records);
  const [present, scopes, token] = grantsOf(table, []);
  if (scopes.length) {
    out.push(["perms", scopes[0][1], { scopes: scopes.map(([s]) => s) }]);
  } else if (!present) {
    const bare = jobs.filter((j) => !grantsOf(table, ["jobs", j])[0]);
    if (bare.length) {
      const top = records.find((r) => r.path.length === 0 && r.key === "jobs");
      out.push(["perms-missing", top ? top.line : 1, { jobs: bare }]);
    }
  }
  for (const r of records) {
    const p = r.path;
    if (r.key !== "uses" || !((p.length === 4 && p[0] === "jobs" && p[2] === "steps" && p[3] === "-")
        || (p.length === 2 && p[0] === "jobs"))) continue;
    const ref = actionRef(r.value);
    if (ref !== null && !ref[3]) {
      const [kind, name, tag] = ref;
      out.push(["unpinned", r.line, {
        uses: r.value, kind, ref: tag,
        first: kind === "action" && FIRST_PARTY.some((f) => name.toLowerCase().startsWith(f)), tag: tagLike(tag)}]);
    }
  }
  if (evs.includes("pull_request_target")) {
    for (const [job, recs] of steps) {
      let hit = null;
      const use = stepUses(recs);
      const ref = use !== null ? actionRef(use[0]) : null;
      if (ref !== null && ref[1].toLowerCase() === "actions/checkout") {
        const withs = stepWith(recs);
        for (const name of ["ref", "repository"]) {
          const [value, line] = withs.get(name) ?? ["", 0];
          const m = PR_HEAD_RE.exec(value);
          if (m) {
            hit = [line, "with " + name, m[0]];
            break;
          }
        }
      }
      if (hit === null) {
        for (const [line, t] of stepRunLines(recs)) {
          let m = GH_PR_CHECKOUT_RE.exec(t);                     // always the pull request's branch
          if (m === null && PR_CHECKOUT_CMD_RE.test(t)) m = PR_HEAD_RE.exec(t);
          if (m) {
            hit = [line, "a command", m[0]];
            break;
          }
        }
      }
      if (hit !== null) out.push(["pr-checkout", hit[0], { job, via: hit[1], expr: hit[2] }]);
    }
  }
  const why = releaseWhy(table, steps, evs);
  if (why !== null) {
    for (const [job, recs] of steps) {
      const found = cacheOf(recs);
      if (found !== null) out.push(["cache", found[0], { job, what: found[1], explicit: found[2], why }]);
    }
  }
  const byJob = new Map();
  for (const [job, recs] of steps) {
    if (!byJob.has(job)) byJob.set(job, []);
    byJob.get(job).push(recs);
  }
  for (const job of jobs) {
    const [jPresent, , jToken] = grantsOf(table, ["jobs", job]);
    const [grant, source2] = jPresent ? [jToken, "job"] : [token, "workflow"];
    if (grant === null) continue;
    let hit = null;
    for (const recs of byJob.get(job) ?? []) {
      for (const [line, t] of stepRunLines(recs)) {
        const found = installCommand(t);
        if (found !== null) {
          hit = [line, found];
          break;
        }
      }
      if (hit !== null) break;
    }
    if (hit !== null) out.push(["oidc-install", hit[0], { job, from: source2, command: hit[1] }]);
  }
  for (const [job, recs] of steps) {                          // a script fetched and run without being read
    for (const [line, t] of logicalLines(stepRunLines(recs))) {
      const found = pipeToShell(t);
      if (found !== null) {
        out.push(["pipe-to-shell", line, { job, command: found }]);
        break;
      }
    }
  }
  out.sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return out;
}

const UNPINNED_WHY =
  "A tag or a branch can be moved to other code after you reviewed it: in March 2025 the tags of " +
  "tj-actions/changed-files were rewritten to a commit that printed the secrets of every workflow that used " +
  "it into its build log. A full commit SHA, or an image digest, can't be moved.";
const UNPINNED_FIX =
  "Pin it to the full 40-character commit SHA and keep the version in a comment " +
  "(`uses: owner/repo@<sha> # v4.1.0`); let Dependabot or Renovate propose the updates. " +
  "For an image, pin `@sha256:…`.";
const PR_CHECKOUT_WHY =
  "pull_request_target runs the base repository's workflow with its secrets and a token that can write, so " +
  "that a workflow can answer a pull request from a fork. Running the fork's code there lets anyone who can " +
  "open a pull request run commands with that access (the \"pwn request\").";
const CACHE_WHY =
  "A cache entry can be written by any job that can write to the repository's cache, and the next run " +
  "restores it as it is: a poisoned entry changes the build that gets published without any change to the " +
  "source.";
const PERMS_WHY =
  "A job should get only the access it uses. A workflow-level `permissions:` with a write scope hands it to " +
  "every job, the ones that run third-party actions and install dependencies among them.";
export const PIPE_SHELL_FIX =
  "Save the script to a file, check its SHA-256 against a value kept in the repository, then run it; or install " +
  "the tool from a package manager at a version, with its hash.";
export const PIPE_SHELL_WHY =
  "A script piped into a shell is not read before it runs: whoever controls the host, or anyone on the path when " +
  "the address is not HTTPS, decides what runs, with the job's token and secrets. The Codecov Bash Uploader, " +
  "piped into a shell by thousands of pipelines, was changed for two months in 2021 to send each job's " +
  "environment to a server of the attacker's.";
const OIDC_WHY =
  "Dependencies run code while they install and build, with the job's permissions. An OIDC token is what a " +
  "package registry's trusted publishing and a cloud account's federation take as proof of identity, so code " +
  "that can request one can publish or deploy as the workflow.";

/** The issue rule of one hardening() finding (ghworkflow.hardening_rule). */
export function hardeningRule(kind, d) {
  if (kind === "unpinned") {
    const what = d.kind === "docker" ? "the image" : (d.kind === "workflow" ? "the reusable workflow" : "");
    const pin = d.kind === "docker" ? "a digest" : "a full commit SHA";
    const small = d.kind === "action" && d.first && d.tag;
    return {
      id: "SC-WORKFLOW-UNPINNED", name: "Workflow runs something not pinned to a commit",
      type: "HOTSPOT", sev: small ? "MINOR" : "MAJOR",
      msg: `The workflow runs ${what ? what + " " : ""}${d.uses}, which is not pinned to ${pin}: ` +
        "whoever controls that ref can change what runs in your pipeline.",
      why: UNPINNED_WHY, fix: UNPINNED_FIX, ref: "CWE-829 · Supply chain"};
  }
  if (kind === "pr-checkout") {
    return {
      id: "SC-WORKFLOW-PR-CHECKOUT", name: "pull_request_target job checks out the pull request",
      type: "HOTSPOT", sev: "CRITICAL",
      msg: `The job "${d.job}" runs on pull_request_target and checks out the pull request's code ` +
        `(${d.via}: ${d.expr}): whatever it then installs, builds or runs gets the repository's ` +
        "secrets and a token that can write.",
      why: PR_CHECKOUT_WHY,
      fix: "Run a pull request's code under `pull_request` (no secrets, a read-only token). If a job needs " +
        "secrets, check out only the base branch and treat the pull request's files as data: never " +
        "install, build or run them.",
      ref: "CWE-94 · Supply chain"};
  }
  if (kind === "cache") {
    return {
      id: "SC-WORKFLOW-CACHE", name: "Release workflow restores a build cache",
      type: "HOTSPOT", sev: d.explicit ? "MAJOR" : "MINOR",
      msg: `The job "${d.job}" restores a cache (${d.what}) in a workflow where ${d.why}: what ` +
        "the cache holds runs with the release's token.",
      why: CACHE_WHY,
      fix: "Build the release without restored caches: no actions/cache, `cache:` off in the setup " +
        "actions, `package-manager-cache: false` for setup-node. The build is slower, and its inputs " +
        "are the ones in the commit.",
      ref: "CWE-345 · Supply chain"};
  }
  if (kind === "perms") {
    const scopes = d.scopes.map((s) => (s === "all" ? "write-all" : s));
    return {
      id: "SC-WORKFLOW-PERMISSIONS", name: "Workflow grants write permissions to every job",
      type: "HOTSPOT", sev: "MAJOR",
      msg: `The workflow's token has write access in every job (${scopes.join(", ")}): a step in any job, ` +
        "or any action it runs, can use it.",
      why: PERMS_WHY,
      fix: "Set `permissions: contents: read` at the top of the workflow and grant a write scope only in " +
        "the job that needs it.",
      ref: "CWE-250 · Supply chain"};
  }
  if (kind === "perms-missing") {
    const names = d.jobs.slice(0, 3).map((j) => `"${j}"`).join(", ")
      + (d.jobs.length > 3 ? ` and ${d.jobs.length - 3} more` : "");
    const who = d.jobs.length === 1 ? `the job ${names} has` : `the jobs ${names} have`;
    return {
      id: "SC-WORKFLOW-PERMISSIONS", name: "Workflow sets no permissions",
      type: "HOTSPOT", sev: "MINOR",
      msg: `The workflow sets no top-level \`permissions:\`, and ${who} none of its own: the token gets the ` +
        "repository's default permissions, which can include write access.",
      why: PERMS_WHY,
      fix: "Set `permissions: contents: read` at the top of the workflow and grant more only where a job needs it.",
      ref: "CWE-250 · Supply chain"};
  }
  if (kind === "pipe-to-shell") {
    return {
      id: "SC-WORKFLOW-PIPE-SHELL", name: "Workflow runs a script it downloads without reading it",
      type: "HOTSPOT", sev: "MAJOR",
      msg: `The job "${d.job}" fetches a script and runs it as it arrives (\`${d.command}\`): it runs ` +
        "whatever that address serves at that moment.",
      why: PIPE_SHELL_WHY, fix: PIPE_SHELL_FIX, ref: "CWE-494 · Supply chain"};
  }
  return {
    id: "SC-WORKFLOW-OIDC-INSTALL", name: "Job that installs dependencies can request an OIDC token",
    type: "HOTSPOT", sev: "MAJOR",
    msg: `The job "${d.job}" can request an OIDC token (${d.from === "job" ? "its own permissions" : "the workflow permissions"}) ` +
      `and runs \`${d.command}\`: an install script or build hook of a dependency can request it too.`,
    why: OIDC_WHY,
    fix: "Install and build in a job without `id-token: write`, upload the result as an artifact, and " +
      "publish from a separate job that only downloads it and installs nothing.",
    ref: "CWE-250 · Supply chain"};
}

/** The hardening checks' pattern text and lists, for the parity test. */
export const HARDENING_TWINS = {
  patterns: {
    _PR_HEAD_RE: PR_HEAD_SRC, _PR_CHECKOUT_CMD_RE: PR_CHECKOUT_CMD_SRC, _GH_PR_CHECKOUT_RE: GH_PR_CHECKOUT_SRC,
    _WRITE_SCOPE_RE: WRITE_SCOPE_SRC,
    _INSTALL_RE: INSTALL_SRC, _PUBLISH_RE: PUBLISH_SRC,
    _FETCH_RE: FETCH_SRC, _SCRIPT_HEAD_RE: SCRIPT_HEAD_SRC, _FETCHED_ARG_RE: FETCHED_ARG_SRC,
    _STDIN_ONLY_RE: STDIN_ONLY_SRC, _PIPELINE_RE: PIPELINE_SRC},
  ignoreCase: ["_FETCH_RE", "_SCRIPT_HEAD_RE", "_FETCHED_ARG_RE"],
  lists: { PUBLISH_ACTIONS, CACHE_ACTIONS, SETUP_CACHES, FIRST_PARTY },
};
