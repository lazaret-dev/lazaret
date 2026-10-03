// GitLab CI files: the supply-chain checks of the CI/CD review, in GitLab's terms (0.1.9, S-3) —
// twin of lazaret.scanner.gitlabci, rule for rule.
//
// `.gitlab-ci.yml` runs whatever it includes, pulls, downloads and expands with the project's
// variables: an `include:` of a URL, of a project's file or a component that is not at a commit; an
// `image:` or a service without a digest; a script that fetches a script and runs it unread; a script
// that hands a merge request's, a commit's or a branch's text to `eval`, `sh -c` or the place of a
// command; and a job that holds a publishing credential and installs dependencies. Like ghworkflow.js
// this reads the outline of the YAML, not YAML: anchors, `extends:`, `!reference` and multi-line flow
// collections are read as the plain text they are.

import { pyRe, pyStripChars } from "./pycompat.js";
import {
  yamlRecords, installCommand, pipeToShell, logicalLines, COMMAND_START, PIPE_SHELL_WHY, PIPE_SHELL_FIX,
} from "./ghworkflow.js";

/** The keys that hold a job's commands (gitlabci.SCRIPT_KEYS). */
export const SCRIPT_KEYS = ["before_script", "script", "after_script"];
const GLOBAL_KEYS = ["image", "services", "before_script", "after_script"];
const NOT_JOBS = ["variables", "stages", "include", "workflow", "cache", "spec", "inputs"];
const HEX = "0123456789abcdefABCDEF";
const DIGITS = "0123456789";

const EXACT_SRC = String.raw`\Av?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?\Z`;
const MR_VAR_SRC =
  String.raw`\$\{?(?:CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME|LABELS)` +
  String.raw`|CI_COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|REF_NAME|BRANCH|TAG_MESSAGE)` +
  String.raw`|CI_EXTERNAL_PULL_REQUEST_SOURCE_BRANCH_NAME)\b\}?`;
const COMMAND_VAR_SRC = COMMAND_START + "(" + MR_VAR_SRC + ")";
const EVAL_SRC = COMMAND_START + String.raw`eval\b`;
const SHELL_C_SRC =
  COMMAND_START + String.raw`(?:[\w./-]*/)?(?:ba|z|da|k|a|c)?sh(?:\s+-[A-Za-z]+)*\s+-[A-Za-z]*c(?![A-Za-z])`;
const ARG_SRC = String.raw`\s+(\"(?:[^\"\\]|\\.)*\"|'[^']*'|[^\s;&|\"']+)`;
const TOKEN_VAR_SRC =
  String.raw`\$\{?(?:NPM_TOKEN|NODE_AUTH_TOKEN|PYPI_[A-Z_]{0,30}TOKEN|TWINE_PASSWORD|CARGO_REGISTRY_TOKEN` +
  String.raw`|GEM_HOST_API_KEY|RUBYGEMS_API_KEY|CI_JOB_JWT(?:_V2)?)\b\}?`;
const EXACT_RE = pyRe(EXACT_SRC);
const MR_VAR_RE = pyRe(MR_VAR_SRC);
const COMMAND_VAR_RE = pyRe(COMMAND_VAR_SRC);
const EVAL_RE = pyRe(EVAL_SRC, "g");
const SHELL_C_RE = pyRe(SHELL_C_SRC, "g");
const ARG_RE = pyRe(ARG_SRC, "y");
const TOKEN_VAR_RE = pyRe(TOKEN_VAR_SRC);

/** Is path a GitLab CI file (gitlabci.is_gitlab_ci)? */
export function isGitlabCi(path) {
  const parts = path.replaceAll("\\", "/").split("/");
  const name = parts[parts.length - 1].toLowerCase();
  if (name.endsWith(".gitlab-ci.yml") || name.endsWith(".gitlab-ci.yaml")) return true;
  return (name.endsWith(".yml") || name.endsWith(".yaml")) && parts.slice(0, -1).some((p) => p.toLowerCase() === ".gitlab");
}

const isHex = (s, n) => [...s].length === n && [...s].every((c) => HEX.includes(c));
const isUrl = (s) => s.slice(0, 8).toLowerCase() === "https://" || s.slice(0, 7).toLowerCase() === "http://";
const tagLike = (ref) => ref !== "" && (DIGITS.includes(ref[0]) || (ref[0] === "v" && ref.slice(1, 2) !== "" && DIGITS.includes(ref[1])));
const stripST = (s) => pyStripChars(s, " \t");

function unquote(s) {
  s = stripST(s);
  if ([...s].length >= 2 && (s[0] === '"' || s[0] === "'") && s[s.length - 1] === s[0]) return s.slice(1, -1);
  return s;
}

/** s split at `sep` outside quotes and brackets, at most `maxsplit` times (gitlabci._split_top). */
function splitTop(s, sep, maxsplit = -1) {
  const out = [];
  let depth = 0;
  let quote = "";
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = "";
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === "[" || c === "{") {
      depth++;
    } else if (c === "]" || c === "}") {
      depth = Math.max(depth - 1, 0);
    } else if (c === sep && depth === 0 && out.length !== maxsplit) {
      out.push(s.slice(start, i));
      start = i + 1;
    }
  }
  out.push(s.slice(start));
  return out;
}

function flowItem(s) {
  s = stripST(s);
  if (!s.startsWith("{")) return unquote(s);
  const out = new Map();
  for (const pair of splitTop(s.endsWith("}") ? s.slice(1, -1) : s.slice(1), ",")) {
    const kv = splitTop(pair, ":", 1);
    if (kv.length === 2) {
      const k = unquote(kv[0]);
      if (!out.has(k)) out.set(k, unquote(kv[1]));
    }
  }
  return out;
}

/** The items of a flow collection on one line: strings, and Maps of a map's values (gitlabci.flow_items). */
export function flowItems(text) {
  const t = stripST(text);
  if (t.startsWith("[")) {
    const body = t.endsWith("]") ? t.slice(1, -1) : t.slice(1);
    return splitTop(body, ",").filter((x) => stripST(x) !== "").map(flowItem);
  }
  if (t.startsWith("{")) return [flowItem(t)];
  return t ? [unquote(t)] : [];
}

/** [name, tag, digest] of an image reference (gitlabci.parse_image). */
export function parseImage(value) {
  const v = stripST(value);
  const at = v.indexOf("@");
  const name = at < 0 ? v : v.slice(0, at);
  const digest = at < 0 ? "" : v.slice(at + 1);
  const cut = name.lastIndexOf(":");
  if (cut > name.lastIndexOf("/")) return [name.slice(0, cut), name.slice(cut + 1), digest];
  return [name, "", digest];
}

/** [variable, how] for a script line that hands text anyone can write to code, or null (gitlabci.mr_text). */
export function mrText(text) {
  if (!MR_VAR_RE.test(text)) return null;
  let m = COMMAND_VAR_RE.exec(text);
  if (m) return [m[1], "the place of a command"];
  for (const [pattern, how, limit] of [[EVAL_RE, "eval", null], [SHELL_C_RE, "a `sh -c` string", 1]]) {
    let pos = 0;
    for (;;) {
      pattern.lastIndex = pos;
      m = pattern.exec(text);
      if (m === null) break;
      pos = m.index + m[0].length;
      let taken = 0;
      while (limit === null || taken < limit) {
        ARG_RE.lastIndex = pos;
        const arg = ARG_RE.exec(text);
        if (arg === null) break;
        pos = arg.index + arg[0].length;
        taken++;
        const word = arg[1];
        const found = word.startsWith("'") ? null : MR_VAR_RE.exec(word);
        if (found) return [found[0], how];
      }
    }
  }
  return null;
}

const linesOf = (r) => (r.value.startsWith("[")
  ? flowItems(r.value).filter((x) => typeof x === "string").map((x) => [r.line, x]).concat(r.block)
  : (r.value ? [[r.line, r.value]] : []).concat(r.block));
const itemLines = (r) => (r.key === null ? linesOf(r)
  : [[r.line, r.value ? r.key + ": " + r.value : r.key + ":"]].concat(r.block));
const allDashes = (a) => a.every((x) => x === "-");

/** {owner: job} (gitlabci._jobs). */
function jobsOf(records) {
  const jobs = new Map();
  for (const r of records) {
    const { path, key } = r;
    let owner;
    let rest;
    if (path.length === 0) {
      if (!GLOBAL_KEYS.includes(key)) continue;
      owner = "default";
      rest = [];
    } else if (GLOBAL_KEYS.includes(path[0])) {
      owner = "default";
      rest = path;
    } else if (NOT_JOBS.includes(path[0])) {
      continue;
    } else {
      owner = path[0];
      rest = path.slice(1);
    }
    let job = jobs.get(owner);
    if (job === undefined) {
      job = { scripts: { before_script: [], script: [], after_script: [] }, loose: [], images: [], idTokens: null, secrets: null };
      jobs.set(owner, job);
    }
    if (rest.length === 0) {
      const value = r.value;
      if (SCRIPT_KEYS.includes(key)) {
        job.scripts[key].push(...linesOf(r));
      } else if (key === "image" && value) {
        for (const item of value.startsWith("{") ? flowItems(value) : [value]) {
          const name = item instanceof Map ? item.get("name") ?? "" : item;
          if (name) job.images.push([r.line, name, "image"]);
        }
      } else if (key === "services" && value.startsWith("[")) {
        for (const item of flowItems(value)) {
          const name = item instanceof Map ? item.get("name") ?? "" : item;
          if (name) job.images.push([r.line, name, "service"]);
        }
      } else if (key === "id_tokens" && job.idTokens === null) {
        job.idTokens = r.line;
      } else if (key === "secrets" && job.secrets === null) {
        job.secrets = r.line;
      }
    } else if (SCRIPT_KEYS.includes(rest[0]) && rest.length >= 2 && allDashes(rest.slice(1))) {
      job.scripts[rest[0]].push(...itemLines(r));
    } else if (rest.length === 1 && rest[0] === "image" && key === "name" && r.value) {
      job.images.push([r.line, r.value, "image"]);
    } else if (rest.length === 2 && rest[0] === "services" && rest[1] === "-" && (key === null || key === "name") && r.value) {
      job.images.push([r.line, r.value, "service"]);
    } else if (owner.startsWith(".") && key === null && rest.length > 0 && allDashes(rest)) {
      job.loose.push(...linesOf(r));
    }
  }
  return jobs;
}

/** [[line, item]]: what `include:` names; an item is a string or a Map of its fields (gitlabci._includes). */
function includesOf(records) {
  const items = [];
  let cur = null;
  let single = null;
  for (const r of records) {
    const { path, key } = r;
    if (path.length === 0) {
      if (key === "include") {
        cur = single = null;
        if (r.value.startsWith("[") || r.value.startsWith("{")) {
          for (const it of flowItems(r.value)) items.push([r.line, it]);
        } else if (r.value) {
          items.push([r.line, unquote(r.value)]);
        }
      }
      continue;
    }
    if (path[0] !== "include") continue;
    if (path.length === 1 && key !== null) {
      if (single === null) {
        single = [r.line, new Map()];
        items.push(single);
      }
      if (!single[1].has(key)) single[1].set(key, r.value);
    } else if (path.length === 2 && path[1] === "-") {
      if (r.item) {
        if (key === null) {
          items.push([r.line, r.value]);
          cur = null;
        } else {
          cur = [r.line, new Map([[key, r.value]])];
          items.push(cur);
        }
      } else if (cur !== null && key !== null && !cur[1].has(key)) {
        cur[1].set(key, r.value);
      }
    }
  }
  return items;
}

/** The commands a job runs, in order: its before_script (the default's when it has none), script, after_script. */
function effective(jobs, name) {
  const job = jobs.get(name);
  const base = jobs.get("default");
  const pick = (k) => (job.scripts[k].length || base === undefined ? job.scripts[k] : base.scripts[k]);
  return [...pick("before_script"), ...job.scripts.script, ...pick("after_script")];
}

/** [[kind, line, detail]] by line for a GitLab CI file's text (gitlabci.hardening). */
export function hardening(source) {
  const records = yamlRecords(source, true, true);
  const jobs = jobsOf(records);
  const out = [];
  for (const [line, item] of includesOf(records)) {
    const fields = item instanceof Map ? item : isUrl(item) ? new Map([["remote", item]]) : new Map();
    const remote = fields.get("remote") ?? "";
    if (remote) {
      out.push(["include-remote", line, { url: remote, http: remote.slice(0, 7).toLowerCase() === "http://" }]);
    } else if (fields.has("project")) {
      const ref = fields.get("ref") ?? "";
      if (!isHex(ref, 40) && ref !== "$CI_COMMIT_SHA" && ref !== "${CI_COMMIT_SHA}") {
        out.push(["include-project", line, { project: fields.get("project"), ref, tag: tagLike(ref) }]);
      }
    } else if (fields.has("component")) {
      const value = fields.get("component");
      const at = value.indexOf("@");
      const name = at < 0 ? value : value.slice(0, at);
      const ref = at < 0 ? "" : value.slice(at + 1);
      if (!isHex(ref, 40)) out.push(["include-component", line, { component: name, ref, exact: EXACT_RE.test(ref) }]);
    }
  }
  for (const [owner, job] of jobs) {
    for (const [line, value, where] of job.images) {
      if (value.startsWith("$CI_REGISTRY_IMAGE") || value.startsWith("${CI_REGISTRY_IMAGE")) continue;
      const [name, tag, digest] = parseImage(value);
      if (digest.startsWith("sha256:") && isHex(digest.slice(7), 64)) continue;
      out.push(["image", line, { job: owner, image: value, where, tag, official: !name.includes("/") }]);
    }
  }
  for (const [owner, job] of jobs) {
    const sections = [...SCRIPT_KEYS.map((k) => job.scripts[k]), job.loose];
    for (const kind of ["pipe-to-shell", "mr-text"]) {
      let hit = null;
      for (const section of sections) {
        for (const [line, t] of logicalLines(section)) {
          const found = kind === "pipe-to-shell" ? pipeToShell(t) : mrText(t);
          if (found !== null) {
            hit = [line, found];
            break;
          }
        }
        if (hit !== null) break;
      }
      if (hit === null) continue;
      if (kind === "pipe-to-shell") out.push([kind, hit[0], { job: owner, command: hit[1] }]);
      else out.push([kind, hit[0], { job: owner, variable: hit[1][0], how: hit[1][1] }]);
    }
  }
  const base = jobs.get("default");
  for (const [owner, job] of jobs) {
    if (owner === "default") continue;
    const lines = effective(jobs, owner);
    let grant = null;
    if (job.idTokens !== null) {
      grant = "its id_tokens";
    } else if (base !== undefined && base.idTokens !== null) {
      grant = "the default id_tokens";
    } else if (job.secrets !== null) {
      grant = "its secrets";
    } else {
      for (const [, t] of lines) {
        const m = TOKEN_VAR_RE.exec(t);
        if (m) {
          grant = m[0];
          break;
        }
      }
    }
    if (grant === null) continue;
    for (const [line, t] of lines) {
      const found = installCommand(t);
      if (found !== null) {
        out.push(["token-install", line, { job: owner, grant, command: found }]);
        break;
      }
    }
  }
  out.sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return out;
}

const INCLUDE_WHY =
  "An included file becomes part of the pipeline: its jobs run with the project's variables, its secrets and its " +
  "runners. A file from a URL can't be pinned to a commit or a hash, so it can change between two pipelines with " +
  "no change in the repository (a new file at that address, a domain that expired and was bought, a man in the " +
  "middle on plain HTTP). A branch moves with every push to it, and a tag can be moved too.";
const INCLUDE_FIX =
  "Copy the file into the repository, or include it from a project at a full commit SHA (`ref: <sha>`) or a " +
  "component at one (`component: gitlab.com/group/project/name@<sha>`), where a change is a commit you can " +
  "review; let Renovate propose the updates.";
const IMAGE_WHY =
  "A tag names whatever image its owner pushed last, and `latest` or any tag a maintainer can push again lets " +
  "them, or an attacker with their account, change the image your jobs run in, with the job's variables and " +
  "token. A digest (`@sha256:…`) names one image.";
const IMAGE_FIX =
  "Pin it to a digest and keep the tag next to it for readers (`image: python:3.12@sha256:<digest>`); let " +
  "Renovate propose the updates.";
const MR_WHY =
  "A variable holds the text as it is, but `eval` and `sh -c` read their argument again as shell code. A merge " +
  "request's title and description, a commit message and a branch name can hold `$(…)` and backticks, and " +
  "whoever can open a merge request or push a branch writes them: they can run commands in the job, with its " +
  "variables and token.";
const MR_FIX =
  "Don't pass these through `eval` or `sh -c`. As an argument of a command (`\"$CI_COMMIT_TITLE\"`) the text is " +
  "data; inside a script that you run, read it from the environment, and check it against a short pattern first.";
const TOKEN_WHY =
  "Dependencies run code while they install and build, with the job's variables. An OIDC token (`id_tokens`), a " +
  "registry's token and the secrets a job fetches are what a registry, a cloud account or a signing service " +
  "takes as proof of identity, so code that can read one can publish or deploy as the pipeline.";
const TOKEN_FIX =
  "Install and build in a job without the credential, pass the result on as an artifact, and publish from a " +
  "separate job that only downloads it and installs nothing.";

/** The issue rule of one hardening() finding (gitlabci.hardening_rule). */
export function hardeningRule(kind, d) {
  if (kind === "include-remote") {
    return {
      id: "SC-GITLAB-INCLUDE", name: "Pipeline includes a file from a URL",
      type: "HOTSPOT", sev: d.http ? "CRITICAL" : "MAJOR",
      msg: `The pipeline includes ${d.url}: GitLab fetches it every time a pipeline runs` +
        (d.http ? ", over plain HTTP, so that anyone on the path can change it, and" : ", and") +
        " whoever controls that address decides what the pipeline does.",
      why: INCLUDE_WHY, fix: INCLUDE_FIX, ref: "CWE-829 · Supply chain"};
  }
  if (kind === "include-project") {
    const at = d.ref === "" ? "no ref (its default branch)" : `the ref "${d.ref}"`;
    return {
      id: "SC-GITLAB-INCLUDE", name: "Pipeline includes a project's file that is not pinned to a commit",
      type: "HOTSPOT", sev: d.tag ? "MINOR" : "MAJOR",
      msg: `The pipeline includes a file from ${d.project} at ${at}, not a full commit SHA: whoever can push ` +
        "to that ref changes what runs in your pipeline.",
      why: INCLUDE_WHY, fix: INCLUDE_FIX, ref: "CWE-829 · Supply chain"};
  }
  if (kind === "include-component") {
    const at = d.ref === "" || d.ref === "~latest" ? "its latest version" : `the version "${d.ref}"`;
    return {
      id: "SC-GITLAB-INCLUDE", name: "Pipeline uses a component that is not pinned to a commit",
      type: "HOTSPOT", sev: d.exact ? "MINOR" : "MAJOR",
      msg: `The pipeline uses the component ${d.component} at ${at}, not a full commit SHA: whoever ` +
        "publishes to it changes what runs in your pipeline.",
      why: INCLUDE_WHY, fix: INCLUDE_FIX, ref: "CWE-829 · Supply chain"};
  }
  if (kind === "image") {
    const small = d.official && d.tag !== "" && d.tag !== "latest";
    const who = d.job === "default" ? "The file's default settings use"
      : `The job "${d.job}" ` + (d.where === "service" ? "starts the service" : "runs");
    return {
      id: "SC-GITLAB-IMAGE", name: "Pipeline runs an image not pinned to a digest",
      type: "HOTSPOT", sev: small ? "MINOR" : "MAJOR",
      msg: `${who} ${d.image}, which is not pinned to a digest: whoever controls that tag can change what ` +
        "runs in your pipeline.",
      why: IMAGE_WHY, fix: IMAGE_FIX, ref: "CWE-829 · Supply chain"};
  }
  if (kind === "pipe-to-shell") {
    return {
      id: "SC-GITLAB-PIPE-SHELL", name: "Pipeline runs a script it downloads without reading it",
      type: "HOTSPOT", sev: "MAJOR",
      msg: `The job "${d.job}" fetches a script and runs it as it arrives (\`${d.command}\`): it runs ` +
        "whatever that address serves at that moment.",
      why: PIPE_SHELL_WHY, fix: PIPE_SHELL_FIX, ref: "CWE-494 · Supply chain"};
  }
  if (kind === "mr-text") {
    return {
      id: "SC-GITLAB-MR-TEXT", name: "Script runs text anyone can write as code",
      type: "HOTSPOT", sev: "MAJOR",
      msg: `The job "${d.job}" puts ${d.variable} in ${d.how}: it is text of a merge request, a commit ` +
        "or a branch, which anyone who can open one writes, and the shell reads it as commands.",
      why: MR_WHY, fix: MR_FIX, ref: "CWE-94 · Supply chain"};
  }
  return {
    id: "SC-GITLAB-TOKEN-INSTALL", name: "Job that installs dependencies holds a publishing credential",
    type: "HOTSPOT", sev: "MAJOR",
    msg: `The job "${d.job}" holds a publishing credential (${d.grant}) and runs \`${d.command}\`: an ` +
      "install script or build hook of a dependency runs with it.",
    why: TOKEN_WHY, fix: TOKEN_FIX, ref: "CWE-250 · Supply chain"};
}

/** The checks' pattern text and lists, for the parity test. */
export const GITLAB_TWINS = {
  patterns: {
    _EXACT_RE: EXACT_SRC, _MR_VAR_RE: MR_VAR_SRC, _COMMAND_VAR_RE: COMMAND_VAR_SRC, _EVAL_RE: EVAL_SRC,
    _SHELL_C_RE: SHELL_C_SRC, _ARG_RE: ARG_SRC, _TOKEN_VAR_RE: TOKEN_VAR_SRC},
  lists: { SCRIPT_KEYS, _GLOBAL_KEYS: GLOBAL_KEYS, _NOT_JOBS: NOT_JOBS },
};
