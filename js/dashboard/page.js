// The browser dashboard (python/src/lazaret/web/lazaret.html): its input, its output and nothing else. The scan is
// the npm package's (lib/collect.js collectEntry for each upload, as the CLI's walk collects each file it meets;
// scancollection.js; result.js) on the engine the page carries (./wasmload.js), so the page reports what the CLI
// reports for the same files. scripts/make_dashboard.py builds the page from this module and those it imports.
//
// Where the page and the CLI differ, it is input: the page reads the files it is given (no directory walk, so no
// pruned trees, links or unreadable entries; nothing is a dependency's) or the code pasted into it; it does not
// follow a package.json's install hooks into the files they run, which the CLI reads from disk (deps.js
// projectHookChecks); and it scans on the tab's thread, so a file over PAGE_MAX_FILE_BYTES (the CLI's default
// limit until 0.1.9) is not read but reported SC-TRUNCATED. Every finding is redacted, as the CLI's by default.

import { collectEntry } from "../src/lib/collect.js";
import { HEADER_SAMPLE, DISGUISE_SAMPLE } from "../src/lib/binary.js";
import { CONFIG_SCAN_CAP } from "../src/lib/configsecrets.js";
import { scanErrorIssue } from "../src/lib/issue.js";
import { redactResult } from "../src/lib/redact.js";
import { SEV_ORDER, TYPES } from "../src/scanner/rules.js";
import { detectLang } from "../src/scanner/scan.js";
import { collectionIssues } from "../src/scancollection.js";
import { gradeResult, localIso } from "../src/result.js";
import { loadEngine } from "./wasmload.js";

/** The size cap of a file the page reads (the CLI's is 16,000,000 bytes: lib/collect.js MAX_FILE_BYTES). */
export const PAGE_MAX_FILE_BYTES = 2_000_000;
/** An upload is read whole up to this size; of a larger one, the first READ_HEAD bytes (all collectEntry reads). */
const READ_WHOLE = Math.max(PAGE_MAX_FILE_BYTES, CONFIG_SCAN_CAP) + 1;
const READ_HEAD = Math.max(HEADER_SAMPLE, DISGUISE_SAMPLE);

/**
 * A file the page scans, as collectEntry reads one: its name, size and the bytes the page read of it (all of
 * them, or its first READ_HEAD of a file over READ_WHOLE).
 */
function pageEntry(rel, size, bytes) {
  return {
    rel, name: rel.split("/").pop(), size, dep: false,
    read(limit) {
      if (limit > bytes.length && bytes.length < size) throw new Error(`only the first ${bytes.length} bytes were read`);
      return bytes.subarray(0, limit);
    },
    head(limit) { return bytes.subarray(0, limit); },
  };
}

/** The result for `entries` (the CLI's scan of a directory holding those files), with their names and the time. */
export function scanEntries(entries) {
  const col = { files: [], manifests: [], pth: [], configs: [], binaryIssues: [], skippedIssues: [],
    maxFileBytes: PAGE_MAX_FILE_BYTES };
  for (const e of entries) {
    try { collectEntry(e, col); } catch (err) { col.binaryIssues.push(scanErrorIssue(e.rel, err)); }
  }
  const res = redactResult(gradeResult(col.files, collectionIssues(col)));
  res.metrics.configFiles = col.configs.length;
  return { files: entries.map((e) => e.rel), scannedAt: localIso(), ...res };
}

/* ======== the page ======== */
const $ = (s) => document.querySelector(s);
let uploaded = [];            // [{rel, size, bytes}] in the walk's order (by name)
let lastResult = null;
const fSev = new Set(), fType = new Set();
let fText = "";
let curPage = 0;              // current issues page (0-based)

function setStatus(html) { $("#status").innerHTML = html; }
const nextFrame = () => new Promise((done) => (typeof requestAnimationFrame === "function"
  ? requestAnimationFrame(() => setTimeout(done, 0)) : setTimeout(done, 0)));
// The engine is compiled as the page opens (its data block comes before this script); a scan waits for it.
let engineError = null;
const engineReady = loadEngine().then(() => true, (e) => {
  engineError = `<div class="read-errs"><b>The scan engine could not be loaded:</b> ${esc(e && e.message ? e.message : e)}</div>`;
  setStatus(engineError);
  return false;
});

$("#files").addEventListener("change", async (e) => {
  uploaded = [];
  const readErrs = [];
  const picked = [...e.target.files];
  // Read every file at once; a failed read must not abort the batch (G18): collect it, keep going, and always
  // repaint so the UI never shows a stale selection while pasted code would silently still be scanned. A file
  // over READ_WHOLE is read only as far as collectEntry looks into it (it is reported SC-TRUNCATED, or skipped as
  // a config file too large to check).
  const settled = await Promise.allSettled(picked.map((f) =>
    (f.size > READ_WHOLE ? f.slice(0, READ_HEAD) : f).arrayBuffer()));
  settled.forEach((r, k) => {
    const f = picked[k];
    if (r.status === "fulfilled") uploaded.push({ rel: f.name, size: f.size, bytes: new Uint8Array(r.value) });
    else readErrs.push({ name: f.name, reason: r.reason && r.reason.message ? r.reason.message : String(r.reason) });
  });
  uploaded.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));   // the walk's order (fs.js listDir)
  if (uploaded.length) $("#code").value = "";   // uploads replace pasted code
  $("#filelist").innerHTML = uploaded.length ? `<b>${uploaded.length} file(s):</b> ${uploaded.map((f) => esc(f.rel)).join(", ")}` : "";
  if (readErrs.length) {
    $("#filelist").innerHTML += `<div class="read-errs"><b>${readErrs.length} file(s) could not be read (not scanned):</b> ${readErrs.map((x) => esc(x.name) + " (" + esc(x.reason) + ")").join(", ")}</div>`;
  }
});

/** What the page scans: the uploads, and the pasted code as pasted-code.<py|js|sql> (its UTF-8 bytes). */
function pageEntries() {
  const entries = uploaded.map((f) => pageEntry(f.rel, f.size, f.bytes));
  const pasted = $("#code").value;
  if (pasted.trim()) {          // scanned as pasted (untrimmed), so line numbers match the text box
    let lang = $("#lang").value;
    if (lang === "auto") lang = detectLang("", pasted);
    const ext = { py: "py", js: "js", sql: "sql" }[lang] || "js";
    const bytes = new TextEncoder().encode(pasted);
    entries.push(pageEntry(`pasted-code.${ext}`, bytes.length, bytes));
  }
  return entries;
}

$("#scanBtn").addEventListener("click", async () => {
  const entries = pageEntries();
  if (!entries.length) { alert("Paste some code or upload files first."); return; }
  const btn = $("#scanBtn");
  btn.disabled = true;
  setStatus("Scanning…");
  try {
    if (!(await engineReady)) { setStatus(engineError); return; }
    await loadEngine();                   // (instances made ahead again, after a scan that used one)
    await nextFrame();                    // the status shown before the scan holds the tab
    lastResult = scanEntries(entries);
    setStatus("");
  } catch (e) {
    setStatus(`<div class="read-errs"><b>The scan failed:</b> ${esc(e && e.message ? e.message : e)}</div>`);
    return;
  } finally {
    btn.disabled = false;
  }
  renderOverview(); renderFilters(lastResult.issues);
  curPage = 0; renderIssues();          // new result set → restart at page 1
  $("#overview").style.display = "block"; $("#issuesPanel").style.display = "block";
  $("#overview").scrollIntoView({ behavior: "smooth" });
});

function ratingBadge(r) {
  const colors = { A: "var(--rA)", B: "var(--rB)", C: "var(--rC)", D: "var(--rD)", E: "var(--rE)" };
  return `<span class="rating" style="background:${colors[r]}">${r}</span>`;
}
function renderOverview() {
  const R = lastResult;
  $("#gateBadge").textContent = R.pass ? "Quality Gate: Passed" : "Quality Gate: Failed";
  $("#gateBadge").className = "gate-badge " + (R.pass ? "pass" : "fail");
  $("#gateConds").innerHTML = R.conditions.map((c) => `<span class="cond ${c.ok ? "ok" : "ko"}">${c.ok ? "✓" : "✗"} ${esc(c.label)}</span>`).join("");
  const alarm = (n) => (n ? ' style="color:var(--fail)"' : "");
  $("#cards").innerHTML = `
    <div class="card"><div class="num">${R.counts.VULN}${ratingBadge(R.ratings.security)}</div><div class="lbl">Vulnerabilities · Security</div></div>
    <div class="card"><div class="num">${R.counts.HOTSPOT}</div><div class="lbl">Security Hotspots</div></div>
    <div class="card"><div class="num">${R.counts.BUG}${ratingBadge(R.ratings.reliability)}</div><div class="lbl">Bugs · Reliability</div></div>
    <div class="card"><div class="num">${R.counts.SMELL}${ratingBadge(R.ratings.maintainability)}</div><div class="lbl">Code Smells · Maintainability</div></div>
    <div class="card"><div class="num"${alarm(R.supplyChain)}>${R.supplyChain}</div><div class="lbl">Supply-chain Indicators</div></div>
    <div class="card"><div class="num"${alarm(R.crossFile)}>${R.crossFile}</div><div class="lbl">Cross-file Taint Flows</div></div>
    <div class="card"><div class="num">${R.metrics.dupPct}%</div><div class="lbl">Duplication</div></div>
    <div class="card"><div class="num">${R.metrics.ncloc}</div><div class="lbl">Lines of Code</div></div>`;
}

function renderFilters(issues) {
  fSev.clear(); fType.clear(); fText = "";
  const sevs = [...new Set(issues.map((i) => i.sev))].sort((a, b) => SEV_ORDER[a] - SEV_ORDER[b]);
  const types = [...new Set(issues.map((i) => i.type))];
  $("#filters").innerHTML =
    sevs.map((s) => `<span class="chip" data-k="sev" data-v="${esc(s)}">${esc(s.charAt(0) + s.slice(1).toLowerCase())}</span>`).join("") +
    (sevs.length && types.length ? `<span style="color:var(--border)">|</span>` : "") +
    types.map((t) => `<span class="chip" data-k="type" data-v="${esc(t)}">${esc(TYPES[t] ?? t)}</span>`).join("") +
    `<input id="search" placeholder="Filter by text or file…">`;
  $("#filters").querySelectorAll(".chip").forEach((ch) => ch.addEventListener("click", () => {
    const set = ch.dataset.k === "sev" ? fSev : fType;
    if (set.has(ch.dataset.v)) set.delete(ch.dataset.v); else set.add(ch.dataset.v);
    ch.classList.toggle("on"); curPage = 0; renderIssues();   // filter change → page 1
  }));
  $("#search").addEventListener("input", (e) => { fText = e.target.value.toLowerCase(); curPage = 0; renderIssues(); });
}

function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"); }
const MAX_RENDERED_ISSUES = 500;   // cap issues rendered into one innerHTML string (tab-freeze guard)
function renderIssues() {
  const all = lastResult.issues;
  const shown = all.filter((i) =>
    (!fSev.size || fSev.has(i.sev)) && (!fType.size || fType.has(i.type)) &&
    (!fText || (i.msg + i.name + i.file + i.rule).toLowerCase().includes(fText)));
  // G19: cap the number of issue cards rendered into one innerHTML string — issue-dense pastes produced 10k+
  // cards and froze the tab.
  const pages = Math.max(1, Math.ceil(shown.length / MAX_RENDERED_ISSUES));
  if (curPage >= pages) curPage = pages - 1;    // filter changes can shrink the page count
  const start = curPage * MAX_RENDERED_ISSUES;
  const pageSlice = shown.slice(start, start + MAX_RENDERED_ISSUES);
  $("#countNote").textContent = shown.length <= MAX_RENDERED_ISSUES
    ? `${shown.length} of ${all.length} issues shown`
    : `${shown.length} of ${all.length} issues shown — showing ${start + 1}–${start + pageSlice.length} (page ${curPage + 1}/${pages}; rendering capped at ${MAX_RENDERED_ISSUES} to keep the tab responsive)`;
  if (!shown.length) {
    $("#issueList").innerHTML = all.length ? `<div class="empty">No issues match the current filters.</div>` : `<div class="empty">🎉 No issues found.</div>`;
    $("#pager").innerHTML = "";
    return;
  }
  $("#issueList").innerHTML = pageSlice.map((i, idx) => `
    <div class="issue" data-i="${start + idx}">
      <div class="issue-head">
        <span class="sev ${esc(i.sev)}">${esc(i.sev)}</span>
        <span class="itype">${esc(TYPES[i.type] ?? i.type)}</span>
        <span class="imsg">${esc(i.msg)}</span>
        <span class="iloc">${esc(i.file)}:${esc(i.line)}</span>
      </div>
      <div class="issue-body">
        <div class="snippet">${(i.snippet || []).map((l, k) => {
          const no = i.snipStart + k;
          return `<div class="ln${no === i.line ? " hl" : ""}"><span class="no">${no}</span><code>${esc(l) || " "}</code></div>`;
        }).join("")}</div>
        <div class="why"><b>Why it matters</b><div>${esc(i.why || "")}</div></div>
        <div class="why"><b>How to fix</b><div>${esc(i.fix || "")}</div></div>
        <div class="refs">Rule ${esc(i.rule)} · ${esc(i.ref || "")}</div>
      </div>
    </div>`).join("");
  // pager — rendered only when the filtered list exceeds one page
  $("#pager").innerHTML = pages > 1
    ? `<button class="ghost" ${curPage === 0 ? "disabled" : ""} data-p="${curPage - 1}">‹ Prev</button>
       <span class="pg">${curPage + 1} / ${pages}</span>
       <button class="ghost" ${curPage === pages - 1 ? "disabled" : ""} data-p="${curPage + 1}">Next ›</button>` : "";
  $("#pager").querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    if (b.disabled) return;
    curPage = +b.dataset.p;
    renderIssues();
    $("#issueList").scrollIntoView({ behavior: "smooth" });
  }));
  $("#issueList").querySelectorAll(".issue-head").forEach((h) =>
    h.addEventListener("click", () => h.parentElement.classList.toggle("open")));
}

// The export is the dashboard's own format, not a CLI report: a different file name (the CLI writes
// lazaret-report.json) and a generatedBy marker the CLI's reports don't carry, so neither can be mistaken for the
// other (as a --baseline, say). Its findings are redacted (scanEntries). 2: the CLI's result (conditions, crossFile,
// perFile, metrics.configFiles), with the files scanned and the time.
export const EXPORT_FORMAT = "lazaret-dashboard-2";
const EXPORT_FILENAME = "lazaret-dashboard-export.json";
$("#exportBtn").addEventListener("click", () => {
  if (!lastResult) return;
  const report = Object.assign({ generatedBy: EXPORT_FORMAT }, lastResult);
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = EXPORT_FILENAME; a.click();
  URL.revokeObjectURL(a.href);
});

/* ---------------- Samples ---------------- */
const SAMPLE_PY = `import os, pickle, hashlib, random, yaml, sqlite3, requests
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "sup3rSecret42"          # hardcoded credential
API_KEY = "sk-live-8f3a9d2b1c4e"

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {user_id}")   # SQL injection
    return cur.fetchone()

@app.route("/run")
def run_cmd():
    cmd = request.args.get("cmd")
    os.system("ping " + cmd)            # command injection
    return "ok"

@app.route("/load")
def load_data():
    data = request.get_data()
    obj = pickle.loads(data)            # unsafe deserialization
    cfg = yaml.load(request.args.get("cfg"))
    return str(obj)

def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()   # weak hash

def make_reset_token():
    return str(random.randint(100000, 999999))    # predictable token

def fetch(url):
    return requests.get(url, verify=False)        # TLS verification off

try:
    risky()
except:
    pass

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
`;
const SAMPLE_JS = `const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");
const app = express();

var apiSecret = "9f8e7d6c5b4a3210";   // hardcoded credential

app.get("/search", (req, res) => {
  db.query("SELECT * FROM products WHERE name = '" + req.query.q + "'");  // SQLi
  res.send("ok");
});

app.get("/ping", (req, res) => {
  exec("ping -c 1 " + req.query.host, (e, out) => res.send(out));  // cmd injection
});

function renderComment(c) {
  document.getElementById("out").innerHTML = c.body;   // XSS sink
}

function makeSessionToken() {
  return Math.random().toString(36).slice(2);          // predictable token
}

function checkHash(data) {
  return crypto.createHash("md5").update(data).digest("hex");  // weak hash
}

function saveAuth(token) {
  localStorage.setItem("auth_token", token);           // token in localStorage
}

try { risky(); } catch (e) {}

if (user.role == "admin") {                            // loose equality
  eval(req.query.callback + "()");                     // eval
  console.log("TODO: remove this before launch");
}
`;
const SAMPLE_SQL = `-- user provisioning script
CREATE USER app IDENTIFIED BY 'hunter2';        -- hardcoded credential
GRANT ALL PRIVILEGES ON app.* TO 'app'@'%';     -- excessive privilege
GRANT SELECT ON app.logs TO PUBLIC;             -- grant to PUBLIC

CREATE PROCEDURE search_users(IN term VARCHAR(100))
BEGIN
  SET @sql = 'SELECT * FROM users WHERE name = ''' + term + '''';  -- dynamic SQL
  EXEC(@sql);
END;

DELETE FROM sessions;                           -- no WHERE clause
UPDATE accounts SET status = 'active';          -- no WHERE clause

SELECT * FROM users WITH (NOLOCK);              -- SELECT * + dirty read
EXEC xp_cmdshell 'whoami';                      -- OS command execution
SELECT LOAD_FILE('/etc/passwd');                -- filesystem access
SELECT name INTO OUTFILE '/tmp/out.txt' FROM users;
`;
function clearUploads() { uploaded = []; $("#files").value = ""; $("#filelist").innerHTML = ""; }
$("#samplePy").addEventListener("click", () => { clearUploads(); $("#code").value = SAMPLE_PY; $("#lang").value = "py"; });
$("#sampleJs").addEventListener("click", () => { clearUploads(); $("#code").value = SAMPLE_JS; $("#lang").value = "js"; });
$("#sampleSql").addEventListener("click", () => { clearUploads(); $("#code").value = SAMPLE_SQL; $("#lang").value = "sql"; });
