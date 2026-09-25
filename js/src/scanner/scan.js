// scanFile and helpers — verbatim from the dashboard (lazaret/web/lazaret.html) (exports added).
import { RULES, TEXT_RULES } from "./rules.js";
import { STRING_LIT_RE, ASSIGN_RE, TAINT_SOURCES, TAINT_SINKS, FULL_SAN, PARTIAL_SAN, neutralize, escRe } from "./taint.js";
import { sqlSinkScan } from "./sql.js";
import { B64_BLOB_RE, OBF_IDENT_RE, ENTROPY_VALUE_RE, SECRET_SKIP_RE, SUPPRESS_RE, isSuppressed, shannonEntropy, isComment, mkIssue } from "./engine.js";
import { extractFunctions } from "./functions.js";

export const FILE_ISSUE_BUDGET = 500;   // per-file issue budget (G19)
export { isComment } from "./engine.js";

/* ---------------- Analyzers ---------------- */
export function detectLang(name, content){
  if(/\.(py)$/i.test(name)) return "py";
  if(/\.(js|jsx|ts|tsx|mjs|cjs)$/i.test(name)) return "js";
  if(/\.sql$/i.test(name)) return "sql";
  // content heuristic: SQL keywords dominate and no JS/py structure
  if(/\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+(TABLE|PROCEDURE|USER)|GRANT|ALTER\s+TABLE)\b/i.test(content)
     && !/\b(function|=>|def |import )\b/.test(content)) return "sql";
  if(/^\s*(def |import |from \w+ import|class \w+.*:)/m.test(content) && !/[{};]\s*$/m.test(content)) return "py";
  return /\b(def |elif |None|self\.)/.test(content) && !/\b(const|let|=>|function)\b/.test(content) ? "py" : "js";
}
// isComment moved to engine.js (shared by metrics without import cycles).
export function taintScan(file, lines, lang){
  if(!TAINT_SOURCES[lang]) return [];   // SQL and others: pattern rules only
  const issues=[], tainted={};          // var -> {line, clean:Set(suffix)}
  const src = TAINT_SOURCES[lang];
  const partialCats = Object.keys(PARTIAL_SAN[lang]||{});
  const hasVar = (code, suf)=>Object.keys(tainted).some(v=>
    !tainted[v].clean.has(suf) && new RegExp(`\\b${escRe(v)}\\b`).test(code));
  lines.forEach((line,i)=>{
    if(isComment(line,lang)) return;
    const m = line.match(ASSIGN_RE[lang]);
    if(m){
      const name=m[1], rhs=m[2];
      const base = neutralize(rhs, lang).replace(STRING_LIT_RE,"");
      if(src.test(base) || hasVar(base, null)){
        const clean = new Set();
        for(const suf of partialCats){
          const neut = neutralize(rhs, lang, suf).replace(STRING_LIT_RE,"");
          if(!src.test(neut) && !hasVar(neut, suf)) clean.add(suf);
        }
        if(!(name in tainted)) tainted[name] = {line:i+1, clean};
      }
    }
    for(const [suffix, sinkRe, cat, sev, cwe, fix] of TAINT_SINKS[lang]){
      const sm = sinkRe.exec(line);
      if(!sm) continue;
      const rest = neutralize(line.slice(sm.index + sm[0].length), lang, suffix);
      const restCode = rest.replace(STRING_LIT_RE,"");
      const carriers = Object.keys(tainted).filter(v=>
        !tainted[v].clean.has(suffix) && new RegExp(`\\b${escRe(v)}\\b`).test(restCode));
      if(!carriers.length && !src.test(restCode)) continue;
      const what = carriers.length? `untrusted data via '${carriers[0]}' (tainted at line ${tainted[carriers[0]].line})` : "untrusted data";
      issues.push(mkIssue({id:`T-${suffix}`, name:`Tainted flow → ${cat}`, type:"VULN", sev,
        msg:`Possible ${cat}: ${what} reaches this sink.`,
        why:"Data from user input or a decode function flows into a dangerous call without visible sanitization (lightweight intra-file taint tracking).",
        fix, ref:`${cwe} · Taint analysis`}, file, i+1, lines));
    }
  });
  return issues;
}

// ---- Hex-escape decoding (SC-HEXSTR); twin of lazaret.scanner.core.hex_hidden_text.
// Obfuscation means escaping characters that did not need it: "\x65\x76\x61\x6c"
// spells "eval". Binary data (NUL bytes, byte-order marks, UTF-8 sequences,
// protocol bytes, palettes) legitimately needs escapes and is never flagged.
const HEX_ESCAPE_RE = /\\x([0-9A-Fa-f]{2})/g;
const HEX_MIN_ESCAPES = 8;
const HEX_PRINTABLE_SHARE = 0.75;
const LETTER_RUN_RE = /[A-Za-z]{3}/;
export const HIDDEN_TEXT_DANGER_RE = new RegExp(
  "https?://|\\b(?:eval|exec|execSync|compile|__import__|import|require|child_process|" +
  "subprocess|system|popen|spawn|powershell|cmd\\.exe|curl|wget|base64|b64decode|atob|" +
  "Function|fromCharCode|marshal|pickle)\\b|/bin/(?:ba)?sh", "i");

export function hexHiddenText(line){
  const codes = [...line.matchAll(HEX_ESCAPE_RE)].map((m) => parseInt(m[1], 16));
  if(codes.length < HEX_MIN_ESCAPES) return null;
  const printable = codes.filter((c) => c >= 0x20 && c < 0x7f);
  if(printable.length / codes.length < HEX_PRINTABLE_SHARE) return null;
  const text = String.fromCharCode(...printable);
  const letters = [...text].filter((ch) => /[A-Za-z]/.test(ch)).length;
  if(!LETTER_RUN_RE.test(text) || letters / text.length < 0.4) return null;
  return text;
}

// A "-----BEGIN ... PRIVATE KEY-----" header alone is not a key: libraries keep the
// header as a constant to recognize key files. Require base64 key material after it,
// on the same line or the next two. Twin of lazaret.scanner.core._token_has_material.
const PEM_BODY_RE = /[A-Za-z0-9+/]{40,}={0,2}/;
function tokenHasMaterial(ruleRe, line, lines, i){
  const m = new RegExp(ruleRe.source, ruleRe.flags.replace("g", "")).exec(line);
  if(!m || !m[0].startsWith("-----BEGIN")) return true;
  return [line.slice(m.index + m[0].length), ...lines.slice(i + 1, i + 3)].some((t) => PEM_BODY_RE.test(t));
}

export function scanFile(file){
  const issues = [];
  const lines = file.content.split("\n");
  const lang = file.lang;
  const dep = !!file.dep;   // dependency mode: supply-chain + secret rules only
  const DEP_RULE_PREFIXES = ["SC-", "S-TOKEN", "S-SECRET"];   // lazaret.py parity

  // line rules
  lines.forEach((line, i)=>{
    if(issues.length >= FILE_ISSUE_BUDGET) return;   // per-file issue budget (G19)
    for(const r of RULES){
      if(!r.langs.includes(lang)) continue;
      if(dep && !DEP_RULE_PREFIXES.some((p) => r.id.startsWith(p))) continue;
      const target = r.id==="B-EQEQ" ? line.replace(STRING_LIT_RE,'""') : line;
      let hit = r.check ? r.check(target) : r.re.test(target);
      if(hit && r.need && !r.need.test(line)) hit = false;
      if(hit && r.skip && r.skip.test(line)) hit = false;
      // don't flag security rules inside comments (except TODO + token signatures)
      if(hit && !["Q-TODO","Q-LONGLINE","S-TOKEN"].includes(r.id) && isComment(line, lang)) hit = false;
      if(hit && r.id==="S-TOKEN" && !tokenHasMaterial(r.re, line, lines, i)) hit = false;
      if(hit) issues.push(mkIssue(r, file, i+1, lines));
    }
    // obfuscation heuristics (supply-chain indicators)
    const hidden = hexHiddenText(line);
    if(hidden !== null){
      const dangerous = HIDDEN_TEXT_DANGER_RE.test(hidden);
      const preview = hidden.length <= 60 ? hidden : hidden.slice(0, 57) + "...";
      issues.push(mkIssue({id:"SC-HEXSTR", name:"Hex-escaped readable text", type:"HOTSPOT",
        sev: dangerous ? "CRITICAL" : "MAJOR",
        msg:`Hex escapes hide readable text: ${JSON.stringify(preview)}.`,
        why:"Escaping ordinary printable characters serves no purpose except hiding them from review and search; this text "
          + (dangerous ? "names code execution, a download, or a URL." : "is readable once decoded."),
        fix:"Decode the string and review what it does.",
        ref:"CWE-506 · Supply chain"}, file, i+1, lines));
    }
    if(lang==="js" && /String\.fromCharCode/.test(line) && (line.match(/\b\d{2,3}\b/g)||[]).length>=10)
      issues.push(mkIssue({id:"SC-CHARCODE", name:"Char-code string building", type:"HOTSPOT", sev:"MAJOR",
        msg:"String assembled from character codes — obfuscation indicator.",
        why:"fromCharCode chains hide payloads from static review.",
        fix:"Decode and review what string is being built.",
        ref:"CWE-506 · Supply chain"}, file, i+1, lines));
    if(B64_BLOB_RE.test(line) && !line.includes("sourceMappingURL"))
      issues.push(mkIssue({id:"SC-B64", name:"Large base64 blob", type:"HOTSPOT", sev:"MAJOR",
        msg:"Base64 blob (200+ chars) embedded in code.",
        why:"Embedded encoded blobs can carry second-stage payloads.",
        fix:"Decode and verify the content; move legitimate assets to data files.",
        ref:"CWE-506 · Supply chain"}, file, i+1, lines));
    // entropy-based secret detection
    if(!isComment(line, lang) && !SECRET_SKIP_RE.test(line)){
      const em = line.match(ENTROPY_VALUE_RE);
      if(em && shannonEntropy(em[1])>4.0 &&
         !issues.some(x=>x.line===i+1 && (x.rule==="S-TOKEN"||x.rule==="S-SECRET")))
        issues.push(mkIssue({id:"S-ENTROPY", name:"High-entropy string", type:"HOTSPOT", sev:"MAJOR",
          msg:"High-entropy string literal — possible hardcoded secret.",
          why:"Random-looking constants are usually keys or tokens.",
          fix:"If it is a secret, rotate it and load it from the environment.",
          ref:"CWE-798 · OWASP A07"}, file, i+1, lines));
    }
  });
  // file-level: javascript-obfuscator identifier signature
  if(lang==="js"){
    const obf = file.content.match(OBF_IDENT_RE)||[];
    const uniq = new Set(obf);
    if(uniq.size>=5){
      const firstLine = file.content.slice(0, file.content.indexOf(obf[0])).split("\n").length;
      issues.push(mkIssue({id:"SC-OBF-IDENT", name:"Obfuscated identifier pattern", type:"HOTSPOT", sev:"CRITICAL",
        msg:`${uniq.size} '_0x…' identifiers — javascript-obfuscator signature.`,
        why:"This naming pattern is produced by obfuscation tools; in a dependency it is a classic indicator of a compromised or malicious package.",
        fix:"Diff against the package's published repository; consider removing the dependency.",
        ref:"CWE-506 · Supply chain"}, file, firstLine, lines));
    }
  }
  // text rules
  let lineStarts = null, budgetNoted = false;   // precomputed line-start offsets; budgetNoted guards the one-time SCAN-BUDGET notice
  const truncated = (issues.length >= FILE_ISSUE_BUDGET);   // line rules/entropy already filled the budget
  const noteBudget = () => {   // one-time per-file "budget reached" transparency notice
    if(budgetNoted || issues.length < FILE_ISSUE_BUDGET) return;
    budgetNoted = true;
    issues.push(mkIssue({id:"SCAN-BUDGET", name:"Issue budget reached",
      type:"SMELL", sev:"INFO",
      msg:`Issue generation for "${file.name}" was capped at ${FILE_ISSUE_BUDGET} issues (per-file budget) — further matches in this file were not recorded.`,
      why:"Very issue-dense input produces overwhelming, slow output; the budget keeps the dashboard responsive.",
      fix:"Fix the highest-severity issues first, or split the file and rescan the remainder.",
      ref:"Performance"}, file, 1, lines));
  };
  if(truncated) noteBudget();   // line rules alone exhausted the budget — don't go silent about it
  for(const r of TEXT_RULES){
    if(!r.langs.includes(lang)) continue;
    r.re.lastIndex = 0; let m; let guard = 0;
    while((m = r.re.exec(file.content))){
      if(m[0].length===0){ r.re.lastIndex++; continue; }   // zero-length match: advance, never loop
      if(r.noWhere && /\bWHERE\b/i.test(m[0])) continue;   // linear form: skip statements that DO have WHERE
      if(!lineStarts){
        lineStarts = [0];
        for(let j=0;j<file.content.length;j++)
          if(file.content.charCodeAt(j)===10) lineStarts.push(j+1);
      }
      const lineNo = lineStarts.filter(off=>off<=m.index).length;   // line starts ≤ offset
      if(issues.length < FILE_ISSUE_BUDGET) issues.push(mkIssue(r, file, lineNo, lines));
      else noteBudget();
      if(++guard > FILE_ISSUE_BUDGET) break;   // pathological rule: stop after budget matches
    }
  }
  // function length & complexity — quality rules, skipped in dep mode
  // (vendored code would be pure noise: lazaret.py DEP parity)
  if(!dep) for(const fn of extractFunctions(lines, lang)){
    if(fn.len > 60) issues.push(mkIssue({id:"Q-FN-LONG", name:"Function too long", type:"SMELL", sev:"MAJOR",
      msg:`Function "${fn.name}" is ${fn.len} lines long (limit 60).`,
      why:"Long functions do too much and resist testing and reuse.",
      fix:"Extract cohesive blocks into helper functions.", ref:"Maintainability"}, file, fn.line, lines));
    if(fn.cx > 12) issues.push(mkIssue({id:"Q-FN-CX", name:"High cyclomatic complexity", type:"SMELL", sev:"MAJOR",
      msg:`Function "${fn.name}" has complexity ~${fn.cx} (limit 12).`,
      why:"Highly branched code is hard to reason about and to cover with tests.",
      fix:"Split branches into smaller functions; use early returns or lookup tables.", ref:"Maintainability"}, file, fn.line, lines));
  }
  if(!dep) issues.push(...taintScan(file, lines, lang));
  // G12: whole-argument SQL-sink analysis (py only) — mirrors the CLI/MCP
  // sql_sink_analyzer so a dashboard scan reports the same S-SQL-PY set the
  // CLI and MCP report for identical Python input.
  if(lang === "py" && !dep){ try{ sqlSinkScan(file, lines, issues); }catch(e){ /* analyzer must never break a scan */ } }
  return issues.filter(i=>!isSuppressed(i, lines));
}
