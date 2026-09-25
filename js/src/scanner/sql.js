// G12 analyzer — verbatim from the dashboard (lazaret/web/lazaret.html).
import { mkIssue } from "./engine.js";

/* ---------------- Flow-sensitive SQL-sink analysis (G12) ----------------
   Mirror of the Python CLI's sql_sink_analyzer (lazaret.scanner.core): the S-SQL-PY
   line rule only sees formatting applied to a literal INSIDE execute(); SQL
   assigned to a variable earlier in the file (concat / %-interpolation /
   .format / f-string) then passed to execute(q) escapes it. Parity rules
   (stage 4): mirrors Python exactly, INCLUDING not skipping comment lines
   (only the nosec filter applied to the final issue list removes those) and
   including the dedup-by-line against the S-SQL-PY line-rule pass. Parameterized
   calls (2nd top-level arg starting with ( [ or {) are safe and never flagged. */
const SQL_CALL_RE   = /\.(execute|executemany)\s*\(/g;   // .exec → reuse via lastIndex=0
const SQL_IDENT_RE  = /^[A-Za-z_]\w*$/;
const SQL_ASSIGN_RE = /^\s*([A-Za-z_]\w*)\s*(\+=|=)(?!=)\s*(.+?)\s*$/;
const SQL_LIT_RE    = /^(?:[rbu]*)["'](.*)["']$/s;
function sqlSplitTopLevel(argstr){      // split on top-level commas (nested brackets/quotes respected)
  const parts=[]; let cur="", depth=0, quote=null;
  for(const ch of argstr){
    if(quote){ cur+=ch; if(ch===quote) quote=null; continue; }
    if(ch==='"'||ch==="'"){ quote=ch; cur+=ch; }
    else if(ch==="("||ch==="["||ch==="{"){ depth++; cur+=ch; }
    else if(ch===")"||ch==="]"||ch==="}"){ depth--; cur+=ch; }
    else if(ch===","&&depth===0){ parts.push(cur); cur=""; }
    else cur+=ch;
  }
  parts.push(cur); return parts;
}
function sqlParenSlice(line, openIdx){  // content of the balanced (…) starting at openIdx, or null
  let depth=0, quote=null;
  for(let j=openIdx;j<line.length;j++){
    const ch=line[j];
    if(quote){ if(ch===quote) quote=null; continue; }
    if(ch==='"'||ch==="'") quote=ch;
    else if(ch==="(") depth++;
    else if(ch===")"){ if(--depth===0) return line.slice(openIdx+1, j); }
  }
  return null;
}
function sqlBuildMethod(arg){           // 'format' | 'percent' | 'concat' | null
  if(/\.format\s*\(/.test(arg) || /^\s*(?:f"|f')/.test(arg)) return "format";
  if(/(?:["'][^"']*["']|\b[A-Za-z_]\w*)\s*%\s*[^=%\s]/.test(arg)) return "percent";
  if(/["'][^"']*["']\s*\+/.test(arg) || /\+\s*["']/.test(arg)) return "concat";
  return null;
}
function sqlTemplateMap(lines){         // varname → how its value was built (flow-sensitive)
  const tmap={};
  for(const ln of lines){
    const mm=ln.match(SQL_ASSIGN_RE); if(!mm) continue;
    const name=mm[1], op=mm[2], rhs=mm[3];
    if(op==="+="){ tmap[name]=tmap[name]||"concat"; continue; }  // += keeps earlier state (a var built static then += stays flagged once built)
    const build=sqlBuildMethod(rhs);
    if(build){ tmap[name]=build; continue; }
    const lit=rhs.trim().match(SQL_LIT_RE);
    if(lit) tmap[name]=lit[1].includes("%")?"percent":(lit[1].includes("{")?"format":"static");
  }
  return tmap;
}
function sqlSinkScan(file, lines, issues){
  const tmap=sqlTemplateMap(lines);
  const flagged=new Set(issues.filter(i=>i.rule==="S-SQL-PY").map(i=>i.line));  // dedup vs the line-rule pass
  const HOW={percent:"%-interpolation", format:".format()/f-string", concat:"concatenation"};
  lines.forEach((line,i)=>{
    if(flagged.has(i+1)) return;
    SQL_CALL_RE.lastIndex=0; let m;
    while((m=SQL_CALL_RE.exec(line))){
      const argStr=sqlParenSlice(line, m.index+m[0].length-1);
      if(argStr===null) continue;
      const parts=sqlSplitTopLevel(argStr);
      const first=(parts[0]||"").trim();
      const second=(parts.length>1?parts[1]:"").trim();
      if(!first) continue;
      // SAFE: parameterized call — literal/identifier first arg + a tuple/list/dict after the top-level comma
      if(parts.length>=2 && second && "([{".includes(second[0])) continue;
      let build=sqlBuildMethod(first);
      if(build===null && SQL_IDENT_RE.test(first)){
        build=tmap[first];
        if(build===undefined || build==="static") continue;
      }
      if(build) issues.push(mkIssue({id:"S-SQL-PY", name:"SQL built from strings", type:"VULN", sev:"BLOCKER",
        msg:`SQL query built with ${HOW[build]||"string-building"} into execute().`,
        why:"Interpolating values into SQL enables SQL injection — the classic path to full database compromise.",
        fix:'Use parameterized queries: cursor.execute("SELECT … WHERE id = %s", (user_id,)).',
        ref:"CWE-89 · OWASP A03"}, file, i+1, lines));
    }
  });
}
export { sqlSplitTopLevel, sqlParenSlice, sqlBuildMethod, sqlTemplateMap, sqlSinkScan };
