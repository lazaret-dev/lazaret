// extractFunctions — verbatim from the dashboard (lazaret/web/lazaret.html) (G4 linear brace-walk).

import { isComment } from "./engine.js";

export function extractFunctions(lines, lang){
  const fns = [];
  if(lang!=="py" && lang!=="js") return fns;   // no function metrics for SQL
  const cxRe = lang==="py"
    ? /\b(if|elif|for|while|and|or|except|case)\b/g
    : /\b(if|for|while|case|catch)\b|&&|\|\||\?[^.:]/g;
  if(lang==="py"){
    for(let i=0;i<lines.length;i++){
      const m = lines[i].match(/^(\s*)(?:async\s+)?def\s+(\w+)/);
      if(!m) continue;
      const indent = m[1].length; let end = i+1;
      while(end<lines.length){
        const l = lines[end];
        if(l.trim()!=="" && !isComment(l,"py") && l.search(/\S/)<=indent) break;
        end++;
      }
      const body = lines.slice(i,end).join("\n");
      fns.push({name:m[2], line:i+1, len:end-i, cx:1+(body.match(cxRe)||[]).length});
    }
  } else {
    // G4 fix (twin of the Python extract_functions fix): the old loop
    // restarted a forward 800-line window scan for EVERY fn header —
    // O(lines × 800 × line-length) on minified/adversarial JS (browser tab
    // freeze; audit G4) — and copied a body string per function. One linear
    // brace walk now: each header claims the first '{' at/after its LINE
    // START (exactly where the old per-line scan began), spans share a brace
    // exactly as the old independent scans did, the 800-line cap is kept,
    // and complexity comes from per-line counts instead of body copies.
    const content = lines.join("\n");
    const starts = [0];
    for(let j=0;j<content.length;j++)
      if(content.charCodeAt(j)===10) starts.push(j+1);
    starts.push(content.length+1);            // sentinel
    const fnRe = /(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function|\([^)]*\)\s*=>|\w+\s*=>)|(\w+)\s*\([^)]*\)\s*\{)/g;
    const headers = [];                        // {line, name}
    for(let i=0;i<lines.length;i++){
      fnRe.lastIndex = 0;
      const m = fnRe.exec(lines[i]);
      if(m) headers.push({line:i, name:m[1]||m[2]||m[3]||"(anonymous)"});
    }
    // per-line complexity counts (tokens cannot span '\n')
    const cxPrefix = [0];
    for(const line of lines) cxPrefix.push(cxPrefix[cxPrefix.length-1] + ((line.match(cxRe)||[]).length));
    // one brace walk: stack of [openPos, owner header indices]
    const matched = new Map();                 // header idx -> [openPos, closePos]
    const stack = [], waiting = [];
    let hi = 0;
    const braceRe = /[{}]/g; let bm;
    while((bm = braceRe.exec(content)) !== null){
      const bpos = bm.index;
      while(hi < headers.length && starts[headers[hi].line] <= bpos){
        waiting.push(hi);                      // header's line has begun: it
        hi++;                                  // claims the next '{' it sees
      }
      if(bm[0]==="{"){
        stack.push([bpos, waiting.splice(0, waiting.length)]);
      } else if(stack.length){
        const [openPos, owners] = stack.pop();
        for(const h of owners) matched.set(h, [openPos, bpos]);
      }
    }
    for(let h=0;h<headers.length;h++){
      const i = headers[h].line, name = headers[h].name;
      const n = lines.length;
      const windowEndOff = starts[Math.min(n, i+800)];
      // first '{' at/after the header's line start (old semantics: the scan
      // started at the first char of the line)
      let braceOff = -1;
      for(let o = starts[i]; o < content.length && o < windowEndOff; o++){
        if(content.charCodeAt(o)===123){ braceOff = o; break; }
      }
      if(braceOff === -1) continue;            // no '{' in window: old `started` never set
      let end;
      if(matched.has(h) && matched.get(h)[1] < windowEndOff){
        const closePos = matched.get(h)[1];
        end = lowerBound(starts.length, x => starts[x] > closePos) - 1; // line of '}'
      } else {
        end = Math.min(n, i+800) - 1;          // unclosed within window: old truncation
      }
      fns.push({name, line:i+1, len:end-i+1, cx:1+cxPrefix[end+1]-cxPrefix[i]});
    }
  }
  return fns;
}
function lowerBound(n, pred){
  let lo=0, hi=n;
  while(lo<hi){ const mid=(lo+hi)>>1; if(pred(mid)) hi=mid; else lo=mid+1; }
  return lo;
}
