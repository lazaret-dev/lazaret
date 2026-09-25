// Metrics & ratings — verbatim from the dashboard (lazaret/web/lazaret.html).

import { isComment } from "./engine.js";

export function computeMetrics(files){
  let ncloc=0, comments=0, dupLines=0;
  const nonDep = files.filter(f=>!f.dep);   // deps excluded from quality metrics
  const depFiles = files.length - nonDep.length;
  const winMap = new Map();
  for(const f of nonDep){
    const lines = f.content.split("\n");
    const code = [];
    lines.forEach((l,i)=>{
      const t=l.trim();
      if(!t) return;
      if(isComment(l,f.lang)){comments++; return;}
      ncloc++; code.push({t,i,f:f.name});
    });
    for(let i=0;i+6<=code.length;i++){
      const key = code.slice(i,i+6).map(c=>c.t).join("");
      if(!winMap.has(key)) winMap.set(key, []);
      winMap.get(key).push(code.slice(i,i+6));
    }
  }
  const dupSet = new Set();
  for(const [,occ] of winMap){
    if(occ.length>1) occ.forEach(win=>win.forEach(c=>dupSet.add(c.f+":"+c.i)));
  }
  dupLines = dupSet.size;
  return {files: nonDep.length, depFiles, ncloc, comments, dupPct: ncloc? +(100*dupLines/ncloc).toFixed(1) : 0};
}

export function worstSevRating(issues, types){
  const sevs = issues.filter(i=>types.includes(i.type)).map(i=>i.sev);
  if(sevs.includes("BLOCKER")) return "E";
  if(sevs.includes("CRITICAL")) return "D";
  if(sevs.includes("MAJOR")) return "C";
  if(sevs.includes("MINOR")) return "B";
  return "A";
}
export function maintainabilityRating(issues, ncloc){
  const smells = issues.filter(i=>i.type==="SMELL").length;
  const per100 = ncloc? 100*smells/ncloc : 0;
  return per100<=5?"A":per100<=10?"B":per100<=20?"C":per100<=40?"D":"E";
}
