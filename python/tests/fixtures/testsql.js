const fs=require('fs');
const html=fs.readFileSync('lazaret.html','utf8');
const script=html.match(/<script>([\s\S]*)<\/script>/)[1];
const engine=script.split('/* ---------------- UI ----------------')[0];
eval(engine.replace(`"use strict";`,""));
const sql=fs.readFileSync('sqlproj/schema.sql','utf8');
const clean=fs.readFileSync('sqlproj/clean.sql','utf8');
function rep(name,content){
  const issues=scanFile({name,content,lang:"sql"});
  console.log(`=== ${name}: ${issues.length} issues ===`);
  issues.sort((a,b)=>({BLOCKER:0,CRITICAL:1,MAJOR:2,MINOR:3,INFO:4}[a.sev]-{BLOCKER:0,CRITICAL:1,MAJOR:2,MINOR:3,INFO:4}[b.sev]));
  issues.forEach(i=>console.log(`  ${i.sev.padEnd(8)} ${i.rule.padEnd(18)} L${i.line}`));
}
rep('schema.sql',sql);
rep('clean.sql',clean);
// detectLang check
console.log('\ndetectLang(no-name, SQL content):', detectLang("", sql));
