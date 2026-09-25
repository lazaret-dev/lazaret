const fs = require('fs');
const html = fs.readFileSync('lazaret.html','utf8');
const script = html.match(/<script>([\s\S]*)<\/script>/)[1];
const engine = script.split('/* ---------------- UI ----------------')[0];
eval(engine.replace(`"use strict";`,""));

const taintedPy = fs.readFileSync('testproj/tainted.py','utf8');
const evilJs = fs.readFileSync('testproj/node_modules/evil-pkg/index.js','utf8');
const secretsPy = fs.readFileSync('testproj/secrets.py','utf8');
const cleanPy = fs.readFileSync('testproj/utils/clean.py','utf8');

function report(name, content, lang){
  const issues = scanFile({name, content, lang});
  console.log(`=== ${name}: ${issues.length} issues ===`);
  issues.forEach(i=>console.log(`  ${i.sev.padEnd(8)} ${i.rule.padEnd(15)} L${i.line} ${i.msg.slice(0,80)}`));
}
report('tainted.py', taintedPy, 'py');
report('evil.js', evilJs, 'js');
report('secrets.py', secretsPy, 'py');
report('clean.py', cleanPy, 'py');
