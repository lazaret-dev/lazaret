const fs=require('fs');
const html=fs.readFileSync('lazaret.html','utf8');
const script=html.match(/<script>([\s\S]*)<\/script>/)[1];
const engine=script.split('/* ---------------- UI ----------------')[0];
eval(engine.replace(`"use strict";`,""));
function taints(code,lang){ return scanFile({name:lang==="py"?"t.py":"t.js",content:code,lang}).filter(x=>x.rule.startsWith("T-")).map(x=>x.rule).sort(); }
const cases=[
 ["py int()",'uid = int(request.args.get("id"))\ncur.execute("SELECT id="+uid)',"py",[]],
 ["py raw",'uid = request.args.get("id")\ncur.execute("SELECT id="+uid)',"py",["T-SQL"]],
 ["py shlex CMD",'h = shlex.quote(request.args.get("h"))\nos.system("ping "+h)',"py",[]],
 ["py html wrong CMD",'h = html.escape(request.args.get("h"))\nos.system("ping "+h)',"py",["T-CMD"]],
 ["js Number",'const id=Number(req.query.id);\ndb.query("x="+id)',"js",[]],
 ["js raw",'const id=req.query.id;\ndb.query("x="+id)',"js",["T-SQL"]],
 ["js DOMPurify XSS",'const h=DOMPurify.sanitize(req.query.html);\nel.innerHTML=h',"js",[]],
 ["js DOMPurify wrong SQL",'const h=DOMPurify.sanitize(req.query.q);\ndb.query("x="+h)',"js",["T-SQL"]],
];
let ok=true;
for(const [n,c,l,e] of cases){const g=taints(c,l);const s=JSON.stringify(g)===JSON.stringify(e.sort());if(!s)ok=false;console.log(`  [${s?"OK":"FAIL"}] ${n}: ${JSON.stringify(g)} exp ${JSON.stringify(e)}`);}
console.log(ok?"DASHBOARD ALL PASS":"DASHBOARD FAIL");
