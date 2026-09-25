const fs = require('fs');
const html = fs.readFileSync('lazaret.html','utf8');
const script = html.match(/<script>([\s\S]*)<\/script>/)[1];
// engine part: everything before the UI section
const engine = script.split('/* ---------------- UI ----------------')[0];
eval(engine.replace(`"use strict";`,""));
// extract samples
const py = script.match(/const SAMPLE_PY = `([\s\S]*?)`;/)[1];
const js = script.match(/const SAMPLE_JS = `([\s\S]*?)`;/)[1].replace(/\\`/g,'`').replace(/\\\$\{/g,'${');

function report(name, content, lang){
  const issues = scanFile({name, content, lang});
  console.log(`\n=== ${name} (${lang}) — ${issues.length} issues ===`);
  issues.forEach(i=>console.log(`${i.sev.padEnd(8)} ${i.type.padEnd(7)} ${i.rule.padEnd(14)} L${i.line}: ${i.msg}`));
  const m = computeMetrics([{name, content, lang}]);
  console.log('metrics:', JSON.stringify(m));
  return issues;
}
report('sample.py', py, 'py');
report('sample.js', js, 'js');

// clean code should produce zero (or near-zero) issues
const cleanPy = `import secrets
import hashlib

def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()

def make_token():
    return secrets.token_urlsafe(32)

def digest(data):
    return hashlib.sha256(data).hexdigest()
`;
const cleanJs = `const crypto = require("crypto");

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function getUser(db, id) {
  const rows = await db.query("SELECT * FROM users WHERE id = ?", [id]);
  return rows[0];
}

function render(el, text) {
  el.textContent = text;
}
`;
report('clean.py', cleanPy, 'py');
report('clean.js', cleanJs, 'js');
