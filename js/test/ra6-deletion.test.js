// Inert fragments shared with Python; only the scanner interprets their text.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/index.js';
import { call } from '../src/lib/native.js';
const reason = "deletes the user's files";
const cases = JSON.parse(readFileSync(new URL('../../tests/fixtures/ra6-deletion.json', import.meta.url)));
test('RA-6 paths and cleanup exclusions, shared with Python', () => {
  for (const c of cases) {
    const args = {lang:c.lang, command:c.command};
    assert.equal(call('install_script_risk', args, c.text).includes(reason), c.found, c.text);
    if(c.lang !== 'sh') assert.equal(call('import_time_risk', args, c.text)[0].includes(reason),c.found,c.text);
  }
});
test('RA-6 build/import are CRITICAL; use is MAJOR in both readers', () => {
  for (const [op, what, name, text, build, sev] of [
    ['go_package','module','p.go','package p\nimport "os"\nfunc init(){os.RemoveAll("/home/example")}\n',null,'CRITICAL'],
    ['go_package','module','p.go','package p\nimport "os"\nfunc Clean(){os.RemoveAll("/home/example")}\n',null,'MAJOR'],
    ['rs_crate','crate','build.rs','fn main(){std::fs::remove_dir_all("/home/example").unwrap();}', 'build.rs','CRITICAL'],
    ['rs_crate','crate','src/lib.rs','pub fn clean(){std::fs::remove_dir_all("/home/example").unwrap();}',null,'MAJOR'],
  ]) {
    const answer = call(op,{what,names:[name],files:[[name,text.length]],build},text);
    const issues=answer.issues.map(x=>x[1]).filter(x=>x[4].includes(reason));
    assert.ok(issues.length,JSON.stringify(answer));
    assert.ok(issues.every(x=>x[3]===sev),JSON.stringify(issues));
  }
});

test('RA-6 npm and Python install hooks are CRITICAL in the npm scanner', () => {
  for (const [name, command, text] of [
    ['install.js','node install.js','const fs=require("fs");fs.rmSync("/home/example",{recursive:true});'],
    ['setup.py','python3 setup.py','import shutil\nshutil.rmtree("/home/example")\n'],
  ]) {
    const root=mkdtempSync(join(tmpdir(),'ra6-source-'));
    const out=mkdtempSync(join(tmpdir(),'ra6-report-'));
    try {
      writeFileSync(join(root,'package.json'),JSON.stringify({name:'ra6-probe',version:'1.0.0',scripts:{postinstall:command}}));
      writeFileSync(join(root,name),text);
      run(['check',root,'--out-dir',out,'--no-html','--quiet'],{out:()=>{},err:()=>{},env:{}});
      const report=JSON.parse(readFileSync(join(out,'lazaret-report.json'),'utf8'));
      assert.ok(report.issues.some(i=>i.rule==='SC-INSTALL-HOOK' && i.sev==='CRITICAL' && i.msg.includes(reason)),JSON.stringify(report.issues));
    } finally {
      rmSync(root,{recursive:true,force:true});rmSync(out,{recursive:true,force:true});
    }
  }
});

test('RA-6 own folders, protected subtrees, and deleting-call lines', () => {
  const fixture=JSON.parse(readFileSync(new URL('../../tests/fixtures/ra6-own-folders.json', import.meta.url),'utf8'));
  for (const c of fixture.paths) {
    const jp=c.path.startsWith('~') ? "require('os').homedir()+"+JSON.stringify(c.path.slice(1)) : JSON.stringify(c.path);
    const pp=c.path.startsWith('~') ? "os.path.expanduser('~')+"+JSON.stringify(c.path.slice(1)) : JSON.stringify(c.path);
    for(const [lang,text] of [['js',"require('fs').rmSync("+jp+",{recursive:true});"],['py',"import os,shutil\nshutil.rmtree("+pp+")"]]) {
      const reasons=call('install_script_risk',{lang},text);
      assert.equal(reasons.includes(reason),c.found,`${lang}: ${c.path}: ${reasons}`);
      if(c.found) assert.equal(call('install_script_severity',{reasons}), 'CRITICAL');
    }
  }
  for(const c of fixture.sources) {
    const install=call('install_script_risk',{lang:c.lang},c.text);
    assert.equal(install.includes(reason),c.found,c.name);
    if(c.found) assert.equal(call('install_script_severity',{reasons:install}),'CRITICAL',c.name);
    const [reasons,line]=call('import_time_risk',{lang:c.lang},c.text);
    assert.equal(reasons.includes(reason),c.found,c.name);
    if(c.line !== undefined) assert.equal(line,c.line,c.name);
  }
});

 test('RA-6 listed-name work stays bounded', () => {
  let text="const fs=require('fs'),path=require('path');const D=require('os').homedir()+'/.tool/state';\n";
  text+="fs.readdirSync(D).map(n=>fs.rmSync(path.join(D,n),{recursive:true}));\n".repeat(1600);
  text+="fs.rmSync(require('os').homedir()+'/Documents',{recursive:true});";
  assert.ok(call('install_script_risk',{lang:'js'},text).includes(reason));
 });
