"""action.yml, the repository as a GitHub Action (README.md, "In CI").

- It installs Lazaret from its own files (the commit a workflow pins), with
  no package index: what runs is that commit's code.
- It uses no other action, and no input is spliced into a script: inputs
  reach the scripts through the environment (a value spliced into `run:`
  runs as shell), and a value with a line break can't add an output.
- The scan step turns the inputs into the CLI's arguments as documented:
  gate -> --ci, deps -> --deps, the SARIF path under the scanned directory,
  and its path is the `sarif` output, set before the scan so that a failed
  gate still uploads.

Read as text (no YAML parser is installed); the scan step's script is run
with bash against a stand-in interpreter that records its arguments.
"""

import os
import re
import shutil
import subprocess
import tempfile
import unittest

from tests import _support

ACTION = os.path.join(_support.REPO_ROOT, "action.yml")
README = os.path.join(_support.REPO_ROOT, "README.md")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def steps(text):
    """[(name, {"shell", "id", "env": {..}, "run": script})] of runs.steps."""
    found = []
    for block in re.split(r"(?m)^    - ", text.split("\n  steps:\n", 1)[1])[1:]:
        lines = ("  " + block).splitlines()
        step = {"env": {}, "run": ""}
        i = 0
        while i < len(lines):
            line = lines[i]
            m = re.match(r"^      (\w+):\s*(.*)$", line) or re.match(r"^  (\w+):\s*(.*)$", line)
            if m and m.group(1) == "env":
                i += 1
                while i < len(lines) and lines[i].startswith("        "):
                    k, _, v = lines[i].strip().partition(":")
                    step["env"][k] = v.strip()
                    i += 1
                continue
            if m and m.group(1) == "run" and m.group(2) == "|":
                i += 1
                body = []
                while i < len(lines) and (lines[i].startswith("        ") or not lines[i].strip()):
                    body.append(lines[i][8:])
                    i += 1
                step["run"] = "\n".join(body).rstrip() + "\n"
                continue
            if m:
                step[m.group(1)] = m.group(2)
            i += 1
        found.append(step)
    return found


class ActionFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read(ACTION)
        cls.steps = steps(cls.text)

    def test_two_bash_steps_and_no_other_action(self):
        self.assertEqual([s.get("name") for s in self.steps],
                         ["Install Lazaret from this action's commit (compiles the engine)", "Scan"])
        self.assertTrue(all(s.get("shell") == "bash" for s in self.steps))
        self.assertNotRegex(self.text, r"(?m)^\s*-?\s*uses:")
        self.assertIn("  using: composite\n", self.text)

    def test_it_installs_its_own_commit_with_no_index(self):
        install = self.steps[0]["run"]
        self.assertIn('-m pip install --no-index --disable-pip-version-check "$GITHUB_ACTION_PATH/python"', install)
        self.assertNotRegex(install, r"pip install[^\n]*\blazaret\b")       # never a package by name
        self.assertIn("set -euo pipefail", install)

    def test_inputs_reach_the_scripts_through_the_environment(self):
        for step in self.steps:
            with self.subTest(step=step.get("name")):
                self.assertNotIn("${{", step["run"])
        self.assertEqual(self.steps[1]["env"], {"SCAN_PATH": "${{ inputs.path }}", "SARIF_PATH": "${{ inputs.sarif }}",
                                                "GATE": "${{ inputs.gate }}", "DEPS": "${{ inputs.deps }}"})
        inputs = re.findall(r"(?m)^  (\w+):\n    description:", self.text.split("\noutputs:")[0])
        self.assertEqual(inputs, ["path", "sarif", "gate", "deps"])
        self.assertIn("value: ${{ steps.scan.outputs.sarif }}", self.text)
        self.assertIn("id: scan", self.text)

    def test_the_readme_documents_it(self):
        readme = read(README)
        section = readme[readme.index("### In CI"):readme.index("## Detection capabilities")]
        for word in ("`path`", "`sarif`", "`gate`", "`deps`", "steps.lazaret.outputs.sarif", "security-events: write",
                     "if: ${{ !cancelled() }}", "persist-credentials: false"):
            self.assertIn(word, section)


@unittest.skipUnless(shutil.which("bash"), "no bash here")
class ScanStepTests(unittest.TestCase):
    """The scan step's script, run with bash; the venv's python is a stand-in
    that writes its arguments, one per line, and exits with $EXIT."""

    @classmethod
    def setUpClass(cls):
        cls.script = steps(read(ACTION))[1]["run"]

    def run_step(self, path=".", sarif="lazaret.sarif", gate="true", deps="false", exit_code=0):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        bindir = os.path.join(d.name, "lazaret-action", "bin")
        os.makedirs(bindir)
        argv_file = os.path.join(d.name, "argv")
        stub = os.path.join(bindir, "python")
        with open(stub, "w", encoding="utf-8") as fh:
            fh.write(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{argv_file}"\nexit "$EXIT"\n')
        os.chmod(stub, 0o755)
        output = os.path.join(d.name, "github_output")
        open(output, "w", encoding="utf-8").close()
        env = dict(os.environ, RUNNER_TEMP=d.name, GITHUB_OUTPUT=output, SCAN_PATH=path, SARIF_PATH=sarif,
                   GATE=gate, DEPS=deps, EXIT=str(exit_code))
        p = subprocess.run(["bash", "-c", self.script], env=env, capture_output=True, encoding="utf-8",
                           errors="replace", timeout=30)
        argv = read(argv_file).splitlines() if os.path.exists(argv_file) else None
        return p, argv, read(output)

    def test_the_arguments_and_the_output(self):
        p, argv, output = self.run_step()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(argv, ["-m", "lazaret", ".", "--sarif", "lazaret.sarif", "--no-html", "--no-json", "--ci"])
        self.assertEqual(output, "sarif=./lazaret.sarif\n")
        p, argv, output = self.run_step(path="src/app/", sarif="out/l.sarif", gate="false", deps="true")
        self.assertEqual(argv, ["-m", "lazaret", "src/app/", "--sarif", "out/l.sarif", "--no-html", "--no-json",
                                "--deps"])
        self.assertEqual(output, "sarif=src/app/out/l.sarif\n")
        _p, _argv, output = self.run_step(sarif="/tmp/x/l.sarif")
        self.assertEqual(output, "sarif=/tmp/x/l.sarif\n")

    def test_a_failed_gate_fails_the_step_after_the_output_is_set(self):
        p, argv, output = self.run_step(exit_code=1)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(output, "sarif=./lazaret.sarif\n")

    def test_values_that_are_not_what_they_should_be(self):
        for kwargs in ({"gate": "yes"}, {"deps": "1"}, {"sarif": "a.sarif\nother=x"}, {"path": "a\rb"}):
            with self.subTest(**kwargs):
                p, argv, output = self.run_step(**kwargs)
                self.assertEqual(p.returncode, 2)
                self.assertIsNone(argv)                     # nothing ran
                self.assertEqual(output, "")
                self.assertIn("::error::", p.stderr)

    def test_a_value_is_an_argument_never_shell(self):
        p, argv, output = self.run_step(path="$(touch pwned); `id` ; x", sarif="'; echo hi #")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(argv[2], "$(touch pwned); `id` ; x")
        self.assertEqual(argv[4], "'; echo hi #")
        self.assertFalse(os.path.exists("pwned"))


if __name__ == "__main__":
    unittest.main()
