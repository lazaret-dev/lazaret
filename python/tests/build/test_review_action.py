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
- Nothing of the repository it scans runs in it (F-01): each step's shell
  starts without BASH_ENV and ENV; the step drops a function of the
  environment's named as a command it runs, the PYTHON* variables,
  Lazaret's native-library overrides and the Rust tool and flag variables
  (not CARGO_HOME and RUSTUP_HOME, refused in the workspace), and runs from
  $RUNNER_TEMP; python3 and cargo come from PATH by their absolute path and
  are refused in the workspace, and the build gets PATH without the
  workspace's folders; every interpreter runs with -I, pip with --isolated
  and PIP_CONFIG_FILE the null device; the directory to scan is made
  absolute from the workspace. tests/build/test_action_isolation.py runs
  both steps with a real interpreter in a hostile checkout.

Read as text (no YAML parser is installed). Each step's script is run as
the runner runs it (a file, run with the step's `shell:`) against stand-ins
that record their arguments, working directory and environment.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import _support

ACTION = os.path.join(_support.REPO_ROOT, "action.yml")
README = os.path.join(_support.REPO_ROOT, "README.md")


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


SHELL = "env -u BASH_ENV -u ENV bash --noprofile --norc -eo pipefail {0}"
# what the runner runs for a shell named by its name (GitHub's documentation, "jobs.<job_id>.steps[*].shell")
NAMED_SHELLS = {"bash": "bash --noprofile --norc -eo pipefail {0}", "sh": "sh -e {0}"}


def run_script(step, folder, cwd, env, timeout=30):
    """A step's script run as the runner runs it: written to a file in `folder`, then the step's `shell:` (a
    command with {0} for the file, which the runner splits at whitespace, or a shell's name) run in `cwd` with
    `env`."""
    path = os.path.join(folder, "step.sh")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(step["run"])
    shell = NAMED_SHELLS.get(step["shell"], step["shell"])
    argv = [path if word == "{0}" else word for word in shell.split()]
    return subprocess.run(argv, cwd=cwd, env=env, capture_output=True, encoding="utf-8", errors="replace",
                          timeout=timeout)


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
        self.assertTrue(all(s.get("shell") == SHELL for s in self.steps))     # bash, without BASH_ENV and ENV
        self.assertNotRegex(self.text, r"(?m)^\s*-?\s*uses:")
        self.assertIn("  using: composite\n", self.text)

    def test_it_installs_its_own_commit_with_no_index(self):
        install = self.steps[0]["run"]
        self.assertIn('PIP_CONFIG_FILE="$("$venv" -I -c \'import os, sys; sys.stdout.write(os.devnull)\')" \\\n'
                      '  "$venv" -I -m pip install --isolated --no-index --disable-pip-version-check '
                      '"$GITHUB_ACTION_PATH/python"\n', install)
        self.assertNotRegex(install, r"pip install[^\n]*\blazaret\b")       # never a package by name
        self.assertIn("set -euo pipefail", install)

    def test_every_python_runs_isolated(self):
        """F-01: `python -m` puts the current directory first on sys.path, and a
        step starts in the checkout. Every interpreter runs with -I, after the
        step has dropped the functions and variables and left for
        $RUNNER_TEMP."""
        for step in self.steps:
            with self.subTest(step=step.get("name")):
                script = step["run"]
                lines = [line.strip() for line in script.splitlines()]
                calls = re.findall(r'(?m)^\s*"\$(?:python|venv)" (.*)$', script) + re.findall(r'"\$venv" (-I -c )', script)
                self.assertTrue(calls)
                for call in calls:
                    if call == '"${args[@]}"':
                        self.assertIn("args=(-I -m lazaret ", script)
                    else:
                        self.assertTrue(call.startswith(("-I -m ", "-I -c ")), call)
                unset = [i for i, line in enumerate(lines) if line.startswith("unset -f ")]
                clear = [i for i, line in enumerate(lines)
                         if re.match(r"PYTHON\*\|(PIP_\*\|)?LAZARET_NATIVE_LIB\|LAZARET_NATIVE_LIBRARY\|LAZARET_WHEEL_PLATFORM", line)]
                cd = [i for i, line in enumerate(lines) if line == 'cd "$RUNNER_TEMP"']
                self.assertEqual((len(unset), len(clear), len(cd)), (1, 1, 1))
                first = min(i for i, line in enumerate(lines) if re.match(r'(python=|venv=|"\$|PIP_CONFIG_FILE=)', line))
                self.assertLess(unset[0], clear[0])
                self.assertLess(clear[0], cd[0])
                self.assertLess(cd[0], first)

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


STUB = """\
#!/bin/sh
# a stand-in python3 and venv python: records what it was run with; `-I -m venv DIR` makes DIR/bin/python (itself),
# `-I -c` prints the null device as os.devnull would
{ printf 'argv:'; printf ' %s' "$@"; printf '\\n'; printf 'cwd: %s\\n' "$(pwd -P)"
  env | grep -i -E '^(python|lazaret_|cargo|rust|pip_|path=)' | sed 's/^/env: /'; } >> "$RECORD"
if [ "$1 $2 $3" = "-I -m venv" ]; then mkdir -p "$4/bin" && cp "$0" "$4/bin/python"; fi
if [ "$1 $2" = "-I -c" ]; then printf /dev/null; fi
exit 0
"""


@unittest.skipUnless(shutil.which("bash") and sys.platform != "win32",
                     "needs bash (on Windows the one on PATH can be WSL's launcher, while a runner runs the "
                     "step in Git Bash: the script is tested on Linux and macOS)")
class InstallStepTests(unittest.TestCase):
    """The install step's script, run with the step's shell, against a stand-in python3 (and the venv's python it
    makes) and cargo in a folder of their own on PATH: what the interpreter and pip are started with, in which
    folder and environment, and what is refused (F-01). Markers only; nothing is installed."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = os.path.realpath(d.name)
        self.temp, self.workspace, self.bin, self.home = (os.path.join(self.root, n) for n in
                                                          ("runner-temp", "workspace", "bin", "cargo-home"))
        self.ws_bin = os.path.join(self.workspace, "node_modules", ".bin")
        for folder in (self.temp, self.ws_bin, self.bin, self.home):
            os.makedirs(folder)
        self.record, self.marker = os.path.join(self.root, "record"), os.path.join(self.root, "marker")
        for folder, name in ((self.bin, "python3"), (self.bin, "cargo")):
            self.write(os.path.join(folder, name), STUB, 0o755)
        for name in ("python3", "python", "cargo", "startup.sh"):          # the checkout's: each only writes a marker
            self.write(os.path.join(self.workspace, name), f"#!/bin/sh\necho {name} > '{self.marker}'\n", 0o755)
        self.env = {k: v for k, v in os.environ.items()
                    if not k.upper().startswith(("PYTHON", "CARGO", "RUST", "PIP_", "LAZARET_"))}
        self.env.update(RUNNER_TEMP=self.temp, GITHUB_WORKSPACE=self.workspace, GITHUB_ACTION_PATH=self.root,
                        RECORD=self.record, CARGO_HOME=self.home, RUSTUP_HOME=self.home,
                        PATH=os.pathsep.join([self.bin, self.ws_bin, "node_modules/.bin", os.environ.get("PATH", "")]))

    @staticmethod
    def write(path, text, mode=0o644):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(path, mode)

    def run_step(self, **env):
        p = run_script(steps(read(ACTION))[0], self.root, self.workspace, dict(self.env, **env))
        self.assertFalse(os.path.exists(self.marker), read(self.marker) if os.path.exists(self.marker) else "")
        return p, (read(self.record) if os.path.exists(self.record) else "")

    def calls(self, record):
        """[(argv, cwd, {name: value})] of the stand-ins' runs."""
        found = []
        for line in record.splitlines():
            key, _, value = line.partition(": ")
            if line.startswith("argv:"):
                found.append([line[len("argv: "):], None, {}])
            elif key == "cwd":
                found[-1][1] = value
            elif key == "env":
                name, _, val = value.partition("=")
                found[-1][2][name] = val
        return found

    def test_what_python_and_pip_are_started_with(self):
        hostile = {"PYTHONPATH": self.workspace, "PythonHome": self.workspace, "PYTHONUSERBASE": self.workspace,
                   "LAZARET_NATIVE_LIB": self.workspace + "/lib.so", "LAZARET_NATIVE_LIBRARY": self.workspace + "/lib.so",
                   "lazaret_wheel_platform": "linux_x86_64", "CARGO": self.workspace + "/cargo",
                   "RUSTC": self.workspace + "/rustc", "RUSTC_WRAPPER": self.workspace + "/w", "RUSTFLAGS": "-C x",
                   "CARGO_ENCODED_RUSTFLAGS": "-C", "CARGO_BUILD_RUSTC_WRAPPER": self.workspace + "/w",
                   "cargo_target_dir": self.workspace, "RUSTUP_TOOLCHAIN": self.workspace,
                   "PIP_CONFIG_FILE": self.workspace + "/pip.conf",
                   "BASH_ENV": os.path.join(self.workspace, "startup.sh"),
                   "BASH_FUNC_python3%%": f"() {{ echo function > '{self.marker}'; }}",
                   "BASH_FUNC_cargo%%": f"() {{ echo function > '{self.marker}'; }}"}
        p, record = self.run_step(**hostile)
        self.assertEqual(p.returncode, 0, p.stderr)
        (venv_argv, venv_cwd, venv_env), (_c_argv, _c_cwd, _c_env), (pip_argv, pip_cwd, pip_env) = self.calls(record)
        self.assertEqual(venv_argv, f"-I -m venv {self.temp}/lazaret-action")
        self.assertEqual(pip_argv, f"-I -m pip install --isolated --no-index --disable-pip-version-check {self.root}/python")
        self.assertEqual((venv_cwd, pip_cwd), (self.temp, self.temp))
        path = pip_env.pop("PATH").split(os.pathsep)
        self.assertEqual(pip_env, {"PIP_CONFIG_FILE": os.devnull, "CARGO": os.path.join(self.bin, "cargo"),
                                   "CARGO_HOME": self.home, "RUSTUP_HOME": self.home})
        self.assertIn(self.bin, path)
        self.assertNotIn(self.ws_bin, path)                                  # (the build's PATH: none of the workspace)
        self.assertNotIn("node_modules/.bin", path)
        self.assertEqual(venv_env.pop("PATH").split(os.pathsep), path)
        self.assertEqual(venv_env, {"CARGO": os.path.join(self.bin, "cargo"), "CARGO_HOME": self.home,
                                    "RUSTUP_HOME": self.home})                # (no PIP_* at all)

    def test_a_python3_or_cargo_in_the_workspace_is_refused(self):
        os.symlink(os.path.join(self.workspace, "cargo"), os.path.join(self.ws_bin, "cargo-link"))
        trusted_link = os.path.join(self.root, "links")
        os.makedirs(trusted_link)
        os.symlink(os.path.join(self.workspace, "python3"), os.path.join(trusted_link, "python3"))
        os.makedirs(os.path.join(self.temp, "rel"))                          # (PATH's "rel", from $RUNNER_TEMP)
        shutil.copy(os.path.join(self.bin, "python3"), os.path.join(self.temp, "rel"))
        for name, path in (("python3", [self.workspace, self.bin]), ("python3", ["rel", self.bin]),
                           ("python3", [trusted_link, self.bin]), ("cargo", [self.bin + "-none", self.workspace]),
                           ("cargo", [self.ws_bin.replace(".bin", ".bin/../.bin"), self.workspace])):
            with self.subTest(name=name, path=path):
                if os.path.exists(self.record):
                    os.unlink(self.record)
                first = [os.path.join(self.root, "only-python")] if name == "cargo" else []
                if first:
                    os.makedirs(first[0], exist_ok=True)
                    shutil.copy(os.path.join(self.bin, "python3"), first[0])
                p, record = self.run_step(PATH=os.pathsep.join(first + path + ["/usr/bin", "/bin"]))
                self.assertEqual(p.returncode, 2, p.stderr)
                self.assertIn(f"::error::{name} on PATH is ", p.stderr)
                self.assertNotIn("-m venv", record)                         # nothing ran

    def test_a_toolchain_home_or_runner_temp_in_the_workspace_is_refused(self):
        inside = os.path.join(self.workspace, ".cargo")
        os.makedirs(inside)
        for env in ({"CARGO_HOME": inside}, {"RUSTUP_HOME": inside}, {"RUNNER_TEMP": inside}):
            with self.subTest(**env):
                p, record = self.run_step(**env)
                self.assertEqual(p.returncode, 2, p.stderr)
                self.assertIn("is in the workspace: refused", p.stderr)
                self.assertEqual(record, "")


@unittest.skipUnless(shutil.which("bash") and sys.platform != "win32",
                     "needs bash (on Windows the one on PATH can be WSL's launcher, while a runner runs the "
                     "step in Git Bash: the script is tested on Linux and macOS)")
class ScanStepTests(unittest.TestCase):
    """The scan step's script, run with the step's shell; the venv's python is
    a stand-in that writes its arguments, one per line, its working directory
    and the PYTHON* and native-library variables it has, and exits with $EXIT.
    The step starts in the workspace, as a composite action's step does."""

    @classmethod
    def setUpClass(cls):
        cls.step = steps(read(ACTION))[1]

    def run_step(self, path=".", sarif="lazaret.sarif", gate="true", deps="false", exit_code=0):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.temp = os.path.join(d.name, "runner-temp")
        self.workspace = os.path.join(d.name, "workspace")
        os.makedirs(self.workspace)
        bindir = os.path.join(self.temp, "lazaret-action", "bin")
        os.makedirs(bindir)
        argv_file, cwd_file, env_file = (os.path.join(d.name, n) for n in ("argv", "cwd", "env"))
        stub = os.path.join(bindir, "python")
        with open(stub, "w", encoding="utf-8") as fh:
            fh.write(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{argv_file}"\npwd -P > "{cwd_file}"\n'
                     f'env | grep -i -E "^(python|lazaret_native|lazaret_wheel|cargo|rust)" > "{env_file}"\n'
                     f'exit "$EXIT"\n')
        os.chmod(stub, 0o755)
        output = os.path.join(d.name, "github_output")
        open(output, "w", encoding="utf-8").close()
        env = dict(os.environ, RUNNER_TEMP=self.temp, GITHUB_WORKSPACE=self.workspace, GITHUB_OUTPUT=output,
                   SCAN_PATH=path, SARIF_PATH=sarif, GATE=gate, DEPS=deps, EXIT=str(exit_code),
                   PYTHONPATH=self.workspace, PYTHONHOME=self.workspace, PYTHONUSERBASE=self.workspace,
                   PYTHONSTARTUP=os.path.join(self.workspace, "startup.py"), PythonInspect="1",
                   LAZARET_NATIVE_LIB=os.path.join(self.workspace, "lib.so"), lazaret_native_library="x",
                   LAZARET_WHEEL_PLATFORM="linux_x86_64", BASH_ENV=os.path.join(self.workspace, "startup.sh"),
                   CARGO=os.path.join(self.workspace, "cargo"), RUSTC_WRAPPER=os.path.join(self.workspace, "w"))
        for name in [k for k in env if k.upper().startswith(("CARGO_", "RUSTUP_"))]:
            del env[name]                                                   # (this machine's toolchain homes)
        self.marker = os.path.join(d.name, "marker")
        with open(env["BASH_ENV"], "w", encoding="utf-8") as fh:
            fh.write(f"echo ran > '{self.marker}'\n")
        p = run_script(self.step, d.name, self.workspace, env)
        self.assertFalse(os.path.exists(self.marker))                         # (BASH_ENV: the shell starts without it)
        argv = read(argv_file).splitlines() if os.path.exists(argv_file) else None
        if argv is not None:
            self.ran_in = read(cwd_file).strip()
            self.python_env = read(env_file)
        return p, argv, read(output)

    def test_the_arguments_and_the_output(self):
        p, argv, output = self.run_step()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(argv, ["-I", "-m", "lazaret", self.workspace, "--sarif", "lazaret.sarif", "--no-html",
                                "--no-json", "--ci"])
        self.assertEqual(output, "sarif=./lazaret.sarif\n")
        p, argv, output = self.run_step(path="src/app/", sarif="out/l.sarif", gate="false", deps="true")
        self.assertEqual(argv, ["-I", "-m", "lazaret", self.workspace + "/src/app/", "--sarif", "out/l.sarif",
                                "--no-html", "--no-json", "--deps"])
        self.assertEqual(output, "sarif=src/app/out/l.sarif\n")
        _p, _argv, output = self.run_step(sarif="/tmp/x/l.sarif")
        self.assertEqual(output, "sarif=/tmp/x/l.sarif\n")
        for sarif in ("\\\\host\\share\\r.sarif", "C:\\r.sarif"):                        # (Windows: a UNC path, a drive)
            with self.subTest(sarif=sarif):
                _p, argv, output = self.run_step(sarif=sarif)
                self.assertEqual(argv[5], sarif)
                self.assertEqual(output, f"sarif={sarif}\n")

    def test_the_directory_to_scan_is_the_workspaces(self):
        """The step runs in $RUNNER_TEMP, so a relative path is made absolute
        from $GITHUB_WORKSPACE; an absolute one (POSIX or Windows) is kept, and
        an empty one stays empty (the CLI's usage error, as before)."""
        for path, target, report in (("./src", "{ws}/./src", "./src/lazaret.sarif"),
                                     ("/abs/dir", "/abs/dir", "/abs/dir/lazaret.sarif"),
                                     ("C:\\a\\b", "C:\\a\\b", "C:\\a\\b/lazaret.sarif"),
                                     ("D:/a", "D:/a", "D:/a/lazaret.sarif"),
                                     ("", "", "/lazaret.sarif")):
            with self.subTest(path=path):
                p, argv, output = self.run_step(path=path)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(argv[3], target.format(ws=self.workspace))
                self.assertEqual(output, f"sarif={report}\n")

    def test_it_runs_isolated_from_the_workspace(self):
        """F-01: the interpreter is started in $RUNNER_TEMP, with -I, with no
        PYTHON* variable, native-library override or Rust tool variable
        (whatever its case) the workflow set, and BASH_ENV did not run."""
        p, argv, _output = self.run_step()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(argv[:3], ["-I", "-m", "lazaret"])
        self.assertEqual(self.ran_in, os.path.realpath(self.temp))
        self.assertEqual(self.python_env, "")

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
        self.assertEqual(argv[3], self.workspace + "/$(touch pwned); `id` ; x")
        self.assertEqual(argv[5], "'; echo hi #")
        for folder in (os.curdir, self.workspace, self.temp):
            self.assertFalse(os.path.exists(os.path.join(folder, "pwned")))


if __name__ == "__main__":
    unittest.main()
