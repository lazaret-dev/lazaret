"""action.yml's two steps run for real in a hostile checkout (F-01).

`python -m` puts the current directory first on sys.path, and a composite
action's step starts in the workspace, the checkout it scans: a pull request
that adds venv.py, pip.py or lazaret.py (or a sitecustomize.py), or a
workflow that sets PYTHONPATH, had its code run by the action. Here the
install and scan steps' scripts (read from action.yml as
test_review_action reads them) run as the runner runs them (a file, with
the step's `shell:`) and with this test's interpreter (sys.executable, as
the runner's python3) in a temporary checkout holding shadow modules (venv,
pip, ensurepip, lazaret, sitecustomize, usercustomize), a user site .pth
file, a startup file, a BASH_ENV script and exported bash functions named
python3, python and cargo, each of which only writes a marker file, with
PYTHONPATH, PYTHONUSERBASE and PYTHONSTARTUP pointing into it and the
native-library overrides and Rust tool variables naming files of
it. No marker may be written. A second install adds BASH_ENV and the
functions, PYTHONHOME into the checkout (a Python that honoured it would
not start) and a pip configuration of the checkout's, by PIP_CONFIG_FILE and
by XDG_CONFIG_DIRS, that would install elsewhere and turn pip's build
isolation off.

The real install compiles the Rust engine, too slow here, so
GITHUB_ACTION_PATH is a small stand-in action: its python/ is a source tree
with its own standard-library build backend (as Lazaret's is: no build
requirements, backend-path), which pip builds offline with the step's own
command. The backend records what it saw (working directory, sys.path, the
PYTHON*, PIP_*, LAZARET_*, CARGO* and RUST* variables) into the wheel, and
the stand-in `lazaret` writes a minimal SARIF report where the CLI would,
with that and its own view, and exits as a gate does (1 when
$LAZARET_TEST_GATE_EXIT says so and --ci is given). About 12 s: two venvs.
test_action_backend.py runs the install step on this repository's own
python/, the real build backend.
"""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.build.test_review_action import ACTION, read, run_script, steps

SHADOWS = ("venv", "pip", "ensurepip", "lazaret", "sitecustomize", "usercustomize")
WATCHED = ("PYTHON", "PIP_", "LAZARET_", "CARGO", "RUST")

BACKEND = '''\
"""A stand-in build backend (PEP 517), standard library only."""
import base64
import hashlib
import json
import os
import sys
import zipfile

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
WATCHED = ("PYTHON", "PIP_", "LAZARET_", "CARGO", "RUST")
DIST_INFO = "lazaret-0.0.0.dist-info"
WHEEL = "lazaret-0.0.0-py3-none-any.whl"


def _files():
    files = {}
    for folder, dirs, names in os.walk(SRC):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(names):
            path = os.path.join(folder, name)
            with open(path, "rb") as fh:
                files[os.path.relpath(path, SRC).replace(os.sep, "/")] = fh.read()
    seen = {"cwd": os.getcwd(), "sys_path": sys.path,
            "env": {k: v for k, v in os.environ.items() if k.upper().startswith(WATCHED)}}
    files["lazaret/_built.json"] = json.dumps(seen).encode("utf-8")
    files[DIST_INFO + "/METADATA"] = b"Metadata-Version: 2.1\\nName: lazaret\\nVersion: 0.0.0\\n"
    files[DIST_INFO + "/WHEEL"] = b"Wheel-Version: 1.0\\nGenerator: test\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n"
    record = []
    for arc, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")
        record.append(f"{arc},sha256={digest},{len(data)}")
    record.append(DIST_INFO + "/RECORD,,")
    files[DIST_INFO + "/RECORD"] = ("\\n".join(record) + "\\n").encode("utf-8")
    return files


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    with zipfile.ZipFile(os.path.join(wheel_directory, WHEEL), "w") as zf:
        for arc, data in _files().items():
            zf.writestr(arc, data)
    return WHEEL
'''

MAIN = '''\
"""The stand-in `python -m lazaret DIR --sarif PATH ...`: a minimal SARIF
report where the CLI writes it (a relative PATH is under DIR), then the gate's
exit code."""
import json
import os
import sys

WATCHED = ("PYTHON", "PIP_", "LAZARET_", "CARGO", "RUST")


def main(argv):
    target = argv[0]
    sarif = argv[argv.index("--sarif") + 1]
    report = sarif if os.path.isabs(sarif) else os.path.join(target, sarif)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "_built.json"), encoding="utf-8") as fh:
        built = json.load(fh)
    seen = {"argv": argv, "cwd": os.getcwd(), "sys_path": sys.path, "isolated": sys.flags.isolated,
            "env": {k: v for k, v in os.environ.items() if k.upper().startswith(WATCHED)}, "built": built}
    log = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "lazaret"}}, "results": [],
                                         "properties": seen}]}
    with open(report, "w", encoding="utf-8") as fh:
        json.dump(log, fh)
    return int(os.environ.get("LAZARET_TEST_GATE_EXIT", "0")) if "--ci" in argv else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
'''


def write(path, text, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    if mode is not None:
        os.chmod(path, mode)


def ensurepip_missing():
    """Why this Python can't make a venv with pip (the install step needs
    one), or None."""
    try:
        import ensurepip
        import venv
        if venv.EnvBuilder and ensurepip.version():
            return None
    except Exception as exc:                       # (Debian's Python without python3-venv, a stripped build)
        return f"this Python's venv can't install pip ({type(exc).__name__}: {exc})"
    return "this Python's venv can't install pip (ensurepip has no pip)"


def marker_code(markers, name):
    return (f"import os\nwith open(os.path.join({markers!r}, {name!r}), 'w', encoding='utf-8') as fh:\n"
            f"    fh.write(__file__)\n")


def hostile_checkout(root, markers):
    """A checkout whose files only write markers, and the variables a workflow could set into it: (checkout,
    {Python's, Lazaret's and Rust's}, {the shell's: BASH_ENV and exported functions})."""
    checkout = os.path.join(root, "checkout")
    for name in SHADOWS:
        write(os.path.join(checkout, name + ".py"), marker_code(markers, name))
    write(os.path.join(checkout, "startup.py"), marker_code(markers, "startup"))
    sh = f"#!/bin/sh\necho ran > {shlex.quote(os.path.join(markers, 'shell'))}\nexit 37\n"
    for name in ("startup.sh", "cargo", "python3"):
        write(os.path.join(checkout, name), sh, 0o755)
    write(os.path.join(checkout, "native.so"), "F-01 inert native payload marker\n")
    userbase = os.path.join(checkout, "userbase")
    # the user site directory this Python would read under that PYTHONUSERBASE (its own site module says)
    usersite = subprocess.run([sys.executable, "-I", "-c", "import site; print(site.getusersitepackages())"],
                              cwd=root, env=dict(os.environ, PYTHONUSERBASE=userbase),
                              capture_output=True, encoding="utf-8", errors="replace", timeout=30).stdout.strip()
    if os.path.isabs(usersite):
        write(os.path.join(usersite, "shadow.pth"),
              f"import os; open(os.path.join({markers!r}, 'pth'), 'w', encoding='utf-8').close()\n")
    function = f"() {{ echo ran > {shlex.quote(os.path.join(markers, 'function'))}; return 37; }}"
    shell = {"BASH_ENV": os.path.join(checkout, "startup.sh"), "BASH_FUNC_python3%%": function,
             "BASH_FUNC_python%%": function, "BASH_FUNC_cargo%%": function}
    variables = {"PYTHONPATH": checkout, "PYTHONUSERBASE": userbase, "PYTHONSTARTUP": os.path.join(checkout, "startup.py"),
                 "LAZARET_NATIVE_LIB": os.path.join(checkout, "native.so"),
                 "LAZARET_NATIVE_LIBRARY": os.path.join(checkout, "native.so"), "LAZARET_WHEEL_PLATFORM": "linux_x86_64",
                 "CARGO": os.path.join(checkout, "cargo"), "RUSTC": os.path.join(checkout, "cargo"),
                 "RUSTC_WRAPPER": os.path.join(checkout, "cargo"), "RUSTFLAGS": "-C linker=" + os.path.join(checkout, "cargo"),
                 "CARGO_BUILD_RUSTC_WRAPPER": os.path.join(checkout, "cargo"),
                 "CARGO_TARGET_DIR": os.path.join(checkout, "target"), "RUSTUP_TOOLCHAIN": checkout}
    return checkout, variables, shell


def base_env(root, bindir):
    """This process's environment without the variables the test sets, and PATH with `bindir` (python3: this
    test's interpreter) first."""
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(WATCHED)}
    env.update(PATH=bindir + os.pathsep + os.environ.get("PATH", ""), XDG_CACHE_HOME=os.path.join(root, "cache"))
    write(os.path.join(bindir, "python3"), f"#!/bin/sh\nexec {shlex.quote(sys.executable)} \"$@\"\n", 0o755)
    return env


def inside(path, folder):
    path = os.path.realpath(path)
    return path == folder or path.startswith(folder + os.sep)


SKIP_BASH = (shutil.which("bash") and shutil.which("env") and sys.platform != "win32",
             "needs bash and env (on Windows the bash on PATH can be WSL's launcher, while a runner runs the step in "
             "Git Bash: the scripts are tested on Linux and macOS)")


@unittest.skipUnless(*SKIP_BASH)
class IsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        why = ensurepip_missing()
        if why:
            raise unittest.SkipTest(why)
        cls.install, cls.scan = steps(read(ACTION))
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        root = cls.root = os.path.realpath(tmp.name)
        cls.markers = os.path.join(root, "markers")
        os.makedirs(cls.markers)
        cls.checkout, hostile, shell = hostile_checkout(root, cls.markers)
        action = os.path.join(root, "action")
        write(os.path.join(action, "python", "pyproject.toml"),
              '[build-system]\nrequires = []\nbuild-backend = "fake_backend"\nbackend-path = ["_build"]\n')
        write(os.path.join(action, "python", "_build", "fake_backend.py"), BACKEND)
        write(os.path.join(action, "python", "src", "lazaret", "__init__.py"), '"""A stand-in Lazaret."""\n')
        write(os.path.join(action, "python", "src", "lazaret", "__main__.py"), MAIN)
        cls.env = base_env(root, os.path.join(root, "bin"))
        cls.env.update(GITHUB_WORKSPACE=cls.checkout, GITHUB_ACTION_PATH=action, **hostile)
        # the checkout's pip configuration, read by pip whatever --isolated says: it would install elsewhere and
        # turn the build isolation off (pip reads a --no-* option's value inverted: false turns it off)
        cls.pip_target = os.path.join(root, "pip-target")
        config = f"[install]\ntarget = {cls.pip_target}\nno-build-isolation = false\n"
        write(os.path.join(cls.checkout, "pip.conf"), config)
        write(os.path.join(cls.checkout, "xdg", "pip", "pip.conf"), config)
        cls.runs = {}
        for name, extra in (("plain", {}),
                            ("the shell's, PYTHONHOME and pip's configuration",
                             {"PYTHONHOME": os.path.join(cls.checkout, "home"),
                              "PIP_CONFIG_FILE": os.path.join(cls.checkout, "pip.conf"),
                              "XDG_CONFIG_DIRS": os.path.join(cls.checkout, "xdg"), **shell})):
            temp = os.path.join(root, "runner-temp-" + str(len(cls.runs)))
            os.makedirs(temp)
            env = dict(cls.env, RUNNER_TEMP=temp, **extra)
            cls.runs[name] = temp, run_script(cls.install, temp, cls.checkout, env, timeout=25)

    def installed(self, build="plain"):
        temp, p = self.runs[build]
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        return temp

    def assertNoMarker(self):
        self.assertEqual(sorted(os.listdir(self.markers)), [], "code from the checkout ran:\n" +
                         "".join(p.stdout + p.stderr for _temp, p in self.runs.values()))

    def assertOutside(self, seen, what):
        """No entry of sys.path in the checkout, no watched variable that points into it (pip's own PYTHONPATH
        for its build environment is not the workflow's), and not run there."""
        self.assertEqual([p for p in seen["sys_path"] if inside(os.path.join(seen["cwd"], p), self.checkout)], [],
                         f"{what}: sys.path holds the checkout")
        pointing = {k: v for k, v in seen["env"].items() if self.checkout in v}
        self.assertEqual(pointing, {}, f"{what}: variables into the checkout")
        self.assertFalse(inside(seen["cwd"], self.checkout), f"{what}: ran in the checkout")

    def run_scan(self, path=".", sarif="lazaret.sarif", gate="true", deps="false", exit_code=0, build="plain"):
        self.temp = self.installed(build)
        output = os.path.join(self.temp, "github_output")
        open(output, "w", encoding="utf-8").close()
        env = dict(self.env, RUNNER_TEMP=self.temp, GITHUB_OUTPUT=output, SCAN_PATH=path, SARIF_PATH=sarif,
                   GATE=gate, DEPS=deps, LAZARET_TEST_GATE_EXIT=str(exit_code))
        p = run_script(self.scan, self.temp, self.checkout, env)
        return p, read(output)

    def report(self, output):
        """The SARIF log at the path the step's output names (upload-sarif
        reads it from the workspace), and what the stand-in saw."""
        name = output.strip().partition("=")[2]
        path = os.path.join(self.checkout, name)
        self.assertTrue(os.path.isfile(path), f"no report at {path}")
        with open(path, encoding="utf-8") as fh:
            log = json.load(fh)
        self.assertEqual(log["version"], "2.1.0")
        return log["runs"][0]["properties"]

    def test_the_install_runs_no_code_of_the_checkout(self):
        self.assertNoMarker()                       # (first: on the old action the plain install writes four)
        for build in self.runs:
            with self.subTest(build=build):
                self.installed(build)

    def test_pips_build_runs_outside_the_checkout_and_reads_no_configuration(self):
        """The build backend's process (a subprocess pip starts, not with -I) has no part of the checkout on
        sys.path and none of the variables the workflow set: pip's own two for its isolated build, its null
        configuration file, and the cargo the step resolved. The checkout's pip configuration is not read: the
        build is isolated and the package is in the venv, not in its target."""
        for build in self.runs:
            with self.subTest(build=build):
                p, output = self.run_scan(build=build)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
                built = self.report(output)["built"]
                self.assertOutside(built, "the build backend")
                env = dict(built["env"])
                cargo = env.pop("CARGO", None)
                self.assertTrue(cargo is None or not inside(cargo, self.checkout), cargo)
                env.pop("CARGO_HOME", None), env.pop("RUSTUP_HOME", None)
                self.assertEqual(env.pop("PIP_CONFIG_FILE"), os.devnull)
                env.pop("PIP_BUILD_TRACKER", None)                            # (pip's own, outside the checkout)
                self.assertEqual(sorted(env), ["PYTHONNOUSERSITE", "PYTHONPATH"])   # (pip's isolated build)
                venv = os.path.join(self.temp, "lazaret-action") + os.sep
                self.assertFalse([p for p in built["sys_path"] if os.path.realpath(p).startswith(venv)])
        self.assertFalse(os.path.exists(self.pip_target))
        self.assertNoMarker()

    def test_the_scan_runs_isolated_and_writes_the_report_where_it_says(self):
        p, output = self.run_scan()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(output, "sarif=./lazaret.sarif\n")
        seen = self.report(output)
        self.assertEqual(seen["argv"], [self.checkout, "--sarif", "lazaret.sarif", "--no-html", "--no-json", "--ci"])
        self.assertEqual(seen["isolated"], 1)
        self.assertEqual(seen["env"], {"LAZARET_TEST_GATE_EXIT": "0"})    # (no PYTHON*, native or Rust variable)
        self.assertEqual(os.path.realpath(seen["cwd"]), self.temp)
        self.assertOutside(seen, "the scan")
        self.assertNoMarker()

    def test_a_failed_gate_fails_the_step_and_the_report_is_written(self):
        p, output = self.run_scan(exit_code=1)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertEqual(output, "sarif=./lazaret.sarif\n")
        self.report(output)
        p, output = self.run_scan(gate="false", exit_code=1)      # no --ci: no gate
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNoMarker()

    def test_a_relative_directory_and_report(self):
        os.makedirs(os.path.join(self.checkout, "sub", "dir", "out"), exist_ok=True)
        p, output = self.run_scan(path="sub/dir/", sarif="out/l.sarif", deps="true")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(output, "sarif=sub/dir/out/l.sarif\n")
        seen = self.report(output)
        self.assertEqual(seen["argv"][0], self.checkout + "/sub/dir/")
        self.assertEqual(seen["argv"][-1], "--deps")
        self.assertNoMarker()


if __name__ == "__main__":
    unittest.main()
