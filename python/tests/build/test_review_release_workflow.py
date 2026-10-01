"""The GitHub workflows, read as text (no YAML parser: nothing is installed).

- npm commands name local files as paths npm reads as paths. npm resolves a
  package argument like "npm-dist/lazaret-0.1.0.tgz" as the GitHub
  repository npm-dist/lazaret-0.1.0.tgz, not as a file, and tries to clone
  it: the v0.1.0 release run failed that way in `npm stage publish`, after
  PyPI had already published. A local path needs "./" (or "../", "/").
- Every action is pinned to a full commit SHA, and every container image to
  a digest.
- wheels.yml builds, packs, checks and installs the same platforms: the tags
  of its library jobs, of the backend's --platform list (each library where
  its artifact lands, under the name _native.py loads), of the check's
  --expect list and of the install job are one set, and release.yml
  publishes what it builds.
- The parity modules skip where the library does not load, so every job that
  runs them first proves the library loads (a job that built a library the
  tests can't find would otherwise pass without testing it); likewise the
  npm engine's (test_js_parity*, test_wasm_parity*) where its WebAssembly
  build is missing (0.1.8).
- The npm package's WebAssembly engine is built for a release with the
  compiler of the platform wheels' libraries, and the tarball carries it.
- No `{a, b}` inside double quotes nested in "$(...)": macOS runs `shell:
  bash` steps with /bin/bash 3.2, which brace-expands it there. CI run 47
  split a Python dict literal that way into two broken programs, and the
  macOS parity step failed.
"""

import glob
import os
import re
import shlex
import unittest

from tests import _support

WORKFLOWS = os.path.join(_support.REPO_ROOT, ".github", "workflows")
NPM_CMD = re.compile(r"\bnpm\s+(?:stage\s+)?(?:publish|install|i|add|pack)\b(.*)")
LOCAL = ("./", "../", "/", "~/", "$")         # "$VAR/x": the variable holds a path


def misread_specs(text):
    """-> [(line number, argument)] for npm arguments npm would take for a
    GitHub owner/repo instead of the local file they name."""
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        code = line.strip()
        if code.startswith("#"):
            continue
        if code.startswith("- run:"):
            code = code[len("- run:"):]
        m = NPM_CMD.search(code)
        if not m:
            continue
        try:
            args = shlex.split(m.group(1), comments=True)
        except ValueError:
            args = m.group(1).split()
        for arg in args:
            if (arg.startswith("-") or "/" not in arg or arg.startswith(LOCAL)
                    or arg.startswith("@") or "://" in arg or arg in ("|", "&&", ";")):
                continue
            found.append((n, arg))
    return found


class NpmPathTests(unittest.TestCase):
    def test_workflows_pass_local_paths_npm_reads_as_paths(self):
        for path in sorted(glob.glob(os.path.join(WORKFLOWS, "*.yml"))):
            with self.subTest(workflow=os.path.basename(path)):
                with open(path, encoding="utf-8") as fh:
                    self.assertEqual(misread_specs(fh.read()), [])

    def test_the_check_catches_the_v010_line(self):
        bad = '      - run: npm stage publish "npm-dist/lazaret-${GITHUB_REF_NAME#v}.tgz"\n'
        good = ('      - run: npm stage publish "./npm-dist/lazaret-${GITHUB_REF_NAME#v}.tgz"\n'
                "          npm pack --ignore-scripts --pack-destination ../npm-dist\n"
                "      # npm publish npm-dist/x.tgz (a comment)\n"
                "        run: npm install @scope/pkg lazaret\n")
        self.assertEqual(misread_specs(bad), [(1, "npm-dist/lazaret-${GITHUB_REF_NAME#v}.tgz")])
        self.assertEqual(misread_specs(good), [])


def read(name):
    with open(os.path.join(WORKFLOWS, name), encoding="utf-8") as fh:
        return fh.read()


def workflows():
    """{file name: text} of every workflow."""
    return {os.path.basename(p): read(os.path.basename(p)) for p in sorted(glob.glob(os.path.join(WORKFLOWS, "*.yml")))}


def code_lines(text):
    """The lines that are not YAML comments, with their numbers."""
    return [(n, line) for n, line in enumerate(text.splitlines(), 1) if not line.strip().startswith("#")]


def jobs(text):
    """{job id: its lines (comments left out)} for a workflow's top-level jobs: map."""
    found, current, inside = {}, None, False
    for _n, line in code_lines(text):
        if not inside:
            inside = line.rstrip() == "jobs:"
            continue
        if line.strip() and not line.startswith("  "):
            break                                        # the next top-level key: the jobs are over
        header = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if header:
            current = header.group(1)
            found[current] = ""
        elif current:
            found[current] += line + "\n"
    return found


TAG_RE = re.compile(r"^\s*(?:-\s*)?\{?\s*tag:\s*([a-z0-9_]+)", re.M)


class PinTests(unittest.TestCase):
    def test_actions_are_pinned_to_commits_and_images_to_digests(self):
        for name, text in workflows().items():
            for n, line in code_lines(text):
                with self.subTest(workflow=name, line=n):
                    m = re.search(r"\buses:\s*(\S+)", line)
                    if m and not m.group(1).startswith("./.github/workflows/"):
                        self.assertRegex(m.group(1), r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
                        self.assertRegex(line, r"# v\d")
                    m = re.search(r"\b(?:image|IMAGE):\s*(\S+)", line)
                    if m and not m.group(1).startswith("${{"):
                        self.assertRegex(m.group(1), r"@sha256:[0-9a-f]{64}$")


class WheelPlatformTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = read("wheels.yml")
        cls.jobs = jobs(cls.text)
        cls.check = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "check_native_library.py"),
                                         "check_native_library_for_workflows")

    def tags(self, job):
        return sorted(TAG_RE.findall(self.jobs[job]))

    def test_the_jobs(self):
        self.assertEqual(sorted(self.jobs), ["dist", "install", "linux", "macos-windows"])

    def test_every_step_names_the_same_platforms(self):
        built = sorted(self.tags("linux") + self.tags("macos-windows"))
        self.assertEqual(built, sorted(["manylinux_2_28_x86_64", "manylinux_2_28_aarch64", "macosx_11_0_arm64",
                                        "macosx_10_12_x86_64", "win_amd64"]))
        packed = re.findall(r"--platform (\S+?)=(\S+)", self.jobs["dist"])
        self.assertEqual(sorted(tag for tag, _ in packed), built)
        for tag, library in packed:
            with self.subTest(tag=tag):
                # download-artifact puts artifact native-<tag> in native/native-<tag>/
                self.assertEqual(library, f"../native/native-{tag}/{self.check.library_name(tag)}")
                self.assertTrue(self.check.supported(tag))
        self.assertEqual(sorted(re.findall(r"--expect (\S+)", self.jobs["dist"])), built)
        self.assertEqual(self.tags("install"), built)
        for job in ("linux", "macos-windows"):
            self.assertIn("name: native-${{ matrix.tag }}", self.jobs[job])
        self.assertIn("pattern: native-*", self.jobs["dist"])

    def test_each_library_is_built_for_its_tag(self):
        linux = self.jobs["linux"]
        for tag in self.tags("linux"):
            with self.subTest(tag=tag):
                arch = re.match(r"manylinux_\d+_\d+_(\w+)$", tag).group(1)
                self.assertRegex(linux, rf"tag: {tag}\n.*\n\s+target: {arch}-unknown-linux-gnu\n"
                                        rf"\s+image: quay\.io/pypa/{tag}:\S+@sha256:")
        other = self.jobs["macos-windows"]
        for tag, version in (("macosx_11_0_arm64", "11.0"), ("macosx_10_12_x86_64", "10.12")):
            with self.subTest(tag=tag):
                block = other[other.index(f"tag: {tag}"):][:400]
                self.assertIn(f'deployment-target: "{version}"', block)
        block = other[other.index("tag: win_amd64"):][:400]
        self.assertIn("rustflags: -C target-feature=+crt-static", block)
        self.assertIn("MACOSX_DEPLOYMENT_TARGET: ${{ matrix.deployment-target }}", other)
        self.assertIn("RUSTFLAGS: ${{ matrix.rustflags }}", other)

    def test_the_toolchain_is_pinned_and_builds_are_locked(self):
        self.assertRegex(self.text, r'(?m)^  RUST_VERSION: "\d+\.\d+\.\d+"$')
        for job in ("linux", "macos-windows"):
            with self.subTest(job=job):
                self.assertIn('rustup toolchain install "$RUST_VERSION" --profile minimal', self.jobs[job])
                self.assertIn("cargo build --release --offline --locked", self.jobs[job].replace(
                    'cargo +"$RUST_VERSION" build', "cargo build"))

    def test_release_publishes_what_wheels_builds(self):
        release = jobs(read("release.yml"))
        self.assertIn("uses: ./.github/workflows/wheels.yml", release["build-python"])
        self.assertIn("name: python-dist", self.jobs["dist"])
        for job in ("publish-pypi", "publish-npm"):
            with self.subTest(job=job):
                self.assertRegex(release[job], r"needs: \[build-python, build-npm\]")
        self.assertIn("name: python-dist", release["publish-pypi"])
        self.assertIn("workflow_call:", self.text)


# a brace list with a comma, inside a double-quoted string inside "$(...)"
BASH32_BRACES = re.compile(r'"\$\((?:[^()]|\([^()]*\))*?"[^"]*\{[^{}"]*,[^{}"]*\}[^"]*"')


class Bash32Tests(unittest.TestCase):
    def test_no_brace_lists_in_nested_double_quotes(self):
        for name, text in workflows().items():
            for n, line in code_lines(text):
                with self.subTest(workflow=name, line=n):
                    self.assertIsNone(BASH32_BRACES.search(line), line.strip())

    def test_the_check_catches_run_47s_line(self):
        run_47 = ('export LAZARET_NATIVE_LIB="$(python -c "import os, sys; n = {\'win32\': \'x.dll\', '
                  '\'darwin\': \'x.dylib\'}.get(sys.platform, \'x.so\'); print(n)")"')
        self.assertIsNotNone(BASH32_BRACES.search(run_47))
        for fine in ('toolchain="$(rustc +"$RUST_VERSION" --print sysroot)"',
                     'if [ "$(git cat-file -t "refs/tags/${GITHUB_REF_NAME}")" != "tag" ]; then',
                     "lib=$(python -c 'n = {\"a\": 1, \"b\": 2}; print(n)')",
                     '"$py" -c \'print(f"{v}, {w}")\''):
            self.assertIsNone(BASH32_BRACES.search(fine), fine)


class ParityTestsProveTheLibraryLoads(unittest.TestCase):
    def test_every_job_that_runs_them_loads_the_library_first(self):
        runs = 0
        for name, workflow in workflows().items():
            for job, text in jobs(workflow).items():
                if "test_rust_parity_" not in text:
                    continue
                runs += 1
                with self.subTest(workflow=name, job=job):
                    before = text[:text.index("test_rust_parity_")]
                    self.assertTrue("--load" in before and "check_native_library.py" in before
                                    or "_native.available()" in before, "the parity modules would skip silently")
        self.assertEqual(runs, 3)             # ci.yml's rust job, wheels.yml's two library jobs

    def test_every_job_that_runs_them_runs_them_all(self):
        # the modules skip without the library, so the jobs that run the whole
        # suite skip them: each job that builds a library names every one
        arch = os.path.join(_support.REPO_ROOT, "python", "tests", "architecture")
        modules = sorted(f[:-3] for f in os.listdir(arch) if f.startswith("test_rust_parity_") and f.endswith(".py"))
        self.assertGreater(len(modules), 10)
        for name, workflow in workflows().items():
            for job, text in jobs(workflow).items():
                if "test_rust_parity_" not in text:
                    continue
                for module in modules:
                    with self.subTest(workflow=name, job=job, module=module):
                        self.assertTrue(re.search(rf"tests\.architecture\.{module}\b", text), "not run here")


class NpmEngineTests(unittest.TestCase):
    def test_every_job_that_tests_the_npm_engine_builds_it_and_loads_it_first(self):
        runs = 0
        for name, workflow in workflows().items():
            for job, text in jobs(workflow).items():
                at = min((text.index(m) for m in ("tests.architecture.test_js_parity", "test_wasm_parity")
                          if m in text), default=None)
                if at is None:
                    continue
                runs += 1
                with self.subTest(workflow=name, job=job):
                    before = text[:at]
                    self.assertIn("rustup target add wasm32-unknown-unknown", before)
                    self.assertIn("npm run build", before)
                    self.assertIn("n.available()", before, "the parity modules would skip silently")
        self.assertEqual(runs, 2)             # ci.yml's js and rust jobs

    def test_every_module_that_needs_the_npm_engine_runs_where_it_is_built(self):
        # a module whose tests skip without js/native/lazaret.wasm (NPM_READY)
        # is skipped by the jobs that run the whole suite: a job that builds
        # the engine must name it, or nothing runs it
        arch = os.path.join(_support.REPO_ROOT, "python", "tests", "architecture")
        gated = sorted(f[:-3] for f in os.listdir(arch) if f.startswith("test_") and f.endswith(".py")
                       and "NPM_READY" in open(os.path.join(arch, f), encoding="utf-8").read())
        self.assertGreater(len(gated), 10)
        built = "".join(text for workflow in workflows().values() for text in jobs(workflow).values()
                        if "npm run build" in text)
        for module in gated:
            self.assertTrue(re.search(rf"tests\.architecture\.{module}\b", built),
                            f"{module} is run by no job that builds the npm engine")

    def test_release_builds_the_engine_with_the_wheels_compiler(self):
        pin = re.compile(r'(?m)^  RUST_VERSION: "(\d+\.\d+\.\d+)"$')
        self.assertEqual(pin.findall(read("release.yml")), pin.findall(read("wheels.yml")))
        build = jobs(read("release.yml"))["build-npm"]
        self.assertIn('rustup toolchain install "$RUST_VERSION" --profile minimal --target wasm32-unknown-unknown',
                      build)
        self.assertIn("RUSTUP_TOOLCHAIN: ${{ env.RUST_VERSION }}", build)
        self.assertLess(build.index("npm run build"), build.index("npm test"))
        self.assertLess(build.index("npm test"), build.index("npm pack"))
        for f in ("package/native/lazaret.wasm", "package/native/NOTICE"):
            self.assertIn(f, build)
        script = open(os.path.join(_support.REPO_ROOT, "js", "scripts", "build-wasm.js"), encoding="utf-8").read()
        self.assertIn('"--profile", "wasm", "--offline", "--locked", "--target", "wasm32-unknown-unknown"', script)


if __name__ == "__main__":
    unittest.main()
