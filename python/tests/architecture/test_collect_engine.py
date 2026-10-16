"""The collection is the engine's (BR-7 step 4 (e), 0.1.9).

core decided what a project scan's walk does with each entry of a folder and how it reads each file it meets
(_collect, _collect_file, _collect_config, _check_pycache, _dep_tree_kind, _vendor_kind, _vendor_lang and the
coverage notes; configsecrets' is_config_file and own_report), and the npm package its twin (lib/fs.js collectFiles
and checkPycache, lib/collect.js collectEntry, lib/configsecrets.js); the registry decided which members are tests
(is_test_path, _not_used_code) and which findings in them are listed only (_demote_test_findings). The engine decides
for all of them (rust/crates/lazaret-engine/src/collect.rs: collect_dir, collect_file, collect_pycache, collect_issue,
collect_check, test_paths, demote_tests); the packages list folders, read bytes, keep the folders seen and count a
pruned tree.

Held here to core's code as it was (below: what this replaced, word for word but its docstrings, the modules' names
local), on generated trees: sources, scripts by their #! line, binaries, images, manifests, .pth files, AppleDouble
files, a camera's .mts videos, config files (UTF-16 ones, Lazaret's own reports, lockfiles), files over the size
limits, links, named pipes, folders seen twice, .git, excluded names, node_modules, venvs with and without
pyvenv.cfg, Go and cargo vendor trees, __pycache__ folders with .pyc headers, with --deps and without; and the npm
package's walk to the Python package's. Two answers changed on purpose (0.1.9, rule set 2.85.0: SECRET-FP): Rust's
tests.rs and *_test.rs are test files, and a secret (S-SECRET, S-TOKEN) in test code is listed as INFO. All content
is inert.
"""
import copy
import json
import os
import random
import shutil
import stat as _stat
import subprocess
import tempfile
import unittest

from lazaret.scanner import _native, core, engine
from lazaret.scanner.core import (
    ScanTargetError, _NotRegularFile, _count_skipped_tree, _fs_display, _is_reparse_point, _mpeg_ts, _read_prefix,
    _readlink, _special_kind, classify_binary, decode_member, decode_source, disguised_binary, looks_binary,
    normalize_newlines, pth_issues, pyc_issues, script_source_lang, truncated_issue, _safe_text)
from tests import _support
from tests.architecture.test_js_parity import NPM_READY, NPM_SKIP

if not _native.available():
    raise unittest.SkipTest(f"the collection is the native engine's ({_native.load_error()})")

# ---------------------------------------------------------------- core's code as it was (4 (d))

EXTS = core.EXTS
DEP_TREE_DIRS = frozenset({"node_modules", "bower_components", "site-packages"})
DEP_TREE_MARKERS = {
    "venv": (("pyvenv.cfg",), ()),
    ".venv": (("pyvenv.cfg",), ()),
    "env": (("pyvenv.cfg",), ()),
    "vendor": (("modules.txt", "autoload.php", "package.json"), (".dist-info", ".egg-info")),
}
ALWAYS_PRUNE_DIRS = frozenset({".git"})
PYCACHE_DIR = "__pycache__"
VENDOR_CODE = {"go": ".go", "cargo": ".rs"}
_VENDOR_PROBE = 256
SOURCE_SIZE_CAP = 16_000_000
HEADER_SAMPLE_BYTES = 512
DISGUISE_SAMPLE_BYTES = 2048
MANIFEST_NAMES = ("package.json", "binding.gyp")
GYP_EXTS = (".gyp", ".gypi")
PTH_EXT = ".pth"
MPEG_TS_EXTS = (".ts", ".mts", ".m2ts")
APPLE_DOUBLE_MAGIC = (b"\x00\x05\x16\x07", b"\x00\x05\x16\x00")
CONFIG_EXTS = frozenset((
    ".env", ".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".sh", ".bash", ".zsh", ".pem", ".key", ".tfvars",
))
CONFIG_NAMES = frozenset((
    ".env", ".envrc", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".dockercfg",
    "dockerfile", "containerfile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
))
CONFIG_SKIP_NAMES = frozenset((
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "packages.lock.json",
    "pylock.toml",
))
CONFIG_SCAN_CAP = 2_000_000
_OWN_REPORT_RE = __import__("re").compile(r'\A\ufeff?\s*\{\s*"generatedBy"\s*:\s*"lazaret-')
TEST_DIR_NAMES = {"test", "tests", "testing", "__tests__", "spec", "specs", "fixtures",
                  "__fixtures__", "testdata", "test_data", "test-data", "test-fixtures",
                  "unittests", "test cases"}
_TEST_FILE_RE = __import__("re").compile(r"(?:^test_.*\.py|.*_test\.(?:py|go)|.*\.(?:test|spec)\.[cm]?[jt]sx?)$", __import__("re").I)
USE_RISK_SKIP_DIRS = {"example", "examples", "doc", "docs", "demo", "demos", "sample", "samples", "benchmark",
                      "benchmarks", "bench", "__mocks__", "_next", "static", "public"}
STRONG_SEVERITIES = ("BLOCKER", "CRITICAL")
TRUNCATION_RULES = ("SC-TRUNCATED", "SC-MANIFEST-UNPARSEABLE", "SC-UNREAD-CODE")
REDACT_SECRETS = True


def dep_source_lang(ext):
    lang = EXTS.get(ext)
    return lang if lang in ("py", "js", "sql") else None


def _coverage_issue(rule, name, path, msg, why, fix, ref="Maintainability"):
    return {"rule": rule, "name": name, "type": "SMELL", "sev": "INFO",
            "msg": msg, "why": why, "fix": fix, "ref": ref,
            "file": path, "line": 1, "snippet": [], "snipStart": 1}


def symlink_issue(path, target):
    target = _safe_text(target)
    if len(target) > 200:
        target = target[:197] + "..."
    return _coverage_issue(
        "Q-SYMLINK", "Symbolic link (not followed)", path,
        f"Symbolic link {path} -> {target} was not followed; its target was not scanned.",
        "Following links would let a repository pull files from outside the scanned tree "
        "(host credentials, /dev/urandom) into the scan and its reports, or loop forever. "
        "The link target is not part of the tree under review.",
        "If the target belongs to the project, scan it directly.",
        "CWE-59 · Scan coverage")


def unreadable_issue(path, reason):
    return _coverage_issue(
        "Q-UNREADABLE", "Unreadable entry (not scanned)", path,
        f"{path} could not be read ({_safe_text(reason)}); it was not scanned.",
        "An entry the scanner cannot read is invisible to every rule. Special files "
        "(named pipes, sockets, devices) are never opened: reading one can hang or "
        "exhaust the scan.",
        "Fix the permissions (or remove the special file) and re-scan.",
        "Scan coverage")


def config_skipped_issue(path, detail):
    return _coverage_issue(
        "Q-SKIPPED-CONFIG", "Config file not checked (too large)", path,
        f"{path} was not checked for credentials: {_safe_text(detail)}.",
        "Config and data files are read only to look for credentials, and one this large is "
        "data rather than configuration: a credential in it would not be reported.",
        "Keep credentials out of large data files, and real configuration in files of its own.",
        "Scan coverage")


def _skipped_issue(rel, n_files, n_bytes):
    return {
        "rule": "Q-SKIPPED-TREE", "name": "Skipped directory (not scanned)",
        "type": "SMELL", "sev": "INFO",
        "msg": f"Directory {rel} was skipped ({n_files} files, {n_bytes} bytes unread).",
        "why": "Skipped trees are invisible to every rule — the classic hiding places "
               "(dist, build, .git) hold published code and committed-then-deleted "
               "secrets. Generated trees you own are fine to skip on purpose; "
               "unexpected entries here are blind spots.",
        "fix": "Only exclude generated trees you control; remove the exclusion "
               "otherwise so the tree is scanned.",
        "ref": "Maintainability",
        "file": rel, "line": 1, "snippet": [], "snipStart": 1}


def _dep_tree_kind(name, path):
    if name in DEP_TREE_DIRS:
        return True
    if name == "vendor":
        kind = _vendor_kind(path)
        if kind is not None:
            return kind
    markers = DEP_TREE_MARKERS.get(name)
    if markers is None:
        return False
    names, suffixes = markers
    try:
        with os.scandir(path) as it:
            for e in it:
                if e.name in names or (suffixes and e.name.endswith(suffixes)):
                    return True
    except OSError:
        pass
    return False


def _check_pycache(rel_dir, path, parent_names, out):
    try:
        with os.scandir(path) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError as exc:
        out.append(unreadable_issue(_fs_display(rel_dir), exc.strerror or type(exc).__name__))
        return
    for e in entries:
        rel = os.path.join(rel_dir, e.name)
        disp = _fs_display(rel)
        try:
            st = e.stat(follow_symlinks=False)
        except OSError as exc:
            out.append(unreadable_issue(disp, exc.strerror or type(exc).__name__))
            continue
        if _stat.S_ISLNK(st.st_mode) or _is_reparse_point(st):
            out.append(symlink_issue(disp, _readlink(e.path)))
            continue
        if not (_stat.S_ISREG(st.st_mode) and e.name.endswith(".pyc")):
            continue
        try:
            header = _read_prefix(e.path, 16)
        except OSError as exc:
            out.append(unreadable_issue(disp, exc.strerror or str(exc) or type(exc).__name__))
            continue
        module = e.name.split(".", 1)[0]
        has_source = (module + ".py") in parent_names or (module + ".pyw") in parent_names
        out.extend(pyc_issues(disp, header, has_source))


def _collect_file(path, rel, st, in_dep, col):
    name = os.path.basename(rel)
    disp = _fs_display(rel)
    ext = os.path.splitext(name)[1].lower()
    size = st.st_size
    manifest = name in MANIFEST_NAMES or ext in GYP_EXTS
    pth = not manifest and ext == PTH_EXT
    vendor = in_dep if isinstance(in_dep, tuple) else None      # (a vendor tree's kind, its rel)
    lang = (None if manifest or pth else (_vendor_lang(vendor, rel, ext) or dep_source_lang(ext)) if in_dep
            else EXTS.get(ext))
    issues = col["issues"]
    if not manifest and not pth and lang is None:
        # FIX-SPEC 9: every non-source regular file is classified by magic
        # bytes from a header sample (repo mode used to look at a fixed list
        # of extensions only: an ELF named `helper` or `logo.png` passed) —
        # unless its #! line makes it a Node or Python script: then it is
        # source (script_source_lang).
        head = _read_prefix(path, HEADER_SAMPLE_BYTES)
        lang = script_source_lang(head)
        if lang is None:
            bi = classify_binary(disp, head, size, "repo")
            if bi:
                issues.append(bi)
            elif not in_dep and is_config_file(name) and (
                    head.startswith((b"\xff\xfe", b"\xfe\xff")) or not looks_binary(head)):
                _collect_config(path, disp, size, col)          # text (UTF-16 with its BOM too)
            return
    if lang is not None and ext in MPEG_TS_EXTS:
        head = _read_prefix(path, HEADER_SAMPLE_BYTES)
        if _mpeg_ts(head):                  # a video (a camera's .mts), not TypeScript
            bi = classify_binary(disp, head, size, "repo")
            if bi:
                issues.append(bi)
            return
    # FIX-SPEC 9: the size cap applies only to files that would be read whole.
    # Verdict integrity (audit C2/G16): an oversize file is an SC-TRUNCATED
    # finding, never a silent skip, and it is not added to the scanned files.
    if size > SOURCE_SIZE_CAP:
        issues.append(truncated_issue(
            disp, f"{size:,} bytes exceeds the {SOURCE_SIZE_CAP:,}-byte file limit"))
        if lang is not None:             # its first bytes still tell a program (as in the registry)
            try:
                head = _read_prefix(path, DISGUISE_SAMPLE_BYTES)
            except OSError:              # not read: the SC-TRUNCATED stands alone, as before
                head = b""
            disguised = disguised_binary(disp, head)
            if disguised:
                issues.append(disguised)
        return
    data = _read_prefix(path, SOURCE_SIZE_CAP + 1)
    if len(data) > SOURCE_SIZE_CAP:      # grew between the lstat and the read
        issues.append(truncated_issue(
            disp, f"read exceeded the {SOURCE_SIZE_CAP:,}-byte file limit"))
        disguised = disguised_binary(disp, data) if lang is not None else None
        if disguised:
            issues.append(disguised)
        return
    if manifest:
        col["manifests"].append({"path": disp, "dep": bool(in_dep),
                                 "content": normalize_newlines(data.decode("utf-8", "replace"))})
        return
    if pth:                # only the .pth check runs on it (decoded as the registry does)
        col["pth"].append(disp)
        try:
            issues.extend(pth_issues(disp, data.decode("utf-8-sig", "replace")))
        except _native.NativeError as exc:
            issues.append(engine.error_issue(disp, exc))
        return
    if data[:4] in APPLE_DOUBLE_MAGIC:
        bi = classify_binary(disp, data[:HEADER_SAMPLE_BYTES], size, "repo")
        if bi:
            issues.append(bi)
        return
    # read as the registry reads a member (0.1.8): bytes that don't decode to
    # anything text-like are SC-TRUNCATED, not mojibake no rule can read
    text, extra = decode_member(disp, data, lang)
    issues.extend(extra)
    disguised = disguised_binary(disp, data)     # a program under a source file's name (0.1.8)
    if disguised:
        issues.append(disguised)
    entry = {"path": disp, "content": text, "lang": lang, "dep": bool(in_dep)}
    if vendor is not None and lang in ("go", "rs"):
        entry["vendor"] = _fs_display(vendor[1])                # (its module or crate is read whole: _vendored_code)
    col["files"].append(entry)


def _collect_config(path, disp, size, col):
    cap = CONFIG_SCAN_CAP
    if size > cap:
        col["issues"].append(config_skipped_issue(
            disp, f"{size:,} bytes is over the {cap:,}-byte limit for config files"))
        return
    data = _read_prefix(path, cap + 1)
    if len(data) > cap:                  # grew between the lstat and the read
        col["issues"].append(config_skipped_issue(
            disp, f"it grew past the {cap:,}-byte limit for config files while it was read"))
        return
    text = decode_source(data)[0]
    if not own_report(text):          # a report of Lazaret's own is not config
        col["configs"].append({"path": disp, "content": text})


def _collect(root, excludes=(), include_deps=False):
    excludes = set(excludes or ())
    col = {"files": [], "manifests": [], "pth": [], "issues": [], "skipped": [], "configs": []}
    issues = col["issues"]
    seen_dirs = set()
    stack = [("", False)]
    while stack:
        rel_dir, in_dep = stack.pop()
        full_dir = os.path.join(root, rel_dir) if rel_dir else root
        try:
            with os.scandir(full_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
            st_dir = os.stat(full_dir) if not rel_dir else None
        except OSError as exc:
            if not rel_dir:
                raise ScanTargetError(
                    f"cannot read directory {_fs_display(str(root))}: "
                    f"{exc.strerror or type(exc).__name__}") from None
            issues.append(unreadable_issue(_fs_display(rel_dir), exc.strerror or type(exc).__name__))
            continue
        if st_dir is not None and st_dir.st_ino:
            seen_dirs.add((st_dir.st_dev, st_dir.st_ino))
        names = {e.name for e in entries}
        subdirs = []
        for e in entries:
            rel = os.path.join(rel_dir, e.name) if rel_dir else e.name
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as exc:
                issues.append(unreadable_issue(_fs_display(rel), exc.strerror or type(exc).__name__))
                continue
            mode = st.st_mode
            if _stat.S_ISLNK(mode) or (_stat.S_ISDIR(mode) and _is_reparse_point(st)):
                issues.append(symlink_issue(_fs_display(rel), _readlink(e.path)))
            elif _stat.S_ISDIR(mode):
                subdirs.append((e, rel, st))
            elif not _stat.S_ISREG(mode):
                issues.append(unreadable_issue(_fs_display(rel), _special_kind(mode)))
            else:
                try:
                    _collect_file(e.path, rel, st, in_dep, col)
                except OSError as exc:
                    reason = (str(exc) if isinstance(exc, _NotRegularFile)
                              else exc.strerror or type(exc).__name__)
                    issues.append(unreadable_issue(_fs_display(rel), reason))
                except Exception as exc:        # one file must never kill the walk
                    issues.append(engine.error_issue(_fs_display(rel), exc))
        push = []
        for e, rel, st in subdirs:
            name = e.name
            if name in ALWAYS_PRUNE_DIRS or name in excludes:
                _count_skipped_tree(root, e.path, _fs_display(rel), col["skipped"])
                continue
            if name == PYCACHE_DIR:
                try:
                    _check_pycache(rel, e.path, names, issues)
                except Exception as exc:
                    issues.append(engine.error_issue(_fs_display(rel), exc))
                continue
            key = (st.st_dev, st.st_ino)
            if st.st_ino and key in seen_dirs:
                issues.append(unreadable_issue(_fs_display(rel),
                                               "directory already visited (filesystem loop)"))
                continue
            if st.st_ino:
                seen_dirs.add(key)
            dep = in_dep or _dep_tree_kind(name, e.path)
            if dep and not in_dep and not include_deps:
                _count_skipped_tree(root, e.path, _fs_display(rel), col["skipped"])
                continue
            if isinstance(dep, str):
                dep = (dep, rel)                # a Go or cargo vendor tree: its kind and where it is
            push.append((rel, dep))
        stack.extend(reversed(push))       # pop order = sorted, depth-first (like os.walk)
    return col


def _vendor_kind(path):
    try:
        with os.scandir(path) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError:
        return None
    if any(e.name == "modules.txt" for e in entries):
        return "go"
    for e in [e for e in entries if e.is_dir(follow_symlinks=False)][:_VENDOR_PROBE]:
        try:
            st = os.lstat(os.path.join(e.path, ".cargo-checksum.json"))
        except OSError:
            continue
        if _stat.S_ISREG(st.st_mode):
            return "cargo"
    return None


def _vendor_lang(vendor, rel, ext):
    if vendor is None or ext != VENDOR_CODE.get(vendor[0]):
        return None
    below = rel[len(vendor[1]) + 1:].replace(os.sep, "/")
    if vendor[0] == "go":
        return None if never_built("go", below) else "go"
    _crate, _, inside = below.partition("/")
    return None if not inside or never_built("crate", inside) else "rs"


def never_built(kind, rel):
    if kind == "go":
        parts = rel.split("/")
        name = parts[-1]
        return (name[:1] in ("_", ".") or name.lower().endswith("_test.go")
                or any(p in ("testdata", "vendor") for p in parts[:-1]))
    if kind == "crate":
        return rel.split("/", 1)[0] in ("tests", "benches", "examples")
    return False


def is_config_file(name):
    low = name.lower()
    if low in CONFIG_SKIP_NAMES or (low.startswith("pylock.") and low.endswith(".toml")):
        return False
    if (low in CONFIG_NAMES or low.startswith(".env.") or low.startswith("dockerfile.")
            or low.endswith(".dockerfile")):
        return True
    return os.path.splitext(low)[1] in CONFIG_EXTS


def own_report(text):
    return bool(_OWN_REPORT_RE.match(text))


def is_test_path(rel):
    parts = rel.replace("\\", "/").split("/")
    return (any(_is_test_dir(part.lower()) for part in parts[:-1])
            or bool(_TEST_FILE_RE.match(parts[-1])))


def _is_test_dir(name):
    # exact names only: testkit/, testutils/, attestation/ are code, not tests
    return name in TEST_DIR_NAMES


def _not_used_code(rel):
    parts = rel.replace("\\", "/").split("/")
    return is_test_path(rel) or any(part.lower() in USE_RISK_SKIP_DIRS for part in parts[:-1])


def _demote_test_findings(issues, reachable=frozenset()):
    for issue in issues:
        if (issue["rule"].startswith("SC-") and issue["rule"] not in TRUNCATION_RULES
                and issue["sev"] not in STRONG_SEVERITIES + ("INFO",)
                and issue["file"] not in reachable
                and is_test_path(issue["file"])):
            issue["sev"] = "INFO"
            issue["msg"] = issue["msg"].rstrip() + " (in test code: listed, not counted)"


# ---------------------------------------------------------------- generated trees

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 57
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 24
PYC = b"\x55\x0d\x0d\x0a" + b"\x00" * 12               # (a 3.12 magic; flags 0: timestamp-based)
PYC_UNCHECKED = b"\xf3\x0d\x0d\x0a" + b"\x01\x00\x00\x00" + b"\x00" * 8
MTS = (b"\x47" + b"\x00" * 187) * 3


def file_body(rng, name):
    """Content for a file named `name`, chosen to reach each of the collection's answers. Inert."""
    pick = rng.random()
    if name.endswith((".py", ".pyw")):
        return rng.choice([b"x = 1\n", b"# -*- coding: latin-1 -*-\nx = '\xe9'\n", b"\xff\xfe" + "x = 1\n".encode("utf-16-le"),
                           b"\x00\x01\x02" * 300, b"import os\r\nos.getcwd()\r\n", b"#!/usr/bin/env python\nprint(1)\n"])
    if name.endswith((".js", ".ts", ".mjs", ".tsx", ".cjs", ".go", ".rs", ".sql")):
        return rng.choice([b"let a = 1;\n", b"package main\n", b"fn main() {}\n", b"select 1;\n", MTS, ELF + b"x" * 100,
                           b"\x00\x05\x16\x07rest", "const s = 'é\U0001F600';\n".encode()])
    if name.endswith(".mts"):
        return rng.choice([MTS, b"export const a = 1;\n"])
    if name.endswith(".pth"):
        return rng.choice([b"import os\n", b"\xef\xbb\xbfimport sys; exec('x')\n", b"./lib\n"])
    if name in ("package.json",):
        return rng.choice([b'{"name": "a", "scripts": {"postinstall": "node x.js"}}\n', b'{"name": "a"}\r\n', b"\xef\xbb\xbf{}"])
    if name.endswith((".gyp", ".gypi")):
        return b"{'targets': []}\n"
    if name.endswith(".pyc"):
        return rng.choice([PYC, PYC_UNCHECKED, b"\x00\x01"])
    if name.startswith("._"):
        return b"\x00\x05\x16\x07" + b"\x00" * 30
    if pick < 0.2:
        return rng.choice([b"#!/usr/bin/env node\nconsole.log(1)\n", b"#!/bin/sh\necho hi\n", b"#!/usr/bin/python3\nx=1\n"])
    if pick < 0.4:
        return rng.choice([ELF, PNG, b"PK\x03\x04" + b"\x00" * 26, os.urandom(300)])
    if pick < 0.6:
        return rng.choice([b"KEY=value\n", b"\xff\xfe" + "A=1\n".encode("utf-16-le"), b'{"generatedBy": "lazaret-cli-1"}',
                           b"\x00binary config", b"[x]\ny = 2\n"])
    return b"plain text\n"


NAMES = ["a.py", "b.js", "c.ts", "d.mts", "e.go", "f.rs", "g.sql", "h.pth", "package.json", "binding.gyp", "x.gypi",
         "README", "run", "cli", ".env", ".env.local", "Dockerfile", "config.yaml", "settings.json", "id_rsa",
         "package-lock.json", "pylock.dev.toml", "lazaret-report.json", "._a.py", "logo.png", "lib.so", "data.bin",
         "x_test.go", "_skip.go", "main.go", "lib.rs", "tests.rs", "Mixed.PY", "café.py", "a b.js", "pyvenv.cfg",
         "modules.txt", "autoload.php", "foo.dist-info", ".cargo-checksum.json", "Cargo.toml"]
DIRS = ["src", "lib", "node_modules", "venv", ".venv", "env", "vendor", "site-packages", "bower_components", ".git",
        "__pycache__", "dist", "tests", "build", "skipme", "testdata", "crate1", "sub"]


def make_tree(rng, root, depth=0, budget=None):
    """A random tree under `root`; links and named pipes among its entries."""
    budget = budget if budget is not None else [60]
    for name in rng.sample(NAMES, rng.randrange(2, 7)):
        if budget[0] <= 0:
            return
        budget[0] -= 1
        path = os.path.join(root, name)
        if name == "pyvenv.cfg" or name == "modules.txt" or name == ".cargo-checksum.json":
            data = b"x\n"
        elif name.endswith(".dist-info"):
            os.makedirs(path, exist_ok=True)
            continue
        else:
            data = file_body(rng, name)
        with open(path, "wb") as f:
            f.write(data)
    if rng.random() < 0.15:
        os.symlink(rng.choice(["/etc/hostname", "missing", "src", "a.py"]), os.path.join(root, "link" + str(depth)))
    if rng.random() < 0.05 and hasattr(os, "mkfifo"):
        os.mkfifo(os.path.join(root, "pipe"))
    if rng.random() < 0.05:
        with open(os.path.join(root, "big.py"), "wb") as f:
            f.write(b"x = 1\n" * 2000)                      # over the small limit the tests set
    if rng.random() < 0.02:
        with open(os.path.join(root, "huge.yaml"), "wb") as f:
            f.write(b"a: 1\n" * 420_000)                    # over the config limit (2,000,000 bytes)
    if depth >= 3:
        return
    for d in rng.sample(DIRS, rng.randrange(0, 4)):
        path = os.path.join(root, d)
        os.makedirs(path, exist_ok=True)
        if d == "__pycache__":
            for n in rng.sample(["a.cpython-312.pyc", "z.cpython-312.pyc", "lib.cpython-312.pyc", "notes.txt"], 2):
                with open(os.path.join(path, n), "wb") as f:
                    f.write(file_body(rng, n))
            continue
        if d == "vendor" and rng.random() < 0.4:
            crate = os.path.join(path, "crate1")
            os.makedirs(os.path.join(crate, "src"), exist_ok=True)
            os.makedirs(os.path.join(crate, "tests"), exist_ok=True)
            with open(os.path.join(crate, ".cargo-checksum.json"), "w", encoding="utf-8") as f:
                f.write("{}")
            for rel in ("src/lib.rs", "tests/t.rs", "build.rs"):
                with open(os.path.join(crate, rel), "w", encoding="utf-8") as f:
                    f.write("fn main() {}\n")
        make_tree(rng, path, depth + 1, budget)


def ref_collect(root, excludes, deps):
    return _collect(root, excludes, include_deps=deps)


def comparable(col):
    col = copy.deepcopy(col)
    col["manifests"] = [{k: m[k] for k in ("path", "dep", "content")} for m in col["manifests"]]
    return col


class CollectTests(unittest.TestCase):
    def setUp(self):
        self.saved = core.SOURCE_SIZE_CAP
        core.SOURCE_SIZE_CAP = globals()["SOURCE_SIZE_CAP"] = 5000

    def tearDown(self):
        core.SOURCE_SIZE_CAP = globals()["SOURCE_SIZE_CAP"] = self.saved

    def test_the_engines_walk_is_cores(self):
        rng = random.Random(7)
        for k in range(60):
            d = tempfile.mkdtemp(prefix="lazaret-collect-")
            try:
                make_tree(rng, d)
                excludes = rng.choice([(), ("dist",), ("skipme", "sub")])
                deps = rng.random() < 0.5
                with self.subTest(k, deps=deps, excludes=excludes):
                    want = ref_collect(d, excludes, deps)
                    got = core._collect(d, excludes, include_deps=deps)
                    self.assertEqual(comparable(got), comparable(want))
            finally:
                shutil.rmtree(d, ignore_errors=True)

    def test_a_folder_seen_twice_is_a_loop(self):
        # (a bind mount cannot be made here; the engine's answer for a folder the walk has seen, given directly)
        got = _native.call("collect_dir", {"dir": "x", "dep": False, "entries": [["a", "dir", "1:2", True],
                                                                                ["b", "dir", "1:3", False],
                                                                                ["c", "dir", "1:3", False]],
                                           "excludes": [], "includeDeps": False, "windows": False, "answers": {}})
        self.assertEqual([(row[0], row[1]) for row in got["do"]], [(0, "issue"), (1, "walk"), (2, "issue")])
        self.assertEqual(got["seen"], ["1:3"])
        self.assertIn("directory already visited (filesystem loop)", got["do"][0][2][1][4])


class TestPathTests(unittest.TestCase):
    def test_test_paths_are_the_registrys(self):
        from lazaret.registry import repo
        rng = random.Random(3)
        parts = ["tests", "Test", "testing", "testkit", "src", "spec", "__tests__", "test cases", "unittests", "lib",
                 "examples", "docs", "public", "_next", "STATIC", "bench", "app"]
        files = ["test_a.py", "a_test.py", "a_test.go", "a.test.js", "a.spec.tsx", "a.test.mjs", "main.py",
                 "contest.py", "Test_A.PY", "x.SPEC.ts", "attestation.js", "a_test.rs", "tests.rs", "mytests.rs"]
        paths = []
        for _ in range(3000):
            sep = rng.choice(["/", "\\"])
            paths.append(sep.join(rng.sample(parts, rng.randrange(0, 3)) + [rng.choice(files)]))
        for p in paths:
            with self.subTest(p):
                rust = p.lower().replace("\\", "/").rsplit("/", 1)[-1] in ("a_test.rs", "tests.rs")
                self.assertEqual(repo.is_test_path(p), is_test_path(p) or rust)
                self.assertEqual(repo._not_used_code(p), _not_used_code(p) or rust)

    def test_demotion_is_the_registrys(self):
        from lazaret.registry import repo
        rng = random.Random(4)
        for k in range(500):
            issues = [{"rule": rng.choice(["SC-B64", "SC-TRUNCATED", "SC-BINARY", "S-SECRET", "S-TOKEN", "S-EVAL-JS"]),
                       "sev": rng.choice(["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]),
                       "file": rng.choice(["tests/a.js", "src/a.js", "lib/a.test.js", "test/fixtures/x.bin"]),
                       "msg": rng.choice(["m", "m ", "m\n"])} for _ in range(rng.randrange(1, 6))]
            reachable = frozenset(rng.sample(["tests/a.js", "src/a.js"], rng.randrange(0, 2)))
            mine, theirs = copy.deepcopy(issues), copy.deepcopy(issues)
            repo._demote_test_findings(mine, reachable)
            _demote_test_findings(theirs, reachable)
            # (0.1.9: a secret in test code is listed too, as an SC-* finding there is)
            for i in theirs:
                if (i["rule"] in ("S-SECRET", "S-TOKEN") and i["sev"] != "INFO" and i["file"] not in reachable
                        and is_test_path(i["file"])):
                    i["sev"], i["msg"] = "INFO", i["msg"].rstrip() + " (in test code: listed, not counted)"
            with self.subTest(k):
                self.assertEqual(mine, theirs)


NODE_WALK = """
import { pathToFileURL } from "node:url";
const fs = await import(pathToFileURL(process.argv[1]).href);
const [root, exclude, deps, cap] = JSON.parse(process.argv[2]);
const col = fs.collectFiles(root, { includeDeps: deps, exclude, maxFileBytes: cap });
process.stdout.write(JSON.stringify(col));
"""


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class NpmTests(unittest.TestCase):
    def test_the_npm_packages_walk_is_the_python_packages(self):
        rng = random.Random(8)
        saved = core.SOURCE_SIZE_CAP
        core.SOURCE_SIZE_CAP = 5000
        try:
            for k in range(25):
                d = tempfile.mkdtemp(prefix="lazaret-collect-npm-")
                try:
                    make_tree(rng, d)
                    excludes = rng.choice([[], ["dist"], ["skipme", "sub"]])
                    deps = rng.random() < 0.5
                    p = subprocess.run([NPM_READY, "--input-type=module", "-e", NODE_WALK,
                                        os.path.join(_support.REPO_ROOT, "js", "src", "lib", "fs.js"),
                                        json.dumps([d, excludes, deps, 5000])], capture_output=True, encoding="utf-8",
                                       errors="surrogatepass", timeout=120)
                    self.assertEqual(p.returncode, 0, p.stderr[-2000:])
                    npm = json.loads(p.stdout)
                    col = core._collect(d, excludes, include_deps=deps)
                    with self.subTest(k, deps=deps):
                        self.assertEqual(npm["files"], json.loads(json.dumps(col["files"])))
                        self.assertEqual([{k2: m[k2] for k2 in ("path", "dep", "content")} for m in npm["manifests"]],
                                         json.loads(json.dumps(col["manifests"])))
                        self.assertEqual(npm["configs"], json.loads(json.dumps(col["configs"])))
                        self.assertEqual(npm["pth"], col["pth"])
                        self.assertEqual(npm["binaryIssues"], json.loads(json.dumps(col["issues"])))
                        self.assertEqual(npm["skippedIssues"], json.loads(json.dumps(core.skipped_tree_issues(col["skipped"]))))
                finally:
                    shutil.rmtree(d, ignore_errors=True)
        finally:
            core.SOURCE_SIZE_CAP = saved


if __name__ == "__main__":
    unittest.main()
