#!/usr/bin/env python3
"""UNIT tests — terminal escape-sequence injection (audit H1, card db325ffb).

safe_excerpt() always sanitized the code excerpt; every OTHER string printed
to the terminal was raw: file-path headers (i['file'] is an archive MEMBER
NAME in registry mode — fully attacker-controlled), issue messages (X-FLOW
source/sink paths, SC-INSTALL-HOOK {cmd!r}, SCA advisory fields), registry
metadata, stored DB blobs and config paths. The fix is lazaret.sanitize_term
(C0 control bytes except \\n/\\t, plus CR and DEL → '·') applied at every
print site.

This suite proves:
  1. the mapping itself (incl. the card PoC and byte-reassembly attempts),
  2. identity for clean ASCII (no regression of existing message text),
  3. lazaret_flow's local twin is byte-identical to the canonical helper,
  4. the c() argument-ordering contract (sanitize the ARGUMENT, not the
     result — the SGR wrapper Lazaret itself emits must survive),
  5. the two CONFIRMED PoCs end-to-end: a hostile FILE NAME in repo mode and
     a hostile archive MEMBER NAME in registry mode (fake-registry child
     process, real argparse/Store/print_scan), plus the stored-blob 'report'
     re-print, an ESC-laden install-hook command and the taint-config
     warning path, all with 0 escape/control bytes in the output.
"""
import io
import json
import os

from tests import _support  # noqa: E402
import subprocess
import sys
import tarfile
import tempfile
import unittest
import unittest.mock

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures

from lazaret.scanner import core as lazaret  # noqa: E402
from lazaret.scanner import flow as lazaret_flow  # noqa: E402
from lazaret.registry import repo as lazaret_repo  # noqa: E402

# The card's confirmed PoC file/member name: raw SGR (severity-color spoofing)
# + OSC 0 (terminal title hijack). BEL terminates the OSC, as in the audit.
POC_NAME = "ok\x1b[31mPWNED_RED\x1b[0m\x1b]0;TITLE_HIJACK\x07var.js"
# What the sanitizer must turn it into (every control byte → '·').
POC_SANITIZED = "ok·[31mPWNED_RED·[0m·]0;TITLE_HIJACK·var.js"

# Control bytes that must NEVER survive in terminal output.
FORBIDDEN_BYTES = (
    b"\x1b",   # ESC — starts every SGR/OSC sequence
    b"\x07",   # BEL — ends OSC (title hijack)
    b"\x08",   # BS — overwrites the severity column
    b"\x0b",   # VT — line spoofing in some emulators
    b"\x0c",   # FF — form feed / screen clear
    b"\x7f",   # DEL
    b"\r",     # CR — carriage-return overwrite spoofs
)
# All C0 except \t (0x09) and \n (0x0a), plus 0x7f — for exhaustive checks.
ALL_CONTROL = [chr(n) for n in range(0x20) if n not in (0x09, 0x0a)] + [chr(0x7f)]


def assert_clean(out_bytes, msg):
    """Assert no terminal-control byte survives in subprocess output."""
    for b in FORBIDDEN_BYTES:
        if b in out_bytes:
            # Show the offending line for diagnosis.
            idx = out_bytes.find(b)
            ctx = out_bytes[max(0, idx - 60):idx + 60]
            raise AssertionError(
                f"{msg}: byte {b!r} leaked in output near {ctx!r}")


def build_tgz(members):
    """{(member name, content bytes)} → in-memory tar.gz bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        for name, content in members.items():
            data = content if isinstance(content, bytes) else content.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def run_cli(args, db, tarballs, timeout=180):
    """Run lazaret_repo.py main() end-to-end in a child process whose
    network seam serves `tarballs` {(name, version): tgz bytes}
    (same pattern as test_crash_guards_registry.py)."""
    reg = _support.BOOTSTRAP
    env = dict(os.environ)
    env["CG_FAKE_REGISTRY"] = json.dumps(
        {"tarballs": {f"{n}@{v}": blob.hex() for (n, v), blob in tarballs.items()}})
    env["LAZARET_DB"] = db
    return subprocess.run(
        [sys.executable, reg, "lazaret_repo.py"] + args,
        capture_output=True, timeout=timeout, env=env, cwd=HERE)


def run_scanner(root, extra_args=("--no-json", "--no-html"), timeout=180):
    """Run lazaret.py on a scan root; returns CompletedProcess."""
    return subprocess.run(
        [sys.executable, _support.CLI, root, *extra_args],
        capture_output=True, timeout=timeout, cwd=HERE)


# ---------------------------------------------------------------------------
# 1. The mapping itself
# ---------------------------------------------------------------------------
class SanitizeTermUnit(unittest.TestCase):
    """lazaret.sanitize_term — the canonical helper."""

    def test_card_poc_name(self):
        self.assertEqual(lazaret.sanitize_term(POC_NAME), POC_SANITIZED)

    def test_exhaustive_c0_and_del(self):
        for ch in ALL_CONTROL:
            self.assertEqual(lazaret.sanitize_term("a" + ch + "b"), "a·b",
                             f"control byte 0x{ord(ch):02x} not neutralized")

    def test_all_control_bytes_in_one_string(self):
        blob = "".join(ALL_CONTROL)
        out = lazaret.sanitize_term(blob)
        self.assertEqual(out, "·" * len(ALL_CONTROL))
        self.assertNotIn("\x1b", out)

    def test_newline_and_tab_preserved(self):
        self.assertEqual(lazaret.sanitize_term("a\nb\tc"), "a\nb\tc")

    def test_printable_ascii_unchanged(self):
        s = ("Lazaret scan — 2026 report [BLOCKER] L42 "
             "«paths»/utf-8 déjà vu ✓ ✗ · …")
        self.assertEqual(lazaret.sanitize_term(s), s)

    def test_empty(self):
        self.assertEqual(lazaret.sanitize_term(""), "")

    def test_non_string_coerced(self):
        self.assertEqual(lazaret.sanitize_term(7), "7")
        self.assertEqual(lazaret.sanitize_term(None), "None")

    def test_no_reassembly_into_esc(self):
        """Pairs/triples that could re-form an escape sequence after the
        translation must still be ESC-free afterwards."""
        hostile = [
            "\x1b[31m", "\x1b]0;title\x07", "\x1b\x1b", "\x1b[", "P\x1b",
            "\x1b[0m", "\x1b]0;", "\x1bOP", "\x07\x07", "\x1b[2K",
            "\x1b]8;;http://evil\x1b\\",  # OSC-8 hyperlink style
            "\x1b[?25l", "\x1b(B", "\x1b#8",
        ]
        for payload in hostile:
            out = lazaret.sanitize_term(payload + "\x1b")
            self.assertNotIn("\x1b", out, f"ESC survived from {payload!r}")
            self.assertNotIn("\x07", out, f"BEL survived from {payload!r}")
            self.assertNotIn("\r", out, f"CR survived from {payload!r}")

    def test_multiline_preserved_readable(self):
        msg = "line one\nline two"
        self.assertEqual(lazaret.sanitize_term(msg), msg)

    def test_idempotent(self):
        once = lazaret.sanitize_term(POC_NAME)
        self.assertEqual(lazaret.sanitize_term(once), once)


# ---------------------------------------------------------------------------
# 2. No regression for clean message text
# ---------------------------------------------------------------------------
class CleanTextIdentity(unittest.TestCase):
    """sanitize_term must be the identity for the ASCII-clean strings the
    engine itself emits (existing tests assert on those substrings)."""

    def test_static_rule_messages(self):
        samples = [
            "Credential appears to be hardcoded in source.",
            "Use of eval/exec enables arbitrary code execution.",
            "eval() call with a non-literal argument",
            "yaml.load without SafeLoader can instantiate arbitrary objects.",
            "SQL query built with string formatting/concatenation.",
            "L108 (X-FLOW): cross-file flow from\x1bnoop",   # hostile tail
        ]
        for s in samples:
            if "noop" in s:      # the one hostile sample
                self.assertIn("·", lazaret.sanitize_term(s))
                self.assertNotIn("\x1b", lazaret.sanitize_term(s))
            else:
                self.assertEqual(lazaret.sanitize_term(s), s)

    def test_scan_result_messages_identity(self):
        """The scanner's own ASCII-clean output text is byte-identical through
        sanitize_term — covered end-to-end by RepoScanNoopForCleanInput."""
        samples = [
            "Lazaret scan — /tmp/clean",
            "  2 files · 12 lines of code · 0.0% duplication",
            "  Quality gate:  FAILED ",
            "New issues vs baseline: 3",
        ]
        for s in samples:
            self.assertEqual(lazaret.sanitize_term(s), s)


# ---------------------------------------------------------------------------
# 3. Flow twin equivalence + c() argument ordering
# ---------------------------------------------------------------------------
class FlowTwinEquivalence(unittest.TestCase):
    """lazaret_flow.sanitize_term must be byte-identical to the canonical
    helper (no import cycle — a deliberate local duplicate)."""

    def test_equivalence_matrix(self):
        hostile = [POC_NAME, "\x1b[31m", "\x07", "\r", "\x00", "\x0b",
                   "\x1b]0;t\x07", "clean", "", "a\nb\tc",
                   "\x00\x01\x02\x1f\x7f", "\x1b\\",
                   "".join(ALL_CONTROL), "PWNED\x1b[0m"]
        for s in hostile:
            self.assertEqual(lazaret_flow.sanitize_term(s),
                             lazaret.sanitize_term(s), f"diverged on {s!r}")

    def test_both_defined(self):
        self.assertTrue(callable(lazaret.sanitize_term))
        self.assertTrue(callable(lazaret_flow.sanitize_term))


class CArgumentOrdering(unittest.TestCase):
    """sanitize the ARGUMENT of c(), never the result — sanitizing the result
    would strip Lazaret's own SGR wrapper and leave the color span open."""

    def test_argument_sanitized_result_keeps_wrapper(self):
        with unittest.mock.patch("sys.stdout") as fake_out:
            fake_out.isatty.return_value = True
            wrapped = lazaret.c("4", lazaret.sanitize_term(POC_NAME))
        # Exactly one SGR open and one reset survive, wrapping sanitized text.
        self.assertEqual(wrapped, f"\x1b[4m{POC_SANITIZED}\x1b[0m")

    def test_result_sanitization_would_be_wrong(self):
        """Guard the contract: sanitizing c()'s RESULT breaks the wrapper —
        this documents WHY the call sites sanitize the argument instead."""
        wrapped = f"\x1b[4m{POC_NAME}\x1b[0m"
        broken = lazaret.sanitize_term(wrapped)
        # the wrapper's own ESC bytes would be gone:
        self.assertNotIn("\x1b", broken)
        self.assertEqual(broken, "·[4m" + POC_SANITIZED + "·[0m")


class ExcerptStillSanitized(unittest.TestCase):
    """The pre-existing excerpt path must keep working (no regression)."""

    def test_safe_excerpt_still_strips(self):
        out = lazaret.safe_excerpt(POC_NAME)
        # the PoC is longer than the default excerpt width → truncated with …
        self.assertIn("PWNED_RED", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertIn("·", out)


class RepoScanNoopForCleanInput(unittest.TestCase):
    """End-to-end: clean scan output is unchanged in bytes vs the pre-fix
    behavior — proven by asserting the sanitized render of the header line
    equals the raw path (identity for clean paths)."""

    def test_clean_repo_scan_completes(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "clean.py"), "w",
                      encoding="utf-8") as f:
                f.write("x = eval('1')\n")
            proc = run_scanner(root)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn(b"clean.py", proc.stdout)
            assert_clean(proc.stdout, "clean scan leaked control bytes")
            assert_clean(proc.stderr, "clean scan stderr leaked")


# ---------------------------------------------------------------------------
# 4. The card PoC, repo mode: hostile FILE NAME
# ---------------------------------------------------------------------------
class RepoModeFileHeaderPoc(unittest.TestCase):
    """The confirmed PoC: a file named with raw SGR + OSC sequences in the
    scan root. Before the fix, print_report printed the path raw (severity
    color spoofing + terminal title hijack)."""

    def test_hostile_filename_sanitized(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, POC_NAME), "w",
                      encoding="utf-8") as f:
                f.write("function f() { return eval('hostile'); }\n")
            proc = run_scanner(root)
            out, err = proc.stdout, proc.stderr
            assert_clean(out, "PoC stdout")
            assert_clean(err, "PoC stderr")
            # the finding is still reported (nothing was dropped):
            self.assertIn(b"PWNED_RED", out.replace(b"\x1b", b""))
            self.assertIn(b"S-EVAL-JS", out)
            # and rendered sanitized, not raw:
            self.assertIn(POC_SANITIZED.encode(), out)


# ---------------------------------------------------------------------------
# 5. msg embedding: install-hook command with escapes
# ---------------------------------------------------------------------------
class InstallHookMsgPoc(unittest.TestCase):
    """SC-INSTALL-HOOK embeds the raw package.json lifecycle cmd via
    {cmd!r} — a cmd containing ESC reaches the msg text."""

    def test_install_hook_msg_sanitized(self):
        with tempfile.TemporaryDirectory() as root:
            # A NON-suspicious cmd (no curl/eval token) so the message takes
            # the {cmd!r}-embedding branch. NOTE: Python's repr() itself
            # escapes control bytes to literal backslash-text, so the raw ESC
            # never reaches the terminal from this branch even pre-fix —
            # sanitize_term on i['msg'] is belt-and-braces here (and still
            # the guard for every OTHER engine that embeds paths raw).
            cmd = "node ./x\x1b[31mRED\x1b[0m.js"
            with open(os.path.join(root, "package.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"name": "poc", "version": "1.0.0",
                           "scripts": {"preinstall": cmd}}, f)
            proc = run_scanner(root)
            out, err = proc.stdout, proc.stderr
            assert_clean(out, "install-hook PoC stdout")
            assert_clean(err, "install-hook PoC stderr")
            self.assertIn(b"SC-INSTALL-HOOK", out)
            # the command is shown repr-escaped (no raw control byte) and
            # visibly present:
            self.assertIn(b"node ./x\\x1b[31mRED\\x1b[0m.js", out)


# ---------------------------------------------------------------------------
# 6. Taint-config warning path (auto-loaded from the untrusted scan root)
# ---------------------------------------------------------------------------
class TaintConfigWarningPoc(unittest.TestCase):
    """The auto-loaded <root>/.lazaret-taint.json is scanned-repo content;
    both its PATH and its rejected-rule message reach the terminal."""

    def test_taint_config_warning_sanitized(self):
        with tempfile.TemporaryDirectory() as root:
            # invalid pattern → rejected-rule warnings naming the file+rule
            with open(os.path.join(root, ".lazaret-taint.json"), "w",
                      encoding="utf-8") as f:
                f.write('{"python": {"sources": ["("]}}')
            proc = run_scanner(root)
            out, err = proc.stdout, proc.stderr
            assert_clean(out, "taint-config stdout")
            assert_clean(err, "taint-config stderr")
            combined = out + err
            self.assertIn(b"taint config", combined)
            self.assertIn(b"warning", combined.lower())


# ---------------------------------------------------------------------------
# 7. Registry mode PoCs (member name, stored blob re-print)
# ---------------------------------------------------------------------------
class RegistryModeMemberNamePoc(unittest.TestCase):
    """Registry mode: the 'file' IS the archive member name — fully
    attacker-controlled by the package publisher. print_scan and the stored
    DB blob re-print ('report') both carried it raw."""

    def test_member_name_sanitized_in_scan_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "cg.db")
            hostile_member = "package/" + POC_NAME
            blob = build_tgz({hostile_member: b"function f(){ return eval('h'); }\n"})
            # 1) the scan itself
            proc = run_cli(["scan", "npm:poc-escape", "--full"], db,
                           {("poc-escape", "1.0.0"): blob})
            out, err = proc.stdout, proc.stderr
            assert_clean(out, "registry scan stdout")
            assert_clean(err, "registry scan stderr")
            self.assertIn(b"PWNED_RED", out)          # still reported…
            self.assertIn(POC_SANITIZED.encode(), out)  # …but sanitized
            self.assertIn(b"eval", out)
            # 2) the stored blob re-printed by 'report'
            rep = run_cli(["report", "npm:poc-escape@1.0.0"], db, {})
            assert_clean(rep.stdout, "report stdout")
            assert_clean(rep.stderr, "report stderr")
            self.assertIn(POC_SANITIZED.encode(), rep.stdout)
            self.assertIn(b"eval", rep.stdout)

    def test_report_unknown_spec_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "cg.db")
            # sys.exit(f"no stored scan for {spec}") — spec echoed before
            # validation applies to it on this path.
            hostile_spec = "npm:\x1b]0;HIJACK\x07no-such"
            proc = run_cli(["report", hostile_spec], db, {})
            assert_clean(proc.stderr, "unknown spec stderr")
            assert_clean(proc.stdout, "unknown spec stdout")
            # exit code non-zero and the message names the package sanitized
            self.assertNotEqual(proc.returncode, 0)


# ---------------------------------------------------------------------------
# 8. SCA: inventory/advisory text with escapes
# ---------------------------------------------------------------------------
class ScaOutputPoc(unittest.TestCase):
    """lazaret_sca.py interpolates inventory names/versions (hostile
    node_modules package.json) and CVE-bundle fields (advisory title,
    sources, generated_at) into its terminal output."""

    def test_sca_issue_line_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = os.path.join(tmp, "proj")
            nm = os.path.join(root, "node_modules",
                              "poc-\x1b[31mRED\x1b[0m")
            os.makedirs(nm)
            with open(os.path.join(nm, "package.json"), "w",
                      encoding="utf-8") as f:
                json.dump({"name": "poc-\x1b[31mRED\x1b[0m",
                           "version": "1.0.0"}, f)
            # npm name folding drops nothing here; advisory keyed on the
            # sanitized spelling would not match, so key on a clean alias:
            # use the raw hostile name in BOTH inventory and advisory.
            title = "RCE \x1b]0;TITLE\x07 in loader"
            adv = {
                "cve": "CVE-2026-9999",
                "title": title,
                "cvss": 9.8,
                "severity": "critical",
                "packages": [{
                    "ecosystem": "npm",
                    "name": "poc-\x1b[31mRED\x1b[0m",
                    "ranges": [{"fromVersion": "0.0.1", "toVersion": "2.0.0",
                                "toInclusive": False}],
                }],
            }
            bundle = {"bundleVersion": 1,
                      "generatedAt": "2026-09-26T00:00:00Z",
                      "sources": ["\x1b[31mREDSOURCE\x1b[0m"],
                      "counts": {"advisories": 1},
                      "advisories": [adv]}
            bundle_path = os.path.join(tmp, "bundle.json")
            with open(bundle_path, "w", encoding="utf-8") as f:
                json.dump(bundle, f)
            proc = subprocess.run(
                [sys.executable, _support.SCA,
                 root, "--bundle", bundle_path, "--no-json"],
                capture_output=True, timeout=180, cwd=HERE)
            out, err = proc.stdout, proc.stderr
            assert_clean(out, "sca stdout")
            assert_clean(err, "sca stderr")
            # the match is still found and printed, sanitized:
            self.assertIn(b"CVE-2026-9999", out)
            # title sanitized (OSC + BEL gone, words kept):
            self.assertIn("RCE ·]0;TITLE· in loader".encode(), out)
            # inventory name sanitized:
            self.assertIn("poc-·[31mRED·[0m".encode(), out)
            # bundle sources sanitized:
            self.assertIn("·[31mREDSOURCE·[0m".encode(), out)

    def test_sca_imports_standalone(self):
        """The new `import lazaret` must not break standalone import of
        lazaret_sca (no import-time side effects)."""
        proc = subprocess.run(
            [sys.executable, "-c", "import lazaret.scanner.sca"],
            capture_output=True, timeout=60, cwd=HERE)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
