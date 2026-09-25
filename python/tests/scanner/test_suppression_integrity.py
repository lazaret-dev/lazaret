"""Verdict-integrity tests (audit C2/H6 = G1/G2/G16).

Scanned code must not be able to produce a clean verdict for itself:
  1. suppression markers honored only in real comments (never inside string
     literals), never for SC-*/X-* rules and never in dependency mode;
  2. SECRET/S-CRED skip regexes word-bounded (no bare `test` blinding);
  3. archive scanning uses real decompressed byte counts and emits a signal
     whenever scanning is cut short; the verdict cache is keyed on the engine
     version that produced the stored scan.

Run:  python3 -m unittest test_suppression_integrity -v   (from lazaret/)
"""
import io
import os

from tests import _support  # noqa: E402
import re
import struct
import sys
import tarfile
import unittest
import zipfile

HERE = _support.FIXTURES   # fixture trees and demo inputs live in tests/fixtures

from lazaret.scanner import core as lazaret                      # noqa: E402
from lazaret.registry import repo as cr           # noqa: E402


HIGH_ENTROPY = "z9vKq2LmT4pR8wXy3Qa1B"   # >4.0 bits/char after filters


class SuppressionMaskTests(unittest.TestCase):
    """A marker only counts when at least one char of it is outside every
    string literal on the line."""

    def test_mask_basics(self):
        line = 'os.system("rm -rf / -- nosec")'
        mask = lazaret.string_literal_mask(line, "py")
        lit = line.index('"') + 1          # first masked char is after the quote
        end = line.rindex('"')             # closing quote itself is unmasked
        for k in range(lit, end):
            self.assertTrue(mask[k], f"char {k} should be masked: {line[k]!r}")
        for k in list(range(0, lit - 1)) + [end, len(line) - 1]:
            self.assertFalse(mask[k])

    def test_mask_backtick_js_only(self):
        line = "x = `payload -- nosec`"
        js_mask = lazaret.string_literal_mask(line, "js")
        start = line.index("`") + 1
        end = line.rindex("`")
        self.assertTrue(all(js_mask[k] for k in range(start, end)))
        # for py the backtick is not a quote: the marker is unmasked → real
        py_mask = lazaret.string_literal_mask(line, "py")
        m = re.search(lazaret.SUPPRESS_RE, line)
        self.assertFalse(all(py_mask[k] for k in range(m.start(), m.end())))

    def test_mask_escaped_quote(self):
        line = r'"a \" b -- nosec"'
        mask = lazaret.string_literal_mask(line, "py")
        m = lazaret.SUPPRESS_RE.search(line)
        self.assertTrue(m)
        self.assertTrue(all(mask[k] for k in range(m.start(), m.end())))

    def test_marker_in_string_not_found(self):
        self.assertIsNone(lazaret.marker_in_comment(
            'os.system("rm -rf / -- nosec")', "py"))

    def test_marker_in_real_comment_found(self):
        m = lazaret.marker_in_comment("os.system(cmd)  # nosec", "py")
        self.assertIsNotNone(m)

    def test_marker_fully_in_string_after_close_not_honored(self):
        # `# nos"ec` — the marker must not be reconstructed across quotes
        self.assertIsNone(lazaret.marker_in_comment('x = 1 # nos"ec', "py"))

    def test_marker_split_across_quote_states(self):
        # the `// nosec` STARTS inside the string: chars inside → masked;
        # even if the span leaks past the closing quote it is still honored
        # only if an UNMASKED char exists in the span (fail-open to finding)
        line = 'x = "a // nosec" + y'
        m = lazaret.marker_in_comment(line, "js")
        # the whole marker is inside the string → no suppression
        self.assertIsNone(m)

    def test_trailing_real_comment_marker(self):
        line = 'os.system(cmd)  # nosec: S-OSCMD-PY'
        m = lazaret.marker_in_comment(line, "py")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "S-OSCMD-PY")


class IsSuppressedTests(unittest.TestCase):
    def _issue(self, rule, line_no, lines=None):
        return {"rule": rule, "line": line_no, "lines": lines or ["x = 1 # nosec", ""]}

    def test_sc_rules_never_suppressible(self):
        issue = {"rule": "SC-B64", "line": 1}
        self.assertFalse(lazaret.is_suppressed(issue, ["x = 1 # nosec", ""]))

    def test_x_rules_never_suppressible(self):
        issue = {"rule": "X-SQL", "line": 1}
        self.assertFalse(lazaret.is_suppressed(issue, ["x = 1 # nosec", ""]))

    def test_dep_mode_never_suppressible(self):
        issue = {"rule": "S-OSCMD-PY", "line": 1}
        self.assertTrue(lazaret.is_suppressed(issue, ["x = 1 # nosec", ""]))
        self.assertFalse(
            lazaret.is_suppressed(issue, ["x = 1 # nosec", ""], dep=True))

    def test_real_comment_still_suppresses(self):
        issue = {"rule": "S-OSCMD-PY", "line": 1}
        self.assertTrue(lazaret.is_suppressed(issue, ["os.system(cmd) # nosec", ""]))

    def test_string_marker_does_not_suppress(self):
        issue = {"rule": "S-OSCMD-PY", "line": 2}
        lines = ["", 'os.system("rm -rf / -- nosec")']
        self.assertFalse(lazaret.is_suppressed(issue, lines, lang="py"))

    def test_prev_line_standalone_comment_still_suppresses(self):
        issue = {"rule": "S-OSCMD-PY", "line": 2}
        lines = ["# nosec", "os.system(cmd)"]
        self.assertTrue(lazaret.is_suppressed(issue, lines))

    def test_prev_line_code_not_comment_does_not_suppress(self):
        issue = {"rule": "S-OSCMD-PY", "line": 2}
        lines = ["x = 1 -- nosec", "os.system(cmd)"]
        # not a standalone # / // comment AND the marker is SQL-style `--` in py:
        # either way it must not suppress
        self.assertFalse(lazaret.is_suppressed(issue, lines, lang="py"))

    def test_lang_backtick_marker_suppression_in_js(self):
        issue = {"rule": "Q-FN-CX", "line": 1}
        self.assertFalse(lazaret.is_suppressed(
            issue, ["`code // nosec`"]))


class ScanFilePoCTests(unittest.TestCase):
    """The audit's executed PoCs, as regressions."""

    def test_os_system_nosec_in_string_flagged(self):
        issues = lazaret.scan_file(
            "poc.py", 'import os\nos.system("rm -rf / -- nosec")\n', "py")
        rules = {i["rule"] for i in issues}
        self.assertIn("S-OSCMD-PY", rules)

    def test_dep_mode_nosec_comment_cannot_clear_implant(self):
        # `// nosec` on a decode-execute line in a vendored dependency
        issues = lazaret.scan_file(
            "poc.js", "eval(atob(P)) // nosec\n", "js", dep=True)
        rules = {i["rule"] for i in issues}
        self.assertIn("SC-EVAL-DECODE", rules)

    def test_dep_mode_nosec_in_string_cannot_clear_implant(self):
        issues = lazaret.scan_file(
            "poc.js", 'eval(atob("// nosec"))\n', "js", dep=True)
        rules = {i["rule"] for i in issues}
        self.assertIn("SC-EVAL-DECODE", rules)

    def test_hexstr_in_dep_with_marker(self):
        src = "var s = \"\\x48\\x65\\x6c\\x6c\\x6f\\x2c\\x20\\x77\\x6f\\x72\\x6c\\x64\" // nosec\n"
        issues = lazaret.scan_file("p.js", src, "js", dep=True)
        self.assertIn("SC-HEXSTR", {i["rule"] for i in issues})

    def test_py_backslash_x_blob_in_dep_not_suppressible(self):
        src = "s = \"\\x48\\x65\\x6c\\x6c\\x6f\\x20\\x77\\x6f\\x72\\x6c\\x64\"  # nosec\n"
        issues = lazaret.scan_file("p.py", src, "py", dep=True)
        self.assertIn("SC-HEXSTR", {i["rule"] for i in issues})

    def test_sql_line_marker_in_comment_suppresses_normal_rule(self):
        # control: benign suppression still functional on sql
        issues = lazaret.scan_file(
            "a.sql", "GRANT ALL ON t TO PUBLIC; -- nosec\n", "sql")
        self.assertEqual({i["rule"] for i in issues}, set())

    def test_full_mode_comment_still_suppresses_secret(self):
        # control: an explicit reviewer nosec on a false-positive line
        src = f"password = \"{HIGH_ENTROPY}\"  # nosec: S-SECRET\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertNotIn("S-SECRET", {i["rule"] for i in issues})

    def test_string_marker_does_not_clear_secret(self):
        src = f"password = \"{HIGH_ENTROPY} -- nosec\"\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertIn("S-SECRET", {i["rule"] for i in issues})


class GateVerdictTests(unittest.TestCase):
    """The PoC end-to-end: finding + gate FAILED, not clean/PASSED."""

    def test_nosec_string_poc_fails_gate(self):
        import shutil
        import tempfile
        root = tempfile.mkdtemp(prefix="cg-sup-")
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        with open(os.path.join(root, "poc.py"), "w", encoding="utf-8") as fh:
            fh.write('import os\nos.system("rm -rf / -- nosec")\n')
        files, manifests, binary_issues = lazaret.collect_files(root, [])
        issues = list(binary_issues)
        for f in files:
            issues.extend(lazaret.scan_file(
                f["path"], f["content"], f["lang"], dep=f.get("dep", False)))
        res = lazaret.build_result(root, files, issues)
        self.assertFalse(res["pass"])
        self.assertIn("S-OSCMD-PY", {i["rule"] for i in res["issues"]})


class SecretSkipTests(unittest.TestCase):
    def test_word_test_no_longer_blinds_entropy(self):
        # contains the bare word `test` in a comment — still flagged
        src = f"token = \"{HIGH_ENTROPY}\" # test fixtures only\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertIn("S-ENTROPY", {i["rule"] for i in issues})

    def test_substring_attested_no_longer_blinds(self):
        src = f"token = \"{HIGH_ENTROPY}\"  # attested latest\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertIn("S-ENTROPY", {i["rule"] for i in issues})

    def test_env_lines_still_skipped(self):
        src = "token = os.environ['API_KEY']\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertNotIn("S-ENTROPY", {i["rule"] for i in issues})

    def test_placeholder_word_still_skipped(self):
        src = "password = \"placeholder\"\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertNotIn("S-SECRET", {i["rule"] for i in issues})

    def test_real_secret_with_plural_examples_word_on_line(self):
        # `examples` is NOT the word `example` — no skip, the credential fires
        # (word boundary is the fix; bare `example` was a substring match that
        # consumed `examples-deployed` too).
        src = f"password = \"{HIGH_ENTROPY}\"  # examples deployment\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertIn("S-SECRET", {i["rule"] for i in issues})

    def test_substring_latest_not_a_word_match(self):
        # `latest` contains no SECRET_SKIP token at all (old regexes had bare
        # `test`): a real credential must be flagged (here via S-SECRET).
        src = f"api_key = \"{HIGH_ENTROPY}\"  # latest key\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertIn("S-SECRET", {i["rule"] for i in issues})

    def test_s_secret_angle_bracket_no_longer_skips(self):
        # `<...>` used to skip the whole line — a real secret now flagged
        src = f"password = \"{HIGH_ENTROPY}\"  # <production>\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertIn("S-SECRET", {i["rule"] for i in issues})


class SecretRuleSkipWordBoundary(unittest.TestCase):
    """S-SECRET / SQL-CRED rule-level skip regexes."""

    def test_s_secret_line_with_angle_placeholder_still_fires(self):
        src = "password = \"Sup3rS3cret!\"\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertIn("S-SECRET", {i["rule"] for i in issues})

    def test_s_secret_placeholder_word_still_skips(self):
        src = "password = \"placeholder-value-1234\"\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertNotIn("S-SECRET", {i["rule"] for i in issues})

    def test_s_secret_import_line_still_skips(self):
        src = "from app import password\n"
        issues = lazaret.scan_file("a.py", src, "py")
        self.assertNotIn("S-SECRET", {i["rule"] for i in issues})

    def test_sql_cred_flagged_when_no_noise_words(self):
        issues = lazaret.scan_file(
            "a.sql", "CREATE USER u IDENTIFIED BY 'S3cretPass';\n", "sql")
        self.assertIn("SQL-CRED", {i["rule"] for i in issues})

    def test_sql_cred_placeholder_word_still_skips(self):
        issues = lazaret.scan_file(
            "a.sql", "CREATE USER u IDENTIFIED BY 'placeholder';\n", "sql")
        self.assertNotIn("SQL-CRED", {i["rule"] for i in issues})

    def test_sql_cred_substring_exampled_not_a_match(self):
        # `exampled` is not the word `example` — must NOT skip
        issues = lazaret.scan_file(
            "a.sql", "CREATE USER u IDENTIFIED BY 'pass';  -- exampled\n", "sql")
        self.assertIn("SQL-CRED", {i["rule"] for i in issues})


def make_zip(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, payload in entries:
            zf.writestr(name, payload)
    return buf.getvalue()


def make_tar(entries):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, payload in entries:
            ti = tarfile.TarInfo(name)
            ti.size = len(payload)
            tf.addfile(ti, io.BytesIO(payload))
    return buf.getvalue()


class IterArchiveTests(unittest.TestCase):
    def test_real_sizes_and_reason_none_for_normal_members(self):
        data = make_zip([("pkg/a.py", b"x = 1\n"), ("pkg/b.py", b"y = 2\n")])
        members = list(cr.iter_archive(data, "zip"))
        self.assertEqual([(m[0], m[1], m[3]) for m in members],
                         [("a.py", 6, None), ("b.py", 6, None)])

    def test_oversize_member_gets_member_reason_and_prefix(self):
        big = b"\x00" * (cr.MAX_MEMBER + 10)
        data = make_tar([("pkg/blob.bin", big)])
        members = list(cr.iter_archive(data, "tgz"))
        rel, size, raw, reason = members[0]
        self.assertEqual(reason, "member")
        self.assertEqual(size, len(raw))
        self.assertEqual(size, cr.SAMPLE)

    def test_max_files_cutoff_yields_attributable_member(self):
        data = make_tar([(f"pkg/f{i}.txt", b"abc") for i in range(5)])
        cr.MAX_FILES = 3
        try:
            members = list(cr.iter_archive(data, "tgz"))
            reasons = [m[3] for m in members]
            self.assertEqual(reasons, [None, None, None, "files"])
            self.assertEqual(members[-1][0], "f3.txt")
        finally:
            cr.MAX_FILES = 4000

    def test_max_files_silent_return_before_fix(self):
        # regression: the audit found a SILENT return with attacker-controlled
        # entry order; now the last yielded member carries reason "files"
        data = make_zip([(f"pkg/f{i}.txt", b"abc") for i in range(6)])
        cr.MAX_FILES = 4
        try:
            members = list(cr.iter_archive(data, "zip"))
            self.assertEqual([m[3] for m in members][-1], "files")
        finally:
            cr.MAX_FILES = 4000

    def test_cumulative_budget_charged_from_real_bytes(self):
        # 6 x 600KB members (each under MAX_MEMBER), 2MB budget: the 4th
        # member trips the cumulative cap → reason "total", iteration stops.
        # Budget is charged from measured decompressed bytes, not headers.
        data = make_tar([(f"pkg/f{i}.bin", b"\x00" * (600 * 1024))
                         for i in range(6)])
        cr.MAX_ARCHIVE_TOTAL = 2 * 1024 * 1024
        try:
            members = list(cr.iter_archive(data, "tgz"))
            self.assertLess(len(members), 6)
            self.assertEqual(members[-1][3], "total")
            # the tripping member is included in the count (it is yielded so
            # the cutoff is attributable); all earlier members fit the budget
            self.assertLessEqual(sum(m[1] for m in members) - members[-1][1],
                                 2 * 1024 * 1024)
        finally:
            cr.MAX_ARCHIVE_TOTAL = 500 * 1024 * 1024

    def test_lying_zip_declared_size_does_not_skip(self):
        # audit PoC: declared >MAX_MEMBER in the zip headers with real content
        # small — old code skipped the member entirely (zero scanning, zero
        # signal). Now the member is yielded with REAL bytes and reason None.
        payload = b"eval(base64.b64decode(P))  # nosec\n"
        data = bytearray(make_zip([("pkg/implant.py", payload)]))
        cd_off = struct.unpack_from("<I", data, len(data) - 6)[0]
        struct.pack_into("<I", data, cd_off + 24, 50_000_000)   # central dir
        lh = data.find(b"PK\x03\x04")
        struct.pack_into("<I", data, lh + 18, 50_000_000)       # local header
        members = list(cr.iter_archive(bytes(data), "zip"))
        rel, size, raw, reason = members[0]
        self.assertEqual(reason, None)
        self.assertEqual(raw, payload)
        self.assertEqual(size, len(payload))


class TruncatedIssueTests(unittest.TestCase):
    def test_truncated_issue_shape(self):
        i = lazaret.truncated_issue("pkg/x", "11644385 bytes declared")
        self.assertEqual(i["rule"], "SC-TRUNCATED")
        self.assertEqual(i["sev"], "CRITICAL")
        self.assertEqual(i["type"], "HOTSPOT")
        self.assertEqual(i["line"], 1)
        for key in ("name", "msg", "why", "fix", "ref", "file", "snippet", "snipStart"):
            self.assertIn(key, i)


class HasScanEngineVersionTests(unittest.TestCase):
    def test_scan_cache_is_engine_keyed(self):
        store = cr.Store(":memory:")
        pid, _ = store.add_package("npm", "cache-test")
        res = {"ecosystem": "npm", "name": "cache-test", "version": "1.0.0",
               "artifact": "sdist", "archiveBytes": 100, "filesScanned": 1,
               "binaryArtifacts": 0, "profile": "supply-chain",
               "sevCounts": {s: 0 for s in lazaret.SEV_ORDER},
               "supplyChain": 0, "truncated": 0, "verdict": "OK", "issues": [],
               "digest": None, "scannedAt": "2026-01-01T00:00:00+00:00"}
        store.save_scan(pid, res)
        self.assertTrue(store.has_scan(pid, "1.0.0", "supply-chain"))
        self.assertFalse(
            store.has_scan(pid, "1.0.0", "supply-chain", engine_version="2.1.0"))
        # engine version bump makes the old clean verdict stale:
        self.assertEqual(cr.ENGINE_VERSION, "2.4.0")

    def test_save_scan_does_not_collide_across_engines(self):
        store = cr.Store(":memory:")
        pid, _ = store.add_package("npm", "cache-test2")
        res = {"ecosystem": "npm", "name": "cache-test2", "version": "1.0.0",
               "artifact": "sdist", "archiveBytes": 100, "filesScanned": 1,
               "binaryArtifacts": 0, "profile": "supply-chain",
               "sevCounts": {s: 0 for s in lazaret.SEV_ORDER},
               "supplyChain": 0, "truncated": 0, "verdict": "OK", "issues": [],
               "digest": None, "scannedAt": "2026-01-01T00:00:00+00:00"}
        store.save_scan(pid, res)
        # a scan from an older engine under the same (pkg,ver,profile):
        res_old = dict(res, verdict="SUSPICIOUS")
        cur = store.conn.cursor()
        cur.execute(
            f"INSERT INTO {store.t}scans (package_id,version,profile,scanned_at,"
            f"engine_version,files_scanned,archive_bytes,blockers,criticals,majors,"
            f"supply_chain,issue_count,verdict,issues) VALUES "
            f"({','.join([store.ph] * 14)})",
            (pid, "1.0.0", "supply-chain", "2025-01-01T00:00:00+00:00", "2.1.0",
             1, 100, 0, 0, 0, 0, 0, "OK", "[]"))
        store.conn.commit()
        # has_scan matches only the CURRENT engine version's row
        self.assertTrue(store.has_scan(pid, "1.0.0", "supply-chain"))


class SCRuleObjectTests(unittest.TestCase):
    """Rule table invariants the fixes rely on."""

    def test_sc_rules_cannot_be_suppressed_via_is_suppressed(self):
        sc_ids = [r["id"] for r in lazaret.RULES + lazaret.TEXT_RULES
                  if r["id"].startswith("SC-")]
        self.assertTrue(sc_ids)
        for rid in sc_ids:
            self.assertFalse(lazaret.is_suppressed(
                {"rule": rid, "line": 1}, ["x = 1 # nosec", ""]),
                f"{rid} must never be suppressible")

    def test_secret_skip_re_compiled_and_bounded(self):
        self.assertIsNotNone(lazaret.SECRET_SKIP_RE)
        # bare `test` removed entirely (card: "SECRET_SKIP_RE contains bare
        # `test` gating all entropy detection")
        self.assertFalse(lazaret.SECRET_SKIP_RE.search("test"))      # noqa: S105
        self.assertFalse(lazaret.SECRET_SKIP_RE.search("testing"))
        self.assertFalse(lazaret.SECRET_SKIP_RE.search("attested"))
        self.assertFalse(lazaret.SECRET_SKIP_RE.search("latest"))
        # noise words still word-bounded
        self.assertTrue(lazaret.SECRET_SKIP_RE.search("placeholder"))
        self.assertTrue(lazaret.SECRET_SKIP_RE.search("dummy"))

    def test_engine_version_bumped(self):
        self.assertEqual(cr.ENGINE_VERSION, "2.4.0")


if __name__ == "__main__":
    unittest.main()
