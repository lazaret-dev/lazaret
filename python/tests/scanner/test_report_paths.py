#!/usr/bin/env python3
"""Unit tests — lazaret_report.py (safe report paths, card "CLI writes
reports into CWD").

Run:  python3 lazaret/test_lazaret_report.py [unittest-args]

Covers the acceptance criteria:
  1. Default report paths resolve under the scan root (or --out-dir), never
     bare CWD-relative names.
  2. Output writability is checked BEFORE scanning (the module API the CLI
     calls pre-scan), failing with ReportPathError + clear message.
  3. Never silently clobber a pre-existing file that was not produced by
     this run/engine: refused with a clear error; --force-overwrite
     overrides (but still refuses dirs/symlinks/special files); our own
     earlier reports ARE replaceable (re-scan workflow).
  4. Regression: a scan with CWD set to a read-only directory succeeds (the
     reports land under the scan root, not the CWD) — covered end-to-end by
     the CLI-level tests; here the path-computation half is asserted.
  5. Card f22ce3c5: a deeply nested pre-existing destination (json.loads →
     RecursionError, NOT a ValueError) is treated exactly like an
     unreadable file — not ours → ReportPathError — at the pre-scan check,
     at the write-time re-check, and for the html fallback path; the
     re-scan workflow and the plain-unparseable case are unchanged.
"""
from __future__ import annotations

import json
import os

from tests import _support  # noqa: E402
import stat
import sys
import tempfile
import unittest

# ^ the lazaret/ dir itself: import the SIBLING lazaret_report.py this
# suite ships with (same convention as the other lazaret/ suites). Never
# the parent dir — a stale flat-layout copy there would shadow the module
# under test (exposed by card f22ce3c5's in-process deep-nest tests).
from lazaret.scanner import reports as cr  # noqa: E402


class Args:
    """Minimal argparse.Namespace stand-in for report_paths()."""

    def __init__(self, json=None, html=None, sarif=None, out_dir=None,
                 no_json=False, no_html=False, force_overwrite=False):
        self.json = json
        self.html = html
        self.sarif = sarif
        self.out_dir = out_dir
        self.no_json = no_json
        self.no_html = no_html
        self.force_overwrite = force_overwrite


# ---------------------------------------------------------------------------
# 1. Path computation
# ---------------------------------------------------------------------------
class TestReportPaths(unittest.TestCase):
    def setUp(self):
        self._cwd = os.getcwd()
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cg-unit-"))

    def tearDown(self):
        os.chdir(self._cwd)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_default_paths_are_absolute_under_scan_root(self):
        p = cr.report_paths(Args(), self.tmp)
        self.assertEqual(p["json"], os.path.join(self.tmp, "lazaret-report.json"))
        self.assertEqual(p["html"], os.path.join(self.tmp, "lazaret-report.html"))
        self.assertIsNone(p["sarif"])

    def test_default_paths_independent_of_cwd(self):
        # Scan root given relative; CWD changes between the two calls — the
        # resolved default paths must still live under the scan root, not
        # under either CWD.
        scan = "scanroot"
        os.makedirs(os.path.join(self.tmp, scan), exist_ok=True)
        os.chdir(self.tmp)
        p1 = cr.report_paths(Args(), scan)
        os.chdir(os.path.join(self.tmp, scan))
        p2 = cr.report_paths(Args(), os.path.join("..", scan))
        self.assertEqual(p1, p2)
        for key in ("json", "html"):
            self.assertEqual(os.path.dirname(p1[key]),
                             os.path.join(self.tmp, scan))

    def test_out_dir_overrides_default_location(self):
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        p = cr.report_paths(Args(out_dir=out), "/scan/root")
        self.assertEqual(p["json"], os.path.join(out, "lazaret-report.json"))
        self.assertEqual(p["html"], os.path.join(out, "lazaret-report.html"))

    def test_relative_explicit_paths_are_out_dir_relative(self):
        out = os.path.join(self.tmp, "out")
        os.makedirs(out)
        p = cr.report_paths(Args(json="a.json", html="b.html",
                                 sarif="c.sarif", out_dir=out), "/scan/root")
        self.assertEqual(p["json"], os.path.join(out, "a.json"))
        self.assertEqual(p["html"], os.path.join(out, "b.html"))
        self.assertEqual(p["sarif"], os.path.join(out, "c.sarif"))

    def test_absolute_explicit_paths_are_kept(self):
        # An absolute path on this platform: "/tmp" on POSIX, "D:\\tmp" on
        # Windows. (A bare "/tmp/x.json" is NOT absolute on Windows: since
        # Python 3.13 os.path.isabs agrees, and it resolves onto a drive.)
        tmp = os.path.abspath(os.path.join(os.sep, "tmp"))
        json_p, html_p, sarif_p = (os.path.join(tmp, n) for n in ("x.json", "y.html", "z.sarif"))
        p = cr.report_paths(Args(json=json_p, html=html_p, sarif=sarif_p), "/scan/root")
        self.assertEqual(p["json"], json_p)
        self.assertEqual(p["html"], html_p)
        self.assertEqual(p["sarif"], sarif_p)


# ---------------------------------------------------------------------------
# 2. Writability + no-clobber validation (pre-scan)
# ---------------------------------------------------------------------------
class TestValidatePaths(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cg-unit-"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _path(self, name):
        return os.path.join(self.tmp, name)

    def _symlink(self, target, link, **kw):
        # Windows runners without the symlink privilege raise OSError
        try:
            os.symlink(target, link, **kw)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"cannot create symlinks here: {exc}")

    def test_plain_writable_dir_passes(self):
        p = self._path("lazaret-report.json")
        cr.validate_report_paths({"json": p})
        self.assertFalse(os.path.exists(p))          # nothing created

    @_support.skip_unless_permissions_enforced

    def test_unwritable_dir_fails_with_clear_message(self):
        ro = os.path.join(self.tmp, "ro")
        os.makedirs(ro)
        os.chmod(ro, stat.S_IRUSR | stat.S_IXUSR)
        try:
            p = os.path.join(ro, "lazaret-report.json")
            with self.assertRaises(cr.ReportPathError) as cm:
                cr.validate_report_paths({"json": p})
            self.assertIn("not writable", str(cm.exception))
            self.assertIn(p, str(cm.exception))
        finally:
            os.chmod(ro, 0o755)

    def test_nonexistent_dir_fails_with_clear_message(self):
        p = os.path.join(self.tmp, "no", "such", "dir", "report.json")
        with self.assertRaises(cr.ReportPathError) as cm:
            cr.validate_report_paths({"json": p})
        self.assertIn("does not exist", str(cm.exception))

    def test_existing_unrelated_file_is_refused(self):
        p = self._path("lazaret-report.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("precious data")
        with self.assertRaises(cr.ReportPathError) as cm:
            cr.validate_report_paths({"json": p})
        self.assertIn("refusing to overwrite", str(cm.exception))
        with open(p, encoding="utf-8") as fh:                # untouched
            self.assertEqual(fh.read(), "precious data")

    def test_existing_empty_file_is_refused(self):
        p = self._path("lazaret-report.json")
        open(p, "w").close()
        with self.assertRaises(cr.ReportPathError):
            cr.validate_report_paths({"json": p})

    def test_directory_destination_refused(self):
        p = self._path("adir")
        os.makedirs(p)
        for strict in (False, True):
            with self.assertRaises(cr.ReportPathError) as cm:
                cr.validate_report_paths({"json": p}, strict=strict)
            self.assertIn("directory", str(cm.exception))

    def test_symlink_destination_refused(self):
        real = self._path("real.json")
        with open(real, "w") as fh:
            fh.write("data")
        p = self._path("link.json")
        self._symlink(real, p)
        for strict in (False, True):
            with self.assertRaises(cr.ReportPathError) as cm:
                cr.validate_report_paths({"json": p}, strict=strict)
            self.assertIn("symlink", str(cm.exception))
        target = os.readlink(p)
        if target.startswith("\\\\?\\"):       # Windows returns an extended-length path
            target = target[4:]
        self.assertEqual(target, real)      # untouched

    def test_symlink_lying_between_path_and_file(self):
        # dir link + real file: replacing through it would silently clobber
        # the target file — must be refused at write time.
        realdir = os.path.join(self.tmp, "realdir")
        os.makedirs(realdir)
        dirlink = os.path.join(self.tmp, "dirlink")
        self._symlink(realdir, dirlink, target_is_directory=True)
        dest = os.path.join(dirlink, "lazaret-report.json")
        with open(os.path.join(realdir, "lazaret-report.json"), "w") as fh:
            fh.write("old")
        with self.assertRaises(cr.ReportPathError):
            cr.write_report(dest, lambda: "NEW", kind="json")

    def test_force_overwrite_allows_unrelated_file(self):
        p = self._path("lazaret-report.json")
        with open(p, "w") as fh:
            fh.write("precious data")
        cr.validate_report_paths({"json": p}, strict=True)
        cr.write_report(p, lambda: cr.json_renderer({"pass": True}),
                        kind="json", strict=True)
        with open(p, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["pass"], True)

    def test_force_overwrite_still_refuses_symlink(self):
        real = self._path("real.json")
        with open(real, "w") as fh:
            fh.write("data")
        p = self._path("link.json")
        self._symlink(real, p)
        with self.assertRaises(cr.ReportPathError):
            cr.validate_report_paths({"json": p}, strict=True)

    def test_our_own_report_is_replaceable(self):
        p = self._path("lazaret-report.json")
        cr.write_report(p, lambda: cr.json_renderer({"pass": True}), kind="json")
        cr.validate_report_paths({"json": p})      # no error
        cr.write_report(p, lambda: cr.json_renderer({"pass": False}), kind="json")
        with open(p, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["pass"], False)

    def test_our_own_html_report_is_replaceable(self):
        p = self._path("lazaret-report.html")
        cr.write_report(p, lambda: "<!DOCTYPE html>\n<html><head>" +
                         cr.HTML_ENGINE_MARKER + "\n</head></html>",
                        kind="html")
        cr.validate_report_paths({"html": p})      # no error
        cr.write_report(p, lambda: "<html><head>" + cr.HTML_ENGINE_MARKER +
                        "</head><body>2</body></html>", kind="html")
        with open(p, encoding="utf-8") as fh:
            self.assertIn("2", fh.read())

    def test_html_file_without_marker_refused(self):
        p = self._path("lazaret-report.html")
        with open(p, "w") as fh:
            fh.write("<html><body>not a lazaret file</body></html>")
        with self.assertRaises(cr.ReportPathError):
            cr.validate_report_paths({"html": p})

    def test_marker_position_is_checked_not_just_presence(self):
        # JSON without our exact marker is not ours.
        p = self._path("lazaret-report.json")
        with open(p, "w") as fh:
            json.dump({"generatedBy": "something-else"}, fh)
        with self.assertRaises(cr.ReportPathError):
            cr.validate_report_paths({"json": p})

    def test_sarif_report_is_replaceable_and_bad_sarif_refused(self):
        p = self._path("out.sarif")
        cr.write_report(p, lambda: cr.sarif_renderer({"version": "2.1.0"}),
                        kind="sarif")
        cr.validate_report_paths({"sarif": p})     # no error
        # A SARIF-shaped JSON without our property-bag marker is refused.
        with open(p, "w") as fh:
            json.dump({"$schema": "x", "version": "2.1.0", "runs": []}, fh)
        with self.assertRaises(cr.ReportPathError):
            cr.validate_report_paths({"sarif": p})


# ---------------------------------------------------------------------------
# 3. Writes (atomic, marker-stamping)
# ---------------------------------------------------------------------------
class TestWriteReport(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cg-unit-"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _path(self, name):
        return os.path.join(self.tmp, name)

    def test_write_creates_file_with_marker_first(self):
        p = self._path("lazaret-report.json")
        cr.write_report(p, lambda: cr.json_renderer({"pass": True}), kind="json")
        with open(p, encoding="utf-8") as fh:
            text = fh.read()
        first_key = json.loads(text)
        self.assertEqual(list(first_key.keys())[0], cr.ENGINE_MARKER)
        self.assertTrue(os.path.isfile(p))

    def test_write_is_atomic_no_temp_left_behind(self):
        p = self._path("lazaret-report.json")
        cr.write_report(p, lambda: cr.json_renderer({"a": 1}), kind="json")
        leftovers = [f for f in os.listdir(self.tmp)
                     if f.startswith(".lazaret")]
        self.assertEqual(leftovers, [])
        self.assertFalse(os.path.exists(p + ".tmp"))

    def test_no_temp_files_on_clobber_refusal(self):
        p = self._path("lazaret-report.json")
        with open(p, "w") as fh:
            fh.write("precious")
        with self.assertRaises(cr.ReportPathError):
            cr.write_report(p, lambda: "NEW", kind="json")
        leftovers = [f for f in os.listdir(self.tmp)
                     if f.startswith(".lazaret")]
        self.assertEqual(leftovers, [])
        with open(p) as fh:
            self.assertEqual(fh.read(), "precious")

    def test_partial_write_on_crash_leaves_no_target(self):
        # render() raising mid-write: no destination file, no temp residue.
        p = self._path("lazaret-report.json")

        def bad_render():
            raise RuntimeError("crash during render")

        with self.assertRaises(RuntimeError):
            cr.write_report(p, bad_render, kind="json")
        self.assertFalse(os.path.exists(p))
        self.assertEqual([f for f in os.listdir(self.tmp)
                          if f.startswith(".lazaret")], [])

    def test_race_clobber_is_refused_at_write_time(self):
        # TOCTOU: file appears AFTER validation — write refuses.
        p = self._path("lazaret-report.json")
        cr.validate_report_paths({"json": p})
        with open(p, "w") as fh:                     # the "race"
            fh.write("precious")
        with self.assertRaises(cr.ReportPathError):
            cr.write_report(p, lambda: "NEW", kind="json")
        with open(p) as fh:
            self.assertEqual(fh.read(), "precious")


# ---------------------------------------------------------------------------
# 3b. Deep-nest guard on the provenance parse (card f22ce3c5)
# ---------------------------------------------------------------------------
#: The hostile pre-planted destination: MARKER_READ_BYTES of '[' parses
#: ~60k deep, so json.loads raises RecursionError — which is NOT a
#: ValueError and used to escape is_our_report as a traceback.
DEEP = "[" * 120000


class TestDeepNestGuard(unittest.TestCase):
    """A hostile repo can pre-plant the report destination (the default
    JSON path lazaret-report.json resolves under the scan root) with a
    deeply nested document. The provenance check must treat that exactly
    like an unreadable file: not ours → pre-scan refusal with a message
    naming the path, never a RecursionError traceback."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="cg-deep-"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _plant(self, name=cr.JSON_REPORT_NAME, content=DEEP):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return path

    def test_is_our_report_returns_false_no_raise(self):
        for kind in ("json", "sarif"):
            p = self._plant()
            self.assertFalse(cr.is_our_report(p, kind))   # no exception

    def test_deep_head_within_marker_window_is_enough(self):
        # A deep doc longer than the 64KB marker window: the head we
        # actually read is 120k '[' bytes — still deep, still must refuse.
        p = self._plant(content="[" * (cr.MARKER_READ_BYTES + 1000))
        self.assertFalse(cr.is_our_report(p, "json"))

    def test_validate_refuses_deep_json_destination(self):
        p = self._plant()
        with self.assertRaises(cr.ReportPathError) as cm:
            cr.validate_report_paths({"json": p})
        self.assertIn("refusing to overwrite", str(cm.exception))
        self.assertIn(p, str(cm.exception))               # names the path
        with open(p, encoding="utf-8") as fh:             # untouched
            self.assertEqual(len(fh.read()), len(DEEP))

    def test_validate_refuses_deep_sarif_destination(self):
        p = self._plant(name="out.sarif")
        with self.assertRaises(cr.ReportPathError) as cm:
            cr.validate_report_paths({"sarif": p})
        self.assertIn("refusing to overwrite", str(cm.exception))

    def test_write_time_recheck_also_refuses_deep_doc(self):
        # TOCTOU: the deep file appears AFTER validation — the write-time
        # re-check in write_report() must refuse, not traceback, and must
        # not clobber the planted file nor leave a temp file behind.
        p = self._plant()
        with self.assertRaises(cr.ReportPathError):
            cr.write_report(p, lambda: cr.json_renderer({"pass": True}),
                            kind="json")
        with open(p, encoding="utf-8") as fh:
            self.assertEqual(len(fh.read()), len(DEEP))   # untouched
        self.assertEqual([f for f in os.listdir(self.tmp)
                          if f.startswith(".lazaret")], [])

    def test_force_overwrite_replaces_deep_doc(self):
        p = self._plant()
        cr.validate_report_paths({"json": p}, strict=True)
        cr.write_report(p, lambda: cr.json_renderer({"pass": True}),
                        kind="json", strict=True)
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data[cr.ENGINE_MARKER], cr.ENGINE_VERSION)

    def test_rescan_workflow_still_works_after_refusal(self):
        # The clean re-scan workflow (card acceptance): after the refusal,
        # either --force-overwrite or a fresh destination succeeds.
        p = self._plant()
        with self.assertRaises(cr.ReportPathError):
            cr.validate_report_paths({"json": p})
        fresh = os.path.join(self.tmp, "fresh.json")
        cr.validate_report_paths({"json": fresh})
        cr.write_report(fresh, lambda: cr.json_renderer({"pass": True}),
                        kind="json")
        with open(fresh, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["pass"], True)

    def test_deep_doc_at_html_destination_falls_back_to_marker_check(self):
        # After the fix a JSON-parse failure at an html destination falls
        # through to the HTML-marker string check (same as any non-JSON
        # head); a deep doc has no marker → refused, no traceback.
        p = self._plant(name=cr.HTML_REPORT_NAME)
        self.assertFalse(cr.is_our_report(p, "html"))
        with self.assertRaises(cr.ReportPathError):
            cr.validate_report_paths({"html": p})

    def test_html_marker_survives_deep_parse_failure(self):
        # Vacuity guard: the html kind keeps its string-marker path when
        # the head is not JSON at all (unrelated to the deep primitive).
        p = self._plant(name=cr.HTML_REPORT_NAME,
                        content="<html><head>" + cr.HTML_ENGINE_MARKER +
                                "</head><body>x</body></html>")
        self.assertTrue(cr.is_our_report(p, "html"))

    def test_vacuity_plain_unrelated_json_still_refused(self):
        # Vacuity guard: behavior for ordinary unparseable content is
        # unchanged (regression around the new except tuple).
        p = self._plant(content="}{ not json")
        self.assertFalse(cr.is_our_report(p, "json"))
        with self.assertRaises(cr.ReportPathError):
            cr.validate_report_paths({"json": p})


# ---------------------------------------------------------------------------
# 4. Read-only CWD regression (module-level half)
# ---------------------------------------------------------------------------
class TestReadOnlyCwd(unittest.TestCase):
    """The CLI-level regression (run a scan from a read-only CWD) is covered
    in test_lazaret_report_cli.py; this pins the module's contribution:
    paths computed for the same invocation don't change with the CWD."""

    def test_paths_stable_across_cwd_change(self):
        tmp = os.path.realpath(tempfile.mkdtemp(prefix="cg-unit-"))
        # Cleanups run LIFO: rmtree (with its own chmod-safe lambda) first…
        self.addCleanup(
            lambda: (os.path.isdir(tmp) and os.chmod(tmp, 0o755),
                     __import__("shutil").rmtree(tmp, ignore_errors=True)))
        # …then this no-op chmod guard, only if the dir still exists.
        self.addCleanup(lambda: os.path.isdir(tmp) and os.chmod(tmp, 0o755))
        root = os.path.join(tmp, "root")
        os.makedirs(root)
        cwd = os.getcwd()
        try:
            os.chdir(root)
            p = cr.report_paths(Args(), ".")
            self.assertEqual(p["json"], os.path.join(root, "lazaret-report.json"))
        finally:
            os.chdir(cwd)
        os.chmod(tmp, 0o555)                       # simulate read-only
        p2 = cr.report_paths(Args(), root)         # no CWD dependency
        self.assertEqual(p2["json"], os.path.join(root, "lazaret-report.json"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
