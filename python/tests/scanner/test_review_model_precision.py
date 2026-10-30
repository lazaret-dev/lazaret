"""FP-MODEL-FILES, the precision review of Oct 21: benign files the real libraries write are read quiet.

The first reader reported a datetime's zone (zoneinfo's ZoneInfo pickles as getattr(ZoneInfo, '_unpickle')) as
CRITICAL, pandas 3's Arrow-backed strings and pyarrow's own objects (py_buffer, schema) as MAJOR, dateutil's tzfile
called with its zone file's path as MAJOR, an enum of the standard library (http.HTTPStatus) as CRITICAL, an enum's
member looked up by its value (Source('https://...')) as MAJOR, and pandas' zip-compressed pickle as an archive. Now:
getattr(<a global>, '<a name>') is read as that global; pyarrow's pickling helpers and dateutil's and pytz's zones are
the formats' own; the data types of modules of code (http.HTTPStatus, signal.Signals, os.stat_result) are data; a zip
of one pickle is read. A call with text of an enum stays MAJOR whatever the scanned source says of the class (the
external re-review of Oct 27 dropped the waiver: which file the name is at load time is the loading program's).

FP-MODEL-FILES-PY311: Python 3.10 and 3.11.0 to 3.11.4 pickle a member of signal's, socket's and ssl's converted
enums by its module-level name (GLOBAL 'signal SIGTERM'), and 3.11.0 to 3.11.4 another as getattr(ssl.TLSVersion,
'TLSv1_2'), where 3.12 writes signal.Signals(15): the alias was code (CRITICAL), so a benign pickle 3.10 or 3.11 wrote
was a false CRITICAL and these tests failed there. Each form is now built here byte by byte (tests/_model_files.
std_members, the bytes those Pythons write), whatever Python runs the tests; such a member kept as data is quiet, and
called, made, changed or reached through it is code as before.

The libraries' files the tests cannot write (pandas 3 with pyarrow, dateutil, pytz, datasets) are fixtures written by
scripts/make_model_fixtures.py (tests/fixtures/model_files); the standard library's are written here. Nothing is
unpickled or loaded: the scanner reads bytes.
"""
import http
import io
import os
import pickle
import platform
import signal
import socket
import subprocess
import time
import unittest
import zipfile

from tests import _model_files as mf
from tests.scanner.test_review_model_files import CODE, found, msgs, scan
from lazaret.scanner import core

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures", "model_files")
INFO = ("SC-PICKLE-GLOBAL", "INFO")
MAJOR = ("SC-PICKLE-GLOBAL", "MAJOR")


def fixtures():
    out = {}
    for name in sorted(os.listdir(FIXTURES)):
        with open(os.path.join(FIXTURES, name), "rb") as fh:
            out[f"data/{name}"] = fh.read()
    return out


def stdlib_data():
    """The standard library's data types of modules of code, pickled by pickle itself at every protocol; and the
    members of its data enums as Python 3.10, 3.11.0 to 3.11.4 and 3.12 write them, hand-built (whatever Python runs
    the tests: FP-MODEL-FILES-PY311)."""
    objs = {
        "status": [http.HTTPStatus.OK, http.HTTPStatus.NOT_FOUND],
        "signals": [signal.Signals.SIGTERM, signal.Handlers.SIG_DFL],
        "socket": [socket.AddressFamily.AF_INET, socket.SocketKind.SOCK_STREAM],
        "stat": os.stat_result((0o100644, 1, 2, 1, 0, 0, 12, 0, 0, 0)),
        "time": time.gmtime(0),
        "uname": platform.uname_result("Linux", "host", "6.1", "#1", "x86_64"),
        "done": subprocess.CompletedProcess(["echo", "x"], 0, stdout=b"x\n"),
    }
    if hasattr(http, "HTTPMethod"):
        objs["method"] = http.HTTPMethod.GET
    out = {f"std/data.p{p}.pkl": pickle.dumps(objs, protocol=p) for p in range(6)}
    out.update({f"std/members.{form}.p{p}.pkl": mf.std_members(protocol=p, form=form)
                for form in mf.STD_FORMS for p in range(6)})
    return out


class TheLibrariesFiles(unittest.TestCase):
    def test_each_is_quiet_alone(self):
        for rel, data in {**fixtures(), **stdlib_data()}.items():
            got = core.model_file(rel, data, len(data), 16_000_000)
            self.assertIsNotNone(got, rel)
            self.assertEqual((got["issues"], got["calls"], got["opaque"]), ([], [], False), rel)

    def test_in_a_project(self):
        res = scan({**fixtures(), **stdlib_data(), "app.py": "import pandas\n"})
        self.assertEqual(found(res), {}, [(i["file"], i["rule"], i["msg"]) for i in res["issues"]])
        self.assertTrue(res["pass"])

    def test_a_zip_of_one_pickle_is_read_for_what_it_runs(self):
        # pandas' to_pickle("x.pkl.zip"): read_pickle reads the zip's one member, so it is read as the pickle it is
        def zipped(members):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
                for name, data in members.items():
                    z.writestr(name, data)
            return buf.getvalue()
        res = scan({"frame.pkl.zip": zipped({"frame.pkl": mf.os_system("id")}),
                    "ok.pkl.zip": zipped({"ok.pkl": mf.plain_pickle({"a": [1, 2]}, 4)}),
                    "more.zip": zipped({"ok.pickle": mf.plain_pickle({"a": 1}, 4), "notes.txt": "x"}),
                    "a.py": "x = 1\n"})
        got = found(res)
        self.assertEqual(got.get("frame.pkl.zip"), {CODE})
        self.assertNotIn("ok.pkl.zip", got)
        # (a zip of more than its pickle stays an archive the scan does not open)
        self.assertEqual(got.get("more.zip"), {("SC-NESTED-ARCHIVE", "MINOR")})


class StdlibEnumMembers(unittest.TestCase):
    """FP-MODEL-FILES-PY311: a member of the standard library's data enums by the exact name a pickle writes for it
    (PICKLE_DATA_MEMBERS: signal.SIGTERM, ssl.TLSVersion.TLSv1_2) is data where it is only kept; called, made, changed
    by BUILD or reached through, it is code as before, and so is a name that is no member's exactly."""

    def test_each_python_s_form_is_quiet(self):
        # (the forms differ: 3.10's and 3.11.0's name the module-level alias, 3.12's the class)
        self.assertIn(b"csignal\nSIGTERM\n", mf.std_members(protocol=2, form="3.10"))
        self.assertIn(b"c__builtin__\ngetattr\n", mf.std_members(protocol=2, form="3.11.0"))
        self.assertIn(b"csignal\nSignals\n", mf.std_members(protocol=2, form="3.12"))
        for form in mf.STD_FORMS:
            for p in range(6):
                data = mf.std_members(protocol=p, form=form)
                got = core.model_file("m.pkl", data, len(data), 16_000_000)
                self.assertEqual((got["issues"], got["calls"], got["opaque"]), ([], [], False), (form, p))

    def test_each_use(self):
        for name, (data, quiet) in mf.std_member_shapes().items():
            got = core.model_file(name, data, len(data), 16_000_000)
            sev = {(i["rule"], i["sev"]) for i in got["issues"]}
            if quiet:
                self.assertEqual((got["issues"], got["calls"]), ([], []), name)
            else:
                self.assertIn(CODE, sev, name)

    def test_in_a_project_and_with_deps(self):
        shapes = mf.std_member_shapes()
        files = {f"m/{k}": v for k, (v, _) in shapes.items()}
        files.update({f"m/members.{form}.p{p}.pkl": mf.std_members(protocol=p, form=form)
                      for form in mf.STD_FORMS for p in range(6)})
        for deps in (False, True):
            got = found(scan({**files, "app.py": "x = 1\n", ".venv/pyvenv.cfg": "home = /usr/bin\n"},
                             include_deps=deps), "m/")
            self.assertEqual(sorted(got), sorted(f"m/{k}" for k, (_, quiet) in shapes.items() if not quiet), deps)
            for k, (_, quiet) in shapes.items():
                if not quiet:
                    self.assertIn(CODE, got[f"m/{k}"], k)


class Enums(unittest.TestCase):
    """An enum's member pickles as its class called with its value: Source('https://hub.invalid/x'): a call with text,
    MAJOR, whatever the scan's source defines (the waiver of John's MEDIUM-1 dropped by the external re-review of Oct
    27: which file a module name is when the file is loaded is the loading program's import path)."""

    URL = "https://hub.invalid/datasets/x"

    def pkl(self, module):
        source = mf.fn(module, "Source")
        return mf.plain_pickle([mf.Reduce(source, (self.URL,))], 2, {module: {"Source": source}})

    def test_the_projects_own_enum(self):
        plain = "import enum\n\nclass Source(enum.Enum):\n    HUB = '%s'\n" % self.URL
        res = scan({"m.pkl": self.pkl("kinds"), "kinds.py": plain})
        self.assertEqual(found(res), {"m.pkl": {INFO, MAJOR}})
        self.assertTrue(any("this package's own module: kinds (Source" in m for m in msgs(res, "SC-PICKLE-GLOBAL")))
        # (the re-review's shapes: sys.path set by a file, a project enum.py, an alias whose _missing_ is set)
        for more in ({"loader.py": "import sys\nsys.path.insert(0, 'alt')\n", "alt/kinds.py": "def Source(v):\n    return v\n"},
                     {"enum.py": "class Enum:\n    pass\n"},
                     {"kinds.py": plain + "alias = Source\nalias._missing_ = classmethod(lambda c, v: v)\n"}):
            self.assertEqual(found(scan({"m.pkl": self.pkl("kinds"), "kinds.py": plain, **more})).get("m.pkl"),
                             {INFO, MAJOR}, more)

    def test_an_enum_that_decides_its_lookup_stays_major(self):
        for body in ("    @classmethod\n    def _missing_(cls, value):\n        return cls.HUB\n",
                     "    def __new__(cls, value):\n        obj = object.__new__(cls)\n        obj._value_ = value\n"
                     "        return obj\n"):
            src = "import enum\n\nclass Source(enum.Enum):\n    HUB = '%s'\n%s" % (self.URL, body)
            res = scan({"m.pkl": self.pkl("kinds"), "kinds.py": src})
            self.assertEqual(found(res), {"m.pkl": {INFO, MAJOR}}, body)
            self.assertTrue(any(f"kinds.Source with '{self.URL}'" in m for m in msgs(res, "SC-PICKLE-GLOBAL")))
        # a class that is not an enum: a call told what to use
        res = scan({"m.pkl": self.pkl("kinds"), "kinds.py": "class Source:\n    def __init__(self, url): pass\n"})
        self.assertEqual(found(res), {"m.pkl": {INFO, MAJOR}})

    def test_a_class_the_scan_cannot_read_stays_major(self):
        # __main__ (the script that wrote it), and a package the scan does not hold
        for module in ("__main__", "otherpkg.kinds"):
            res = scan({"m.pkl": self.pkl(module), "app.py": "x = 1\n"})
            self.assertEqual(found(res), {"m.pkl": {MAJOR}}, module)

    def test_a_dependencys_enum(self):
        sp = ".venv/lib/python3.12/site-packages"
        files = {".venv/pyvenv.cfg": "home = /usr/bin\n", "app.py": "import hubkit\n", "m.pkl": self.pkl("hubkit.kinds"),
                 f"{sp}/hubkit/__init__.py": "",
                 f"{sp}/hubkit/kinds.py": "import enum\n\nclass Source(enum.Enum):\n    HUB = '%s'\n" % self.URL}
        # with --deps or without: the call is MAJOR
        self.assertEqual(found(scan(files, include_deps=True)), {"m.pkl": {MAJOR}})
        self.assertEqual(found(scan(files)), {"m.pkl": {MAJOR}})


if __name__ == "__main__":
    unittest.main()
