"""What the fuzzers (`scripts/fuzz`, 0.1.9 X-1) found in the dependency readers of `scanner/sca.py`.

1  A requirements file with an include whose path holds a NUL byte (`-r a<NUL>b`) raised ValueError out of
   `os.path.realpath`, and with it out of `scan_all`: one hostile requirements.txt ended the inventory. The include
   is now "not found", counted in a warning like any other missing include.
2  A TOML file nested too deeply (`x = [[[[…`, `[[[[…`, inline tables in inline tables) raised RecursionError out of
   `tomllib` on Python 3.11+, which `load_toml` did not turn into the ValueError its callers catch: `scan_all`
   (uv.lock, poetry.lock, pylock.toml, pyproject.toml), the guard's uv.lock reader and the package-manager
   settings readers. It is now ValueError, as on 3.10, where the subset parser already did so.
3  Reading a setup.py whose strings hold an invalid escape (`"\\d"`) printed a SyntaxWarning on stderr (the file
   is compiled to be read, never run), and under `-W error` changed the way the file was read. The warnings are
   now ignored while it is parsed.

All fixtures are inert text."""

import os
import shutil
import tempfile
import unittest
import warnings

from lazaret.scanner import sca


def project(files):
    root = tempfile.mkdtemp(prefix="lazaret-sca-fz-")
    for name, data in files.items():
        path = os.path.join(root, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
    return root


class Case(unittest.TestCase):
    def project(self, files):
        root = project(files)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return root

    def declared(self, files):
        warned = sca._Warnings()
        inventory = sca.scan_pypi_declared(self.project(files), warned)
        return sorted((n, v) for e, n, v, w in inventory), warned.counts


class NulInAnInclude(Case):
    def test_an_include_with_a_nul_byte_is_a_missing_include(self):
        for line in (b"-r a\x00b", b"-c\x00", b"-r\x00", b"--requirement=x\x00y"):
            with self.subTest(line):
                self.assertEqual(self.declared({"requirements.txt": line + b"\nsix==1.16.0\n"}),
                                 ([("six", "1.16.0")], {"requirements includes not found": 1}))

    def test_the_rest_of_the_file_and_other_includes_are_still_read(self):
        found = self.declared({"requirements.txt": b"-r base.txt\n-r bad\x00.txt\nidna==2.5\n",
                               "base.txt": b"urllib3==1.24.1\n"})
        self.assertEqual(found, ([("idna", "2.5"), ("urllib3", "1.24.1")], {"requirements includes not found": 1}))

    def test_scan_all_is_not_stopped_by_it(self):
        root = self.project({"requirements.txt": b"-r \x00\n", "package-lock.json":
                             b'{"lockfileVersion": 3, "packages": {"node_modules/lodash": {"version": "4.17.20"}}}'})
        self.assertEqual([(e, n, v) for e, n, v, w in sca.scan_all(root)], [("npm", "lodash", "4.17.20")])


class DeepToml(Case):
    def deep(self, depth):
        return {"array": "x = " + "[" * depth, "tables": "[" * depth + "a" + "]" * depth,
                "inline": "x = " + "{a = " * depth + "1" + "}" * depth,
                "closed array": "x = " + "[" * depth + "]" * depth}

    def test_load_toml_refuses_it_as_a_value_error(self):
        for what, text in self.deep(200_000).items():
            with self.subTest(what), self.assertRaises(ValueError):
                sca.load_toml(text)

    def test_what_is_nested_but_not_too_deeply_is_read(self):
        self.assertEqual(sca.load_toml("x = [[[1]]]\n"), {"x": [[[1]]]})
        self.assertEqual(sca.load_toml("x = {a = {b = 1}}\n"), {"x": {"a": {"b": 1}}})

    def test_every_toml_reader_of_the_inventory_warns_and_goes_on(self):
        text = ("x = " + "[" * 100_000 + "\n").encode("ascii")
        for name in ("uv.lock", "poetry.lock", "pylock.toml", "pyproject.toml"):
            with self.subTest(name):
                warned = sca._Warnings()
                root = self.project({name: text, "requirements.txt": b"six==1.16.0\n"})
                inventory = sca.scan_pypi_declared(root, warned)
                self.assertEqual([(n, v) for e, n, v, w in inventory], [("six", "1.16.0")])
                self.assertEqual(warned.counts, {f"unparseable {name} file(s)": 1})

    def test_the_guards_uv_lock_reader_gets_no_packages_from_it(self):
        from lazaret.registry import guard
        self.assertEqual(guard.uv_lock_packages("x = " + "[" * 100_000), [])


class SetupPyWarnings(Case):
    TEXT = ('"""Matches \\d+ and \\w."""\n'
            "from setuptools import setup\n"
            "setup(name='x', install_requires=['six==1.16.0', 'a\\d==1'])\n")

    def test_no_warning_is_raised_or_printed(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            reqs = sca._setup_py_requirements(self.TEXT)
        self.assertEqual(caught, [])
        self.assertEqual(reqs, (["six==1.16.0", "a\\d==1"], True))

    def test_the_answer_does_not_depend_on_the_warning_filters(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            strict = sca._setup_py_requirements(self.TEXT)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            quiet = sca._setup_py_requirements(self.TEXT)
        self.assertEqual(strict, quiet)

    def test_the_filters_of_the_caller_are_left_as_they_were(self):
        with warnings.catch_warnings():
            warnings.simplefilter("error", SyntaxWarning)
            before = list(warnings.filters)
            sca._setup_py_requirements(self.TEXT)
            self.assertEqual(warnings.filters, before)

    def test_a_python_2_setup_py_is_still_read_by_its_tokens(self):
        text = "print 'x'\nsetup(install_requires=['six==1.16.0', 'a\\d'])\n"
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertEqual(sca._setup_py_requirements(text), (["six==1.16.0", "a\\d"], True))
        self.assertEqual(caught, [])


if __name__ == "__main__":
    unittest.main()
