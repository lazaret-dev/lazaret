"""FP-GRADLE-WRAPPER in the registry scan: a release's `gradle/wrapper/gradle-wrapper.jar` is judged by its checksum,
with the `gradle-wrapper.properties` beside it wherever the archive holds it (after the jar too: the jars are judged
once every member is read), in an sdist, a wheel and an npm tarball (React Native libraries ship their Android
project's wrapper); and in a GitHub scan's verdict (ghdiscover.result over the project scan of a checkout).

A genuine wrapper is quiet; a changed one is SC-GRADLE-WRAPPER, CRITICAL; one for what may be the next release of
Gradle, newer than the list knows, is MAJOR (can't be verified). The genuine jars are tests/fixtures/gradle-wrapper's; the changed ones are made here.
Inert: nothing is run.
"""
import os
import shutil
import tempfile
import types
import unittest
from unittest import mock

from tests._support import native_rel
from tests.registry._review_support import scan_npm, scan_sdist, scan_wheel
from tests.scanner.test_review_gradle_wrapper import (JAR, PROPS, genuine, hostile, next_release, one_byte, props,
                                                      with_class)

SETUP = "from setuptools import setup\nsetup(name='x')\n"
WHEEL_META = {"x-1.0.dist-info/METADATA": "Name: x\nVersion: 1.0\n"}
NPM = '{"name": "x", "version": "1.0.0", "main": "index.js"}'


def kinds():
    """(scan, its base files) for an sdist, a wheel and an npm tarball."""
    return ((scan_sdist, {"setup.py": SETUP, "x/__init__.py": ""}),
            (scan_wheel, {"x/__init__.py": "", **WHEEL_META}),
            (scan_npm, {"package.json": NPM, "index.js": "1;\n"}))


def found(res):
    return sorted((i["file"], i["rule"], i["sev"]) for i in res["issues"] if i["rule"].startswith("SC-"))


class Releases(unittest.TestCase):
    def test_genuine_wrappers_are_quiet(self):
        for scan_, base in kinds():
            for v, dist in (("4.10.3", "4.10.3"), ("8.14", "9.4.1"), ("9.8", "9.8.1")):
                with self.subTest(scan=scan_.__name__, v=v):
                    # (the properties after the jar, as an archive may hold them)
                    res = scan_({**base, f"x/android/{JAR}": genuine(v), f"x/android/{PROPS}": props(dist)})
                    self.assertEqual(found(res), [], res["issues"])
                    self.assertEqual(res["verdict"], "OK", res["verdictReason"])
                    self.assertEqual(res["binaryArtifacts"], 0)

    def test_changed_wrappers_are_critical(self):
        for scan_, base in kinds():
            for jar in (one_byte(genuine("9.8")), with_class(genuine("8.14"))):
                res = scan_({**base, f"x/{PROPS}": props("9.8.1"), f"x/{JAR}": jar})
                self.assertEqual(found(res), [(f"x/{JAR}", "SC-GRADLE-WRAPPER", "CRITICAL")])
                self.assertNotEqual(res["verdict"], "OK")

    def test_newer_than_the_list_is_major(self):
        for scan_, base in kinds():
            res = scan_({**base, f"x/{JAR}": one_byte(genuine("9.8")), f"x/{PROPS}": props(next_release())})
            self.assertEqual(found(res), [(f"x/{JAR}", "SC-GRADLE-WRAPPER", "MAJOR")])
            self.assertEqual(res["verdict"], "WARN", res["verdictReason"])
            # a version no next release has: a changed wrapper
            res = scan_({**base, f"x/{JAR}": one_byte(genuine("9.8")), f"x/{PROPS}": props("99.0")})
            self.assertEqual(found(res), [(f"x/{JAR}", "SC-GRADLE-WRAPPER", "CRITICAL")])

    def test_another_place_or_name_is_any_jar(self):
        jar = one_byte(genuine("9.8"))
        res = scan_npm({"package.json": NPM, "index.js": "1;\n", "x/libs/gradle-wrapper.jar": jar,
                        "x/gradle/wrapper/wrapper.jar": jar})
        self.assertEqual(found(res), [("x/gradle/wrapper/wrapper.jar", "SC-BINARY", "MAJOR"),
                                      ("x/libs/gradle-wrapper.jar", "SC-BINARY", "MAJOR")])

    def test_past_the_member_limit(self):
        # not read whole: can't be verified, unless it is larger than any wrapper jar of Gradle's (the member limit,
        # 16 MB unless lowered, is far above GRADLE_WRAPPER_MAX_BYTES, 1 MiB)
        from lazaret.registry import repo
        for limit, jar, sev in ((8192, genuine("9.8"), "MAJOR"), (1 << 20, genuine("9.8") + bytes(2 << 20), "CRITICAL")):
            with mock.patch.object(repo, "MAX_MEMBER", limit):
                for scan_, base in kinds():
                    res = scan_({**base, f"x/{JAR}": jar, f"x/{PROPS}": props("9.8.1")})
                    self.assertEqual(found(res), [(f"x/{JAR}", "SC-GRADLE-WRAPPER", sev)], (limit, scan_.__name__))


    def test_properties_as_java_reads_them(self):
        # (the re-review of Oct 27, N3) a genuine jar with properties whose last distributionUrl, as Java reads it, is
        # plain HTTP; past the bytes read; past the member limit, not read whole: MAJOR, never quiet
        from lazaret.registry import repo
        for scan_, base in kinds():
            for how in ("escape", "crlf", "long"):
                res = scan_({**base, f"x/{JAR}": genuine("8.14"), f"x/{PROPS}": hostile(how)})
                self.assertEqual(found(res), [(f"x/{JAR}", "SC-GRADLE-WRAPPER", "MAJOR")], (scan_.__name__, how))
            self.assertEqual(found(scan_({**base, f"x/{JAR}": genuine("8.14"), f"x/{PROPS}": hostile("fits")})), [])
            with mock.patch.object(repo, "MAX_MEMBER", 60_000):
                res = scan_({**base, f"x/{JAR}": genuine("8.14"), f"x/{PROPS}": hostile("fits")})
            self.assertEqual(found(res), [(f"x/{JAR}", "SC-GRADLE-WRAPPER", "MAJOR")], scan_.__name__)
            self.assertIn("larger than the member size limit",
                          next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER"))


class GitHubScans(unittest.TestCase):
    """A repository's checkout scanned as a project, its verdict decided as a registry's (ghdiscover.result). Its
    findings are at the checkout's files' paths, as a project scan reports them (os.sep-separated: `native_rel`)."""

    def verdict(self, files):
        from lazaret.registry import ghdiscover
        root = tempfile.mkdtemp(prefix="lz-gh-gradle-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, data in files.items():
            path = os.path.join(root, *rel.split("/"))
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(data.encode() if isinstance(data, str) else data)
        ck = types.SimpleNamespace(root=root, commit="0" * 40, bytes=0, files=len(files), incomplete=[], calls=[],
                                   skipped=[], twins=[], overlaid={})
        res = ghdiscover.result("owner/repo", ck)
        return res["verdict"], found(res)

    def test_a_gradle_project(self):
        base = {"build.gradle": "plugins { id 'java' }\n", "README.md": "# x\n", PROPS: props("9.8.1")}
        jar = native_rel(JAR)
        self.assertEqual(self.verdict({**base, JAR: genuine("9.8")}), ("OK", []))
        verdict, got = self.verdict({**base, JAR: with_class(genuine("9.8"))})
        self.assertEqual(got, [(jar, "SC-GRADLE-WRAPPER", "CRITICAL")])
        self.assertNotEqual(verdict, "OK")
        self.assertEqual(self.verdict({**base, PROPS: props(next_release()), JAR: one_byte(genuine("9.8"))}),
                         ("WARN", [(jar, "SC-GRADLE-WRAPPER", "MAJOR")]))
        # a genuine wrapper whose distribution comes over plain HTTP
        http = props("9.8.1").replace("https\\://services.gradle.org", "http\\://192.0.2.1")
        self.assertEqual(self.verdict({**base, PROPS: http, JAR: genuine("9.8")}), ("WARN", [(jar, "SC-GRADLE-WRAPPER", "MAJOR")]))
        # (the re-review of Oct 27, N3) the distribution Java reads: an escaped key, a continuation across a CRLF
        for how in ("escape", "crlf", "long"):
            self.assertEqual(self.verdict({**base, PROPS: hostile(how), JAR: genuine("8.14")}),
                             ("WARN", [(jar, "SC-GRADLE-WRAPPER", "MAJOR")]), how)


if __name__ == "__main__":
    unittest.main()
