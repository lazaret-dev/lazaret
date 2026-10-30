"""FP-GRADLE-WRAPPER (John's approval of Oct 21: "Yes, check checksums"): a Gradle wrapper jar is judged by its
content, as Gradle's own wrapper validation judges it, in a project scan, with --deps and in the registry.

SC-BINARY (MAJOR: WARN) reported every `gradle/wrapper/gradle-wrapper.jar`, which nearly every Gradle project commits
(John's fp-tally: 9 WARN verdicts SC-BINARY set, 3 by it alone). `./gradlew` runs the jar, which is why Gradle
publishes each release's wrapper checksum: a jar there whose SHA-256 is one of them (GRADLE_WRAPPER_CHECKSUMS, the
pack's list, from gradle/actions' wrapper-checksums.json) is quiet; one that matches none is SC-GRADLE-WRAPPER,
CRITICAL, a changed wrapper; one the list cannot judge yet is MAJOR, and only that (the review of Oct 27): a wrapper
jar whose gradle-wrapper.properties (its last distributionUrl, as Java reads it) names what may be the next release,
newer than the list (Gradle's release form, a couple of patches, minors or the next major past the list's newest; a
nightly no older than the list); a Git LFS pointer, not the jar; a jar whose manifest names a version Gradle publishes
no checksum for (3.3 to 4.0.2). Any other version is CRITICAL. A genuine wrapper whose distribution comes over plain
HTTP is MAJOR, and from another host with no checksum, INFO. A jar elsewhere or under another name is SC-BINARY, as
any jar is.

The genuine jars (tests/fixtures/gradle-wrapper) are Gradle's own, as three open-source projects commit them
(butterknife: 4.10.3; mockito: 8.14.x; RxJava: 9.8.x); the changed ones are made here (a byte changed, a class
added). Inert: nothing is run.
"""
import io
import json
import os
import re
import shutil
import tempfile
import unittest
import zipfile
from unittest import mock

from lazaret.scanner import core

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(HERE))), "tests", "fixtures", "gradle-wrapper")
JAR, PROPS = "gradle/wrapper/gradle-wrapper.jar", "gradle/wrapper/gradle-wrapper.properties"


def genuine(version):
    with open(os.path.join(FIX, version, *JAR.split("/")), "rb") as f:
        return f.read()


def props(version):
    return ("distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\n"
            f"distributionUrl=https\\://services.gradle.org/distributions/gradle-{version}-bin.zip\n"
            "zipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n")


def newest():
    """The (major, minor) of the newest release in the pack's list of Gradle's checksums."""
    pack = os.path.join(os.path.dirname(FIX), "..", "..", "rust", "crates", "lazaret-engine", "rules", "lazaret-rules.json")
    with open(pack, encoding="utf-8") as f:
        versions = json.load(f)["values"]["GRADLE_WRAPPER_CHECKSUMS"]["map"]
    return max(tuple(int(n) for n in v.split("-")[0].split(".")[:2]) for v in versions)


def next_release():
    """A release that may come next, newer than the list: the next major's first."""
    return f"{newest()[0] + 1}.0"


def with_manifest(jar, version):
    """The jar with its manifest naming Gradle `version` (as the wrappers Gradle 4.x and older wrote say theirs)."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(jar)) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            data = src.read(info)
            if info.filename == "META-INF/MANIFEST.MF":
                data = re.sub(rb"Implementation-Version: [^\r\n]*", b"Implementation-Version: " + version.encode(), data)
                if b"Implementation-Version" not in data:
                    data = data.rstrip(b"\r\n") + b"\nImplementation-Title: Gradle\nImplementation-Version: " \
                        + version.encode() + b"\n"
            dst.writestr(info, data)
    return out.getvalue()


def one_byte(jar):
    k = len(jar) // 2
    return jar[:k] + bytes([jar[k] ^ 1]) + jar[k + 1:]


def with_class(jar):
    """The jar with one more class (inert bytes), as a changed wrapper carries its own code."""
    buf = io.BytesIO(jar)
    out = io.BytesIO()
    with zipfile.ZipFile(buf) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            dst.writestr(info, src.read(info))
        dst.writestr("org/gradle/wrapper/Extra.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + bytes(40))
    return out.getvalue()


def tree(files):
    root = tempfile.mkdtemp(prefix="lz-gradle-")
    for rel, data in files.items():
        path = os.path.join(root, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data.encode() if isinstance(data, str) else data)
    return root


def scan(files, **kw):
    root = tree(files)
    try:
        return core.scan_project(root, **kw)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def found(res):
    return {(i["file"].replace(os.sep, "/"), i["rule"], i["sev"]) for i in res["issues"] if i["rule"].startswith("SC-")}


class TheFalsePositive(unittest.TestCase):
    def test_genuine_wrappers_are_quiet(self):
        for v, dist in (("4.10.3", "4.10.3"), ("8.14", "9.4.1"), ("9.8", "9.8.1")):
            with self.subTest(v=v):
                res = scan({JAR: genuine(v), PROPS: props(dist), "build.gradle": "plugins { id 'java' }\n"})
                self.assertEqual(found(res), set(), res["issues"])
                self.assertEqual(res["supplyChain"], 0)


class ChangedWrappers(unittest.TestCase):
    def test_a_byte_changed_or_a_class_added_is_critical(self):
        for jar in (one_byte(genuine("9.8")), with_class(genuine("8.14"))):
            res = scan({JAR: jar, PROPS: props("9.8.1")})
            self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")})
            msg = next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER")
            self.assertIn("matches none of Gradle's published wrapper checksums", msg)
            self.assertIn("Gradle 9.8.1", msg)

    def test_no_properties_is_critical(self):
        self.assertEqual(found(scan({JAR: one_byte(genuine("9.8"))})), {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")})

    def test_newer_than_the_list_is_major(self):
        major, minor = newest()
        for dist in (next_release(), f"{major}.{minor + 1}", f"{major}.{minor + 2}.0-rc-1"):
            res = scan({JAR: one_byte(genuine("9.8")), PROPS: props(dist)})
            self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")}, dist)
            self.assertIn("newer than Lazaret's list of Gradle's checksums",
                          next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER"))

    def test_any_other_version_is_critical(self):
        # (the review of Oct 27: a version no next release has, a version of no form of Gradle's, the first of two
        # distributionUrl lines when the last is listed, what is not a wrapper jar at the wrapper's place)
        jar = one_byte(genuine("9.8"))
        major, _ = newest()
        for dist in ("99.0", "999999999.0", "8.14.99", "9.8.99", f"{major + 2}.0", f"{major + 1}.2", "1.0-00000000000000+0000"):
            res = scan({JAR: jar, PROPS: props(dist)})
            self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")}, dist)
        two = props(next_release()) + props("9.8.1").split("distributionPath=wrapper/dists\n")[1]
        self.assertEqual(found(scan({JAR: jar, PROPS: two})), {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")})
        elf = b"\x7fELF\x02\x01\x01\x00" + bytes(60000)
        self.assertEqual(found(scan({JAR: elf, PROPS: props(next_release())})), {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")})

    def test_a_manifest_naming_a_version_without_a_checksum(self):
        # Gradle 3.3 to 4.0.2 publish none: can't be verified; another unlisted version in a manifest is no excuse
        jar = genuine("4.10.3")
        self.assertEqual(found(scan({JAR: with_manifest(jar, "3.4"), PROPS: props("3.4")})),
                         {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")})
        for v in ("99.0", "8.14.99"):
            self.assertEqual(found(scan({JAR: with_manifest(jar, v), PROPS: props("8.14")})),
                             {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")}, v)

    def test_a_listed_distribution_and_a_newer_manifest(self):
        # (the review of Oct 27) properties pinned to a listed version: the jar's manifest names the release it may
        # be; one that may come next can't be verified, another is a changed wrapper's, and so is a jar the
        # properties name no distribution for
        jar = genuine("9.8")
        major, minor = newest()
        for v in (next_release(), f"{major}.{minor + 1}"):
            res = scan({JAR: with_manifest(jar, v), PROPS: props("9.8.1")})
            self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")}, v)
            self.assertIn("its manifest", next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER"))
        for v in ("99.0", "9.8", f"{major}.{minor + 1}-custom"):
            self.assertEqual(found(scan({JAR: with_manifest(jar, v), PROPS: props("9.8.1")})),
                             {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")}, v)
        self.assertEqual(found(scan({JAR: with_manifest(jar, next_release())})), {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")})

    def test_a_genuine_wrappers_distribution(self):
        # ./gradlew downloads and runs it: plain HTTP is MAJOR, another host with no checksum INFO, with one quiet
        jar = genuine("8.14")
        http = props("8.14").replace("https\\://services.gradle.org", "http\\://192.0.2.1")
        mirror = props("8.14").replace("services.gradle.org", "repo.example.invalid")
        self.assertEqual(found(scan({JAR: jar, PROPS: http})), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")})
        res = scan({JAR: jar, PROPS: mirror})
        self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "INFO")})
        self.assertIn("repo.example.invalid", next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER"))
        self.assertEqual(found(scan({JAR: jar, PROPS: mirror + "distributionSha256Sum=" + "0" * 64 + "\n"})), set())

    def test_elsewhere_or_another_name_is_any_jar(self):
        jar = one_byte(genuine("9.8"))
        # (a folder named otherwise, `gradle/Wrapper/`, is the engine's tests': a case-insensitive disk has one)
        res = scan({"libs/gradle-wrapper.jar": jar, "gradle/wrapper/other.jar": jar,
                    "wrapper/gradle-wrapper.jar": jar, "lib/gradle/wrapper/gradle-wrapper.jar": genuine("9.8")})
        self.assertEqual(found(res), {("libs/gradle-wrapper.jar", "SC-BINARY", "MAJOR"),
                                      ("gradle/wrapper/other.jar", "SC-BINARY", "MAJOR"),
                                      ("wrapper/gradle-wrapper.jar", "SC-BINARY", "MAJOR")})


class WhatTheListCannotJudge(unittest.TestCase):
    def test_a_nightly(self):
        res = scan({JAR: one_byte(genuine("9.8")), PROPS: props("9.9-20261022000000+0000")})
        self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")})

    def test_a_git_lfs_pointer(self):
        lfs = ("version https://git-lfs.github.com/spec/v1\n"
               "oid sha256:3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98\nsize 48749\n")
        self.assertEqual(found(scan({JAR: lfs, PROPS: props("9.8.1")})), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")})

    def test_over_the_size_limit(self):
        with mock.patch.object(core, "SOURCE_SIZE_CAP", 4096):
            res = scan({JAR: genuine("9.8"), PROPS: props("9.8.1")})
            self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")})
            self.assertIn("not read whole", next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER"))
            # larger than any wrapper jar of Gradle's: a changed one
            res = scan({JAR: genuine("9.8") + bytes(2 << 20), PROPS: props("9.8.1")})
            self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "CRITICAL")})


def hostile(how):
    """Properties whose distribution Java reads as plain HTTP where a reader unlike Java's saw Gradle's (the re-review
    of Oct 27, N3): a key written with an escape, a continuation across a CRLF, a file past the bytes read; and one
    that is exactly as long as the bytes read, which is read."""
    https = "https\\://services.gradle.org/distributions/gradle-8.14-bin.zip"
    http = "http\\://192.0.2.1/gradle-8.14-bin.zip"
    if how == "escape":
        return f"distributionUrl={https}\n\\u0064istributionUrl={http}\n"
    if how == "crlf":
        return f"distributionUrl={http}\r\nzipStorePath=wrapper/dists\\\r\ndistributionUrl={https}\r\n"
    head = f"distributionUrl={https}\n"
    if how == "long":
        return head + "#" * (65536 - len(head)) + f"\ndistributionUrl={http}\n"
    return head + "#" * (65536 - len(head))


class AsJavaReadsTheProperties(unittest.TestCase):
    """The re-review of Oct 27 (N3): a genuine jar is judged by the distribution Java reads, and is MAJOR (can't be
    verified) when its properties can't be read as Java reads them."""

    def test_an_escaped_key_and_a_crlf_continuation(self):
        for how in ("escape", "crlf"):
            res = scan({JAR: genuine("8.14"), PROPS: hostile(how)})
            self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")}, how)
            self.assertIn("plain HTTP", next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER"))

    def test_past_the_bytes_read(self):
        res = scan({JAR: genuine("8.14"), PROPS: hostile("long")})
        self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")})
        msg = next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER")
        self.assertIn("longer than the 65536 bytes", msg)
        self.assertEqual(found(scan({JAR: genuine("8.14"), PROPS: hostile("fits")})), set())

    def test_a_symbolic_link_java_follows(self):
        # Where a file is opened beneath the root's folders with no link followed, the scan does not read the
        # properties a link names: the jar can't be verified. Where a file is opened by its path (Windows: no such
        # open), the link is followed and what it reaches kept only when it is under the root (core._open_verified):
        # the properties judged are those Java reads, genuine or not.
        for target, want in ((props("8.14"), set()), (hostile("crlf"), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")})):
            root = tree({JAR: genuine("8.14"), "elsewhere.properties": target})
            try:
                os.symlink(os.path.join(root, "elsewhere.properties"), os.path.join(root, *PROPS.split("/")))
                res = core.scan_project(root)
            finally:
                shutil.rmtree(root, ignore_errors=True)
            with self.subTest(target=target.splitlines()[0]):
                if core._ANCHORED_OPEN:
                    self.assertEqual(found(res), {(JAR, "SC-GRADLE-WRAPPER", "MAJOR")})
                    self.assertIn("was not read",
                                  next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER"))
                else:
                    self.assertEqual(found(res), want)
                    if want:
                        self.assertIn("plain HTTP",
                                      next(i["msg"] for i in res["issues"] if i["rule"] == "SC-GRADLE-WRAPPER"))


class Dependencies(unittest.TestCase):
    def test_with_deps(self):
        base = {"app.js": "require('rnlib')\n", "package.json": '{"dependencies": {"rnlib": "1.0.0"}}',
                "node_modules/rnlib/package.json": '{"name": "rnlib", "version": "1.0.0"}',
                "node_modules/rnlib/index.js": "module.exports = 1\n"}
        res = scan({**base, f"node_modules/rnlib/android/{JAR}": genuine("8.14"),
                    f"node_modules/rnlib/android/{PROPS}": props("8.14")}, include_deps=True)
        self.assertEqual({f for f, _, _ in found(res) if f.startswith("node_modules/")}, set())
        res = scan({**base, f"node_modules/rnlib/android/{JAR}": with_class(genuine("8.14")),
                    f"node_modules/rnlib/android/{PROPS}": props("8.14")}, include_deps=True)
        self.assertIn((f"node_modules/rnlib/android/{JAR}", "SC-GRADLE-WRAPPER", "CRITICAL"), found(res))


if __name__ == "__main__":
    unittest.main()
