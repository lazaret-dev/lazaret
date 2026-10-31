"""scripts/update_gradle_wrapper_checksums.py (FP-GRADLE-WRAPPER): the script that refreshes the rule pack's list of
Gradle's wrapper checksums. The tests never touch the network: a fake opener answers as services.gradle.org does (its
versions list, each version's .sha256, the jar), and lies where a test needs it to. They check that the pack's list
is well formed (--check), that a refresh adds what Gradle publishes and verifies each new jar against its checksum,
and that it refuses what it must: a host off Gradle's, a redirect elsewhere, a checksum that is not one, a jar that
does not hash to it, a release whose checksum changed, a version that disappeared, a version not in Gradle's form. The
versions Gradle publishes no checksum for come from versions/all too (the review of Oct 27), with the list's date.
"""
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
import zipfile

from tests import _support

upd = _support.load_script(os.path.join(_support.REPO_ROOT, "scripts", "update_gradle_wrapper_checksums.py"),
                           "update_gradle_wrapper_checksums")


def jar(tag):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", f"Manifest-Version: 1.0\nX-Tag: {tag}\n")
    return out.getvalue()


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpener:
    """services.gradle.org as a dict: url -> bytes (an Exception to raise)."""

    def __init__(self, pages):
        self.pages = pages
        self.asked = []

    def open(self, req, timeout=None):
        url = req.full_url
        self.asked.append(url)
        page = self.pages.get(url)
        if page is None:
            raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
        if isinstance(page, Exception):
            raise page
        return FakeResponse(page)


BASE = "https://services.gradle.org/distributions/"


def gradle(versions, extra=()):
    """The pages for `versions` (version -> jar bytes), and the versions list naming them (with `extra` entries)."""
    pages, entries = {}, []
    for v, j in versions.items():
        url = f"{BASE}gradle-{v}-wrapper.jar.sha256"
        pages[url] = hashlib.sha256(j).hexdigest().encode() + b"\n"
        pages[url[:-len(".sha256")]] = j
        entries.append({"version": v, "snapshot": False, "nightly": False, "wrapperChecksumUrl": url})
    entries.extend(extra)
    pages[upd.VERSIONS_URL] = json.dumps(entries).encode()
    return pages


class Pack:
    """A copy of the repository's pack to refresh."""

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="lz-gradle-pack-")
        self.path = os.path.join(self.dir, "lazaret-rules.json")
        shutil.copy(upd.PACK, self.path)
        return self

    def __exit__(self, *a):
        shutil.rmtree(self.dir, ignore_errors=True)

    def checksums(self):
        return upd.current(upd.read_pack(self.path))


class TheShippedList(unittest.TestCase):
    def test_check_passes(self):
        self.assertEqual(upd.main(["--check"]), 0)

    def test_it_is_gradles(self):
        pack = upd.read_pack()
        got = upd.current(pack)
        self.assertGreaterEqual(len(got), 300)
        none = upd.no_checksum(pack)
        self.assertEqual(upd.check(got, none, pack["values"][upd.DATE_KEY]["value"]), [])
        # 3.3 to 4.0.2 and their candidates: no checksum, and none in the list
        for v in ("3.3", "3.4.1", "3.5-rc-2", "4.0-milestone-1", "4.0.2"):
            self.assertIn(v, none)
        self.assertEqual(upd.check(got, ["8.14"]), ["8.14 has a checksum and is listed as having none"])
        # the genuine jars of tests/fixtures/gradle-wrapper are in it
        fix = os.path.join(_support.REPO_ROOT, "tests", "fixtures", "gradle-wrapper")
        for v in ("4.10.3", "8.14", "9.8"):
            with open(os.path.join(fix, v, "gradle", "wrapper", "gradle-wrapper.jar"), "rb") as f:
                self.assertIn(hashlib.sha256(f.read()).hexdigest(), set(got.values()), v)
        self.assertIn("gradle/actions", pack["values"][upd.SOURCE_KEY]["value"])


class Refresh(unittest.TestCase):
    def test_new_releases_are_added_and_their_jars_verified(self):
        with Pack() as p:
            old = p.checksums()
            new_jar = jar("99.0")
            pages = gradle({**{v: None for v in []}, "99.0": new_jar, "99.0-rc-1": new_jar})
            # every listed version is published as before (their jars are not downloaded again)
            for v, c in old.items():
                url = f"{BASE}gradle-{v}-wrapper.jar.sha256"
                pages[url] = c.encode()
            listed = json.loads(pages[upd.VERSIONS_URL])
            listed += [{"version": v, "wrapperChecksumUrl": f"{BASE}gradle-{v}-wrapper.jar.sha256"} for v in old]
            listed += [{"version": "99.1-20261022000000+0000", "snapshot": True, "wrapperChecksumUrl": BASE + "x"}]
            listed += [{"version": v} for v in ("3.4", "3.4-rc-1", "4.0.2")]           # (no wrapperChecksumUrl)
            pages[upd.VERSIONS_URL] = json.dumps(listed).encode()
            opener = FakeOpener(pages)
            self.assertEqual(upd.main(["--pack", p.path], opener=opener, today="2026-10-21"), 0)
            got = p.checksums()
            self.assertEqual(got["99.0"], hashlib.sha256(new_jar).hexdigest())
            self.assertEqual({k: v for k, v in got.items() if k not in ("99.0", "99.0-rc-1")}, old)
            jars = [u for u in opener.asked if u.endswith(".jar")]
            self.assertEqual(sorted(jars), [f"{BASE}gradle-99.0-rc-1-wrapper.jar", f"{BASE}gradle-99.0-wrapper.jar"])
            pack = upd.read_pack(p.path)
            self.assertIn("2026-10-21", pack["values"][upd.SOURCE_KEY]["value"])
            self.assertEqual(pack["values"][upd.DATE_KEY]["value"], "2026-10-21")
            self.assertEqual(upd.no_checksum(pack), ["3.4", "3.4-rc-1", "4.0.2"])

    def refused(self, pages, *args):
        with Pack() as p:
            before = open(p.path, "rb").read()
            self.assertEqual(upd.main(["--pack", p.path, "--prune", *args], opener=FakeOpener(pages)), 1)
            self.assertEqual(open(p.path, "rb").read(), before)

    def test_a_jar_that_does_not_hash_to_its_checksum(self):
        pages = gradle({"99.0": jar("a")})
        pages[f"{BASE}gradle-99.0-wrapper.jar"] = jar("b")
        self.refused(pages)

    def test_a_checksum_that_is_not_one(self):
        pages = gradle({"99.0": jar("a")})
        pages[f"{BASE}gradle-99.0-wrapper.jar.sha256"] = b"<html>not found</html>"
        self.refused(pages)

    def test_a_host_off_gradles(self):
        pages = gradle({}, extra=[{"version": "99.0", "wrapperChecksumUrl": "https://example.invalid/x.sha256"}])
        self.refused(pages)

    def test_a_redirect_off_gradles(self):
        handler = upd._SameHost()
        req = upd.urllib.request.Request(upd.VERSIONS_URL)
        with self.assertRaises(upd.Refused):
            handler.redirect_request(req, None, 302, "Found", {}, "https://example.invalid/all")
        with self.assertRaises(upd.Refused):
            handler.redirect_request(req, None, 302, "Found", {}, "http://services.gradle.org/versions/all")
        self.assertIsNotNone(handler.redirect_request(req, None, 302, "Found", {}, "https://github.com/gradle/x"))

    def test_a_version_not_in_gradles_form(self):
        self.refused(gradle({"99.0 && curl": jar("a")}))

    def test_a_release_whose_checksum_changed(self):
        with Pack() as p:
            old = p.checksums()
            v = sorted(old)[0]
            pages = gradle({v: jar("changed")})
            self.assertEqual(upd.main(["--pack", p.path], opener=FakeOpener(pages)), 1)

    def test_a_version_that_disappeared(self):
        with Pack() as p:
            self.assertEqual(upd.main(["--pack", p.path], opener=FakeOpener(gradle({"99.0": jar("a")}))), 1)

    def test_from_json(self):
        with Pack() as p, tempfile.TemporaryDirectory() as d:
            old = p.checksums()
            src = os.path.join(d, "wrapper-checksums.json")
            with open(src, "w", encoding="utf-8") as f:
                json.dump([{"version": v, "checksum": c} for v, c in old.items()], f)
            none = upd.no_checksum(upd.read_pack(p.path))
            self.assertEqual(upd.main(["--pack", p.path, "--from-json", src, "--source", "test", "--date",
                                       "2026-10-20"]), 0)
            self.assertEqual(p.checksums(), old)
            self.assertEqual(upd.no_checksum(upd.read_pack(p.path)), none)
            with open(src, "w", encoding="utf-8") as f:
                json.dump([{"version": "1.0", "checksum": "zz"}], f)
            self.assertEqual(upd.main(["--pack", p.path, "--from-json", src]), 1)


if __name__ == "__main__":
    unittest.main()
