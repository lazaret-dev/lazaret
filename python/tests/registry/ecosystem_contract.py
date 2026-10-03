"""The conformance mixin for registry modules (0.1.9, wave 2; `specs/lazaret-registry-module-interface-2026-10-03.md`).

A module's test file subclasses `EcosystemContract` together with `unittest.TestCase`, says what its good names and
recorded responses are, and gets the checks of the six rules for free:

    class CratesContract(EcosystemContract, unittest.TestCase):
        GOOD_NAMES = ("serde", "Foo_Bar")
        ...
        def make(self):
            return crates.Crates()
        def responses(self):
            return {...recorded...}

It is not a test module itself (its name does not start with `test`), so nothing here runs on its own. The same mixin
runs against PyPI and npm in X-2, which is also the proof that wrapping them changed nothing.

What a module's test file supplies (the class attributes and methods below; the ones marked * are required):

    make()*              a new `Ecosystem`
    GOOD_NAMES*          names it accepts; GOOD_VERSIONS* likewise
    GOOD_SPEC*           (name, version) that `responses()` can resolve, and `responses()*` the recorded responses
                         (url -> bytes, or an exception to raise) for that spec and for "latest"
    GOOD_ARCHIVE_MEMBERS member names of the recorded archive of GOOD_SPEC; each must sit under `archive_root`
    DIGEST_COVERS_EVERY_BYTE / changed_downloads(data)   for a digest of an archive's contents and not of its bytes
    verify_case()*       (data, entry, name, version) that verifies, or None if the registry publishes no digest
    SAME_IDENTITY / DIFFERENT_IDENTITY   pairs of names that are, and are not, the same package
    ACCEPTS              entries of HOSTILE_NAMES / HOSTILE_VERSIONS this module legitimately accepts
    EXTRA_BAD_NAMES / EXTRA_BAD_VERSIONS     its own hostile cases
    MEMBER_PATHS         (kind, member, root, (rel, problem)) rows; roots() gives the root per kind
    hostile_responses(url)    `responses()` with the primary artifact's URL in the metadata replaced by `url`, or None
                         when the module builds that URL itself and never reads it from a document
    malformed_digests()  entries whose digest is garbled (from `verify_case`'s entry)
    MISSING_VERSION      a version no recorded response knows

Nothing here opens a socket: the module's `Fetch` gets a recorded transport."""

import posixpath
import re
import threading
import urllib.parse

from lazaret.registry.ecosystems import base

BODY_LIMIT = 600                         # an error message is a sentence, not a copy of the input


def printable(text):
    return isinstance(text, str) and text.isprintable()


# Documents that no registry's metadata can be. Each is given for every URL a resolve asks for.
GARBAGE = (
    b"", b" ", b"\n\n\n", b"null", b"true", b"0", b"NaN", b'""', b"[]", b"{}", b"[1, 2, 3]", b"[[]]", b"[null]",
    b'{"versions": 5}', b'{"versions": []}', b'{"versions": {"1.0.0": 5}}', b'{"versions": {"1.0.0": []}}',
    b'{"info": 5}', b'{"info": {"version": 1}, "urls": 5}', b'{"name": "x", "version": "1", "dist": 5}',
    b'{"dist-tags": 5, "versions": {}}', b'{"Version": ["v1"]}', b'{"Version": "v1", "Time": 5}',
    b'{"vers": "1.0.0", "cksum": 5}\n', b'{"vers": "1.0.0"}\n{"vers": 2}\n', b'[null]\n[null]\n',
    b'{"a": {"b": {"c": null}}}', b'{"versions": {"\\u202e\\u001b[31m": {}}}',
    b'{"Version": "\\u202ev1.0.0\\u001b[2J"}', b'{"vers": "\\u202e1.0.0", "cksum": "\\u001b[2J"}\n',
    b"\xff\xfe\x00", b"\x00" * 100, b"\xe2\x80\xae", b"{", b"[" * 10000, b'{"a":' * 5000,
    b'{"versions": {"1.0.0": {"dist": {"tarball": "javascript:alert(1)"}}}}',
    b'{"versions": {"1.0.0": {"dist": {"tarball": "file:///etc/passwd"}}}}',
)

GARBAGE_TEXT = ("", " ", "\0", "{", "[]", "null", "x" * 100_000, "[" * 5000, "\u202e", "\ud800", "a = ", "[package]",
                "[package]\nname = 5\n", "module\n", "name: x\n", '{"name": 5, "scripts": 5, "dependencies": []}',
                '{"name": "x", "dependencies": {"a": 5}, "scripts": {"install": ["x"]}}')

MEMBER_ATOMS = ("", ".", "..", "/", "//", "\\", "a", "a/b", "../a", "a/../b", "/a", "//a", "C:/a", "C:\\a", "c:a",
                "a\\..\\b", "a/./b", "./a", "a//b", "a/b/", "\0", "a\0b", "\u202e", "%2e%2e/x", "..%2fa", "a" * 5000,
                "../" * 100 + "x", "x/" * 1000, "a/..", "a/../..", "/../a", "~/a", "$HOME/a", "CON", "a:b")

HOSTS_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$")


def _host_of(url):
    parts = urllib.parse.urlsplit(url)
    return (parts.hostname or "").lower()


class EcosystemContract:
    """The checks. A subclass sets the attributes in the module docstring."""

    GOOD_NAMES = ()
    GOOD_VERSIONS = ()
    GOOD_SPEC = None
    SAME_IDENTITY = ()
    DIFFERENT_IDENTITY = ()
    ACCEPTS = ()
    EXTRA_BAD_NAMES = ()
    EXTRA_BAD_VERSIONS = ()
    MEMBER_PATHS = ()
    MISSING_VERSION = "9999.0.0-none"
    GOOD_ARCHIVE_MEMBERS = ()               # member names of the recorded archive of GOOD_SPEC, as they appear in it
    DIGEST_COVERS_EVERY_BYTE = True         # False for a digest of what is in the archive (Go's h1) and not of its bytes

    # ---- what a module's test supplies
    def make(self):
        raise NotImplementedError("make() -> a new Ecosystem")

    def responses(self):
        raise NotImplementedError("responses() -> {url: bytes} for GOOD_SPEC and for its latest version")

    def verify_case(self):
        raise NotImplementedError("verify_case() -> (data, entry, name, version), or None if nothing is published")

    def hostile_responses(self, url):
        return None

    def changed_downloads(self, data):
        """Archives that differ from `data` in what the digest covers (a member changed, added, removed or renamed); the
        module's test supplies them when `DIGEST_COVERS_EVERY_BYTE` is False."""
        return ()

    def malformed_digests(self):
        return ()

    def roots(self):
        return {}

    # ---- plumbing
    def setUp(self):
        super().setUp()
        self.eco = self.make()

    def fetch_for(self, responses, default=None):
        """A `Fetch` over a recorded transport: -> (fetch, the list of URLs the transport was asked for)."""
        asked = []
        lock = threading.Lock()

        def transport(url, *, max_bytes, accept, timeout, check_redirect):
            with lock:
                asked.append(url)
            body = responses.get(url, default)
            if body is None:
                err = base.FetchError("not found")
                err.status = 404
                raise err
            if isinstance(body, BaseException):
                raise body
            return body

        return base.Fetch(self.eco, transport, clock=lambda: 0.0, sleep=lambda s: None), asked

    def resolve_good(self, version="spec"):
        name, good = self.GOOD_SPEC
        fetch, asked = self.fetch_for(self.responses())
        return self.eco.resolve(name, good if version == "spec" else version, fetch), fetch, asked

    def assertRefusal(self, call, exc=base.SpecError):
        """`call()` raises `exc`, and its message is a sentence of printable text, not a copy of the input."""
        try:
            call()
        except exc as caught:
            message = str(caught)
            self.assertTrue(printable(message), repr(message))
            self.assertLessEqual(len(message), BODY_LIMIT, message[:80])
            return caught
        except Exception as other:                                         # (the wrong class)
            self.fail("expected %s, got %s: %s" % (exc.__name__, type(other).__name__, str(other)[:120]))
        self.fail("expected %s, nothing was raised" % exc.__name__)

    # ---- it says what it is
    def test_declares_itself(self):
        e = self.eco
        self.assertRegex(e.id, r"^[a-z][a-z0-9]{1,15}$")
        self.assertTrue(isinstance(e.title, str) and e.title.strip())
        self.assertIsInstance(e.hosts, frozenset)
        self.assertTrue(e.hosts)
        for host in e.hosts:
            self.assertRegex(host, HOSTS_RE, "hosts are lowercase host[:port], no scheme")
            self.assertIn(".", host)
        for host, seconds in e.rate.items():
            self.assertIn(host, e.hosts, "a rate for a host that is not declared")
            self.assertTrue(isinstance(seconds, (int, float)) and 0 < seconds <= 60, seconds)
        self.assertTrue(isinstance(e.artifact_kinds, tuple) and e.artifact_kinds)
        self.assertTrue(all(isinstance(k, str) and k for k in e.artifact_kinds))
        self.assertIsInstance(e.manifest_names, frozenset)
        for name in e.manifest_names:
            self.assertTrue(isinstance(name, str) and name and "\\" not in name and not name.startswith("/"), name)
        for optional in ("dependencies", "discover", "popular_names"):
            self.assertTrue(callable(getattr(e, optional, None)), optional)

    # ---- names
    def test_good_names_are_accepted_and_checking_one_twice_changes_nothing(self):
        self.assertTrue(self.GOOD_NAMES, "the module's test names no good name")
        for name in self.GOOD_NAMES:
            with self.subTest(name=name):
                once = self.eco.check_name(name)
                self.assertIsInstance(once, str)
                self.assertEqual(self.eco.check_name(once), once)
                self.assertEqual(self.eco.identity(once), self.eco.identity(name))
                self.assertEqual(self.eco.identity(self.eco.identity(name)), self.eco.identity(name))

    def test_identity_groups_names_as_the_module_says(self):
        for a, b in self.SAME_IDENTITY:
            with self.subTest(same=(a, b)):
                self.assertEqual(self.eco.identity(a), self.eco.identity(b))
        for a, b in self.DIFFERENT_IDENTITY:
            with self.subTest(different=(a, b)):
                self.assertNotEqual(self.eco.identity(a), self.eco.identity(b))

    def test_hostile_names_are_refused_without_echoing_them(self):
        for name in tuple(base.HOSTILE_NAMES) + tuple(self.EXTRA_BAD_NAMES):
            if name in self.ACCEPTS:
                continue
            with self.subTest(name=name[:40]):
                self.assertRefusal(lambda: self.eco.check_name(name))
                self.assertRefusal(lambda: self.eco.identity(name))
                self.assertRefusal(lambda: self.eco.parse_spec(name))
                self.assertRefusal(lambda: self.eco.parse_spec(name + "@" + self.GOOD_VERSIONS[0]))

    def test_names_that_are_not_text_are_refused(self):
        for value in (None, 5, 1.5, b"name", ["name"], ("a", "b"), {"a": 1}, object(), True):
            with self.subTest(value=type(value).__name__):
                self.assertRefusal(lambda: self.eco.check_name(value))

    def test_a_refusal_never_contains_what_made_it_hostile(self):
        for name in tuple(base.HOSTILE_NAMES) + tuple(self.EXTRA_BAD_NAMES):
            if name in self.ACCEPTS:
                continue
            caught = self.assertRefusal(lambda: self.eco.check_name(name))
            message = str(caught)
            for ch in set(name):
                if not ch.isprintable():
                    self.assertNotIn(ch, message, "a control, bidi or zero-width character came back in a message")
            if len(name) > 200:
                self.assertNotIn(name[:200], message)

    # ---- versions
    def test_good_versions_are_accepted_and_none_means_latest(self):
        self.assertTrue(self.GOOD_VERSIONS, "the module's test names no good version")
        for version in self.GOOD_VERSIONS:
            with self.subTest(version=version):
                self.assertEqual(self.eco.check_version(version), version)
                self.assertEqual(self.eco.check_version("  " + version + " "), version, "surrounding space is dropped")
        self.assertIsNone(self.eco.check_version(None))

    def test_hostile_versions_are_refused_without_echoing_them(self):
        for version in tuple(base.HOSTILE_VERSIONS) + tuple(self.EXTRA_BAD_VERSIONS):
            if version in self.ACCEPTS:
                continue
            with self.subTest(version=version[:40]):
                caught = self.assertRefusal(lambda: self.eco.check_version(version))
                for ch in set(version):
                    if not ch.isprintable():
                        self.assertNotIn(ch, str(caught))
                self.assertRefusal(lambda: self.eco.parse_spec(self.GOOD_NAMES[0] + "@" + version))

    def test_versions_that_are_not_text_are_refused(self):
        for value in (5, 1.5, b"1.0", ["1.0"], {"a": 1}, object(), True, False, 0):
            with self.subTest(value=type(value).__name__ + repr(value)[:10]):
                self.assertRefusal(lambda: self.eco.check_version(value))

    # ---- specs
    def test_a_spec_is_a_name_and_perhaps_a_version(self):
        name, version = self.GOOD_NAMES[0], self.GOOD_VERSIONS[0]
        self.assertEqual(self.eco.parse_spec(name), (self.eco.check_name(name), None))
        self.assertEqual(self.eco.parse_spec(name + "@" + version), (self.eco.check_name(name), version))
        self.assertEqual(self.eco.parse_spec("  %s@%s  " % (name, version)), (self.eco.check_name(name), version))
        for name in self.GOOD_NAMES:
            with self.subTest(name=name):
                got_name, got_version = self.eco.parse_spec(name)
                self.assertEqual((got_name, got_version), (self.eco.check_name(name), None))

    def test_a_spec_with_nothing_after_the_at_sign_or_nothing_before_it_is_refused(self):
        name = self.GOOD_NAMES[0]
        for spec in (name + "@", "@", "@@", name + "@@1", name + "@ ", "@" + self.GOOD_VERSIONS[0], ""):
            with self.subTest(spec=spec):
                self.assertRefusal(lambda: self.eco.parse_spec(spec))
        for value in (None, 5, b"x@1", ["x"]):
            with self.subTest(value=type(value).__name__):
                self.assertRefusal(lambda: self.eco.parse_spec(value))

    # ---- a name in a URL
    def test_a_checked_name_and_version_cannot_change_where_a_url_goes(self):
        host = sorted(self.eco.hosts)[0]
        for value in tuple(self.GOOD_NAMES) + tuple(self.GOOD_VERSIONS):
            with self.subTest(value=value):
                seg = self.eco.segment(value)
                self.assertIsInstance(seg, str)
                self.assertTrue(seg)
                self.assertTrue(seg.isascii() and seg.isprintable() and " " not in seg, repr(seg))
                for bad in "?#\\@ ":
                    self.assertNotIn(bad, seg)
                self.assertNotIn("//", seg)
                self.assertFalse({".", ".."} & set(seg.split("/")), "a dot segment")
                self.assertNotIn("%2e%2e", seg.lower())
                parts = urllib.parse.urlsplit("https://%s/%s" % (host, seg))
                self.assertEqual((parts.hostname, parts.query, parts.fragment, parts.username),
                                 (host.split(":")[0], "", "", None))

    # ---- resolve
    def check_resolution(self, res, asked):
        self.assertIsInstance(res, tuple)
        self.assertEqual(len(res), 5)
        self.assertIsInstance(res.artifacts, list)
        self.assertTrue(res.artifacts, "a release with nothing to scan resolves to an error, not an empty list")
        self.assertIsInstance(res.skipped, list)
        first = res.artifacts[0]
        self.assertEqual(tuple(res), (res[0], first["url"], first["container"], first["artifact"], first["entry"]))
        self.assertEqual(self.eco.check_version(res[0]), res[0])
        seen = set()
        for art in res.artifacts:
            self.assertEqual(set(art), {"url", "container", "artifact", "entry", "filename"})
            self.assertIn(art["artifact"], self.eco.artifact_kinds)
            self.assertTrue(isinstance(art["container"], str) and art["container"])
            self.assertTrue(isinstance(art["filename"], str) and art["filename"])
            self.assertNotIn(art["url"], seen, "an artifact twice")
            seen.add(art["url"])
            parts = urllib.parse.urlsplit(art["url"])
            self.assertEqual(parts.scheme, "https")
            self.assertTrue(printable(art["url"]) and art["url"].isascii())
            self.assertIn(parts.netloc.lower(), self.eco.hosts, "an artifact on a host the module did not declare")
        for item in res.skipped:
            self.assertEqual(set(item), {"filename", "packagetype", "installable", "size", "reason"})
            self.assertTrue(printable(item["reason"]))
        for url in asked:
            parts = urllib.parse.urlsplit(url)
            self.assertEqual(parts.scheme, "https")
            self.assertIn(parts.netloc.lower(), self.eco.hosts, "a request to a host the module did not declare")

    def test_resolve_gives_the_documented_shape_from_recorded_responses(self):
        res, fetch, asked = self.resolve_good()
        self.assertEqual(res[0], self.GOOD_SPEC[1])
        self.check_resolution(res, asked)
        self.assertEqual(asked, fetch.requests)

    def test_resolve_with_no_version_picks_one_that_is_valid(self):
        res, fetch, asked = self.resolve_good(version=None)
        self.check_resolution(res, asked)

    def test_resolve_of_a_version_the_registry_does_not_have_is_an_error(self):
        name, _ = self.GOOD_SPEC
        fetch, asked = self.fetch_for(self.responses())
        self.assertRefusal(lambda: self.eco.resolve(name, self.MISSING_VERSION, fetch), ValueError)

    def test_resolve_of_a_package_the_registry_does_not_have_is_an_error(self):
        name, version = self.GOOD_SPEC
        fetch, asked = self.fetch_for({})
        caught = self.assertRefusal(lambda: self.eco.resolve(name, version, fetch), ValueError)
        self.assertIsInstance(caught, (base.FetchError, base.SpecError))

    def test_resolve_survives_documents_that_no_registry_sends(self):
        name, version = self.GOOD_SPEC
        for body in GARBAGE:
            for want in (version, None):
                with self.subTest(body=body[:30], version=want):
                    fetch, asked = self.fetch_for({}, default=body)
                    caught = self.assertRefusal(lambda: self.eco.resolve(name, want, fetch), ValueError)
                    for line in asked:
                        self.assertIn(_host_of(line), {h.split(":")[0] for h in self.eco.hosts})

    def test_resolve_survives_a_transport_that_fails_in_its_own_words(self):
        name, version = self.GOOD_SPEC
        for failure in (OSError("boom"), TimeoutError("slow"), ConnectionResetError("reset"), ValueError("v"),
                        base.FetchError("budget")):
            with self.subTest(failure=type(failure).__name__):
                fetch, asked = self.fetch_for({}, default=failure)
                self.assertRefusal(lambda: self.eco.resolve(name, version, fetch), base.FetchError)

    def test_resolve_refuses_a_document_over_the_budget(self):
        name, version = self.GOOD_SPEC
        good = self.responses()
        huge = {url: (b" " * (base.MAX_DOCUMENT_BYTES + 1) if not url.endswith((".zip", ".crate", ".tgz", ".whl"))
                      else body) for url, body in good.items()}
        fetch, asked = self.fetch_for(huge)
        self.assertRefusal(lambda: self.eco.resolve(name, version, fetch), base.FetchError)

    def test_a_document_that_names_an_artifact_on_another_host_is_refused(self):
        name, version = self.GOOD_SPEC
        for url in ("https://evil.example/pkg.tgz", "http://%s/pkg.tgz" % sorted(self.eco.hosts)[0],
                    "file:///etc/passwd", "https://%s@evil.example/p.tgz" % sorted(self.eco.hosts)[0],
                    "//evil.example/pkg.tgz", "https://%s.evil.example/p.tgz" % sorted(self.eco.hosts)[0],
                    "https://evil.example/%s/p.tgz" % sorted(self.eco.hosts)[0]):
            responses = self.hostile_responses(url)
            if responses is None:
                self.skipTest("the module builds its artifact URL itself and reads none from a document")
            with self.subTest(url=url):
                fetch, asked = self.fetch_for(responses)
                try:
                    res = self.eco.resolve(name, version, fetch)
                except ValueError:
                    res = None
                if res is not None:
                    for art in res.artifacts:
                        self.assertNotEqual(_host_of(art["url"]), "evil.example")
                        fetch.check_url(art["url"])
                for line in asked:
                    self.assertNotEqual(_host_of(line), "evil.example")

    def test_resolve_from_two_threads_gives_the_same_answer(self):
        name, version = self.GOOD_SPEC
        fetch, asked = self.fetch_for(self.responses())
        answers, errors = [], []

        def work():
            try:
                res = self.eco.resolve(name, version, fetch)
                answers.append((tuple(res), res.artifacts, res.skipped))
            except BaseException as exc:                                   # (reported below)
                errors.append(exc)

        threads = [threading.Thread(target=work) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(errors, [])
        self.assertEqual(len(answers), 4)
        self.assertTrue(all(a == answers[0] for a in answers))

    # ---- verify
    def test_verify_matches_a_published_digest_and_fails_closed_on_any_change(self):
        case = self.verify_case()
        if case is None:
            self.assertIsNone(self.eco.verify(b"data", {}, *self.GOOD_SPEC))
            return
        data, entry, name, version = case
        got = self.eco.verify(data, entry, name, version)
        self.assertIsInstance(got, tuple)
        self.assertEqual(len(got), 2)
        self.assertTrue(isinstance(got[0], str) and got[0])
        self.assertTrue(isinstance(got[1], str) and got[1])
        changed = [data[:-1], b""]
        if self.DIGEST_COVERS_EVERY_BYTE:
            flips = sorted({0, len(data) // 2, len(data) - 1}) if data else []
            changed += [data + b"\0", b"\0" + data]
            for i in flips:
                bad = bytearray(data)
                bad[i] ^= 1
                changed.append(bytes(bad))
        else:
            self.assertTrue(self.changed_downloads(data), "a digest of the contents needs changed archives to be tested")
        changed += list(self.changed_downloads(data))
        for bad in changed:
            with self.subTest(size=len(bad)):
                caught = self.assertRefusal(lambda: self.eco.verify(bad, entry, name, version), base.DigestError)
                self.assertNotIn(repr(data[:20]), str(caught))

    def test_a_digest_that_is_garbled_is_never_a_match(self):
        case = self.verify_case()
        if case is None:
            self.skipTest("this registry publishes no digest")
        data, entry, name, version = case
        for bad_entry in tuple(self.malformed_digests()) + (None, 5, "x", [], {}, [1, 2], {"integrity": 5}):
            with self.subTest(entry=repr(bad_entry)[:40]):
                try:
                    got = self.eco.verify(data, bad_entry, name, version)
                except ValueError:
                    continue                                               # (fail closed)
                self.assertIsNone(got, "a garbled digest counted as a match")

    # ---- archives
    def test_member_paths_are_as_the_module_says(self):
        for kind, member, root, expected in self.MEMBER_PATHS:
            with self.subTest(kind=kind, member=member[:40]):
                self.assertEqual(self.eco.member_path(kind, member, root), expected)

    def test_member_paths_are_always_safe_to_join_to_a_directory(self):
        roots = self.roots()
        for kind in self.eco.artifact_kinds:
            root = roots.get(kind)
            names = list(MEMBER_ATOMS)
            if root:
                names += [root + atom for atom in MEMBER_ATOMS] + [root.rstrip("/") + atom for atom in MEMBER_ATOMS]
            names += ["top/" + atom for atom in MEMBER_ATOMS]
            for member in names:
                with self.subTest(kind=kind, member=member[:40]):
                    got = self.eco.member_path(kind, member, root) if root else self.eco.member_path(kind, member)
                    self.assertTrue(isinstance(got, tuple) and len(got) == 2, got)
                    rel, problem = got
                    self.assertTrue(problem is None or (isinstance(problem, str) and printable(problem)), problem)
                    if rel is None:
                        continue
                    self.assertIsNone(problem)
                    self.assertIsInstance(rel, str)
                    self.assertTrue(rel and rel == posixpath.normpath(rel), repr(rel))
                    self.assertFalse(rel.startswith("/") or re.match(r"^[A-Za-z]:/", rel), repr(rel))   # (`c:a` stays: repo keeps it)
                    self.assertNotIn("\\", rel)
                    self.assertNotIn("..", rel.split("/"))
                    self.assertFalse(rel.startswith(("../", "./")) or rel in (".", ".."), repr(rel))

    def test_the_archive_root_is_a_directory_the_member_rules_agree_with(self):
        res, fetch, asked = self.resolve_good()
        for art in res.artifacts:
            root = self.eco.archive_root(res, art)
            if root is None:
                continue
            self.assertIsInstance(root, str)
            self.assertTrue(root.endswith("/") and len(root) > 1 and root.isascii() and root.isprintable(), repr(root))
            self.assertNotIn("\\", root)
            self.assertFalse(root.startswith("/") or ".." in root.split("/") or "//" in root, repr(root))
            kind = art["artifact"]
            self.assertEqual(self.eco.member_path(kind, root + "dir/file.txt", root), ("dir/file.txt", None))
            self.assertEqual(self.eco.member_path(kind, root, root), (None, None))
            rel, problem = self.eco.member_path(kind, "elsewhere-9.9.9/file.txt", root)
            self.assertIsNone(rel)
            self.assertTrue(isinstance(problem, str) and problem)
            for member in self.GOOD_ARCHIVE_MEMBERS:
                with self.subTest(member=member[:60]):
                    got = self.eco.member_path(kind, member, root)
                    if member.endswith("/"):
                        self.assertEqual(got, (None, None))
                    else:
                        self.assertTrue(got[0] and got[1] is None, "a member of the real archive is outside its own root")
                        self.assertEqual(self.eco.member_path(kind, member), got, "the root the module derives is another")
        for odd in (None, 5, "x", object(), (), {}):
            self.assertIsNone(self.eco.archive_root(odd, {}), "a root made out of something that is not a resolution")

    def test_links_extracted_is_a_yes_or_a_no_for_every_kind(self):
        for kind in self.eco.artifact_kinds:
            self.assertIn(self.eco.links_extracted(kind), (True, False))

    def test_container_is_defined_for_every_file_name(self):
        for filename in ("", ".", "x", "x.zip", "X.ZIP", "x.tar.gz", "x.tgz", "x.whl", "x.crate", "x.exe", "x.zip/",
                         "../x.zip", "x" * 5000 + ".zip", "a\0.zip", "x.zip\0", "\u202e.zip", ".zip", "zip", "x.TAR.GZ"):
            with self.subTest(filename=filename[:30]):
                got = self.eco.container(filename)
                self.assertTrue(got is None or (isinstance(got, str) and got), got)

    # ---- what is read in an archive
    def test_nothing_in_an_archive_makes_run_targets_or_declared_fail_in_a_new_way(self):
        members_sets = ([], ["a"], sorted(self.eco.manifest_names), ["x/y/%d.py" % i for i in range(1000)],
                        list(MEMBER_ATOMS))
        for kind in self.eco.artifact_kinds:
            for text in GARBAGE_TEXT:
                manifests = {m: text for m in sorted(self.eco.manifest_names)}
                for members in members_sets:
                    with self.subTest(kind=kind, text=text[:20], members=len(members)):
                        try:
                            targets = self.eco.run_targets(kind, manifests, members)
                            declared = self.eco.declared(kind, manifests, members)
                        except ValueError:
                            continue
                        self.assertIsInstance(targets, base.RunTargets)
                        for group in targets:
                            self.assertIsInstance(group, frozenset)
                            self.assertTrue(all(isinstance(p, str) for p in group))
                        self.assertIsInstance(declared, base.Declared)
                        self.assertTrue(declared.name is None or isinstance(declared.name, str))
                        self.assertIsInstance(declared.dependencies, tuple)
                        self.assertTrue(all(isinstance(d, str) for d in declared.dependencies))

    def test_with_no_manifests_nothing_runs_and_nothing_is_declared(self):
        for kind in self.eco.artifact_kinds:
            self.assertEqual(self.eco.run_targets(kind, {}, []), base.RunTargets())
            self.assertEqual(self.eco.declared(kind, {}, []), base.Declared())

    # ---- the optional parts say so when they are not there
    def test_what_a_module_does_not_have_it_answers_with_none(self):
        fetch, asked = self.fetch_for({})
        e = self.eco
        for method, args in (("dependencies", (None, fetch)), ("discover", (None, 10, fetch)), ("popular_names", ())):
            fn = getattr(type(e), method)
            if fn is getattr(base.Ecosystem, method):
                self.assertIsNone(getattr(e, method)(*args), method)
