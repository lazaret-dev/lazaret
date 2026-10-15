"""scripts/datadog.py: the benchmark's malicious releases and a holdout, drawn from DataDog's
malicious-software-packages-dataset and written as the files bench.py scans. The draw is the audit
harness's (pinned here on a made-up listing), each sample is read in memory and written as its registry
serves the release, and a run goes on where it stopped. The samples here are built in the test: zips of
inert text (a package.json, `module.exports = 1;`, `x = 1`), encrypted as the dataset's are, in a git
repository made in a temporary folder. Nothing is fetched from the network, and nothing is run.
"""
import contextlib
import io
import json
import os
import pathlib
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
import zlib
from unittest import mock

from tests import _support

SCRIPT = os.path.join(_support.REPO_ROOT, "scripts", "datadog.py")
BENCH = os.path.join(_support.REPO_ROOT, "scripts", "bench.py")
GIT = shutil.which("git")


def datadog():
    return _support.load_script(SCRIPT, "datadog_for_tests")


# ---------------------------------------------------------------- zips as the dataset's (traditional PKWARE encryption)
def _crc_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


CRC_TABLE = _crc_table()


def _update(keys, byte):
    keys[0] = (keys[0] >> 8) ^ CRC_TABLE[(keys[0] ^ byte) & 0xFF]
    keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
    keys[2] = (keys[2] >> 8) ^ CRC_TABLE[(keys[2] ^ (keys[1] >> 24)) & 0xFF]


def _encrypt(keys, data):
    out = bytearray()
    for byte in data:
        t = (keys[2] | 2) & 0xFFFF
        out.append(byte ^ ((t * (t ^ 1)) >> 8) & 0xFF)
        _update(keys, byte)
    return bytes(out)


def encrypted_zip(files, password=b"infected"):
    """{name: content} -> a zip whose entries are stored and encrypted with the traditional PKWARE cipher. A
    name is str (written as UTF-8, flagged so) or bytes (written as given, not flagged); a content is bytes, or
    a dict: {"data": bytes, "mode": int, "extra": bytes} (a link's mode is stat.S_IFLNK | 0o777)."""
    body, central = bytearray(), bytearray()
    for name, content in files.items():
        spec = content if isinstance(content, dict) else {"data": content}
        data, extra = spec["data"], spec.get("extra", b"")
        mode = spec.get("mode", stat.S_IFREG | 0o644)
        raw = name.encode("utf-8") if isinstance(name, str) else name
        flags = 0x1 | (0x800 if isinstance(name, str) and not name.isascii() else 0)
        crc = zlib.crc32(data)
        keys = [0x12345678, 0x23456789, 0x34567890]
        for byte in password:
            _update(keys, byte)
        sealed = _encrypt(keys, bytes(11) + bytes([crc >> 24])) + _encrypt(keys, data)
        offset = len(body)
        body += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, 0, 0, 0x21, crc, len(sealed), len(data),
                            len(raw), len(extra)) + raw + extra + sealed
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 20, 20, flags, 0, 0, 0x21, crc,
                               len(sealed), len(data), len(raw), len(extra), 0, 0, 0, mode << 16, offset) + raw + extra
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(files), len(files), len(central), len(body), 0)
    return bytes(body + central + end)


def unicode_path_field(stored, name):
    """Info-ZIP's Unicode Path extra field (0x7075): the UTF-8 name of an entry stored as `stored`."""
    value = b"\x01" + struct.pack("<I", zlib.crc32(stored)) + name.encode("utf-8")
    return struct.pack("<HH", 0x7075, len(value)) + value


def tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def members(data, container):
    if container == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            return {i.filename: z.read(i) for i in z.infolist() if not i.is_dir()}
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}


JS = b"module.exports = 1;\n"
PY = b"x = 1\n"
PJ = b'{"name": "x", "version": "1.0.0"}'


# ---------------------------------------------------------------- the draw
def listing():
    """A made-up dataset listing: samples/ECO/CATEGORY/NAME/VERSION/FILE.zip, a few versions each."""
    paths = []
    for eco, cat, n in (("npm", "malicious_intent", 12), ("pypi", "malicious_intent", 9),
                        ("npm", "compromised_lib", 6), ("pypi", "compromised_lib", 3)):
        for i in range(n):
            name = f"{cat[0]}{eco[0]}{i:02d}"
            for v in range(1 + i % 3):
                paths.append(f"samples/{eco}/{cat}/{name}/1.{v}.0/2026-09-0{v + 1}-{name}-v1.{v}.0.zip")
    return paths


class DrawTests(unittest.TestCase):
    def setUp(self):
        self.d = datadog()
        self.sizes = {("npm", "malicious_intent"): 4, ("pypi", "malicious_intent"): 3,
                      ("npm", "compromised_lib"): 2, ("pypi", "compromised_lib"): self.d.EVERY}

    def test_the_draw_is_the_audit_harness_draw(self):
        # The harness's pick_malicious on this listing, seed 20260928 (the benchmark's): the same commit of the
        # dataset gives the audit's 516 releases only while this holds.
        chosen = self.d.draw(self.d.samples_by_package(listing()), self.d.BENCHMARK_SEED, self.sizes)
        self.assertEqual([(c["name"], c["version"]) for c in chosen], [
            ("mn00", "1.0.0"), ("mn04", "1.0.0"), ("mn08", "1.1.0"), ("mn10", "1.1.0"),
            ("mp03", "1.0.0"), ("mp04", "1.1.0"), ("mp05", "1.0.0"),
            ("cn02", "1.2.0"), ("cn03", "1.0.0"),
            ("cp00", "1.0.0"), ("cp01", "1.0.0"), ("cp02", "1.1.0")])
        self.assertEqual(chosen[0]["path"], "samples/npm/malicious_intent/mn00/1.0.0/2026-09-01-mn00-v1.0.0.zip")
        self.assertEqual(self.d.fingerprint(chosen), self.d.fingerprint(
            self.d.draw(self.d.samples_by_package(reversed(listing())), self.d.BENCHMARK_SEED, self.sizes)))

    def test_only_the_dataset_s_sample_zips_are_drawn_from(self):
        groups = self.d.samples_by_package(listing() + [
            "samples/npm/malicious_intent/@scope/pkg/1.0.0/x.zip",       # seven parts
            '"samples/npm/malicious_intent/\\303\\251/1.0.0/x.zip"',      # a path git quotes
            "samples/npm/malicious_intent/notes/1.0.0/notes.txt", "samples/npm/manifest.json",
            "samples/go/malicious_intent/g/1.0.0/x.zip", "samples/npm/other/o/1.0.0/x.zip", "README.md"])
        self.assertEqual(len(groups), 30)
        self.assertEqual(groups[("npm", "malicious_intent", "mn02")],
                         [("1.0.0", "samples/npm/malicious_intent/mn02/1.0.0/2026-09-01-mn02-v1.0.0.zip"),
                          ("1.1.0", "samples/npm/malicious_intent/mn02/1.1.0/2026-09-02-mn02-v1.1.0.zip"),
                          ("1.2.0", "samples/npm/malicious_intent/mn02/1.2.0/2026-09-03-mn02-v1.2.0.zip")])

    def test_the_holdout_leaves_out_the_benchmark_s_packages(self):
        groups = self.d.samples_by_package(listing())
        bench = self.d.draw(groups, self.d.BENCHMARK_SEED, self.sizes)
        taken = {(c["eco"], c["name"]) for c in bench}
        hold = self.d.draw(groups, self.d.HOLDOUT_SEED, self.sizes, taken)
        self.assertFalse({(c["eco"], c["name"]) for c in hold} & taken)
        self.assertEqual([len([c for c in hold if (c["eco"], c["cat"]) == k]) for k in self.sizes], [4, 3, 2, 0])


# ---------------------------------------------------------------- one sample
class SampleTests(unittest.TestCase):
    def setUp(self):
        self.d = datadog()

    def release(self, files, eco="npm", name="pkg", version="1.0.0"):
        item = {"eco": eco, "cat": "malicious_intent", "name": name, "version": version}
        body, container, kind = self.d.release(self.d.Sample(encrypted_zip(files)), item)
        return container, kind, members(body, container)

    def test_npm_releases(self):
        cases = {
            "under package/": {"package/package.json": PJ, "package/index.js": JS, "package_info-pkg.json": b"{}"},
            "at the top": {"package.json": PJ, "index.js": JS, "package_info-pkg.json": b"{}"},
            "doubled paths": {"package.json/package.json": PJ, "index.js/index.js": JS, "package_info-pkg.json": b"{}"},
            "the folder with package_info": {"rel/package_info-pkg.json": b"{}", "rel/package.json": PJ,
                                             "rel/index.js": JS, "other/package.json": PJ, "other/evil.js": JS},
            "upstream sources left out": {"sources/up/package.json": PJ, "sources/up/x.js": JS,
                                          "rel/package.json": PJ, "rel/index.js": JS},
        }
        for label, files in cases.items():
            with self.subTest(label):
                self.assertEqual(self.release(files),
                                 ("tgz", "npm", {"package/package.json": PJ, "package/index.js": JS}))
        with self.assertRaisesRegex(self.d.Skip, "no package.json"):
            self.release({"index.js": JS, "package_info-pkg.json": b"{}"})

    def test_pypi_releases(self):
        self.assertEqual(self.release({"pkg-1.0/setup.py": PY, "pkg-1.0/pkg/__init__.py": PY,
                                       "package_info-pkg.json": b"{}"}, "pypi", "pkg", "1.0"),
                         ("tgz", "sdist", {"pkg-1.0/setup.py": PY, "pkg-1.0/pkg/__init__.py": PY}))
        self.assertEqual(self.release({"setup.py": PY, "m.py": PY, "package_info-pkg.json": b"{}"}, "pypi", "pkg", "2.0"),
                         ("tgz", "sdist", {"pkg-2.0/setup.py": PY, "pkg-2.0/m.py": PY}))
        self.assertEqual(self.release({"pkg/__init__.py": PY, "pkg-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n",
                                       "package_info-pkg.json": b"{}"}, "pypi"),
                         ("zip", "wheel", {"pkg/__init__.py": PY, "pkg-1.0.dist-info/WHEEL": b"Wheel-Version: 1.0\n"}))
        own = tgz({"pkg-1.0/setup.py": PY})
        container, kind, got = self.release({"pkg-1.0.tar.gz": own, "x.py": PY, "package_info-pkg.json": b"{}"}, "pypi")
        self.assertEqual((container, kind, got), ("tgz", "sdist", {"pkg-1.0/setup.py": PY}))   # the release's own
        for label, top in (("a gzipped pickle", zlib.compress(b"no tar")), ("a damaged zip", b"PK\x03\x04 cut")):
            with self.subTest(label):
                container, kind, got = self.release({"pkg-data.gz": top, "setup.py": PY,
                                                     "package_info-pkg.json": b"{}"}, "pypi", "pkg", "1.0")
                self.assertEqual((container, kind, sorted(got)), ("tgz", "sdist", ["pkg-1.0/pkg-data.gz", "pkg-1.0/setup.py"]))
        nested = {"pkg-1.0/setup.py": PY, "pkg-1.0/dist/pkg-0.9.tar.gz": own, "package_info-pkg.json": b"{}"}
        self.assertEqual(sorted(self.release(nested, "pypi", "pkg", "1.0")[2]),
                         ["pkg-1.0/dist/pkg-0.9.tar.gz", "pkg-1.0/setup.py"])                # not at the top: a file
        with self.assertRaisesRegex(self.d.Skip, "no files"):
            self.release({"package_info-pkg.json": b"{}"}, "pypi")

    def test_entries_read_as_unzip_reads_them(self):
        link = {"data": b"index.js", "mode": stat.S_IFLNK | 0o777}
        self.assertEqual(self.release({"../package.json": PJ, "./a/../index.js": JS, "/abs/b.js": JS, "c.js": link,
                                       "package_info-pkg.json": b"{}"}),
                         ("tgz", "npm", {"package/package.json": PJ, "package/a/index.js": JS, "package/abs/b.js": JS}))
        stored = "café.js".encode("utf-8")
        latin = "été.js".encode("latin-1")
        got = self.release({"package.json": PJ, "日本.js": JS,                           # flagged UTF-8
                            stored: JS,                                                          # unflagged UTF-8
                            b"x.js": {"data": JS, "extra": unicode_path_field(b"x.js", "ü.js")},
                            latin: JS, "package_info-pkg.json": b"{}"})[2]
        self.assertEqual(sorted(got), sorted(["package/package.json", "package/日本.js", "package/café.js",
                                              "package/ü.js", "package/" + latin.decode("utf-8", "surrogateescape")]))

    def test_the_password_is_the_dataset_s(self):
        sample = self.d.Sample(encrypted_zip({"package.json": PJ}, password=b"other"))
        with self.assertRaisesRegex(self.d.Skip, "package.json"):
            self.d.release(sample, {"eco": "npm", "name": "pkg", "version": "1.0.0"})
        with self.assertRaisesRegex(self.d.Skip, "Git LFS"):
            self.d.Sample(b"version https://git-lfs.github.com/spec/v1\n")
        with self.assertRaisesRegex(self.d.Skip, "not a zip"):
            self.d.Sample(b"PK\x03\x04 cut short")


# ---------------------------------------------------------------- a run, on a dataset in git
@unittest.skipUnless(GIT, "git is not installed")
class RunTests(unittest.TestCase):
    def setUp(self):
        self.d = datadog()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
                        GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
                        GIT_CONFIG_NOSYSTEM="1", HOME=str(self.tmp))
        self.dataset = self.tmp / "dataset"
        self.dataset.mkdir()
        self.git(self.dataset, "init", "-q")
        self.add_samples({("npm", "malicious_intent"): range(5), ("pypi", "malicious_intent"): range(4),
                          ("npm", "compromised_lib"): range(3), ("pypi", "compromised_lib"): range(1)})
        self.git(self.dataset, "add", "-A")
        self.git(self.dataset, "commit", "-q", "-m", "samples")
        self.sha = self.git(self.dataset, "rev-parse", "HEAD").strip()   # stands for the audit's commit
        self.add_samples({("npm", "malicious_intent"): range(5, 10), ("pypi", "malicious_intent"): range(4, 7),
                          ("npm", "compromised_lib"): range(3, 5)})
        (self.dataset / "README.md").write_text("later\n", encoding="utf-8")
        self.git(self.dataset, "add", "-A")
        self.git(self.dataset, "commit", "-q", "-m", "later")             # the head: more samples
        sizes = {"benchmark": {("npm", "malicious_intent"): 3, ("pypi", "malicious_intent"): 2,
                               ("npm", "compromised_lib"): 2, ("pypi", "compromised_lib"): self.d.EVERY},
                 "holdout": {("npm", "malicious_intent"): 2, ("pypi", "malicious_intent"): 2,
                             ("npm", "compromised_lib"): 1, ("pypi", "compromised_lib"): self.d.EVERY}}
        for patcher in (mock.patch.object(self.d, "SIZES", sizes), mock.patch.object(self.d, "AUDIT_COMMIT", self.sha)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def add_samples(self, numbers):
        for (eco, cat), indexes in numbers.items():
            for i in indexes:
                name = f"{cat[0]}{eco[0]}{i}"
                files = {"package/package.json": PJ, "package/index.js": JS} if eco == "npm" else \
                    {f"{name}-1.0/setup.py": PY}
                files[f"package_info-{name}.json"] = b"{}"
                dest = self.dataset / "samples" / eco / cat / name / "1.0" / f"2026-09-01-{name}-v1.0.zip"
                dest.parent.mkdir(parents=True)
                dest.write_bytes(encrypted_zip(files))

    def git(self, cwd, *args):
        return subprocess.run([GIT, *args], cwd=cwd, env=self.env, check=True, capture_output=True,
                              timeout=30).stdout.decode()

    def run_script(self, *args):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out), mock.patch.dict(os.environ, self.env):
            code = self.d.main([str(a) for a in args])
        return code, out.getvalue()

    def manifest(self, out, name):
        with open(out / name / "manifest.jsonl", encoding="utf-8") as f:
            return [json.loads(line) for line in f]

    def test_the_manifests_bench_runs_and_a_run_that_goes_on(self):
        out = self.tmp / "corpus"
        code, said = self.run_script(self.dataset, out, "--commit", self.sha[:8])
        self.assertEqual(code, 0, said)
        bench, hold = self.manifest(out, "benchmark"), self.manifest(out, "holdout")
        self.assertEqual((len(bench), len(hold)), (8, 5))                  # 3 + 2 + 2 + 1; 2 + 2 + 1
        self.assertFalse({(r["eco"], r["name"]) for r in bench} & {(r["eco"], r["name"]) for r in hold})
        self.assertEqual(sorted(bench[0]), ["artifact_path", "cat", "container", "eco", "id", "kind", "name",
                                            "set", "sha256", "source", "version"])
        self.assertEqual(bench[0]["id"], f"datadog:npm:malicious_intent:{bench[0]['name']}@1.0")
        entry = {"name": "holdout", "manifest": str(out.resolve() / "holdout" / "manifest.jsonl"), "aggregate_only": True}
        self.assertIn(json.dumps(entry), said)
        harness = _support.load_script(BENCH, "bench_for_datadog_tests")
        for rec in bench + hold:
            data, container, kind = harness._release(rec)
            want = {"package/package.json": PJ, "package/index.js": JS} if rec["eco"] == "npm" else \
                {f"{rec['name']}-1.0/setup.py": PY}
            self.assertEqual((container, kind, members(data, container)),
                             ("tgz", "npm" if rec["eco"] == "npm" else "sdist", want))
        about = json.loads((out / "benchmark" / "draw.json").read_text(encoding="utf-8"))
        self.assertEqual((about["commit"], about["seed"], about["releases"]), (self.sha, 20260928, 8))

        reads = []
        real = self.d.Dataset.read
        with mock.patch.object(self.d.Dataset, "read", lambda ds, path: reads.append(path) or real(ds, path)):
            self.assertEqual(self.run_script(self.dataset, out, "--commit", self.sha[:8])[0], 0)
            self.assertEqual(reads, [])                                    # done: nothing read again
            records = out / "benchmark" / "records.jsonl"
            lines = records.read_text(encoding="utf-8").splitlines(keepends=True)
            records.write_text("".join(lines[:-3]), encoding="utf-8")      # stopped three short
            os.remove(bench[0]["artifact_path"])                           # and a file lost
            self.assertEqual(self.run_script(self.dataset, out, "--commit", self.sha[:8], "--only", "benchmark")[0], 0)
            self.assertEqual(len(reads), 4)
        self.assertEqual(self.manifest(out, "benchmark"), bench)

    def test_what_is_refused(self):
        out = self.tmp / "corpus"
        self.assertEqual(self.run_script(self.dataset, out, "--commit", self.sha[:8], "--only", "holdout")[0], 0)
        code, said = self.run_script(self.dataset, out, "--commit", self.sha[:8], "--holdout-seed", "7")
        self.assertEqual(code, 2)
        self.assertIn("holds another draw", said)
        checkout = self.tmp / "lazaret"
        (checkout / ".git").mkdir(parents=True)
        (checkout / "scripts").mkdir()
        (checkout / "scripts" / "bench.py").write_text("", encoding="utf-8")
        code, said = self.run_script(self.dataset, checkout / "Claude outputs" / "corpus", "--commit", self.sha[:8])
        self.assertEqual(code, 2)
        self.assertIn("inside the repository", said)
        shallow = self.tmp / "shallow"
        self.git(self.tmp, "clone", "-q", "--depth", "1", self.dataset.as_uri(), str(shallow))
        code, said = self.run_script(shallow, self.tmp / "other", "--commit", self.sha[:8])
        self.assertEqual(code, 2)
        self.assertIn("is a shallow clone, without the commit given", said)

    def test_new_sets_at_a_later_commit_leave_out_the_audit_benchmark(self):
        head = self.git(self.dataset, "rev-parse", "HEAD").strip()
        audit_out, out = self.tmp / "audit", self.tmp / "corpus"
        self.assertEqual(self.run_script(self.dataset, audit_out, "--only", "benchmark")[0], 0)  # the default: audit's
        code, said = self.run_script(self.dataset, out, "--commit", "HEAD")
        self.assertEqual(code, 0, said)
        self.assertIn(f"not the audit's {self.sha}: new sets", said)
        self.assertIn(f"give --commit {head} to draw them again", said)
        packages = lambda rows: {(r["eco"], r["name"]) for r in rows}                      # noqa: E731
        written_from = packages(self.manifest(audit_out, "benchmark"))
        bench, hold = packages(self.manifest(out, "benchmark")), packages(self.manifest(out, "holdout"))
        self.assertTrue(written_from - bench)                       # the audit's benchmark is not this one's
        self.assertEqual(len(hold), 5)
        self.assertFalse(hold & bench)
        self.assertFalse(hold & written_from)                       # none of what the detectors were written from
        about = json.loads((out / "holdout" / "draw.json").read_text(encoding="utf-8"))
        self.assertEqual((about["commit"], about["leaves_out"]), (head, f"the audit's benchmark, drawn at {self.sha}"))

        shallow = self.tmp / "shallow"                              # a --depth 1 clone has no history to draw from
        self.git(self.tmp, "clone", "-q", "--depth", "1", self.dataset.as_uri(), str(shallow))
        code, said = self.run_script(shallow, self.tmp / "again", "--commit", "HEAD")
        self.assertEqual(code, 2)
        self.assertIn(f"git -C '{shallow}' fetch --unshallow --filter=blob:none origin", said)
        self.git(self.dataset, "config", "uploadpack.allowFilter", "true")
        try:
            self.git(shallow, "fetch", "-q", "--unshallow", "--filter=blob:none", "origin")
        except subprocess.CalledProcessError as exc:
            self.skipTest(f"this git cannot add history without blobs: {exc.stderr.decode(errors='replace').strip()}")
        code, said = self.run_script(shallow, self.tmp / "again", "--commit", "HEAD")
        self.assertEqual(code, 0, said)
        for name in ("benchmark", "holdout"):
            self.assertEqual([(r["id"], r["sha256"]) for r in self.manifest(self.tmp / "again", name)],
                             [(r["id"], r["sha256"]) for r in self.manifest(out, name)])

    def test_a_blobless_clone_fetches_the_samples_drawn_in_one_request(self):
        self.git(self.dataset, "config", "uploadpack.allowFilter", "true")
        self.git(self.dataset, "config", "uploadpack.allowAnySHA1InWant", "true")
        clone = self.tmp / "blobless"
        try:
            self.git(self.tmp, "clone", "-q", "--no-checkout", "--filter=blob:none", self.dataset.as_uri(), str(clone))
        except subprocess.CalledProcessError as exc:
            self.skipTest(f"this git makes no partial clone: {exc.stderr.decode(errors='replace').strip()}")
        packs = lambda: len(list((clone / ".git" / "objects" / "pack").glob("*.pack")))  # noqa: E731
        before = packs()
        code, said = self.run_script(clone, self.tmp / "corpus", "--commit", self.sha[:8])
        self.assertEqual(code, 0, said)
        self.assertIn("fetching the 13 samples drawn from origin", said)
        self.assertEqual(packs(), before + 1)                              # one request, not one per sample
        self.dataset.rename(self.tmp / "gone")                             # and nothing is fetched again
        self.assertEqual(self.run_script(clone, self.tmp / "corpus2", "--commit", self.sha[:8])[0], 0)
        for name in ("benchmark", "holdout"):
            self.assertEqual([(r["id"], r["sha256"]) for r in self.manifest(self.tmp / "corpus2", name)],
                             [(r["id"], r["sha256"]) for r in self.manifest(self.tmp / "corpus", name)])


if __name__ == "__main__":
    unittest.main()
