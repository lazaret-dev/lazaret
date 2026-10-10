#!/usr/bin/env python3
"""The CVE bundle read two ways (0.1.9, P-5): what a scan pays to load `cve-bundle.json` and what it pays to open the
indexed bundle built from it.

    python3 scripts/profile/sca_bundle.py compare cve-bundle.json [--deps 2000] [--json report.json] [--keep DIR]
    python3 scripts/profile/sca_bundle.py gen 120000 synthetic.json     # a bundle the size of the real one
    python3 scripts/profile/sca_bundle.py inventory cve-bundle.json inventory.json [--deps N] [--seed S]
    python3 scripts/profile/sca_bundle.py build cve-bundle.json cve-bundle.lzx
    python3 scripts/profile/sca_bundle.py measure BUNDLE inventory.json

`compare` is the whole experiment: it makes an inventory (half of it names the bundle has, half it has not), builds the
indexed bundle, and then, each in a process of its own so that the peak memory is the format's and not what ran before
it, loads each bundle and matches the inventory against it. It prints the seconds to load, the seconds to match, the
peak resident memory and the file's size, and **fails (exit 1) if the two give different matches**: the answer, in
order, is hashed. `gen` writes a synthetic bundle shaped like the real one (npm and PyPI advisories with ranges, KEV and
EPSS fields) for a machine that cannot reach OSV; the first nightly run with network should use the real bundle
(`lazaret-sca --update-bundle`). Standard library plus this checkout."""

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common  # noqa: E402

try:
    import resource
except ImportError:                                              # Windows: no peak figure
    resource = None

WORDS = ("lodash react vite express requests django flask numpy pillow axios webpack babel core utils parser server "
         "client auth crypto http json yaml xml cli sdk api tool kit lib plugin").split()


def peak_mb():
    """The peak resident memory of this process in MB, or None where the platform does not say."""
    if resource is None:
        return None
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return round(peak / 1e6 if sys.platform == "darwin" else peak / 1024, 1)        # (bytes on macOS, KB elsewhere)


def synthetic(count, seed=7):
    """A bundle document of `count` advisories: the shape and size of one the update builds, from invented names."""
    rnd = random.Random(seed)
    pool = ["-".join(rnd.choice(WORDS) for _ in range(rnd.choice((1, 2, 3)))) + "-%d" % i for i in range(70000)]
    advisories = []
    for i in range(count):
        packages = []
        for _ in range(rnd.choice((1, 1, 1, 2, 3))):
            eco = rnd.choice(("npm", "pypi"))
            name = rnd.choice(pool)
            if eco == "npm" and rnd.random() < 0.3:
                name = "@scope%d/%s" % (rnd.randrange(900), name)
            ranges = [{"fromVersion": "%d.%d.%d" % (rnd.randrange(10), rnd.randrange(20), rnd.randrange(30)),
                       "toVersion": "%d.%d.%d" % (rnd.randrange(10, 20), rnd.randrange(20), rnd.randrange(30)),
                       "toInclusive": False} for _ in range(rnd.choice((1, 1, 2, 3)))]
            packages.append({"name": name, "ecosystem": eco, "exact": True, "ranges": ranges})
        adv = {"cve": "CVE-2099-%06d" % i,
               "aliases": ["GHSA-%04x-%04x-%04x" % (rnd.randrange(65536), rnd.randrange(65536), rnd.randrange(65536))],
               "title": "Improper handling of untrusted input in %s allows remote attackers to do something "
                        "unpleasant" % packages[0]["name"],
               "severity": rnd.choice(("low", "medium", "high", "critical")), "cvss": round(rnd.uniform(1, 10), 1),
               "cwes": ["CWE-%d" % rnd.randrange(20, 1300)],
               "published": "2025-0%d-1%dT10:00:00Z" % (rnd.randrange(1, 9), rnd.randrange(10)),
               "refs": ["https://osv.dev/vulnerability/GHSA-xxxx-%d" % i,
                        "https://github.com/example/repo%d/security/advisories/GHSA-%d" % (i, i),
                        "https://nvd.nist.gov/vuln/detail/CVE-2099-%06d" % i],
               "sources": ["osv:ghsa", "epss"], "epss": round(rnd.random() * 0.2, 5),
               "epssPercentile": round(rnd.random(), 4), "packages": packages}
        if rnd.random() < 0.01:
            adv["knownExploited"] = True
        advisories.append(adv)
    return {"bundleVersion": 1, "generator": "synthetic", "generatedAt": "2026-10-01T00:00:00Z",
            "sources": ["osv:npm", "osv:pypi", "cisa-kev", "epss"], "counts": {"advisories": count},
            "advisories": advisories}


def inventory_of(doc, deps=2000, seed=3):
    """[[ecosystem, name, version]] of `deps` dependencies: half named by the bundle's own exact packages (each at
    the first version its range names, so some are affected and some not) and half it has no advisory for."""
    rnd = random.Random(seed)
    named = []
    for adv in doc.get("advisories", ()):
        for pkg in adv.get("packages", ()) if isinstance(adv, dict) else ():
            if isinstance(pkg, dict) and pkg.get("exact") and pkg.get("ecosystem") in ("npm", "pypi") \
                    and isinstance(pkg.get("name"), str):
                ranges = pkg.get("ranges")
                first = ranges[0].get("fromVersion") if isinstance(ranges, list) and ranges and \
                    isinstance(ranges[0], dict) else None
                named.append([pkg["ecosystem"], pkg["name"], first if isinstance(first, str) and first else "1.0.0"])
    rnd.shuffle(named)
    out = named[:deps // 2]
    while len(out) < deps:
        out.append([rnd.choice(("npm", "pypi")), "no-advisory-for-this-%d" % rnd.randrange(10 ** 9),
                    "%d.%d.%d" % (rnd.randrange(10), rnd.randrange(20), rnd.randrange(30))])
    rnd.shuffle(out)
    return out


def digest_of(matches):
    """A hash of the matches in the order `match_inventory` returned them: what two bundles must agree on. The
    indexed bundle keeps an advisory's keys sorted, so a range's keys are compared as a set, not in their order."""
    h = hashlib.sha256()
    for adv, pkg, dep, detail in matches:
        h.update(json.dumps([adv.get("cve"), pkg.get("name"), pkg.get("ecosystem"), list(dep[:3]), detail],
                            sort_keys=True, default=str).encode("utf-8"))              # (a range's keys in any order)
        h.update(b"\n")
    return h.hexdigest()


def load_json(path):
    from lazaret.scanner import core as lazaret
    with open(path, "rb") as fh:
        return lazaret.json_loads_bounded(fh.read().decode("utf-8"))


def cmd_gen(args):
    from lazaret.scanner import sca_feeds
    if args.count < 1:
        print("error: a bundle needs at least one advisory", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        sca_feeds.dump_bundle(synthetic(args.count, args.seed), fh)
    print(f"wrote {args.out}: {args.count} advisories, {os.path.getsize(args.out) / 1e6:.1f} MB")
    return 0


def cmd_inventory(args):
    inventory = inventory_of(load_json(args.bundle), args.deps, args.seed)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(inventory, fh)
    print(json.dumps({"deps": len(inventory)}))
    return 0


def cmd_build(args):
    from lazaret.scanner import sca_feeds
    started = time.perf_counter()
    doc = load_json(args.bundle)
    parsed = time.perf_counter() - started
    started = time.perf_counter()
    size = sca_feeds.write_bundle(doc, args.out, force=True, fmt="index")
    print(json.dumps({"parse_s": round(parsed, 2), "build_s": round(time.perf_counter() - started, 2),
                      "bytes": size, "peak_mb": peak_mb()}))
    return 0


def cmd_measure(args):
    from lazaret.scanner import sca
    with open(args.inventory, encoding="utf-8") as fh:
        inventory = [(eco, name, version, "inventory") for eco, name, version in json.load(fh)]
    started = time.perf_counter()
    bundle = sca.CveBundle.load(args.bundle)
    loaded = time.perf_counter() - started
    try:
        started = time.perf_counter()
        matches, unknown = sca.match_inventory(inventory, bundle)
        matched = time.perf_counter() - started
        print(json.dumps({"bundle": os.path.basename(args.bundle), "bytes": os.path.getsize(args.bundle),
                          "format": "index" if type(bundle).__name__ == "IndexedBundle" else "json",
                          "advisories": len(bundle.advisories), "deps": len(inventory),
                          "load_s": round(loaded, 3), "match_s": round(matched, 3), "matches": len(matches),
                          "unknown": len(unknown), "peak_mb": peak_mb(), "digest": digest_of(matches)}))
    finally:
        bundle.close()
    return 0


def child(*argv):
    """Run one of this script's commands in a process of its own -> the JSON line it printed."""
    done = subprocess.run([sys.executable, os.path.abspath(__file__), *argv], capture_output=True, encoding="utf-8",
                          errors="replace")
    if done.returncode != 0:
        raise RuntimeError(f"`{' '.join(argv[:1])}` failed ({done.returncode}): {done.stderr.strip()[-400:]}")
    return json.loads(done.stdout.strip().splitlines()[-1])


def cmd_compare(args):
    keep = args.keep
    with tempfile.TemporaryDirectory(prefix="lz-sca-bundle-") as scratch:
        folder = keep or scratch
        os.makedirs(folder, exist_ok=True)
        inventory, indexed = os.path.join(folder, "inventory.json"), os.path.join(folder, "bundle.lzx")
        try:
            child("inventory", args.bundle, inventory, "--deps", str(args.deps), "--seed", str(args.seed))
            built = child("build", args.bundle, indexed)
            runs = [child("measure", args.bundle, inventory) for _ in range(args.runs)]
            idx = [child("measure", indexed, inventory) for _ in range(args.runs)]
        except (RuntimeError, ValueError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 4
    best_json = min(runs, key=lambda r: r["load_s"] + r["match_s"])
    best_index = min(idx, key=lambda r: r["load_s"] + r["match_s"])
    same = len({r["digest"] for r in runs + idx}) == 1 and len({(r["matches"], r["unknown"]) for r in runs + idx}) == 1
    report = {"advisories": best_json["advisories"], "deps": args.deps, "runs": args.runs, "same_answer": same,
              "build": built, "json": best_json, "index": best_index}
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")
    mb = lambda r: f"{r['bytes'] / 1e6:8.1f} MB"                      # noqa: E731
    mem = lambda r: "n/a" if r["peak_mb"] is None else f"{r['peak_mb']:.0f} MB"      # noqa: E731
    print(f"{best_json['advisories']} advisories; {args.deps} dependencies matched; best of {args.runs} "
          f"(each in a process of its own)")
    print(f"  {'':14}{'file':>11}{'load':>9}{'match':>9}{'peak memory':>14}{'matches':>9}")
    for label, r in (("JSON bundle", best_json), ("indexed bundle", best_index)):
        print(f"  {label:14}{mb(r)}{r['load_s']:8.2f}s{r['match_s']:8.2f}s{mem(r):>14}{r['matches']:>9}")
    print(f"  building the indexed bundle: {built['build_s']} s (parsing the JSON first: {built['parse_s']} s), "
          f"peak {built['peak_mb']} MB")
    print("the two give " + ("the same matches, in the same order" if same else "DIFFERENT matches: this is a bug"))
    return 0 if same else 1


def main(argv=None):
    _common.configure_stdio()
    p = argparse.ArgumentParser(prog="sca_bundle.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="command", required=True)
    g = sub.add_parser("gen", help="write a synthetic bundle")
    g.add_argument("count", type=int)
    g.add_argument("out")
    g.add_argument("--seed", type=int, default=7)
    g.set_defaults(run=cmd_gen)
    i = sub.add_parser("inventory", help="write an inventory for a bundle")
    i.add_argument("bundle")
    i.add_argument("out")
    i.add_argument("--deps", type=int, default=2000)
    i.add_argument("--seed", type=int, default=3)
    i.set_defaults(run=cmd_inventory)
    b = sub.add_parser("build", help="build the indexed bundle from a JSON one, timed")
    b.add_argument("bundle")
    b.add_argument("out")
    b.set_defaults(run=cmd_build)
    m = sub.add_parser("measure", help="load a bundle (either kind) and match an inventory against it")
    m.add_argument("bundle")
    m.add_argument("inventory")
    m.set_defaults(run=cmd_measure)
    c = sub.add_parser("compare", help="build the indexed bundle and measure both")
    c.add_argument("bundle", help="a JSON bundle (cve-bundle.json)")
    c.add_argument("--deps", type=int, default=2000, help="dependencies in the inventory (default 2000)")
    c.add_argument("--runs", type=int, default=1, help="runs of each; the fastest is reported (default 1)")
    c.add_argument("--seed", type=int, default=3)
    c.add_argument("--json", metavar="FILE", help="also write the figures as JSON")
    c.add_argument("--keep", metavar="DIR", help="keep the inventory and the indexed bundle here")
    c.set_defaults(run=cmd_compare)
    args = p.parse_args(argv)
    if getattr(args, "deps", 1) < 1 or getattr(args, "runs", 1) < 1:
        print("error: --deps and --runs are at least 1", file=sys.stderr)
        return 2
    _common.use_source_tree()
    try:
        return args.run(args)
    except (OSError, ValueError, MemoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
