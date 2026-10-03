"""Dependencies a package declares that nothing in it uses (0.1.8).

A dependency is installed with the package, and its install scripts run,
whether the package's code uses it or not. The @mastra compromise (June
2026) changed no code: each hijacked release gained a dependency on
easy-day-js, which no file of the release named and which carried the
payload. So a registry scan of an npm release lists the runtime dependencies
nothing in it names (SC-UNUSED-DEPENDENCY, INFO), and a scan that can see
the dependency is also brand-new makes that SC-NEW-DEPENDENCY CRITICAL
(repo.new_dependency_issues).

On its own it is context, not a verdict. Measured on the benchmark's
in-sample npm releases (Oct 3, uses read as below): of the 219 popular
packages, none declares an unused dependency that is neither one of npm's
5,000 most-downloaded packages nor in the package's own scope, and 1 of the
1,045 packages installed with 20 popular command-line tools does
(autolinker's gulp-header). But 14 of the 83 other compromised packages'
own manifests do too (a build tool, a bundled library, an ember addon): in
the long tail it is common, so it stays INFO. It is listed for 72 of the
300 malicious npm releases, among them the 17 @mastra ones.

The interface is language-neutral, so other registries reuse it (0.1.9's
crates and Go modules): unused(declared, used, key) takes the names a
manifest declares, the names the code uses (already reduced to the package,
crate or module they name) and an ecosystem's normalizer, and returns the
declared names no used name matches. npm's collector, npm_unused, counts a
name as used when any other text of the package quotes it as a module or
package name ('x', "x/sub", `x`, or ~x/ in a style import), which covers
require, import, export-from, import(), require.resolve and TypeScript's
references, or when package.json's other fields name it (a script's
command, a babel preset).
"""
import re

#: npm dependency specs that install nothing from the registry: left out.
NPM_LOCAL_SPECS = ("file:", "link:", "workspace:", "portal:")
#: package.json fields that declare dependencies: their names are not uses.
NPM_DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies",
                         "peerDependenciesMeta", "bundleDependencies", "bundledDependencies", "resolutions",
                         "overrides")
_BEFORE, _AFTER = "'\"`~", "'\"`/"
_BEFORE_B, _AFTER_B = _BEFORE.encode(), _AFTER.encode()


def unused(declared, used, key=None):
    """The declared names nothing uses, in declared order, each once.
    declared: names as a manifest declares them; used: the names the code
    uses, reduced to what they name (an npm package, a crate, a Go module);
    key: the ecosystem's normalizer, applied to both sides (crate_key: Rust
    code writes the crate serde-json as serde_json)."""
    key = key or (lambda name: name)
    seen = {key(u) for u in used}
    out, done = [], set()
    for name in declared:
        k = key(name)
        if k not in seen and k not in done:
            done.add(k)
            out.append(name)
    return out


def crate_key(name):
    """A crate's name as Rust code writes it: Cargo maps "-" to "_"."""
    return name.replace("-", "_")


def npm_package(specifier):
    """The npm package a module specifier names ("@s/n/sub" -> "@s/n",
    "n/sub" -> "n"), else None: a relative or absolute path, a URL, a node:
    built-in or a #subpath import."""
    if not isinstance(specifier, str) or not specifier or specifier.startswith((".", "/", "#", "node:")) \
            or "://" in specifier:
        return None
    parts = specifier.split("/")
    if specifier.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 and parts[1] else None
    return parts[0]


def quoted_in(name, texts):
    """True when one of `texts` (str or bytes) quotes `name` as a module or
    package name: 'name', "name/sub", `name`, ~name/ (a style import)."""
    for text in texts:
        if isinstance(text, (bytes, bytearray)):
            needle, before, after = name.encode("utf-8"), _BEFORE_B, _AFTER_B
        else:
            needle, before, after = name, _BEFORE, _AFTER
        n = len(needle)
        i = text.find(needle)
        while i >= 0:
            # one character each side ("" would be `in` any string)
            if 0 < i and i + n < len(text) and text[i - 1:i] in before and text[i + n:i + n + 1] in after:
                return True
            i = text.find(needle, i + 1)
    return False


def _strings(obj, out):
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, list):
        for x in obj:
            _strings(x, out)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            _strings(v, out)
    return out


def npm_declared(manifest):
    """[(name, spec)] of package.json's "dependencies" that install from the
    registry, leaving out @types/ packages (types, not code) and local specs."""
    deps = manifest.get("dependencies") if isinstance(manifest, dict) else None
    out = []
    for name, spec in (deps.items() if isinstance(deps, dict) else ()):
        spec = spec.strip() if isinstance(spec, str) else ""
        if isinstance(name, str) and name and not name.startswith("@types/") and not spec.startswith(NPM_LOCAL_SPECS):
            out.append((name, spec))
    return out


def npm_registry_name(name, spec):
    """The registry package a dependency installs: an `npm:` alias names
    another (repo.npm_dependency_names reads it the same way)."""
    if isinstance(spec, str) and spec.startswith("npm:"):
        target = spec[4:]
        at = target.rfind("@")
        return target[:at] if at > 0 else target
    return name


def npm_unused(manifest, texts):
    """The runtime dependencies ("dependencies", see npm_declared) of an
    npm package that nothing in it uses, as [(name, spec)]: no text quotes
    the name (quoted_in) and none of package.json's other fields names it.
    texts: every text of the package but its package.json, read whole (str
    or bytes; a list, read once per dependency left)."""
    declared = npm_declared(manifest)
    if not declared:
        return []
    rest = " ".join(_strings({k: v for k, v in manifest.items() if k not in NPM_DEPENDENCY_FIELDS}, []))
    used = []
    for name, _spec in declared:
        word = re.compile(r"(?<![\w@/.-])" + re.escape(name) + r"(?![\w-])")
        if word.search(rest) or quoted_in(name, texts):
            used.append(name)
    left = set(unused([n for n, _s in declared], used))
    return [(n, s) for n, s in declared if n in left]
