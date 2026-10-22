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
crates and Go modules, and PyPI's: below): unused(declared, used, key) takes the names a
manifest declares, the names the code uses (already reduced to the package,
crate or module they name) and an ecosystem's normalizer, and returns the
declared names no used name matches. npm's collector, npm_unused, counts a
name as used when any other text of the package quotes it as a module or
package name ('x', "x/sub", `x`, or ~x/ in a style import), which covers
require, import, export-from, import(), require.resolve and TypeScript's
references, or when package.json's other fields name it (a script's
command, a babel preset).

PyPI's (D-5, 0.1.9): a distribution's name is not the name its code is
imported by (beautifulsoup4 is bs4, PyYAML is yaml), so a PyPI release's
requirements are read against its imports by the names a distribution is
commonly imported as (pypi_import_keys: its own, without a "python-" or
"py-" prefix or a "-python"-like suffix, and without a "py" prefix: pyjwt
is jwt), a dotted import answering for each of its chains (pypi_used_keys:
google.cloud.storage for google-cloud-storage); a requirement a text quotes
(`version("x")`, an entry point's group) is used too. That reading misses a
distribution imported by an unrelated name, so it is context
(SC-UNUSED-DEPENDENCY, INFO, the registry's most-downloaded distributions
left out). A requirement the dependency history finds brand-new is read
exactly instead (repo.pypi_unused_new): the modules its own files make
importable (pypi_modules), none of which the release imports.
"""
import re

#: npm dependency specs that install nothing from the registry: left out.
NPM_LOCAL_SPECS = ("file:", "link:", "workspace:", "portal:")
#: package.json fields that declare dependencies: their names are not uses.
NPM_DEPENDENCY_FIELDS = ("dependencies", "optionalDependencies", "devDependencies", "peerDependencies",
                         "peerDependenciesMeta", "bundleDependencies", "bundledDependencies", "resolutions",
                         "overrides")
#: (D-5) PyPI: the prefixes and suffixes a distribution's import name commonly lacks (pypi_import_keys)
_PY_PREFIXES = ("python-", "py-")
_PY_SUFFIXES = ("-python", "-python3", "-py", "-py3", "-client", "-sdk", "-api", "-lib", "-binary", "-headless")
#: (D-5) what an sdist holds beside its modules: files and folders that are no import name (pypi_modules)
_SDIST_NOT_MODULES = frozenset({"setup", "conftest", "noxfile", "tasks", "fabfile", "manage", "docs", "doc", "tests",
                                "test", "testing", "examples", "example", "benchmarks", "scripts", "tools", "build",
                                "dist"})
_MODULE_FILES = (".py", ".pyi", ".so", ".pyd")
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



def pypi_key(name):
    """A distribution's or a module's name as compared: PEP 503's (lowercase; `-`, `_` and `.` alike)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def pypi_import_keys(dist):
    """The keys of the names a distribution is commonly imported as (see above)."""
    k = pypi_key(dist)
    out = {k}
    for p in _PY_PREFIXES:
        if k.startswith(p) and len(k) > len(p) + 1:
            out.add(k[len(p):])
    for s in _PY_SUFFIXES:
        for base in list(out):
            if base.endswith(s) and len(base) > len(s) + 1:
                out.add(base[:-len(s)])
    if k.startswith("py") and not k.startswith("python") and len(k) > 4:
        out.add(k[2:])
    return out


def pypi_used_keys(imports):
    """The keys a release's imports (dotted module names) answer for: each one's chains (a.b.c: a, a-b, a-b-c)."""
    out = set()
    for dotted in imports:
        parts = [p for p in dotted.split(".") if p]
        for i in range(1, len(parts) + 1):
            out.add(pypi_key("-".join(parts[:i])))
    return out


def pypi_unused(declared, imports, texts):
    """The requirements (distribution names, in declared order, each once) none of the release's imports (dotted
    module names) answers for and no text quotes (see above); a stub distribution (types-x, x-stubs: types, not
    code, as npm's @types/) left out."""
    used_keys = pypi_used_keys(imports)
    declared = [d for d in declared if not pypi_key(d).startswith("types-") and not pypi_key(d).endswith("-stubs")]
    used = [dist for dist in declared
            if pypi_import_keys(dist) & used_keys or quoted_in(dist, texts) or quoted_in(pypi_key(dist), texts)]
    return unused(declared, used, pypi_key)


def pypi_modules(paths, sdist=False):
    """The keys of the top-level modules a distribution's files make importable, from their paths (as the archive
    reader gives them: an sdist's without its top folder): a folder holding Python or an extension module, a .py file,
    an extension module; a wheel's .dist-info left out, its .data/purelib and platlib read as the top level; an
    sdist's src/ read as the top, and what is no module left out (setup.py, tests/, docs/ …). A .pth file names none:
    it runs, and nothing imports it."""
    out = {_module_of(_installed_parts(str(path), sdist), sdist) for path in paths}
    out.discard(None)
    return out


def _installed_parts(path, sdist):
    """A file's path parts where the distribution installs it: an sdist's src/ and a wheel's .data/purelib or
    platlib are the top level."""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if sdist and parts[:1] == ["src"]:
        return parts[1:]
    if len(parts) >= 3 and parts[0].endswith(".data") and parts[1] in ("purelib", "platlib"):
        return parts[2:]
    return parts


def _module_of(parts, sdist):
    """The key of the top-level module a file at `parts` belongs to, else None (metadata, no Python, no module)."""
    if not parts or parts[0].endswith((".dist-info", ".data", ".egg-info")) or not parts[-1].endswith(_MODULE_FILES):
        return None
    name = parts[0].split(".", 1)[0] if len(parts) == 1 else parts[0]
    if not name.isidentifier() or (sdist and name.lower() in _SDIST_NOT_MODULES):
        return None
    return pypi_key(name)
