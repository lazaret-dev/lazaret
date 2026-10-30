"""BIG-BUNDLE-TAIL's texts: ncc-style bundles past 2,000,000 characters (a GitHub Action's dist/index.js is one), with
code put at a module's place, and the action scan of one. Inert text only: nothing is run; the addresses are .invalid.
"""
from lazaret.registry import repo
from tests.registry import _actions_support as fx

ACTION_YML = "name: x\nruns:\n  using: node24\n  main: dist/index.js\n"
HARVEST = "reads credentials or the whole environment and sends data over the network"
PAST = 2_100_000


def module(k, code=None):
    """A webpack/ncc module: `code`, or about 1 KB of benign code (a class, helpers, a request with its own options)."""
    body = code if code is not None else (
        f"function normalize{k}(options) {{\n  options = options || {{}};\n"
        f"  const result = {{ retries: options.retries || 3, timeout: options.timeout || 1000, name: \"m{k}\" }};\n"
        f"  return result;\n}}\n"
        f"class Client{k} {{\n  constructor(base) {{ this.base = base; "
        f"this.options = normalize{k}({{ retries: {k % 7} }}); }}\n"
        f"  path(p) {{ return this.base + \"/\" + p.split(\"/\").filter((s) => s.length > 0)"
        f".map((s) => encodeURIComponent(s)).join(\"/\"); }}\n"
        f"  format(data) {{ let out = \"\"; for (const key of Object.keys(data)) {{ out += key + \"=\" + "
        f"String(data[key]).replace(/[\\n\\r]/g, \" \") + \";\"; }} return out; }}\n"
        f"  async get(p) {{ const res = await __nccwpck_require__(9002).request(this.path(p), "
        f"{{ method: \"GET\", timeout: this.options.timeout }}); "
        f"return res.status === 200 ? JSON.parse(res.body) : null; }}\n}}\n"
        f"const cache{k} = new Map();\nfunction lookup{k}(key) {{ if (cache{k}.has(key)) return cache{k}.get(key); "
        f"const v = key.split(\"\").reverse().join(\"\") + {k}; cache{k}.set(key, v); return v; }}\n"
        f"module.exports = {{ Client{k}, lookup{k}, normalize{k} }};\n")
    return f"/***/ {k}:\n/***/ ((module, exports, __nccwpck_require__) => {{\n\n\"use strict\";\n{body}\n/***/ }}),\n\n"


CORE = ("exports.getInput = function getInput(name) { return \"x\" + name; };\n"
        "exports.info = function info(message) { return message.length; };\n")


def bundle(size=PAST, code=None, at=0.0, main="", helper=""):
    """A bundle of about `size` characters: its benign modules, `code` among them (at its start: 0, its middle: 0.5,
    its end: 1), `main`, the entry's code, after the module table, `helper` added to the core module (9001) at its
    start."""
    mods, n = [], 0
    while n < size:
        mods.append(module(10_000 + len(mods)))
        n += len(mods[-1])
    if code is not None:
        mods.insert(min(int(len(mods) * at), len(mods)), module(99, code))
    mods.insert(0, module(9001, CORE + helper))
    mods.insert(1, module(9002, "module.exports = { request: async (url, options) => "
                                "({ status: 200, body: \"{}\", url, options }) };\n"))
    return ("/******/ (() => { // webpackBootstrap\n/******/ \tvar __webpack_modules__ = ({\n\n" + "".join(mods)
            + "/******/ \t});\n/******/ \tvar __webpack_module_cache__ = {};\n"
            "/******/ \tfunction __nccwpck_require__(moduleId) {\n"
            "/******/ \t\tvar cachedModule = __webpack_module_cache__[moduleId];\n"
            "/******/ \t\tif (cachedModule !== undefined) return cachedModule.exports;\n"
            "/******/ \t\tvar module = __webpack_module_cache__[moduleId] = { exports: {} };\n"
            "/******/ \t\t__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);\n"
            "/******/ \t\treturn module.exports;\n/******/ \t}\n"
            "(() => {\nconst core = __nccwpck_require__(9001);\nasync function run() {\n" + main
            + "  core.info(\"done\");\n}\nrun();\n})();\n/******/ })();\n")


def action_issues(js, rules=("SC-IMPORT-RISK", "SC-TRUNCATED")):
    """The action scan of a repository whose action runs `js` (dist/index.js): its verdict, and its issues of
    `rules` as (rule, severity, message)."""
    res = repo.scan_action(fx.archive("o/r", "0" * 40, {"action.yml": ACTION_YML, "dist/index.js": js}), "")
    return res["verdict"], [(i["rule"], i["sev"], i["msg"]) for i in res["issues"] if i["rule"] in rules]
