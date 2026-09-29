"""Seeded random JavaScript / TypeScript projects for the engine parity tests.

Every program is valid (the readers must accept it) and built from the
shapes the cross-file flow pass follows: functions of every kind, classes,
object literals with methods, ESM and CommonJS exports and relative imports,
Express-style routes, request data, sinks, sanitizers, locals, closures,
loops, branches, destructuring, spreads, callbacks, templates and JSX. The
same seed gives the same project (random.Random only: no dict or set
ordering is involved), so both engines read the very same text.

Inert text only: nothing here is executed.
"""
import random

SOURCES = ["req.query.q", "req.body.name", "req.params.id", "req.headers.host", "request.query.x",
           "location.hash", "window.location.search", "process.argv[2]", "req.get('x')", "req.cookies.sid"]
SINK_CALLS = ["exec({})", "execSync('ls ' + {})", "db.query('SELECT * FROM t WHERE a = ' + {})",
              "db.query(`SELECT ${{{}}}`)", "db.query('SELECT ?', [{}])", "pool.query({})", "eval({})",
              "new Function({})", "fetch({})", "fetch('https://api.example.com/' + {})", "axios.get({})",
              "res.redirect({})", "res.redirect('/p/' + {})", "res.send({})", "res.send({{ v: {} }})",
              "res.type('text/plain').send({})", "fs.readFileSync({})", "res.sendFile({})",
              "res.sendFile({}, {{ root: DIR }})", "document.write({})", "ejs.render({})", "vm.runInNewContext({})",
              "knex.raw('SELECT ' + {})", "el.insertAdjacentHTML('beforeend', {})", "cp.exec({})"]
SINK_ASSIGN = ["el.innerHTML = {}", "node.outerHTML = '<b>' + {}", "this.el.innerHTML += {}"]
SANITIZERS = ["Number({})", "parseInt({}, 10)", "escapeHtml({})", "encodeURIComponent({})", "shellQuote({})",
              "path.basename({})", "DOMPurify.sanitize({})", "pool.escape({})", "String({})", "JSON.stringify({})",
              "({}).trim()", "({}).toLowerCase()", "({}).includes('x')", "({}).length", "[{}].join(',')", "`${{{}}}`"]


class Gen:
    def __init__(self, seed):
        self.r = random.Random(seed)
        self.n = 0

    def pick(self, seq):
        return seq[self.r.randrange(len(seq))]

    def chance(self, p):
        return self.r.random() < p

    def fresh(self, base="v"):
        self.n += 1
        return f"{base}{self.n}"

    # ---- expressions ----
    def value(self, names, depth=0):
        """An expression over names (locals, parameters), sources and calls."""
        k = self.r.randrange(12 if depth < 3 else 5)
        if k == 0 or not names:
            return self.pick(SOURCES) if self.chance(0.5) else self.pick(["'lit'", "42", "null", "`t`", "DIR"])
        if k in (1, 2):
            return self.pick(names)
        if k == 3:
            return self.pick(SANITIZERS).format(self.value(names, depth + 1))
        if k == 4:
            return f"{self.value(names, depth + 1)} + {self.value(names, depth + 1)}"
        if k == 5:
            return f"`pre ${{{self.value(names, depth + 1)}}} post`"
        if k == 6 and self.funcs:
            f = self.pick(self.funcs)
            return f"{f}({', '.join(self.value(names, depth + 1) for _ in range(self.r.randrange(3)))})"
        if k == 7:
            return f"{self.value(names, depth + 1)} || {self.value(names, depth + 1)}"
        if k == 8:
            return f"({self.value(names, depth + 1)} ? {self.value(names, depth + 1)} : {self.value(names, depth + 1)})"
        if k == 9:
            return f"[{self.value(names, depth + 1)}, 1]"
        if k == 10:
            return f"({{ a: {self.value(names, depth + 1)}, ...{self.pick(names)} }})"
        return f"(x => {self.value(names + ['x'], depth + 1)})"

    # ---- statements ----
    def stmt(self, names, depth, out, indent):
        pad = "  " * indent
        k = self.r.randrange(16 if depth < 3 else 9)
        if k == 0:
            v = self.fresh()
            kw = self.pick(["const", "let", "var"])
            out.append(f"{pad}{kw} {v} = {self.value(names)};")
            names.append(v)
        elif k == 1:
            out.append(f"{pad}{self.pick(SINK_CALLS).format(self.value(names))};")
        elif k == 2:
            out.append(f"{pad}{self.pick(SINK_ASSIGN).format(self.value(names))};")
        elif k == 3 and self.funcs:
            f = self.pick(self.funcs)
            out.append(f"{pad}{f}({', '.join(self.value(names) for _ in range(self.r.randrange(1, 4)))});")
        elif k == 4 and names:
            target = self.pick(names)
            op = self.pick(["=", "+=", "||="])
            out.append(f"{pad}{target} {op} {self.value(names)};")
        elif k == 5:
            v = self.fresh()
            out.append(f"{pad}const {{ {v}, b{self.n}: {v}x = 1 }} = {self.value(names)};")
            names.extend([v, f"{v}x"])
        elif k == 6:
            v = self.fresh()
            out.append(f"{pad}const [{v}, ...{v}r] = {self.value(names)};")
            names.extend([v, f"{v}r"])
        elif k == 7 and names:
            arr = self.fresh("arr")
            out.append(f"{pad}const {arr} = [];")
            out.append(f"{pad}{arr}.push({self.value(names)});")
            names.append(arr)
        elif k == 8:
            out.append(f"{pad}return {self.value(names)};")
        elif k == 9:
            out.append(f"{pad}if ({self.value(names)}) {{")
            self.block(list(names), depth + 1, out, indent + 1)
            if self.chance(0.5):
                out.append(f"{pad}}} else if ({self.value(names)}) {{")
                self.block(list(names), depth + 1, out, indent + 1)
            if self.chance(0.5):
                out.append(f"{pad}}} else {{")
                self.block(list(names), depth + 1, out, indent + 1)
            out.append(f"{pad}}}")
        elif k == 10:
            v = self.fresh("it")
            out.append(f"{pad}for (const {v} of {self.value(names)}) {{")
            self.block(names + [v], depth + 1, out, indent + 1)
            out.append(f"{pad}}}")
        elif k == 11:
            out.append(f"{pad}while ({self.value(names)}) {{")
            self.block(list(names), depth + 1, out, indent + 1)
            out.append(f"{pad}}}")
        elif k == 12:
            out.append(f"{pad}try {{")
            self.block(list(names), depth + 1, out, indent + 1)
            out.append(f"{pad}}} catch (e) {{")
            self.block(names + ["e"], depth + 1, out, indent + 1)
            out.append(f"{pad}}}")
        elif k == 13:
            out.append(f"{pad}[1, 2].forEach((i) => {{")
            self.block(names + ["i"], depth + 1, out, indent + 1)
            out.append(f"{pad}}});")
        elif k == 14:
            out.append(f"{pad}switch ({self.value(names)}) {{")
            out.append(f"{pad}  case 1:")
            self.block(list(names), depth + 1, out, indent + 2)
            out.append(f"{pad}  default:")
            self.block(list(names), depth + 1, out, indent + 2)
            out.append(f"{pad}}}")
        else:
            out.append(f"{pad}log({self.value(names)});")

    def block(self, names, depth, out, indent):
        for _ in range(self.r.randrange(1, 5)):
            self.stmt(names, depth, out, indent)

    # ---- functions and modules ----
    def function(self, name, out, style):
        params = [f"p{self.fresh('')}" for _ in range(self.r.randrange(0, 4))]
        if self.chance(0.2):
            params.append("{ id, name }")
        body = []
        names = [p for p in params if not p.startswith("{")] + (["id", "name"] if any(p.startswith("{") for p in params)
                                                                else [])
        self.block(names, 0, body, 1)
        head = ", ".join(params)
        if style == "decl":
            out.append(f"function {name}({head}) {{")
        elif style == "expr":
            out.append(f"const {name} = function ({head}) {{")
        elif style == "arrow":
            out.append(f"const {name} = async ({head}) => {{")
        else:
            out.append(f"exports.{name} = function {name}({head}) {{")
        out.extend(body)
        out.append("}" + (";" if style in ("expr", "arrow", "exports") else ""))

    def module(self, path, others, ts):
        out = []
        self.funcs = []
        for o in others:
            rel = self.rel(path, o)
            names = self.exports[o]
            if not names:
                continue
            pick = [self.pick(names) for _ in range(self.r.randrange(1, 3))]
            pick = list(dict.fromkeys(pick))
            if self.chance(0.5):
                out.append(f"import {{ {', '.join(pick)} }} from '{rel}';")
            else:
                out.append(f"const {{ {', '.join(pick)} }} = require('{rel}');")
            self.funcs.extend(pick)
        if self.chance(0.3):
            out.append("const cp = require('child_process');")
        mine = []
        for _ in range(self.r.randrange(1, 5)):
            name = self.fresh("f")
            self.function(name, out, self.pick(["decl", "expr", "arrow", "exports"]))
            mine.append(name)
            self.funcs.append(name)
        if self.chance(0.4):
            cls = self.fresh("C")
            out.append(f"class {cls} {{")
            for m in range(self.r.randrange(1, 3)):
                body = []
                self.block(["a"], 1, body, 2)
                out.append(f"  m{m}(a) {{")
                out.extend(body)
                out.append("  }")
            out.append("}")
            out.append(f"new {cls}().m0({self.value(['x'])});")
        for _ in range(self.r.randrange(0, 3)):
            method = self.pick(["get", "post", "use"])
            path_arg = "" if method == "use" and self.chance(0.5) else f"'/{self.fresh('r')}', "
            body = []
            self.block(["req", "res"], 1, body, 1)
            out.append(f"app.{method}({path_arg}(req, res) => {{")
            out.extend(body)
            out.append("});")
        if self.chance(0.3):
            out.append(f"export const Page = () => <div dangerouslySetInnerHTML={{{{ __html: {self.value(['x'])} }}}} />;"
                       if not ts else "")
        style = self.r.randrange(3)
        if style == 0:
            out.append(f"module.exports = {{ {', '.join(mine)} }};")
        elif style == 1:
            out.append(f"export {{ {', '.join(mine)} }};")
        self.exports[path] = mine
        if ts:
            out = [line.replace(f"  m{m}(a) {{", f"  m{m}(a: string) {{") for line in out for m in (0,)]
        return "\n".join(line for line in out if line) + "\n"

    @staticmethod
    def rel(frm, to):
        a = frm.split("/")[:-1]
        b = to.split("/")
        i = 0
        while i < len(a) and i < len(b) - 1 and a[i] == b[i]:
            i += 1
        up = [".."] * (len(a) - i)
        rest = b[i:]
        spec = "/".join(up + rest) if up else "./" + "/".join(rest)
        for ext in (".js", ".ts", ".mjs"):
            if spec.endswith(ext) and ext != ".mjs":
                spec = spec[:-len(ext)] + (".js" if ext == ".ts" and random.random() < 0 else "")
        return spec

    def project(self):
        paths = ["lib/util.js", "lib/db.ts", "routes/app.js", "index.mjs", "web/view.jsx"]
        n = self.r.randrange(1, len(paths) + 1)
        chosen = paths[:n]
        self.exports = {}
        files = []
        for k, path in enumerate(chosen):
            others = chosen[:k]
            files.append({"path": path, "content": self.module(path, others, path.endswith(".ts")), "lang": "js"})
        return files


def projects(seed, count):
    """count seeded projects: lists of {path, content, lang} files."""
    return [Gen(seed * 100_003 + k).project() for k in range(count)]
