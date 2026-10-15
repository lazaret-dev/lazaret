"""S-EXEC-JS reads a member call's receiver (0.1.9; the engine's scanfile.rs exec_js_regex, the dashboard's
execJsRegex; js/test/exec-js.test.js has the npm package's twin).

S-EXEC-JS flagged every `x.exec(…)` with a non-literal argument as child_process's, so RegExp's `exec` in a matching
loop (`while ((m = re.exec(s)))`) was CRITICAL in any script that matches text. Now a call on a regex is left out: a
literal the lexer reads as one, or a name the file assigns a whole regex and nothing else. Everything else counts as
before, whatever the file loads: a receiver can come from another file (`require('./a').exec(cmd)`) or a computed
name, so the rule does not ask where it came from. Benign code only.
"""
import time
import unittest

from lazaret.scanner import core

CP = "const cp = require('child_process');\n"


def lines(text, lang="js"):
    # RUN stands for exec, so that Lazaret's scan of its own sources does not read these strings as calls
    text = text.replace("RUN", "exec")
    return [i["line"] for i in core.scan_file("x.js", text, lang) if i["rule"] == "S-EXEC-JS"]


class RegexTests(unittest.TestCase):
    def test_a_regex_literal(self):
        self.assertEqual(lines(CP + "const d = /^[A-Za-z]:/i.RUN(p);\n"), [])
        self.assertEqual(lines("const m = /a(b)\\/c/g . RUN(s);\n"), [])

    def test_a_name_assigned_a_regex_and_nothing_else(self):
        self.assertEqual(lines("const RE = /a(b)/g;\nlet m;\nwhile ((m = RE.RUN(text))) use(m);\n"), [])
        self.assertEqual(lines(CP + "const re = new RegExp(x);\nconst m = re.RUN(line);\n"), [])
        self.assertEqual(lines(CP + "let re = RegExp('(' + x + ')', 'g') // why\n, n = 0;\nre?.RUN(line);\n"), [])
        self.assertEqual(lines("let re = /x/g\nre.lastIndex = 0\nre.RUN(s)\n"), [])

    def test_another_name_or_member_is_not(self):
        self.assertEqual(lines(CP + "const re = /x/;\nconfig.re.RUN(cmd);\n"), [3])
        self.assertEqual(lines(CP + "const re = /x/;\nconfig. re.RUN(cmd);\n"), [3])
        self.assertEqual(lines("const re = /x/;\nmy_re.RUN(cmd);\n"), [2])


class ShellTests(unittest.TestCase):
    def test_shell_calls_still_count(self):
        self.assertEqual(lines(CP + "cp.RUN(cmd);\ncp.RUNSync(cmd);\nrunner?.RUN(cmd);\n"), [2, 3, 4])
        self.assertEqual(lines("const { exec } = require('child_process');\nRUN('ls ' + dir);\n"), [2])
        self.assertEqual(lines("RUN(cmd);\n"), [1])

    def test_wherever_the_receiver_came_from(self):
        self.assertEqual(lines("require('./run').RUN(cmd);\n"), [1])
        self.assertEqual(lines("const c = require('./run');\nc.RUN(cmd);\n"), [2])
        self.assertEqual(lines("const c = require('child_' + 'process');\nc.RUN(cmd);\n"), [2])
        self.assertEqual(lines("db.RUN(sql + where);\n"), [1])

    def test_a_name_also_assigned_something_else(self):
        self.assertEqual(lines(CP + "let re = /x/;\nre = cp;\nre.RUN(cmd);\n"), [4])
        self.assertEqual(lines(CP + "let re = /x/;\nre &&= cp;\nre.RUN(cmd);\n"), [4])

    def test_a_regex_that_is_not_the_whole_value(self):
        self.assertEqual(lines(CP + "const re = /x/ && cp;\nre.RUN(cmd);\n"), [3])
        self.assertEqual(lines(CP + "const re = /x/\n  && cp;\nre.RUN(cmd);\n"), [4])
        self.assertEqual(lines(CP + "const re = new RegExp(x) || cp;\nre.RUN(cmd);\n"), [3])

    def test_a_division_is_not_a_regex(self):
        self.assertEqual(lines("const ig = require('child_process');\nx = \"(/\" + 1 /ig.RUN(cmd);\n"), [2])


class TimeTests(unittest.TestCase):
    def test_unclosed_constructors_on_one_line_take_linear_time(self):
        # each `RegExp(` is read to its `)` within _REGEX_CTOR_REACH steps; read to the end of the line, the time grew
        # with the square of their number (16,000 of them, 160 kB: over 6 seconds; 32,000: 0.2 seconds now)
        text = "a=RegExp((" * 32000 + "\nb.RUN(c);\n"
        start = time.monotonic()
        self.assertEqual(lines(text), [2])
        self.assertLess(time.monotonic() - start, 5)


if __name__ == "__main__":
    unittest.main()
