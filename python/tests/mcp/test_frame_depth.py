"""The MCP server's deep-nesting guard doesn't depend on the interpreter.

Older Pythons raise RecursionError on very deep JSON; 3.14's parser doesn't.
The server measures depth itself, so every version answers a too-deep frame
with -32700 and keeps serving."""

import unittest

from lazaret.mcp.server import MAX_FRAME_DEPTH as LIMIT
from lazaret.mcp.server import _frame_depth_exceeds, _loads_frame


class FrameDepthTests(unittest.TestCase):
    def test_depth_limit(self):
        cases = {
            "at the limit": ("[" * LIMIT + "]" * LIMIT, False),
            "one past the limit": ("[" * (LIMIT + 1) + "]" * (LIMIT + 1), True),
            "unterminated 60k": ("[" * 60000, True),
            "objects and arrays": ('{"a":' * 300 + "[" * 300 + "1" + "]" * 300 + "}" * 300, True),
            "brackets inside a string": ('{"code":"' + "[" * 5000 + '"}', False),
            "escaped quotes in a string": ('{"s":"a\\"' + "{" * 5000 + '\\"b"}', False),
        }
        for name, (line, expected) in cases.items():
            with self.subTest(case=name):
                self.assertIs(_frame_depth_exceeds(line), expected)

    def test_too_deep_frame_is_a_parse_error(self):
        req, err = _loads_frame("[" * (LIMIT + 1) + "]" * (LIMIT + 1))
        self.assertIsNone(req)
        self.assertEqual(err["code"], -32700)

    def test_normal_frames_parse(self):
        req, err = _loads_frame('{"jsonrpc":"2.0","id":7,"method":"tools/call",'
                                '"params":{"name":"scan_snippet","arguments":{"code":"x = [[1], {2: 3}]"}}}')
        self.assertIsNone(err)
        self.assertEqual(req["id"], 7)

    def test_malformed_frames_are_a_parse_error(self):
        # JSON-RPC 2.0: not-JSON is answered with -32700 (review finding 18c)
        req, err = _loads_frame('{"jsonrpc": "2.0", "id": 1')
        self.assertIsNone(req)
        self.assertEqual(err["code"], -32700)


if __name__ == "__main__":
    unittest.main()
