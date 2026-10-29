"""A dependency's Rust test code is left out of the file rules (0.1.9, N-20).

A crate's tests/, benches/ and examples/ are never built into a dependent, and neither the Rust reader nor the file
rules read them, as Go's *_test.go. Test code inside src/ is the same: what `#[cfg(test)]` (or a `cfg(all(…, test))`),
`#[test]`, `#[bench]` or `#[tokio::test]` marks is compiled only when the crate's own tests are, and the reader leaves
it out (rsread::test_items). The file rules read it, and its test vectors were WARNs in Part C's and Part F's sets. In
dependency mode (registry and guard scans, --deps) the engine now leaves out the findings of a line whose text, blanks
aside, is all in such an item, or of every line under a file's own `#![cfg(test)]`; a line that also holds other code,
and a file the parser can't read whole, keep theirs. A project's own code (project mode) is read whole, its tests too.
The rule is the engine's (scanfile.rs, rs_test_only_lines), so the npm package's dependency scans follow it too."""

import unittest

from lazaret.scanner import core
from tests.registry._review_support import B64_DATA


def b64(text, dep=True):
    return [i["line"] for i in core.scan_file("src/lib.rs", text, "rs", dep) if i["rule"] == "SC-B64"]


KEEP = f'pub const KEPT: &str = "{B64_DATA}";\n'


class TestItemsTests(unittest.TestCase):
    def test_a_test_module_is_left_out_and_the_rest_read(self):
        text = (f'pub fn f() {{}}\n\n#[cfg(test)]\nmod tests {{\n    const V: &str = "{B64_DATA}";\n\n'
                f'    #[test]\n    fn t() {{\n        let _ = "{B64_DATA}";\n    }}\n}}\n' + KEEP)
        self.assertEqual(b64(text), [12])
        self.assertEqual(b64(text, dep=False), [5, 9, 12], "a project's own tests are read")

    def test_what_marks_test_code(self):
        for attr in ("#[test]", "#[bench]", "#[tokio::test]", "#[cfg(test)]", "#[cfg(all(test, feature = \"x\"))]",
                     "#[cfg( all( unix , test ) )]"):
            with self.subTest(attr=attr):
                text = f'{attr}\nfn t() {{\n    let _ = "{B64_DATA}";\n}}\n' + KEEP
                self.assertEqual(b64(text), [5])
        for attr in ("#[cfg(any(test, unix))]", "#[cfg(not(test))]", "#[cfg(feature = \"test\")]", "#[cfg_attr(test, x)]",
                     "#[testing]", "#[should_panic]"):
            with self.subTest(attr=attr):
                text = f'{attr}\nfn t() {{\n    let _ = "{B64_DATA}";\n}}\n' + KEEP
                self.assertEqual(b64(text), [3, 5])

    def test_a_file_or_a_module_under_its_own_cfg_test(self):
        self.assertEqual(b64(f'#![cfg(test)]\n\nconst V: &str = "{B64_DATA}";\n' + KEEP), [])
        self.assertEqual(b64(f'#![cfg(not(test))]\n\nconst V: &str = "{B64_DATA}";\n'), [3])
        text = f'mod m {{\n    #![cfg(test)]\n    const V: &str = "{B64_DATA}";\n}}\n' + KEEP
        self.assertEqual(b64(text), [5])

    def test_a_line_with_other_code_is_read(self):
        one_line = f'#[test] fn t() {{ let _ = "{B64_DATA}"; }}\n'
        self.assertEqual(b64(one_line + KEEP), [2], "an item and its attribute on one line")
        self.assertEqual(b64(f'pub const A: &str = "{B64_DATA}"; #[cfg(test)] mod t {{}}\n'), [1])
        self.assertEqual(b64(f'#[cfg(test)] mod t {{}} pub const A: &str = "{B64_DATA}";\n'), [1])

    def test_a_file_the_parser_cannot_read_whole_is_read_whole(self):
        text = f'#[cfg(test)]\nmod tests {{\n    const V: &str = "{B64_DATA}";\n}}\nfn broken( {{\n'
        self.assertEqual(b64(text), [3])

    def test_other_languages_are_unchanged(self):
        text = f'#[cfg(test)]\nmod tests {{\n    const V: &str = "{B64_DATA}";\n}}\n'
        self.assertEqual([i["line"] for i in core.scan_file("x.go", text, "go", True) if i["rule"] == "SC-B64"], [3])


if __name__ == "__main__":
    unittest.main()
