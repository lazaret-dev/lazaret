#!/usr/bin/env python3
"""Check inert path strings against the installed Node and Python libraries.

No source snippets, deletions or network operations are executed. The checked-in
matrix is also read by Rust's model::paths test. Go has a separate stdlib test.
"""
import argparse
import json
import ntpath
from pathlib import Path
import posixpath
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "tests/fixtures/path-api-semantics.json"


def main():
    sys.path.insert(0, str(ROOT / "python/src"))
    from lazaret.scanner.core import configure_stdio
    configure_stdio()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    rows = json.loads(MATRIX.read_text(encoding="utf-8"))
    node_rows = [r for r in rows if r["api"].startswith("node.")]
    program = """const fs=require('fs'),p=require('path');
const rows=JSON.parse(fs.readFileSync(0,'utf8'));
process.stdout.write(JSON.stringify(rows.map(r=>{const [,f,op]=r.api.split('.');return p[f][op](...r.parts)})));"""
    node = json.loads(subprocess.run(["node", "-e", program], input=json.dumps(node_rows),
                                    text=True, encoding="utf-8", capture_output=True,
                                    check=True, timeout=30).stdout)
    results = iter(node)
    checked = 0
    for row in rows:
        if row["api"].startswith("node."):
            result = next(results)
        elif row["api"].startswith("python."):
            module = posixpath if ".posixpath." in row["api"] else ntpath
            result = module.join(*row["parts"])
        else:
            continue
        checked += 1
        if args.refresh:
            row["result"] = result
        elif result != row["result"]:
            raise AssertionError((row, result))
    if args.refresh:
        MATRIX.write_text(json.dumps(rows, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(f"{checked} Node/Python path-library comparisons passed")


if __name__ == "__main__":
    main()
