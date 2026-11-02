// FP-HOMOGLYPH-ORDINAL: an ordinal (digits or one ASCII letter, then ª or º, no identifier character around it) in
// what a JSX file holds as display text, by the lexer and the parser, in a file that does not parse as JavaScript
// without JSX, is not a look-alike name in the npm package's project scan and --deps, as in the Python package's
// (python/tests/scanner/test_review_homoglyph_ordinal.py; the engine's scanfile.rs, ordinal_display_runs). A
// look-alike in a name (`evªl` too), any other look-alike in display text, and the review of Oct 27's comparisons
// (`of <b> evªl("1")`, `obj.return <b> evªl("1")`) are SC-HOMOGLYPH as before. Inert files: nothing is run.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { run } from "../src/index.js";

const PKG = '{"name": "x", "version": "1.0.0", "main": "index.js"}\n';
const TALLY = `import React from "react";

export function LocalLibrary({ items }) {
  return (
    <ul>
      {items.map((item, index) => (
        <li key={item.id}>
          <span className="n">Nº {index + 1}</span> {item.title}
        </li>
      ))}
    </ul>
  );
}
`;

function scan(files, extra = []) {
  const d = mkdtempSync(join(tmpdir(), "lazaret-hg-"));
  try {
    for (const [rel, data] of Object.entries(files)) {
      const p = join(d, ...rel.split("/"));
      mkdirSync(dirname(p), { recursive: true });
      writeFileSync(p, data);
    }
    const code = run(["check", d, "-q", "--no-html", ...extra], { out: () => {}, err: () => {} });
    return { code, issues: JSON.parse(readFileSync(join(d, "lazaret-report.json"), "utf8")).issues };
  } finally { rmSync(d, { recursive: true, force: true }); }
}
const hg = (issues) => issues.filter((i) => i.rule === "SC-HOMOGLYPH").map((i) => [i.file.replaceAll("\\", "/"), i.line, i.sev]).sort();

test("ordinals in display text are quiet (the tally case and its variants)", () => {
  const r = scan({
    "package.json": PKG, "src/library/LocalLibrary.tsx": TALLY,
    "src/a.jsx": "export const A = () => <p>1º lugar, 2ª vez, Nº 7, nº 8</p>;\n",
    "src/b.js": "export const B = () => <p>Mª José, Nº {n}</p>;\n",
    "src/c.tsx": "export const C = () => <p>it's Nº {n}</p>;\n",
  });
  assert.deepEqual(hg(r.issues), []);
  assert.equal(r.code, 0);
});

test("look-alikes in names, and other look-alikes in display text, stay", () => {
  const r = scan({
    "package.json": PKG,
    "src/h.ts": "const Nº = 1;\nexport const y = Nº + 1;\n",
    "src/j.js": "const evªl = eval;\nevªl('1');\n",
    "src/k.tsx": "export const K = () => <a>Visit pаypal</a>;\n",
    "src/n.tsx": "export const N = () => <p>Nº {isАdmin}</p>;\nconst isAdmin = 1;\n",
  });
  assert.deepEqual(hg(r.issues), [["src/h.ts", 1, "MAJOR"], ["src/h.ts", 2, "MAJOR"], ["src/j.js", 1, "CRITICAL"],
    ["src/j.js", 2, "CRITICAL"], ["src/k.tsx", 1, "MAJOR"], ["src/n.tsx", 1, "CRITICAL"]]);
});

test("--deps: a dependency's labels are quiet, its look-alike names are not", () => {
  const r = scan({
    "package.json": PKG, "index.js": "1;\n",
    "node_modules/ui/package.json": '{"name": "ui", "version": "1.0.0"}\n',
    "node_modules/ui/LocalLibrary.jsx": TALLY,
    "node_modules/ui/bad.js": "const evªl = eval;\nevªl('1');\n",
  }, ["--deps"]);
  assert.deepEqual(hg(r.issues), [["node_modules/ui/bad.js", 1, "CRITICAL"], ["node_modules/ui/bad.js", 2, "CRITICAL"]]);
});

// the review of Oct 27 (H1): two comparisons a JSX reading took for an element, in every extension it read
const SHAPES = {
  of: 'const of=1,b=2;\nof <b> evªl("1");\n',
  property: 'const obj={return:1},b=2;\nobj.return <b> evªl("1");\n',
  control: 'const a=1,b=2;\na <b> evªl("1");\n',
};
const EXTS = ["js", "mjs", "cjs", "jsx", "tsx"];
const LABEL = "export const L = () => <p>Nº 1, 1º lugar, 2ª vez</p>;\n";

test("the review's comparisons stay CRITICAL in .js .mjs .cjs .jsx .tsx; real labels stay quiet", () => {
  const files = { "package.json": PKG, "src/library/LocalLibrary.tsx": TALLY };
  const want = [];
  for (const [name, text] of Object.entries(SHAPES)) {
    for (const ext of EXTS) {
      files[`${name}/x.${ext}`] = text;
      want.push([`${name}/x.${ext}`, 2, "CRITICAL"]);
      files[`label/${name}.${ext}`] = LABEL;
    }
  }
  files["names/of.js"] = "const of=1,b=2;\nof <b> Nº;\n";
  files["names/mixed.jsx"] = LABEL + "const of=1,b=2;\nof <b> Nº;\n";
  files["names/evil.tsx"] = "export const G = () => <p>evªl</p>;\n";
  want.push(["names/evil.tsx", 1, "CRITICAL"], ["names/mixed.jsx", 3, "MAJOR"], ["names/of.js", 2, "MAJOR"]);
  const r = scan(files);
  assert.deepEqual(hg(r.issues), want.sort());
});

test("--deps: the review's comparisons in a dependency stay CRITICAL", () => {
  const r = scan({
    "package.json": PKG, "index.js": "1;\n",
    "node_modules/x/package.json": '{"name": "x", "version": "1.0.0"}\n',
    "node_modules/x/of.mjs": SHAPES.of, "node_modules/x/prop.cjs": SHAPES.property,
    "node_modules/x/L.jsx": LABEL,
  }, ["--deps"]);
  assert.deepEqual(hg(r.issues), [["node_modules/x/of.mjs", 2, "CRITICAL"], ["node_modules/x/prop.cjs", 2, "CRITICAL"]]);
});
