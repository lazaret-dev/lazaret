# JS-Confuser's string concealing (D-11)

`input.js` is an inert script in the shape of an exfiltration (the host name and the environment, sent to
`collect.invalid`, a reserved name); it is never run. The obfuscated files are what JS-Confuser 2.1.3 (MIT,
`npm install js-confuser@2.1.3`) wrote, once each, with `target: "node"`:

- `string-concealing.js`: `{ stringConcealing: true }`, string concealing alone;
- `preset-low.js`: `{ preset: "low" }`, string concealing with the low preset's other transforms (renamed names,
  minified code, numbers moved into a list);
- `benign-string-concealing.js`: `benign-input.js`, a greeting, with `{ stringConcealing: true }` (its decoder is
  the function's own: JS-Confuser puts one in a block now and then).

Its "medium" and "high" presets put the whole program in a string that `Function` runs, which the decoded view does
not read.
