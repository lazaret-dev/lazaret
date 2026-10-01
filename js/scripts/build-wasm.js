#!/usr/bin/env node
// `npm run build`: the native engine (../rust, docs/RUST_ENGINE.md) built as
// WebAssembly into native/lazaret.wasm, the file src/lib/native.js loads, with
// the engine's notices beside it (native/NOTICE: rust/NOTICE; see NOTICE).
// Needs Rust (rust/Cargo.toml's rust-version or newer) and its
// wasm32-unknown-unknown target (`rustup target add wasm32-unknown-unknown`).
// The workspace has no external crates: the build downloads nothing.
//
// `--check` (npm's prepack: `npm pack` or `npm publish` from a checkout)
// builds nothing: it fails unless native/ holds the engine of this version
// and its notice, so a package is never published without them. (Release CI
// packs with --ignore-scripts, after its own build.)
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const rust = fileURLToPath(new URL("../../rust/", import.meta.url));
const native = fileURLToPath(new URL("../native/", import.meta.url));

if (process.argv.includes("--check")) {
  const fail = (why) => { console.error(`error: ${why}: run \`npm run build\` first`); process.exit(1); };
  const read = (path) => { try { return readFileSync(path); } catch { return null; } };
  const wasm = read(join(native, "lazaret.wasm"));
  const notice = read(join(native, "NOTICE"));
  if (!wasm || !notice) fail("native/lazaret.wasm or native/NOTICE is missing");
  if (!notice.equals(readFileSync(join(rust, "NOTICE")))) fail("native/NOTICE is not rust/NOTICE");
  const { call } = await import("../src/lib/native.js");
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const engine = call("version").version;
  if (engine !== pkg.version) fail(`native/lazaret.wasm is the engine of ${engine}, not of ${pkg.version}`);
  console.log(`native/lazaret.wasm (engine ${engine}) and native/NOTICE are in place`);
  process.exit(0);
}

execFileSync("cargo", ["build", "--profile", "wasm", "--offline", "--locked", "--target", "wasm32-unknown-unknown",
  "-p", "lazaret-ffi"], { cwd: rust, stdio: "inherit" });
const target = process.env.CARGO_TARGET_DIR || join(rust, "target");
mkdirSync(native, { recursive: true });
copyFileSync(join(target, "wasm32-unknown-unknown", "wasm", "lazaret_native.wasm"), join(native, "lazaret.wasm"));
chmodSync(join(native, "lazaret.wasm"), 0o644);       // data, not a program (the linker marks it executable)
copyFileSync(join(rust, "NOTICE"), join(native, "NOTICE"));
console.log("native/lazaret.wasm built (and native/NOTICE)");
