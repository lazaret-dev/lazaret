// Config and data files: which ones are read for credentials (lazaret/scanner/configsecrets.py's collection part):
// .env, JSON, YAML, TOML, INI, .properties, shell, PEM keys, Dockerfiles, .npmrc / .pypirc and Terraform variables
// are read as text and checked by the two credential rules only, never as code. How they are read is the native
// engine's (BR-7 step 3: config.rs, the `scan_config` call; scanConfigFile in ../scanner/scan.js).
// Never import from ../scanner/ (RESTRUCTURE.md §5).

import { pyRe } from "./pycompat.js";
import { pyExt } from "./binary.js";

export const CONFIG_EXTS = new Set([
  ".env", ".json", ".jsonc", ".json5", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf",
  ".properties", ".sh", ".bash", ".zsh", ".pem", ".key", ".tfvars",
]);
export const CONFIG_NAMES = new Set([
  ".env", ".envrc", ".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".dockercfg",
  "dockerfile", "containerfile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
]);
export const CONFIG_SKIP_NAMES = new Set([
  "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "packages.lock.json", "pylock.toml",
]);
/** Config files larger than this are not read (Q-SKIPPED-CONFIG). */
export const CONFIG_SCAN_CAP = 2_000_000;

// Lazaret's own JSON reports (lazaret-report.json, lazaret-sca.json, a
// baseline) start with the provenance marker; they are not read.
const OWN_REPORT_RE = pyRe(String.raw`^﻿?\s*\{\s*"generatedBy"\s*:\s*"lazaret-`);
export function ownReport(text) { return OWN_REPORT_RE.test(text); }

/** True for a file (by its base name) that is read as config or data. */
export function isConfigFile(name) {
  const low = String(name).toLowerCase();
  if (CONFIG_SKIP_NAMES.has(low) || (low.startsWith("pylock.") && low.endsWith(".toml"))) return false;
  if (CONFIG_NAMES.has(low) || low.startsWith(".env.") || low.startsWith("dockerfile.")
      || low.endsWith(".dockerfile")) return true;
  return CONFIG_EXTS.has(pyExt(low));
}
