// Config and data files: which ones are read for credentials: .env, JSON, YAML, TOML, INI, .properties, shell, PEM
// keys, Dockerfiles, .npmrc / .pypirc and Terraform variables are read as text and checked by the two credential
// rules only, never as code. Which files they are and how they are read are the native engine's (BR-7 step 3:
// config.rs, the `scan_config` call, scanConfigFile in ../scanner/scan.js; step 4 e: collect.rs), as for the Python
// package (lazaret/scanner/configsecrets.py). Never import from ../scanner/ (RESTRUCTURE.md §5).

import { call } from "./native.js";

/** Config files larger than this are not read (Q-SKIPPED-CONFIG: the rule pack's CONFIG_SCAN_CAP). */
export const CONFIG_SCAN_CAP = 2_000_000;

/** True for the text of one of Lazaret's own JSON reports (a report is not config). */
export function ownReport(text) { return call("collect_check", { check: "own_report" }, String(text)); }

/** True for a file (by its base name) that is read as config or data. */
export function isConfigFile(name) { return call("collect_check", { check: "config_name", name: String(name) }); }
