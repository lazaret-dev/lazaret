// Baselines (new-code focus): the engine's (baseline.rs, BR-7 step 4 d), as core.apply_baseline and the
// reports module's fingerprints and signature ask it. What stays here is the package's: whether the file is one
// of our reports (its head), where it is (inside the scanned tree, links followed), its bytes, the key from the
// environment, and the warnings handed to `warn`.
//
// Trust (G17): the engine marker is a public constant, so a hand-written
// "baseline" carrying it could zero `newIssues`. Therefore:
//   * $LAZARET_BASELINE_KEY set: JSON reports carry an HMAC-SHA256 signature
//     over their fingerprints, and a baseline is trusted only if its
//     signature verifies with that key (wherever it lives);
//   * no key: a baseline inside the scanned tree is untrusted (the scanned
//     repository could have planted it); outside it the marker check applies.
// An untrusted baseline counts every finding as new (fail closed). N-15: a signed baseline that verifies accepts
// the findings it holds that no marker can accept (SC-*, X-*): the gate's conditions on findings are judged
// without them.

import { readFileSync, realpathSync } from "node:fs";
import { sep } from "node:path";
import { isOurReport } from "./lib/fs.js";
import { call, bytesText } from "./lib/native.js";
import { findingRows } from "./result.js";

export const BASELINE_KEY_ENV = "LAZARET_BASELINE_KEY";
export const SIGNATURE_FIELD = "baselineSignature";
export const SIGNATURE_ALG = "HMAC-SHA256";

/** Findings per engine call. */
const BATCH = 2000;

/** Each finding's rule|path|flagged-line fingerprint, null for an entry that has none (the engine's). */
export function fingerprints(issues) {
  const out = [];
  for (let k = 0; k < issues.length; k += BATCH) {
    for (const fp of call("baseline_fingerprints", { issues: issues.slice(k, k + BATCH) }).fingerprints) out.push(fp);
  }
  return out;
}

/** One finding's fingerprint; throws a TypeError for an entry that has none (core.fingerprint). */
export function fingerprint(issue) {
  const fp = fingerprints([issue])[0];
  if (fp === null) throw new TypeError("not a baseline entry (an object with rule, file, line and snipStart)");
  return fp;
}

/** Hex HMAC-SHA256 over a domain prefix and the sorted, distinct fingerprints as ASCII JSON (the engine's). */
export function signFingerprints(fps, key) {
  return call("baseline_sign", { fingerprints: fps.filter((f) => typeof f === "string"), key }).value;
}

/** The signature object a JSON report carries when a key is configured (else null). */
export function reportSignature(res, key) {
  if (!key) return null;
  return { alg: SIGNATURE_ALG, value: signFingerprints(Array.isArray(res.issues) ? fingerprints(res.issues) : [], key) };
}
/** Back-compatible helper: the signature value for a list of issues. */
export function baselineSignature(issues, key) {
  return signFingerprints(fingerprints(issues), key);
}

/** Does `path` resolve (symlinks followed) inside directory `root`? */
export function pathIsInside(path, root) {
  try {
    const p = realpathSync(path), r = realpathSync(root);
    return p === r || p.startsWith(r.endsWith(sep) ? r : r + sep);
  } catch {
    return false;
  }
}

/**
 * Apply a baseline to a scan result (mutates res): each issue gets `new`, res gets `newIssues` (and
 * `baselineUntrusted` when the baseline was not trusted); a signed one's accepted findings get `accepted`, res
 * `acceptedIssues` and the gate judged without them. `warn` receives the warning lines.
 */
export function applyBaseline(res, baselinePath, { root = null, warn = () => {}, env = process.env } = {}) {
  const issues = res.issues;
  const args = {
    path: String(baselinePath), ours: isOurReport(baselinePath, "json"),
    inside: !!root && pathIsInside(baselinePath, root), key: env[BASELINE_KEY_ENV] || null,
    fingerprints: fingerprints(issues), issues: findingRows(issues),
    conditions: (res.conditions || []).map((c) => [c.label, c.ok]),
  };
  let data = "";
  if (args.ours) {
    try {
      data = bytesText(readFileSync(baselinePath));
    } catch (e) {
      args.error = e.message;
    }
  }
  const got = call("baseline_apply", args, data);
  for (const line of got.warnings) warn(line);
  if (got.new) {
    got.new.forEach((isNew, k) => { issues[k].new = isNew; });
    res.newIssues = got.newIssues;
  }
  if (got.untrusted) res.baselineUntrusted = true;
  if (got.accepted) {
    got.accepted.forEach((yes, k) => { if (yes) issues[k].accepted = true; });
    res.acceptedIssues = got.acceptedIssues;
    got.conditions.forEach((now, k) => { res.conditions[k].ok = now.ok; });
    res.pass = got.pass;
  }
}
