// A download piped into a shell (`curl … | sh`, `wget -qO- … | bash`), or
// substituted into a shell's or an interpreter's command line (`sh -c
// "$(curl …)"`, `source <(curl …)`) — twin of lazaret.scanner.core's
// _PIPE_SCAN_RE / _pipes_download_to_shell, _DL_SUBST_RE /
// runs_substituted_download, _EXEC_CALL_RE and _runs_download_through_shell.
// A leaf module: lib/hooks.js (the install-script and import-time tests) and
// scanner/scan.js (SC-PIPE-SHELL) use it, and the dashboard carries a copy.

import { pyRe } from "./pycompat.js";

// `curl … | sh` / `wget … | bash`, read in one left-to-right pass (core's comment)
export const PIPE_SCAN_SRC = String.raw`\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|[\n|;&]|\b(?:curl|wget)\b`;
const PIPE_SCAN_RE = pyRe(PIPE_SCAN_SRC, "g");

/** twin of core._pipes_download_to_shell: a pipe into a shell after curl or wget in the same command */
export function pipesDownloadToShell(text) {
  let download = false;
  for (const m of text.matchAll(PIPE_SCAN_RE)) {
    const token = m[0];
    if (token[0] === "|" && token.length > 1) {                        // | sh, | sudo bash
      if (download) return true;
      download = false;
    } else if (token === "\n" || token === "|" || token === ";" || token === "&") {
      download = false;
    } else {                                                           // curl / wget
      download = true;
    }
  }
  return false;
}

// A download handed to a shell or an interpreter without a pipe, through a
// command or process substitution; one row at a time (core's comment)
export const DL_SUBST_SRC =
  String.raw`\b(?:(?:ba|z|da|k)?sh|node(?:js)?|bun|python[\d.]*|perl|ruby|php|pwsh|powershell)(?:\.exe)?` +
  String.raw`(?:[ \t]+-[\w-]+){0,6}?[ \t]+-(?:c|e|E|p|r|-eval|-print|Command|command)[ \t]+(?:["'][ \t]*)?` +
  String.raw`(?:\$\(|${"`"})[ \t]*(?:curl|wget)\b` +
  String.raw`|\beval[ \t]+(?:["'][ \t]*)?(?:\$\(|${"`"})[ \t]*(?:curl|wget)\b` +
  String.raw`|(?:\b(?:(?:ba|z|da|k)?sh|source|node(?:js)?|python[\d.]*)|(?:^|[ \t;&|(])\.)[ \t]+<\([ \t]*(?:curl|wget)\b`;
const DL_SUBST_RE = pyRe(DL_SUBST_SRC);
export const DL_SUBST_NEEDLE_SRC = String.raw`(?:\$\(|${"`"}|<\()[ \t]*(?:curl|wget)`;
const DL_SUBST_NEEDLE_RE = pyRe(DL_SUBST_NEEDLE_SRC);

/** Does this row hand a download to a shell or an interpreter through a command or process
 * substitution? Twin of core.runs_substituted_download. */
export function runsSubstitutedDownload(row) {
  return (row.includes("curl") || row.includes("wget")) && DL_SUBST_NEEDLE_RE.test(row) && DL_SUBST_RE.test(row);
}

export const EXEC_CALL_SRC =
  String.raw`\b(?:execSync|exec|execFileSync|execFile|spawnSync|spawn|system|popen|Popen|run|call|` +
  String.raw`check_call|check_output|getoutput|getstatusoutput)\s*\(`;
export const EXEC_CALL_RE = pyRe(EXEC_CALL_SRC);

/**
 * Does this line hand a download piped into a shell, or substituted into a
 * shell's or an interpreter's command line, to an exec call? A CLI's help
 * text showing `curl … | sh` does not. Twin of core._runs_download_through_shell.
 */
export function runsDownloadThroughShell(row) {
  return (row.includes("curl") || row.includes("wget")) && EXEC_CALL_RE.test(row)
    && (pipesDownloadToShell(row) || runsSubstitutedDownload(row));
}
