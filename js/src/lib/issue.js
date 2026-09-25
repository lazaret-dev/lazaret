// Issue shape-builder — the one shared primitive every producer (scanner
// engine, SQL-sink analyzer, supply-chain manifest scanner) needs. Lives here
// so src/lib/supplychain.js can build issues without importing the scanner
// (RESTRUCTURE.md §5: src/lib/ imports nothing from src/scanner/); the
// scanner's engine.js re-exports it, so existing scanner-side imports keep
// working unchanged.

/**
 * Build a finding. `rule` is a table row or a hand-built row with
 * {id, name, type, sev, msg, why, fix, ref}; `file` is {name} or the name.
 * Snippet is ±2 lines around the finding line.
 */
export function mkIssue(rule, file, line, lines) {
  return {rule:rule.id, name:rule.name, type:rule.type, sev:rule.sev, msg:rule.msg,
    why:rule.why, fix:rule.fix, ref:rule.ref, file:file.name, line,
    snippet: lines.slice(Math.max(0,line-3), Math.min(lines.length, line+2)),
    snipStart: Math.max(0,line-3)+1};
}
