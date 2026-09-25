import { readFileSync } from "node:fs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

// CLI logic lives here and returns an exit code, so tests can call it directly;
// bin/lazaret.js is only the executable shim.

export const version = pkg.version;
export const TAGLINE = "lazaret: quarantine for your dependencies";

/**
 * Run the CLI. Returns an exit code instead of calling process.exit so it's testable.
 * @param {string[]} argv arguments after the program name
 * @param {{ out?: (s: string) => void, err?: (s: string) => void }} io
 */
export function run(argv, { out = console.log, err = console.error } = {}) {
  const [command, ...rest] = argv;

  if (command === "--version" || command === "-v") {
    out(`lazaret ${version}`);
    return 0;
  }
  if (command === "--help" || command === "-h") {
    out(`${TAGLINE}\n\nUsage:\n  lazaret --version\n  lazaret check [path]   (not yet implemented)`);
    return 0;
  }
  if (command === "check") {
    err(`lazaret ${version}: 'check' is not implemented yet (path: ${rest[0] ?? "."})`);
    return 2;
  }
  if (command !== undefined) {
    err(`lazaret: unknown command '${command}'. Run 'lazaret --help'.`);
    return 1;
  }

  out(`${TAGLINE} (v${version}, pre-release)`);
  out("Run 'lazaret --help' for commands.");
  return 0;
}
