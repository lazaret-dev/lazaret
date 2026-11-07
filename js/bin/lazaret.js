#!/usr/bin/env node

const args = process.argv.slice(2);
if (args[0] === "mcp") {
  const { main } = await import("../src/mcp.js");
  process.exitCode = await main(args.slice(1));
} else {
  const { run } = await import("../src/index.js");
  const code = run(args);
  if (code && typeof code.then === "function") code.then((c) => { process.exitCode = c; }); // (--verify-secrets)
  else process.exitCode = code;
}
