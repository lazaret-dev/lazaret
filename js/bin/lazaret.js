#!/usr/bin/env node
import { run } from "../src/index.js";

const code = run(process.argv.slice(2));
if (code && typeof code.then === "function") code.then((c) => { process.exitCode = c; });   // (--verify-secrets)
else process.exitCode = code;
