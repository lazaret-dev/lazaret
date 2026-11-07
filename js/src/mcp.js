// Lazaret's npm MCP server.
//
// This is the first internal milestone of issue #83. Only tools whose npm
// implementation already satisfies the Python server's contract are listed.
// Do not describe this as full MCP parity until the path tools, registry
// tools, roots, limits and cancellation tests in #83 are complete.

import { readFileSync } from "node:fs";
import { scanFile } from "./scanner/scan.js";
import { SEV_ORDER } from "./scanner/rules.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2024-11-05"];
export const PROTOCOL_VERSION = "2024-11-05";
export const MAX_FRAME_BYTES = 16 * 1024 * 1024;
export const MAX_FRAME_DEPTH = 512;

const SCAN_SNIPPET = {
  name: "scan_snippet",
  description: "Scan a code snippet (string) for security and quality issues before writing it to disk. language: 'py' or 'js'.",
  inputSchema: {
    type: "object",
    properties: {
      code: { type: "string", description: "Source code to scan" },
      language: { type: "string", enum: ["py", "js"] },
    },
    required: ["code", "language"],
  },
};

// The full catalog is deliberately not advertised yet. A smaller internal
// milestone is acceptable; a smaller released/public parity claim is not.
export const TOOLS = [SCAN_SNIPPET];

function slim(issue) {
  return Object.fromEntries(["rule", "type", "sev", "msg", "fix", "file", "line"].map((key) => [key, issue[key]]));
}

export function scanSnippet(args) {
  const lang = args?.language;
  const code = args?.code;
  if ((lang !== "py" && lang !== "js") || typeof code !== "string")
    throw new Error("scan_snippet needs code (string) and language 'py' or 'js'");
  const name = lang === "py" ? "snippet.py" : "snippet.js";
  const issues = scanFile({ path: name, content: code, lang });
  issues.sort((a, b) => (SEV_ORDER[a.sev] - SEV_ORDER[b.sev]) || (a.line - b.line));
  return { issueCount: issues.length, issues: issues.map(slim) };
}

const HANDLERS = new Map([["scan_snippet", scanSnippet]]);

export function negotiateProtocol(requested) {
  if (typeof requested === "string" && SUPPORTED_PROTOCOL_VERSIONS.includes(requested)) return requested;
  if (requested === undefined || requested === null) return PROTOCOL_VERSION;
  return SUPPORTED_PROTOCOL_VERSIONS[0];
}

/** A bounded, linear JSON nesting check; brackets inside strings do not count. */
export function frameDepthExceeds(text, limit = MAX_FRAME_DEPTH) {
  let possible = 0;
  for (const ch of text) if (ch === "[" || ch === "{") possible++;
  if (possible <= limit) return false;
  let depth = 0, quoted = false, escaped = false;
  for (const ch of text) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') quoted = false;
      continue;
    }
    if (ch === '"') quoted = true;
    else if (ch === "[" || ch === "{") {
      if (++depth > limit) return true;
    } else if (ch === "]" || ch === "}") depth--;
  }
  return false;
}

function parseFrame(line) {
  if (frameDepthExceeds(line)) return [null, {
    code: -32700,
    message: `Parse error: request JSON exceeds the maximum nesting depth of ${MAX_FRAME_DEPTH} (treated as hostile input, not a crash; re-send the request with bounded depth)`,
  }];
  try { return [JSON.parse(line), null]; }
  catch { return [null, { code: -32700, message: "Parse error: the frame is not valid JSON" }]; }
}

function requestShape(req) {
  if (req === null || Array.isArray(req) || typeof req !== "object") return [null, null, null, {
    code: -32600,
    message: `Invalid Request: frame must be a JSON object (got ${req === null ? "null" : Array.isArray(req) ? "list" : typeof req})`,
  }, false];
  const hasId = Object.hasOwn(req, "id"), id = req.id;
  if (hasId && !((typeof id === "string") || (typeof id === "number" && Number.isInteger(id)))) return [null, null, null, {
    code: -32600, message: "Invalid Request: id must be a string or an integer",
  }, false];
  if (req.jsonrpc !== "2.0" || typeof req.method !== "string") return [null, id, null, {
    code: -32600, message: "Invalid Request: needs jsonrpc==\"2.0\" and a string method",
  }, false];
  let params = req.params;
  if (params === undefined || params === null) params = {};
  else if (Array.isArray(params) || typeof params !== "object") return [null, id, null, {
    code: -32602, message: `Invalid params: 'params' must be an object (got ${Array.isArray(params) ? "list" : typeof params})`,
  }, false];
  return [req.method, id, params, null, !hasId];
}

const idKey = (id) => JSON.stringify(id);

export class McpServer {
  constructor({ write }) {
    if (typeof write !== "function") throw new TypeError("McpServer needs a frame writer");
    this.write = write;
    this.pending = new Map();
    this.queue = Promise.resolve();
  }

  reply(id, result = undefined, error = undefined) {
    const frame = { jsonrpc: "2.0", id };
    if (error !== undefined) frame.error = error;
    else frame.result = result;
    this.write(frame);
  }

  handleLine(raw) {
    const line = String(raw).trim();
    if (!line) return;
    if (Buffer.byteLength(line) > MAX_FRAME_BYTES) {
      this.reply(null, undefined, { code: -32600, message: `Invalid Request: frame exceeds ${MAX_FRAME_BYTES} byte limit` });
      return;
    }
    const [req, parseError] = parseFrame(line);
    if (parseError) { this.reply(null, undefined, parseError); return; }
    // Responses to requests this server will make (roots/list in the next
    // milestone) are never themselves answered.
    if (req && typeof req === "object" && !Array.isArray(req) && !("method" in req)
        && ("result" in req || "error" in req)) return;
    const [method, id, params, error, notification] = requestShape(req);
    if (error) { this.reply(id ?? null, undefined, error); return; }
    if (notification) { this.notification(method, params); return; }
    this.request(method, id, params);
  }

  notification(method, params) {
    if (method !== "notifications/cancelled") return;
    const id = params.requestId;
    if ((typeof id === "string") || (typeof id === "number" && Number.isInteger(id))) {
      const token = this.pending.get(idKey(id));
      if (token) token.cancelled = true;
    }
  }

  request(method, id, params) {
    if (method === "initialize") {
      this.reply(id, {
        protocolVersion: negotiateProtocol(params.protocolVersion),
        capabilities: { tools: {} },
        serverInfo: { name: "lazaret", version: pkg.version },
      });
      return;
    }
    if (method === "ping") { this.reply(id, {}); return; }
    if (method === "tools/list") { this.reply(id, { tools: TOOLS }); return; }
    if (method !== "tools/call") {
      this.reply(id, undefined, { code: -32601, message: `Method not found: ${method}` });
      return;
    }
    const name = params.name, handler = typeof name === "string" ? HANDLERS.get(name) : null;
    if (!handler) {
      this.reply(id, undefined, { code: -32602, message: `Unknown tool: ${name}` });
      return;
    }
    let args = params.arguments;
    if (args === undefined || args === null) args = {};
    else if (Array.isArray(args) || typeof args !== "object") {
      this.reply(id, undefined, {
        code: -32602,
        message: `Invalid params: 'arguments' must be an object (got ${Array.isArray(args) ? "list" : typeof args})`,
      });
      return;
    }
    const token = { cancelled: false }, key = idKey(id);
    this.pending.set(key, token);
    this.queue = this.queue.then(async () => {
      try {
        if (token.cancelled) return;
        const value = await handler(args, token);
        if (!token.cancelled) this.reply(id, { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] });
      } catch (e) {
        if (!token.cancelled) this.reply(id, {
          content: [{ type: "text", text: `Error: ${e?.message ?? e}` }], isError: true,
        });
      } finally {
        if (this.pending.get(key) === token) this.pending.delete(key);
      }
    }).catch((e) => {
      if (!token.cancelled) this.reply(id, undefined, {
        code: -32603, message: `Internal error: ${e?.name ?? "Error"}: ${e?.message ?? e}`,
      });
      if (this.pending.get(key) === token) this.pending.delete(key);
    });
  }

  async drain() { await this.queue; }
}

/**
 * Read newline-delimited MCP frames without allowing an unterminated line to
 * grow without bound. Oversize input is discarded through its next newline;
 * the following frame is still served.
 */
export function serveStream(input, output, { maxFrameBytes = MAX_FRAME_BYTES } = {}) {
  const write = (frame) => output.write(`${JSON.stringify(frame)}\n`);
  const server = new McpServer({ write });
  let kept = Buffer.alloc(0), keptBytes = 0, discarding = false;
  const clear = () => { keptBytes = 0; };
  const append = (part) => {
    const needed = keptBytes + part.length;
    if (needed > maxFrameBytes) return false;
    if (needed > kept.length) {
      const capacity = Math.min(maxFrameBytes, Math.max(4096, needed, kept.length * 2));
      const grown = Buffer.allocUnsafe(capacity);
      if (keptBytes) kept.copy(grown, 0, 0, keptBytes);
      kept = grown;
    }
    part.copy(kept, keptBytes);
    keptBytes = needed;
    return true;
  };
  const oversized = () => server.reply(null, undefined, {
    code: -32600, message: `Invalid Request: frame exceeds ${maxFrameBytes} byte limit`,
  });
  const done = new Promise((resolve, reject) => {
    input.on("error", reject);
    output.on?.("error", reject);
    input.on("data", (part) => {
      let chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
      while (chunk.length) {
        const end = chunk.indexOf(0x0a);
        if (discarding) {
          if (end < 0) return;
          discarding = false;
          chunk = chunk.subarray(end + 1);
          continue;
        }
        if (end < 0) {
          if (!append(chunk)) {
            clear();
            discarding = true;
            oversized();
          }
          return;
        }
        const piece = chunk.subarray(0, end);
        if (!append(piece)) oversized();
        else server.handleLine(kept.subarray(0, keptBytes).toString("utf8").replace(/\r$/, ""));
        clear();
        chunk = chunk.subarray(end + 1);
      }
    });
    input.on("end", () => {
      if (!discarding && keptBytes) {
        server.handleLine(kept.subarray(0, keptBytes).toString("utf8").replace(/\r$/, ""));
      }
      clear();
      server.drain().then(resolve, reject);
    });
  });
  return { server, done };
}

export async function main(argv = process.argv.slice(2), io = {}) {
  const input = io.input ?? process.stdin, output = io.output ?? process.stdout, error = io.error ?? process.stderr;
  if (argv.length === 1 && argv[0] === "--version") {
    output.write(`lazaret-mcp ${pkg.version}\n`);
    return 0;
  }
  if (argv.length) {
    error.write("error: lazaret mcp takes no arguments (except --version)\n");
    return 2;
  }
  const { done } = serveStream(input, output);
  await done;
  return 0;
}
