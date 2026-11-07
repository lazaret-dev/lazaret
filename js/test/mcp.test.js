import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";

import {
  MAX_FRAME_DEPTH, McpServer, TOOLS, frameDepthExceeds, scanSnippet, serveStream,
} from "../src/mcp.js";

const request = (id, method, params = {}) => JSON.stringify({ jsonrpc: "2.0", id, method, params });

function memoryServer() {
  const frames = [];
  const server = new McpServer({ write: (frame) => frames.push(frame) });
  return { server, frames };
}

test("the internal milestone advertises only the tool whose parity is complete", () => {
  assert.deepEqual(TOOLS.map((tool) => tool.name), ["scan_snippet"]);
});

test("initialize negotiates the Python server's protocol versions; ping stays responsive", () => {
  const { server, frames } = memoryServer();
  server.handleLine(request(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {} }));
  server.handleLine(request(2, "ping"));
  assert.equal(frames[0].result.protocolVersion, "2025-06-18");
  assert.deepEqual(frames[0].result.capabilities, { tools: {} });
  assert.equal(frames[0].result.serverInfo.name, "lazaret");
  assert.deepEqual(frames[1], { jsonrpc: "2.0", id: 2, result: {} });
});

test("tools/list and scan_snippet return the MCP content envelope", async () => {
  const { server, frames } = memoryServer();
  server.handleLine(request(1, "tools/list"));
  const args = { language: "js", code: "const user = req.query.q; eval(user);\n" };
  const expected = scanSnippet(args);
  server.handleLine(request(2, "tools/call", { name: "scan_snippet", arguments: args }));
  await server.drain();
  assert.deepEqual(frames[0].result.tools, TOOLS);
  assert.deepEqual(JSON.parse(frames[1].result.content[0].text), expected);
  assert.equal(frames[1].result.content[0].type, "text");
  assert.ok(expected.issueCount > 0);
});

test("invalid tool arguments are tool errors, while unknown methods are JSON-RPC errors", async () => {
  const { server, frames } = memoryServer();
  server.handleLine(request("bad", "tools/call", {
    name: "scan_snippet", arguments: { language: "rust", code: "fn main() {}" },
  }));
  server.handleLine(request("missing", "not/a/method"));
  await server.drain();
  const tool = frames.find((frame) => frame.id === "bad");
  assert.equal(tool.result.isError, true);
  assert.match(tool.result.content[0].text, /language 'py' or 'js'/);
  const method = frames.find((frame) => frame.id === "missing");
  assert.equal(method.error.code, -32601);
});

test("a cancelled queued call has no response and does not remain pending", async () => {
  const { server, frames } = memoryServer();
  server.handleLine(request(7, "tools/call", {
    name: "scan_snippet", arguments: { language: "py", code: "print('ok')\n" },
  }));
  server.handleLine(JSON.stringify({
    jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 7 },
  }));
  await server.drain();
  assert.deepEqual(frames, []);
  assert.equal(server.pending.size, 0);
});

test("notifications are never answered; malformed frames do not stop the next request", () => {
  const { server, frames } = memoryServer();
  server.handleLine(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }));
  server.handleLine("{");
  server.handleLine(request(3, "ping"));
  assert.equal(frames.length, 2);
  assert.equal(frames[0].error.code, -32700);
  assert.deepEqual(frames[1], { jsonrpc: "2.0", id: 3, result: {} });
});

test("deep frames are rejected before JSON.parse", () => {
  const text = "[".repeat(MAX_FRAME_DEPTH + 1) + "]".repeat(MAX_FRAME_DEPTH + 1);
  assert.equal(frameDepthExceeds(text), true);
  const { server, frames } = memoryServer();
  server.handleLine(text);
  assert.equal(frames[0].error.code, -32700);
  assert.match(frames[0].error.message, /maximum nesting depth/);
});

test("the stream reader bounds an unterminated frame and serves the next one", async () => {
  const input = new PassThrough(), output = new PassThrough();
  let shown = "";
  output.on("data", (part) => { shown += part.toString("utf8"); });
  const { done } = serveStream(input, output, { maxFrameBytes: 128 });
  input.write("x".repeat(160));
  input.write("\n" + request(9, "ping") + "\n");
  input.end();
  await done;
  const frames = shown.trim().split("\n").map(JSON.parse);
  assert.equal(frames[0].error.code, -32600);
  assert.deepEqual(frames[1], { jsonrpc: "2.0", id: 9, result: {} });
});

test("an unterminated final line is still a frame", async () => {
  const input = new PassThrough(), output = new PassThrough();
  let shown = "";
  output.on("data", (part) => { shown += part.toString("utf8"); });
  const { done } = serveStream(input, output);
  input.end(request(10, "ping"));
  await done;
  assert.deepEqual(JSON.parse(shown), { jsonrpc: "2.0", id: 10, result: {} });
});

test("many tiny input chunks do not change framing", async () => {
  const input = new PassThrough(), output = new PassThrough();
  let shown = "";
  output.on("data", (part) => { shown += part.toString("utf8"); });
  const { done } = serveStream(input, output);
  for (const byte of Buffer.from(request(11, "ping") + "\n")) input.write(Buffer.of(byte));
  input.end();
  await done;
  assert.deepEqual(JSON.parse(shown), { jsonrpc: "2.0", id: 11, result: {} });
});

test("the shipped lazaret binary dispatches the mcp subcommand", () => {
  const cli = fileURLToPath(new URL("../bin/lazaret.js", import.meta.url));
  const version = spawnSync(process.execPath, [cli, "mcp", "--version"], { encoding: "utf8" });
  assert.equal(version.status, 0);
  assert.match(version.stdout, /^lazaret-mcp \d+\.\d+\.\d+\n$/);
  assert.equal(version.stderr, "");

  const ping = spawnSync(process.execPath, [cli, "mcp"], {
    encoding: "utf8", input: request(12, "ping") + "\n",
  });
  assert.equal(ping.status, 0);
  assert.deepEqual(JSON.parse(ping.stdout), { jsonrpc: "2.0", id: 12, result: {} });
  assert.equal(ping.stderr, "");
});
