#!/usr/bin/env node
// Small NetScope WebSocket hook examples: node hook.js <example> [ws://host:port]
const WebSocket = require("ws");
const fs = require("fs");

const examples = new Set(["log", "request-header", "remove-response-header", "rewrite-request-json",
  "rewrite-response-json", "block", "respond", "delay", "save", "observe"]);
const example = process.argv[2] || "log";
const url = process.argv[3] || "ws://127.0.0.1:8765";
if (!examples.has(example)) throw new Error(`choose one of: ${[...examples].join(", ")}`);
const role = example === "observe" ? "observe" : "intercept";
const bodyMode = example.startsWith("rewrite-") || example === "save" ? "json" : "none";

function decide(message) {
  const { event, phase } = message;
  const kind = event.kind;
  const headers = kind.headers || {};
  const host = headers.host || event.destination.host;
  const target = kind.target || "";
  const pattern = process.env.NETSCOPE_PATTERN || "blocked.example";
  if (example === "log") console.log(phase, kind.type, event.source, "->", event.destination);
  if (example === "request-header" && phase === "request_headers")
    return { action: "modify", set_headers: { "x-netscope-example": "node" } };
  if (example === "remove-response-header" && phase === "response_headers")
    return { action: "modify", remove_headers: ["server"] };
  if ((example === "rewrite-request-json" && phase === "request_body") ||
      (example === "rewrite-response-json" && phase === "response_body")) {
    const body = JSON.parse(Buffer.from(message.body_base64, "base64"));
    body.rewritten_by = "netscope-node";
    return { action: "modify", body_base64: Buffer.from(JSON.stringify(body)).toString("base64") };
  }
  if (example === "block" && phase === "request_headers" && (host.includes(pattern) || target.includes(pattern)))
    return { action: "drop", reason: "matched NETSCOPE_PATTERN" };
  if (example === "respond" && phase === "request_headers" && target.includes("/synthetic"))
    return { action: "respond", status: 200, headers: { "content-type": "application/json" },
      body_base64: Buffer.from('{"source":"netscope-node","synthetic":true}').toString("base64") };
  if (example === "delay" && (target.includes("/delay") || phase.endsWith("_body")))
    return { action: "delay", milliseconds: 500 };
  if (example === "save" && phase.endsWith("_body")) {
    fs.mkdirSync("bodies", { recursive: true });
    const path = `bodies/${message.request_id}-${phase}.bin`;
    fs.writeFileSync(path, Buffer.from(message.body_base64, "base64"));
    console.log(`saved ${path}`);
  }
  return { action: "continue" };
}

const socket = new WebSocket(url);
socket.on("open", () => socket.send(JSON.stringify({ type: "register", protocol_version: 1, role, body_mode: bodyMode })));
socket.on("message", raw => {
  try {
    const message = JSON.parse(raw);
    if (message.type === "registered") return console.log(message);
    if (message.type !== "event") return;
    const result = decide(message);
    if (role === "intercept") socket.send(JSON.stringify({ type: "action", request_id: message.request_id, ...result }));
  } catch (error) {
    console.error("hook error:", error.message);
  }
});
socket.on("error", error => console.error("socket error:", error.message));
