#!/usr/bin/env python3
"""Small NetScope WebSocket hook examples: python hook.py <example> [ws://host:port]."""
import asyncio
import base64
import json
import os
import sys
from pathlib import Path

import websockets

EXAMPLES = {
    "log", "request-header", "remove-response-header", "rewrite-request-json",
    "rewrite-response-json", "block", "respond", "delay", "save", "observe",
}


def action(message, example):
    event = message["event"]
    kind = event["kind"]
    phase = message["phase"]
    headers = kind.get("headers", {})
    host = headers.get("host", event["destination"]["host"])
    target = kind.get("target", "")
    pattern = os.getenv("NETSCOPE_PATTERN", "blocked.example")

    if example == "log":
        print(phase, kind["type"], event["source"], "->", event["destination"], flush=True)
    elif example == "request-header" and phase == "request_headers":
        return {"action": "modify", "set_headers": {"x-netscope-example": "python"}}
    elif example == "remove-response-header" and phase == "response_headers":
        return {"action": "modify", "remove_headers": ["server"]}
    elif example in {"rewrite-request-json", "rewrite-response-json"} and phase == (
        "request_body" if example.startswith("rewrite-request") else "response_body"
    ):
        body = json.loads(base64.b64decode(message["body_base64"]))
        body["rewritten_by"] = "netscope-python"
        return {"action": "modify", "body_base64": base64.b64encode(json.dumps(body).encode()).decode()}
    elif example == "block" and phase == "request_headers" and (pattern in host or pattern in target):
        return {"action": "drop", "reason": "matched NETSCOPE_PATTERN"}
    elif example == "respond" and phase == "request_headers" and "/synthetic" in target:
        body = b'{"source":"netscope-python","synthetic":true}'
        return {"action": "respond", "status": 200, "headers": {"content-type": "application/json"},
                "body_base64": base64.b64encode(body).decode()}
    elif example == "delay" and ("/delay" in target or phase.endswith("_body")):
        return {"action": "delay", "milliseconds": 500}
    elif example == "save" and phase.endswith("_body"):
        directory = Path("bodies")
        directory.mkdir(exist_ok=True)
        path = directory / f'{message["request_id"]}-{phase}.bin'
        path.write_bytes(base64.b64decode(message["body_base64"]))
        print(f"saved {path}", flush=True)
    return {"action": "continue"}


async def main():
    example = sys.argv[1] if len(sys.argv) > 1 else "log"
    if example not in EXAMPLES:
        raise SystemExit(f"choose one of: {', '.join(sorted(EXAMPLES))}")
    url = sys.argv[2] if len(sys.argv) > 2 else "ws://127.0.0.1:8765"
    role = "observe" if example == "observe" else "intercept"
    body_mode = "json" if example.startswith("rewrite-") or example == "save" else "none"
    # NetScope v1 only reads an active hook socket while awaiting an action. Disable client-side
    # keepalive pings so an idle example stays connected between traffic events.
    async with websockets.connect(url, ping_interval=None) as socket:
        await socket.send(json.dumps({"type": "register", "protocol_version": 1,
                                      "role": role, "body_mode": body_mode}))
        print(await socket.recv())
        async for raw in socket:
            message = None
            try:
                message = json.loads(raw)
                if message.get("type") != "event":
                    continue
                result = action(message, example)
                if role == "intercept":
                    result.update({"type": "action", "request_id": message["request_id"]})
                    await socket.send(json.dumps(result))
            except Exception as error:
                print(f"hook error: {error}", file=sys.stderr, flush=True)
                if role == "intercept" and message is not None:
                    await socket.send(json.dumps({"type": "action", "request_id": message["request_id"], "action": "continue"}))


if __name__ == "__main__":
    asyncio.run(main())
