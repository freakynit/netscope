# Local hook protocol (v1)

NetScope exposes an optional, loopback-only WebSocket endpoint for local tools. It is deliberately JSON-only and language-neutral: a process can use any WebSocket client and does not need Swift, Rust, a plugin, or a rebuild of NetScope.

Start it with `netscope proxy --hook-listen 127.0.0.1:8765`. The endpoint has no authentication because it is intended for loopback use only; do not bind it to a LAN address.

## Registration

The first client message selects a role. `intercept` is the one active, request/response-gating hook; a newer interceptor replaces the earlier one. `observe` clients receive a best-effort non-blocking event stream and never send actions.

```json
{"type":"register","protocol_version":1,"role":"intercept","body_mode":"json"}
```

`body_mode` is `none` (the default) or `json`. With `json`, NetScope emits `request_body` and `response_body` messages for fixed-length, uncompressed JSON messages no larger than `--hook-max-json-body-bytes` (default 1 MiB). This is the intentional buffering boundary; chunked, compressed, oversized, and non-JSON bodies continue streaming without body events.

The server acknowledges successful registration:

```json
{"type":"registered","protocol_version":1,"role":"intercept","body_mode":"json"}
```

## Events

Every event is JSON and retains the core `TrafficEvent` shape. Events are immutable snapshots: an action is a decision/request for the proxy to apply, not a mutation of the event itself. `body_base64` is absent for header events and base64-encoded for JSON body events.

```json
{
  "type":"event",
  "protocol_version":1,
  "request_id":"hook-42",
  "phase":"request_headers",
  "event":{
    "id":"...","timestamp_ms":0,"connection_id":"...",
    "direction":"client_to_server",
    "source":{"host":"127.0.0.1","port":50123},
    "destination":{"host":"example.test","port":80},
    "kind":{"type":"http_request","method":"GET","target":"/","version":"HTTP/1.1","headers":{"host":"example.test"}},
    "attributes":{}
  }
}
```

Valid phases are `request_headers`, `request_body`, `response_headers`, and `response_body`. Body-phase events use `kind.type: "http_body"` and include the byte length/content type; the bytes are in `body_base64`.

## Actions

An `intercept` client responds with the same `request_id`. Unknown, malformed, stale, or invalid actions fail open as `continue`.

```json
{"type":"action","request_id":"hook-42","action":"continue"}
{"type":"action","request_id":"hook-42","action":"modify","set_headers":{"x-example":"yes"},"remove_headers":["server"]}
{"type":"action","request_id":"hook-42","action":"modify","body_base64":"eyJyZXdyaXR0ZW4iOnRydWV9"}
{"type":"action","request_id":"hook-42","action":"drop","reason":"policy"}
{"type":"action","request_id":"hook-42","action":"respond","status":403,"headers":{"content-type":"text/plain"},"body_base64":"ZGVuaWVk"}
{"type":"action","request_id":"hook-42","action":"delay","milliseconds":500}
```

`modify` may change headers and, on a buffered JSON body event, replace the decoded body. NetScope recalculates `content-length` and removes `transfer-encoding` for a replaced body. `drop` closes the current proxied connection after consuming the available message boundary. `respond` returns a synthetic HTTP response without forwarding the request (or replaces an already received response). `delay` pauses forwarding for the requested duration.

## Timeouts and failures

The default active-hook deadline is 250 ms, configurable with `--hook-timeout-ms`. On timeout, malformed response, disconnect, or hook-process crash, NetScope logs a warning, removes the interceptor, and continues traffic without modification. A fresh hook can register immediately. Observer queues are bounded and best effort: a stalled/disconnected observer is removed rather than slowing the proxy.

The current transport serializes active decisions, intentionally favouring predictable ordering over throughput. It is a local development API, not a remote multi-tenant control plane.

Passive capture uses the same event schema but is observational. It can emit to observers and sinks, while `allow`, `drop`, `replace`, and `delay` require an enforcement-capable backend; the current active actions apply only to the explicit proxy.
