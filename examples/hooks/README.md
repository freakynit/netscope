# NetScope hook examples

These scripts are intentionally small and use the version-1 JSON WebSocket protocol directly. They are not an SDK.

Start the proxy, then one active interceptor or any number of observers:

```sh
cargo run -- proxy --hook-listen 127.0.0.1:8765 --hook-timeout-ms 500
python3 -m pip install websockets
python3 examples/hooks/python/hook.py log
# or: npm install ws && node examples/hooks/node/hook.js log
```

Both `hook.py` and `hook.js` accept these example names:

| Name | Effect |
| --- | --- |
| `log` | Log every HTTP request and response boundary. |
| `request-header` | Add `x-netscope-example`. |
| `remove-response-header` | Remove the upstream `server` header. |
| `rewrite-request-json` | Add `rewritten_by` to a bounded JSON request body. |
| `rewrite-response-json` | Add `rewritten_by` to a bounded JSON response body. |
| `block` | Drop a request whose host or target matches `NETSCOPE_PATTERN`. |
| `respond` | Return JSON for a target containing `/synthetic`, without forwarding it. |
| `delay` | Delay matching `/delay` traffic by 500 ms. |
| `save` | Write JSON request/response bodies to `./bodies`. |
| `observe` | Receive header events without awaiting an action. |

For JSON rewrite/save modes, restart the proxy with its default body limit (1 MiB is already the default), then run the hook before generating traffic:

```sh
python3 examples/hooks/python/hook.py rewrite-request-json
curl -x http://127.0.0.1:8080 http://httpbin.org/anything \
  -H 'content-type: application/json' --data '{"hello":"world"}'
```

Use `NETSCOPE_PATTERN=example.com` for the `block` mode. For HTTPS examples, generate/install the local CA and add `--mitm`; see the root README. `curl` test traffic can be sent through the proxy with `-x http://127.0.0.1:8080`.

The active `intercept` role receives an event and must reply with an action. `observe` receives events over an independent, non-blocking queue and never replies. See [the protocol reference](../../docs/HOOK_PROTOCOL.md) for action schemas, timeouts, and failure semantics.
