# NetScope core architecture

NetScope is a macOS-focused Rust CLI. Its first release has two independent ingestion paths: a passive libpcap reader and an explicit HTTP proxy. They share event types, storage, filters, and the interception contract, but neither depends on the other.

```
libpcap -> classify/BPF -> decode -> correlate -> immutable events -> hooks -> sinks
                                      |                              |       |
                                      +-> rotating pcapng             |       +-> NDJSON + broadcast
explicit proxy -> HTTP/TLS parser ---+                              decisions: continue/modify/drop/respond/delay
                         |
                         +-> streamed upstream
```

The passive path is observational: hook decisions do not alter packets captured by libpcap. System-wide allow/drop/replace behaviour requires a separate macOS Network Extension backend (for example, a content filter or packet tunnel), not this capture backend.

## Modules

- `capture`: capture-time BPF filtering; Ethernet IPv4/IPv6 TCP/UDP/ICMP decoding; canonical, bidirectional connection IDs; directional flow state; bounded in-order TCP reassembly; distinct TCP anomaly markers; DNS request/response latency and answer parsing; plus passive TLS ClientHello and eligible TLS 1.0-1.2 leaf-certificate metadata. Packet records retain wire/captured/payload lengths, IP hop/fragment fields, transport metadata, and an optional raw pcapng reference. The live adapter uses libpcap only.
- `proxy`: explicit HTTP/1.1 proxy. It streams fixed-length and chunked bodies between client and upstream, handles persistent connections, raw CONNECT tunnels, and optional TLS MITM. Fixed-length, uncompressed JSON is buffered only when a hook registers `body_mode: "json"`.
- `parsers`: bounded, dependency-light parsers for HTTP/1 headers, DNS questions/answers, TLS ClientHello metadata, and X.509 leaf metadata.
- `hooks`: a stable, language-neutral interception boundary and local WebSocket v1 transport. One active interceptor can return `continue`, `modify`, `drop`, `respond`, or `delay`; observers receive best-effort events without waiting for an action. The proxy fails open after a deadline or client failure. See [the protocol](HOOK_PROTOCOL.md).
- `store`: append-only NDJSON and an in-process broadcast stream. The broadcast queue is bounded (2,048 events); slow subscribers receive lag notifications rather than delaying producers. pcapng writing happens before decode in the capture loop, so raw frames remain the source of truth even when a later decoder declines a packet.
- `certs`: local CA lifecycle and per-host leaf creation for MITM. The proxy parses the upstream leaf certificate into subject, issuer, serial, and expiry event metadata after a successful TLS handshake.

Events use JSON-compatible tagged enums and string endpoint fields deliberately: non-Swift/non-Rust rule runtimes can consume the schema directly. The initial WebSocket transport serializes active decisions to keep ordering predictable.

## Capture event and correlation contract

`connection_id` sorts the two endpoint keys, so `client:port -> server:port` and the reverse packet use the same ID. TCP SYN establishes the client role; DNS port direction and well-known-port heuristics cover flows whose opening packet was missed. TCP observations are tracked per endpoint direction and exposed independently: `attributes.duplicate_ack` is a repeated pure ACK with the same acknowledgement number and advertised window; `attributes.retransmitted_segment` is a repeated observed sequence-space segment (payload or SYN/FIN); `attributes.out_of_order` is a new sequence-space segment beginning before the highest sequence end already observed in that direction; and `attributes.zero_window_probe` is a one-byte segment at the peer's zero-window probe sequence. These are bounded passive-capture signals, not proof of host behaviour or on-wire loss.

Each `packet` event has `wire_length`, `captured_length`, and `payload_length` (`length` is the legacy alias for payload length). It also exposes IP version/TTL-or-hop-limit/fragmentation, TCP flags/sequence/ACK/window/options, UDP length, and ICMP type/code where those headers exist. If raw output is enabled, `raw_packet` contains a packet ID, pcapng filename, and byte offset of the Enhanced Packet Block. Files rotate before exceeding `--pcapng-rotate-mb` (default 128 MiB).

DNS state is bounded to 4,096 outstanding queries and keys transactions by DNS ID plus client/server endpoints. TCP stream state is bounded to a 128 KiB in-order prefix per direction. This release correlates DNS and proxy HTTP/1 transactions, extracts passive TLS ClientHello metadata, and extracts a leaf certificate from an unencrypted TLS 1.0-1.2 Certificate handshake. It deliberately does not claim passive HTTP, QUIC, or TLS 1.3 encrypted-certificate transaction decoding.

## Security boundary

The proxy is explicit and bound to loopback by default. It does not install system-wide routing, a Network Extension, or firewall rules. CA installation is an explicit macOS `security` command and requires administrator authorization. Private key material stays in the selected CA directory; it must not be committed or shared.
