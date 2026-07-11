# Phased implementation plan

1. **Core (implemented):** Rust CLI, loopback HTTP/1 proxy, CONNECT tunnel/MITM mode, local CA commands, streaming fixed-length/chunked bodies, multi-interface passive capture with BPF prefiltering, bounded in-order TCP reassembly, DNS/HTTP/TLS/X.509 metadata parsers, NDJSON events, and a local WebSocket v1 hook API with observer and interceptor roles.
2. **Capture hardening:** add out-of-order/retransmission-aware TCP reassembly, VLAN/IPv6 extension support, DNS-over-TCP, hostname-to-flow correlation, connection timeouts, and validated process attribution via macOS APIs.
3. **Interception API hardening:** add Unix-socket and local HTTP/RPC transports, endpoint authentication/authorization, per-hook permissions, concurrent ordered decision lanes, chunk-window protocols, rule persistence, and a formal compatibility test suite for the v1 schema.
4. **Protocol expansion:** HTTP/1 trailer and close-delimited response semantics, gzip/br/zstd transform pipeline with bounded buffering, WebSocket frame metadata/rules, certificate chain metadata, and HTTP/2 proxy support.
5. **macOS integration:** optional Swift helper only where needed for Network Extension lifecycle, per-process attribution, and approved transparent routing. Keep it out of the data path.

Each phase retains the JSON event/action schema and uses integration fixtures before broadening capture scope.
