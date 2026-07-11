### Overall capture summary
```sql
SELECT
    min(event_time) AS capture_started,
    max(event_time) AS capture_ended,
    date_diff('second', min(event_time), max(event_time))
        AS duration_seconds,
    count(*) AS total_events,
    count(DISTINCT connection_id) AS connections,
    count(DISTINCT source_host) AS source_hosts,
    count(DISTINCT destination_host) AS destination_hosts,
    sum(coalesce(wire_length, captured_length, 0)) AS observed_bytes,
    format_bytes(
        CAST(
            sum(coalesce(wire_length, captured_length, 0))
            AS BIGINT
        )
    ) AS observed_size
FROM traffic_events;
```

### Traffic breakdown by interface, protocol, and direction
```sql
SELECT
    interface,
    protocol,
    direction,
    count(*) AS packets,
    sum(effective_payload_length) AS payload_bytes,
    format_bytes(sum(effective_payload_length)::BIGINT) AS payload_size,
    sum(effective_wire_length) AS wire_bytes,
    format_bytes(sum(effective_wire_length)::BIGINT) AS wire_size
FROM packets
GROUP BY interface, protocol, direction
ORDER BY wire_bytes DESC;
```

### Top remote servers by traffic volume
```sql
SELECT
    server_host,
    server_port,
    protocol,
    count(DISTINCT connection_id) AS connections,
    count(*) AS packets,
    sum(effective_payload_length) AS payload_bytes,
    format_bytes(sum(effective_payload_length)::BIGINT) AS payload_size
FROM packets
WHERE server_host IS NOT NULL
GROUP BY server_host, server_port, protocol
ORDER BY payload_bytes DESC
LIMIT 25;
```

### Largest connections
```sql
SELECT
    connection_id,
    client_host,
    client_port,
    server_host,
    server_port,
    protocol,
    packet_count,
    format_bytes(payload_bytes::BIGINT) AS payload_size,
    format_bytes(uploaded_bytes::BIGINT) AS uploaded,
    format_bytes(downloaded_bytes::BIGINT) AS downloaded,
    duration_ms,
    retransmitted_segment_packets
FROM connection_summary
ORDER BY payload_bytes DESC
LIMIT 25;
```

### Upload/download asymmetry

> Useful for spotting downloads, uploads, backups, streaming, or exfiltration-like behaviour.

```sql
SELECT
    connection_id,
    server_host,
    server_port,
    format_bytes(uploaded_bytes::BIGINT) AS uploaded,
    format_bytes(downloaded_bytes::BIGINT) AS downloaded,

    round(
        downloaded_bytes::DOUBLE
        / nullif(uploaded_bytes, 0),
        2
    ) AS download_to_upload_ratio,

    packet_count,
    duration_ms
FROM connection_summary
WHERE payload_bytes > 0
ORDER BY greatest(uploaded_bytes, downloaded_bytes) DESC
LIMIT 25;
```

### Connections with the highest retransmitted-segment rate
```sql
SELECT
    connection_id,
    client_host,
    server_host,
    server_port,
    packet_count,
    retransmitted_segment_packets,

    round(
        100.0 * retransmitted_segment_packets
        / nullif(packet_count, 0),
        2
    ) AS retransmitted_segment_percent,

    format_bytes(payload_bytes::BIGINT) AS payload_size,
    duration_ms
FROM connection_summary
WHERE retransmitted_segment_packets > 0
-- AND packet_count >= 20
ORDER BY retransmitted_segment_percent DESC,
         retransmitted_segment_packets DESC
LIMIT 25;
```

### Throughput over time

> Change the bucket from 30 seconds to one minute for longer captures.

```sql
SELECT
    time_bucket(INTERVAL '30 second', event_time) AS bucket,
    count(*) AS packets,
    sum(effective_wire_length) AS wire_bytes,
    sum(effective_payload_length) AS payload_bytes,

    round(
        sum(effective_wire_length) * 8.0 / 1000000,
        3
    ) AS observed_mbps

FROM packets
GROUP BY bucket
ORDER BY bucket;
```
