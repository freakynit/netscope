-- ============================================================
-- NetScope NDJSON import
-- ============================================================

INSTALL json;
LOAD json;

DROP VIEW IF EXISTS connection_summary;
DROP VIEW IF EXISTS packets;
DROP TABLE IF EXISTS traffic_events;

CREATE TABLE traffic_events AS
SELECT
    -- Common event identity
    json_extract_string(json, '$.id')                              AS id,
    try_cast(json_extract_string(json, '$.timestamp_ms') AS BIGINT) AS timestamp_ms,
    to_timestamp(
        try_cast(json_extract_string(json, '$.timestamp_ms') AS DOUBLE) / 1000.0
    )                                                             AS event_time,
    json_extract_string(json, '$.connection_id')                   AS connection_id,
    json_extract_string(json, '$.direction')                       AS direction,

    -- Endpoints
    json_extract_string(json, '$.source.host')                     AS source_host,
    try_cast(json_extract_string(json, '$.source.port') AS INTEGER) AS source_port,
    json_extract_string(json, '$.destination.host')                AS destination_host,
    try_cast(
        json_extract_string(json, '$.destination.port') AS INTEGER
    )                                                             AS destination_port,

    -- Event classification
    json_extract_string(json, '$.kind.type')                       AS event_type,
    json_extract_string(json, '$.kind.interface')                  AS interface,
    lower(json_extract_string(json, '$.kind.protocol'))            AS protocol,

    -- Packet lengths
    try_cast(json_extract_string(json, '$.kind.length') AS BIGINT) AS length,
    try_cast(
        json_extract_string(json, '$.kind.wire_length') AS BIGINT
    )                                                             AS wire_length,
    try_cast(
        json_extract_string(json, '$.kind.captured_length') AS BIGINT
    )                                                             AS captured_length,
    try_cast(
        json_extract_string(json, '$.kind.payload_length') AS BIGINT
    )                                                             AS payload_length,

    -- IP metadata
    try_cast(
        json_extract_string(json, '$.kind.ip_version') AS SMALLINT
    )                                                             AS ip_version,
    try_cast(
        json_extract_string(json, '$.kind.ttl_or_hop_limit') AS SMALLINT
    )                                                             AS ttl_or_hop_limit,
    json_extract(json, '$.kind.fragmentation')                     AS fragmentation,

    -- TCP metadata
    try_cast(
        json_extract(json, '$.kind.tcp_flags') AS VARCHAR[]
    )                                                             AS tcp_flags,
    try_cast(
        json_extract_string(json, '$.kind.sequence_number') AS UBIGINT
    )                                                             AS sequence_number,
    try_cast(
        json_extract_string(
            json,
            '$.kind.acknowledgement_number'
        ) AS UBIGINT
    )                                                             AS acknowledgement_number,
    try_cast(
        json_extract_string(json, '$.kind.window_size') AS UINTEGER
    )                                                             AS window_size,
    json_extract(json, '$.kind.tcp_options')                       AS tcp_options,

    -- UDP / ICMP metadata
    try_cast(
        json_extract_string(json, '$.kind.udp_length') AS INTEGER
    )                                                             AS udp_length,
    try_cast(
        json_extract_string(json, '$.kind.icmp_type') AS SMALLINT
    )                                                             AS icmp_type,
    try_cast(
        json_extract_string(json, '$.kind.icmp_code') AS SMALLINT
    )                                                             AS icmp_code,

    -- Raw pcapng linkage
    json_extract_string(json, '$.kind.raw_packet.packet_id')       AS raw_packet_id,
    json_extract_string(json, '$.kind.raw_packet.file')            AS raw_packet_file,
    try_cast(
        json_extract_string(json, '$.kind.raw_packet.offset') AS UBIGINT
    )                                                             AS raw_packet_offset,

    -- Frequently used attributes
    coalesce(
        try_cast(json_extract_string(json, '$.attributes.duplicate_ack') AS BOOLEAN),
        false
    )                                                             AS is_duplicate_ack,
    coalesce(
        try_cast(
            json_extract_string(json, '$.attributes.retransmitted_segment') AS BOOLEAN
        ),
        false
    )                                                             AS is_retransmitted_segment,
    coalesce(
        try_cast(json_extract_string(json, '$.attributes.out_of_order') AS BOOLEAN),
        false
    )                                                             AS is_out_of_order,
    coalesce(
        try_cast(
            json_extract_string(json, '$.attributes.zero_window_probe') AS BOOLEAN
        ),
        false
    )                                                             AS is_zero_window_probe,

    -- Preserve evolving/unrecognised fields
    json_extract(json, '$.attributes')                             AS attributes,
    json_extract(json, '$.kind')                                   AS kind,
    json                                                          AS raw_event

FROM read_json_objects(
    'capture.ndjson',
    format = 'newline_delimited'
);

CREATE VIEW packets AS
SELECT
    *,
    CASE direction
        WHEN 'client_to_server' THEN source_host
        WHEN 'server_to_client' THEN destination_host
    END AS client_host,
    CASE direction
        WHEN 'client_to_server' THEN source_port
        WHEN 'server_to_client' THEN destination_port
    END AS client_port,
    CASE direction
        WHEN 'client_to_server' THEN destination_host
        WHEN 'server_to_client' THEN source_host
    END AS server_host,
    CASE direction
        WHEN 'client_to_server' THEN destination_port
        WHEN 'server_to_client' THEN source_port
    END AS server_port,
    coalesce(payload_length, length, 0) AS effective_payload_length,
    coalesce(wire_length, captured_length, payload_length, length, 0)
        AS effective_wire_length,
    list_contains(tcp_flags, 'SYN') AS has_syn,
    list_contains(tcp_flags, 'ACK') AS has_ack,
    list_contains(tcp_flags, 'FIN') AS has_fin,
    list_contains(tcp_flags, 'RST') AS has_rst,
    list_contains(tcp_flags, 'PSH') AS has_psh
FROM traffic_events
WHERE event_type = 'packet';

CREATE VIEW connection_summary AS
SELECT
    connection_id,
    any_value(interface) AS interface,
    any_value(protocol) AS protocol,
    any_value(client_host) AS client_host,
    any_value(client_port) AS client_port,
    any_value(server_host) AS server_host,
    any_value(server_port) AS server_port,
    min(event_time) AS first_seen,
    max(event_time) AS last_seen,
    date_diff('millisecond', min(event_time), max(event_time)) AS duration_ms,
    count(*) AS packet_count,
    count(*) FILTER (WHERE direction = 'client_to_server') AS client_to_server_packets,
    count(*) FILTER (WHERE direction = 'server_to_client') AS server_to_client_packets,
    sum(effective_payload_length) AS payload_bytes,
    sum(effective_payload_length) FILTER (WHERE direction = 'client_to_server')
        AS uploaded_bytes,
    sum(effective_payload_length) FILTER (WHERE direction = 'server_to_client')
        AS downloaded_bytes,
    count(*) FILTER (WHERE is_duplicate_ack) AS duplicate_ack_packets,
    count(*) FILTER (WHERE is_retransmitted_segment) AS retransmitted_segment_packets,
    count(*) FILTER (WHERE is_out_of_order) AS out_of_order_packets,
    count(*) FILTER (WHERE is_zero_window_probe) AS zero_window_probe_packets,
    count(*) FILTER (WHERE has_rst) AS reset_packets,
    count(*) FILTER (WHERE has_syn) AS syn_packets,
    count(*) FILTER (WHERE has_fin) AS fin_packets
FROM packets
GROUP BY connection_id;
