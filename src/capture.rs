use crate::{
    events::{
        Direction, Endpoint, EventKind, Fragmentation, RawPacketReference, TcpOption, TrafficEvent,
        TrafficFilter,
    },
    parsers::{certificate, dns, tls},
    store::EventStore,
};
use anyhow::{Result, anyhow};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::Instant,
};
#[cfg(feature = "capture")]
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone)]
pub struct TcpMetadata {
    pub flags: Vec<String>,
    pub flags_bits: u8,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub window_size: u16,
    pub options: Vec<TcpOption>,
}

#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub interface: String,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub protocol: String,
    pub captured_length: usize,
    pub wire_length: usize,
    pub ip_version: u8,
    pub ttl_or_hop_limit: u8,
    pub fragmentation: Option<Fragmentation>,
    pub tcp: Option<TcpMetadata>,
    pub udp_length: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub raw_packet: Option<RawPacketReference>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RawCaptureOptions {
    pub path: PathBuf,
    pub rotate_bytes: u64,
}

#[derive(Debug, Default)]
pub struct TcpReassembler {
    streams: HashMap<String, StreamState>,
}
#[derive(Debug)]
struct StreamState {
    next_sequence: Option<u32>,
    bytes: Vec<u8>,
    last_seen: Instant,
}
impl TcpReassembler {
    /// Returns the complete in-order prefix observed for this directional stream.
    /// A gap is held back rather than emitted as a corrupt protocol message.
    pub fn push(&mut self, key: String, sequence: u32, payload: &[u8]) -> Option<Vec<u8>> {
        self.push_segment(key, sequence, payload, 0)
    }

    pub fn push_segment(
        &mut self,
        key: String,
        sequence: u32,
        payload: &[u8],
        sequence_consumed_by_flags: u32,
    ) -> Option<Vec<u8>> {
        let state = self.streams.entry(key).or_insert(StreamState {
            next_sequence: Some(sequence),
            bytes: vec![],
            last_seen: Instant::now(),
        });
        state.last_seen = Instant::now();
        if state.next_sequence != Some(sequence) {
            return None;
        }
        state.bytes.extend_from_slice(payload);
        const MAX_REASSEMBLED_PREFIX: usize = 128 * 1024;
        if state.bytes.len() > MAX_REASSEMBLED_PREFIX {
            let excess = state.bytes.len() - MAX_REASSEMBLED_PREFIX;
            state.bytes.drain(..excess);
        }
        state.next_sequence = Some(
            sequence
                .wrapping_add(payload.len() as u32)
                .wrapping_add(sequence_consumed_by_flags),
        );
        Some(state.bytes.clone())
    }
}

#[derive(Debug, Default)]
struct CaptureState {
    #[cfg(feature = "capture")]
    reassembler: TcpReassembler,
    flows: HashMap<String, FlowState>,
    dns_queries: HashMap<DnsKey, Instant>,
}

#[derive(Debug, Default)]
struct FlowState {
    client: Option<Endpoint>,
    tcp_directions: HashMap<String, TcpDirectionState>,
    tls_client_hello_emitted: bool,
    tls_certificate_emitted: bool,
}

#[derive(Debug, Default)]
struct TcpDirectionState {
    seen_segments: HashSet<(u32, usize, u8)>,
    highest_sequence_end: Option<u32>,
    last_pure_ack: Option<(u32, u16)>,
    last_advertised_window: Option<(u32, u16)>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct DnsKey {
    transaction_id: u16,
    client: String,
    server: String,
}

#[derive(Debug)]
struct FlowObservation {
    connection_id: String,
    direction: Direction,
    opened: bool,
    closed: Option<String>,
    duplicate_ack: bool,
    retransmitted_segment: bool,
    out_of_order: bool,
    zero_window_probe: bool,
}

fn sequence_before(sequence: u32, reference: u32) -> bool {
    sequence != reference && sequence.wrapping_sub(reference) > u32::MAX / 2
}

fn endpoint_key(endpoint: &Endpoint) -> String {
    if endpoint.host.contains(':') {
        format!("[{}]:{}", endpoint.host, endpoint.port)
    } else {
        format!("{}:{}", endpoint.host, endpoint.port)
    }
}

/// A canonical ID has sorted endpoint keys, so the two packet directions always share it.
fn canonical_connection_id(
    interface: &str,
    protocol: &str,
    source: &Endpoint,
    destination: &Endpoint,
) -> String {
    let mut endpoints = [endpoint_key(source), endpoint_key(destination)];
    endpoints.sort();
    format!(
        "capture:{interface}:{protocol}:{}-{}",
        endpoints[0], endpoints[1]
    )
}

fn known_server(endpoint: &Endpoint, peer: &Endpoint) -> bool {
    endpoint.port != 0 && endpoint.port <= 1024 && peer.port > 1024
}

impl CaptureState {
    fn observe(&mut self, packet: &CapturedPacket) -> FlowObservation {
        let connection_id = canonical_connection_id(
            &packet.interface,
            &packet.protocol,
            &packet.source,
            &packet.destination,
        );
        let flow = self.flows.entry(connection_id.clone()).or_default();
        let tcp = packet.tcp.as_ref();
        let syn = tcp.is_some_and(|metadata| metadata.flags.iter().any(|flag| flag == "SYN"));
        let ack = tcp.is_some_and(|metadata| metadata.flags.iter().any(|flag| flag == "ACK"));
        if flow.client.is_none() {
            if (syn && !ack)
                || packet.destination.port == 53
                || known_server(&packet.destination, &packet.source)
            {
                flow.client = Some(packet.source.clone());
            } else if known_server(&packet.source, &packet.destination) {
                flow.client = Some(packet.destination.clone());
            }
        }
        let direction = match &flow.client {
            Some(client)
                if client.host == packet.source.host && client.port == packet.source.port =>
            {
                Direction::ClientToServer
            }
            Some(_) => Direction::ServerToClient,
            None => Direction::Unknown,
        };
        let (duplicate_ack, retransmitted_segment, out_of_order, zero_window_probe) = tcp
            .map(|metadata| {
                let source_key = endpoint_key(&packet.source);
                let destination_key = endpoint_key(&packet.destination);
                let peer_zero_window = flow
                    .tcp_directions
                    .get(&destination_key)
                    .and_then(|state| state.last_advertised_window)
                    .filter(|(_, window_size)| *window_size == 0)
                    .map(|(acknowledgement_number, _)| acknowledgement_number);
                let state = flow.tcp_directions.entry(source_key).or_default();

                let sequence_space =
                    packet.payload.len() + usize::from(metadata.flags_bits & 0x03 != 0);
                let retransmitted_segment = if sequence_space == 0 {
                    false
                } else {
                    let identity = (
                        metadata.sequence_number,
                        packet.payload.len(),
                        metadata.flags_bits & 0x03,
                    );
                    if state.seen_segments.len() >= 4096 {
                        state.seen_segments.clear();
                    }
                    !state.seen_segments.insert(identity)
                };
                let sequence_end = metadata.sequence_number.wrapping_add(sequence_space as u32);
                let out_of_order = sequence_space > 0
                    && !retransmitted_segment
                    && state
                        .highest_sequence_end
                        .is_some_and(|highest| sequence_before(metadata.sequence_number, highest));
                if sequence_space > 0
                    && state
                        .highest_sequence_end
                        .is_none_or(|highest| sequence_before(highest, sequence_end))
                {
                    state.highest_sequence_end = Some(sequence_end);
                }

                let pure_ack = metadata.flags_bits == 0x10 && packet.payload.is_empty();
                let duplicate_ack = pure_ack
                    && state.last_pure_ack
                        == Some((metadata.acknowledgement_number, metadata.window_size));
                if pure_ack {
                    state.last_pure_ack =
                        Some((metadata.acknowledgement_number, metadata.window_size));
                }
                if metadata.flags_bits & 0x10 != 0 {
                    state.last_advertised_window =
                        Some((metadata.acknowledgement_number, metadata.window_size));
                }

                let zero_window_probe = packet.payload.len() == 1
                    && metadata.flags_bits & 0x07 == 0
                    && peer_zero_window.is_some_and(|acknowledgement_number| {
                        metadata.sequence_number == acknowledgement_number.wrapping_sub(1)
                    });
                (
                    duplicate_ack,
                    retransmitted_segment,
                    out_of_order,
                    zero_window_probe,
                )
            })
            .unwrap_or((false, false, false, false));
        FlowObservation {
            connection_id,
            direction,
            opened: syn && !ack,
            closed: tcp.and_then(|metadata| {
                if metadata.flags.iter().any(|flag| flag == "RST") {
                    Some("reset".into())
                } else if metadata.flags.iter().any(|flag| flag == "FIN") {
                    Some("fin".into())
                } else {
                    None
                }
            }),
            duplicate_ack,
            retransmitted_segment,
            out_of_order,
            zero_window_probe,
        }
    }

    fn mark_tls_client_hello(&mut self, connection_id: &str) -> bool {
        let flow = self.flows.entry(connection_id.to_owned()).or_default();
        if flow.tls_client_hello_emitted {
            false
        } else {
            flow.tls_client_hello_emitted = true;
            true
        }
    }

    fn mark_tls_certificate(&mut self, connection_id: &str) -> bool {
        let flow = self.flows.entry(connection_id.to_owned()).or_default();
        if flow.tls_certificate_emitted {
            false
        } else {
            flow.tls_certificate_emitted = true;
            true
        }
    }
}

pub fn decode_packet(interface: String, bytes: &[u8]) -> Result<CapturedPacket> {
    decode_packet_with_metadata(interface, bytes, bytes.len(), bytes.len(), None)
}

pub fn decode_packet_with_metadata(
    interface: String,
    bytes: &[u8],
    captured_length: usize,
    wire_length: usize,
    raw_packet: Option<RawPacketReference>,
) -> Result<CapturedPacket> {
    if bytes.len() < 14 {
        return Err(anyhow!("short Ethernet frame"));
    }
    let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
    let (src, dst, proto, offset, ip_end, ip_version, ttl_or_hop_limit, fragmentation) =
        match ethertype {
            0x0800 => {
                if bytes.len() < 34 {
                    return Err(anyhow!("short IPv4 packet"));
                }
                let ihl = (bytes[14] & 0x0f) as usize * 4;
                if ihl < 20 || bytes.len() < 14 + ihl {
                    return Err(anyhow!("invalid IPv4 header"));
                }
                let total_length = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
                if total_length < ihl {
                    return Err(anyhow!("invalid IPv4 total length"));
                }
                let flags_and_offset = u16::from_be_bytes([bytes[20], bytes[21]]);
                let fragment_offset = (flags_and_offset & 0x1fff) * 8;
                let more_fragments = flags_and_offset & 0x2000 != 0;
                let fragment = (fragment_offset != 0 || more_fragments).then_some(Fragmentation {
                    is_fragmented: true,
                    offset: fragment_offset,
                    more_fragments,
                    identification: Some(u16::from_be_bytes([bytes[18], bytes[19]]) as u32),
                });
                (
                    IpAddr::V4(Ipv4Addr::new(bytes[26], bytes[27], bytes[28], bytes[29])),
                    IpAddr::V4(Ipv4Addr::new(bytes[30], bytes[31], bytes[32], bytes[33])),
                    bytes[23],
                    14 + ihl,
                    (14 + total_length).min(bytes.len()),
                    4,
                    bytes[22],
                    fragment,
                )
            }
            0x86dd => parse_ipv6(bytes)?,
            _ => return Err(anyhow!("unsupported link protocol")),
        };

    let non_initial_fragment = fragmentation
        .as_ref()
        .is_some_and(|fragment| fragment.offset != 0);
    let protocol = match proto {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        _ => return Err(anyhow!("unsupported IP transport")),
    }
    .to_string();
    let (source_port, destination_port) = if non_initial_fragment || !matches!(proto, 6 | 17) {
        (0, 0)
    } else {
        (read_port(bytes, offset)?, read_port(bytes, offset + 2)?)
    };
    let source = Endpoint::new(src.to_string(), source_port);
    let destination = Endpoint::new(dst.to_string(), destination_port);

    let (payload_offset, tcp, udp_length, icmp_type, icmp_code) = if non_initial_fragment {
        (offset.min(ip_end), None, None, None, None)
    } else {
        match proto {
            6 => parse_tcp(bytes, offset, ip_end)?,
            17 => {
                if offset + 8 > ip_end {
                    return Err(anyhow!("short UDP packet"));
                }
                let length = u16::from_be_bytes([bytes[offset + 4], bytes[offset + 5]]);
                (offset + 8, None, Some(length), None, None)
            }
            1 | 58 => {
                if offset + 2 > ip_end {
                    return Err(anyhow!("short ICMP packet"));
                }
                (
                    offset + 8.min(ip_end - offset),
                    None,
                    None,
                    Some(bytes[offset]),
                    Some(bytes[offset + 1]),
                )
            }
            _ => unreachable!(),
        }
    };
    if payload_offset > ip_end {
        return Err(anyhow!("invalid transport header"));
    }
    Ok(CapturedPacket {
        interface,
        source,
        destination,
        protocol,
        captured_length,
        wire_length,
        ip_version,
        ttl_or_hop_limit,
        fragmentation,
        tcp,
        udp_length,
        icmp_type,
        icmp_code,
        raw_packet,
        payload: bytes[payload_offset..ip_end].to_vec(),
    })
}

type IpDecode = (
    IpAddr,
    IpAddr,
    u8,
    usize,
    usize,
    u8,
    u8,
    Option<Fragmentation>,
);

fn parse_ipv6(bytes: &[u8]) -> Result<IpDecode> {
    if bytes.len() < 54 {
        return Err(anyhow!("short IPv6 packet"));
    }
    let payload_length = u16::from_be_bytes([bytes[18], bytes[19]]) as usize;
    let ip_end = (54 + payload_length).min(bytes.len());
    let a = |p| Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[p..p + 16]).unwrap());
    let mut next = bytes[20];
    let mut offset = 54;
    let mut fragmentation = None;
    while matches!(next, 0 | 43 | 44 | 51 | 60) {
        if next == 44 {
            if offset + 8 > ip_end {
                return Err(anyhow!("truncated IPv6 fragment header"));
            }
            let following = bytes[offset];
            let offset_and_flags = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            fragmentation = Some(Fragmentation {
                is_fragmented: true,
                offset: (offset_and_flags >> 3) * 8,
                more_fragments: offset_and_flags & 1 != 0,
                identification: Some(u32::from_be_bytes([
                    bytes[offset + 4],
                    bytes[offset + 5],
                    bytes[offset + 6],
                    bytes[offset + 7],
                ])),
            });
            next = following;
            offset += 8;
        } else {
            if offset + 2 > ip_end {
                return Err(anyhow!("truncated IPv6 extension header"));
            }
            let following = bytes[offset];
            let length = if next == 51 {
                (bytes[offset + 1] as usize + 2) * 4
            } else {
                (bytes[offset + 1] as usize + 1) * 8
            };
            if offset + length > ip_end {
                return Err(anyhow!("truncated IPv6 extension header"));
            }
            next = following;
            offset += length;
        }
    }
    Ok((
        IpAddr::V6(a(22)),
        IpAddr::V6(a(38)),
        next,
        offset,
        ip_end,
        6,
        bytes[21],
        fragmentation,
    ))
}

fn read_port(bytes: &[u8], offset: usize) -> Result<u16> {
    let pair = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("short IP transport"))?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

type TransportDecode = (
    usize,
    Option<TcpMetadata>,
    Option<u16>,
    Option<u8>,
    Option<u8>,
);

fn parse_tcp(bytes: &[u8], offset: usize, ip_end: usize) -> Result<TransportDecode> {
    if offset + 20 > ip_end {
        return Err(anyhow!("short TCP packet"));
    }
    let header_len = (bytes[offset + 12] >> 4) as usize * 4;
    if header_len < 20 || offset + header_len > ip_end {
        return Err(anyhow!("invalid TCP header"));
    }
    let flags_bits = bytes[offset + 13];
    let options = parse_tcp_options(&bytes[offset + 20..offset + header_len]);
    Ok((
        offset + header_len,
        Some(TcpMetadata {
            flags: tcp_flags(flags_bits),
            flags_bits,
            sequence_number: u32::from_be_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]),
            acknowledgement_number: u32::from_be_bytes([
                bytes[offset + 8],
                bytes[offset + 9],
                bytes[offset + 10],
                bytes[offset + 11],
            ]),
            window_size: u16::from_be_bytes([bytes[offset + 14], bytes[offset + 15]]),
            options,
        }),
        None,
        None,
        None,
    ))
}

fn tcp_flags(bits: u8) -> Vec<String> {
    [
        (0x80, "CWR"),
        (0x40, "ECE"),
        (0x20, "URG"),
        (0x10, "ACK"),
        (0x08, "PSH"),
        (0x04, "RST"),
        (0x02, "SYN"),
        (0x01, "FIN"),
    ]
    .into_iter()
    .filter_map(|(mask, name)| (bits & mask != 0).then_some(name.into()))
    .collect()
}

fn parse_tcp_options(bytes: &[u8]) -> Vec<TcpOption> {
    let mut options = Vec::new();
    let mut p = 0;
    while p < bytes.len() {
        let kind = bytes[p];
        match kind {
            0 => {
                options.push(TcpOption {
                    kind: "end".into(),
                    length: 1,
                    value_hex: None,
                });
                break;
            }
            1 => {
                options.push(TcpOption {
                    kind: "nop".into(),
                    length: 1,
                    value_hex: None,
                });
                p += 1;
            }
            _ => {
                if p + 2 > bytes.len() || bytes[p + 1] < 2 {
                    break;
                }
                let length = bytes[p + 1] as usize;
                if p + length > bytes.len() {
                    break;
                }
                let name = match kind {
                    2 => "mss",
                    3 => "window_scale",
                    4 => "sack_permitted",
                    5 => "sack",
                    8 => "timestamps",
                    _ => "unknown",
                };
                options.push(TcpOption {
                    kind: name.into(),
                    length: length as u8,
                    value_hex: (length > 2).then(|| hex::encode(&bytes[p + 2..p + length])),
                });
                p += length;
            }
        }
    }
    options
}

#[cfg(feature = "capture")]
async fn emit_reassembled_packet(
    packet: CapturedPacket,
    filter: &TrafficFilter,
    store: &EventStore,
    state: &mut CaptureState,
) {
    let reassembled = if packet.protocol == "tcp" && !packet.payload.is_empty() {
        let key = format!(
            "{}>{}",
            endpoint_key(&packet.source),
            endpoint_key(&packet.destination)
        );
        let consumed = packet.tcp.as_ref().map_or(0, |tcp| {
            u32::from(tcp.flags.iter().any(|flag| flag == "SYN" || flag == "FIN"))
        });
        packet.tcp.as_ref().and_then(|tcp| {
            state
                .reassembler
                .push_segment(key, tcp.sequence_number, &packet.payload, consumed)
        })
    } else {
        None
    };
    emit_packet_state(packet, filter, store, state, reassembled.as_deref()).await;
}

/// Emits one decoded packet without retaining flow state. Live capture uses the stateful variant.
pub async fn emit_packet(packet: CapturedPacket, filter: &TrafficFilter, store: &EventStore) {
    let mut state = CaptureState::default();
    emit_packet_state(packet, filter, store, &mut state, None).await;
}

async fn emit_packet_state(
    packet: CapturedPacket,
    filter: &TrafficFilter,
    store: &EventStore,
    state: &mut CaptureState,
    reassembled_payload: Option<&[u8]>,
) {
    if !filter.protocols.is_empty()
        && !filter
            .protocols
            .iter()
            .any(|protocol| protocol_matches(protocol, &packet.protocol))
    {
        return;
    }
    if !filter.matches_packet(&packet.interface, &packet.source, &packet.destination) {
        return;
    }
    let observation = state.observe(&packet);
    let tcp = packet.tcp.as_ref();
    let mut event = TrafficEvent::new(
        observation.connection_id.clone(),
        observation.direction.clone(),
        packet.source.clone(),
        packet.destination.clone(),
        EventKind::Packet {
            interface: packet.interface.clone(),
            protocol: packet.protocol.clone(),
            length: packet.payload.len(),
            captured_length: packet.captured_length,
            wire_length: packet.wire_length,
            payload_length: packet.payload.len(),
            ip_version: packet.ip_version,
            ttl_or_hop_limit: packet.ttl_or_hop_limit,
            fragmentation: packet.fragmentation.clone(),
            tcp_flags: tcp.map(|metadata| metadata.flags.clone()),
            sequence_number: tcp.map(|metadata| metadata.sequence_number),
            acknowledgement_number: tcp.map(|metadata| metadata.acknowledgement_number),
            window_size: tcp.map(|metadata| metadata.window_size),
            tcp_options: tcp.map(|metadata| metadata.options.clone()),
            udp_length: packet.udp_length,
            icmp_type: packet.icmp_type,
            icmp_code: packet.icmp_code,
            raw_packet: packet.raw_packet.clone(),
        },
    );
    if observation.duplicate_ack {
        event.attributes.insert("duplicate_ack".into(), true.into());
    }
    if observation.retransmitted_segment {
        event
            .attributes
            .insert("retransmitted_segment".into(), true.into());
    }
    if observation.out_of_order {
        event.attributes.insert("out_of_order".into(), true.into());
    }
    if observation.zero_window_probe {
        event
            .attributes
            .insert("zero_window_probe".into(), true.into());
    }
    store.emit(event).await;

    if observation.opened {
        store
            .emit(TrafficEvent::new(
                observation.connection_id.clone(),
                observation.direction.clone(),
                packet.source.clone(),
                packet.destination.clone(),
                EventKind::ConnectionOpened {
                    transport: packet.protocol.clone(),
                },
            ))
            .await;
    }
    if let Some(reason) = observation.closed {
        store
            .emit(TrafficEvent::new(
                observation.connection_id.clone(),
                observation.direction.clone(),
                packet.source.clone(),
                packet.destination.clone(),
                EventKind::ConnectionClosed {
                    reason: Some(reason),
                },
            ))
            .await;
    }

    if (packet.source.port == 53 || packet.destination.port == 53)
        && packet.protocol == "udp"
        && let Ok(summary) = dns::parse_dns(&packet.payload)
    {
        if summary
            .query
            .as_deref()
            .is_some_and(|name| !filter.matches_hostname(name))
        {
            return;
        }
        let (client, server) = if summary.is_response {
            (&packet.destination, &packet.source)
        } else {
            (&packet.source, &packet.destination)
        };
        let dns_key = DnsKey {
            transaction_id: summary.transaction_id,
            client: endpoint_key(client),
            server: endpoint_key(server),
        };
        let latency_ms = if summary.is_response {
            state
                .dns_queries
                .remove(&dns_key)
                .map(|started| started.elapsed().as_millis())
        } else {
            if state.dns_queries.len() >= 4096 {
                state.dns_queries.clear();
            }
            state.dns_queries.insert(dns_key, Instant::now());
            None
        };
        let answers = summary
            .answers
            .iter()
            .map(|answer| {
                format!(
                    "{} {} {} ttl={}",
                    answer.name, answer.record_type, answer.value, answer.ttl
                )
            })
            .collect();
        store
            .emit(TrafficEvent::new(
                observation.connection_id.clone(),
                observation.direction.clone(),
                packet.source.clone(),
                packet.destination.clone(),
                EventKind::Dns {
                    query: summary.query,
                    record_type: summary.record_type,
                    response_code: Some(summary.response_code),
                    transaction_id: summary.transaction_id,
                    is_response: summary.is_response,
                    answers,
                    cname_chain: summary.cname_chain,
                    latency_ms,
                },
            ))
            .await;
    }

    if packet.protocol == "tcp"
        && let Some(payload) = reassembled_payload
        && let Ok(hello) = tls::parse_client_hello(payload)
    {
        if hello
            .sni
            .as_deref()
            .is_some_and(|name| !filter.matches_hostname(name))
        {
            return;
        }
        if !state.mark_tls_client_hello(&observation.connection_id) {
            return;
        }
        store
            .emit(TrafficEvent::new(
                observation.connection_id.clone(),
                observation.direction.clone(),
                packet.source.clone(),
                packet.destination.clone(),
                EventKind::TlsClientHello {
                    sni: hello.sni,
                    alpn: hello.alpn,
                    tls_version: hello.tls_version,
                    cipher_suites: hello.cipher_suites,
                },
            ))
            .await;
    }

    if packet.protocol == "tcp"
        && let Some(payload) = reassembled_payload
        && let Ok(der) = tls::parse_server_certificate(payload)
        && let Ok(summary) = certificate::parse_certificate(&der)
        && state.mark_tls_certificate(&observation.connection_id)
    {
        store
            .emit(TrafficEvent::new(
                observation.connection_id,
                observation.direction,
                packet.source,
                packet.destination,
                EventKind::TlsCertificate {
                    subject: Some(summary.subject),
                    issuer: Some(summary.issuer),
                    serial: Some(summary.serial),
                    not_after: Some(summary.not_after),
                },
            ))
            .await;
    }
}

fn protocol_matches(filter_protocol: &str, packet_protocol: &str) -> bool {
    filter_protocol.eq_ignore_ascii_case(packet_protocol)
        || (filter_protocol.eq_ignore_ascii_case("icmp6") && packet_protocol == "icmpv6")
        || (filter_protocol.eq_ignore_ascii_case("icmpv6") && packet_protocol == "icmpv6")
}

#[cfg(feature = "capture")]
pub async fn run_live(
    interface: String,
    filter: TrafficFilter,
    store: EventStore,
    raw_capture: Option<RawCaptureOptions>,
) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut state = CaptureState::default();
        let device = pcap::Device::list()?
            .into_iter()
            .find(|d| d.name == interface)
            .ok_or_else(|| anyhow!("interface not found: {interface}"))?;
        let mut cap = pcap::Capture::from_device(device)?
            .promisc(true)
            .immediate_mode(true)
            .open()?;
        let raw_link_type = u16::try_from(cap.get_datalink().0)
            .map_err(|_| anyhow!("pcap link type does not fit in a pcapng interface descriptor"))?;
        let mut raw_writer = raw_capture
            .map(|options| PcapNgWriter::new(options, raw_link_type))
            .transpose()?;
        if let Some(expression) = bpf_filter(&filter) {
            cap.filter(&expression, true)?;
        }
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let raw_packet = raw_writer
                        .as_mut()
                        .map(|writer| writer.write(packet.data, packet.header.len as usize))
                        .transpose()?;
                    if let Ok(decoded) = decode_packet_with_metadata(
                        interface.clone(),
                        packet.data,
                        packet.header.caplen as usize,
                        packet.header.len as usize,
                        raw_packet,
                    ) {
                        tokio::runtime::Handle::current().block_on(emit_reassembled_packet(
                            decoded, &filter, &store, &mut state,
                        ));
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {}
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await??;
    Ok(())
}

/// Runs one capture loop per selected interface and returns when a loop fails.
pub async fn run_interfaces(
    interfaces: Vec<String>,
    mut filter: TrafficFilter,
    store: EventStore,
    raw_capture: Option<RawCaptureOptions>,
) -> Result<()> {
    if interfaces.is_empty() {
        return Err(anyhow!("at least one --interface is required"));
    }
    filter.interfaces = interfaces.clone();
    let multiple_interfaces = interfaces.len() > 1;
    let mut tasks = tokio::task::JoinSet::new();
    for interface in interfaces {
        let task_filter = filter.clone();
        let task_store = store.clone();
        let task_raw_capture = raw_capture.as_ref().map(|options| RawCaptureOptions {
            path: raw_path_for_interface(&options.path, &interface, multiple_interfaces),
            rotate_bytes: options.rotate_bytes,
        });
        tasks.spawn(
            async move { run_live(interface, task_filter, task_store, task_raw_capture).await },
        );
    }
    match tasks.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(error)) => Err(error.into()),
        None => Ok(()),
    }
}

fn raw_path_for_interface(path: &Path, interface: &str, multiple_interfaces: bool) -> PathBuf {
    if !multiple_interfaces {
        return path.to_path_buf();
    }
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("capture");
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("pcapng");
    let safe_interface: String = interface
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect();
    path.with_file_name(format!("{stem}.{safe_interface}.{extension}"))
}

#[cfg(feature = "capture")]
struct PcapNgWriter {
    options: RawCaptureOptions,
    file: BufWriter<File>,
    current_path: PathBuf,
    bytes_written: u64,
    packet_number: u64,
    rotation: u64,
    link_type: u16,
}

#[cfg(feature = "capture")]
impl PcapNgWriter {
    fn new(options: RawCaptureOptions, link_type: u16) -> Result<Self> {
        let current_path = options.path.clone();
        let (file, bytes_written) = Self::open(&current_path, link_type)?;
        Ok(Self {
            options,
            file,
            current_path,
            bytes_written,
            packet_number: 0,
            rotation: 0,
            link_type,
        })
    }
    fn open(path: &Path, link_type: u16) -> Result<(BufWriter<File>, u64)> {
        let file = File::create(path)?;
        let mut file = BufWriter::new(file);
        write_block(
            &mut file,
            0x0a0d0d0a,
            &[0x1a2b3c4d, 0x00000001, 0xffff_ffff, 0xffff_ffff],
        )?;
        // Preserve libpcap's link type and use a 64 KiB snapshot length.
        write_block(&mut file, 0x00000001, &[u32::from(link_type), 0x0000ffff])?;
        file.flush()?;
        Ok((file, 48))
    }
    fn write(&mut self, bytes: &[u8], wire_length: usize) -> Result<RawPacketReference> {
        let padded = (bytes.len() + 3) & !3;
        let block_length = 32 + padded as u64;
        if self.packet_number > 0
            && self.bytes_written + block_length > self.options.rotate_bytes.max(48)
        {
            self.rotation += 1;
            self.current_path = rotated_path(&self.options.path, self.rotation);
            let (file, header_bytes) = Self::open(&self.current_path, self.link_type)?;
            self.file = file;
            self.bytes_written = header_bytes;
        }
        let offset = self.bytes_written;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let payload = pcapng_packet_payload(now, bytes, wire_length);
        write_block(&mut self.file, 0x00000006, &payload)?;
        self.file.flush()?;
        self.bytes_written += block_length;
        self.packet_number += 1;
        Ok(RawPacketReference {
            packet_id: format!("{}-{}", self.current_path.display(), self.packet_number),
            file: self.current_path.display().to_string(),
            offset,
        })
    }
}

#[cfg(feature = "capture")]
fn rotated_path(path: &Path, rotation: u64) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("capture");
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("pcapng");
    path.with_file_name(format!("{stem}.{rotation:04}.{extension}"))
}

#[cfg(feature = "capture")]
fn write_block(file: &mut BufWriter<File>, kind: u32, words: &[u32]) -> Result<()> {
    let total_length = 12 + words.len() as u32 * 4;
    file.write_all(&kind.to_le_bytes())?;
    file.write_all(&total_length.to_le_bytes())?;
    for word in words {
        file.write_all(&word.to_le_bytes())?;
    }
    file.write_all(&total_length.to_le_bytes())?;
    Ok(())
}

#[cfg(feature = "capture")]
fn pcapng_packet_payload(timestamp_micros: u64, bytes: &[u8], wire_length: usize) -> Vec<u32> {
    let padded = (bytes.len() + 3) & !3;
    let mut raw = Vec::with_capacity(20 + padded);
    raw.extend_from_slice(&0_u32.to_le_bytes()); // interface id
    raw.extend_from_slice(&((timestamp_micros >> 32) as u32).to_le_bytes());
    raw.extend_from_slice(&(timestamp_micros as u32).to_le_bytes());
    raw.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    raw.extend_from_slice(&(wire_length as u32).to_le_bytes());
    raw.extend_from_slice(bytes);
    raw.resize(20 + padded, 0);
    raw.chunks_exact(4)
        .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
        .collect()
}

#[cfg(feature = "capture")]
fn bpf_filter(filter: &TrafficFilter) -> Option<String> {
    let mut clauses = Vec::new();
    if !filter.protocols.is_empty() {
        let protocols = filter
            .protocols
            .iter()
            .filter_map(|protocol| match protocol.to_ascii_lowercase().as_str() {
                "tcp" | "udp" | "icmp" | "ip" | "ip6" => Some(protocol.to_ascii_lowercase()),
                "icmp6" | "icmpv6" => Some("icmp6".into()),
                _ => None,
            })
            .collect::<Vec<_>>();
        if !protocols.is_empty() {
            clauses.push(format!("({})", protocols.join(" or ")));
        }
    }
    if !filter.ports.is_empty() {
        clauses.push(format!(
            "({})",
            filter
                .ports
                .iter()
                .map(|port| format!("port {port}"))
                .collect::<Vec<_>>()
                .join(" or ")
        ));
    }
    if !filter.ips.is_empty() {
        clauses.push(format!(
            "({})",
            filter
                .ips
                .iter()
                .map(|ip| format!("host {ip}"))
                .collect::<Vec<_>>()
                .join(" or ")
        ));
    }
    (!clauses.is_empty()).then(|| clauses.join(" and "))
}

#[cfg(not(feature = "capture"))]
pub async fn run_live(
    _: String,
    _: TrafficFilter,
    _: EventStore,
    _: Option<RawCaptureOptions>,
) -> Result<()> {
    Err(anyhow!("built without packet capture support"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_packet(
        source: Endpoint,
        destination: Endpoint,
        sequence_number: u32,
        acknowledgement_number: u32,
        flags_bits: u8,
        window_size: u16,
        payload: &[u8],
    ) -> CapturedPacket {
        CapturedPacket {
            interface: "en0".into(),
            source,
            destination,
            protocol: "tcp".into(),
            captured_length: 0,
            wire_length: 0,
            ip_version: 4,
            ttl_or_hop_limit: 64,
            fragmentation: None,
            tcp: Some(TcpMetadata {
                flags: tcp_flags(flags_bits),
                flags_bits,
                sequence_number,
                acknowledgement_number,
                window_size,
                options: vec![],
            }),
            udp_length: None,
            icmp_type: None,
            icmp_code: None,
            raw_packet: None,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn decodes_ipv4_udp_metadata() {
        let mut frame = vec![0_u8; 14 + 20 + 8 + 3];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&(31_u16).to_be_bytes());
        frame[22] = 64;
        frame[23] = 17;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        frame[34..36].copy_from_slice(&12345_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&53_u16.to_be_bytes());
        frame[38..40].copy_from_slice(&(11_u16).to_be_bytes());
        frame[42..].copy_from_slice(b"dns");
        let packet = decode_packet("en0".into(), &frame).unwrap();
        assert_eq!(packet.destination.port, 53);
        assert_eq!(packet.payload, b"dns");
        assert_eq!(packet.udp_length, Some(11));
        assert_eq!(packet.ttl_or_hop_limit, 64);
    }

    #[test]
    fn canonical_ids_and_flow_direction_are_shared() {
        let client = Endpoint::new("192.0.2.1", 50000);
        let server = Endpoint::new("198.51.100.2", 443);
        assert_eq!(
            canonical_connection_id("en0", "tcp", &client, &server),
            canonical_connection_id("en0", "tcp", &server, &client),
        );
    }

    #[test]
    fn decodes_tcp_flags_and_lengths() {
        let mut frame = vec![0_u8; 14 + 20 + 20];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&(40_u16).to_be_bytes());
        frame[22] = 63;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[198, 51, 100, 2]);
        frame[34..36].copy_from_slice(&50000_u16.to_be_bytes());
        frame[36..38].copy_from_slice(&443_u16.to_be_bytes());
        frame[38..42].copy_from_slice(&123_u32.to_be_bytes());
        frame[42..46].copy_from_slice(&456_u32.to_be_bytes());
        frame[46] = 0x50;
        frame[47] = 0x12;
        frame[48..50].copy_from_slice(&65535_u16.to_be_bytes());
        let packet = decode_packet("en0".into(), &frame).unwrap();
        let tcp = packet.tcp.unwrap();
        assert_eq!(tcp.flags, vec!["ACK", "SYN"]);
        assert_eq!(tcp.sequence_number, 123);
        assert_eq!(tcp.acknowledgement_number, 456);
        assert_eq!(tcp.window_size, 65535);
        assert!(packet.payload.is_empty());
    }

    #[test]
    fn reassembles_contiguous_tcp_segments() {
        let mut r = TcpReassembler::default();
        assert_eq!(r.push("a".into(), 10, b"hello"), Some(b"hello".to_vec()));
        assert_eq!(
            r.push("a".into(), 15, b" world"),
            Some(b"hello world".to_vec())
        );
    }

    #[test]
    fn classifies_tcp_anomalies_without_calling_pure_acks_retransmissions() {
        let client = Endpoint::new("192.0.2.1", 50000);
        let server = Endpoint::new("198.51.100.2", 443);

        let mut duplicate_ack_state = CaptureState::default();
        duplicate_ack_state.observe(&tcp_packet(
            client.clone(),
            server.clone(),
            10,
            0,
            0x02,
            4096,
            b"",
        ));
        duplicate_ack_state.observe(&tcp_packet(
            client.clone(),
            server.clone(),
            11,
            100,
            0x10,
            4096,
            b"",
        ));
        let duplicate_ack = duplicate_ack_state.observe(&tcp_packet(
            client.clone(),
            server.clone(),
            11,
            100,
            0x10,
            4096,
            b"",
        ));
        assert!(duplicate_ack.duplicate_ack);
        assert!(!duplicate_ack.retransmitted_segment);

        let mut retransmission_state = CaptureState::default();
        retransmission_state.observe(&tcp_packet(
            client.clone(),
            server.clone(),
            100,
            0,
            0x18,
            4096,
            b"hello",
        ));
        let retransmission = retransmission_state.observe(&tcp_packet(
            client.clone(),
            server.clone(),
            100,
            0,
            0x18,
            4096,
            b"hello",
        ));
        assert!(retransmission.retransmitted_segment);
        assert!(!retransmission.out_of_order);

        let mut out_of_order_state = CaptureState::default();
        out_of_order_state.observe(&tcp_packet(
            client.clone(),
            server.clone(),
            100,
            0,
            0x18,
            4096,
            b"hello",
        ));
        let out_of_order = out_of_order_state.observe(&tcp_packet(
            client.clone(),
            server.clone(),
            90,
            0,
            0x18,
            4096,
            b"there",
        ));
        assert!(out_of_order.out_of_order);
        assert!(!out_of_order.retransmitted_segment);

        let mut zero_window_state = CaptureState::default();
        zero_window_state.observe(&tcp_packet(
            server.clone(),
            client.clone(),
            500,
            100,
            0x10,
            0,
            b"",
        ));
        let zero_window_probe =
            zero_window_state.observe(&tcp_packet(client, server, 99, 500, 0x10, 4096, b"x"));
        assert!(zero_window_probe.zero_window_probe);
    }

    #[cfg(feature = "capture")]
    #[test]
    fn writes_an_enhanced_packet_block_with_a_stable_offset() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.pcapng");
        let mut writer = PcapNgWriter::new(
            RawCaptureOptions {
                path: path.clone(),
                rotate_bytes: 1024,
            },
            1,
        )
        .unwrap();
        let reference = writer.write(&[1, 2, 3], 60).unwrap();
        drop(writer);

        let file = std::fs::read(path).unwrap();
        assert_eq!(reference.offset, 48);
        assert_eq!(&file[0..4], &0x0a0d0d0au32.to_le_bytes());
        assert_eq!(&file[12..16], &1u32.to_le_bytes());
        assert_eq!(&file[28..32], &1u32.to_le_bytes());
        assert_eq!(&file[36..40], &1u32.to_le_bytes());
        assert_eq!(&file[48..52], &0x00000006u32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(file[52..56].try_into().unwrap()), 36);
        assert_eq!(file.len(), 84);
    }
}
