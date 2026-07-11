use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub type ConnectionId = String;

static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEvent {
    pub id: String,
    pub timestamp_ms: u128,
    pub connection_id: ConnectionId,
    pub direction: Direction,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub kind: EventKind,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

impl TrafficEvent {
    pub fn new(
        connection_id: impl Into<String>,
        direction: Direction,
        source: Endpoint,
        destination: Endpoint,
        kind: EventKind,
    ) -> Self {
        let connection_id = connection_id.into();
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self {
            id: format!(
                "{connection_id}-{timestamp_ms}-{}",
                EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
            timestamp_ms,
            connection_id,
            direction,
            source,
            destination,
            kind,
            attributes: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

/// Metadata retained for a raw packet when `capture --pcapng` is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPacketReference {
    pub packet_id: String,
    pub file: String,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fragmentation {
    pub is_fragmented: bool,
    pub offset: u16,
    pub more_fragments: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identification: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpOption {
    pub kind: String,
    pub length: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_hex: Option<String>,
}
impl Endpoint {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    ConnectionOpened {
        transport: String,
    },
    ConnectionClosed {
        reason: Option<String>,
    },
    Packet {
        interface: String,
        protocol: String,
        /// Retained for compatibility; this is always the transport payload length.
        length: usize,
        captured_length: usize,
        wire_length: usize,
        payload_length: usize,
        ip_version: u8,
        ttl_or_hop_limit: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        fragmentation: Option<Fragmentation>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tcp_flags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sequence_number: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        acknowledgement_number: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        window_size: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tcp_options: Option<Vec<TcpOption>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        udp_length: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        icmp_type: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        icmp_code: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw_packet: Option<RawPacketReference>,
    },
    Dns {
        query: Option<String>,
        record_type: Option<u16>,
        response_code: Option<u8>,
        transaction_id: u16,
        is_response: bool,
        answers: Vec<String>,
        cname_chain: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        latency_ms: Option<u128>,
    },
    HttpRequest {
        method: String,
        target: String,
        version: String,
        headers: BTreeMap<String, String>,
    },
    HttpResponse {
        status: u16,
        reason: String,
        headers: BTreeMap<String, String>,
    },
    HttpBody {
        direction: Direction,
        length: usize,
        content_type: Option<String>,
    },
    TlsClientHello {
        sni: Option<String>,
        alpn: Vec<String>,
        tls_version: String,
        cipher_suites: Vec<String>,
    },
    TlsCertificate {
        subject: Option<String>,
        issuer: Option<String>,
        serial: Option<String>,
        not_after: Option<String>,
    },
    Tunnel {
        authority: String,
        intercepted: bool,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct TrafficFilter {
    pub interfaces: Vec<String>,
    pub protocols: Vec<String>,
    pub ips: Vec<IpAddr>,
    pub hostnames: Vec<String>,
    pub ports: Vec<u16>,
    pub process: Option<String>,
}

impl TrafficFilter {
    pub fn matches_packet(
        &self,
        interface: &str,
        source: &Endpoint,
        destination: &Endpoint,
    ) -> bool {
        if !self.interfaces.is_empty() && !self.interfaces.iter().any(|value| value == interface) {
            return false;
        }
        if !self.ports.is_empty()
            && !self.ports.contains(&source.port)
            && !self.ports.contains(&destination.port)
        {
            return false;
        }
        if !self.ips.is_empty()
            && ![&source.host, &destination.host].into_iter().any(|host| {
                host.parse::<IpAddr>()
                    .is_ok_and(|ip| self.ips.contains(&ip))
            })
        {
            return false;
        }
        true
    }

    /// Applies hostname filtering only after a hostname was learned from DNS or TLS metadata.
    pub fn matches_hostname(&self, hostname: &str) -> bool {
        self.hostnames.is_empty()
            || self
                .hostnames
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(hostname))
    }

    pub fn matches_endpoint(&self, endpoint: &Endpoint) -> bool {
        (self.ports.is_empty() || self.ports.contains(&endpoint.port))
            && (self.hostnames.is_empty()
                || self
                    .hostnames
                    .iter()
                    .any(|h| endpoint.host.eq_ignore_ascii_case(h)))
            && (self.ips.is_empty()
                || endpoint
                    .host
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| self.ips.contains(&ip)))
    }
}
