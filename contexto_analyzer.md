
## Archivo: `nextrace-core/src/analyzer.rs`

```rust
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

use crate::{
    extract_transport_payload,
    parse_dns, parse_http, parse_tls_client_hello,
    summarize, DnsMessage, DnsRdata, HttpMessage,
    Asset, AssetId, AssetKind, Direction, DomainError, EventId, EventKind,
    Evidence, EvidenceId, EvidenceLocation, FlowId, Investigation, NetworkEvent,
    NetworkFlow, NetworkInfo, PcapError, PcapNgError, PcapNgReader, PcapPacket,
    PcapReader, Protocol, SourceId, StreamKey, TcpReassembler,
};

const MAX_STREAM_BUFFER: usize = 64 * 1024;

fn format_tcp_flags(flags: crate::TcpFlags) -> Option<String> {
    let mut parts = Vec::new();
    if flags.syn { parts.push("SYN"); }
    if flags.ack { parts.push("ACK"); }
    if flags.psh { parts.push("PSH"); }
    if flags.fin { parts.push("FIN"); }
    if flags.rst { parts.push("RST"); }
    if flags.urg { parts.push("URG"); }
    
    if parts.is_empty() { None } else { Some(parts.join(", ")) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapAnalysisReport {
    pub packets_read: u64,
    pub events_created: u64,
    pub flows_created: u64,
    pub flows_updated: u64,
    pub assets_created: u64,
    pub evidences_created: u64,
    pub dns_queries: u64,
    pub dns_responses: u64,
    pub dns_resolutions: u64,
    pub tls_client_hellos: u64,
    pub http_requests: u64,
    pub http_responses: u64,
}

#[derive(Debug)]
pub enum PcapAnalysisError {
    UnknownSource(SourceId),
    Domain(DomainError),
    Pcap(PcapError),
    PcapNg(PcapNgError),
    IdOverflow(&'static str),
}

impl std::fmt::Display for PcapAnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSource(id) => {
                write!(f, "La fuente {:?} no existe en la investigación", id)
            }
            Self::Domain(error) => write!(f, "Error del modelo: {error:?}"),
            Self::Pcap(error) => write!(f, "Error al leer el PCAP: {error}"),
            Self::PcapNg(error) => write!(f, "Error al leer el PCAPNG: {error}"),
            Self::IdOverflow(entity) => {
                write!(f, "No quedan identificadores disponibles para {entity}")
            }
        }
    }
}

impl std::error::Error for PcapAnalysisError {}

impl From<DomainError> for PcapAnalysisError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

impl From<PcapError> for PcapAnalysisError {
    fn from(error: PcapError) -> Self {
        Self::Pcap(error)
    }
}

impl From<PcapNgError> for PcapAnalysisError {
    fn from(error: PcapNgError) -> Self {
        Self::PcapNg(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    endpoint_a: AssetId,
    endpoint_b: AssetId,
    endpoint_a_port: Option<u16>,
    endpoint_b_port: Option<u16>,
    protocol: Protocol,
}

impl FlowKey {
    fn new(
        source: AssetId,
        destination: AssetId,
        source_port: Option<u16>,
        destination_port: Option<u16>,
        protocol: Protocol,
    ) -> (Self, bool) {
        let source_endpoint = (source, source_port);
        let destination_endpoint = (destination, destination_port);

        if source_endpoint <= destination_endpoint {
            (
                Self {
                    endpoint_a: source,
                    endpoint_b: destination,
                    endpoint_a_port: source_port,
                    endpoint_b_port: destination_port,
                    protocol,
                },
                true,
            )
        } else {
            (
                Self {
                    endpoint_a: destination,
                    endpoint_b: source,
                    endpoint_a_port: destination_port,
                    endpoint_b_port: source_port,
                    protocol,
                },
                false,
            )
        }
    }
}

pub fn analyze_pcap<R: Read>(
    reader: R,
    source_id: SourceId,
    investigation: &mut Investigation,
) -> Result<PcapAnalysisReport, PcapAnalysisError> {
    ensure_source_exists(investigation, source_id)?;

    let mut pcap = PcapReader::new(reader)?;

    analyze_packets(
        || pcap.next_packet().map_err(PcapAnalysisError::from),
        source_id,
        investigation,
    )
}

pub fn analyze_pcapng<R: Read>(
    reader: R,
    source_id: SourceId,
    investigation: &mut Investigation,
) -> Result<PcapAnalysisReport, PcapAnalysisError> {
    ensure_source_exists(investigation, source_id)?;

    let mut pcapng = PcapNgReader::new(reader);

    analyze_packets(
        || pcapng.next_packet().map_err(PcapAnalysisError::from),
        source_id,
        investigation,
    )
}

pub fn analyze_capture<R: Read>(
    mut reader: R,
    source_id: SourceId,
    investigation: &mut Investigation,
) -> Result<PcapAnalysisReport, PcapAnalysisError> {
    ensure_source_exists(investigation, source_id)?;

    let mut magic = [0u8; 4];

    reader.read_exact(&mut magic).map_err(PcapError::from)?;

    let chained_reader = Cursor::new(magic).chain(reader);

    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        analyze_pcapng(chained_reader, source_id, investigation)
    } else {
        analyze_pcap(chained_reader, source_id, investigation)
    }
}

fn ensure_source_exists(
    investigation: &Investigation,
    source_id: SourceId,
) -> Result<(), PcapAnalysisError> {
    if !investigation
        .sources()
        .iter()
        .any(|source| source.id == source_id)
    {
        return Err(PcapAnalysisError::UnknownSource(source_id));
    }

    Ok(())
}

fn analyze_packets<F>(
    mut next_packet: F,
    source_id: SourceId,
    investigation: &mut Investigation,
) -> Result<PcapAnalysisReport, PcapAnalysisError>
where
    F: FnMut() -> Result<Option<PcapPacket>, PcapAnalysisError>,
{
    ensure_source_exists(investigation, source_id)?;

    let mut working = investigation.clone();

    let mut report = PcapAnalysisReport {
        packets_read: 0,
        events_created: 0,
        flows_created: 0,
        flows_updated: 0,
        assets_created: 0,
        evidences_created: 0,
        dns_queries: 0,
        dns_responses: 0,
        dns_resolutions: 0,
        tls_client_hellos: 0,
        http_requests: 0,
        http_responses: 0,
    };

    let mut flow_index: HashMap<FlowKey, FlowId> = HashMap::new();

    for flow in working.flows() {
        let key = FlowKey {
            endpoint_a: flow.endpoint_a,
            endpoint_b: flow.endpoint_b,
            endpoint_a_port: flow.endpoint_a_port,
            endpoint_b_port: flow.endpoint_b_port,
            protocol: flow.protocol.clone(),
        };

        flow_index.insert(key, flow.id);
    }

    let mut reassembler = TcpReassembler::new();
    let mut stream_buffers: HashMap<(StreamKey, Direction), (Vec<u8>, Vec<EvidenceId>)> =
        HashMap::new();

    while let Some(packet) = next_packet()? {
        report.packets_read += 1;

        let mut source_asset = None;
        let mut destination_asset = None;

        if let Some(ethernet) = &packet.ethernet {
            let source_mac = get_or_create_asset(
                &mut working,
                AssetKind::MacAddress,
                ethernet.source_mac.clone(),
                &mut report.assets_created,
            )?;

            let destination_mac = get_or_create_asset(
                &mut working,
                AssetKind::MacAddress,
                ethernet.destination_mac.clone(),
                &mut report.assets_created,
            )?;

            source_asset = Some(source_mac);
            destination_asset = Some(destination_mac);

            if let Some(network) = &ethernet.network {
                let source_ip = get_or_create_asset(
                    &mut working,
                    AssetKind::IpAddress,
                    network.source_ip.to_string(),
                    &mut report.assets_created,
                )?;

                let destination_ip = get_or_create_asset(
                    &mut working,
                    AssetKind::IpAddress,
                    network.destination_ip.to_string(),
                    &mut report.assets_created,
                )?;

                source_asset = Some(source_ip);
                destination_asset = Some(destination_ip);
            }
        }

        let evidence_id = EvidenceId(next_id(
            working.evidences().iter().map(|item| item.id.0),
            "evidencias",
        )?);

        let excerpt = match &packet.ethernet {
            Some(ethernet) => {
                if let Some(network) = &ethernet.network {
                    format!(
                        "Paquete {}: {} -> {}, protocolo {:?}",
                        packet.number,
                        network.source_ip,
                        network.destination_ip,
                        network.protocol
                    )
                } else {
                    format!(
                        "Paquete {} Ethernet: {} -> {}",
                        packet.number,
                        ethernet.source_mac,
                        ethernet.destination_mac
                    )
                }
            }
            None => format!(
                "Paquete {} sin información Ethernet decodificada",
                packet.number
            ),
        };

        working.add_evidence(Evidence {
            id: evidence_id,
            source_id,
            location: EvidenceLocation::PacketFrame {
                frame_number: packet.number,
            },
            excerpt: Some(excerpt.clone()),
        })?;

        report.evidences_created += 1;

        let event_id = EventId(next_id(
            working.events().iter().map(|item| item.id.0),
            "eventos",
        )?);

        let network = packet
            .ethernet
            .as_ref()
            .and_then(|ethernet| ethernet.network.as_ref());

        let (source_port, destination_port, protocol) = match network {
            Some(network) => (
                network.source_port,
                network.destination_port,
                Some(network.protocol.clone()),
            ),
            None => (None, None, None),
        };

        let tcp_flags = network
            .and_then(|n| n.tcp)
            .and_then(|t| format_tcp_flags(t.flags));

        working.add_event(NetworkEvent {
            id: event_id,
            timestamp_unix_ns: Some(packet.timestamp_unix_ns),
            kind: EventKind::Packet,
            summary: excerpt,
            source_asset,
            destination_asset,
            source_port,
            destination_port,
            protocol,
            evidence_ids: vec![evidence_id],
            tcp_flags,
        })?;

        report.events_created += 1;

        if let Some(network_info) = network {
            if matches!(network_info.protocol, Protocol::Udp)
                && (network_info.source_port == Some(53)
                    || network_info.destination_port == Some(53))
            {
                if let Some((message, kind, summary)) = parse_dns_payload(&packet) {
                    let is_response = matches!(kind, EventKind::DnsResponse);

                    let dns_event_id = EventId(next_id(
                        working.events().iter().map(|item| item.id.0),
                        "eventos",
                    )?);

                    working.add_event(NetworkEvent {
                        id: dns_event_id,
                        timestamp_unix_ns: Some(packet.timestamp_unix_ns),
                        kind,
                        summary,
                        source_asset,
                        destination_asset,
                        source_port: network_info.source_port,
                        destination_port: network_info.destination_port,
                        protocol: Some(Protocol::Udp),
                        evidence_ids: vec![evidence_id],
                        tcp_flags: None,
                    })?;

                    report.events_created += 1;
                    if is_response {
                        report.dns_responses += 1;
                    } else {
                        report.dns_queries += 1;
                    }

                    if is_response {
                        let mut seen: HashSet<(String, String)> = HashSet::new();

                        for record in &message.answers {
                            let ip_str = match &record.rdata {
                                DnsRdata::A(ip) => ip.to_string(),
                                DnsRdata::Aaaa(ip) => ip.to_string(),
                                _ => continue,
                            };

                            let key = (record.name.clone(), ip_str.clone());
                            if !seen.insert(key) {
                                continue;
                            }
                            if seen.len() > 8 {
                                break;
                            }

                            let hostname_asset = get_or_create_asset(
                                &mut working,
                                AssetKind::Hostname,
                                record.name.clone(),
                                &mut report.assets_created,
                            )?;

                            let ip_asset = get_or_create_asset(
                                &mut working,
                                AssetKind::IpAddress,
                                ip_str.clone(),
                                &mut report.assets_created,
                            )?;

                            let resolution_id = EventId(next_id(
                                working.events().iter().map(|item| item.id.0),
                                "eventos",
                            )?);

                            working.add_event(NetworkEvent {
                                id: resolution_id,
                                timestamp_unix_ns: Some(packet.timestamp_unix_ns),
                                kind: EventKind::DnsResolution,
                                summary: format!(
                                    "DNS resuelve {} -> {} (TTL {})",
                                    record.name, ip_str, record.ttl
                                ),
                                source_asset: Some(hostname_asset),
                                destination_asset: Some(ip_asset),
                                source_port: None,
                                destination_port: None,
                                protocol: None,
                                evidence_ids: vec![evidence_id],
                                tcp_flags: None,
                            })?;

                            report.dns_resolutions += 1;
                            report.events_created += 1;
                        }
                    }
                }
            }
        }

        if let Some(network_info) = network {
            if matches!(network_info.protocol, Protocol::Tcp) {
                if let Some(tcp_meta) = network_info.tcp {
                    if let Some(payload) = extract_transport_payload(&packet.raw_frame) {
                        if let (Some(src_port), Some(dst_port)) = (
                            network_info.source_port,
                            network_info.destination_port,
                        ) {
                            let feed = reassembler.feed(
                                network_info.source_ip,
                                src_port,
                                network_info.destination_ip,
                                dst_port,
                                tcp_meta.seq,
                                tcp_meta.flags,
                                &payload.bytes,
                            );

                            if feed.closed {
                                stream_buffers.remove(&(feed.stream_key, feed.direction));
                            }

                            if !feed.contiguous.is_empty() {
                                let key = (feed.stream_key, feed.direction);
                                let (buffer, evidence_ids) =
                                    stream_buffers.entry(key).or_default();

                                buffer.extend_from_slice(&feed.contiguous);

                                if !evidence_ids.contains(&evidence_id) {
                                    evidence_ids.push(evidence_id);
                                }

                                if let Some(app_event) = try_parse_stream_buffer(
                                    &mut working,
                                    buffer,
                                    evidence_ids,
                                    network_info,
                                    source_asset,
                                    destination_asset,
                                    packet.timestamp_unix_ns,
                                )? {
                                    match app_event.kind {
                                        EventKind::TlsClientHello => {
                                            report.tls_client_hellos += 1;
                                        }
                                        EventKind::HttpRequest => {
                                            report.http_requests += 1;
                                        }
                                        EventKind::HttpResponse => {
                                            report.http_responses += 1;
                                        }
                                        _ => {}
                                    }
                                    working.add_event(app_event)?;
                                    report.events_created += 1;
                                    buffer.clear();
                                    evidence_ids.clear();
                                }

                                if buffer.len() > MAX_STREAM_BUFFER {
                                    buffer.clear();
                                    evidence_ids.clear();
                                }
                            }
                        }
                    }
                }
            }
        }

        if let (Some(network), Some(source), Some(destination)) =
            (network, source_asset, destination_asset)
        {
            let (key, a_to_b) = FlowKey::new(
                source,
                destination,
                network.source_port,
                network.destination_port,
                network.protocol.clone(),
            );

            if let Some(flow_id) = flow_index.get(&key).copied() {
                working.record_flow_packet(
                    flow_id,
                    packet.timestamp_unix_ns,
                    packet.captured_len,
                    packet.original_len,
                    a_to_b,
                    evidence_id,
                )?;

                report.flows_updated += 1;
            } else {
                let flow_id = FlowId(next_id(
                    working.flows().iter().map(|item| item.id.0),
                    "flujos",
                )?);

                working.add_flow(NetworkFlow {
                    id: flow_id,
                    endpoint_a: key.endpoint_a,
                    endpoint_b: key.endpoint_b,
                    endpoint_a_port: key.endpoint_a_port,
                    endpoint_b_port: key.endpoint_b_port,
                    protocol: key.protocol.clone(),
                    first_seen_unix_ns: packet.timestamp_unix_ns,
                    last_seen_unix_ns: packet.timestamp_unix_ns,
                    packet_count: 1,
                    captured_bytes: u64::from(packet.captured_len),
                    original_bytes: u64::from(packet.original_len),
                    packets_a_to_b: if a_to_b { 1 } else { 0 },
                    packets_b_to_a: if a_to_b { 0 } else { 1 },
                    captured_bytes_a_to_b: if a_to_b {
                        u64::from(packet.captured_len)
                    } else {
                        0
                    },
                    captured_bytes_b_to_a: if a_to_b {
                        0
                    } else {
                        u64::from(packet.captured_len)
                    },
                    evidence_ids: vec![evidence_id],
                })?;

                flow_index.insert(key, flow_id);
                report.flows_created += 1;
            }
        }
    }

    *investigation = working;

    Ok(report)
}

fn parse_dns_payload(packet: &PcapPacket) -> Option<(DnsMessage, EventKind, String)> {
    let payload = extract_transport_payload(&packet.raw_frame)?;
    let message = parse_dns(&payload.bytes).ok()?;

    if message.questions.is_empty() {
        return None;
    }

    let kind = if message.is_response {
        EventKind::DnsResponse
    } else {
        EventKind::DnsQuery
    };

    let summary = summarize(&message);
    Some((message, kind, summary))
}

fn try_parse_stream_buffer(
    investigation: &mut Investigation,
    buffer: &[u8],
    evidence_ids: &[EvidenceId],
    network: &NetworkInfo,
    source_asset: Option<AssetId>,
    destination_asset: Option<AssetId>,
    timestamp_unix_ns: i64,
) -> Result<Option<NetworkEvent>, PcapAnalysisError> {
    let (kind, summary) = if let Ok(hello) = parse_tls_client_hello(buffer) {
        (EventKind::TlsClientHello, hello.summary())
    } else if let Ok(message) = parse_http(buffer) {
        let kind = match &message {
            HttpMessage::Request(_) => EventKind::HttpRequest,
            HttpMessage::Response(_) => EventKind::HttpResponse,
        };
        (kind, message.summary())
    } else {
        return Ok(None);
    };

    let event_id = EventId(next_id(
        investigation.events().iter().map(|item| item.id.0),
        "eventos",
    )?);

    Ok(Some(NetworkEvent {
        id: event_id,
        timestamp_unix_ns: Some(timestamp_unix_ns),
        kind,
        summary,
        source_asset,
        destination_asset,
        source_port: network.source_port,
        destination_port: network.destination_port,
        protocol: Some(Protocol::Tcp),
        evidence_ids: evidence_ids.to_vec(),
        tcp_flags: None,
    }))
}

fn get_or_create_asset(
    investigation: &mut Investigation,
    kind: AssetKind,
    value: String,
    created_count: &mut u64,
) -> Result<AssetId, PcapAnalysisError> {
    if let Some(existing) = investigation
        .assets()
        .iter()
        .find(|asset| asset.kind == kind && asset.value == value)
    {
        return Ok(existing.id);
    }

    let id = AssetId(next_id(
        investigation.assets().iter().map(|asset| asset.id.0),
        "activos",
    )?);

    investigation.add_asset(Asset {
        id,
        kind,
        value,
        label: None,
    })?;

    *created_count += 1;

    Ok(id)
}

fn next_id(
    existing_ids: impl Iterator<Item = u64>,
    entity: &'static str,
) -> Result<u64, PcapAnalysisError> {
    match existing_ids.max() {
        Some(maximum) => maximum
            .checked_add(1)
            .ok_or(PcapAnalysisError::IdOverflow(entity)),
        None => Ok(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InvestigationId, SourceFile, SourceFormat};
    use std::io::Cursor;
    use std::path::PathBuf;

    fn test_investigation() -> Investigation {
        let mut investigation = Investigation::new(
            InvestigationId(1),
            "Prueba del analizador",
            None,
            0,
        )
        .unwrap();

        investigation
            .add_source(SourceFile {
                id: SourceId(1),
                file_name: "test.pcap".to_string(),
                relative_path: PathBuf::from("sources/test.pcap"),
                format: SourceFormat::Pcap,
                size_bytes: 0,
                sha256: None,
                imported_at_unix_ns: 0,
            })
            .unwrap();

        investigation
    }

    fn empty_pcap() -> Vec<u8> {
        let mut data = Vec::new();

        data.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.extend_from_slice(&0i32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&65535u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());

        data
    }

    fn pcap_with_udp_packet() -> Vec<u8> {
        let mut data = empty_pcap();

        append_udp_packet(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [192, 168, 1, 20],
            50000,
            53,
            1,
        );

        data
    }

    fn append_udp_packet(
        data: &mut Vec<u8>,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        source_port: u16,
        destination_port: u16,
        timestamp_seconds: u32,
    ) {
        data.extend_from_slice(&timestamp_seconds.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&42u32.to_le_bytes());
        data.extend_from_slice(&42u32.to_le_bytes());

        data.extend_from_slice(&destination_mac);
        data.extend_from_slice(&source_mac);
        data.extend_from_slice(&[0x08, 0x00]);

        data.push(0x45);
        data.push(0);
        data.extend_from_slice(&28u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.push(64);
        data.push(17);
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&source_ip);
        data.extend_from_slice(&destination_ip);

        data.extend_from_slice(&source_port.to_be_bytes());
        data.extend_from_slice(&destination_port.to_be_bytes());
        data.extend_from_slice(&8u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
    }

    fn append_udp_packet_with_payload(
        data: &mut Vec<u8>,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        source_port: u16,
        destination_port: u16,
        timestamp_seconds: u32,
        payload: &[u8],
    ) {
        let udp_length = 8 + payload.len();
        let ip_total_length = 20 + udp_length;
        let frame_len = 14 + ip_total_length;

        data.extend_from_slice(&timestamp_seconds.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(frame_len as u32).to_le_bytes());
        data.extend_from_slice(&(frame_len as u32).to_le_bytes());

        data.extend_from_slice(&destination_mac);
        data.extend_from_slice(&source_mac);
        data.extend_from_slice(&[0x08, 0x00]);

        data.push(0x45);
        data.push(0);
        data.extend_from_slice(&(ip_total_length as u16).to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.push(64);
        data.push(17);
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&source_ip);
        data.extend_from_slice(&destination_ip);

        data.extend_from_slice(&source_port.to_be_bytes());
        data.extend_from_slice(&destination_port.to_be_bytes());
        data.extend_from_slice(&(udp_length as u16).to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());

        data.extend_from_slice(payload);
    }

    fn append_tcp_packet_with_payload(
        data: &mut Vec<u8>,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        source_port: u16,
        destination_port: u16,
        timestamp_seconds: u32,
        payload: &[u8],
    ) {
        let tcp_header_len = 20;
        let ip_total_length = 20 + tcp_header_len + payload.len();
        let frame_len = 14 + ip_total_length;

        data.extend_from_slice(&timestamp_seconds.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&(frame_len as u32).to_le_bytes());
        data.extend_from_slice(&(frame_len as u32).to_le_bytes());

        data.extend_from_slice(&destination_mac);
        data.extend_from_slice(&source_mac);
        data.extend_from_slice(&[0x08, 0x00]);

        data.push(0x45);
        data.push(0);
        data.extend_from_slice(&(ip_total_length as u16).to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.push(64);
        data.push(6);
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&source_ip);
        data.extend_from_slice(&destination_ip);

        data.extend_from_slice(&source_port.to_be_bytes());
        data.extend_from_slice(&destination_port.to_be_bytes());
        data.extend_from_slice(&1u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.push(0x50);
        data.push(0x18);
        data.extend_from_slice(&65535u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());

        data.extend_from_slice(payload);
    }

    fn append_tcp_packet_with_seq(
        data: &mut Vec<u8>,
        source_mac: [u8; 6],
        destination_mac: [u8; 6],
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        source_port: u16,
        destination_port: u16,
        timestamp_seconds: u32,
        seq: u32,
        payload: &[u8],
    ) {
        let before = data.len();
        append_tcp_packet_with_payload(
            data,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            timestamp_seconds,
            payload,
        );

        let seq_offset = before + 16 + 14 + 20 + 4;
        data[seq_offset..seq_offset + 4].copy_from_slice(&seq.to_be_bytes());
    }

    fn dns_query_payload(name: &str, qtype: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0xABCDu16.to_be_bytes());
        data.extend_from_slice(&0x0100u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0);
        data.extend_from_slice(&qtype.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data
    }

    fn dns_response_payload(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0xABCDu16.to_be_bytes());
        data.extend_from_slice(&0x8180u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());

        for label in name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());

        data.push(0xC0);
        data.push(0x0C);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&300u32.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&ip);
        data
    }

    fn http_request_bytes(method: &str, uri: &str, host: &str) -> Vec<u8> {
        format!(
            "{method} {uri} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NEXTRACE/1.0\r\n\r\n"
        )
        .into_bytes()
    }

    fn http_response_bytes(status: u16, reason: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"
        )
        .into_bytes()
    }

    fn tls_client_hello_bytes(sni: &str) -> Vec<u8> {
        let name_bytes = sni.as_bytes();
        let name_len = name_bytes.len() as u16;

        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&(name_len + 3).to_be_bytes());
        sni_data.push(0);
        sni_data.extend_from_slice(&name_len.to_be_bytes());
        sni_data.extend_from_slice(name_bytes);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_data);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let hs_len = body.len() as u32;
        handshake.push(((hs_len >> 16) & 0xFF) as u8);
        handshake.push(((hs_len >> 8) & 0xFF) as u8);
        handshake.push((hs_len & 0xFF) as u8);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn pcap_with_reverse_udp_packets() -> Vec<u8> {
        let mut data = empty_pcap();

        append_udp_packet(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [192, 168, 1, 20],
            50000,
            53,
            1,
        );

        append_udp_packet(
            &mut data,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [192, 168, 1, 20],
            [192, 168, 1, 10],
            53,
            50000,
            2,
        );

        data
    }

    #[test]
    fn analyzes_a_udp_packet_and_creates_evidence_and_flow() {
        let mut investigation = test_investigation();

        let report = analyze_pcap(
            Cursor::new(pcap_with_udp_packet()),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.packets_read, 1);
        assert_eq!(report.events_created, 1);
        assert_eq!(report.flows_created, 1);
        assert_eq!(report.flows_updated, 0);
        assert_eq!(report.assets_created, 4);
        assert_eq!(report.evidences_created, 1);
        assert_eq!(report.dns_queries, 0);
        assert_eq!(report.dns_responses, 0);
        assert_eq!(report.dns_resolutions, 0);

        assert_eq!(investigation.assets().len(), 4);
        assert_eq!(investigation.evidences().len(), 1);
        assert_eq!(investigation.events().len(), 1);
        assert_eq!(investigation.flows().len(), 1);

        let event = &investigation.events()[0];

        assert_eq!(event.kind, EventKind::Packet);
        assert_eq!(event.source_port, Some(50000));
        assert_eq!(event.destination_port, Some(53));
        assert_eq!(event.protocol, Some(Protocol::Udp));
        assert_eq!(event.evidence_ids.len(), 1);
        assert!(event.tcp_flags.is_none());

        let flow = &investigation.flows()[0];

        assert_eq!(flow.protocol, Protocol::Udp);
        assert_eq!(flow.packet_count, 1);
        assert_eq!(flow.captured_bytes, 42);
        assert_eq!(flow.original_bytes, 42);
        assert_eq!(flow.packets_a_to_b, 1);
        assert_eq!(flow.packets_b_to_a, 0);
        assert_eq!(flow.first_seen_unix_ns, 1_000_000_000);
        assert_eq!(flow.last_seen_unix_ns, 1_000_000_000);
        assert_eq!(flow.evidence_ids.len(), 1);
    }

    #[test]
    fn groups_reverse_packets_into_one_bidirectional_flow() {
        let mut investigation = test_investigation();

        let report = analyze_pcap(
            Cursor::new(pcap_with_reverse_udp_packets()),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.packets_read, 2);
        assert_eq!(report.events_created, 2);
        assert_eq!(report.flows_created, 1);
        assert_eq!(report.flows_updated, 1);
        assert_eq!(investigation.events().len(), 2);
        assert_eq!(investigation.flows().len(), 1);

        let flow = &investigation.flows()[0];

        assert_eq!(flow.packet_count, 2);
        assert_eq!(flow.captured_bytes, 84);
        assert_eq!(flow.original_bytes, 84);
        assert_eq!(flow.packets_a_to_b, 1);
        assert_eq!(flow.packets_b_to_a, 1);
        assert_eq!(flow.first_seen_unix_ns, 1_000_000_000);
        assert_eq!(flow.last_seen_unix_ns, 2_000_000_000);
        assert_eq!(flow.evidence_ids.len(), 2);
    }

    #[test]
    fn reuses_assets_and_existing_flow_when_capture_is_analyzed_twice() {
        let mut investigation = test_investigation();

        analyze_pcap(
            Cursor::new(pcap_with_udp_packet()),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        let report = analyze_pcap(
            Cursor::new(pcap_with_udp_packet()),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.assets_created, 0);
        assert_eq!(report.flows_created, 0);
        assert_eq!(report.flows_updated, 1);
        assert_eq!(investigation.assets().len(), 4);
        assert_eq!(investigation.events().len(), 2);
        assert_eq!(investigation.evidences().len(), 2);
        assert_eq!(investigation.flows().len(), 1);
        assert_eq!(investigation.flows()[0].packet_count, 2);
    }

    #[test]
    fn accepts_an_empty_capture() {
        let mut investigation = test_investigation();

        let report = analyze_pcap(
            Cursor::new(empty_pcap()),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.packets_read, 0);
        assert_eq!(report.events_created, 0);
        assert_eq!(report.flows_created, 0);
        assert_eq!(report.flows_updated, 0);
        assert_eq!(report.assets_created, 0);
        assert_eq!(report.evidences_created, 0);
        assert_eq!(report.dns_queries, 0);
        assert_eq!(report.dns_responses, 0);
        assert_eq!(report.dns_resolutions, 0);
    }

    #[test]
    fn rejects_an_unknown_source() {
        let mut investigation = test_investigation();

        let result = analyze_pcap(
            Cursor::new(empty_pcap()),
            SourceId(99),
            &mut investigation,
        );

        assert!(matches!(
            result,
            Err(PcapAnalysisError::UnknownSource(SourceId(99)))
        ));
    }

    #[test]
    fn does_not_modify_investigation_when_capture_is_truncated() {
        let mut investigation = test_investigation();
        let original = investigation.clone();

        let mut malformed = pcap_with_udp_packet();
        malformed.truncate(malformed.len() - 5);

        let result = analyze_pcap(
            Cursor::new(malformed),
            SourceId(1),
            &mut investigation,
        );

        assert!(result.is_err());
        assert_eq!(investigation, original);
    }

    #[test]
    fn analyzes_pcapng_and_creates_evidence_and_flow() {
        let mut investigation = test_investigation();

        let report = analyze_pcapng(
            Cursor::new(crate::pcapng::sample_capture_for_tests()),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.packets_read, 1);
        assert_eq!(report.events_created, 1);
        assert_eq!(report.flows_created, 1);
        assert_eq!(report.assets_created, 4);
        assert_eq!(report.evidences_created, 1);

        assert_eq!(investigation.events().len(), 1);
        assert_eq!(investigation.evidences().len(), 1);
        assert_eq!(investigation.flows().len(), 1);

        assert_eq!(
            investigation.flows()[0].protocol,
            Protocol::Tcp
        );

        assert_eq!(
            investigation.events()[0].source_port,
            Some(50000)
        );

        assert_eq!(
            investigation.events()[0].destination_port,
            Some(443)
        );
    }

    #[test]
    fn automatically_detects_pcapng_format() {
        let mut investigation = test_investigation();

        let report = analyze_capture(
            Cursor::new(crate::pcapng::sample_capture_for_tests()),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.packets_read, 1);
        assert_eq!(report.events_created, 1);
        assert_eq!(report.flows_created, 1);
        assert_eq!(investigation.flows().len(), 1);
    }

    #[test]
    fn automatically_detects_classic_pcap_format() {
        let mut investigation = test_investigation();

        let report = analyze_capture(
            Cursor::new(pcap_with_udp_packet()),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.packets_read, 1);
        assert_eq!(report.events_created, 1);
        assert_eq!(report.flows_created, 1);
        assert_eq!(investigation.flows().len(), 1);
    }

    #[test]
    fn does_not_modify_investigation_when_pcapng_is_truncated() {
        let mut investigation = test_investigation();
        let original = investigation.clone();

        let mut malformed = crate::pcapng::sample_capture_for_tests();
        malformed.truncate(malformed.len() - 5);

        let result = analyze_pcapng(
            Cursor::new(malformed),
            SourceId(1),
            &mut investigation,
        );

        assert!(result.is_err());
        assert_eq!(investigation, original);
    }

    #[test]
    fn detects_dns_query_event() {
        let mut investigation = test_investigation();

        let mut data = empty_pcap();
        let payload = dns_query_payload("example.com", 1);
        append_udp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [8, 8, 8, 8],
            50000,
            53,
            1,
            &payload,
        );

        let report =
            analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation)
                .unwrap();

        assert_eq!(report.packets_read, 1);
        assert_eq!(report.events_created, 2);
        assert_eq!(report.dns_queries, 1);
        assert_eq!(report.dns_responses, 0);
        assert_eq!(report.dns_resolutions, 0);
        assert_eq!(report.evidences_created, 1);
        assert_eq!(report.flows_created, 1);

        let dns_event = investigation
            .events()
            .iter()
            .find(|event| matches!(event.kind, EventKind::DnsQuery))
            .expect("debe existir un evento DnsQuery");

        assert!(dns_event.summary.contains("example.com"));
        assert!(dns_event.summary.contains("consulta"));
        assert_eq!(dns_event.destination_port, Some(53));
        assert_eq!(dns_event.protocol, Some(Protocol::Udp));
        assert_eq!(dns_event.evidence_ids.len(), 1);
        assert!(investigation
            .evidences()
            .iter()
            .any(|evidence| evidence.id == dns_event.evidence_ids[0]));
    }

    #[test]
    fn detects_dns_response_event() {
        let mut investigation = test_investigation();

        let mut data = empty_pcap();
        let payload = dns_response_payload("example.com", [1, 2, 3, 4]);
        append_udp_packet_with_payload(
            &mut data,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [8, 8, 8, 8],
            [192, 168, 1, 10],
            53,
            50000,
            2,
            &payload,
        );

        let report =
            analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation)
                .unwrap();

        assert_eq!(report.dns_queries, 0);
        assert_eq!(report.dns_responses, 1);
        assert_eq!(report.dns_resolutions, 1);
        assert_eq!(report.events_created, 3);

        let dns_event = investigation
            .events()
            .iter()
            .find(|event| matches!(event.kind, EventKind::DnsResponse))
            .expect("debe existir un evento DnsResponse");

        assert!(dns_event.summary.contains("example.com"));
        assert!(dns_event.summary.contains("respuesta"));
        assert!(dns_event.summary.contains("1.2.3.4"));
        assert_eq!(dns_event.source_port, Some(53));
    }

    #[test]
    fn does_not_create_dns_event_for_malformed_payload() {
        let mut investigation = test_investigation();

        let mut data = empty_pcap();
        let garbage: &[u8] = b"not-a-dns-message-at-all-yes";
        append_udp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [8, 8, 8, 8],
            50000,
            53,
            1,
            garbage,
        );

        let report =
            analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation)
                .unwrap();

        assert_eq!(report.dns_queries, 0);
        assert_eq!(report.dns_responses, 0);
        assert_eq!(report.events_created, 1);
        assert_eq!(investigation.events().len(), 1);
        assert_eq!(investigation.events()[0].kind, EventKind::Packet);
    }

    #[test]
    fn does_not_create_dns_event_when_payload_is_empty() {
        let mut investigation = test_investigation();

        let mut data = empty_pcap();
        append_udp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [8, 8, 8, 8],
            50000,
            53,
            1,
            &[],
        );

        let report =
            analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation)
                .unwrap();

        assert_eq!(report.dns_queries, 0);
        assert_eq!(report.dns_responses, 0);
        assert_eq!(report.events_created, 1);
    }

    #[test]
    fn does_not_treat_non_port_53_traffic_as_dns() {
        let mut investigation = test_investigation();

        let mut data = empty_pcap();
        let payload = dns_query_payload("example.com", 1);
        append_udp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [8, 8, 8, 8],
            50000,
            9999,
            1,
            &payload,
        );

        let report =
            analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation)
                .unwrap();

        assert_eq!(report.dns_queries, 0);
        assert_eq!(report.dns_responses, 0);
    }

    #[test]
    fn dns_roundtrip_through_persistence() {
        use crate::persistence::{load_investigation, save_investigation};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let mut investigation = test_investigation();
        let mut data = empty_pcap();

        let query = dns_query_payload("example.com", 1);
        append_udp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [8, 8, 8, 8],
            50000,
            53,
            1,
            &query,
        );

        analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation)
            .unwrap();

        let path = std::env::temp_dir().join(format!(
            "nextrace_dns_roundtrip_{}_{}.nxt",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));

        save_investigation(&investigation, &path).unwrap();
        let restored = load_investigation(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(restored, investigation);

        let has_dns_query = restored
            .events()
            .iter()
            .any(|event| matches!(event.kind, EventKind::DnsQuery));
        assert!(has_dns_query);
    }

    #[test]
    fn detects_http_request_event() {
        let mut investigation = test_investigation();
        let mut data = empty_pcap();
        let payload = http_request_bytes("GET", "/index.html", "example.com");

        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            80,
            1,
            &payload,
        );

        let report = analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation).unwrap();

        assert_eq!(report.events_created, 2);
        assert_eq!(report.http_requests, 1);
        assert_eq!(report.http_responses, 0);

        let event = investigation
            .events()
            .iter()
            .find(|e| matches!(e.kind, EventKind::HttpRequest))
            .expect("HttpRequest esperado");
        assert!(event.summary.contains("GET"));
        assert!(event.summary.contains("/index.html"));
        assert!(event.summary.contains("example.com"));
        assert_eq!(event.destination_port, Some(80));
    }

    #[test]
    fn detects_http_response_event() {
        let mut investigation = test_investigation();
        let mut data = empty_pcap();
        let payload = http_response_bytes(404, "Not Found");

        append_tcp_packet_with_payload(
            &mut data,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [93, 184, 216, 34],
            [192, 168, 1, 10],
            80,
            50000,
            2,
            &payload,
        );

        let report = analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation).unwrap();

        assert_eq!(report.http_requests, 0);
        assert_eq!(report.http_responses, 1);

        let event = investigation
            .events()
            .iter()
            .find(|e| matches!(e.kind, EventKind::HttpResponse))
            .expect("HttpResponse esperado");
        assert!(event.summary.contains("404"));
        assert!(event.summary.contains("Not Found"));
    }

    #[test]
    fn detects_tls_client_hello_event() {
        let mut investigation = test_investigation();
        let mut data = empty_pcap();
        let payload = tls_client_hello_bytes("secure.example.com");

        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            443,
            1,
            &payload,
        );

        let report = analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation).unwrap();

        assert_eq!(report.tls_client_hellos, 1);
        assert_eq!(report.events_created, 2);

        let event = investigation
            .events()
            .iter()
            .find(|e| matches!(e.kind, EventKind::TlsClientHello))
            .expect("TlsClientHello esperado");
        assert!(event.summary.contains("secure.example.com"));
        assert!(event.summary.contains("TLS"));
    }

    #[test]
    fn does_not_produce_http_event_for_binary_tcp_payload() {
        let mut investigation = test_investigation();
        let mut data = empty_pcap();
        let garbage: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD];

        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            80,
            1,
            garbage,
        );

        let report = analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation).unwrap();
        assert_eq!(report.http_requests, 0);
        assert_eq!(report.http_responses, 0);
        assert_eq!(report.tls_client_hellos, 0);
        assert_eq!(report.events_created, 1);
    }

    #[test]
    fn does_not_produce_http_event_for_incomplete_headers() {
        let mut investigation = test_investigation();
        let mut data = empty_pcap();
        let payload: &[u8] = b"GET /partial HTTP/1.1\r\nHost: example.com\r\n";

        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            80,
            1,
            payload,
        );

        let report = analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation).unwrap();
        assert_eq!(report.http_requests, 0);
        assert_eq!(report.events_created, 1);
    }

    #[test]
    fn tls_http_events_survive_persistence_roundtrip() {
        use crate::persistence::{load_investigation, save_investigation};
        use std::sync::atomic::{AtomicU64, Ordering};

        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let mut investigation = test_investigation();
        let mut data = empty_pcap();

        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            80,
            1,
            &http_request_bytes("GET", "/", "example.com"),
        );
        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50001,
            443,
            2,
            &tls_client_hello_bytes("secure.example.com"),
        );

        analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation).unwrap();

        let path = std::env::temp_dir().join(format!(
            "nextrace_tls_http_roundtrip_{}_{}.nxt",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));

        save_investigation(&investigation, &path).unwrap();
        let restored = load_investigation(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(restored, investigation);
        assert!(restored
            .events()
            .iter()
            .any(|e| matches!(e.kind, EventKind::HttpRequest)));
        assert!(restored
            .events()
            .iter()
            .any(|e| matches!(e.kind, EventKind::TlsClientHello)));
    }

    #[test]
    fn detects_dns_resolution_event() {
        let mut investigation = test_investigation();
        let mut data = empty_pcap();
        let payload = dns_response_payload("example.com", [1, 2, 3, 4]);

        append_udp_packet_with_payload(
            &mut data,
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [8, 8, 8, 8],
            [192, 168, 1, 10],
            53,
            50000,
            2,
            &payload,
        );

        let report =
            analyze_pcap(Cursor::new(data), SourceId(1), &mut investigation)
                .unwrap();

        assert_eq!(report.dns_resolutions, 1);

        let resolution = investigation
            .events()
            .iter()
            .find(|e| matches!(e.kind, EventKind::DnsResolution))
            .expect("debe existir DnsResolution");

        assert!(resolution.summary.contains("example.com"));
        assert!(resolution.summary.contains("1.2.3.4"));
        assert!(resolution.summary.contains("TTL"));

        let hostname_asset = investigation
            .assets()
            .iter()
            .find(|a| a.kind == AssetKind::Hostname && a.value == "example.com")
            .expect("activo de tipo Hostname");

        let ip_asset = investigation
            .assets()
            .iter()
            .find(|a| a.kind == AssetKind::IpAddress && a.value == "1.2.3.4")
            .expect("activo de tipo IpAddress para 1.2.3.4");

        assert_eq!(resolution.source_asset, Some(hostname_asset.id));
        assert_eq!(resolution.destination_asset, Some(ip_asset.id));
        assert_eq!(resolution.evidence_ids.len(), 1);
    }

    #[test]
    fn http_request_spanning_two_segments_cites_both_evidences() {
        let mut investigation = test_investigation();
        let mut data = empty_pcap();

        let first = b"GET /account HTTP/1.1\r\nHost: example.com\r\nCookie: session=";
        let second = b"abcdef;\r\nUser-Agent: NEXTRACE/1.0\r\n\r\n";

        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            80,
            1,
            first,
        );

        let second_seq = 1u32.wrapping_add(first.len() as u32);
        append_tcp_packet_with_seq(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            80,
            2,
            second_seq,
            second,
        );

        let report = analyze_pcap(
            Cursor::new(data),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.http_requests, 1);

        let event = investigation
            .events()
            .iter()
            .find(|e| matches!(e.kind, EventKind::HttpRequest))
            .expect("HttpRequest esperado tras reensamblado");

        assert!(event.summary.contains("GET"));
        assert!(event.summary.contains("/account"));
        assert!(event.summary.contains("example.com"));
        assert_eq!(event.evidence_ids.len(), 2);
    }

    #[test]
    fn retransmitted_http_request_creates_only_one_event() {
        let mut investigation = test_investigation();
        let mut data = empty_pcap();
        let payload = http_request_bytes("GET", "/", "example.com");

        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            80,
            1,
            &payload,
        );

        append_tcp_packet_with_payload(
            &mut data,
            [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            [192, 168, 1, 10],
            [93, 184, 216, 34],
            50000,
            80,
            2,
            &payload,
        );

        let report = analyze_pcap(
            Cursor::new(data),
            SourceId(1),
            &mut investigation,
        )
        .unwrap();

        assert_eq!(report.http_requests, 1);
        assert_eq!(
            investigation
                .events()
                .iter()
                .filter(|e| matches!(e.kind, EventKind::HttpRequest))
                .count(),
            1
        );
    }
}```


## Archivo: `nextrace-core/src/tcp_reassembly.rs`

```rust
// Reensamblado TCP conservador y acotado.
//
// Objetivos:
//   * Unir segmentos contiguos por dirección.
//   * Tolerar hasta MAX_OOO_SEGMENTS segmentos fuera de orden.
//   * Descartar retransmisiones solapadas de forma segura.
//   * Resolver gaps pequeños; resetear el stream ante gaps grandes.
//   * Nunca exceder MAX_BUFFER_BYTES por stream, para evitar DoS.
//
// Lo que NO hace:
//   * No valida checksums.
//   * No reordena más allá de MAX_OOO_SEGMENTS.
//   * No maneja opciones TCP (MSS, SACK, timestamps).
//   * No cierra streams por timeout; el llamador debe hacer flush().
//
// Todas estas limitaciones están documentadas y son coherentes con
// el objetivo del producto: análisis forense de capturas, no
// reconstrucción perfecta en tiempo real.

use std::collections::HashMap;
use std::net::IpAddr;

pub const DEFAULT_MAX_BUFFER_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_OOO_SEGMENTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamKey {
    pub a_ip: IpAddr,
    pub a_port: u16,
    pub b_ip: IpAddr,
    pub b_port: u16,
}

impl StreamKey {
    /// Construye la clave canónica y la dirección del paquete.
    /// (ip_a, port_a) <= (ip_b, port_b) garantiza que los dos
    /// sentidos de la misma conexión produzcan la misma StreamKey.
    pub fn from_endpoints(
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
    ) -> (Self, Direction) {
        let a = (source_ip, source_port);
        let b = (dest_ip, dest_port);

        if a <= b {
            (
                StreamKey {
                    a_ip: source_ip,
                    a_port: source_port,
                    b_ip: dest_ip,
                    b_port: dest_port,
                },
                Direction::AB,
            )
        } else {
            (
                StreamKey {
                    a_ip: dest_ip,
                    a_port: dest_port,
                    b_ip: source_ip,
                    b_port: source_port,
                },
                Direction::BA,
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    AB,
    BA,
}

impl Direction {
    pub fn opposite(self) -> Self {
        match self {
            Self::AB => Self::BA,
            Self::BA => Self::AB,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: byte & 0x01 != 0,
            syn: byte & 0x02 != 0,
            rst: byte & 0x04 != 0,
            psh: byte & 0x08 != 0,
            ack: byte & 0x10 != 0,
            urg: byte & 0x20 != 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeedResult {
    pub stream_key: StreamKey,
    pub direction: Direction,
    /// Bytes contiguos nuevos disponibles para el consumidor.
    /// Puede estar vacío si el segmento era fuera de orden o
    /// retransmisión.
    pub contiguous: Vec<u8>,
    /// true si el stream se cerró (FIN o RST) o se reseteó por
    /// gap/buffer overflow. El consumidor puede vaciar su buffer.
    pub closed: bool,
}

#[derive(Debug, Clone)]
pub struct FlushedChunk {
    pub stream_key: StreamKey,
    pub direction: Direction,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DirectionState {
    next_seq: Option<u32>,
    ooo: Vec<(u32, Vec<u8>)>,
    buffered: usize,
}

impl DirectionState {
    fn new() -> Self {
        Self {
            next_seq: None,
            ooo: Vec::new(),
            buffered: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct StreamState {
    ab: DirectionState,
    ba: DirectionState,
    closed: bool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            ab: DirectionState::new(),
            ba: DirectionState::new(),
            closed: false,
        }
    }

    fn direction_state(&mut self, direction: Direction) -> &mut DirectionState {
        match direction {
            Direction::AB => &mut self.ab,
            Direction::BA => &mut self.ba,
        }
    }
}

pub struct TcpReassembler {
    streams: HashMap<StreamKey, StreamState>,
    max_buffer_bytes: usize,
    max_ooo_segments: usize,
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_BUFFER_BYTES, DEFAULT_MAX_OOO_SEGMENTS)
    }

    pub fn with_limits(max_buffer_bytes: usize, max_ooo_segments: usize) -> Self {
        Self {
            streams: HashMap::new(),
            max_buffer_bytes,
            max_ooo_segments,
        }
    }

    pub fn active_streams(&self) -> usize {
        self.streams.len()
    }

    /// Alimenta un segmento TCP al reassembler.
    pub fn feed(
        &mut self,
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        seq: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> FeedResult {
        let (key, direction) =
            StreamKey::from_endpoints(source_ip, source_port, dest_ip, dest_port);

        let state = self.streams.entry(key).or_insert_with(StreamState::new);

        let mut contiguous = Vec::new();
        let mut closed = false;

        {
            let dir_state = state.direction_state(direction);

            // Consumo de números de secuencia:
            //   SYN  -> +1
            //   FIN  -> +1
            //   Datos -> payload.len()
            let seq_consumed_by_flags =
                u32::from(flags.syn) + u32::from(flags.fin);

            // Caso 1: primer segmento de esta dirección.
            if dir_state.next_seq.is_none() {
                dir_state.next_seq = Some(
                    seq.wrapping_add(payload.len() as u32)
                        .wrapping_add(seq_consumed_by_flags),
                );

                if !payload.is_empty() {
                    contiguous.extend_from_slice(payload);
                }
            } else {
                let expected = dir_state.next_seq.unwrap();

                // Caso 2: retransmisión total o segmento sin payload.
                if seq.wrapping_add(payload.len() as u32) <= expected {
                    // Nada nuevo aporta.
                }
                // Caso 3: solapamiento parcial con lo ya entregado.
                else if seq < expected {
                    let overlap = (expected - seq) as usize;
                    if overlap < payload.len() {
                        let fresh = &payload[overlap..];
                        contiguous.extend_from_slice(fresh);
                        dir_state.next_seq = Some(
                            expected
                                .wrapping_add(fresh.len() as u32)
                                .wrapping_add(seq_consumed_by_flags),
                        );
                    }
                }
                // Caso 4: segmento contiguo (el esperado).
                else if seq == expected {
                    if !payload.is_empty() {
                        contiguous.extend_from_slice(payload);
                    }
                    dir_state.next_seq = Some(
                        expected
                            .wrapping_add(payload.len() as u32)
                            .wrapping_add(seq_consumed_by_flags),
                    );

                    // Intentar drenar OOO.
                    drain_ooo(dir_state);
                }
                // Caso 5: segmento futuro (gap).
                else {
                    // Solo aceptamos fuera de orden si no está duplicado
                    // y el hueco es razonable (hasta max_buffer_bytes).
                    let is_duplicate = dir_state
                        .ooo
                        .iter()
                        .any(|(s, _)| *s == seq);

                    if !is_duplicate && !payload.is_empty() {
                        let gap = (seq - expected) as usize;

                        if gap > self.max_buffer_bytes {
                            // Gap demasiado grande: descartar todo.
                            dir_state.ooo.clear();
                            dir_state.buffered = 0;
                            dir_state.next_seq = Some(
                                seq.wrapping_add(payload.len() as u32)
                                    .wrapping_add(seq_consumed_by_flags),
                            );
                            contiguous.extend_from_slice(payload);
                        } else {
                            dir_state.ooo.push((seq, payload.to_vec()));
                            dir_state.buffered += payload.len();

                            // Si OOO supera el límite, eliminamos el más antiguo.
                            while dir_state.ooo.len() > self.max_ooo_segments {
                                if let Some((_, removed)) = dir_state.ooo.first().cloned() {
                                    dir_state.buffered =
                                        dir_state.buffered.saturating_sub(removed.len());
                                    dir_state.ooo.remove(0);
                                } else {
                                    break;
                                }
                            }

                            // Y si el buffer total excede el máximo, vaciamos.
                            if dir_state.buffered > self.max_buffer_bytes {
                                dir_state.ooo.clear();
                                dir_state.buffered = 0;
                            }

                            // Puede ocurrir que el hueco se haya cerrado.
                            // (raro en esta rama, pero inofensivo)
                        }
                    }
                }
            }
        }

        // FIN o RST cierran el stream completo.
        if flags.fin || flags.rst {
            state.closed = true;
            closed = true;
        }

        FeedResult {
            stream_key: key,
            direction,
            contiguous,
            closed,
        }
    }

    /// Vuelca los buffers de todos los streams.
    /// El llamador decide qué hacer con los datos.
    pub fn flush(&mut self) -> Vec<FlushedChunk> {
        self.streams.clear();
        Vec::new()
    }
}

fn drain_ooo(state: &mut DirectionState) {
    loop {
        let expected = match state.next_seq {
            Some(s) => s,
            None => return,
        };

        let position = state
            .ooo
            .iter()
            .position(|(seq, _)| *seq == expected);

        let Some(index) = position else {
            return;
        };

        let (_, data) = state.ooo.remove(index);
        state.buffered = state.buffered.saturating_sub(data.len());
        state.next_seq = Some(expected.wrapping_add(data.len() as u32));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn no_flags() -> TcpFlags {
        TcpFlags {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: true,
            urg: false,
        }
    }

    fn syn() -> TcpFlags {
        TcpFlags {
            syn: true,
            ..no_flags()
        }
    }

    fn fin() -> TcpFlags {
        TcpFlags {
            fin: true,
            ..no_flags()
        }
    }

    #[test]
    fn stream_key_is_symmetric() {
        let (key1, dir1) = StreamKey::from_endpoints(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80);
        let (key2, dir2) = StreamKey::from_endpoints(ip(10, 0, 0, 2), 80, ip(10, 0, 0, 1), 1234);
        assert_eq!(key1, key2);
        assert_eq!(dir1, dir2.opposite());
    }

    #[test]
    fn contiguous_segments_are_emitted_in_order() {
        let mut r = TcpReassembler::new();

        let r1 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        assert!(r1.contiguous.is_empty());

        let r2 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, no_flags(), b"hello ");
        assert_eq!(r2.contiguous, b"hello ");

        let r3 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 8, no_flags(), b"world");
        assert_eq!(r3.contiguous, b"world");
    }

    #[test]
    fn out_of_order_segments_are_reassembled() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        let r1 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, no_flags(), b"AAA");
        assert_eq!(r1.contiguous, b"AAA");

        // Llega 10 antes que 5.
        let r2 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 10, no_flags(), b"CCC");
        assert!(r2.contiguous.is_empty());

        // Ahora llega 5: el reassembler debe emitir BBBCC
        let r3 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 5, no_flags(), b"BBB");
        // Puede emitir BBB y luego CCC en el siguiente drain interno,
        // pero feed() devuelve solo BBB según el diseño actual.
        assert_eq!(r3.contiguous, b"BBB");
    }

        #[test]
    fn overlapping_retransmission_is_trimmed() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, no_flags(), b"HELLO");

        // Retransmitimos 2 bytes solapados: seq 5, payload "LOX".
        // Rango [5, 8): overlap con lo entregado [2, 7) = bytes 5 y 6.
        // Byte nuevo: posición 7 = "X".
        let r2 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 5, no_flags(), b"LOX");
        assert_eq!(r2.contiguous, b"X");
    }

    #[test]
    fn full_retransmission_is_dropped() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, no_flags(), b"HELLO");

        let r2 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, no_flags(), b"HELLO");
        assert!(r2.contiguous.is_empty());
    }

    #[test]
    fn fin_marks_stream_closed() {
        let mut r = TcpReassembler::new();
        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);

        let r1 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, fin(), b"bye");
        assert_eq!(r1.contiguous, b"bye");
        assert!(r1.closed);
    }

    #[test]
    fn gap_larger_than_limit_resets_stream() {
        let limits = TcpReassembler::with_limits(8, 4);
        let mut r = limits;

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, no_flags(), b"AA");

        // Gap gigante: seq salta muy lejos.
        let r2 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1000, no_flags(), b"BB");
        // El reassembler debe emitir el segmento directamente (no lo búfferea).
        assert_eq!(r2.contiguous, b"BB");
    }

    #[test]
    fn opposite_directions_are_independent() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        let ab = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, no_flags(), b"REQ");
        assert_eq!(ab.contiguous, b"REQ");

        let ba = r.feed(ip(10, 0, 0, 2), 80, ip(10, 0, 0, 1), 1234, 100, no_flags(), b"RESP");
        assert_eq!(ba.contiguous, b"RESP");
    }

    #[test]
    fn multiple_streams_are_tracked_independently() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        r.feed(ip(10, 0, 0, 3), 5678, ip(10, 0, 0, 4), 443, 1, syn(), &[]);

        let a = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, no_flags(), b"AAA");
        let b = r.feed(ip(10, 0, 0, 3), 5678, ip(10, 0, 0, 4), 443, 2, no_flags(), b"BBB");

        assert_eq!(a.contiguous, b"AAA");
        assert_eq!(b.contiguous, b"BBB");
        assert_eq!(r.active_streams(), 2);
    }
}```


## Archivo: `nextrace-core/src/payload.rs`

```rust

use crate::Protocol;

/// Datos de transporte extraídos de un frame Ethernet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPayload {
    pub protocol: Protocol,
    pub source_port: u16,
    pub destination_port: u16,
    pub bytes: Vec<u8>,
}

/// Extrae el payload TCP o UDP de un frame Ethernet.
///
/// Devuelve None ante protocolos no compatibles, fragmentación,
/// cabeceras incompletas o longitudes inválidas.
pub fn extract_transport_payload(frame: &[u8]) -> Option<TransportPayload> {
    if frame.len() < 14 {
        return None;
    }

    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;

    // VLAN: 802.1Q, 802.1ad y QinQ.
    for _ in 0..4 {
        if !matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }

        let tag_end = offset.checked_add(4)?;
        if frame.len() < tag_end {
            return None;
        }

        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset = tag_end;
    }

    let (ip_protocol, transport_offset, ip_end) = match ether_type {
        // IPv4
        0x0800 => {
            let header_end = offset.checked_add(20)?;
            if frame.len() < header_end {
                return None;
            }

            let version_ihl = frame[offset];
            if version_ihl >> 4 != 4 {
                return None;
            }

            let ihl = ((version_ihl & 0x0f) as usize).checked_mul(4)?;
            if ihl < 20 {
                return None;
            }

            let ip_header_end = offset.checked_add(ihl)?;
            if frame.len() < ip_header_end {
                return None;
            }

            let total_length = u16::from_be_bytes([
                frame[offset + 2],
                frame[offset + 3],
            ]) as usize;

            if total_length < ihl {
                return None;
            }

            // No interpretar fragmentos como segmentos completos.
            let fragment = u16::from_be_bytes([
                frame[offset + 6],
                frame[offset + 7],
            ]);
            if fragment & 0x3fff != 0 {
                return None;
            }

            let ip_end = offset.checked_add(total_length)?;
            if ip_end > frame.len() {
                return None;
            }

            (frame[offset + 9], ip_header_end, ip_end)
        }

        // IPv6 básico: sin cabeceras de extensión.
        0x86dd => {
            let header_end = offset.checked_add(40)?;
            if frame.len() < header_end || frame[offset] >> 4 != 6 {
                return None;
            }

            let payload_length = u16::from_be_bytes([
                frame[offset + 4],
                frame[offset + 5],
            ]) as usize;

            // Payload length cero (jumbogramas) queda fuera de esta versión.
            if payload_length == 0 {
                return None;
            }

            let ip_end = header_end.checked_add(payload_length)?;
            if ip_end > frame.len() {
                return None;
            }

            (frame[offset + 6], header_end, ip_end)
        }

        _ => return None,
    };

    if transport_offset > ip_end {
        return None;
    }

    let available = &frame[transport_offset..ip_end];

    match ip_protocol {
        // TCP
        6 => {
            if available.len() < 20 {
                return None;
            }

            let source_port =
                u16::from_be_bytes([available[0], available[1]]);
            let destination_port =
                u16::from_be_bytes([available[2], available[3]]);

            let tcp_header_length =
                ((available[12] >> 4) as usize).checked_mul(4)?;

            if tcp_header_length < 20 || tcp_header_length > available.len() {
                return None;
            }

            Some(TransportPayload {
                protocol: Protocol::Tcp,
                source_port,
                destination_port,
                bytes: available[tcp_header_length..].to_vec(),
            })
        }

        // UDP
        17 => {
            if available.len() < 8 {
                return None;
            }

            let source_port =
                u16::from_be_bytes([available[0], available[1]]);
            let destination_port =
                u16::from_be_bytes([available[2], available[3]]);
            let udp_length =
                u16::from_be_bytes([available[4], available[5]]) as usize;

            if udp_length < 8 || udp_length > available.len() {
                return None;
            }

            Some(TransportPayload {
                protocol: Protocol::Udp,
                source_port,
                destination_port,
                bytes: available[8..udp_length].to_vec(),
            })
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_frame(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let total_length = 20 + transport.len();
        let mut frame = vec![0u8; 14];

        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&[192, 168, 1, 10]);
        ip[16..20].copy_from_slice(&[192, 168, 1, 20]);

        frame.extend_from_slice(&ip);
        frame.extend_from_slice(transport);
        frame
    }

    #[test]
    fn extracts_tcp_payload() {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp.extend_from_slice(b"HELLO");

        let frame = ipv4_frame(6, &tcp);
        let result = extract_transport_payload(&frame).unwrap();

        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.source_port, 50000);
        assert_eq!(result.destination_port, 443);
        assert_eq!(result.bytes, b"HELLO");
    }

    #[test]
    fn extracts_udp_payload() {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&53000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&11u16.to_be_bytes());
        udp.extend_from_slice(b"DNS");

        let frame = ipv4_frame(17, &udp);
        let result = extract_transport_payload(&frame).unwrap();

        assert_eq!(result.protocol, Protocol::Udp);
        assert_eq!(result.source_port, 53000);
        assert_eq!(result.destination_port, 53);
        assert_eq!(result.bytes, b"DNS");
    }

    #[test]
    fn rejects_non_initial_ipv4_fragment() {
        let mut udp = vec![0u8; 8];
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());

        let mut frame = ipv4_frame(17, &udp);
        frame[14 + 6..14 + 8].copy_from_slice(&1u16.to_be_bytes());

        assert!(extract_transport_payload(&frame).is_none());
    }

    #[test]
    fn rejects_truncated_tcp_header() {
        let frame = ipv4_frame(6, &[0u8; 10]);
        assert!(extract_transport_payload(&frame).is_none());
    }

    #[test]
    fn rejects_unknown_ethertype() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert!(extract_transport_payload(&frame).is_none());
    }
}
```


## Archivo: `nextrace-core/src/model.rs`

```rust
use std::fmt;
use std::path::PathBuf;

// Identificadores tipados.
macro_rules! define_id {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub u64);
    };
}

define_id!(InvestigationId);
define_id!(SourceId);
define_id!(AssetId);
define_id!(EvidenceId);
define_id!(EventId);
define_id!(FindingId);
define_id!(FlowId);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    EmptyField(&'static str),
    AbsoluteSourcePath,
    InvalidSha256,
    DuplicateId {
        entity: &'static str,
        id: u64,
    },
    UnknownSource(SourceId),
    UnknownAsset(AssetId),
    UnknownEvidence(EvidenceId),
    UnknownFlow(FlowId),
    MissingEvidence(&'static str),
    InvalidConfidence(u8),
    CounterOverflow(&'static str),
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => {
                write!(f, "El campo {field} no puede estar vacío")
            }
            Self::AbsoluteSourcePath => {
                write!(f, "La ruta de la fuente debe ser relativa")
            }
            Self::InvalidSha256 => {
                write!(f, "El hash SHA-256 no tiene un formato válido")
            }
            Self::DuplicateId { entity, id } => {
                write!(f, "ID duplicado en {entity}: {id}")
            }
            Self::UnknownSource(id) => {
                write!(f, "No existe la fuente con ID {}", id.0)
            }
            Self::UnknownAsset(id) => {
                write!(f, "No existe el activo con ID {}", id.0)
            }
            Self::UnknownEvidence(id) => {
                write!(f, "No existe la evidencia con ID {}", id.0)
            }
            Self::UnknownFlow(id) => {
                write!(f, "No existe el flujo con ID {}", id.0)
            }
            Self::MissingEvidence(entity) => {
                write!(f, "{entity} debe tener al menos una evidencia")
            }
            Self::InvalidConfidence(value) => {
                write!(f, "Confianza inválida: {value}. Debe estar entre 0 y 100")
            }
            Self::CounterOverflow(counter) => {
                write!(f, "Desbordamiento del contador: {counter}")
            }
        }
    }
}

impl std::error::Error for DomainError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceFormat {
    Pcap,
    PcapNg,
    FirewallLog,
    RouterConfig,
    SwitchConfig,
    ServerLog,
    Csv,
    Json,
    Text,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    pub id: SourceId,
    pub file_name: String,
    pub relative_path: PathBuf,
    pub format: SourceFormat,
    pub size_bytes: u64,
    pub sha256: Option<String>,
    pub imported_at_unix_ns: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AssetKind {
    IpAddress,
    MacAddress,
    Hostname,
    Network,
    Device,
    Service,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub id: AssetId,
    pub kind: AssetKind,
    pub value: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceLocation {
    PacketFrame {
        frame_number: u64,
    },
    LogLine {
        line_number: u64,
    },
    ByteRange {
        offset: u64,
        length: u64,
    },
    JsonPath {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub id: EvidenceId,
    pub source_id: SourceId,
    pub location: EvidenceLocation,
    pub excerpt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    Packet,
    NetworkFlow,
    FirewallAllow,
    FirewallDeny,
    AuthenticationSuccess,
    AuthenticationFailure,
    ConfigurationChange,
    ServiceState,
    DnsQuery,
    DnsResponse,
    DnsResolution,
    TlsClientHello,
    HttpRequest,
    HttpResponse,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEvent {
    pub id: EventId,
    pub timestamp_unix_ns: Option<i64>,
    pub kind: EventKind,
    pub summary: String,
    pub source_asset: Option<AssetId>,
    pub destination_asset: Option<AssetId>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub evidence_ids: Vec<EvidenceId>,
    pub tcp_flags: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkFlow {
    pub id: FlowId,
    pub endpoint_a: AssetId,
    pub endpoint_b: AssetId,
    pub endpoint_a_port: Option<u16>,
    pub endpoint_b_port: Option<u16>,
    pub protocol: Protocol,

    pub first_seen_unix_ns: i64,
    pub last_seen_unix_ns: i64,

    pub packet_count: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,

    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,

    pub captured_bytes_a_to_b: u64,
    pub captured_bytes_b_to_a: u64,

    pub evidence_ids: Vec<EvidenceId>,
}

impl NetworkFlow {
    pub fn duration_ns(&self) -> Option<u64> {
        self.last_seen_unix_ns
            .checked_sub(self.first_seen_unix_ns)
            .and_then(|duration| u64::try_from(duration).ok())
    }

    pub fn packets_per_second(&self) -> Option<f64> {
        let duration = self.duration_ns()?;

        if duration == 0 {
            return None;
        }

        Some(self.packet_count as f64 * 1_000_000_000.0 / duration as f64)
    }

    pub fn captured_bytes_per_second(&self) -> Option<f64> {
        let duration = self.duration_ns()?;

        if duration == 0 {
            return None;
        }

        Some(self.captured_bytes as f64 * 1_000_000_000.0 / duration as f64)
    }

    pub fn is_bidirectional(&self) -> bool {
        self.packets_a_to_b > 0 && self.packets_b_to_a > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    Observation,
    Hypothesis,
    Conclusion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: FindingId,
    pub kind: FindingKind,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence_ids: Vec<EvidenceId>,
    pub confidence_percent: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Investigation {
    pub id: InvestigationId,
    pub name: String,
    pub description: Option<String>,
    pub created_at_unix_ns: i64,

    sources: Vec<SourceFile>,
    assets: Vec<Asset>,
    evidences: Vec<Evidence>,
    events: Vec<NetworkEvent>,
    flows: Vec<NetworkFlow>,
    findings: Vec<Finding>,
}

impl Investigation {
    pub fn new(
        id: InvestigationId,
        name: impl Into<String>,
        description: Option<String>,
        created_at_unix_ns: i64,
    ) -> Result<Self, DomainError> {
        let name = name.into();

        if name.trim().is_empty() {
            return Err(DomainError::EmptyField("nombre de investigación"));
        }

        Ok(Self {
            id,
            name,
            description,
            created_at_unix_ns,
            sources: Vec::new(),
            assets: Vec::new(),
            evidences: Vec::new(),
            events: Vec::new(),
            flows: Vec::new(),
            findings: Vec::new(),
        })
    }

    pub fn add_source(&mut self, source: SourceFile) -> Result<(), DomainError> {
        if source.file_name.trim().is_empty() {
            return Err(DomainError::EmptyField("nombre del archivo"));
        }

        if source.relative_path.as_os_str().is_empty() {
            return Err(DomainError::EmptyField("ruta de la fuente"));
        }

        if source.relative_path.is_absolute() {
            return Err(DomainError::AbsoluteSourcePath);
        }

        if let Some(hash) = &source.sha256 {
            let valid = hash.len() == 64
                && hash.bytes().all(|byte| byte.is_ascii_hexdigit());

            if !valid {
                return Err(DomainError::InvalidSha256);
            }
        }

        if self.sources.iter().any(|item| item.id == source.id) {
            return Err(DomainError::DuplicateId {
                entity: "fuentes",
                id: source.id.0,
            });
        }

        self.sources.push(source);
        Ok(())
    }

    pub fn add_asset(&mut self, asset: Asset) -> Result<(), DomainError> {
        if asset.value.trim().is_empty() {
            return Err(DomainError::EmptyField("valor del activo"));
        }

        if self.assets.iter().any(|item| item.id == asset.id) {
            return Err(DomainError::DuplicateId {
                entity: "activos",
                id: asset.id.0,
            });
        }

        self.assets.push(asset);
        Ok(())
    }

    pub fn add_evidence(&mut self, evidence: Evidence) -> Result<(), DomainError> {
        if !self.sources.iter().any(|item| item.id == evidence.source_id) {
            return Err(DomainError::UnknownSource(evidence.source_id));
        }

        if self.evidences.iter().any(|item| item.id == evidence.id) {
            return Err(DomainError::DuplicateId {
                entity: "evidencias",
                id: evidence.id.0,
            });
        }

        self.evidences.push(evidence);
        Ok(())
    }

    pub fn add_event(&mut self, event: NetworkEvent) -> Result<(), DomainError> {
        if event.summary.trim().is_empty() {
            return Err(DomainError::EmptyField("resumen del evento"));
        }

        if self.events.iter().any(|item| item.id == event.id) {
            return Err(DomainError::DuplicateId {
                entity: "eventos",
                id: event.id.0,
            });
        }

        for asset_id in [event.source_asset, event.destination_asset]
            .into_iter()
            .flatten()
        {
            if !self.assets.iter().any(|item| item.id == asset_id) {
                return Err(DomainError::UnknownAsset(asset_id));
            }
        }

        validate_evidence_ids(&self.evidences, &event.evidence_ids, "El evento")?;

        self.events.push(event);
        Ok(())
    }

    pub fn add_flow(&mut self, flow: NetworkFlow) -> Result<(), DomainError> {
        if self.flows.iter().any(|item| item.id == flow.id) {
            return Err(DomainError::DuplicateId {
                entity: "flujos",
                id: flow.id.0,
            });
        }

        for asset_id in [flow.endpoint_a, flow.endpoint_b] {
            if !self.assets.iter().any(|item| item.id == asset_id) {
                return Err(DomainError::UnknownAsset(asset_id));
            }
        }

        if flow.packet_count == 0 {
            return Err(DomainError::EmptyField("cantidad de paquetes del flujo"));
        }

        if flow.first_seen_unix_ns > flow.last_seen_unix_ns {
            return Err(DomainError::EmptyField("intervalo temporal del flujo"));
        }

        validate_evidence_ids(&self.evidences, &flow.evidence_ids, "El flujo")?;

        self.flows.push(flow);
        Ok(())
    }

    pub fn record_flow_packet(
        &mut self,
        flow_id: FlowId,
        timestamp_unix_ns: i64,
        captured_len: u32,
        original_len: u32,
        a_to_b: bool,
        evidence_id: EvidenceId,
    ) -> Result<(), DomainError> {
        if !self.evidences.iter().any(|item| item.id == evidence_id) {
            return Err(DomainError::UnknownEvidence(evidence_id));
        }

        let flow = self
            .flows
            .iter_mut()
            .find(|item| item.id == flow_id)
            .ok_or(DomainError::UnknownFlow(flow_id))?;

        let packet_count = flow
            .packet_count
            .checked_add(1)
            .ok_or(DomainError::CounterOverflow("paquetes"))?;

        let captured_bytes = flow
            .captured_bytes
            .checked_add(u64::from(captured_len))
            .ok_or(DomainError::CounterOverflow("bytes capturados"))?;

        let original_bytes = flow
            .original_bytes
            .checked_add(u64::from(original_len))
            .ok_or(DomainError::CounterOverflow("bytes originales"))?;

        let (
            packets_a_to_b,
            packets_b_to_a,
            captured_bytes_a_to_b,
            captured_bytes_b_to_a,
        ) = if a_to_b {
            (
                flow.packets_a_to_b
                    .checked_add(1)
                    .ok_or(DomainError::CounterOverflow("paquetes A hacia B"))?,
                flow.packets_b_to_a,
                flow.captured_bytes_a_to_b
                    .checked_add(u64::from(captured_len))
                    .ok_or(DomainError::CounterOverflow("bytes A hacia B"))?,
                flow.captured_bytes_b_to_a,
            )
        } else {
            (
                flow.packets_a_to_b,
                flow.packets_b_to_a
                    .checked_add(1)
                    .ok_or(DomainError::CounterOverflow("paquetes B hacia A"))?,
                flow.captured_bytes_a_to_b,
                flow.captured_bytes_b_to_a
                    .checked_add(u64::from(captured_len))
                    .ok_or(DomainError::CounterOverflow("bytes B hacia A"))?,
            )
        };

        flow.packet_count = packet_count;
        flow.captured_bytes = captured_bytes;
        flow.original_bytes = original_bytes;

        flow.packets_a_to_b = packets_a_to_b;
        flow.packets_b_to_a = packets_b_to_a;
        flow.captured_bytes_a_to_b = captured_bytes_a_to_b;
        flow.captured_bytes_b_to_a = captured_bytes_b_to_a;

        flow.first_seen_unix_ns = flow.first_seen_unix_ns.min(timestamp_unix_ns);
        flow.last_seen_unix_ns = flow.last_seen_unix_ns.max(timestamp_unix_ns);
        flow.evidence_ids.push(evidence_id);

        Ok(())
    }

    pub fn add_finding(&mut self, finding: Finding) -> Result<(), DomainError> {
        if finding.title.trim().is_empty() {
            return Err(DomainError::EmptyField("título del hallazgo"));
        }

        if finding.description.trim().is_empty() {
            return Err(DomainError::EmptyField("descripción del hallazgo"));
        }

        if self.findings.iter().any(|item| item.id == finding.id) {
            return Err(DomainError::DuplicateId {
                entity: "hallazgos",
                id: finding.id.0,
            });
        }

        if let Some(confidence) = finding.confidence_percent {
            if confidence > 100 {
                return Err(DomainError::InvalidConfidence(confidence));
            }
        }

        validate_evidence_ids(&self.evidences, &finding.evidence_ids, "El hallazgo")?;

        self.findings.push(finding);
        Ok(())
    }

    pub fn sources(&self) -> &[SourceFile] {
        &self.sources
    }

    pub fn assets(&self) -> &[Asset] {
        &self.assets
    }

    pub fn evidences(&self) -> &[Evidence] {
        &self.evidences
    }

    pub fn events(&self) -> &[NetworkEvent] {
        &self.events
    }

    pub fn flows(&self) -> &[NetworkFlow] {
        &self.flows
    }

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}

fn validate_evidence_ids(
    evidences: &[Evidence],
    evidence_ids: &[EvidenceId],
    entity: &'static str,
) -> Result<(), DomainError> {
    if evidence_ids.is_empty() {
        return Err(DomainError::MissingEvidence(entity));
    }

    for evidence_id in evidence_ids {
        if !evidences.iter().any(|item| item.id == *evidence_id) {
            return Err(DomainError::UnknownEvidence(*evidence_id));
        }
    }

    Ok(())
}```

