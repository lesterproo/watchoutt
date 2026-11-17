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
            let is_dns_port = |port: Option<u16>| matches!(port, Some(53) | Some(5353));
            
            if matches!(network_info.protocol, Protocol::Udp)
                && (is_dns_port(network_info.source_port) || is_dns_port(network_info.destination_port))
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
                        
                        let all_records = message.answers.iter().chain(message.additionals.iter());

                        for record in all_records {
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

                                while !buffer.is_empty() {
                                    if let Some((app_event, consumed)) = try_parse_stream_buffer(
                                        &mut working,
                                        buffer,
                                        evidence_ids,
                                        network_info,
                                        source_asset,
                                        destination_asset,
                                        packet.timestamp_unix_ns,
                                    )? {
                                        match app_event.kind {
                                            EventKind::TlsClientHello => report.tls_client_hellos += 1,
                                            EventKind::HttpRequest => report.http_requests += 1,
                                            EventKind::HttpResponse => report.http_responses += 1,
                                            _ => {}
                                        }
                                        working.add_event(app_event)?;
                                        report.events_created += 1;
                                        buffer.drain(0..consumed);
                                    } else {
                                        break;
                                    }
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
) -> Result<Option<(NetworkEvent, usize)>, PcapAnalysisError> {
    let (kind, summary, consumed) = if let Ok(hello) = parse_tls_client_hello(buffer) {
        (EventKind::TlsClientHello, hello.summary(), buffer.len())
    } else if let Ok(message) = parse_http(buffer) {
        let kind = match &message {
            HttpMessage::Request(_) => EventKind::HttpRequest,
            HttpMessage::Response(_) => EventKind::HttpResponse,
        };
        let summary = message.summary();
        let consumed = buffer.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(buffer.len());
        (kind, summary, consumed)
    } else {
        return Ok(None);
    };

    let event_id = EventId(next_id(
        investigation.events().iter().map(|item| item.id.0),
        "eventos",
    )?);

    let event = NetworkEvent {
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
    };

    Ok(Some((event, consumed)))
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
}