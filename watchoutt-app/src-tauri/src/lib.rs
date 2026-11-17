mod notes;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use watchoutt_core::{
    AnomalyConfig, AssetId, AssetKind, BaselineConfig, EventKind, EventQuery, FindingKind,
    Investigation, InvestigationId, NetworkEvent, Protocol, Severity, SourceFormat, SourceId,
    TimelineEntryKind, analyze_capture, analyze_flows, build_investigation_timeline,
    correlate_events, detect_anomalies_with_config, detect_baseline_anomalies_with_config,
    export_events_csv, export_events_json, import_source, open_project, save_project,
    write_markdown_report,
};

static STOP_CAPTURE: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
static LIVE_CAPTURE_PATH: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

// =====================================================================
// DTOs
// =====================================================================

#[derive(Serialize)]
struct TopAssetDto {
    id: u64,
    value: String,
    kind: String,
    total_bytes: u64,
    flow_count: u64,
}

#[derive(Serialize)]
struct KindCountDto {
    kind: String,
    count: usize,
}

#[derive(Serialize)]
struct ProtocolStatDto {
    protocol: String,
    flow_count: u64,
    packet_count: u64,
    captured_bytes: u64,
}

#[derive(Serialize)]
struct EndpointStatDto {
    asset_id: u64,
    value: String,
    flow_count: u64,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
}

#[derive(Serialize)]
struct FlowStatsDto {
    flow_count: u64,
    packet_count: u64,
    captured_bytes: u64,
    original_bytes: u64,
    bidirectional_flow_count: u64,
    protocols: Vec<ProtocolStatDto>,
    endpoints: Vec<EndpointStatDto>,
}

#[derive(Serialize)]
struct OverviewDto {
    sources: usize,
    sources_analyzed: usize,
    assets: usize,
    events: usize,
    flows: usize,
    findings: usize,
    dns_queries: usize,
    dns_responses: usize,
    dns_resolutions: usize,
    tls_client_hellos: usize,
    http_requests: usize,
    http_responses: usize,
    top_assets: Vec<TopAssetDto>,
    kind_distribution: Vec<KindCountDto>,
    flow_stats: FlowStatsDto,
}

#[derive(Serialize)]
struct EventDto {
    id: u64,
    timestamp_ns: Option<i64>,
    kind: String,
    summary: String,
    source_asset: Option<String>,
    destination_asset: Option<String>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    protocol: Option<String>,
    evidence_ids: Vec<u64>,
    tcp_flags: Option<String>,
}

#[derive(Serialize)]
struct FlowDto {
    id: u64,
    protocol: String,
    endpoint_a: String,
    endpoint_a_port: Option<u16>,
    endpoint_b: String,
    endpoint_b_port: Option<u16>,
    service_a: Option<String>,
    service_b: Option<String>,
    flags: Option<String>,
    first_seen_ns: i64,
    last_seen_ns: i64,
    duration_ns: Option<u64>,
    packets_per_second: Option<f64>,
    bytes_per_second: Option<f64>,
    packet_count: u64,
    captured_bytes: u64,
    bidirectional: bool,
}

#[derive(Serialize)]
struct FindingDto {
    id: u64,
    severity: String,
    kind: String,
    title: String,
    description: String,
    confidence_percent: Option<u8>,
    evidence_ids: Vec<u64>,
}

#[derive(Serialize)]
struct SourceDto {
    id: u64,
    file_name: String,
    format: String,
    size_bytes: u64,
    sha256: Option<String>,
    imported_at_ns: i64,
    analyzed: bool,
}

#[derive(Serialize)]
struct AssetDto {
    id: u64,
    value: String,
    kind: String,
    label: Option<String>,
    flow_count: u64,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    event_count: u64,
}

#[derive(Serialize)]
struct AssetDetailDto {
    asset: AssetDto,
    flows: Vec<FlowDto>,
    events: Vec<EventDto>,
}

#[derive(Serialize)]
struct EvidenceExcerptDto {
    id: u64,
    frame_number: u64,
    excerpt: Option<String>,
}

#[derive(Serialize)]
struct EventDetailDto {
    event: EventDto,
    evidence: Vec<EvidenceExcerptDto>,
    related_events: Vec<EventDto>,
    flow: Option<FlowDto>,
    tcp_flags: Option<String>,
}

#[derive(Serialize)]
struct CorrelationGroupDto {
    shared_asset: String,
    event_count: usize,
    events: Vec<EventDto>,
    evidence_ids: Vec<u64>,
    time_min_ns: i64,
    time_max_ns: i64,
}

#[derive(Serialize)]
struct CorrelationDto {
    window_ns: u64,
    events_considered: usize,
    events_without_timestamp: usize,
    total_events: usize,
    total_candidates: usize,
    truncated: bool,
    total_found: usize,
    groups: Vec<CorrelationGroupDto>,
}

#[derive(Serialize)]
struct TimelineV2Dto {
    events_without_timestamp: usize,
    entries: Vec<TimelineEntryV2Dto>,
}

#[derive(Serialize)]
struct TimelineEntryV2Dto {
    timestamp_ns: i64,
    kind: String,
    event_id: Option<u64>,
    event_summary: Option<String>,
    event_kind: Option<String>,
    associated_flow_ids: Option<Vec<u64>>,
    flow_id: Option<u64>,
    flow_endpoint_a: Option<String>,
    flow_endpoint_b: Option<String>,
    flow_packet_count: Option<u64>,
    flow_captured_bytes: Option<u64>,
    evidence_ids: Vec<u64>,
}

#[derive(Serialize)]
struct DnsResolutionDto {
    hostname: String,
    ip: String,
    timestamp_ns: Option<i64>,
    event_id: u64,
    summary: String,
}

#[derive(Serialize)]
struct HttpHostDto {
    host: String,
    request_count: usize,
    methods: Vec<String>,
    sample_uris: Vec<String>,
}

#[derive(Serialize)]
struct TlsSniDto {
    sni: String,
    count: usize,
    versions: Vec<String>,
    alpn: Vec<String>,
    client_ips: Vec<String>,
}

#[derive(Serialize)]
struct ProjectInfoDto {
    name: String,
    description: Option<String>,
    created_at_ns: i64,
    investigation_id: u64,
}

#[derive(Serialize)]
struct IntegrityReportDto {
    sources_verified: usize,
    sources_without_hash: usize,
    total_sources: usize,
    all_ok: bool,
}

#[derive(Serialize)]
struct NoteDto {
    id: u64,
    target_type: String,
    target_id: u64,
    text: String,
    created_at_ns: i64,
}

#[derive(Serialize)]
struct DiffDto {
    name_a: String,
    name_b: String,
    assets_only_in_a: Vec<String>,
    assets_only_in_b: Vec<String>,
    assets_shared: Vec<String>,
    flows_only_in_a: Vec<String>,
    flows_only_in_b: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone)]
struct AnomalyConfigDto {
    enable_http_on_unusual_port: bool,
    enable_tls_on_plain_port: bool,
    enable_large_flow: bool,
    large_flow_threshold_bytes: u64,
    enable_beaconing: bool,
    beacon_min_connections: usize,
    beacon_max_cv: f64,
    enable_dns_tunneling: bool,
    dns_long_name_threshold: usize,
    dns_max_unique_subdomains: usize,
    enable_port_scanning: bool,
    portscan_max_distinct_destinations: usize,
    portscan_window_ns: i64,
}

#[derive(Deserialize, Serialize, Clone)]
struct BaselineConfigDto {
    min_entities_per_kind: usize,
    modified_zscore_threshold: f64,
    high_zscore_threshold: f64,
    min_flows_per_asset: u64,
    enable_bytes_baseline: bool,
    enable_flow_count_baseline: bool,
}

impl From<AnomalyConfig> for AnomalyConfigDto {
    fn from(c: AnomalyConfig) -> Self {
        Self {
            enable_http_on_unusual_port: c.enable_http_on_unusual_port,
            enable_tls_on_plain_port: c.enable_tls_on_plain_port,
            enable_large_flow: c.enable_large_flow,
            large_flow_threshold_bytes: c.large_flow_threshold_bytes,
            enable_beaconing: c.enable_beaconing,
            beacon_min_connections: c.beacon_min_connections,
            beacon_max_cv: c.beacon_max_cv,
            enable_dns_tunneling: c.enable_dns_tunneling,
            dns_long_name_threshold: c.dns_long_name_threshold,
            dns_max_unique_subdomains: c.dns_max_unique_subdomains,
            enable_port_scanning: c.enable_port_scanning,
            portscan_max_distinct_destinations: c.portscan_max_distinct_destinations,
            portscan_window_ns: c.portscan_window_ns,
        }
    }
}

impl From<AnomalyConfigDto> for AnomalyConfig {
    fn from(d: AnomalyConfigDto) -> Self {
        let mut c = AnomalyConfig::default();
        c.enable_http_on_unusual_port = d.enable_http_on_unusual_port;
        c.enable_tls_on_plain_port = d.enable_tls_on_plain_port;
        c.enable_large_flow = d.enable_large_flow;
        c.large_flow_threshold_bytes = d.large_flow_threshold_bytes;
        c.enable_beaconing = d.enable_beaconing;
        c.beacon_min_connections = d.beacon_min_connections;
        c.beacon_max_cv = d.beacon_max_cv;
        c.enable_dns_tunneling = d.enable_dns_tunneling;
        c.dns_long_name_threshold = d.dns_long_name_threshold;
        c.dns_max_unique_subdomains = d.dns_max_unique_subdomains;
        c.enable_port_scanning = d.enable_port_scanning;
        c.portscan_max_distinct_destinations = d.portscan_max_distinct_destinations;
        c.portscan_window_ns = d.portscan_window_ns;
        c
    }
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct EventFilter {
    text: Option<String>,
    kind: Option<String>,
    protocol: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    time_start_ns: Option<i64>,
    time_end_ns: Option<i64>,
    min_port: Option<u16>,
    max_port: Option<u16>,
    asset_ids: Vec<u64>,
    asset_value: Option<String>,
    ioc_tokens: Vec<String>,
    exclude_loopback: bool,
    tcp_flags: Vec<String>,
}

// =====================================================================
// Helpers
// =====================================================================

fn now_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn is_local_or_loopback(value: &str) -> bool {
    let v = value.trim();
    v == "127.0.0.1"
        || v == "::1"
        || v == "0.0.0.0"
        || v == "::"
        || v.starts_with("127.")
        || v.starts_with("fe80:")
        || v.starts_with("169.254.")
        || v == "255.255.255.255"
        || v.starts_with("224.")
        || v.starts_with("ff02:")
}

fn port_to_service(port: Option<u16>) -> Option<String> {
    let p = port?;
    let name = match p {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 587 => "SMTP",
        53 => "DNS",
        67 | 68 => "DHCP",
        69 => "TFTP",
        80 | 8080 | 8000 => "HTTP",
        110 => "POP3",
        123 => "NTP",
        135 => "RPC",
        137 | 138 | 139 => "NetBIOS",
        143 => "IMAP",
        161 | 162 => "SNMP",
        389 => "LDAP",
        443 | 8443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        3306 => "MySQL",
        3389 => "RDP",
        5060 | 5061 => "SIP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => return None,
    };
    Some(name.to_string())
}

fn build_asset_index(inv: &Investigation) -> HashMap<u64, String> {
    inv.assets()
        .iter()
        .map(|a| (a.id.0, a.value.clone()))
        .collect()
}

fn resolve_asset_fast(index: &HashMap<u64, String>, id: AssetId) -> String {
    index
        .get(&id.0)
        .cloned()
        .unwrap_or_else(|| format!("AssetId({})", id.0))
}

fn event_kind_str(k: &EventKind) -> &'static str {
    match k {
        EventKind::Packet => "Packet",
        EventKind::NetworkFlow => "NetworkFlow",
        EventKind::FirewallAllow => "FirewallAllow",
        EventKind::FirewallDeny => "FirewallDeny",
        EventKind::AuthenticationSuccess => "AuthenticationSuccess",
        EventKind::AuthenticationFailure => "AuthenticationFailure",
        EventKind::ConfigurationChange => "ConfigurationChange",
        EventKind::ServiceState => "ServiceState",
        EventKind::DnsQuery => "DnsQuery",
        EventKind::DnsResponse => "DnsResponse",
        EventKind::DnsResolution => "DnsResolution",
        EventKind::TlsClientHello => "TlsClientHello",
        EventKind::HttpRequest => "HttpRequest",
        EventKind::HttpResponse => "HttpResponse",
        EventKind::Other(_) => "Other",
    }
}

fn protocol_str(p: &Protocol) -> &str {
    match p {
        Protocol::Tcp => "TCP",
        Protocol::Udp => "UDP",
        Protocol::Icmp => "ICMP",
        Protocol::IcmpV6 => "ICMPv6",
        Protocol::Other(s) => s.as_str(),
    }
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Info => "Info",
        Severity::Low => "Low",
        Severity::Medium => "Medium",
        Severity::High => "High",
        Severity::Critical => "Critical",
    }
}

fn finding_kind_str(k: &FindingKind) -> &'static str {
    match k {
        FindingKind::Observation => "Observation",
        FindingKind::Hypothesis => "Hypothesis",
        FindingKind::Conclusion => "Conclusion",
    }
}

fn asset_kind_str(k: &AssetKind) -> &'static str {
    match k {
        AssetKind::IpAddress => "IpAddress",
        AssetKind::MacAddress => "MacAddress",
        AssetKind::Hostname => "Hostname",
        AssetKind::Network => "Network",
        AssetKind::Device => "Device",
        AssetKind::Service => "Service",
    }
}

fn source_format_str(f: &SourceFormat) -> &'static str {
    match f {
        SourceFormat::Pcap => "PCAP",
        SourceFormat::PcapNg => "PCAPNG",
        SourceFormat::FirewallLog => "FirewallLog",
        SourceFormat::RouterConfig => "RouterConfig",
        SourceFormat::SwitchConfig => "SwitchConfig",
        SourceFormat::ServerLog => "ServerLog",
        SourceFormat::Csv => "CSV",
        SourceFormat::Json => "JSON",
        SourceFormat::Text => "Text",
        SourceFormat::Unknown => "Unknown",
    }
}

fn event_to_dto_fast(e: &NetworkEvent, idx: &HashMap<u64, String>) -> EventDto {
    EventDto {
        id: e.id.0,
        timestamp_ns: e.timestamp_unix_ns,
        kind: event_kind_str(&e.kind).to_string(),
        summary: e.summary.clone(),
        source_asset: e.source_asset.map(|id| resolve_asset_fast(idx, id)),
        destination_asset: e.destination_asset.map(|id| resolve_asset_fast(idx, id)),
        source_port: e.source_port,
        destination_port: e.destination_port,
        protocol: e.protocol.as_ref().map(|p| protocol_str(p).to_string()),
        evidence_ids: e.evidence_ids.iter().map(|id| id.0).collect(),
        tcp_flags: e.tcp_flags.clone(),
    }
}

fn get_flow_flags(
    flow: &watchoutt_core::NetworkFlow,
    event_flags_map: &HashMap<(AssetId, AssetId, Option<u16>, Option<u16>), HashSet<String>>,
) -> Option<String> {
    let mut merged = HashSet::new();
    let key1 = (
        flow.endpoint_a,
        flow.endpoint_b,
        flow.endpoint_a_port,
        flow.endpoint_b_port,
    );
    let key2 = (
        flow.endpoint_b,
        flow.endpoint_a,
        flow.endpoint_b_port,
        flow.endpoint_a_port,
    );

    if let Some(f) = event_flags_map.get(&key1) {
        merged.extend(f.clone());
    }
    if let Some(f) = event_flags_map.get(&key2) {
        merged.extend(f.clone());
    }

    if merged.is_empty() {
        None
    } else {
        let mut v: Vec<_> = merged.into_iter().collect();
        v.sort_by_key(|f| match f.as_str() {
            "SYN" => 0,
            "ACK" => 1,
            "PSH" => 2,
            "FIN" => 3,
            "RST" => 4,
            _ => 5,
        });
        Some(v.join(", "))
    }
}

fn flow_to_dto_fast(
    f: &watchoutt_core::NetworkFlow,
    idx: &HashMap<u64, String>,
    event_flags_map: &HashMap<(AssetId, AssetId, Option<u16>, Option<u16>), HashSet<String>>,
) -> FlowDto {
    FlowDto {
        id: f.id.0,
        protocol: protocol_str(&f.protocol).to_string(),
        endpoint_a: resolve_asset_fast(idx, f.endpoint_a),
        endpoint_a_port: f.endpoint_a_port,
        endpoint_b: resolve_asset_fast(idx, f.endpoint_b),
        endpoint_b_port: f.endpoint_b_port,
        service_a: port_to_service(f.endpoint_a_port),
        service_b: port_to_service(f.endpoint_b_port),
        flags: get_flow_flags(f, event_flags_map),
        first_seen_ns: f.first_seen_unix_ns,
        last_seen_ns: f.last_seen_unix_ns,
        duration_ns: f.duration_ns(),
        packets_per_second: f.packets_per_second(),
        bytes_per_second: f.captured_bytes_per_second(),
        packet_count: f.packet_count,
        captured_bytes: f.captured_bytes,
        bidirectional: f.is_bidirectional(),
    }
}

fn build_event_flags_map(
    inv: &Investigation,
) -> HashMap<(AssetId, AssetId, Option<u16>, Option<u16>), HashSet<String>> {
    let mut map = HashMap::new();
    for event in inv.events() {
        if let (Some(sa), Some(da), Some(flags_str)) = (
            event.source_asset,
            event.destination_asset,
            &event.tcp_flags,
        ) {
            let key = (sa, da, event.source_port, event.destination_port);
            let entry = map.entry(key).or_insert_with(HashSet::new);
            for f in flags_str.split(", ") {
                entry.insert(f.to_string());
            }
        }
    }
    map
}

fn flow_stats_dto(inv: &Investigation, idx: &HashMap<u64, String>) -> FlowStatsDto {
    let stats = analyze_flows(inv);
    let mut protocols: Vec<ProtocolStatDto> = stats
        .protocols
        .iter()
        .map(|p| ProtocolStatDto {
            protocol: protocol_str(&p.protocol).to_string(),
            flow_count: p.flow_count,
            packet_count: p.packet_count,
            captured_bytes: p.captured_bytes,
        })
        .collect();
    protocols.truncate(20);
    let mut endpoints: Vec<EndpointStatDto> = stats
        .endpoints
        .iter()
        .map(|e| EndpointStatDto {
            asset_id: e.asset_id.0,
            value: resolve_asset_fast(idx, e.asset_id),
            flow_count: e.flow_count,
            packets_sent: e.packets_sent,
            packets_received: e.packets_received,
            bytes_sent: e.bytes_sent,
            bytes_received: e.bytes_received,
        })
        .collect();
    endpoints.truncate(20);
    FlowStatsDto {
        flow_count: stats.flow_count,
        packet_count: stats.packet_count,
        captured_bytes: stats.captured_bytes,
        original_bytes: stats.original_bytes,
        bidirectional_flow_count: stats.bidirectional_flow_count,
        protocols,
        endpoints,
    }
}

fn parse_http_host(s: &str) -> Option<String> {
    let m = "(host ";
    let start = s.find(m)? + m.len();
    let rest = &s[start..];
    let end = rest.find(')')?;
    Some(rest[..end].to_string())
}
fn parse_http_method(s: &str) -> Option<String> {
    let r = s.strip_prefix("HTTP ")?;
    r.split_whitespace().next().map(|x| x.to_string())
}
fn parse_http_uri(s: &str) -> Option<String> {
    let r = s.strip_prefix("HTTP ")?;
    let mut p = r.splitn(2, ' ');
    p.next()?;
    p.next()?.split_whitespace().next().map(|x| x.to_string())
}
fn parse_tls_sni(s: &str) -> Option<String> {
    let m = "SNI=";
    let start = s.find(m)? + m.len();
    let rest = &s[start..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}
fn parse_tls_field(s: &str, key: &str) -> Vec<String> {
    let m = format!("{key}=");
    let Some(start) = s.find(&m) else {
        return Vec::new();
    };
    let rest = &s[start + m.len()..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    rest[..end]
        .split(',')
        .filter(|x| !x.is_empty())
        .map(|x| x.to_string())
        .collect()
}

fn format_hex_dump(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(frame vacío)".to_string();
    }
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex = String::new();
        for j in 0..16 {
            if j == 8 {
                hex.push(' ');
            }
            if j < chunk.len() {
                hex.push_str(&format!("{:02x} ", chunk[j]));
            } else {
                hex.push_str("   ");
            }
        }
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if (0x20..=0x7e).contains(b) {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!("{:08x}  {} |{}|\n", offset, hex.trim_end(), ascii));
    }
    out
}

fn read_frame_hex(path: &std::path::Path, frame_number: u64) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("Error abriendo: {e}"))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)
        .map_err(|e| format!("Error leyendo: {e}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("Error rebobinando: {e}"))?;

    let frame = if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        let mut reader = watchoutt_core::PcapNgReader::new(file);
        let mut n = 0u64;
        loop {
            match reader.next_packet() {
                Ok(Some(pkt)) => {
                    n += 1;
                    if n == frame_number {
                        break Ok(pkt.raw_frame);
                    }
                }
                Ok(None) => break Err(format!("Frame {frame_number} no encontrado")),
                Err(e) => break Err(format!("Error PCAPNG: {e}")),
            }
        }
    } else {
        let mut reader = watchoutt_core::PcapReader::new(file).map_err(|e| format!("{e}"))?;
        let mut n = 0u64;
        loop {
            match reader.next_packet() {
                Ok(Some(pkt)) => {
                    n += 1;
                    if n == frame_number {
                        break Ok(pkt.raw_frame);
                    }
                }
                Ok(None) => break Err(format!("Frame {frame_number} no encontrado")),
                Err(e) => break Err(format!("Error PCAP: {e}")),
            }
        }
    }?;
    Ok(format_hex_dump(&frame))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn fmt_ts_html(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000);
    format!("{secs}.{nanos:09} UTC")
}

fn svg_bars(title: &str, items: &[(String, u64)]) -> String {
    if items.is_empty() {
        return String::new();
    }
    let max = items.iter().map(|(_, v)| *v).max().unwrap_or(1);
    let bar_height = 26;
    let height = (items.len() as u32) * bar_height + 60;
    let width = 900u32;
    let mut s = String::new();
    s.push_str(&format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {} {}\" width=\"100%\" style=\"max-width:{0}px;background:#161b22;border-radius:6px;font-family:sans-serif\">", width, height));
    s.push_str(&format!(
        "<text x=\"20\" y=\"32\" fill=\"#58a6ff\" font-size=\"15\" font-weight=\"600\">{}</text>",
        html_escape(title)
    ));
    for (i, (label, value)) in items.iter().enumerate() {
        let y = 50 + (i as u32) * bar_height;
        let bar_w = ((*value as f64 / max as f64) * 550.0) as u32;
        s.push_str(&format!(
            "<text x=\"20\" y=\"{}\" fill=\"#e6edf3\" font-size=\"12\">{}</text>",
            y + 16,
            html_escape(label)
        ));
        s.push_str(&format!(
            "<rect x=\"200\" y=\"{}\" width=\"{}\" height=\"14\" fill=\"#58a6ff\" rx=\"2\"/>",
            y + 5,
            bar_w
        ));
        s.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" fill=\"#8b949e\" font-size=\"11\">{}</text>",
            210 + bar_w,
            y + 16,
            value
        ));
    }
    s.push_str("</svg>");
    s
}

fn flow_key_string(f: &watchoutt_core::NetworkFlow, idx: &HashMap<u64, String>) -> String {
    format!(
        "{}:{} → {}:{} ({})",
        resolve_asset_fast(idx, f.endpoint_a),
        f.endpoint_a_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string()),
        resolve_asset_fast(idx, f.endpoint_b),
        f.endpoint_b_port
            .map(|p| p.to_string())
            .unwrap_or_else(|| "—".to_string()),
        protocol_str(&f.protocol)
    )
}

// =====================================================================
// Comandos
// =====================================================================

#[tauri::command]
async fn cmd_create_project(project_dir: String, name: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Error creando directorio: {e}"))?;
    let inv = Investigation::new(InvestigationId(1), name, None, now_unix_ns())
        .map_err(|e| format!("Error creando investigación: {e:?}"))?;
    save_project(&inv, &dir).map_err(|e| format!("Error guardando: {e}"))?;
    Ok(format!("Proyecto creado en {}", dir.display()))
}

#[tauri::command]
async fn cmd_open_project(project_dir: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    match open_project(&dir) {
        Ok((inv, r)) => Ok(format!(
            "{} eventos · {} flujos · {} hallazgos · {} fuentes",
            inv.events().len(),
            inv.flows().len(),
            inv.findings().len(),
            r.sources_verified + r.sources_without_hash
        )),
        Err(e) => Err(format!("Error abriendo proyecto: {e}")),
    }
}

#[tauri::command]
async fn cmd_get_project_info(project_dir: String) -> Result<ProjectInfoDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    Ok(ProjectInfoDto {
        name: inv.name.clone(),
        description: inv.description.clone(),
        created_at_ns: inv.created_at_unix_ns,
        investigation_id: inv.id.0,
    })
}

#[tauri::command]
async fn cmd_update_project_description(
    project_dir: String,
    description: String,
) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    inv.description = if description.trim().is_empty() {
        None
    } else {
        Some(description.trim().to_string())
    };
    save_project(&inv, &dir).map_err(|e| format!("{e}"))?;
    Ok("Descripción actualizada".to_string())
}

#[tauri::command]
async fn cmd_verify_integrity(project_dir: String) -> Result<IntegrityReportDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, r) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let total = inv.sources().len();
    Ok(IntegrityReportDto {
        sources_verified: r.sources_verified,
        sources_without_hash: r.sources_without_hash,
        total_sources: total,
        all_ok: r.sources_verified == total && total > 0,
    })
}

#[tauri::command]
async fn cmd_import_source(project_dir: String, file_path: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let file = PathBuf::from(&file_path);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("Error abriendo proyecto: {e}"))?;
    let next_id = inv.sources().iter().map(|s| s.id.0).max().unwrap_or(0) + 1;
    match import_source(&mut inv, SourceId(next_id), &file, &dir, now_unix_ns()) {
        Ok(s) => {
            save_project(&inv, &dir).map_err(|e| format!("Error guardando: {e}"))?;
            Ok(format!(
                "Fuente {} importada: {} ({} bytes)",
                s.id.0, s.file_name, s.size_bytes
            ))
        }
        Err(e) => Err(format!("Error importando: {e}")),
    }
}

#[tauri::command]
async fn cmd_analyze(project_dir: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("Error abriendo proyecto: {e}"))?;
    let ids: Vec<u64> = inv.sources().iter().map(|s| s.id.0).collect();
    if ids.is_empty() {
        return Err("No hay fuentes importadas".to_string());
    }
    let mut lines = Vec::new();
    for sid in ids {
        if inv
            .evidences()
            .iter()
            .any(|ev| ev.source_id == SourceId(sid))
        {
            continue;
        }
        let src = inv
            .sources()
            .iter()
            .find(|s| s.id.0 == sid)
            .cloned()
            .ok_or_else(|| format!("Fuente {sid} no encontrada"))?;
        let path = dir.join(&src.relative_path);
        let reader = std::fs::File::open(&path)
            .map_err(|e| format!("Error abriendo {}: {}", path.display(), e))?;
        let r = analyze_capture(reader, SourceId(sid), &mut inv)
            .map_err(|e| format!("Error analizando: {e:?}"))?;
        lines.push(format!(
            "Fuente {}: {} paquetes, {} eventos, {} flujos",
            sid, r.packets_read, r.events_created, r.flows_created
        ));
    }
    save_project(&inv, &dir).map_err(|e| format!("Error guardando: {e}"))?;
    if lines.is_empty() {
        Ok("Todas las fuentes ya estaban analizadas".to_string())
    } else {
        Ok(lines.join("\n"))
    }
}

#[tauri::command]
async fn cmd_get_anomaly_config() -> AnomalyConfigDto {
    AnomalyConfigDto::from(AnomalyConfig::default())
}

#[tauri::command]
async fn cmd_detect_anomalies_with_config(
    project_dir: String,
    config: AnomalyConfigDto,
) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("Error abriendo proyecto: {e}"))?;
    let cfg: AnomalyConfig = config.into();
    let r = detect_anomalies_with_config(&mut inv, &cfg)
        .map_err(|e| format!("Error detectando: {e}"))?;
    save_project(&inv, &dir).map_err(|e| format!("Error guardando: {e}"))?;
    Ok(format!(
        "{} reglas · {} propuestas · {} añadidas · {} duplicadas",
        r.rules_evaluated,
        r.findings_proposed,
        r.findings_added.len(),
        r.findings_skipped_duplicate
    ))
}

#[tauri::command]
async fn cmd_get_baseline_config() -> BaselineConfigDto {
    let c = BaselineConfig::default();
    BaselineConfigDto {
        min_entities_per_kind: c.min_entities_per_kind,
        modified_zscore_threshold: c.modified_zscore_threshold,
        high_zscore_threshold: c.high_zscore_threshold,
        min_flows_per_asset: c.min_flows_per_asset,
        enable_bytes_baseline: c.enable_bytes_baseline,
        enable_flow_count_baseline: c.enable_flow_count_baseline,
    }
}

#[tauri::command]
async fn cmd_detect_baseline_anomalies(
    project_dir: String,
    config: BaselineConfigDto,
) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let cfg = BaselineConfig {
        min_entities_per_kind: config.min_entities_per_kind,
        modified_zscore_threshold: config.modified_zscore_threshold,
        high_zscore_threshold: config.high_zscore_threshold,
        min_flows_per_asset: config.min_flows_per_asset,
        enable_bytes_baseline: config.enable_bytes_baseline,
        enable_flow_count_baseline: config.enable_flow_count_baseline,
    };
    let report = detect_baseline_anomalies_with_config(&mut inv, &cfg)
        .map_err(|e| format!("Error baseline: {e}"))?;
    save_project(&inv, &dir).map_err(|e| format!("{e}"))?;
    Ok(format!(
        "{} reglas · {} tipos con datos · {} añadidos · {} duplicados",
        report.rules_evaluated,
        report.asset_kinds_with_enough_data,
        report.findings_added.len(),
        report.findings_skipped_duplicate
    ))
}

#[tauri::command]
async fn cmd_get_overview(project_dir: String) -> Result<OverviewDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let (mut dq, mut dr, mut dres, mut tls, mut hq, mut hr) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut kind_counts: HashMap<&'static str, usize> = HashMap::new();
    for e in inv.events() {
        *kind_counts.entry(event_kind_str(&e.kind)).or_insert(0) += 1;
        match &e.kind {
            EventKind::DnsQuery => dq += 1,
            EventKind::DnsResponse => dr += 1,
            EventKind::DnsResolution => dres += 1,
            EventKind::TlsClientHello => tls += 1,
            EventKind::HttpRequest => hq += 1,
            EventKind::HttpResponse => hr += 1,
            _ => {}
        }
    }
    let mut kind_distribution: Vec<KindCountDto> = kind_counts
        .into_iter()
        .map(|(k, c)| KindCountDto {
            kind: k.to_string(),
            count: c,
        })
        .collect();
    kind_distribution.sort_by(|a, b| b.count.cmp(&a.count));
    let mut traffic: HashMap<u64, (u64, u64)> = HashMap::new();
    for flow in inv.flows() {
        for id in [flow.endpoint_a, flow.endpoint_b] {
            let e = traffic.entry(id.0).or_insert((0, 0));
            e.0 += flow.captured_bytes;
            e.1 += 1;
        }
    }
    let mut top: Vec<_> = traffic.into_iter().collect();
    top.sort_by(|a, b| b.1.0.cmp(&a.1.0));
    let top_assets: Vec<TopAssetDto> = top
        .iter()
        .take(10)
        .map(|(id, (bytes, flows))| {
            let a = inv.assets().iter().find(|x| x.id.0 == *id);
            TopAssetDto {
                id: *id,
                value: a.map(|x| x.value.clone()).unwrap_or_default(),
                kind: a
                    .map(|x| asset_kind_str(&x.kind).to_string())
                    .unwrap_or_default(),
                total_bytes: *bytes,
                flow_count: *flows,
            }
        })
        .collect();
    let analyzed = inv
        .sources()
        .iter()
        .filter(|s| inv.evidences().iter().any(|e| e.source_id == s.id))
        .count();
    Ok(OverviewDto {
        sources: inv.sources().len(),
        sources_analyzed: analyzed,
        assets: inv.assets().len(),
        events: inv.events().len(),
        flows: inv.flows().len(),
        findings: inv.findings().len(),
        dns_queries: dq,
        dns_responses: dr,
        dns_resolutions: dres,
        tls_client_hellos: tls,
        http_requests: hq,
        http_responses: hr,
        top_assets,
        kind_distribution,
        flow_stats: flow_stats_dto(&inv, &idx),
    })
}

#[tauri::command]
async fn cmd_list_events(
    project_dir: String,
    filter: EventFilter,
) -> Result<Vec<EventDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let mut q = EventQuery::new();
    if let Some(t) = filter.text {
        if !t.trim().is_empty() {
            q.text_contains = Some(t);
        }
    }
    if let Some(k) = filter.kind {
        if !k.is_empty() {
            match k.as_str() {
                "Packet" => q.kinds.push(EventKind::Packet),
                "DnsQuery" => q.kinds.push(EventKind::DnsQuery),
                "DnsResponse" => q.kinds.push(EventKind::DnsResponse),
                "DnsResolution" => q.kinds.push(EventKind::DnsResolution),
                "TlsClientHello" => q.kinds.push(EventKind::TlsClientHello),
                "HttpRequest" => q.kinds.push(EventKind::HttpRequest),
                "HttpResponse" => q.kinds.push(EventKind::HttpResponse),
                _ => {}
            }
        }
    }
    if let Some(p) = filter.protocol {
        if !p.is_empty() {
            match p.as_str() {
                "TCP" => q.protocols.push(Protocol::Tcp),
                "UDP" => q.protocols.push(Protocol::Udp),
                _ => {}
            }
        }
    }
    if let (Some(s), Some(e)) = (filter.time_start_ns, filter.time_end_ns) {
        q.time_range = Some((s, e));
    }
    if let Some(p) = filter.min_port {
        q.min_port = Some(p);
    }
    if let Some(p) = filter.max_port {
        q.max_port = Some(p);
    }
    for id in filter.asset_ids {
        q.asset_ids.push(AssetId(id));
    }
    if let Some(av) = &filter.asset_value {
        if !av.is_empty() {
            if let Some(asset) = inv.assets().iter().find(|a| &a.value == av) {
                q.asset_ids.push(asset.id);
            }
        }
    }
    q.limit = None;
    for f in filter.tcp_flags {
        q.tcp_flags.push(f);
    }

    let mut events = q.run(&inv);
    if filter.exclude_loopback {
        events.retain(|e| {
            !is_local_or_loopback(
                &e.source_asset
                    .map(|id| resolve_asset_fast(&idx, id))
                    .unwrap_or_default(),
            ) && !is_local_or_loopback(
                &e.destination_asset
                    .map(|id| resolve_asset_fast(&idx, id))
                    .unwrap_or_default(),
            )
        });
    }
    if !filter.ioc_tokens.is_empty() {
        let tokens: Vec<String> = filter
            .ioc_tokens
            .iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        events.retain(|e| {
            let haystack = format!(
                "{} {} {}",
                e.summary.to_lowercase(),
                e.source_asset
                    .map(|id| resolve_asset_fast(&idx, id).to_lowercase())
                    .unwrap_or_default(),
                e.destination_asset
                    .map(|id| resolve_asset_fast(&idx, id).to_lowercase())
                    .unwrap_or_default()
            );
            tokens.iter().any(|t| haystack.contains(t))
        });
    }
    let offset = filter.offset.unwrap_or(0);
    Ok(events
        .iter()
        .skip(offset)
        .map(|e| event_to_dto_fast(e, &idx))
        .collect())
}

#[tauri::command]
async fn cmd_list_flows(project_dir: String) -> Result<Vec<FlowDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let flags_map = build_event_flags_map(&inv);
    Ok(inv
        .flows()
        .iter()
        .map(|f| flow_to_dto_fast(f, &idx, &flags_map))
        .collect())
}

#[tauri::command]
async fn cmd_list_flow_events(project_dir: String, flow_id: u64) -> Result<Vec<EventDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let flow = inv
        .flows()
        .iter()
        .find(|f| f.id.0 == flow_id)
        .ok_or_else(|| format!("Flujo {flow_id} no encontrado"))?;
    let (a, b) = (flow.endpoint_a, flow.endpoint_b);
    let (ap, bp) = (flow.endpoint_a_port, flow.endpoint_b_port);
    let mut events: Vec<EventDto> = inv
        .events()
        .iter()
        .filter(|e| {
            let ep = (e.source_asset == Some(a) && e.destination_asset == Some(b))
                || (e.source_asset == Some(b) && e.destination_asset == Some(a));
            if !ep {
                return false;
            }
            let port = (e.source_port == ap && e.destination_port == bp)
                || (e.source_port == bp && e.destination_port == ap);
            if !port {
                return false;
            }
            match (&e.protocol, &flow.protocol) {
                (Some(p), fp) => p == fp,
                (None, _) => true,
            }
        })
        .map(|e| event_to_dto_fast(e, &idx))
        .collect();
    events.sort_by_key(|e| e.timestamp_ns);
    Ok(events)
}

#[tauri::command]
async fn cmd_list_findings(project_dir: String) -> Result<Vec<FindingDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    Ok(inv
        .findings()
        .iter()
        .map(|f| FindingDto {
            id: f.id.0,
            severity: severity_str(&f.severity).to_string(),
            kind: finding_kind_str(&f.kind).to_string(),
            title: f.title.clone(),
            description: f.description.clone(),
            confidence_percent: f.confidence_percent,
            evidence_ids: f.evidence_ids.iter().map(|id| id.0).collect(),
        })
        .collect())
}

#[tauri::command]
async fn cmd_list_sources(project_dir: String) -> Result<Vec<SourceDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    Ok(inv
        .sources()
        .iter()
        .map(|s| SourceDto {
            id: s.id.0,
            file_name: s.file_name.clone(),
            format: source_format_str(&s.format).to_string(),
            size_bytes: s.size_bytes,
            sha256: s.sha256.clone(),
            imported_at_ns: s.imported_at_unix_ns,
            analyzed: inv.evidences().iter().any(|e| e.source_id == s.id),
        })
        .collect())
}

#[tauri::command]
async fn cmd_list_assets(project_dir: String) -> Result<Vec<AssetDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let mut fs: HashMap<u64, (u64, u64, u64, u64)> = HashMap::new();
    for flow in inv.flows() {
        let a = fs.entry(flow.endpoint_a.0).or_insert((0, 0, 0, 0));
        a.0 += 1;
        a.1 += flow.packets_a_to_b;
        a.2 += flow.packets_b_to_a;
        a.3 += flow.captured_bytes;
        let b = fs.entry(flow.endpoint_b.0).or_insert((0, 0, 0, 0));
        b.0 += 1;
        b.1 += flow.packets_b_to_a;
        b.2 += flow.packets_a_to_b;
        b.3 += flow.captured_bytes;
    }
    let mut ec: HashMap<u64, u64> = HashMap::new();
    for e in inv.events() {
        for o in [e.source_asset, e.destination_asset] {
            if let Some(id) = o {
                *ec.entry(id.0).or_insert(0) += 1;
            }
        }
    }
    let mut out: Vec<AssetDto> = inv
        .assets()
        .iter()
        .map(|a| {
            let (fc, ps, pr, tb) = fs.get(&a.id.0).copied().unwrap_or((0, 0, 0, 0));
            AssetDto {
                id: a.id.0,
                value: a.value.clone(),
                kind: asset_kind_str(&a.kind).to_string(),
                label: a.label.clone(),
                flow_count: fc,
                packets_sent: ps,
                packets_received: pr,
                bytes_sent: tb / 2,
                bytes_received: tb / 2,
                event_count: ec.get(&a.id.0).copied().unwrap_or(0),
            }
        })
        .collect();
    out.sort_by(|a, b| b.event_count.cmp(&a.event_count));
    Ok(out)
}

#[tauri::command]
async fn cmd_get_asset_detail(
    project_dir: String,
    asset_id: u64,
) -> Result<AssetDetailDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let flags_map = build_event_flags_map(&inv);
    let asset = inv
        .assets()
        .iter()
        .find(|a| a.id.0 == asset_id)
        .ok_or_else(|| format!("Activo {asset_id} no encontrado"))?;
    let mut flow_count = 0u64;
    let mut pkt_out = 0u64;
    let mut pkt_in = 0u64;
    let mut total_bytes = 0u64;
    let mut asset_flows: Vec<FlowDto> = Vec::new();
    for flow in inv.flows() {
        let in_a = flow.endpoint_a.0 == asset_id;
        let in_b = flow.endpoint_b.0 == asset_id;
        if !in_a && !in_b {
            continue;
        }
        flow_count += 1;
        if in_a {
            pkt_out += flow.packets_a_to_b;
            pkt_in += flow.packets_b_to_a;
        } else {
            pkt_out += flow.packets_b_to_a;
            pkt_in += flow.packets_a_to_b;
        }
        total_bytes += flow.captured_bytes;
        if asset_flows.len() < 100 {
            asset_flows.push(flow_to_dto_fast(flow, &idx, &flags_map));
        }
    }
    let mut asset_events: Vec<EventDto> = Vec::new();
    let mut event_count = 0u64;
    for e in inv.events() {
        let in_s = e.source_asset.map(|id| id.0 == asset_id).unwrap_or(false);
        let in_d = e
            .destination_asset
            .map(|id| id.0 == asset_id)
            .unwrap_or(false);
        if !in_s && !in_d {
            continue;
        }
        event_count += 1;
        if asset_events.len() < 200 {
            asset_events.push(event_to_dto_fast(e, &idx));
        }
    }
    let asset_dto = AssetDto {
        id: asset.id.0,
        value: asset.value.clone(),
        kind: asset_kind_str(&asset.kind).to_string(),
        label: asset.label.clone(),
        flow_count,
        packets_sent: pkt_out,
        packets_received: pkt_in,
        bytes_sent: total_bytes / 2,
        bytes_received: total_bytes / 2,
        event_count,
    };
    Ok(AssetDetailDto {
        asset: asset_dto,
        flows: asset_flows,
        events: asset_events,
    })
}

#[tauri::command]
async fn cmd_get_event_detail(
    project_dir: String,
    event_id: u64,
) -> Result<EventDetailDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let flags_map = build_event_flags_map(&inv);
    let event = inv
        .events()
        .iter()
        .find(|e| e.id.0 == event_id)
        .ok_or_else(|| format!("Evento {event_id} no encontrado"))?;
    let event_dto = event_to_dto_fast(event, &idx);
    let evidence: Vec<EvidenceExcerptDto> = event
        .evidence_ids
        .iter()
        .filter_map(|eid| {
            inv.evidences().iter().find(|e| e.id == *eid).map(|e| {
                let frame_number = match &e.location {
                    watchoutt_core::EvidenceLocation::PacketFrame { frame_number } => *frame_number,
                    _ => 0,
                };
                EvidenceExcerptDto {
                    id: e.id.0,
                    frame_number,
                    excerpt: e.excerpt.clone(),
                }
            })
        })
        .collect();
    let related: Vec<EventDto> = match event.timestamp_unix_ns {
        Some(ts) => {
            let window = 60_000_000_000i64;
            let start = inv.events().len().saturating_sub(2000);
            inv.events().iter().skip(start).filter(|e| e.id != event.id).filter(|e| {
                let Some(o) = e.timestamp_unix_ns else { return false }; if (o - ts).abs() > window { return false; }
                let s = |a: Option<AssetId>, b: Option<AssetId>| matches!((a, b), (Some(x), Some(y)) if x == y);
                s(event.source_asset, e.source_asset) || s(event.source_asset, e.destination_asset) || s(event.destination_asset, e.source_asset) || s(event.destination_asset, e.destination_asset)
            }).take(15).map(|e| event_to_dto_fast(e, &idx)).collect()
        }
        None => Vec::new(),
    };
    let flow = if let (Some(sa), Some(da)) = (event.source_asset, event.destination_asset) {
        if sa != da {
            inv.flows()
                .iter()
                .find(|f| {
                    let ep = |aid: AssetId, bid: AssetId| {
                        (event.source_asset == Some(aid) && event.destination_asset == Some(bid))
                            || (event.source_asset == Some(bid)
                                && event.destination_asset == Some(aid))
                    };
                    let port = (event.source_port == f.endpoint_a_port
                        && event.destination_port == f.endpoint_b_port)
                        || (event.source_port == f.endpoint_b_port
                            && event.destination_port == f.endpoint_a_port);
                    let proto = match (&event.protocol, &f.protocol) {
                        (Some(a), b) => a == b,
                        (None, _) => true,
                    };
                    ep(f.endpoint_a, f.endpoint_b) && port && proto
                })
                .map(|f| flow_to_dto_fast(f, &idx, &flags_map))
        } else {
            None
        }
    } else {
        None
    };
    Ok(EventDetailDto {
        event: event_dto,
        evidence,
        related_events: related,
        flow,
        tcp_flags: event.tcp_flags.clone(),
    })
}

#[tauri::command]
async fn cmd_get_frame_hex(project_dir: String, evidence_id: u64) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let ev = inv
        .evidences()
        .iter()
        .find(|e| e.id.0 == evidence_id)
        .ok_or_else(|| format!("Evidencia {evidence_id} no encontrada"))?;
    let frame_number = match &ev.location {
        watchoutt_core::EvidenceLocation::PacketFrame { frame_number } => *frame_number,
        _ => return Err("Evidencia sin frame asociado".to_string()),
    };
    let source = inv
        .sources()
        .iter()
        .find(|s| s.id == ev.source_id)
        .ok_or_else(|| "Fuente de evidencia no encontrada".to_string())?;
    let capture_path = dir.join(&source.relative_path);
    read_frame_hex(&capture_path, frame_number)
}

#[tauri::command]
async fn cmd_get_correlations(
    project_dir: String,
    window_ns: u64,
) -> Result<CorrelationDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let total_events = inv.events().len();
    let mut asset_degree: HashMap<u64, usize> = HashMap::new();
    for e in inv.events() {
        for opt in [e.source_asset, e.destination_asset] {
            if let Some(id) = opt {
                *asset_degree.entry(id.0).or_insert(0) += 1;
            }
        }
    }
    const HUB_RATIO: f64 = 0.15;
    const MAX_EVENTS: usize = 1000;
    let hub_threshold = ((total_events as f64) * HUB_RATIO).ceil() as usize;
    let hub_threshold = hub_threshold.max(3);
    let is_hub = |id: u64| -> bool {
        let degree = asset_degree.get(&id).copied().unwrap_or(0);
        if degree < hub_threshold && degree < 5 {
            return false;
        }
        let value = idx.get(&id).map(|s| s.as_str()).unwrap_or("");
        is_local_or_loopback(value) || degree >= hub_threshold
    };
    let mut candidates: Vec<&NetworkEvent> = inv
        .events()
        .iter()
        .filter(|e| e.timestamp_unix_ns.is_some())
        .filter(|e| !matches!(e.kind, EventKind::Packet))
        .filter(|e| {
            let src_hub = e.source_asset.map(|id| is_hub(id.0)).unwrap_or(true);
            let dst_hub = e.destination_asset.map(|id| is_hub(id.0)).unwrap_or(true);
            !(src_hub && dst_hub)
        })
        .collect();
    let total_candidates = candidates.len();
    candidates.sort_by_key(|e| e.timestamp_unix_ns);
    let start = candidates.len().saturating_sub(MAX_EVENTS);
    let subset: Vec<NetworkEvent> = candidates[start..].iter().map(|e| (*e).clone()).collect();
    let truncated = total_candidates > MAX_EVENTS;
    let report = correlate_events(&subset, window_ns);
    let mut groups_map: HashMap<u64, HashSet<u64>> = HashMap::new();
    let event_lookup: HashMap<u64, &NetworkEvent> =
        inv.events().iter().map(|e| (e.id.0, e)).collect();
    for c in &report.correlations {
        for asset_id in &c.shared_assets {
            if !is_hub(asset_id.0) {
                let entry = groups_map.entry(asset_id.0).or_default();
                entry.insert(c.first_event.0);
                entry.insert(c.second_event.0);
            }
        }
    }
    let mut groups: Vec<CorrelationGroupDto> = groups_map
        .into_iter()
        .map(|(asset_id, event_ids)| {
            let asset_val = resolve_asset_fast(&idx, AssetId(asset_id));
            let mut events: Vec<EventDto> = event_ids
                .iter()
                .filter_map(|id| event_lookup.get(id))
                .map(|e| event_to_dto_fast(e, &idx))
                .collect();
            events.sort_by_key(|e| e.timestamp_ns);
            let time_min_ns = events.first().and_then(|e| e.timestamp_ns).unwrap_or(0);
            let time_max_ns = events.last().and_then(|e| e.timestamp_ns).unwrap_or(0);
            let mut ev_ids = HashSet::new();
            for e in &events {
                ev_ids.extend(&e.evidence_ids);
            }
            CorrelationGroupDto {
                shared_asset: asset_val,
                event_count: events.len(),
                events,
                evidence_ids: ev_ids.into_iter().collect(),
                time_min_ns,
                time_max_ns,
            }
        })
        .collect();
    groups.sort_by(|a, b| b.event_count.cmp(&a.event_count));
    let total_found = groups.len();
    let groups = groups.into_iter().take(50).collect();
    Ok(CorrelationDto {
        window_ns: report.window_ns,
        events_considered: report.events_considered,
        events_without_timestamp: report.events_without_timestamp,
        total_events,
        total_candidates,
        truncated,
        total_found,
        groups,
    })
}

#[tauri::command]
async fn cmd_get_timeline_v2(project_dir: String) -> Result<TimelineV2Dto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let report = build_investigation_timeline(&inv);
    let entries: Vec<TimelineEntryV2Dto> = report
        .entries
        .iter()
        .take(500)
        .map(|entry| match &entry.kind {
            TimelineEntryKind::Event {
                event_id,
                associated_flow_ids,
                summary,
                evidence_ids,
            } => {
                let kind_str = inv
                    .events()
                    .iter()
                    .find(|e| e.id == *event_id)
                    .map(|e| event_kind_str(&e.kind).to_string())
                    .unwrap_or_default();
                TimelineEntryV2Dto {
                    timestamp_ns: entry.timestamp_unix_ns,
                    kind: "Event".to_string(),
                    event_id: Some(event_id.0),
                    event_summary: Some(summary.clone()),
                    event_kind: Some(kind_str),
                    associated_flow_ids: Some(associated_flow_ids.iter().map(|id| id.0).collect()),
                    flow_id: None,
                    flow_endpoint_a: None,
                    flow_endpoint_b: None,
                    flow_packet_count: None,
                    flow_captured_bytes: None,
                    evidence_ids: evidence_ids.iter().map(|id| id.0).collect(),
                }
            }
            TimelineEntryKind::Flow {
                flow_id,
                endpoint_a,
                endpoint_b,
                packet_count,
                captured_bytes,
                evidence_ids,
            } => TimelineEntryV2Dto {
                timestamp_ns: entry.timestamp_unix_ns,
                kind: "Flow".to_string(),
                event_id: None,
                event_summary: None,
                event_kind: None,
                associated_flow_ids: None,
                flow_id: Some(flow_id.0),
                flow_endpoint_a: Some(resolve_asset_fast(&idx, *endpoint_a)),
                flow_endpoint_b: Some(resolve_asset_fast(&idx, *endpoint_b)),
                flow_packet_count: Some(*packet_count),
                flow_captured_bytes: Some(*captured_bytes),
                evidence_ids: evidence_ids.iter().map(|id| id.0).collect(),
            },
        })
        .collect();
    Ok(TimelineV2Dto {
        events_without_timestamp: report.events_without_timestamp,
        entries,
    })
}

#[tauri::command]
async fn cmd_list_dns_resolutions(project_dir: String) -> Result<Vec<DnsResolutionDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    Ok(inv
        .events()
        .iter()
        .filter(|e| matches!(e.kind, EventKind::DnsResolution))
        .take(500)
        .map(|e| DnsResolutionDto {
            hostname: e
                .source_asset
                .map(|id| resolve_asset_fast(&idx, id))
                .unwrap_or_default(),
            ip: e
                .destination_asset
                .map(|id| resolve_asset_fast(&idx, id))
                .unwrap_or_default(),
            timestamp_ns: e.timestamp_unix_ns,
            event_id: e.id.0,
            summary: e.summary.clone(),
        })
        .collect())
}

#[tauri::command]
async fn cmd_list_http_hosts(project_dir: String) -> Result<Vec<HttpHostDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let mut map: HashMap<String, (usize, Vec<String>, Vec<String>)> = HashMap::new();
    for e in inv
        .events()
        .iter()
        .filter(|e| matches!(e.kind, EventKind::HttpRequest))
    {
        let host = parse_http_host(&e.summary).unwrap_or_else(|| "(sin host)".to_string());
        let entry = map.entry(host).or_insert((0, Vec::new(), Vec::new()));
        entry.0 += 1;
        if let Some(m) = parse_http_method(&e.summary) {
            if !entry.1.contains(&m) {
                entry.1.push(m);
            }
        }
        if let Some(u) = parse_http_uri(&e.summary) {
            if entry.2.len() < 5 && !entry.2.contains(&u) {
                entry.2.push(u);
            }
        }
    }
    let mut out: Vec<HttpHostDto> = map
        .into_iter()
        .map(|(h, (c, m, u))| HttpHostDto {
            host: h,
            request_count: c,
            methods: m,
            sample_uris: u,
        })
        .collect();
    out.sort_by(|a, b| b.request_count.cmp(&a.request_count));
    out.truncate(200);
    Ok(out)
}

#[tauri::command]
async fn cmd_list_tls_snis(project_dir: String) -> Result<Vec<TlsSniDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let mut map: HashMap<String, (usize, Vec<String>, Vec<String>, Vec<String>)> = HashMap::new();
    for e in inv
        .events()
        .iter()
        .filter(|e| matches!(e.kind, EventKind::TlsClientHello))
    {
        let sni = parse_tls_sni(&e.summary).unwrap_or_else(|| "(sin SNI)".to_string());
        let entry = map
            .entry(sni)
            .or_insert((0, Vec::new(), Vec::new(), Vec::new()));
        entry.0 += 1;
        for v in parse_tls_field(&e.summary, "versions") {
            if !entry.1.contains(&v) {
                entry.1.push(v);
            }
        }
        for a in parse_tls_field(&e.summary, "alpn") {
            if !entry.2.contains(&a) {
                entry.2.push(a);
            }
        }
        if let Some(ip) = e.source_asset.map(|id| resolve_asset_fast(&idx, id)) {
            if !entry.3.contains(&ip) && entry.3.len() < 10 {
                entry.3.push(ip);
            }
        }
    }
    let mut out: Vec<TlsSniDto> = map
        .into_iter()
        .map(|(s, (c, v, a, ips))| TlsSniDto {
            sni: s,
            count: c,
            versions: v,
            alpn: a,
            client_ips: ips,
        })
        .collect();
    out.sort_by(|a, b| b.count.cmp(&a.count));
    out.truncate(200);
    Ok(out)
}

#[tauri::command]
async fn cmd_list_notes(
    project_dir: String,
    target_type: Option<String>,
    target_id: Option<u64>,
) -> Result<Vec<NoteDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let all = notes::load_notes(&dir)?;
    let out: Vec<NoteDto> = all
        .into_iter()
        .filter(|n| match (&target_type, target_id) {
            (Some(tt), Some(ti)) => n.target_type == *tt && n.target_id == ti,
            (Some(tt), None) => n.target_type == *tt,
            _ => true,
        })
        .map(|n| NoteDto {
            id: n.id,
            target_type: n.target_type,
            target_id: n.target_id,
            text: n.text,
            created_at_ns: n.created_at_ns,
        })
        .collect();
    Ok(out)
}

#[tauri::command]
async fn cmd_add_note(
    project_dir: String,
    target_type: String,
    target_id: u64,
    text: String,
) -> Result<NoteDto, String> {
    if text.trim().is_empty() {
        return Err("Texto vacío".to_string());
    }
    let dir = PathBuf::from(&project_dir);
    let mut all = notes::load_notes(&dir)?;
    let id = notes::next_id(&all);
    let n = notes::Note {
        id,
        target_type,
        target_id,
        text: text.trim().to_string(),
        created_at_ns: now_unix_ns(),
    };
    all.push(n.clone());
    notes::save_notes(&dir, &all)?;
    Ok(NoteDto {
        id: n.id,
        target_type: n.target_type,
        target_id: n.target_id,
        text: n.text,
        created_at_ns: n.created_at_ns,
    })
}

#[tauri::command]
async fn cmd_delete_note(project_dir: String, note_id: u64) -> Result<(), String> {
    let dir = PathBuf::from(&project_dir);
    let mut all = notes::load_notes(&dir)?;
    all.retain(|n| n.id != note_id);
    notes::save_notes(&dir, &all)
}

#[tauri::command]
async fn cmd_diff_sources(
    project_dir: String,
    source_a: u64,
    source_b: u64,
) -> Result<DiffDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let ev_a: HashSet<u64> = inv
        .evidences()
        .iter()
        .filter(|e| e.source_id.0 == source_a)
        .map(|e| e.id.0)
        .collect();
    let ev_b: HashSet<u64> = inv
        .evidences()
        .iter()
        .filter(|e| e.source_id.0 == source_b)
        .map(|e| e.id.0)
        .collect();
    let mut assets_a = HashSet::new();
    let mut assets_b = HashSet::new();
    for e in inv.events() {
        if e.evidence_ids.iter().any(|id| ev_a.contains(&id.0)) {
            if let Some(a) = e.source_asset {
                assets_a.insert(a.0);
            }
            if let Some(a) = e.destination_asset {
                assets_a.insert(a.0);
            }
        }
        if e.evidence_ids.iter().any(|id| ev_b.contains(&id.0)) {
            if let Some(a) = e.source_asset {
                assets_b.insert(a.0);
            }
            if let Some(a) = e.destination_asset {
                assets_b.insert(a.0);
            }
        }
    }
    let assets_a_str: HashSet<String> = assets_a
        .iter()
        .filter_map(|id| idx.get(id).cloned())
        .collect();
    let assets_b_str: HashSet<String> = assets_b
        .iter()
        .filter_map(|id| idx.get(id).cloned())
        .collect();
    let mut flows_a = HashSet::new();
    let mut flows_b = HashSet::new();
    for f in inv.flows() {
        if f.evidence_ids.iter().any(|id| ev_a.contains(&id.0)) {
            flows_a.insert(f.id.0);
        }
        if f.evidence_ids.iter().any(|id| ev_b.contains(&id.0)) {
            flows_b.insert(f.id.0);
        }
    }
    let flows_a_str: HashSet<String> = flows_a
        .iter()
        .filter_map(|id| inv.flows().iter().find(|f| f.id.0 == *id))
        .map(|f| flow_key_string(f, &idx))
        .collect();
    let flows_b_str: HashSet<String> = flows_b
        .iter()
        .filter_map(|id| inv.flows().iter().find(|f| f.id.0 == *id))
        .map(|f| flow_key_string(f, &idx))
        .collect();
    let name_a = inv
        .sources()
        .iter()
        .find(|s| s.id.0 == source_a)
        .map(|s| s.file_name.clone())
        .unwrap_or_else(|| format!("Fuente {source_a}"));
    let name_b = inv
        .sources()
        .iter()
        .find(|s| s.id.0 == source_b)
        .map(|s| s.file_name.clone())
        .unwrap_or_else(|| format!("Fuente {source_b}"));
    let mut only_a: Vec<String> = assets_a_str.difference(&assets_b_str).cloned().collect();
    let mut only_b: Vec<String> = assets_b_str.difference(&assets_a_str).cloned().collect();
    let mut shared: Vec<String> = assets_a_str.intersection(&assets_b_str).cloned().collect();
    only_a.sort();
    only_b.sort();
    shared.sort();
    let mut flows_only_a: Vec<String> = flows_a_str.difference(&flows_b_str).cloned().collect();
    let mut flows_only_b: Vec<String> = flows_b_str.difference(&flows_a_str).cloned().collect();
    flows_only_a.sort();
    flows_only_b.sort();
    Ok(DiffDto {
        name_a,
        name_b,
        assets_only_in_a: only_a,
        assets_only_in_b: only_b,
        assets_shared: shared,
        flows_only_in_a: flows_only_a,
        flows_only_in_b: flows_only_b,
    })
}

#[tauri::command]
async fn cmd_export_markdown(project_dir: String, output_path: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let out = PathBuf::from(&output_path);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    write_markdown_report(&inv, 60_000_000_000, &out).map_err(|e| format!("Error: {e}"))?;
    Ok(format!("Informe guardado en {}", out.display()))
}

#[tauri::command]
async fn cmd_export_csv(project_dir: String, output_path: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let out = PathBuf::from(&output_path);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let events: Vec<&NetworkEvent> = inv.events().iter().collect();
    export_events_csv(&inv, &events, &out).map_err(|e| format!("Error: {e}"))?;
    Ok(format!("CSV guardado en {}", out.display()))
}

#[tauri::command]
async fn cmd_export_json(project_dir: String, output_path: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let out = PathBuf::from(&output_path);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let events: Vec<&NetworkEvent> = inv.events().iter().collect();
    export_events_json(&inv, &events, &out).map_err(|e| format!("Error: {e}"))?;
    Ok(format!("JSON guardado en {}", out.display()))
}

#[tauri::command]
async fn cmd_export_report_html(
    project_dir: String,
    output_path: String,
) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let out = PathBuf::from(&output_path);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let mut kind_counts: HashMap<&'static str, u64> = HashMap::new();
    for e in inv.events() {
        *kind_counts.entry(event_kind_str(&e.kind)).or_insert(0) += 1;
    }
    let mut kind_items: Vec<(String, u64)> = kind_counts
        .into_iter()
        .map(|(k, c)| (k.to_string(), c))
        .collect();
    kind_items.sort_by(|a, b| b.1.cmp(&a.1));
    let kind_items: Vec<(String, u64)> = kind_items.into_iter().take(10).collect();
    let mut traffic: HashMap<u64, u64> = HashMap::new();
    for flow in inv.flows() {
        for id in [flow.endpoint_a, flow.endpoint_b] {
            *traffic.entry(id.0).or_insert(0) += flow.captured_bytes;
        }
    }
    let mut top: Vec<(String, u64)> = traffic
        .into_iter()
        .filter_map(|(id, bytes)| idx.get(&id).map(|v| (v.clone(), bytes)))
        .collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    let top_talkers: Vec<(String, u64)> = top.into_iter().take(10).collect();
    let all_notes = notes::load_notes(&dir).unwrap_or_default();
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n<meta charset=\"UTF-8\">\n");
    html.push_str(&format!(
        "<title>Informe NEXTRACE — {}</title>\n",
        html_escape(&inv.name)
    ));
    html.push_str("<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0 auto;padding:2rem;max-width:1100px}h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:.5rem}h2{color:#58a6ff;margin-top:2rem}h3{color:#79c0ff}.meta{color:#8b949e;font-size:.9rem;margin-bottom:2rem}.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin:1rem 0}.stat{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1rem}.stat-value{font-size:1.8rem;font-weight:600;color:#e6edf3}.stat-label{color:#8b949e;font-size:.75rem;text-transform:uppercase}table{width:100%;border-collapse:collapse;margin:1rem 0;background:#161b22;border-radius:6px;overflow:hidden}th{background:#1c2128;padding:.5rem;text-align:left;font-size:.75rem;text-transform:uppercase;color:#8b949e}td{padding:.5rem;border-bottom:1px solid #21262d;font-family:ui-monospace,monospace;font-size:.85rem}.severity-Critical,.severity-High{color:#f85149;font-weight:bold}.severity-Medium{color:#d29922}.severity-Low,.severity-Info{color:#8b949e}.note{background:#161b22;border-left:3px solid #58a6ff;padding:.75rem;margin:.5rem 0;border-radius:4px}.flags{color:#3fb950;font-weight:bold}</style>\n</head>\n<body>\n");
    html.push_str(&format!("<h1>Informe: {}</h1>\n", html_escape(&inv.name)));
    html.push_str(&format!(
        "<div class=\"meta\">ID {} · creado {}</div>\n",
        inv.id.0,
        fmt_ts_html(inv.created_at_unix_ns)
    ));
    if let Some(desc) = &inv.description {
        html.push_str(&format!("<p>{}</p>\n", html_escape(desc)));
    }
    html.push_str("<h2>Resumen</h2>\n<div class=\"stat-grid\">\n");
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Fuentes</div></div>\n", inv.sources().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Activos</div></div>\n", inv.assets().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Eventos</div></div>\n", inv.events().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Flujos</div></div>\n", inv.flows().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Hallazgos</div></div>\n", inv.findings().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Notas</div></div>\n", all_notes.len()));
    html.push_str("</div>\n");
    if !kind_items.is_empty() {
        html.push_str("<h2>Distribución por tipo</h2>\n");
        html.push_str(&svg_bars("Eventos por tipo", &kind_items));
        html.push('\n');
    }
    if !top_talkers.is_empty() {
        html.push_str("<h2>Top activos por tráfico</h2>\n");
        html.push_str(&svg_bars("Top activos por bytes", &top_talkers));
        html.push('\n');
    }
    html.push_str("<h2>Hallazgos</h2>\n");
    if inv.findings().is_empty() {
        html.push_str("<p>No se registraron hallazgos.</p>\n");
    } else {
        html.push_str(
            "<table><tr><th>ID</th><th>Severidad</th><th>Título</th><th>Conf.</th></tr>\n",
        );
        for f in inv.findings() {
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"severity-{}\">{:?}</td><td>{}</td><td>{}%</td></tr>\n",
                f.id.0,
                severity_str(&f.severity),
                f.severity,
                html_escape(&f.title),
                f.confidence_percent
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "—".to_string())
            ));
        }
        html.push_str("</table>\n");
    }
    if !all_notes.is_empty() {
        html.push_str("<h2>Notas del analista</h2>\n");
        for n in &all_notes {
            html.push_str(&format!(
                "<div class=\"note\"><strong>{}</strong> #{}: {}</div>\n",
                html_escape(&n.target_type),
                n.target_id,
                html_escape(&n.text)
            ));
        }
    }
    html.push_str("<hr style=\"border-color:#30363d;margin:2rem 0\">\n");
    html.push_str("<p class=\"meta\">Informe generado por NEXTRACE.</p>\n</body>\n</html>\n");
    std::fs::write(&out, html).map_err(|e| format!("Error escribiendo: {e}"))?;
    Ok(format!("Informe HTML guardado en {}", out.display()))
}

// =====================================================================
// Comandos de Captura en Vivo
// =====================================================================

#[tauri::command]
async fn cmd_list_interfaces() -> Result<Vec<String>, String> {
    watchoutt_core::live::list_interfaces()
}

#[tauri::command]
async fn cmd_start_live_capture(project_dir: String, interface: String) -> Result<String, String> {
    STOP_CAPTURE.store(false, Ordering::SeqCst);

    let dir = PathBuf::from(&project_dir);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let filename = format!("live_capture_{}.pcap", timestamp);
    let output_path = dir.join(&filename);

    *LIVE_CAPTURE_PATH.lock().unwrap() = Some(output_path.to_string_lossy().to_string());

    let stop_flag = STOP_CAPTURE.clone();
    watchoutt_core::live::start_capture_to_file(&interface, &output_path, stop_flag)?;

    Ok(format!("Grabando en {}", filename))
}

#[tauri::command]
async fn cmd_stop_live_capture(project_dir: String) -> Result<String, String> {
    STOP_CAPTURE.store(true, Ordering::SeqCst);

    // Esperamos un momento a que el hilo cierre el archivo .pcap correctamente
    std::thread::sleep(std::time::Duration::from_millis(500));

    let file_path = {
        let mut lock = LIVE_CAPTURE_PATH.lock().unwrap();
        lock.take()
    };

    if let Some(path_str) = file_path {
        let dir = PathBuf::from(&project_dir);
        let file = PathBuf::from(&path_str);

        // 1. Importar el archivo capturado como una fuente más
        let (mut inv, _) =
            open_project(&dir).map_err(|e| format!("Error abriendo proyecto: {e}"))?;
        let next_id = inv.sources().iter().map(|s| s.id.0).max().unwrap_or(0) + 1;

        if let Ok(s) = import_source(&mut inv, SourceId(next_id), &file, &dir, now_unix_ns()) {
            save_project(&inv, &dir).map_err(|e| format!("Error guardando: {e}"))?;

            // 2. Analizar los paquetes
            let path = dir.join(&s.relative_path);
            if let Ok(reader) = std::fs::File::open(&path) {
                let _ = analyze_capture(reader, SourceId(next_id), &mut inv);
                save_project(&inv, &dir).map_err(|e| format!("Error guardando analisis: {e}"))?;
            }
            Ok(format!(
                "Captura finalizada. Se importaron y analizaron los paquetes de {}.",
                s.file_name
            ))
        } else {
            Err("No se pudo importar el archivo de captura".to_string())
        }
    } else {
        Err("No había captura activa".to_string())
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            cmd_create_project,
            cmd_open_project,
            cmd_get_project_info,
            cmd_update_project_description,
            cmd_verify_integrity,
            cmd_import_source,
            cmd_analyze,
            cmd_get_anomaly_config,
            cmd_detect_anomalies_with_config,
            cmd_get_baseline_config,
            cmd_detect_baseline_anomalies,
            cmd_get_overview,
            cmd_list_events,
            cmd_list_flows,
            cmd_list_flow_events,
            cmd_list_findings,
            cmd_list_sources,
            cmd_list_assets,
            cmd_get_asset_detail,
            cmd_get_event_detail,
            cmd_get_frame_hex,
            cmd_get_correlations,
            cmd_get_timeline_v2,
            cmd_list_dns_resolutions,
            cmd_list_http_hosts,
            cmd_list_tls_snis,
            cmd_list_notes,
            cmd_add_note,
            cmd_delete_note,
            cmd_diff_sources,
            cmd_export_markdown,
            cmd_export_csv,
            cmd_export_json,
            cmd_export_report_html,
            cmd_list_interfaces,
            cmd_start_live_capture,
            cmd_stop_live_capture
        ])
        .run(tauri::generate_context!())
        .expect("error ejecutando NEXTRACE");
}
