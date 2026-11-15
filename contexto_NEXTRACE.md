
## Archivo: `nextrace-app/src-tauri/tauri.conf.json`

```json
{
  "$schema": "https://schema.tauri.app/config/2",
  "productName": "nextrace-app",
  "version": "0.1.0",
  "identifier": "com.lestersalvi.nextrace-app",
  "build": {
    "beforeDevCommand": "npm run dev",
    "devUrl": "http://localhost:1420",
    "beforeBuildCommand": "npm run build",
    "frontendDist": "../dist"
  },
  "app": {
    "withGlobalTauri": true,
    "windows": [
      {
        "title": "nextrace-app",
        "width": 800,
        "height": 600
      }
    ],
    "security": {
      "csp": null
    }
  },
  "bundle": {
    "active": true,
    "targets": "all",
    "icon": [
      "icons/32x32.png",
      "icons/128x128.png",
      "icons/128x128@2x.png",
      "icons/icon.icns",
      "icons/icon.ico"
    ]
  }
}
```


## Archivo: `nextrace-app/src-tauri/Cargo.toml`

```toml
[package]
name = "nextrace-app"
version = "0.1.0"
description = "A Tauri App"
authors = ["you"]
edition = "2024"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[lib]
# The `_lib` suffix may seem redundant but it is necessary
# to make the lib name unique and wouldn't conflict with the bin name.
# This seems to be only an issue on Windows, see https://github.com/rust-lang/cargo/issues/8519
name = "nextrace_app_lib"
crate-type = ["staticlib", "cdylib", "rlib"]

[build-dependencies]
tauri-build = { version = "2", features = [] }

[dependencies]
tauri = { version = "2", features = [] }
tauri-plugin-opener = "2"
tauri-plugin-dialog = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
nextrace-core = { path = "../../nextrace-core" }


# Read the optimization guideline for more details: https://tauri.app/concept/size/#cargo-configuration
[profile.release]
codegen-units = 1
lto = true
opt-level = 3
panic = "abort"
strip = true
```


## Archivo: `nextrace-app/package.json`

```json
{
  "name": "nextrace-app",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview",
    "tauri": "tauri"
  },
  "dependencies": {
    "@tauri-apps/api": "^2",
    "@tauri-apps/plugin-dialog": "^2.8.4",
    "@tauri-apps/plugin-opener": "^2"
  },
  "devDependencies": {
    "@tauri-apps/cli": "^2",
    "typescript": "~6.0.3",
    "vite": "^8.0.16"
  }
}
```


## Archivo: `nextrace-app/src-tauri/src/lib.rs`

```rust
mod notes;

use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use nextrace_core::{
    analyze_capture, analyze_flows, build_investigation_timeline, correlate_events,
    detect_anomalies_with_config, detect_baseline_anomalies_with_config,
    export_events_csv, export_events_json, import_source, open_project, save_project,
    write_markdown_report,
    AnomalyConfig, AssetId, AssetKind, BaselineConfig, CorrelationBasis, EventKind,
    EventQuery, FindingKind, Investigation, InvestigationId, NetworkEvent,
    Protocol, Severity, SourceFormat, SourceId, TimelineEntryKind,
};

// =====================================================================
// DTOs
// =====================================================================

#[derive(Serialize)]
struct TopAssetDto { id: u64, value: String, kind: String, total_bytes: u64, flow_count: u64 }

#[derive(Serialize)]
struct KindCountDto { kind: String, count: usize }

#[derive(Serialize)]
struct ProtocolStatDto { protocol: String, flow_count: u64, packet_count: u64, captured_bytes: u64 }

#[derive(Serialize)]
struct EndpointStatDto { asset_id: u64, value: String, flow_count: u64, packets_sent: u64, packets_received: u64, bytes_sent: u64, bytes_received: u64 }

#[derive(Serialize)]
struct FlowStatsDto {
    flow_count: u64, packet_count: u64, captured_bytes: u64, original_bytes: u64,
    bidirectional_flow_count: u64,
    protocols: Vec<ProtocolStatDto>,
    endpoints: Vec<EndpointStatDto>,
}

#[derive(Serialize)]
struct OverviewDto {
    sources: usize, sources_analyzed: usize, assets: usize, events: usize, flows: usize, findings: usize,
    dns_queries: usize, dns_responses: usize, dns_resolutions: usize,
    tls_client_hellos: usize, http_requests: usize, http_responses: usize,
    top_assets: Vec<TopAssetDto>,
    kind_distribution: Vec<KindCountDto>,
    flow_stats: FlowStatsDto,
}

#[derive(Serialize)]
struct EventDto {
    id: u64, timestamp_ns: Option<i64>, kind: String, summary: String,
    source_asset: Option<String>, destination_asset: Option<String>,
    source_port: Option<u16>, destination_port: Option<u16>,
    protocol: Option<String>, evidence_ids: Vec<u64>,
    tcp_flags: Option<String>,
}

#[derive(Serialize)]
struct FlowDto {
    id: u64, protocol: String,
    endpoint_a: String, endpoint_a_port: Option<u16>,
    endpoint_b: String, endpoint_b_port: Option<u16>,
    service_a: Option<String>,
    service_b: Option<String>,
    flags: Option<String>, // <-- NUEVO CAMPO AGRUPADO
    first_seen_ns: i64, last_seen_ns: i64,
    duration_ns: Option<u64>,
    packets_per_second: Option<f64>,
    bytes_per_second: Option<f64>,
    packet_count: u64, captured_bytes: u64, bidirectional: bool,
}

#[derive(Serialize)]
struct FindingDto {
    id: u64, severity: String, kind: String, title: String, description: String,
    confidence_percent: Option<u8>, evidence_ids: Vec<u64>,
}

#[derive(Serialize)]
struct SourceDto {
    id: u64, file_name: String, format: String, size_bytes: u64,
    sha256: Option<String>, imported_at_ns: i64, analyzed: bool,
}

#[derive(Serialize)]
struct AssetDto {
    id: u64, value: String, kind: String, label: Option<String>,
    flow_count: u64, packets_sent: u64, packets_received: u64,
    bytes_sent: u64, bytes_received: u64, event_count: u64,
}

#[derive(Serialize)]
struct AssetDetailDto { asset: AssetDto, flows: Vec<FlowDto>, events: Vec<EventDto> }

#[derive(Serialize)]
struct EvidenceExcerptDto { id: u64, frame_number: u64, excerpt: Option<String> }

#[derive(Serialize)]
struct EventDetailDto {
    event: EventDto, evidence: Vec<EvidenceExcerptDto>,
    related_events: Vec<EventDto>, flow: Option<FlowDto>,
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
struct TimelineV2Dto { events_without_timestamp: usize, entries: Vec<TimelineEntryV2Dto> }

#[derive(Serialize)]
struct TimelineEntryV2Dto {
    timestamp_ns: i64, kind: String,
    event_id: Option<u64>, event_summary: Option<String>, event_kind: Option<String>,
    associated_flow_ids: Option<Vec<u64>>,
    flow_id: Option<u64>, flow_endpoint_a: Option<String>, flow_endpoint_b: Option<String>,
    flow_packet_count: Option<u64>, flow_captured_bytes: Option<u64>,
    evidence_ids: Vec<u64>,
}

#[derive(Serialize)]
struct DnsResolutionDto { hostname: String, ip: String, timestamp_ns: Option<i64>, event_id: u64, summary: String }

#[derive(Serialize)]
struct HttpHostDto { host: String, request_count: usize, methods: Vec<String>, sample_uris: Vec<String> }

#[derive(Serialize)]
struct TlsSniDto { sni: String, count: usize, versions: Vec<String>, alpn: Vec<String>, client_ips: Vec<String> }

#[derive(Serialize)]
struct ProjectInfoDto { name: String, description: Option<String>, created_at_ns: i64, investigation_id: u64 }

#[derive(Serialize)]
struct IntegrityReportDto { sources_verified: usize, sources_without_hash: usize, total_sources: usize, all_ok: bool }

#[derive(Serialize)]
struct NoteDto { id: u64, target_type: String, target_id: u64, text: String, created_at_ns: i64 }

#[derive(Serialize)]
struct DiffDto {
    name_a: String, name_b: String,
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
    text: Option<String>, kind: Option<String>, protocol: Option<String>, limit: Option<usize>,
    offset: Option<usize>,
    time_start_ns: Option<i64>, time_end_ns: Option<i64>,
    min_port: Option<u16>, max_port: Option<u16>,
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
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as i64).unwrap_or(0)
}

fn is_local_or_loopback(value: &str) -> bool {
    let v = value.trim();
    v == "127.0.0.1" || v == "::1" || v == "0.0.0.0" || v == "::"
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
        20 | 21 => "FTP", 22 => "SSH", 23 => "Telnet", 25 | 587 => "SMTP",
        53 => "DNS", 67 | 68 => "DHCP", 69 => "TFTP", 80 | 8080 | 8000 => "HTTP",
        110 => "POP3", 123 => "NTP", 135 => "RPC", 137 | 138 | 139 => "NetBIOS",
        143 => "IMAP", 161 | 162 => "SNMP", 389 => "LDAP", 443 | 8443 => "HTTPS",
        445 => "SMB", 465 => "SMTPS", 993 => "IMAPS", 995 => "POP3S",
        1433 => "MSSQL", 1521 => "Oracle", 3306 => "MySQL", 3389 => "RDP",
        5060 | 5061 => "SIP", 5432 => "PostgreSQL", 5900 => "VNC",
        6379 => "Redis", 9200 => "Elasticsearch", 27017 => "MongoDB",
        _ => return None,
    };
    Some(name.to_string())
}

fn build_asset_index(inv: &Investigation) -> HashMap<u64, String> {
    inv.assets().iter().map(|a| (a.id.0, a.value.clone())).collect()
}

fn resolve_asset_fast(index: &HashMap<u64, String>, id: AssetId) -> String {
    index.get(&id.0).cloned().unwrap_or_else(|| format!("AssetId({})", id.0))
}

fn event_kind_str(k: &EventKind) -> &'static str {
    match k {
        EventKind::Packet => "Packet", EventKind::NetworkFlow => "NetworkFlow",
        EventKind::FirewallAllow => "FirewallAllow", EventKind::FirewallDeny => "FirewallDeny",
        EventKind::AuthenticationSuccess => "AuthenticationSuccess",
        EventKind::AuthenticationFailure => "AuthenticationFailure",
        EventKind::ConfigurationChange => "ConfigurationChange",
        EventKind::ServiceState => "ServiceState",
        EventKind::DnsQuery => "DnsQuery", EventKind::DnsResponse => "DnsResponse",
        EventKind::DnsResolution => "DnsResolution",
        EventKind::TlsClientHello => "TlsClientHello",
        EventKind::HttpRequest => "HttpRequest", EventKind::HttpResponse => "HttpResponse",
        EventKind::Other(_) => "Other",
    }
}

fn protocol_str(p: &Protocol) -> &str {
    match p {
        Protocol::Tcp => "TCP", Protocol::Udp => "UDP",
        Protocol::Icmp => "ICMP", Protocol::IcmpV6 => "ICMPv6",
        Protocol::Other(s) => s.as_str(),
    }
}

fn severity_str(s: &Severity) -> &'static str {
    match s {
        Severity::Info => "Info", Severity::Low => "Low", Severity::Medium => "Medium",
        Severity::High => "High", Severity::Critical => "Critical",
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
        AssetKind::IpAddress => "IpAddress", AssetKind::MacAddress => "MacAddress",
        AssetKind::Hostname => "Hostname", AssetKind::Network => "Network",
        AssetKind::Device => "Device", AssetKind::Service => "Service",
    }
}

fn source_format_str(f: &SourceFormat) -> &'static str {
    match f {
        SourceFormat::Pcap => "PCAP", SourceFormat::PcapNg => "PCAPNG",
        SourceFormat::FirewallLog => "FirewallLog", SourceFormat::RouterConfig => "RouterConfig",
        SourceFormat::SwitchConfig => "SwitchConfig", SourceFormat::ServerLog => "ServerLog",
        SourceFormat::Csv => "CSV", SourceFormat::Json => "JSON",
        SourceFormat::Text => "Text", SourceFormat::Unknown => "Unknown",
    }
}

fn event_to_dto_fast(e: &NetworkEvent, idx: &HashMap<u64, String>) -> EventDto {
    EventDto {
        id: e.id.0, timestamp_ns: e.timestamp_unix_ns,
        kind: event_kind_str(&e.kind).to_string(), summary: e.summary.clone(),
        source_asset: e.source_asset.map(|id| resolve_asset_fast(idx, id)),
        destination_asset: e.destination_asset.map(|id| resolve_asset_fast(idx, id)),
        source_port: e.source_port, destination_port: e.destination_port,
        protocol: e.protocol.as_ref().map(|p| protocol_str(p).to_string()),
        evidence_ids: e.evidence_ids.iter().map(|id| id.0).collect(),
        tcp_flags: e.tcp_flags.clone(),
    }
}

// HELPER PARA AGRUPAR FLAGS DE UN FLUJO
fn get_flow_flags(
    flow: &nextrace_core::NetworkFlow,
    event_flags_map: &HashMap<(AssetId, AssetId, Option<u16>, Option<u16>), HashSet<String>>,
) -> Option<String> {
    let mut merged = HashSet::new();
    let key1 = (flow.endpoint_a, flow.endpoint_b, flow.endpoint_a_port, flow.endpoint_b_port);
    let key2 = (flow.endpoint_b, flow.endpoint_a, flow.endpoint_b_port, flow.endpoint_a_port);
    
    if let Some(f) = event_flags_map.get(&key1) { merged.extend(f.clone()); }
    if let Some(f) = event_flags_map.get(&key2) { merged.extend(f.clone()); }
    
    if merged.is_empty() { None } else {
        let mut v: Vec<_> = merged.into_iter().collect();
        // Ordenar lógicamente: SYN, ACK, PSH, FIN, RST, URG
        v.sort_by_key(|f| match f.as_str() {
            "SYN" => 0, "ACK" => 1, "PSH" => 2, "FIN" => 3, "RST" => 4, _ => 5
        });
        Some(v.join(", "))
    }
}

fn flow_to_dto_fast(
    f: &nextrace_core::NetworkFlow, 
    idx: &HashMap<u64, String>,
    event_flags_map: &HashMap<(AssetId, AssetId, Option<u16>, Option<u16>), HashSet<String>>,
) -> FlowDto {
    FlowDto {
        id: f.id.0, protocol: protocol_str(&f.protocol).to_string(),
        endpoint_a: resolve_asset_fast(idx, f.endpoint_a), endpoint_a_port: f.endpoint_a_port,
        endpoint_b: resolve_asset_fast(idx, f.endpoint_b), endpoint_b_port: f.endpoint_b_port,
        service_a: port_to_service(f.endpoint_a_port),
        service_b: port_to_service(f.endpoint_b_port),
        flags: get_flow_flags(f, event_flags_map),
        first_seen_ns: f.first_seen_unix_ns, last_seen_ns: f.last_seen_unix_ns,
        duration_ns: f.duration_ns(),
        packets_per_second: f.packets_per_second(),
        bytes_per_second: f.captured_bytes_per_second(),
        packet_count: f.packet_count, captured_bytes: f.captured_bytes,
        bidirectional: f.is_bidirectional(),
    }
}

fn build_event_flags_map(inv: &Investigation) -> HashMap<(AssetId, AssetId, Option<u16>, Option<u16>), HashSet<String>> {
    let mut map = HashMap::new();
    for event in inv.events() {
        if let (Some(sa), Some(da), Some(flags_str)) = (event.source_asset, event.destination_asset, &event.tcp_flags) {
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
    let mut protocols: Vec<ProtocolStatDto> = stats.protocols.iter().map(|p| ProtocolStatDto {
        protocol: protocol_str(&p.protocol).to_string(),
        flow_count: p.flow_count, packet_count: p.packet_count, captured_bytes: p.captured_bytes,
    }).collect();
    protocols.truncate(20);
    let mut endpoints: Vec<EndpointStatDto> = stats.endpoints.iter().map(|e| EndpointStatDto {
        asset_id: e.asset_id.0,
        value: resolve_asset_fast(idx, e.asset_id),
        flow_count: e.flow_count,
        packets_sent: e.packets_sent, packets_received: e.packets_received,
        bytes_sent: e.bytes_sent, bytes_received: e.bytes_received,
    }).collect();
    endpoints.truncate(20);
    FlowStatsDto {
        flow_count: stats.flow_count, packet_count: stats.packet_count,
        captured_bytes: stats.captured_bytes, original_bytes: stats.original_bytes,
        bidirectional_flow_count: stats.bidirectional_flow_count,
        protocols, endpoints,
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
    let Some(start) = s.find(&m) else { return Vec::new() };
    let rest = &s[start + m.len()..];
    let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    rest[..end].split(',').filter(|x| !x.is_empty()).map(|x| x.to_string()).collect()
}

fn format_hex_dump(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "(frame vacío)".to_string(); }
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let offset = i * 16;
        let mut hex = String::new();
        for j in 0..16 {
            if j == 8 { hex.push(' '); }
            if j < chunk.len() { hex.push_str(&format!("{:02x} ", chunk[j])); }
            else { hex.push_str("   "); }
        }
        let ascii: String = chunk.iter()
            .map(|b| if (0x20..=0x7e).contains(b) { *b as char } else { '.' })
            .collect();
        out.push_str(&format!("{:08x}  {} |{}|\n", offset, hex.trim_end(), ascii));
    }
    out
}

fn read_frame_hex(path: &std::path::Path, frame_number: u64) -> Result<String, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("Error abriendo: {e}"))?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).map_err(|e| format!("Error leyendo: {e}"))?;
    file.seek(SeekFrom::Start(0)).map_err(|e| format!("Error rebobinando: {e}"))?;

    let frame = if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        let mut reader = nextrace_core::PcapNgReader::new(file);
        let mut n = 0u64;
        loop {
            match reader.next_packet() {
                Ok(Some(pkt)) => { n += 1; if n == frame_number { break Ok(pkt.raw_frame); } }
                Ok(None) => break Err(format!("Frame {frame_number} no encontrado")),
                Err(e) => break Err(format!("Error PCAPNG: {e}")),
            }
        }
    } else {
        let mut reader = nextrace_core::PcapReader::new(file).map_err(|e| format!("{e}"))?;
        let mut n = 0u64;
        loop {
            match reader.next_packet() {
                Ok(Some(pkt)) => { n += 1; if n == frame_number { break Ok(pkt.raw_frame); } }
                Ok(None) => break Err(format!("Frame {frame_number} no encontrado")),
                Err(e) => break Err(format!("Error PCAP: {e}")),
            }
        }
    }?;
    Ok(format_hex_dump(&frame))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn fmt_ts_html(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let nanos = ns.rem_euclid(1_000_000_000);
    format!("{secs}.{nanos:09} UTC")
}

fn svg_bars(title: &str, items: &[(String, u64)]) -> String {
    if items.is_empty() { return String::new(); }
    let max = items.iter().map(|(_, v)| *v).max().unwrap_or(1);
    let bar_height = 26;
    let height = (items.len() as u32) * bar_height + 60;
    let width = 900u32;
    let mut s = String::new();
    s.push_str(&format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {} {}\" width=\"100%\" style=\"max-width:{0}px;background:#161b22;border-radius:6px;font-family:sans-serif\">", width, height));
    s.push_str(&format!("<text x=\"20\" y=\"32\" fill=\"#58a6ff\" font-size=\"15\" font-weight=\"600\">{}</text>", html_escape(title)));
    for (i, (label, value)) in items.iter().enumerate() {
        let y = 50 + (i as u32) * bar_height;
        let bar_w = ((*value as f64 / max as f64) * 550.0) as u32;
        s.push_str(&format!("<text x=\"20\" y=\"{}\" fill=\"#e6edf3\" font-size=\"12\">{}</text>", y + 16, html_escape(label)));
        s.push_str(&format!("<rect x=\"200\" y=\"{}\" width=\"{}\" height=\"14\" fill=\"#58a6ff\" rx=\"2\"/>", y + 5, bar_w));
        s.push_str(&format!("<text x=\"{}\" y=\"{}\" fill=\"#8b949e\" font-size=\"11\">{}</text>", 210 + bar_w, y + 16, value));
    }
    s.push_str("</svg>");
    s
}

fn flow_key_string(f: &nextrace_core::NetworkFlow, idx: &HashMap<u64, String>) -> String {
    format!(
        "{}:{} → {}:{} ({})",
        resolve_asset_fast(idx, f.endpoint_a),
        f.endpoint_a_port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string()),
        resolve_asset_fast(idx, f.endpoint_b),
        f.endpoint_b_port.map(|p| p.to_string()).unwrap_or_else(|| "—".to_string()),
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
        Ok((inv, r)) => Ok(format!("{} eventos · {} flujos · {} hallazgos · {} fuentes", inv.events().len(), inv.flows().len(), inv.findings().len(), r.sources_verified + r.sources_without_hash)),
        Err(e) => Err(format!("Error abriendo proyecto: {e}")),
    }
}

#[tauri::command]
async fn cmd_get_project_info(project_dir: String) -> Result<ProjectInfoDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    Ok(ProjectInfoDto { name: inv.name.clone(), description: inv.description.clone(), created_at_ns: inv.created_at_unix_ns, investigation_id: inv.id.0 })
}

#[tauri::command]
async fn cmd_update_project_description(project_dir: String, description: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    inv.description = if description.trim().is_empty() { None } else { Some(description.trim().to_string()) };
    save_project(&inv, &dir).map_err(|e| format!("{e}"))?;
    Ok("Descripción actualizada".to_string())
}

#[tauri::command]
async fn cmd_verify_integrity(project_dir: String) -> Result<IntegrityReportDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, r) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let total = inv.sources().len();
    Ok(IntegrityReportDto { sources_verified: r.sources_verified, sources_without_hash: r.sources_without_hash, total_sources: total, all_ok: r.sources_verified == total && total > 0 })
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
            Ok(format!("Fuente {} importada: {} ({} bytes)", s.id.0, s.file_name, s.size_bytes))
        }
        Err(e) => Err(format!("Error importando: {e}")),
    }
}

#[tauri::command]
async fn cmd_analyze(project_dir: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("Error abriendo proyecto: {e}"))?;
    let ids: Vec<u64> = inv.sources().iter().map(|s| s.id.0).collect();
    if ids.is_empty() { return Err("No hay fuentes importadas".to_string()); }
    let mut lines = Vec::new();
    for sid in ids {
        if inv.evidences().iter().any(|ev| ev.source_id == SourceId(sid)) { continue; }
        let src = inv.sources().iter().find(|s| s.id.0 == sid).cloned().ok_or_else(|| format!("Fuente {sid} no encontrada"))?;
        let path = dir.join(&src.relative_path);
        let reader = std::fs::File::open(&path).map_err(|e| format!("Error abriendo {}: {}", path.display(), e))?;
        let r = analyze_capture(reader, SourceId(sid), &mut inv).map_err(|e| format!("Error analizando: {e:?}"))?;
        lines.push(format!("Fuente {}: {} paquetes, {} eventos, {} flujos", sid, r.packets_read, r.events_created, r.flows_created));
    }
    save_project(&inv, &dir).map_err(|e| format!("Error guardando: {e}"))?;
    if lines.is_empty() { Ok("Todas las fuentes ya estaban analizadas".to_string()) } else { Ok(lines.join("\n")) }
}

#[tauri::command]
async fn cmd_get_anomaly_config() -> AnomalyConfigDto { AnomalyConfigDto::from(AnomalyConfig::default()) }

#[tauri::command]
async fn cmd_detect_anomalies_with_config(project_dir: String, config: AnomalyConfigDto) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("Error abriendo proyecto: {e}"))?;
    let cfg: AnomalyConfig = config.into();
    let r = detect_anomalies_with_config(&mut inv, &cfg).map_err(|e| format!("Error detectando: {e}"))?;
    save_project(&inv, &dir).map_err(|e| format!("Error guardando: {e}"))?;
    Ok(format!("{} reglas · {} propuestas · {} añadidas · {} duplicadas", r.rules_evaluated, r.findings_proposed, r.findings_added.len(), r.findings_skipped_duplicate))
}

#[tauri::command]
async fn cmd_get_baseline_config() -> BaselineConfigDto {
    let c = BaselineConfig::default();
    BaselineConfigDto { min_entities_per_kind: c.min_entities_per_kind, modified_zscore_threshold: c.modified_zscore_threshold, high_zscore_threshold: c.high_zscore_threshold, min_flows_per_asset: c.min_flows_per_asset, enable_bytes_baseline: c.enable_bytes_baseline, enable_flow_count_baseline: c.enable_flow_count_baseline }
}

#[tauri::command]
async fn cmd_detect_baseline_anomalies(project_dir: String, config: BaselineConfigDto) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (mut inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let cfg = BaselineConfig { min_entities_per_kind: config.min_entities_per_kind, modified_zscore_threshold: config.modified_zscore_threshold, high_zscore_threshold: config.high_zscore_threshold, min_flows_per_asset: config.min_flows_per_asset, enable_bytes_baseline: config.enable_bytes_baseline, enable_flow_count_baseline: config.enable_flow_count_baseline };
    let report = detect_baseline_anomalies_with_config(&mut inv, &cfg).map_err(|e| format!("Error baseline: {e}"))?;
    save_project(&inv, &dir).map_err(|e| format!("{e}"))?;
    Ok(format!("{} reglas · {} tipos con datos · {} añadidos · {} duplicados", report.rules_evaluated, report.asset_kinds_with_enough_data, report.findings_added.len(), report.findings_skipped_duplicate))
}

#[tauri::command]
async fn cmd_get_overview(project_dir: String) -> Result<OverviewDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let (mut dq, mut dr, mut dres, mut tls, mut hq, mut hr) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut kind_counts: HashMap<&'static str, usize> = HashMap::new();
    for e in inv.events() {
        *kind_counts.entry(event_kind_str(&e.kind)).or_insert(0) += 1;
        match &e.kind {
            EventKind::DnsQuery => dq += 1, EventKind::DnsResponse => dr += 1, EventKind::DnsResolution => dres += 1, EventKind::TlsClientHello => tls += 1, EventKind::HttpRequest => hq += 1, EventKind::HttpResponse => hr += 1, _ => {}
        }
    }
    let mut kind_distribution: Vec<KindCountDto> = kind_counts.into_iter().map(|(k, c)| KindCountDto { kind: k.to_string(), count: c }).collect();
    kind_distribution.sort_by(|a, b| b.count.cmp(&a.count));
    let mut traffic: HashMap<u64, (u64, u64)> = HashMap::new();
    for flow in inv.flows() {
        for id in [flow.endpoint_a, flow.endpoint_b] {
            let e = traffic.entry(id.0).or_insert((0, 0));
            e.0 += flow.captured_bytes; e.1 += 1;
        }
    }
    let mut top: Vec<_> = traffic.into_iter().collect();
    top.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    let top_assets: Vec<TopAssetDto> = top.iter().take(10).map(|(id, (bytes, flows))| {
        let a = inv.assets().iter().find(|x| x.id.0 == *id);
        TopAssetDto { id: *id, value: a.map(|x| x.value.clone()).unwrap_or_default(), kind: a.map(|x| asset_kind_str(&x.kind).to_string()).unwrap_or_default(), total_bytes: *bytes, flow_count: *flows }
    }).collect();
    let analyzed = inv.sources().iter().filter(|s| inv.evidences().iter().any(|e| e.source_id == s.id)).count();
    Ok(OverviewDto { sources: inv.sources().len(), sources_analyzed: analyzed, assets: inv.assets().len(), events: inv.events().len(), flows: inv.flows().len(), findings: inv.findings().len(), dns_queries: dq, dns_responses: dr, dns_resolutions: dres, tls_client_hellos: tls, http_requests: hq, http_responses: hr, top_assets, kind_distribution, flow_stats: flow_stats_dto(&inv, &idx) })
}

#[tauri::command]
async fn cmd_list_events(project_dir: String, filter: EventFilter) -> Result<Vec<EventDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let mut q = EventQuery::new();
    if let Some(t) = filter.text { if !t.trim().is_empty() { q.text_contains = Some(t); } }
    if let Some(k) = filter.kind {
        if !k.is_empty() { match k.as_str() { "Packet" => q.kinds.push(EventKind::Packet), "DnsQuery" => q.kinds.push(EventKind::DnsQuery), "DnsResponse" => q.kinds.push(EventKind::DnsResponse), "DnsResolution" => q.kinds.push(EventKind::DnsResolution), "TlsClientHello" => q.kinds.push(EventKind::TlsClientHello), "HttpRequest" => q.kinds.push(EventKind::HttpRequest), "HttpResponse" => q.kinds.push(EventKind::HttpResponse), _ => {} } }
    }
    if let Some(p) = filter.protocol {
        if !p.is_empty() { match p.as_str() { "TCP" => q.protocols.push(Protocol::Tcp), "UDP" => q.protocols.push(Protocol::Udp), _ => {} } }
    }
    if let (Some(s), Some(e)) = (filter.time_start_ns, filter.time_end_ns) { q.time_range = Some((s, e)); }
    if let Some(p) = filter.min_port { q.min_port = Some(p); }
    if let Some(p) = filter.max_port { q.max_port = Some(p); }
    for id in filter.asset_ids { q.asset_ids.push(AssetId(id)); }
    if let Some(av) = &filter.asset_value {
        if !av.is_empty() { if let Some(asset) = inv.assets().iter().find(|a| &a.value == av) { q.asset_ids.push(asset.id); } }
    }
    q.limit = None;
    for f in filter.tcp_flags { q.tcp_flags.push(f); }
    
    let mut events = q.run(&inv);
    if filter.exclude_loopback { events.retain(|e| !is_local_or_loopback(&e.source_asset.map(|id| resolve_asset_fast(&idx, id)).unwrap_or_default()) && !is_local_or_loopback(&e.destination_asset.map(|id| resolve_asset_fast(&idx, id)).unwrap_or_default())); }
    if !filter.ioc_tokens.is_empty() {
        let tokens: Vec<String> = filter.ioc_tokens.iter().map(|t| t.trim().to_lowercase()).filter(|t| !t.is_empty()).collect();
        events.retain(|e| {
            let haystack = format!("{} {} {}", e.summary.to_lowercase(), e.source_asset.map(|id| resolve_asset_fast(&idx, id).to_lowercase()).unwrap_or_default(), e.destination_asset.map(|id| resolve_asset_fast(&idx, id).to_lowercase()).unwrap_or_default());
            tokens.iter().any(|t| haystack.contains(t))
        });
    }
    let offset = filter.offset.unwrap_or(0);
    let limit = filter.limit.unwrap_or(200).min(2000);
    Ok(events.iter().skip(offset).take(limit).map(|e| event_to_dto_fast(e, &idx)).collect())
}

#[tauri::command]
async fn cmd_list_flows(project_dir: String) -> Result<Vec<FlowDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let flags_map = build_event_flags_map(&inv);
    Ok(inv.flows().iter().map(|f| flow_to_dto_fast(f, &idx, &flags_map)).collect())
}

#[tauri::command]
async fn cmd_list_flow_events(project_dir: String, flow_id: u64) -> Result<Vec<EventDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let flow = inv.flows().iter().find(|f| f.id.0 == flow_id).ok_or_else(|| format!("Flujo {flow_id} no encontrado"))?;
    let (a, b) = (flow.endpoint_a, flow.endpoint_b);
    let (ap, bp) = (flow.endpoint_a_port, flow.endpoint_b_port);
    let mut events: Vec<EventDto> = inv.events().iter().filter(|e| {
        let ep = (e.source_asset == Some(a) && e.destination_asset == Some(b)) || (e.source_asset == Some(b) && e.destination_asset == Some(a));
        if !ep { return false; }
        let port = (e.source_port == ap && e.destination_port == bp) || (e.source_port == bp && e.destination_port == ap);
        if !port { return false; }
        match (&e.protocol, &flow.protocol) { (Some(p), fp) => p == fp, (None, _) => true }
    }).map(|e| event_to_dto_fast(e, &idx)).collect();
    events.sort_by_key(|e| e.timestamp_ns);
    Ok(events)
}

#[tauri::command]
async fn cmd_list_findings(project_dir: String) -> Result<Vec<FindingDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    Ok(inv.findings().iter().map(|f| FindingDto { id: f.id.0, severity: severity_str(&f.severity).to_string(), kind: finding_kind_str(&f.kind).to_string(), title: f.title.clone(), description: f.description.clone(), confidence_percent: f.confidence_percent, evidence_ids: f.evidence_ids.iter().map(|id| id.0).collect() }).collect())
}

#[tauri::command]
async fn cmd_list_sources(project_dir: String) -> Result<Vec<SourceDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    Ok(inv.sources().iter().map(|s| SourceDto { id: s.id.0, file_name: s.file_name.clone(), format: source_format_str(&s.format).to_string(), size_bytes: s.size_bytes, sha256: s.sha256.clone(), imported_at_ns: s.imported_at_unix_ns, analyzed: inv.evidences().iter().any(|e| e.source_id == s.id) }).collect())
}

#[tauri::command]
async fn cmd_list_assets(project_dir: String) -> Result<Vec<AssetDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let mut fs: HashMap<u64, (u64, u64, u64, u64)> = HashMap::new();
    for flow in inv.flows() {
        let a = fs.entry(flow.endpoint_a.0).or_insert((0, 0, 0, 0)); a.0 += 1; a.1 += flow.packets_a_to_b; a.2 += flow.packets_b_to_a; a.3 += flow.captured_bytes;
        let b = fs.entry(flow.endpoint_b.0).or_insert((0, 0, 0, 0)); b.0 += 1; b.1 += flow.packets_b_to_a; b.2 += flow.packets_a_to_b; b.3 += flow.captured_bytes;
    }
    let mut ec: HashMap<u64, u64> = HashMap::new();
    for e in inv.events() { for o in [e.source_asset, e.destination_asset] { if let Some(id) = o { *ec.entry(id.0).or_insert(0) += 1; } } }
    let mut out: Vec<AssetDto> = inv.assets().iter().map(|a| {
        let (fc, ps, pr, tb) = fs.get(&a.id.0).copied().unwrap_or((0, 0, 0, 0));
        AssetDto { id: a.id.0, value: a.value.clone(), kind: asset_kind_str(&a.kind).to_string(), label: a.label.clone(), flow_count: fc, packets_sent: ps, packets_received: pr, bytes_sent: tb / 2, bytes_received: tb / 2, event_count: ec.get(&a.id.0).copied().unwrap_or(0) }
    }).collect();
    out.sort_by(|a, b| b.event_count.cmp(&a.event_count));
    Ok(out)
}

#[tauri::command]
async fn cmd_get_asset_detail(project_dir: String, asset_id: u64) -> Result<AssetDetailDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let flags_map = build_event_flags_map(&inv);
    let asset = inv.assets().iter().find(|a| a.id.0 == asset_id).ok_or_else(|| format!("Activo {asset_id} no encontrado"))?;
    let mut flow_count = 0u64; let mut pkt_out = 0u64; let mut pkt_in = 0u64; let mut total_bytes = 0u64;
    let mut asset_flows: Vec<FlowDto> = Vec::new();
    for flow in inv.flows() {
        let in_a = flow.endpoint_a.0 == asset_id; let in_b = flow.endpoint_b.0 == asset_id;
        if !in_a && !in_b { continue; }
        flow_count += 1;
        if in_a { pkt_out += flow.packets_a_to_b; pkt_in += flow.packets_b_to_a; } else { pkt_out += flow.packets_b_to_a; pkt_in += flow.packets_a_to_b; }
        total_bytes += flow.captured_bytes;
        if asset_flows.len() < 100 { asset_flows.push(flow_to_dto_fast(flow, &idx, &flags_map)); }
    }
    let mut asset_events: Vec<EventDto> = Vec::new(); let mut event_count = 0u64;
    for e in inv.events() {
        let in_s = e.source_asset.map(|id| id.0 == asset_id).unwrap_or(false); let in_d = e.destination_asset.map(|id| id.0 == asset_id).unwrap_or(false);
        if !in_s && !in_d { continue; }
        event_count += 1;
        if asset_events.len() < 200 { asset_events.push(event_to_dto_fast(e, &idx)); }
    }
    let asset_dto = AssetDto { id: asset.id.0, value: asset.value.clone(), kind: asset_kind_str(&asset.kind).to_string(), label: asset.label.clone(), flow_count, packets_sent: pkt_out, packets_received: pkt_in, bytes_sent: total_bytes / 2, bytes_received: total_bytes / 2, event_count };
    Ok(AssetDetailDto { asset: asset_dto, flows: asset_flows, events: asset_events })
}

#[tauri::command]
async fn cmd_get_event_detail(project_dir: String, event_id: u64) -> Result<EventDetailDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let flags_map = build_event_flags_map(&inv);
    let event = inv.events().iter().find(|e| e.id.0 == event_id).ok_or_else(|| format!("Evento {event_id} no encontrado"))?;
    let event_dto = event_to_dto_fast(event, &idx);
    let evidence: Vec<EvidenceExcerptDto> = event.evidence_ids.iter().filter_map(|eid| {
        inv.evidences().iter().find(|e| e.id == *eid).map(|e| {
            let frame_number = match &e.location { nextrace_core::EvidenceLocation::PacketFrame { frame_number } => *frame_number, _ => 0 };
            EvidenceExcerptDto { id: e.id.0, frame_number, excerpt: e.excerpt.clone() }
        })
    }).collect();
    let related: Vec<EventDto> = match event.timestamp_unix_ns {
        Some(ts) => {
            let window = 60_000_000_000i64; let start = inv.events().len().saturating_sub(2000);
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
            inv.flows().iter().find(|f| {
                let ep = |aid: AssetId, bid: AssetId| (event.source_asset == Some(aid) && event.destination_asset == Some(bid)) || (event.source_asset == Some(bid) && event.destination_asset == Some(aid));
                let port = (event.source_port == f.endpoint_a_port && event.destination_port == f.endpoint_b_port) || (event.source_port == f.endpoint_b_port && event.destination_port == f.endpoint_a_port);
                let proto = match (&event.protocol, &f.protocol) { (Some(a), b) => a == b, (None, _) => true };
                ep(f.endpoint_a, f.endpoint_b) && port && proto
            }).map(|f| flow_to_dto_fast(f, &idx, &flags_map))
        } else { None }
    } else { None };
    Ok(EventDetailDto { event: event_dto, evidence, related_events: related, flow, tcp_flags: event.tcp_flags.clone() })
}

#[tauri::command]
async fn cmd_get_frame_hex(project_dir: String, evidence_id: u64) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let ev = inv.evidences().iter().find(|e| e.id.0 == evidence_id).ok_or_else(|| format!("Evidencia {evidence_id} no encontrada"))?;
    let frame_number = match &ev.location { nextrace_core::EvidenceLocation::PacketFrame { frame_number } => *frame_number, _ => return Err("Evidencia sin frame asociado".to_string()) };
    let source = inv.sources().iter().find(|s| s.id == ev.source_id).ok_or_else(|| "Fuente de evidencia no encontrada".to_string())?;
    let capture_path = dir.join(&source.relative_path);
    read_frame_hex(&capture_path, frame_number)
}

#[tauri::command]
async fn cmd_get_correlations(project_dir: String, window_ns: u64) -> Result<CorrelationDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let total_events = inv.events().len();
    let mut asset_degree: HashMap<u64, usize> = HashMap::new();
    for e in inv.events() { for opt in [e.source_asset, e.destination_asset] { if let Some(id) = opt { *asset_degree.entry(id.0).or_insert(0) += 1; } } }
    const HUB_RATIO: f64 = 0.15; const MAX_EVENTS: usize = 1000;
    let hub_threshold = ((total_events as f64) * HUB_RATIO).ceil() as usize;
    let hub_threshold = hub_threshold.max(3);
    let is_hub = |id: u64| -> bool {
        let degree = asset_degree.get(&id).copied().unwrap_or(0);
        if degree < hub_threshold && degree < 5 { return false; }
        let value = idx.get(&id).map(|s| s.as_str()).unwrap_or("");
        is_local_or_loopback(value) || degree >= hub_threshold
    };
    let mut candidates: Vec<&NetworkEvent> = inv.events().iter().filter(|e| e.timestamp_unix_ns.is_some()).filter(|e| !matches!(e.kind, EventKind::Packet)).filter(|e| {
        let src_hub = e.source_asset.map(|id| is_hub(id.0)).unwrap_or(true);
        let dst_hub = e.destination_asset.map(|id| is_hub(id.0)).unwrap_or(true);
        !(src_hub && dst_hub)
    }).collect();
    let total_candidates = candidates.len();
    candidates.sort_by_key(|e| e.timestamp_unix_ns);
    let start = candidates.len().saturating_sub(MAX_EVENTS);
    let subset: Vec<NetworkEvent> = candidates[start..].iter().map(|e| (*e).clone()).collect();
    let truncated = total_candidates > MAX_EVENTS;
    let report = correlate_events(&subset, window_ns);
    let mut groups_map: HashMap<u64, HashSet<u64>> = HashMap::new();
    let event_lookup: HashMap<u64, &NetworkEvent> = inv.events().iter().map(|e| (e.id.0, e)).collect();
    for c in &report.correlations {
        for asset_id in &c.shared_assets {
            if !is_hub(asset_id.0) {
                let entry = groups_map.entry(asset_id.0).or_default();
                entry.insert(c.first_event.0); entry.insert(c.second_event.0);
            }
        }
    }
    let mut groups: Vec<CorrelationGroupDto> = groups_map.into_iter().map(|(asset_id, event_ids)| {
        let asset_val = resolve_asset_fast(&idx, AssetId(asset_id));
        let mut events: Vec<EventDto> = event_ids.iter().filter_map(|id| event_lookup.get(id)).map(|e| event_to_dto_fast(e, &idx)).collect();
        events.sort_by_key(|e| e.timestamp_ns);
        let time_min_ns = events.first().and_then(|e| e.timestamp_ns).unwrap_or(0); let time_max_ns = events.last().and_then(|e| e.timestamp_ns).unwrap_or(0);
        let mut ev_ids = HashSet::new(); for e in &events { ev_ids.extend(&e.evidence_ids); }
        CorrelationGroupDto { shared_asset: asset_val, event_count: events.len(), events, evidence_ids: ev_ids.into_iter().collect(), time_min_ns, time_max_ns }
    }).collect();
    groups.sort_by(|a, b| b.event_count.cmp(&a.event_count));
    let total_found = groups.len(); let groups = groups.into_iter().take(50).collect();
    Ok(CorrelationDto { window_ns: report.window_ns, events_considered: report.events_considered, events_without_timestamp: report.events_without_timestamp, total_events, total_candidates, truncated, total_found, groups })
}

#[tauri::command]
async fn cmd_get_timeline_v2(project_dir: String) -> Result<TimelineV2Dto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let report = build_investigation_timeline(&inv);
    let entries: Vec<TimelineEntryV2Dto> = report.entries.iter().take(500).map(|entry| match &entry.kind {
        TimelineEntryKind::Event { event_id, associated_flow_ids, summary, evidence_ids } => {
            let kind_str = inv.events().iter().find(|e| e.id == *event_id).map(|e| event_kind_str(&e.kind).to_string()).unwrap_or_default();
            TimelineEntryV2Dto { timestamp_ns: entry.timestamp_unix_ns, kind: "Event".to_string(), event_id: Some(event_id.0), event_summary: Some(summary.clone()), event_kind: Some(kind_str), associated_flow_ids: Some(associated_flow_ids.iter().map(|id| id.0).collect()), flow_id: None, flow_endpoint_a: None, flow_endpoint_b: None, flow_packet_count: None, flow_captured_bytes: None, evidence_ids: evidence_ids.iter().map(|id| id.0).collect() }
        }
        TimelineEntryKind::Flow { flow_id, endpoint_a, endpoint_b, packet_count, captured_bytes, evidence_ids } => {
            TimelineEntryV2Dto { timestamp_ns: entry.timestamp_unix_ns, kind: "Flow".to_string(), event_id: None, event_summary: None, event_kind: None, associated_flow_ids: None, flow_id: Some(flow_id.0), flow_endpoint_a: Some(resolve_asset_fast(&idx, *endpoint_a)), flow_endpoint_b: Some(resolve_asset_fast(&idx, *endpoint_b)), flow_packet_count: Some(*packet_count), flow_captured_bytes: Some(*captured_bytes), evidence_ids: evidence_ids.iter().map(|id| id.0).collect() }
        }
    }).collect();
    Ok(TimelineV2Dto { events_without_timestamp: report.events_without_timestamp, entries })
}

#[tauri::command]
async fn cmd_list_dns_resolutions(project_dir: String) -> Result<Vec<DnsResolutionDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    Ok(inv.events().iter().filter(|e| matches!(e.kind, EventKind::DnsResolution)).take(500).map(|e| DnsResolutionDto { hostname: e.source_asset.map(|id| resolve_asset_fast(&idx, id)).unwrap_or_default(), ip: e.destination_asset.map(|id| resolve_asset_fast(&idx, id)).unwrap_or_default(), timestamp_ns: e.timestamp_unix_ns, event_id: e.id.0, summary: e.summary.clone() }).collect())
}

#[tauri::command]
async fn cmd_list_http_hosts(project_dir: String) -> Result<Vec<HttpHostDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let mut map: HashMap<String, (usize, Vec<String>, Vec<String>)> = HashMap::new();
    for e in inv.events().iter().filter(|e| matches!(e.kind, EventKind::HttpRequest)) {
        let host = parse_http_host(&e.summary).unwrap_or_else(|| "(sin host)".to_string());
        let entry = map.entry(host).or_insert((0, Vec::new(), Vec::new()));
        entry.0 += 1;
        if let Some(m) = parse_http_method(&e.summary) { if !entry.1.contains(&m) { entry.1.push(m); } }
        if let Some(u) = parse_http_uri(&e.summary) { if entry.2.len() < 5 && !entry.2.contains(&u) { entry.2.push(u); } }
    }
    let mut out: Vec<HttpHostDto> = map.into_iter().map(|(h, (c, m, u))| HttpHostDto { host: h, request_count: c, methods: m, sample_uris: u }).collect();
    out.sort_by(|a, b| b.request_count.cmp(&a.request_count)); out.truncate(200); Ok(out)
}

#[tauri::command]
async fn cmd_list_tls_snis(project_dir: String) -> Result<Vec<TlsSniDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let mut map: HashMap<String, (usize, Vec<String>, Vec<String>, Vec<String>)> = HashMap::new();
    for e in inv.events().iter().filter(|e| matches!(e.kind, EventKind::TlsClientHello)) {
        let sni = parse_tls_sni(&e.summary).unwrap_or_else(|| "(sin SNI)".to_string());
        let entry = map.entry(sni).or_insert((0, Vec::new(), Vec::new(), Vec::new()));
        entry.0 += 1;
        for v in parse_tls_field(&e.summary, "versions") { if !entry.1.contains(&v) { entry.1.push(v); } }
        for a in parse_tls_field(&e.summary, "alpn") { if !entry.2.contains(&a) { entry.2.push(a); } }
        if let Some(ip) = e.source_asset.map(|id| resolve_asset_fast(&idx, id)) { if !entry.3.contains(&ip) && entry.3.len() < 10 { entry.3.push(ip); } }
    }
    let mut out: Vec<TlsSniDto> = map.into_iter().map(|(s, (c, v, a, ips))| TlsSniDto { sni: s, count: c, versions: v, alpn: a, client_ips: ips }).collect();
    out.sort_by(|a, b| b.count.cmp(&a.count)); out.truncate(200); Ok(out)
}

#[tauri::command]
async fn cmd_list_notes(project_dir: String, target_type: Option<String>, target_id: Option<u64>) -> Result<Vec<NoteDto>, String> {
    let dir = PathBuf::from(&project_dir);
    let all = notes::load_notes(&dir)?;
    let out: Vec<NoteDto> = all.into_iter().filter(|n| match (&target_type, target_id) {
        (Some(tt), Some(ti)) => n.target_type == *tt && n.target_id == ti,
        (Some(tt), None) => n.target_type == *tt,
        _ => true,
    }).map(|n| NoteDto { id: n.id, target_type: n.target_type, target_id: n.target_id, text: n.text, created_at_ns: n.created_at_ns }).collect();
    Ok(out)
}

#[tauri::command]
async fn cmd_add_note(project_dir: String, target_type: String, target_id: u64, text: String) -> Result<NoteDto, String> {
    if text.trim().is_empty() { return Err("Texto vacío".to_string()); }
    let dir = PathBuf::from(&project_dir);
    let mut all = notes::load_notes(&dir)?;
    let id = notes::next_id(&all);
    let n = notes::Note { id, target_type, target_id, text: text.trim().to_string(), created_at_ns: now_unix_ns() };
    all.push(n.clone()); notes::save_notes(&dir, &all)?;
    Ok(NoteDto { id: n.id, target_type: n.target_type, target_id: n.target_id, text: n.text, created_at_ns: n.created_at_ns })
}

#[tauri::command]
async fn cmd_delete_note(project_dir: String, note_id: u64) -> Result<(), String> {
    let dir = PathBuf::from(&project_dir);
    let mut all = notes::load_notes(&dir)?;
    all.retain(|n| n.id != note_id);
    notes::save_notes(&dir, &all)
}

#[tauri::command]
async fn cmd_diff_sources(project_dir: String, source_a: u64, source_b: u64) -> Result<DiffDto, String> {
    let dir = PathBuf::from(&project_dir);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let ev_a: HashSet<u64> = inv.evidences().iter().filter(|e| e.source_id.0 == source_a).map(|e| e.id.0).collect();
    let ev_b: HashSet<u64> = inv.evidences().iter().filter(|e| e.source_id.0 == source_b).map(|e| e.id.0).collect();
    let mut assets_a = HashSet::new(); let mut assets_b = HashSet::new();
    for e in inv.events() {
        if e.evidence_ids.iter().any(|id| ev_a.contains(&id.0)) { if let Some(a) = e.source_asset { assets_a.insert(a.0); } if let Some(a) = e.destination_asset { assets_a.insert(a.0); } }
        if e.evidence_ids.iter().any(|id| ev_b.contains(&id.0)) { if let Some(a) = e.source_asset { assets_b.insert(a.0); } if let Some(a) = e.destination_asset { assets_b.insert(a.0); } }
    }
    let assets_a_str: HashSet<String> = assets_a.iter().filter_map(|id| idx.get(id).cloned()).collect();
    let assets_b_str: HashSet<String> = assets_b.iter().filter_map(|id| idx.get(id).cloned()).collect();
    let mut flows_a = HashSet::new(); let mut flows_b = HashSet::new();
    for f in inv.flows() {
        if f.evidence_ids.iter().any(|id| ev_a.contains(&id.0)) { flows_a.insert(f.id.0); }
        if f.evidence_ids.iter().any(|id| ev_b.contains(&id.0)) { flows_b.insert(f.id.0); }
    }
    let flows_a_str: HashSet<String> = flows_a.iter().filter_map(|id| inv.flows().iter().find(|f| f.id.0 == *id)).map(|f| flow_key_string(f, &idx)).collect();
    let flows_b_str: HashSet<String> = flows_b.iter().filter_map(|id| inv.flows().iter().find(|f| f.id.0 == *id)).map(|f| flow_key_string(f, &idx)).collect();
    let name_a = inv.sources().iter().find(|s| s.id.0 == source_a).map(|s| s.file_name.clone()).unwrap_or_else(|| format!("Fuente {source_a}"));
    let name_b = inv.sources().iter().find(|s| s.id.0 == source_b).map(|s| s.file_name.clone()).unwrap_or_else(|| format!("Fuente {source_b}"));
    let mut only_a: Vec<String> = assets_a_str.difference(&assets_b_str).cloned().collect();
    let mut only_b: Vec<String> = assets_b_str.difference(&assets_a_str).cloned().collect();
    let mut shared: Vec<String> = assets_a_str.intersection(&assets_b_str).cloned().collect();
    only_a.sort(); only_b.sort(); shared.sort();
    let mut flows_only_a: Vec<String> = flows_a_str.difference(&flows_b_str).cloned().collect();
    let mut flows_only_b: Vec<String> = flows_b_str.difference(&flows_a_str).cloned().collect();
    flows_only_a.sort(); flows_only_b.sort();
    Ok(DiffDto { name_a, name_b, assets_only_in_a: only_a, assets_only_in_b: only_b, assets_shared: shared, flows_only_in_a: flows_only_a, flows_only_in_b: flows_only_b })
}

#[tauri::command]
async fn cmd_export_markdown(project_dir: String, output_path: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir); let out = PathBuf::from(&output_path);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    write_markdown_report(&inv, 60_000_000_000, &out).map_err(|e| format!("Error: {e}"))?;
    Ok(format!("Informe guardado en {}", out.display()))
}

#[tauri::command]
async fn cmd_export_csv(project_dir: String, output_path: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir); let out = PathBuf::from(&output_path);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let events: Vec<&NetworkEvent> = inv.events().iter().collect();
    export_events_csv(&inv, &events, &out).map_err(|e| format!("Error: {e}"))?;
    Ok(format!("CSV guardado en {}", out.display()))
}

#[tauri::command]
async fn cmd_export_json(project_dir: String, output_path: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir); let out = PathBuf::from(&output_path);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let events: Vec<&NetworkEvent> = inv.events().iter().collect();
    export_events_json(&inv, &events, &out).map_err(|e| format!("Error: {e}"))?;
    Ok(format!("JSON guardado en {}", out.display()))
}

#[tauri::command]
async fn cmd_export_report_html(project_dir: String, output_path: String) -> Result<String, String> {
    let dir = PathBuf::from(&project_dir); let out = PathBuf::from(&output_path);
    let (inv, _) = open_project(&dir).map_err(|e| format!("{e}"))?;
    let idx = build_asset_index(&inv);
    let mut kind_counts: HashMap<&'static str, u64> = HashMap::new();
    for e in inv.events() { *kind_counts.entry(event_kind_str(&e.kind)).or_insert(0) += 1; }
    let mut kind_items: Vec<(String, u64)> = kind_counts.into_iter().map(|(k, c)| (k.to_string(), c)).collect();
    kind_items.sort_by(|a, b| b.1.cmp(&a.1)); let kind_items: Vec<(String, u64)> = kind_items.into_iter().take(10).collect();
    let mut traffic: HashMap<u64, u64> = HashMap::new();
    for flow in inv.flows() { for id in [flow.endpoint_a, flow.endpoint_b] { *traffic.entry(id.0).or_insert(0) += flow.captured_bytes; } }
    let mut top: Vec<(String, u64)> = traffic.into_iter().filter_map(|(id, bytes)| idx.get(&id).map(|v| (v.clone(), bytes))).collect();
    top.sort_by(|a, b| b.1.cmp(&a.1)); let top_talkers: Vec<(String, u64)> = top.into_iter().take(10).collect();
    let all_notes = notes::load_notes(&dir).unwrap_or_default();
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"es\">\n<head>\n<meta charset=\"UTF-8\">\n");
    html.push_str(&format!("<title>Informe NEXTRACE — {}</title>\n", html_escape(&inv.name)));
    html.push_str("<style>body{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:0 auto;padding:2rem;max-width:1100px}h1{color:#58a6ff;border-bottom:2px solid #30363d;padding-bottom:.5rem}h2{color:#58a6ff;margin-top:2rem}h3{color:#79c0ff}.meta{color:#8b949e;font-size:.9rem;margin-bottom:2rem}.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem;margin:1rem 0}.stat{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1rem}.stat-value{font-size:1.8rem;font-weight:600;color:#e6edf3}.stat-label{color:#8b949e;font-size:.75rem;text-transform:uppercase}table{width:100%;border-collapse:collapse;margin:1rem 0;background:#161b22;border-radius:6px;overflow:hidden}th{background:#1c2128;padding:.5rem;text-align:left;font-size:.75rem;text-transform:uppercase;color:#8b949e}td{padding:.5rem;border-bottom:1px solid #21262d;font-family:ui-monospace,monospace;font-size:.85rem}.severity-Critical,.severity-High{color:#f85149;font-weight:bold}.severity-Medium{color:#d29922}.severity-Low,.severity-Info{color:#8b949e}.note{background:#161b22;border-left:3px solid #58a6ff;padding:.75rem;margin:.5rem 0;border-radius:4px}.flags{color:#3fb950;font-weight:bold}</style>\n</head>\n<body>\n");
    html.push_str(&format!("<h1>Informe: {}</h1>\n", html_escape(&inv.name)));
    html.push_str(&format!("<div class=\"meta\">ID {} · creado {}</div>\n", inv.id.0, fmt_ts_html(inv.created_at_unix_ns)));
    if let Some(desc) = &inv.description { html.push_str(&format!("<p>{}</p>\n", html_escape(desc))); }
    html.push_str("<h2>Resumen</h2>\n<div class=\"stat-grid\">\n");
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Fuentes</div></div>\n", inv.sources().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Activos</div></div>\n", inv.assets().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Eventos</div></div>\n", inv.events().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Flujos</div></div>\n", inv.flows().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Hallazgos</div></div>\n", inv.findings().len()));
    html.push_str(&format!("<div class=\"stat\"><div class=\"stat-value\">{}</div><div class=\"stat-label\">Notas</div></div>\n", all_notes.len()));
    html.push_str("</div>\n");
    if !kind_items.is_empty() { html.push_str("<h2>Distribución por tipo</h2>\n"); html.push_str(&svg_bars("Eventos por tipo", &kind_items)); html.push('\n'); }
    if !top_talkers.is_empty() { html.push_str("<h2>Top activos por tráfico</h2>\n"); html.push_str(&svg_bars("Top activos por bytes", &top_talkers)); html.push('\n'); }
    html.push_str("<h2>Hallazgos</h2>\n");
    if inv.findings().is_empty() { html.push_str("<p>No se registraron hallazgos.</p>\n"); } else {
        html.push_str("<table><tr><th>ID</th><th>Severidad</th><th>Título</th><th>Conf.</th></tr>\n");
        for f in inv.findings() {
            html.push_str(&format!("<tr><td>{}</td><td class=\"severity-{}\">{:?}</td><td>{}</td><td>{}%</td></tr>\n", f.id.0, severity_str(&f.severity), f.severity, html_escape(&f.title), f.confidence_percent.map(|c| c.to_string()).unwrap_or_else(|| "—".to_string())));
        }
        html.push_str("</table>\n");
    }
    if !all_notes.is_empty() {
        html.push_str("<h2>Notas del analista</h2>\n");
        for n in &all_notes { html.push_str(&format!("<div class=\"note\"><strong>{}</strong> #{}: {}</div>\n", html_escape(&n.target_type), n.target_id, html_escape(&n.text))); }
    }
    html.push_str("<hr style=\"border-color:#30363d;margin:2rem 0\">\n");
    html.push_str("<p class=\"meta\">Informe generado por NEXTRACE.</p>\n</body>\n</html>\n");
    std::fs::write(&out, html).map_err(|e| format!("Error escribiendo: {e}"))?;
    Ok(format!("Informe HTML guardado en {}", out.display()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            cmd_create_project, cmd_open_project, cmd_get_project_info, cmd_update_project_description,
            cmd_verify_integrity, cmd_import_source, cmd_analyze, cmd_get_anomaly_config, cmd_detect_anomalies_with_config,
            cmd_get_baseline_config, cmd_detect_baseline_anomalies, cmd_get_overview, cmd_list_events, cmd_list_flows, cmd_list_flow_events,
            cmd_list_findings, cmd_list_sources, cmd_list_assets, cmd_get_asset_detail, cmd_get_event_detail, cmd_get_frame_hex,
            cmd_get_correlations, cmd_get_timeline_v2, cmd_list_dns_resolutions, cmd_list_http_hosts, cmd_list_tls_snis,
            cmd_list_notes, cmd_add_note, cmd_delete_note, cmd_diff_sources, cmd_export_markdown, cmd_export_csv, cmd_export_json, cmd_export_report_html,
        ])
        .run(tauri::generate_context!())
        .expect("error ejecutando NEXTRACE");
}```


## Archivo: `nextrace-app/src-tauri/src/main.rs`

```rust
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    nextrace_app_lib::run()
}
```


## Archivo: `nextrace-app/src/main.ts`

```typescript
import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

interface TopAsset { id: number; value: string; kind: string; total_bytes: number; flow_count: number }
interface KindCount { kind: string; count: number }
interface ProtocolStat { protocol: string; flow_count: number; packet_count: number; captured_bytes: number }
interface EndpointStat { asset_id: number; value: string; flow_count: number; packets_sent: number; packets_received: number; bytes_sent: number; bytes_received: number }
interface FlowStats { flow_count: number; packet_count: number; captured_bytes: number; original_bytes: number; bidirectional_flow_count: number; protocols: ProtocolStat[]; endpoints: EndpointStat[] }
interface Overview { sources: number; sources_analyzed: number; assets: number; events: number; flows: number; findings: number; dns_queries: number; dns_responses: number; dns_resolutions: number; tls_client_hellos: number; http_requests: number; http_responses: number; top_assets: TopAsset[]; kind_distribution: KindCount[]; flow_stats: FlowStats }
interface EventDto { id: number; timestamp_ns: number | null; kind: string; summary: string; source_asset: string | null; destination_asset: string | null; source_port: number | null; destination_port: number | null; protocol: string | null; evidence_ids: number[]; tcp_flags: string | null; }
interface FlowDto { id: number; protocol: string; endpoint_a: string; endpoint_a_port: number | null; endpoint_b: string; endpoint_b_port: number | null; service_a: string | null; service_b: string | null; flags: string | null; first_seen_ns: number; last_seen_ns: number; duration_ns: number | null; packets_per_second: number | null; bytes_per_second: number | null; packet_count: number; captured_bytes: number; bidirectional: boolean }
interface FindingDto { id: number; severity: string; kind: string; title: string; description: string; confidence_percent: number | null; evidence_ids: number[] }
interface SourceDto { id: number; file_name: string; format: string; size_bytes: number; sha256: string | null; imported_at_ns: number; analyzed: boolean }
interface AssetDto { id: number; value: string; kind: string; label: string | null; flow_count: number; packets_sent: number; packets_received: number; bytes_sent: number; bytes_received: number; event_count: number }
interface AssetDetailDto { asset: AssetDto; flows: FlowDto[]; events: EventDto[] }
interface EvidenceExcerptDto { id: number; frame_number: number; excerpt: string | null }
interface EventDetailDto { event: EventDto; evidence: EvidenceExcerptDto[]; related_events: EventDto[]; flow: FlowDto | null; tcp_flags: string | null; }
interface CorrelationGroupDto { shared_asset: string; event_count: number; events: EventDto[]; evidence_ids: number[]; time_min_ns: number; time_max_ns: number; }
interface CorrelationDto { window_ns: number; events_considered: number; events_without_timestamp: number; total_events: number; total_candidates: number; truncated: boolean; total_found: number; groups: CorrelationGroupDto[]; }
interface TimelineEntryV2Dto { timestamp_ns: number; kind: string; event_id: number | null; event_summary: string | null; event_kind: string | null; associated_flow_ids: number[] | null; flow_id: number | null; flow_endpoint_a: string | null; flow_endpoint_b: string | null; flow_packet_count: number | null; flow_captured_bytes: number | null; evidence_ids: number[] }
interface TimelineV2Dto { events_without_timestamp: number; entries: TimelineEntryV2Dto[] }
interface DnsResolutionDto { hostname: string; ip: string; timestamp_ns: number | null; event_id: number; summary: string }
interface HttpHostDto { host: string; request_count: number; methods: string[]; sample_uris: string[] }
interface TlsSniDto { sni: string; count: number; versions: string[]; alpn: string[]; client_ips: string[] }
interface ProjectInfoDto { name: string; description: string | null; created_at_ns: number; investigation_id: number }
interface IntegrityReportDto { sources_verified: number; sources_without_hash: number; total_sources: number; all_ok: boolean }
interface AnomalyConfigDto { enable_http_on_unusual_port: boolean; enable_tls_on_plain_port: boolean; enable_large_flow: boolean; large_flow_threshold_bytes: number; enable_beaconing: boolean; beacon_min_connections: number; beacon_max_cv: number; enable_dns_tunneling: boolean; dns_long_name_threshold: number; dns_max_unique_subdomains: number; enable_port_scanning: boolean; portscan_max_distinct_destinations: number; portscan_window_ns: number }
interface BaselineConfigDto { min_entities_per_kind: number; modified_zscore_threshold: number; high_zscore_threshold: number; min_flows_per_asset: number; enable_bytes_baseline: boolean; enable_flow_count_baseline: boolean }
interface NoteDto { id: number; target_type: string; target_id: number; text: string; created_at_ns: number }
interface DiffDto { name_a: string; name_b: string; assets_only_in_a: string[]; assets_only_in_b: string[]; assets_shared: string[]; flows_only_in_a: string[]; flows_only_in_b: string[] }

let currentProjectDir: string | null = null;
let allFindings: FindingDto[] = [];
let currentFlows: FlowDto[] = [];
let selectedEventId: number | null = null;
let selectedAssetId: number | null = null;
let anomalyConfigCache: AnomalyConfigDto | null = null;
let baselineConfigCache: BaselineConfigDto | null = null;
let pivotAssetValue: string | null = null;
let iocActive: string[] = [];
let currentEventsInTable: EventDto[] = [];
let currentEventFilter: any = {};

const EVENTS_PAGE_SIZE = 200;
let eventsOffset = 0;
let eventsHasMore = false;

function $(id: string): HTMLElement { const el = document.getElementById(id); if (!el) throw new Error(`Missing ${id}`); return el; }
function setStatus(msg: string) { $("status-message").textContent = msg; }
function fmtBytes(b: number): string { if (b < 1024) return `${b} B`; if (b < 1048576) return `${(b/1024).toFixed(1)} KB`; if (b < 1073741824) return `${(b/1048576).toFixed(1)} MB`; return `${(b/1073741824).toFixed(2)} GB`; }
function fmtTs(ns: number | null): string { if (ns === null) return "—"; const d = new Date(ns / 1e6); return d.toISOString().replace("T", " ").substring(0, 19); }
function fmtTsShort(ns: number | null): string { if (ns === null) return "—"; const d = new Date(ns / 1e6); return d.toISOString().substring(11, 23); }
function fmtDuration(ns: number | null): string { if (ns === null) return "—"; if (ns < 1000) return `${ns} ns`; if (ns < 1e6) return `${(ns/1e3).toFixed(1)} µs`; if (ns < 1e9) return `${(ns/1e6).toFixed(1)} ms`; return `${(ns/1e9).toFixed(2)} s`; }
function esc(s: string): string { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

function showLoading(msg: string) { const ov = document.getElementById("loading-overlay"); const t = document.getElementById("loading-text"); if (ov && t) { t.textContent = msg; ov.classList.remove("hidden"); } }
function hideLoading() { document.getElementById("loading-overlay")?.classList.add("hidden"); }

function kindPill(k: string): string {
    const c = k === "Packet" ? "pill-packet" : k === "DnsQuery" || k === "DnsResponse" ? "pill-dns" : k === "DnsResolution" ? "pill-dnsres" : k === "TlsClientHello" ? "pill-tls" : k === "HttpRequest" || k === "HttpResponse" ? "pill-http" : "pill-packet";
    return `<span class="pill ${c}">${k}</span>`;
}
function protoPill(p: string | null): string { if (!p) return "—"; const c = p === "TCP" ? "pill-tcp" : p === "UDP" ? "pill-udp" : "pill-packet"; return `<span class="pill ${c}">${p}</span>`; }
function sevPill(s: string): string { return `<span class="pill pill-sev-${s.toLowerCase()}">${s}</span>`; }
function flagPill(f: string | null): string { if (!f) return "—"; return `<span class="pill pill-flag">${f}</span>`; }
function assetSpan(v: string | null): string { if (!v) return `<span style="color:var(--muted)">—</span>`; return `<button class="pivot-link" data-pivot-asset="${esc(v)}">${esc(v)}</button>`; }

async function run<T>(label: string, fn: () => Promise<T>, showOverlay = false): Promise<T | null> {
    if (showOverlay) showLoading(label);
    setStatus(`${label}…`);
    try { const r = await fn(); setStatus(`OK · ${label}`); return r; }
    catch (e) { setStatus(`Error · ${label}: ${String(e)}`); return null; }
    finally { if (showOverlay) hideLoading(); }
}

function bindEnter(input: HTMLElement, cb: () => void) {
    input.addEventListener("keydown", (ev) => { if ((ev as KeyboardEvent).key === "Enter" && !(ev as KeyboardEvent).shiftKey) { ev.preventDefault(); cb(); } });
}

document.addEventListener("click", async (ev) => {
    const t = (ev.target as HTMLElement).closest("[data-pivot-asset]");
    if (t) { const v = t.getAttribute("data-pivot-asset"); if (v) await applyPivot(v); }
});

function switchTab(name: string) {
    document.querySelectorAll<HTMLButtonElement>(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll<HTMLElement>(".panel").forEach(p => p.classList.toggle("active", p.dataset.panel === name));
    if (!currentProjectDir) return;
    switch (name) {
        case "overview": refreshOverview(); break;
        case "sources": refreshSources(); break;
        case "events": refreshEvents(); break;
        case "assets": refreshAssets(); break;
        case "flows": refreshFlows(); break;
        case "correlations": refreshCorrelations(); break;
        case "protocols": refreshProtocols(); break;
        case "diff": populateDiffSources(); break;
        case "findings": refreshFindings(); break;
        case "timeline": refreshTimeline(); break;
    }
}
document.querySelectorAll<HTMLButtonElement>(".tab").forEach(b => b.addEventListener("click", () => switchTab(b.dataset.tab!)));

function switchSubtab(name: string) {
    document.querySelectorAll<HTMLButtonElement>(".subtab").forEach(b => b.classList.toggle("active", b.dataset.subtab === name));
    document.querySelectorAll<HTMLElement>(".subpanel").forEach(p => p.classList.toggle("active", p.dataset.subpanel === name));
}
document.querySelectorAll<HTMLButtonElement>(".subtab").forEach(b => b.addEventListener("click", () => switchSubtab(b.dataset.subtab!)));

async function setProject(dir: string) {
    currentProjectDir = dir;
    pivotAssetValue = null;
    iocActive = [];
    updatePivotIndicator();
    const info = await invoke<ProjectInfoDto>("cmd_get_project_info", { projectDir: dir }).catch(() => null);
    if (info) {
        $("case-name").textContent = info.name;
        $("project-info").textContent = `${dir} · creado ${fmtTs(info.created_at_ns)}`;
    } else {
        $("case-name").textContent = dir.split("/").pop() || dir;
        $("project-info").textContent = dir;
    }
    await refreshFindingsBadge();
    switchTab("overview");
}

async function refreshFindingsBadge() {
    if (!currentProjectDir) return;
    const f = await invoke<FindingDto[]>("cmd_list_findings", { projectDir: currentProjectDir }).catch(() => []);
    const badge = $("findings-badge");
    const tabBadge = $("findings-tab-badge");
    badge.textContent = String(f.length);
    badge.classList.toggle("has-items", f.length > 0);
    if (f.length > 0) { tabBadge.textContent = String(f.length); tabBadge.classList.add("visible"); }
    else { tabBadge.classList.remove("visible"); }
}

$("btn-new-project").addEventListener("click", async () => {
    const dir = await open({ directory: true, multiple: false });
    if (!dir) return;
    const name = prompt("Nombre del nuevo caso:", "Caso sin título");
    if (!name) return;
    const r = await run("Creando proyecto", () => invoke<string>("cmd_create_project", { projectDir: dir, name }));
    if (r) await setProject(dir as string);
});

$("btn-open-project").addEventListener("click", async () => {
    const dir = await open({ directory: true, multiple: false });
    if (!dir) return;
    const r = await run("Abriendo proyecto", () => invoke<string>("cmd_open_project", { projectDir: dir }));
    if (r) await setProject(dir as string);
});

async function importPcapFlow() {
    if (!currentProjectDir) {
        const dir = await open({ directory: true, multiple: false });
        if (!dir) return;
        const name = prompt("Nombre del nuevo caso:", dir.split("/").pop() || "Caso");
        if (!name) return;
        const r = await run("Creando proyecto", () => invoke<string>("cmd_create_project", { projectDir: dir, name }));
        if (!r) return;
        await setProject(dir as string);
    }
    const file = await open({ multiple: false, filters: [{ name: "Capturas", extensions: ["pcap", "pcapng", "cap"] }] });
    if (!file) return;
    const r = await run("Importando captura", () => invoke<string>("cmd_import_source", { projectDir: currentProjectDir, filePath: file }), true);
    if (r) {
        setStatus(r);
        switchTab("sources");
        const a = await run("Analizando captura", () => invoke<string>("cmd_analyze", { projectDir: currentProjectDir! }), true);
        if (a) { setStatus(a.replace(/\n/g, " · ")); await refreshSources(); }
    }
}
$("btn-import-capture").addEventListener("click", importPcapFlow);
$("btn-import-capture-2").addEventListener("click", importPcapFlow);
$("btn-findings-shortcut").addEventListener("click", () => switchTab("findings"));

async function refreshOverview() {
    if (!currentProjectDir) return;
    const data = await run("Cargando vista general", () => invoke<Overview>("cmd_get_overview", { projectDir: currentProjectDir }), true);
    if (!data) return;
    const info = await invoke<ProjectInfoDto>("cmd_get_project_info", { projectDir: currentProjectDir }).catch(() => null);
    $("overview-empty").classList.add("hidden");
    $("overview-content").classList.remove("hidden");

    if (info) {
        $("project-banner").innerHTML = `
            <div class="banner-name">${esc(info.name)}</div>
            <div class="banner-desc">${info.description ? esc(info.description) : "<em style='color:var(--muted)'>Sin descripción</em>"} <button class="pivot-link" id="btn-edit-description" style="margin-left:0.5rem;font-size:0.75rem">editar</button></div>
            <div class="banner-meta">ID ${info.investigation_id} · creado ${fmtTs(info.created_at_ns)}</div>`;
        $("btn-edit-description").addEventListener("click", async () => {
            const current = info.description || "";
            const next = prompt("Descripción del proyecto:", current);
            if (next === null) return;
            const r = await run("Actualizando", () => invoke<string>("cmd_update_project_description", { projectDir: currentProjectDir, description: next }));
            if (r) { setStatus(r); refreshOverview(); }
        });
    }

    const cards = [
        { label: "Fuentes", value: data.sources, detail: `${data.sources_analyzed} analizadas` },
        { label: "Activos", value: data.assets, detail: "IPs, MACs, hostnames" },
        { label: "Eventos", value: data.events, detail: "observaciones" },
        { label: "Flujos", value: data.flows, detail: `${data.flow_stats.bidirectional_flow_count} bidir.` },
        { label: "Hallazgos", value: data.findings, detail: "con evidencia" },
        { label: "DNS", value: data.dns_queries + data.dns_responses, detail: `${data.dns_resolutions} res.` },
        { label: "HTTP", value: data.http_requests + data.http_responses, detail: "req+resp" },
        { label: "TLS", value: data.tls_client_hellos, detail: "ClientHellos" },
    ];
    $("stats-grid").innerHTML = cards.map(c => `<div class="stat-card"><div class="stat-label">${c.label}</div><div class="stat-value">${c.value}</div><div class="stat-detail">${c.detail}</div></div>`).join("");

    const maxKind = Math.max(1, ...data.kind_distribution.map(k => k.count));
    $("kind-chart").innerHTML = data.kind_distribution.map(({ kind, count }) => {
        const col = kind === "DnsResolution" ? "var(--kind-dnsres)" : kind === "DnsQuery" || kind === "DnsResponse" ? "var(--kind-dns)" : kind === "TlsClientHello" ? "var(--kind-tls)" : kind === "HttpRequest" || kind === "HttpResponse" ? "var(--kind-http)" : "var(--kind-packet)";
        return `<div class="bar-row"><div class="bar-label">${kind}</div><div class="bar-track"><div class="bar-fill" style="width:${(count/maxKind)*100}%;background:${col}"></div></div><div class="bar-value">${count}</div></div>`;
    }).join("");

    const maxB = Math.max(1, ...data.top_assets.map(a => a.total_bytes));
    $("top-assets").innerHTML = data.top_assets.map(a => `<div class="bar-row"><div class="bar-label"><button class="pivot-link" data-pivot-asset="${esc(a.value)}" title="${esc(a.value)}">${esc(a.value)}</button></div><div class="bar-track"><div class="bar-fill" style="width:${(a.total_bytes/maxB)*100}%;background:var(--accent)"></div></div><div class="bar-value">${fmtBytes(a.total_bytes)}</div></div>`).join("");

    const maxProto = Math.max(1, ...data.flow_stats.protocols.map(p => p.captured_bytes));
    $("protocol-stats").innerHTML = data.flow_stats.protocols.map(p => `<div class="bar-row"><div class="bar-label">${esc(p.protocol)}</div><div class="bar-track"><div class="bar-fill" style="width:${(p.captured_bytes/maxProto)*100}%;background:var(--accent)"></div></div><div class="bar-value">${fmtBytes(p.captured_bytes)}</div></div>`).join("") || `<div style="color:var(--muted);font-size:0.8rem">Sin datos</div>`;

    const maxEp = Math.max(1, ...data.flow_stats.endpoints.map(e => Math.max(e.bytes_sent, e.bytes_received)));
    $("endpoint-stats").innerHTML = data.flow_stats.endpoints.slice(0, 8).map(e => `
        <div style="margin-bottom:0.5rem">
            <div style="font-size:0.78rem;margin-bottom:0.15rem"><button class="pivot-link" data-pivot-asset="${esc(e.value)}">${esc(e.value)}</button></div>
            <div class="bar-row" style="grid-template-columns:40px 1fr 60px;gap:0.4rem"><div style="font-size:0.7rem;color:var(--muted)">env</div><div class="bar-track"><div class="bar-fill" style="width:${(e.bytes_sent/maxEp)*100}%;background:var(--proto-tcp)"></div></div><div class="bar-value">${fmtBytes(e.bytes_sent)}</div></div>
            <div class="bar-row" style="grid-template-columns:40px 1fr 60px;gap:0.4rem"><div style="font-size:0.7rem;color:var(--muted)">recv</div><div class="bar-track"><div class="bar-fill" style="width:${(e.bytes_received/maxEp)*100}%;background:var(--proto-udp)"></div></div><div class="bar-value">${fmtBytes(e.bytes_received)}</div></div>
        </div>`).join("") || `<div style="color:var(--muted);font-size:0.8rem">Sin datos</div>`;
}

async function refreshSources() {
    if (!currentProjectDir) return;
    const s = await run("Cargando fuentes", () => invoke<SourceDto[]>("cmd_list_sources", { projectDir: currentProjectDir }));
    if (!s) return;
    const tb = $("sources-table").querySelector("tbody")!;
    tb.innerHTML = s.map(x => `<tr><td>${x.id}</td><td>${esc(x.file_name)}</td><td>${x.format}</td><td>${fmtBytes(x.size_bytes)}</td><td><span class="pill ${x.analyzed ? "pill-sev-info" : "pill-sev-low"}">${x.analyzed ? "Analizada" : "Pendiente"}</span></td><td style="color:var(--muted);font-size:0.72rem">${(x.sha256 || "—").substring(0, 16)}…</td></tr>`).join("");
}

$("btn-analyze").addEventListener("click", async () => {
    if (!currentProjectDir) return;
    const r = await run("Analizando", () => invoke<string>("cmd_analyze", { projectDir: currentProjectDir }), true);
    if (r) { setStatus(r.replace(/\n/g, " · ")); refreshSources(); }
});

$("btn-verify-integrity").addEventListener("click", async () => {
    if (!currentProjectDir) return;
    const r = await run("Verificando integridad", () => invoke<IntegrityReportDto>("cmd_verify_integrity", { projectDir: currentProjectDir }), true);
    if (!r) return;
    const box = $("integrity-status");
    box.classList.remove("hidden", "ok", "warn");
    box.classList.add(r.all_ok ? "ok" : "warn");
    box.textContent = r.all_ok ? `✓ Integridad: ${r.sources_verified}/${r.total_sources} fuentes.` : `⚠ ${r.sources_verified} verificadas · ${r.sources_without_hash} sin hash · ${r.total_sources} totales.`;
});

function localToNs(v: string): number | null { if (!v) return null; const ms = new Date(v).getTime(); return isNaN(ms) ? null : ms * 1e6; }

function buildEventFilter() {
    const tcp_flags = Array.from(document.querySelectorAll<HTMLInputElement>(".flag-filter:checked")).map(el => el.value);
    return {
        text: ($("filter-text") as HTMLInputElement).value || null,
        kind: ($("filter-kind") as HTMLSelectElement).value || null,
        protocol: ($("filter-protocol") as HTMLSelectElement).value || null,
        limit: EVENTS_PAGE_SIZE, offset: 0,
        min_port: Number(($("filter-min-port") as HTMLInputElement).value) || null,
        max_port: Number(($("filter-max-port") as HTMLInputElement).value) || null,
        time_start_ns: localToNs(($("filter-time-start") as HTMLInputElement).value),
        time_end_ns: localToNs(($("filter-time-end") as HTMLInputElement).value),
        exclude_loopback: ($("filter-exclude-loopback") as HTMLInputElement).checked,
        asset_ids: [], asset_value: pivotAssetValue, ioc_tokens: iocActive,
        tcp_flags,
    };
}

async function refreshEvents() {
    if (!currentProjectDir) return;
    currentEventFilter = buildEventFilter();
    eventsOffset = 0;
    currentEventsInTable = [];
    const ev = await run("Cargando eventos", () => invoke<EventDto[]>("cmd_list_events", { projectDir: currentProjectDir, filter: currentEventFilter }));
    if (!ev) return;
    currentEventsInTable = ev;
    eventsHasMore = ev.length === EVENTS_PAGE_SIZE;
    renderEventsTable(); updateEventsCount(); updatePaginationControls();
}

function renderEventsTable() {
    const tb = $("events-table").querySelector("tbody")!;
    // Añadida la columna flagPill(e.tcp_flags) al HTML de la fila
    tb.innerHTML = currentEventsInTable.map(e => `<tr data-id="${e.id}" class="${e.id === selectedEventId ? "selected" : ""}"><td style="white-space:nowrap;color:var(--muted)">${fmtTsShort(e.timestamp_ns)}</td><td>${kindPill(e.kind)}</td><td>${e.tcp_flags ? flagPill(e.tcp_flags) : "—"}</td><td title="${esc(e.summary)}">${esc(e.summary).substring(0, 90)}</td></tr>`).join("");
    tb.querySelectorAll<HTMLTableRowElement>("tr").forEach(r => r.addEventListener("click", () => selectEvent(Number(r.dataset.id))));
}

async function loadMoreEvents() {
    if (!currentProjectDir || !eventsHasMore) return;
    eventsOffset += EVENTS_PAGE_SIZE;
    const filter = { ...currentEventFilter, offset: eventsOffset, limit: EVENTS_PAGE_SIZE };
    const ev = await run("Cargando más", () => invoke<EventDto[]>("cmd_list_events", { projectDir: currentProjectDir, filter }));
    if (!ev) return;
    currentEventsInTable.push(...ev);
    eventsHasMore = ev.length === EVENTS_PAGE_SIZE;
    renderEventsTable(); updateEventsCount(); updatePaginationControls();
}

function updateEventsCount() { $("events-count").textContent = `${currentEventsInTable.length} eventos${eventsHasMore ? " (hay más)" : ""}`; }
function updatePaginationControls() { const w = document.getElementById("events-pagination"); if (!w) return; w.classList.toggle("hidden", !eventsHasMore && currentEventsInTable.length === 0); const b = document.getElementById("btn-load-more"); if (b) (b as HTMLButtonElement).disabled = !eventsHasMore; }
function updatePivotIndicator() {
    const ind = document.getElementById("pivot-indicator"); const lbl = document.getElementById("pivot-label");
    if (!ind || !lbl) return;
    if (pivotAssetValue || iocActive.length > 0) {
        ind.style.display = "flex";
        const p: string[] = [];
        if (pivotAssetValue) p.push(`"${pivotAssetValue}"`);
        if (iocActive.length > 0) p.push(`${iocActive.length} IoC`);
        lbl.textContent = p.join(" + ");
    } else ind.style.display = "none";
}

async function applyPivot(v: string) {
    pivotAssetValue = v;
    ($("filter-text") as HTMLInputElement).value = "";
    ($("filter-kind") as HTMLSelectElement).value = "";
    ($("filter-protocol") as HTMLSelectElement).value = "";
    ($("filter-min-port") as HTMLInputElement).value = "";
    ($("filter-max-port") as HTMLInputElement).value = "";
    ($("filter-time-start") as HTMLInputElement).value = "";
    ($("filter-time-end") as HTMLInputElement).value = "";
    ($("filter-iocs") as HTMLTextAreaElement).value = "";
    ($("filter-exclude-loopback") as HTMLInputElement).checked = false;
    document.querySelectorAll<HTMLInputElement>(".flag-filter").forEach(el => el.checked = false);
    iocActive = [];
    updatePivotIndicator();
    switchTab("events");
    setTimeout(() => refreshEvents(), 50);
}

$("btn-clear-pivot").addEventListener("click", () => { pivotAssetValue = null; iocActive = []; updatePivotIndicator(); refreshEvents(); });
$("btn-filter").addEventListener("click", () => refreshEvents());
$("btn-clear-filters").addEventListener("click", () => {
    ($("filter-text") as HTMLInputElement).value = "";
    ($("filter-kind") as HTMLSelectElement).value = "";
    ($("filter-protocol") as HTMLSelectElement).value = "";
    ($("filter-min-port") as HTMLInputElement).value = "";
    ($("filter-max-port") as HTMLInputElement).value = "";
    ($("filter-time-start") as HTMLInputElement).value = "";
    ($("filter-time-end") as HTMLInputElement).value = "";
    ($("filter-iocs") as HTMLTextAreaElement).value = "";
    ($("filter-exclude-loopback") as HTMLInputElement).checked = false;
    document.querySelectorAll<HTMLInputElement>(".flag-filter").forEach(el => el.checked = false);
    pivotAssetValue = null; iocActive = []; updatePivotIndicator(); refreshEvents();
});
$("btn-ioc-search").addEventListener("click", () => {
    const raw = ($("filter-iocs") as HTMLTextAreaElement).value || "";
    iocActive = raw.split(/[\n,;]+/).map(s => s.trim()).filter(s => s.length > 0);
    updatePivotIndicator(); refreshEvents();
});
bindEnter($("filter-text"), () => refreshEvents());
bindEnter($("filter-min-port"), () => refreshEvents());
bindEnter($("filter-max-port"), () => refreshEvents());
bindEnter($("filter-time-start"), () => refreshEvents());
bindEnter($("filter-time-end"), () => refreshEvents());
document.addEventListener("click", (ev) => { if ((ev.target as HTMLElement).id === "btn-load-more") loadMoreEvents(); });

async function selectEvent(id: number) {
    if (!currentProjectDir) return;
    selectedEventId = id;
    document.querySelectorAll<HTMLTableRowElement>("#events-table tbody tr").forEach(r => r.classList.toggle("selected", Number(r.dataset.id) === id));
    const d = await invoke<EventDetailDto>("cmd_get_event_detail", { projectDir: currentProjectDir, eventId: id });
    await renderEventDetail(d);
}

async function renderEventDetail(d: EventDetailDto) {
    if (!currentProjectDir) return;
    const e = d.event;
    const notes = await invoke<NoteDto[]>("cmd_list_notes", { projectDir: currentProjectDir, targetType: "event", targetId: e.id }).catch(() => []);

    const flowHtml = d.flow ? `<div class="detail-section"><div class="detail-label">Flujo asociado</div>
        <div class="detail-row"><div class="detail-row-key">Proto</div><div class="detail-row-value">${protoPill(d.flow.protocol)}</div></div>
        <div class="detail-row"><div class="detail-row-key">A</div><div class="detail-row-value">${assetSpan(d.flow.endpoint_a)}:${d.flow.endpoint_a_port ?? "—"} ${d.flow.service_a ? `<span class="service-badge">${d.flow.service_a}</span>` : ""}</div></div>
        <div class="detail-row"><div class="detail-row-key">B</div><div class="detail-row-value">${assetSpan(d.flow.endpoint_b)}:${d.flow.endpoint_b_port ?? "—"} ${d.flow.service_b ? `<span class="service-badge">${d.flow.service_b}</span>` : ""}</div></div>
        <div class="detail-row"><div class="detail-row-key">Paquetes</div><div class="detail-row-value">${d.flow.packet_count}</div></div>
        <div class="detail-row"><div class="detail-row-key">Bytes</div><div class="detail-row-value">${fmtBytes(d.flow.captured_bytes)}</div></div>
        <div style="margin-top:0.5rem"><button class="btn-secondary" id="btn-view-session">Ver sesión completa</button></div></div>` : "";

    const evidenceHtml = d.evidence.map(ev => `<div class="detail-row"><div class="detail-row-key">Frame ${ev.frame_number}</div><div class="detail-row-value">${esc(ev.excerpt || "—")} <button class="pivot-link" data-hexdump="${ev.id}" style="margin-left:0.5rem;font-size:0.72rem">hexdump</button></div></div>`).join("") || "<div style='color:var(--muted);font-size:0.8rem'>Sin evidencias</div>";

    const notesHtml = notes.length === 0 ? `<div style="color:var(--muted);font-size:0.8rem">Sin notas</div>` : notes.map(n => `<div class="note-item"><div class="note-text">${esc(n.text)}</div><div class="note-meta">${fmtTs(n.created_at_ns)} <button class="pivot-link" data-delete-note="${n.id}" style="font-size:0.7rem">eliminar</button></div></div>`).join("");

    const relatedHtml = d.related_events.length > 0 ? `<div class="detail-section"><div class="detail-label">Relacionados (±60s)</div>${d.related_events.map(r => `<div class="related-item" data-id="${r.id}"><div style="display:flex;gap:0.4rem;align-items:center;margin-bottom:0.2rem">${kindPill(r.kind)}<span style="color:var(--muted);font-size:0.72rem">${fmtTsShort(r.timestamp_ns)}</span></div><div style="font-size:0.78rem">${esc(r.summary).substring(0, 100)}</div></div>`).join("")}</div>` : "";

    $("event-detail").innerHTML = `
        <div class="detail-title">${kindPill(e.kind)} #${e.id}</div>
        <div class="detail-meta"><span>${fmtTs(e.timestamp_ns)}</span>${e.protocol ? protoPill(e.protocol) : ""}</div>
        <div class="detail-section"><div class="detail-label">Resumen</div><div style="font-size:0.85rem;line-height:1.5">${esc(e.summary)}</div></div>
        <div class="detail-section"><div class="detail-label">Extremos</div><div class="detail-row"><div class="detail-row-key">Origen</div><div class="detail-row-value">${assetSpan(e.source_asset)}:${e.source_port ?? "—"}</div></div><div class="detail-row"><div class="detail-row-key">Destino</div><div class="detail-row-value">${assetSpan(e.destination_asset)}:${e.destination_port ?? "—"}</div></div>
        ${d.tcp_flags ? `<div class="detail-row"><div class="detail-row-key">Flags TCP</div><div class="detail-row-value">${flagPill(d.tcp_flags)}</div></div>` : ""}
        </div>
        ${flowHtml}
        <div class="detail-section"><div class="detail-label">Evidencias</div>${evidenceHtml}</div>
        <div class="detail-section"><div class="detail-label">Notas del analista</div>${notesHtml}
            <div style="margin-top:0.5rem"><textarea id="new-note-text" placeholder="Añadir nota…" rows="2" style="width:100%;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:4px;padding:0.4rem;font-family:inherit;font-size:0.8rem"></textarea>
            <button class="btn-secondary" id="btn-add-note" style="margin-top:0.3rem">Añadir nota</button></div></div>
        ${relatedHtml}`;

    $("event-detail").querySelectorAll<HTMLElement>(".related-item[data-id]").forEach(el => el.addEventListener("click", () => selectEvent(Number(el.dataset.id))));
    const btnS = document.getElementById("btn-view-session");
    if (btnS && d.flow) btnS.addEventListener("click", () => { switchTab("flows"); setTimeout(() => selectFlow(d.flow!.id), 100); });
    $("event-detail").querySelectorAll<HTMLElement>("[data-hexdump]").forEach(el => {
        el.addEventListener("click", async () => {
            const id = Number(el.getAttribute("data-hexdump"));
            const hex = await run("Hexdump", () => invoke<string>("cmd_get_frame_hex", { projectDir: currentProjectDir, evidenceId: id }), true);
            if (hex) { $("hexdump-content").textContent = hex; $("modal-hexdump").classList.remove("hidden"); }
        });
    });
    const btnAdd = document.getElementById("btn-add-note");
    if (btnAdd) btnAdd.addEventListener("click", async () => {
        const t = ($("new-note-text") as HTMLTextAreaElement).value;
        if (!t.trim()) return;
        await run("Añadiendo nota", () => invoke<NoteDto>("cmd_add_note", { projectDir: currentProjectDir, targetType: "event", targetId: e.id, text: t }), true);
        selectEvent(e.id);
    });
    $("event-detail").querySelectorAll<HTMLElement>("[data-delete-note]").forEach(el => {
        el.addEventListener("click", async () => {
            const id = Number(el.getAttribute("data-delete-note"));
            await run("Eliminando", () => invoke<void>("cmd_delete_note", { projectDir: currentProjectDir, noteId: id }), true);
            selectEvent(e.id);
        });
    });
}

$("modal-close-hexdump").addEventListener("click", () => $("modal-hexdump").classList.add("hidden"));

async function refreshAssets() {
    if (!currentProjectDir) return;
    const a = await run("Cargando activos", () => invoke<AssetDto[]>("cmd_list_assets", { projectDir: currentProjectDir }));
    if (!a) return;
    $("assets-count").textContent = `${a.length} activos`;
    const tb = $("assets-table").querySelector("tbody")!;
    tb.innerHTML = a.map(x => `<tr data-id="${x.id}" class="${x.id === selectedAssetId ? "selected" : ""}"><td><button class="pivot-link" data-pivot-asset="${esc(x.value)}">${esc(x.value)}</button></td><td><span class="pill pill-packet">${x.kind}</span></td><td>${x.flow_count}</td><td>${x.event_count}</td></tr>`).join("");
    tb.querySelectorAll<HTMLTableRowElement>("tr").forEach(r => r.addEventListener("click", (ev) => { if ((ev.target as HTMLElement).classList.contains("pivot-link")) return; selectAsset(Number(r.dataset.id)); }));
}

async function selectAsset(id: number) {
    if (!currentProjectDir) return;
    selectedAssetId = id;
    document.querySelectorAll<HTMLTableRowElement>("#assets-table tbody tr").forEach(r => r.classList.toggle("selected", Number(r.dataset.id) === id));
    const d = await invoke<AssetDetailDto>("cmd_get_asset_detail", { projectDir: currentProjectDir, assetId: id });
    const a = d.asset;
    $("asset-detail").innerHTML = `
        <div class="detail-title">${esc(a.value)}</div>
        <div class="detail-meta"><span class="pill pill-packet">${a.kind}</span>${a.label ? `<span>${esc(a.label)}</span>` : ""}</div>
        <div class="detail-section"><div class="detail-label">Estadísticas</div><div class="detail-row"><div class="detail-row-key">Flujos</div><div class="detail-row-value">${a.flow_count}</div></div><div class="detail-row"><div class="detail-row-key">Eventos</div><div class="detail-row-value">${a.event_count}</div></div><div class="detail-row"><div class="detail-row-key">Paq. env.</div><div class="detail-row-value">${a.packets_sent}</div></div><div class="detail-row"><div class="detail-row-key">Paq. recv.</div><div class="detail-row-value">${a.packets_received}</div></div><div class="detail-row"><div class="detail-row-key">Bytes env.</div><div class="detail-row-value">${fmtBytes(a.bytes_sent)}</div></div><div class="detail-row"><div class="detail-row-key">Bytes recv.</div><div class="detail-row-value">${fmtBytes(a.bytes_received)}</div></div></div>
        <div class="detail-section"><div class="detail-label">Flujos (${d.flows.length})</div>${d.flows.slice(0, 10).map(f => `<div class="related-item"><div style="display:flex;gap:0.4rem;align-items:center;margin-bottom:0.2rem">${protoPill(f.protocol)}<span style="color:var(--muted);font-size:0.72rem">${f.packet_count} pkts · ${fmtBytes(f.captured_bytes)}</span>${f.flags ? flagPill(f.flags) : ""}</div><div style="font-size:0.75rem">${assetSpan(f.endpoint_a)}:${f.endpoint_a_port ?? "—"} ↔ ${assetSpan(f.endpoint_b)}:${f.endpoint_b_port ?? "—"}</div></div>`).join("") || "<div style='color:var(--muted);font-size:0.8rem'>Sin flujos</div>"}</div>
        <div class="detail-section"><div class="detail-label">Eventos recientes (${d.events.length})</div>${d.events.slice(0, 10).map(e => `<div class="related-item" data-id="${e.id}"><div style="display:flex;gap:0.4rem;align-items:center;margin-bottom:0.2rem">${kindPill(e.kind)}<span style="color:var(--muted);font-size:0.72rem">${fmtTsShort(e.timestamp_ns)}</span></div><div style="font-size:0.75rem">${esc(e.summary).substring(0, 90)}</div></div>`).join("") || "<div style='color:var(--muted);font-size:0.8rem'>Sin eventos</div>"}</div>`;
    $("asset-detail").querySelectorAll<HTMLElement>(".related-item[data-id]").forEach(el => el.addEventListener("click", () => { const eid = el.dataset.id; if (eid) { switchTab("events"); setTimeout(() => selectEvent(Number(eid)), 100); } }));
}

async function refreshFlows() {
    if (!currentProjectDir) return;
    const f = await run("Cargando flujos", () => invoke<FlowDto[]>("cmd_list_flows", { projectDir: currentProjectDir }));
    if (!f) return;
    currentFlows = f;
    applyFlowFilters();
}
function applyFlowFilters() {
    const proto = ($("filter-flow-proto") as HTMLSelectElement).value;
    const minB = Number(($("filter-flow-min-bytes") as HTMLInputElement).value) || 0;
    const filtered = currentFlows.filter(x => (!proto || x.protocol === proto) && x.captured_bytes >= minB);
    $("flows-count").textContent = `${filtered.length} flujos (de ${currentFlows.length})`;
    const tb = $("flows-table").querySelector("tbody")!;
    tb.innerHTML = filtered.map(x => `<tr data-flow-id="${x.id}" style="cursor:pointer"><td>${protoPill(x.protocol)}</td><td>${assetSpan(x.endpoint_a)}:${x.endpoint_a_port ?? "—"} ${x.service_a ? `<span class="service-badge">${x.service_a}</span>` : ""}</td><td>${assetSpan(x.endpoint_b)}:${x.endpoint_b_port ?? "—"} ${x.service_b ? `<span class="service-badge">${x.service_b}</span>` : ""}</td><td>${flagPill(x.flags)}</td><td>${x.packet_count}</td><td>${fmtBytes(x.captured_bytes)}</td><td>${fmtDuration(x.duration_ns)}</td><td>${x.packets_per_second !== null ? x.packets_per_second.toFixed(1) : "—"}</td><td>${x.bytes_per_second !== null ? fmtBytes(x.bytes_per_second) + "/s" : "—"}</td><td>${x.bidirectional ? "Sí" : "No"}</td></tr>`).join("");
    tb.querySelectorAll<HTMLTableRowElement>("tr").forEach(r => r.addEventListener("click", (ev) => { if ((ev.target as HTMLElement).classList.contains("pivot-link")) return; selectFlow(Number(r.dataset.flowId)); }));
}
$("btn-filter-flows").addEventListener("click", () => applyFlowFilters());
bindEnter($("filter-flow-min-bytes"), () => applyFlowFilters());

async function selectFlow(id: number) {
    if (!currentProjectDir) return;
    document.querySelectorAll<HTMLTableRowElement>("#flows-table tbody tr").forEach(r => r.classList.toggle("selected", Number(r.dataset.flowId) === id));
    const flow = currentFlows.find(f => f.id === id);
    const events = await run("Cargando sesión", () => invoke<EventDto[]>("cmd_list_flow_events", { projectDir: currentProjectDir, flowId: id }), true);
    if (!events) return;
    const info = flow ? `<div class="detail-title">${protoPill(flow.protocol)} ${esc(flow.endpoint_a)}:${flow.endpoint_a_port ?? "—"} ↔ ${esc(flow.endpoint_b)}:${flow.endpoint_b_port ?? "—"}</div><div class="detail-meta"><span>${flow.packet_count} paquetes · ${fmtBytes(flow.captured_bytes)} · ${fmtDuration(flow.duration_ns)}</span> ${flow.flags ? flagPill(flow.flags) : ""}</div>` : "";
    const evHtml = events.length === 0 ? `<div class="empty-state">Sin eventos para este flujo</div>` : events.map(e => `<div class="related-item" data-id="${e.id}"><div style="display:flex;gap:0.4rem;align-items:center;margin-bottom:0.2rem">${kindPill(e.kind)}<span style="color:var(--muted);font-size:0.72rem">${fmtTsShort(e.timestamp_ns)}</span>${e.tcp_flags ? flagPill(e.tcp_flags) : ""}</div><div style="font-size:0.78rem">${esc(e.summary)}</div></div>`).join("");
    $("flow-session-detail").innerHTML = `${info}<div class="detail-section"><div class="detail-label">Eventos (${events.length})</div>${evHtml}</div><div style="margin-top:0.5rem"><button class="btn-secondary" id="btn-flow-add-note">Añadir nota</button></div>`;
    $("flow-session-detail").querySelectorAll<HTMLElement>(".related-item[data-id]").forEach(el => el.addEventListener("click", () => { const eid = el.dataset.id; if (eid) { switchTab("events"); setTimeout(() => selectEvent(Number(eid)), 100); } }));
    $("btn-flow-add-note").addEventListener("click", async () => {
        const text = prompt("Nota:");
        if (!text || !text.trim()) return;
        await run("Añadiendo", () => invoke<NoteDto>("cmd_add_note", { projectDir: currentProjectDir, targetType: "flow", targetId: id, text }), true);
        setStatus("Nota añadida");
    });
}

async function refreshCorrelations() {
    if (!currentProjectDir) return;
    const w = Number(($("correlation-window") as HTMLSelectElement).value);
    const d = await run("Calculando", () => invoke<CorrelationDto>("cmd_get_correlations", { projectDir: currentProjectDir, windowNs: w }), true);
    if (!d) return;

    const p: string[] = [];
    p.push(`${d.groups.length}${d.total_found > d.groups.length ? ` de ${d.total_found}` : ""} grupos`);
    p.push(`${d.events_considered} eventos`);
    if (d.truncated) p.push(`${d.total_candidates} candidatos → top ${d.events_considered}`);
    if (d.events_without_timestamp > 0) p.push(`${d.events_without_timestamp} sin ts`);
    $("correlations-count").textContent = p.join(" · ");

    $("correlations-list").innerHTML = d.groups.length === 0
        ? `<div class="empty-state">Sin correlaciones en esta ventana</div>`
        : d.groups.map(g => `
        <div class="correlation-item">
            <div class="corr-header">
                <strong>${esc(g.shared_asset)}</strong>
                <span style="color:var(--muted)"> · ${g.event_count} eventos relacionados</span>
                <span style="color:var(--muted)"> · ${fmtTsShort(g.time_min_ns)} → ${fmtTsShort(g.time_max_ns)}</span>
            </div>
            <div class="corr-events">
                ${g.events.map(e => `
                    <div class="corr-event">
                        <div>${kindPill(e.kind)} <strong>#${e.id}</strong> <span style="color:var(--muted);font-size:0.72rem">${fmtTsShort(e.timestamp_ns)}</span></div>
                        <div style="margin-top:0.25rem">${esc(e.summary).substring(0, 120)}</div>
                        <div style="margin-top:0.25rem;font-size:0.7rem;color:var(--muted)">
                            ${esc(e.source_asset || "—")}:${e.source_port ?? "—"} → ${esc(e.destination_asset || "—")}:${e.destination_port ?? "—"}
                        </div>
                    </div>
                `).join("")}
            </div>
            <div class="corr-footer">
                <span style="font-size:0.72rem;color:var(--muted)">Evidencias: ${g.evidence_ids.map(id => `F${id}`).join(", ")}</span>
            </div>
        </div>
        `).join("");
}
$("btn-correlate").addEventListener("click", () => refreshCorrelations());

async function refreshProtocols() {
    if (!currentProjectDir) return;
    const [dns, http, tls] = await Promise.all([
        invoke<DnsResolutionDto[]>("cmd_list_dns_resolutions", { projectDir: currentProjectDir }).catch(() => []),
        invoke<HttpHostDto[]>("cmd_list_http_hosts", { projectDir: currentProjectDir }).catch(() => []),
        invoke<TlsSniDto[]>("cmd_list_tls_snis", { projectDir: currentProjectDir }).catch(() => []),
    ]);
    $("dns-table").querySelector("tbody")!.innerHTML = dns.map(d => `<tr><td>${assetSpan(d.hostname)}</td><td>${assetSpan(d.ip)}</td><td style="color:var(--muted)">${fmtTsShort(d.timestamp_ns)}</td><td>${esc(d.summary)}</td></tr>`).join("") || `<tr><td colspan="4" class="empty-state">Sin resoluciones</td></tr>`;
    $("http-table").querySelector("tbody")!.innerHTML = http.map(h => `<tr><td><strong>${esc(h.host)}</strong></td><td>${h.request_count}</td><td>${h.methods.map(m => `<span class="pill pill-http">${m}</span>`).join(" ")}</td><td style="font-size:0.72rem;color:var(--muted)">${h.sample_uris.map(u => esc(u)).join(" · ")}</td></tr>`).join("") || `<tr><td colspan="4" class="empty-state">Sin peticiones</td></tr>`;
    $("tls-table").querySelector("tbody")!.innerHTML = tls.map(t => `<tr><td><strong>${esc(t.sni)}</strong></td><td>${t.count}</td><td>${t.versions.join(", ")}</td><td>${t.alpn.join(", ")}</td><td style="font-size:0.72rem;color:var(--muted)">${t.client_ips.slice(0, 3).join(", ")}${t.client_ips.length > 3 ? "…" : ""}</td></tr>`).join("") || `<tr><td colspan="5" class="empty-state">Sin ClientHellos</td></tr>`;
}

async function runBaselineDetection() {
    if (!currentProjectDir) return;
    if (!baselineConfigCache) baselineConfigCache = await invoke<BaselineConfigDto>("cmd_get_baseline_config");
    const r = await run("Detectando baseline", () => invoke<string>("cmd_detect_baseline_anomalies", { projectDir: currentProjectDir, config: baselineConfigCache }), true);
    if (!r) return;
    setStatus(r);
    $("baseline-message").textContent = r;
    const all = await invoke<FindingDto[]>("cmd_list_findings", { projectDir: currentProjectDir });
    const baselineFindings = all.filter(f => f.title.includes("Desviación estadística"));
    const container = $("baseline-findings-container");
    if (baselineFindings.length === 0) { container.classList.add("hidden"); } else {
        container.classList.remove("hidden");
        $("baseline-findings-table").querySelector("tbody")!.innerHTML = baselineFindings.map(f => `<tr><td>${sevPill(f.severity)}</td><td>${esc(f.title)}</td><td style="font-size:0.78rem">${esc(f.description)}</td></tr>`).join("");
    }
    refreshFindingsBadge();
}
$("btn-detect-baseline").addEventListener("click", runBaselineDetection);
$("btn-config-baseline").addEventListener("click", async () => {
    if (!baselineConfigCache) baselineConfigCache = await invoke<BaselineConfigDto>("cmd_get_baseline_config");
    renderBaselineConfigModal(baselineConfigCache);
    $("modal-baseline-config").classList.remove("hidden");
});
function renderBaselineConfigModal(c: BaselineConfigDto) {
    $("modal-body-baseline").innerHTML = `
        <div class="config-section"><h4>Muestra mínima</h4><div class="config-row"><label>Activos del mismo tipo</label><input type="number" data-bkey="min_entities_per_kind" value="${c.min_entities_per_kind}" min="2" /></div><div class="config-hint">Por debajo de este número, no se calcula baseline para ese tipo.</div></div>
        <div class="config-section"><h4>Umbrales z-score</h4><div class="config-row"><label>Outlier (bajo)</label><input type="number" data-bkey="modified_zscore_threshold" value="${c.modified_zscore_threshold}" step="0.1" min="1" /></div><div class="config-row"><label>Outlier fuerte (medio)</label><input type="number" data-bkey="high_zscore_threshold" value="${c.high_zscore_threshold}" step="0.1" min="2" /></div><div class="config-hint">Iglewicz-Hoaglin recomienda 3.5 y 5.0.</div></div>
        <div class="config-section"><h4>Flujos mínimos por activo</h4><div class="config-row"><label>Ignorar activos con menos de</label><input type="number" data-bkey="min_flows_per_asset" value="${c.min_flows_per_asset}" min="0" /></div></div>
        <div class="config-section"><h4>Métricas</h4><div class="config-row"><label>Volumen de bytes</label><input type="checkbox" data-bkey="enable_bytes_baseline" ${c.enable_bytes_baseline ? "checked" : ""} /></div><div class="config-row"><label>Número de flujos</label><input type="checkbox" data-bkey="enable_flow_count_baseline" ${c.enable_flow_count_baseline ? "checked" : ""} /></div></div>`;
}
function readBaselineConfigFromModal(): BaselineConfigDto {
    const get = (k: string, c: boolean): any => { const el = document.querySelector<HTMLInputElement>(`[data-bkey="${k}"]`); return !el ? null : (c ? el.checked : Number(el.value)); };
    return { min_entities_per_kind: get("min_entities_per_kind", false), modified_zscore_threshold: get("modified_zscore_threshold", false), high_zscore_threshold: get("high_zscore_threshold", false), min_flows_per_asset: get("min_flows_per_asset", false), enable_bytes_baseline: get("enable_bytes_baseline", true), enable_flow_count_baseline: get("enable_flow_count_baseline", true) };
}
$("modal-close-baseline").addEventListener("click", () => $("modal-baseline-config").classList.add("hidden"));
$("btn-baseline-cancel").addEventListener("click", () => $("modal-baseline-config").classList.add("hidden"));
$("btn-baseline-reset").addEventListener("click", async () => { baselineConfigCache = await invoke<BaselineConfigDto>("cmd_get_baseline_config"); renderBaselineConfigModal(baselineConfigCache); });
$("btn-baseline-apply").addEventListener("click", async () => { baselineConfigCache = readBaselineConfigFromModal(); $("modal-baseline-config").classList.add("hidden"); await runBaselineDetection(); });

async function populateDiffSources() {
    if (!currentProjectDir) return;
    const sources = await invoke<SourceDto[]>("cmd_list_sources", { projectDir: currentProjectDir });
    const sa = $("diff-source-a") as HTMLSelectElement;
    const sb = $("diff-source-b") as HTMLSelectElement;
    const opts = sources.map(s => `<option value="${s.id}">${esc(s.file_name)} (ID ${s.id})</option>`).join("");
    sa.innerHTML = opts; sb.innerHTML = opts;
    if (sources.length > 1) sa.value = String(sources[0].id); sb.value = String(sources[1].id);
}
$("btn-run-diff").addEventListener("click", async () => {
    if (!currentProjectDir) return;
    const sa = Number(($("diff-source-a") as HTMLSelectElement).value);
    const sb = Number(($("diff-source-b") as HTMLSelectElement).value);
    if (!sa || !sb) { setStatus("Selecciona ambas fuentes"); return; }
    if (sa === sb) { setStatus("Selecciona dos fuentes distintas"); return; }
    
    const d = await run("Comparando fuentes", () => invoke<DiffDto>("cmd_diff_sources", { projectDir: currentProjectDir, sourceA: sa, sourceB: sb }), true);
    if (!d) return;
    const listHtml = (items: string[], empty: string) => items.length === 0 ? `<div style="color:var(--muted);font-size:0.8rem">${empty}</div>` : items.map(i => `<div class="diff-item"><code>${esc(i)}</code></div>`).join("");
    $("diff-result").innerHTML = `
        <div class="diff-section">
            <h3>Activos</h3>
            <div class="diff-columns">
                <div class="diff-col"><h4>Solo en ${esc(d.name_a)} (${d.assets_only_in_a.length})</h4>${listHtml(d.assets_only_in_a, "Ninguno")}</div>
                <div class="diff-col"><h4>Solo en ${esc(d.name_b)} (${d.assets_only_in_b.length})</h4>${listHtml(d.assets_only_in_b, "Ninguno")}</div>
                <div class="diff-col"><h4>Compartidos (${d.assets_shared.length})</h4>${listHtml(d.assets_shared.slice(0, 50), "Ninguno")}</div>
            </div>
        </div>
        <div class="diff-section">
            <h3>Flujos</h3>
            <div class="diff-columns">
                <div class="diff-col"><h4>Solo en ${esc(d.name_a)} (${d.flows_only_in_a.length})</h4>${listHtml(d.flows_only_in_a.slice(0, 50), "Ninguno")}</div>
                <div class="diff-col"><h4>Solo en ${esc(d.name_b)} (${d.flows_only_in_b.length})</h4>${listHtml(d.flows_only_in_b.slice(0, 50), "Ninguno")}</div>
            </div>
        </div>`;
});

async function refreshFindings() {
    if (!currentProjectDir) return;
    const f = await run("Cargando hallazgos", () => invoke<FindingDto[]>("cmd_list_findings", { projectDir: currentProjectDir }));
    if (!f) return;
    allFindings = f;
    $("findings-list").innerHTML = f.length === 0 ? `<div class="empty-state">Sin hallazgos. Pulsa "Detectar anomalías".</div>` : f.map(x => `<div class="finding-item" data-id="${x.id}"><div class="finding-title">${esc(x.title)}</div><div class="finding-meta">${sevPill(x.severity)}<span>${x.confidence_percent ?? 0}% conf.</span></div></div>`).join("");
    document.querySelectorAll<HTMLElement>(".finding-item").forEach(el => el.addEventListener("click", () => showFindingDetail(Number(el.dataset.id))));
    await refreshFindingsBadge();
}
function showFindingDetail(id: number) {
    const f = allFindings.find(x => x.id === id);
    if (!f) return;
    document.querySelectorAll<HTMLElement>(".finding-item").forEach(el => el.classList.toggle("selected", Number(el.dataset.id) === id));
    $("finding-detail").innerHTML = `<div class="detail-title">${esc(f.title)}</div><div class="detail-meta">${sevPill(f.severity)}<span>${f.confidence_percent ?? 0}%</span><span>· ${f.kind}</span></div><div class="detail-section"><div class="detail-label">Descripción</div><div style="font-size:0.82rem;line-height:1.6">${esc(f.description)}</div></div><div class="detail-section"><div class="detail-label">Evidencias</div><div>${f.evidence_ids.map(eid => `<span class="evidence-chip">Frame ${eid}</span>`).join("") || "—"}</div></div>`;
}

$("btn-detect-now").addEventListener("click", async () => {
    if (!currentProjectDir) { setStatus("Abre un proyecto primero"); return; }
    const cfg = anomalyConfigCache ?? await invoke<AnomalyConfigDto>("cmd_get_anomaly_config");
    const r = await run("Detectando anomalías", () => invoke<string>("cmd_detect_anomalies_with_config", { projectDir: currentProjectDir, config: cfg }), true);
    if (r) { setStatus(r); refreshFindings(); }
});
$("btn-config-anomalies").addEventListener("click", async () => {
    if (!anomalyConfigCache) anomalyConfigCache = await invoke<AnomalyConfigDto>("cmd_get_anomaly_config");
    renderAnomalyConfigModal(anomalyConfigCache);
    $("modal-anomaly-config").classList.remove("hidden");
});
function renderAnomalyConfigModal(c: AnomalyConfigDto) {
    $("modal-body").innerHTML = `
        <div class="config-section"><h4>HTTP en puerto no estándar</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_http_on_unusual_port" ${c.enable_http_on_unusual_port ? "checked" : ""} /></div></div>
        <div class="config-section"><h4>TLS sobre puerto 80</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_tls_on_plain_port" ${c.enable_tls_on_plain_port ? "checked" : ""} /></div></div>
        <div class="config-section"><h4>Flujo grande</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_large_flow" ${c.enable_large_flow ? "checked" : ""} /></div><div class="config-row"><label>Umbral (bytes)</label><input type="number" data-key="large_flow_threshold_bytes" value="${c.large_flow_threshold_bytes}" min="1024" /></div></div>
        <div class="config-section"><h4>Beaconing</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_beaconing" ${c.enable_beaconing ? "checked" : ""} /></div><div class="config-row"><label>Conexiones mín.</label><input type="number" data-key="beacon_min_connections" value="${c.beacon_min_connections}" min="3" /></div><div class="config-row"><label>CV máx.</label><input type="number" data-key="beacon_max_cv" value="${c.beacon_max_cv}" step="0.01" min="0.01" max="1" /></div></div>
        <div class="config-section"><h4>DNS tunneling</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_dns_tunneling" ${c.enable_dns_tunneling ? "checked" : ""} /></div><div class="config-row"><label>Long. nombre máx.</label><input type="number" data-key="dns_long_name_threshold" value="${c.dns_long_name_threshold}" min="20" /></div><div class="config-row"><label>Subdominios máx.</label><input type="number" data-key="dns_max_unique_subdomains" value="${c.dns_max_unique_subdomains}" min="5" /></div></div>
        <div class="config-section"><h4>Port scanning</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_port_scanning" ${c.enable_port_scanning ? "checked" : ""} /></div><div class="config-row"><label>Destinos máx.</label><input type="number" data-key="portscan_max_distinct_destinations" value="${c.portscan_max_distinct_destinations}" min="5" /></div><div class="config-row"><label>Ventana (ns)</label><input type="number" data-key="portscan_window_ns" value="${c.portscan_window_ns}" min="1000000000" /></div></div>`;
}
function readAnomalyConfigFromModal(): AnomalyConfigDto {
    const r = (k: string, c: boolean): any => { const el = document.querySelector<HTMLInputElement>(`[data-key="${k}"]`); return !el ? null : (c ? el.checked : Number(el.value)); };
    return {
        enable_http_on_unusual_port: r("enable_http_on_unusual_port", true), enable_tls_on_plain_port: r("enable_tls_on_plain_port", true), enable_large_flow: r("enable_large_flow", true), large_flow_threshold_bytes: r("large_flow_threshold_bytes", false), enable_beaconing: r("enable_beaconing", true), beacon_min_connections: r("beacon_min_connections", false), beacon_max_cv: r("beacon_max_cv", false), enable_dns_tunneling: r("enable_dns_tunneling", true), dns_long_name_threshold: r("dns_long_name_threshold", false), dns_max_unique_subdomains: r("dns_max_unique_subdomains", false), enable_port_scanning: r("enable_port_scanning", true), portscan_max_distinct_destinations: r("portscan_max_distinct_destinations", false), portscan_window_ns: r("portscan_window_ns", false)
    };
}
$("modal-close").addEventListener("click", () => $("modal-anomaly-config").classList.add("hidden"));
$("btn-config-cancel").addEventListener("click", () => $("modal-anomaly-config").classList.add("hidden"));
$("btn-config-reset").addEventListener("click", async () => { anomalyConfigCache = await invoke<AnomalyConfigDto>("cmd_get_anomaly_config"); renderAnomalyConfigModal(anomalyConfigCache); });
$("btn-config-apply").addEventListener("click", async () => {
    if (!currentProjectDir) { setStatus("Abre un proyecto primero"); return; }
    anomalyConfigCache = readAnomalyConfigFromModal();
    $("modal-anomaly-config").classList.add("hidden");
    const r = await run("Detectando anomalías", () => invoke<string>("cmd_detect_anomalies_with_config", { projectDir: currentProjectDir, config: anomalyConfigCache }), true);
    if (r) { setStatus(r); switchTab("findings"); }
});

async function refreshTimeline() {
    if (!currentProjectDir) return;
    const d = await run("Cargando cronología", () => invoke<TimelineV2Dto>("cmd_get_timeline_v2", { projectDir: currentProjectDir }), true);
    if (!d) return;
    const entries = d.entries;
    $("timeline-meta").textContent = `${entries.length} entradas${d.events_without_timestamp > 0 ? ` · ${d.events_without_timestamp} sin ts` : ""}`;
    const bucketCount = 60;
    if (entries.length > 0) {
        const minTs = entries[entries.length - 1].timestamp_ns; const maxTs = entries[0].timestamp_ns; const span = maxTs - minTs;
        const buckets = Array.from({ length: bucketCount }, () => ({ e: 0, f: 0, start: 0 }));
        if (span > 0) {
            const step = span / bucketCount;
            for (const e of entries) {
                const i = Math.min(bucketCount - 1, Math.floor((e.timestamp_ns - minTs) / step));
                buckets[i].start = minTs + i * step;
                if (e.kind === "Event") buckets[i].e++; else buckets[i].f++;
            }
        }
        const maxC = Math.max(1, ...buckets.map(b => b.e + b.f));
        $("timeline-histogram").innerHTML = buckets.map(b => `<div class="timeline-bar ${b.f > b.e ? "flow" : ""}" style="height:${Math.max(1, ((b.e + b.f) / maxC) * 100)}%" title="${b.e} ev · ${b.f} fl · ${fmtTsShort(b.start)}"></div>`).join("");
    }
    const tb = $("timeline-table").querySelector("tbody")!;
    tb.innerHTML = entries.map(e => {
        if (e.kind === "Event") return `<tr><td style="white-space:nowrap;color:var(--muted)">${fmtTsShort(e.timestamp_ns)}</td><td>${kindPill(e.event_kind || "Event")}</td><td>${esc(e.event_summary || "")}</td><td style="font-size:0.72rem;color:var(--muted)">${e.evidence_ids.map(id => `F${id}`).join(", ")}</td></tr>`;
        return `<tr><td style="white-space:nowrap;color:var(--muted)">${fmtTsShort(e.timestamp_ns)}</td><td><span class="pill pill-tls">Flow</span></td><td>${esc(e.flow_endpoint_a || "")} ↔ ${esc(e.flow_endpoint_b || "")} · ${e.flow_packet_count} pkts · ${fmtBytes(e.flow_captured_bytes || 0)}</td><td style="font-size:0.72rem;color:var(--muted)">${e.evidence_ids.map(id => `F${id}`).join(", ")}</td></tr>`;
    }).join("");
}

async function exportAs(kind: "md" | "csv" | "json" | "html") {
    if (!currentProjectDir) { setStatus("Abre un proyecto primero"); return; }
    const ext = kind;
    const name = kind === "md" ? "informe.md" : kind === "html" ? "informe.html" : `eventos.${ext}`;
    const path = await save({ defaultPath: name, filters: [{ name: kind.toUpperCase(), extensions: [ext] }] });
    if (!path) return;
    const cmd = kind === "md" ? "cmd_export_markdown" : kind === "csv" ? "cmd_export_csv" : kind === "json" ? "cmd_export_json" : "cmd_export_report_html";
    const r = await run(`Exportando ${ext.toUpperCase()}`, () => invoke<string>(cmd, { projectDir: currentProjectDir, outputPath: path }), true);
    if (r) setStatus(r);
}
$("btn-export-md").addEventListener("click", () => exportAs("md"));
$("btn-export-html").addEventListener("click", () => exportAs("html"));
$("btn-export-csv").addEventListener("click", () => exportAs("csv"));
$("btn-export-json").addEventListener("click", () => exportAs("json"));

setStatus("Listo · Importa un PCAP o abre un proyecto");```


## Archivo: `nextrace-core/Cargo.toml`

```toml
[package]
name = "nextrace-core"
version = "0.1.0"
edition = "2024"

[dependencies]
```


## Archivo: `nextrace-core/src/lib.rs`

```rust
mod pcapng;
pub use pcapng::{PcapNgError, PcapNgReader};

mod project;
pub use project::*;

mod correlation;
pub use correlation::*;

mod flow_analysis;
pub use flow_analysis::*;

mod analyzer;
pub use analyzer::*;

mod model;

pub use model::*;
mod source_store;

mod pcap;
mod payload;

pub use payload::{extract_transport_payload, TransportPayload};

mod dns;
pub use dns::*;

mod tls;
pub use tls::*;

mod http;
pub use http::*;

mod tcp_reassembly;
pub use tcp_reassembly::*;

mod anomaly;
pub use anomaly::*;

mod query;
pub use query::*;

mod export;
pub use export::*;

pub use pcap::*;

pub use source_store::{import_source, SourceImportError};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn creates_a_complete_investigation() {
        let mut investigation = Investigation::new(
            InvestigationId(1),
            "Investigación de prueba",
            Some("Prueba del modelo de datos".to_string()),
            1_798_000_000_000_000_000,
        )
        .unwrap();

        investigation
            .add_source(SourceFile {
                id: SourceId(1),
                file_name: "capture.pcap".to_string(),
                relative_path: PathBuf::from("sources/capture.pcap"),
                format: SourceFormat::Pcap,
                size_bytes: 1024,
                sha256: None,
                imported_at_unix_ns: 1_798_000_000_000_000_000,
            })
            .unwrap();

        investigation
            .add_asset(Asset {
                id: AssetId(1),
                kind: AssetKind::IpAddress,
                value: "192.168.1.10".to_string(),
                label: Some("Equipo de prueba".to_string()),
            })
            .unwrap();

        investigation
            .add_evidence(Evidence {
                id: EvidenceId(1),
                source_id: SourceId(1),
                location: EvidenceLocation::PacketFrame { frame_number: 1 },
                excerpt: Some("Primer paquete de la captura".to_string()),
            })
            .unwrap();

        investigation
            .add_event(NetworkEvent {
                id: EventId(1),
                timestamp_unix_ns: None,
                kind: EventKind::NetworkFlow,
                summary: "Conexión TCP observada".to_string(),
                source_asset: Some(AssetId(1)),
                destination_asset: None,
                source_port: Some(51000),
                destination_port: Some(443),
                protocol: Some(Protocol::Tcp),
                evidence_ids: vec![EvidenceId(1)],
            })
            .unwrap();

        investigation
            .add_finding(Finding {
                id: FindingId(1),
                kind: FindingKind::Observation,
                severity: Severity::Info,
                title: "Conexión identificada".to_string(),
                description: "Se observó una conexión TCP en la captura".to_string(),
                evidence_ids: vec![EvidenceId(1)],
                confidence_percent: Some(100),
            })
            .unwrap();

        assert_eq!(investigation.sources().len(), 1);
        assert_eq!(investigation.assets().len(), 1);
        assert_eq!(investigation.evidences().len(), 1);
        assert_eq!(investigation.events().len(), 1);
        assert_eq!(investigation.findings().len(), 1);
    }

    #[test]
    fn rejects_evidence_without_a_valid_source() {
        let mut investigation =
            Investigation::new(InvestigationId(1), "Prueba", None, 0).unwrap();

        let evidence = Evidence {
            id: EvidenceId(1),
            source_id: SourceId(99),
            location: EvidenceLocation::LogLine { line_number: 10 },
            excerpt: None,
        };

        let result = investigation.add_evidence(evidence);

        assert_eq!(result, Err(DomainError::UnknownSource(SourceId(99))));
    }

    #[test]
    fn rejects_an_event_without_evidence() {
        let mut investigation =
            Investigation::new(InvestigationId(1), "Prueba", None, 0).unwrap();

        let event = NetworkEvent {
            id: EventId(1),
            timestamp_unix_ns: None,
            kind: EventKind::Packet,
            summary: "Evento sin procedencia".to_string(),
            source_asset: None,
            destination_asset: None,
            source_port: None,
            destination_port: None,
            protocol: None,
            evidence_ids: Vec::new(),
        };

        let result = investigation.add_event(event);

        assert_eq!(result, Err(DomainError::MissingEvidence("El evento")));
    }
}

mod timeline;
pub use timeline::*;

mod report;
pub use report::*;

mod baseline;
pub use baseline::*;

mod persistence;
pub use persistence::*;```


## Archivo: `nextrace-core/src/dns.rs`

```rust
// Parser DNS (RFC 1035) sin dependencias externas.
//
// Principios de diseño:
//   * Nunca entra en pánico con datos malformados (fuzz-safe).
//   * Rechaza punteros de compresión hacia delante o autorreferencia.
//   * Valida longitudes de nombre (255) y de etiqueta (63).
//   * Devuelve el mensaje completo o un error tipado, nunca parcial.
//   * Trata rdata desconocida como bytes crudos, no como fallo.
//
// No realiza decodificación de IDNA/Punycode. Los nombres se
// preservan tal como aparecen en la captura, usando from_utf8_lossy
// para no perder bytes no-UTF-8 (mDNS, DNS de laboratorio, etc.).

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

const DNS_HEADER_LEN: usize = 12;
const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255;
const MAX_COMPRESSION_JUMPS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    TruncatedHeader,
    TruncatedName,
    TruncatedRecord,
    CompressionLoop,
    InvalidCompression,
    InvalidLabelType,
    NameTooLong,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => write!(f, "cabecera DNS truncada"),
            Self::TruncatedName => write!(f, "nombre DNS truncado"),
            Self::TruncatedRecord => write!(f, "registro DNS truncado"),
            Self::CompressionLoop => write!(f, "bucle de compresión DNS"),
            Self::InvalidCompression => write!(f, "compresión DNS inválida"),
            Self::InvalidLabelType => write!(f, "tipo de etiqueta DNS inválido"),
            Self::NameTooLong => write!(f, "nombre DNS demasiado largo"),
        }
    }
}

impl std::error::Error for DnsError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Opt,
    Caa,
    Https,
    Other(u16),
}

impl DnsRecordType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            41 => Self::Opt,
            65 => Self::Https,
            257 => Self::Caa,
            other => Self::Other(other),
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A => write!(f, "A"),
            Self::Ns => write!(f, "NS"),
            Self::Cname => write!(f, "CNAME"),
            Self::Soa => write!(f, "SOA"),
            Self::Ptr => write!(f, "PTR"),
            Self::Mx => write!(f, "MX"),
            Self::Txt => write!(f, "TXT"),
            Self::Aaaa => write!(f, "AAAA"),
            Self::Srv => write!(f, "SRV"),
            Self::Opt => write!(f, "OPT"),
            Self::Caa => write!(f, "CAA"),
            Self::Https => write!(f, "HTTPS"),
            Self::Other(value) => write!(f, "TYPE{value}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Name(String),
    Mx { preference: u16, exchange: String },
    Txt(Vec<Vec<u8>>),
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Raw(Vec<u8>),
}

impl DnsRdata {
    /// Representación corta y legible, útil para evidencias y eventos.
    pub fn short(&self) -> String {
        match self {
            Self::A(ip) => ip.to_string(),
            Self::Aaaa(ip) => ip.to_string(),
            Self::Name(name) => name.clone(),
            Self::Mx { preference, exchange } => {
                format!("{preference} {exchange}")
            }
            Self::Txt(strings) => strings
                .iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" "),
            Self::Srv { priority, weight, port, target } => {
                format!("{priority} {weight} {port} {target}")
            }
            Self::Soa { mname, .. } => format!("SOA {mname}"),
            Self::Raw(bytes) => format!("{} bytes", bytes.len()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsRecordType,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: DnsRecordType,
    pub class: u16,
    pub ttl: u32,
    pub rdata: DnsRdata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    /// Nombres de todos los registros A/AAAA/CNAME en la sección de respuestas.
    pub fn answer_addresses(&self) -> Vec<String> {
        self.answers
            .iter()
            .filter_map(|record| match &record.rdata {
                DnsRdata::A(ip) => Some(ip.to_string()),
                DnsRdata::Aaaa(ip) => Some(ip.to_string()),
                DnsRdata::Name(name) => Some(name.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Parser principal. Acepta cualquier `&[u8]` y nunca entra en pánico.
pub fn parse_dns(bytes: &[u8]) -> Result<DnsMessage, DnsError> {
    if bytes.len() < DNS_HEADER_LEN {
        return Err(DnsError::TruncatedHeader);
    }

    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);

    let is_response = flags & 0x8000 != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let authoritative = flags & 0x0400 != 0;
    let truncated = flags & 0x0200 != 0;
    let recursion_desired = flags & 0x0100 != 0;
    let recursion_available = flags & 0x0080 != 0;
    let rcode = (flags & 0x000F) as u8;

    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let nscount = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
    let arcount = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;

    let mut offset = DNS_HEADER_LEN;

    // Reservamos con un tope para evitar DoS si la cabecera miente.
    let mut questions = Vec::with_capacity(qdcount.min(16));
    for _ in 0..qdcount {
        let (name, consumed) = read_name(bytes, offset)?;
        offset = offset
            .checked_add(consumed)
            .ok_or(DnsError::TruncatedRecord)?;

        if offset + 4 > bytes.len() {
            return Err(DnsError::TruncatedRecord);
        }

        let qtype = DnsRecordType::from_u16(u16::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
        ]));
        let qclass = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        offset += 4;

        questions.push(DnsQuestion { name, qtype, qclass });
    }

    let answers = read_records(bytes, &mut offset, ancount)?;
    let authorities = read_records(bytes, &mut offset, nscount)?;
    let additionals = read_records(bytes, &mut offset, arcount)?;

    Ok(DnsMessage {
        id,
        is_response,
        opcode,
        authoritative,
        truncated,
        recursion_desired,
        recursion_available,
        rcode,
        questions,
        answers,
        authorities,
        additionals,
    })
}

fn read_records(
    bytes: &[u8],
    offset: &mut usize,
    count: usize,
) -> Result<Vec<DnsRecord>, DnsError> {
    let mut records = Vec::with_capacity(count.min(32));
    for _ in 0..count {
        let (record, consumed) = read_record(bytes, *offset)?;
        *offset = (*offset)
            .checked_add(consumed)
            .ok_or(DnsError::TruncatedRecord)?;
        records.push(record);
    }
    Ok(records)
}

/// Devuelve `(nombre, bytes_consumidos_desde_start)`.
/// `bytes_consumidos_desde_start` es lo que hay que avanzar en el
/// flujo principal. Si hubo salto de compresión, es la longitud del
/// puntero (2), no lo leído en el destino.
fn read_name(bytes: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut pos = start;
    let mut labels: Vec<String> = Vec::new();
    let mut total_len: usize = 0;
    let mut jumps: usize = 0;
    let mut consumed: Option<usize> = None;

    loop {
        if pos >= bytes.len() {
            return Err(DnsError::TruncatedName);
        }

        let first = bytes[pos];

        if first == 0 {
            pos += 1;
            if consumed.is_none() {
                consumed = Some(pos - start);
            }
            break;
        }

        if first & 0xC0 == 0xC0 {
            if pos + 1 >= bytes.len() {
                return Err(DnsError::TruncatedName);
            }
            if consumed.is_none() {
                consumed = Some((pos + 2) - start);
            }
            let pointer = (((first as usize) & 0x3F) << 8) | (bytes[pos + 1] as usize);
            // Un puntero hacia delante o autorreferencia siempre es inválido:
            // en el RFC 1035 el destino ya debe haber sido leído.
            if pointer >= start {
                return Err(DnsError::InvalidCompression);
            }
            jumps += 1;
            if jumps > MAX_COMPRESSION_JUMPS {
                return Err(DnsError::CompressionLoop);
            }
            pos = pointer;
        } else if first & 0xC0 != 0 {
            return Err(DnsError::InvalidLabelType);
        } else {
            let label_len = first as usize;
            if label_len > MAX_LABEL_LEN {
                return Err(DnsError::InvalidLabelType);
            }
            if pos + 1 + label_len > bytes.len() {
                return Err(DnsError::TruncatedName);
            }
            total_len = total_len
                .checked_add(1 + label_len)
                .ok_or(DnsError::NameTooLong)?;
            if total_len > MAX_NAME_LEN {
                return Err(DnsError::NameTooLong);
            }
            let label = String::from_utf8_lossy(&bytes[pos + 1..pos + 1 + label_len])
                .into_owned();
            labels.push(label);
            pos += 1 + label_len;
        }
    }

    let consumed = consumed.ok_or(DnsError::TruncatedName)?;
    Ok((labels.join("."), consumed))
}

fn read_record(bytes: &[u8], start: usize) -> Result<(DnsRecord, usize), DnsError> {
    let (name, name_consumed) = read_name(bytes, start)?;
    let mut offset = start + name_consumed;

    if offset + 10 > bytes.len() {
        return Err(DnsError::TruncatedRecord);
    }

    let rtype = DnsRecordType::from_u16(u16::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
    ]));
    let class = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
    let ttl = u32::from_be_bytes([
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([bytes[offset + 8], bytes[offset + 9]]) as usize;
    offset += 10;

    if offset + rdlength > bytes.len() {
        return Err(DnsError::TruncatedRecord);
    }

    let rdata_bytes = &bytes[offset..offset + rdlength];
    let rdata = parse_rdata(rtype, bytes, offset, rdata_bytes);

    Ok((
        DnsRecord { name, rtype, class, ttl, rdata },
        name_consumed + 10 + rdlength,
    ))
}

fn parse_rdata(
    rtype: DnsRecordType,
    full_message: &[u8],
    rdata_offset: usize,
    rdata: &[u8],
) -> DnsRdata {
    match rtype {
        DnsRecordType::A => {
            if rdata.len() == 4 {
                DnsRdata::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))
            } else {
                DnsRdata::Raw(rdata.to_vec())
            }
        }
        DnsRecordType::Aaaa => {
            if rdata.len() == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                DnsRdata::Aaaa(Ipv6Addr::from(octets))
            } else {
                DnsRdata::Raw(rdata.to_vec())
            }
        }
        DnsRecordType::Cname | DnsRecordType::Ns | DnsRecordType::Ptr => {
            match read_name(full_message, rdata_offset) {
                Ok((name, _)) => DnsRdata::Name(name),
                Err(_) => DnsRdata::Raw(rdata.to_vec()),
            }
        }
        DnsRecordType::Mx => {
            if rdata.len() < 3 {
                return DnsRdata::Raw(rdata.to_vec());
            }
            let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
            match read_name(full_message, rdata_offset + 2) {
                Ok((exchange, _)) => DnsRdata::Mx { preference, exchange },
                Err(_) => DnsRdata::Raw(rdata.to_vec()),
            }
        }
        DnsRecordType::Txt => {
            let mut strings = Vec::new();
            let mut i = 0usize;
            while i < rdata.len() {
                let len = rdata[i] as usize;
                i += 1;
                if i + len > rdata.len() {
                    return DnsRdata::Raw(rdata.to_vec());
                }
                strings.push(rdata[i..i + len].to_vec());
                i += len;
            }
            DnsRdata::Txt(strings)
        }
        DnsRecordType::Srv => {
            if rdata.len() < 7 {
                return DnsRdata::Raw(rdata.to_vec());
            }
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            match read_name(full_message, rdata_offset + 6) {
                Ok((target, _)) => DnsRdata::Srv { priority, weight, port, target },
                Err(_) => DnsRdata::Raw(rdata.to_vec()),
            }
        }
        DnsRecordType::Soa => {
            let Ok((mname, consumed1)) = read_name(full_message, rdata_offset) else {
                return DnsRdata::Raw(rdata.to_vec());
            };
            let rname_offset = rdata_offset + consumed1;
            let Ok((rname, consumed2)) = read_name(full_message, rname_offset) else {
                return DnsRdata::Raw(rdata.to_vec());
            };
            let fixed = rname_offset + consumed2;
            if fixed + 20 > full_message.len() {
                return DnsRdata::Raw(rdata.to_vec());
            }
            let read_u32 = |off: usize| {
                u32::from_be_bytes([
                    full_message[off],
                    full_message[off + 1],
                    full_message[off + 2],
                    full_message[off + 3],
                ])
            };
            DnsRdata::Soa {
                mname,
                rname,
                serial: read_u32(fixed),
                refresh: read_u32(fixed + 4),
                retry: read_u32(fixed + 8),
                expire: read_u32(fixed + 12),
                minimum: read_u32(fixed + 16),
            }
        }
        _ => DnsRdata::Raw(rdata.to_vec()),
    }
}

/// Resumen legible, apto para `evidence.excerpt` y `event.summary`.
pub fn summarize(message: &DnsMessage) -> String {
    let kind = if message.is_response { "respuesta" } else { "consulta" };

    if message.questions.is_empty() {
        return format!("DNS {kind} sin pregunta (rcode {})", message.rcode);
    }

    let question = &message.questions[0];
    let q = format!("{} {}", question.name, question.qtype);

    if !message.is_response {
        format!("DNS consulta: {q}")
    } else if let Some(answer) = message.answers.first() {
        format!("DNS respuesta: {q} -> {}", answer.rdata.short())
    } else {
        format!("DNS respuesta: {q} sin respuestas (rcode {})", message.rcode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Constructores de fixtures
    //
    // Nota de diseño: construimos siempre con offsets absolutos y
    // escritura secuencial, para que un test nunca pueda "corromper"
    // otra parte del mensaje por error.
    // ------------------------------------------------------------------

    /// Construye una consulta DNS con una sola pregunta.
    fn build_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        data.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD
        data.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        data.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
        data.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        data.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        for label in name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0); // Fin de nombre
        data.extend_from_slice(&qtype.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        data
    }

    /// Construye una respuesta DNS de ejemplo:
    ///   QNAME = "example.com" A IN
    ///   Answer = <name> <rtype> IN <ttl> <rdata>
    /// donde <name> usa compresión apuntando a QNAME (offset 12).
    fn build_response_with_rdata(rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        data.extend_from_slice(&0x8180u16.to_be_bytes()); // QR, RD, RA, rcode=0
        data.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        data.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
        data.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        data.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        // Pregunta: example.com, tipo A, clase IN
        data.push(7);
        data.extend_from_slice(b"example");
        data.push(3);
        data.extend_from_slice(b"com");
        data.push(0);
        data.extend_from_slice(&1u16.to_be_bytes()); // QTYPE A
        data.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN

        // Respuesta: nombre por compresión al offset 12
        data.push(0xC0);
        data.push(0x0C);
        data.extend_from_slice(&rtype.to_be_bytes()); // RTYPE
        data.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        data.extend_from_slice(&300u32.to_be_bytes()); // TTL
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(rdata);
        data
    }

    fn build_response_with_a() -> Vec<u8> {
        build_response_with_rdata(1, &[1, 2, 3, 4])
    }

    // ------------------------------------------------------------------
    // Casos de prueba
    // ------------------------------------------------------------------

    #[test]
    fn parses_simple_a_query() {
        let bytes = build_query("example.com", 1);
        let message = parse_dns(&bytes).unwrap();

        assert_eq!(message.id, 0x1234);
        assert!(!message.is_response);
        assert!(message.recursion_desired);
        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.questions[0].name, "example.com");
        assert_eq!(message.questions[0].qtype, DnsRecordType::A);
        assert_eq!(message.questions[0].qclass, 1);
        assert!(message.answers.is_empty());
    }

    #[test]
    fn parses_response_with_compressed_a_record() {
        let bytes = build_response_with_a();
        let message = parse_dns(&bytes).unwrap();

        assert!(message.is_response);
        assert!(message.recursion_available);
        assert_eq!(message.rcode, 0);
        assert_eq!(message.questions[0].name, "example.com");

        assert_eq!(message.answers.len(), 1);
        let answer = &message.answers[0];
        assert_eq!(answer.name, "example.com");
        assert_eq!(answer.rtype, DnsRecordType::A);
        assert_eq!(answer.ttl, 300);
        assert_eq!(answer.rdata, DnsRdata::A(Ipv4Addr::new(1, 2, 3, 4)));

        assert_eq!(message.answer_addresses(), vec!["1.2.3.4".to_string()]);
    }

    #[test]
    fn parses_txt_record() {
        // Dos cadenas TXT: "hello" y "world".
        let rdata: &[u8] = &[
            5, b'h', b'e', b'l', b'l', b'o',
            5, b'w', b'o', b'r', b'l', b'd',
        ];
        let bytes = build_response_with_rdata(16, rdata);
        let message = parse_dns(&bytes).unwrap();

        assert_eq!(message.answers.len(), 1);
        match &message.answers[0].rdata {
            DnsRdata::Txt(strings) => {
                assert_eq!(strings.len(), 2);
                assert_eq!(strings[0], b"hello");
                assert_eq!(strings[1], b"world");
            }
            other => panic!("se esperaba TXT, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn parses_mx_record() {
        // preference = 10, exchange apunta a QNAME en offset 12.
        let rdata: &[u8] = &[0x00, 0x0A, 0xC0, 0x0C];
        let bytes = build_response_with_rdata(15, rdata);
        let message = parse_dns(&bytes).unwrap();

        assert_eq!(message.answers.len(), 1);
        match &message.answers[0].rdata {
            DnsRdata::Mx { preference, exchange } => {
                assert_eq!(*preference, 10);
                assert_eq!(exchange, "example.com");
            }
            other => panic!("se esperaba MX, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn parses_aaaa_record() {
        // 2001:db8::1
        let rdata: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8,
            0, 0, 0, 0,
            0, 0, 0, 0,
            0, 0, 0, 1,
        ];
        let bytes = build_response_with_rdata(28, &rdata);
        let message = parse_dns(&bytes).unwrap();

        assert_eq!(message.answers.len(), 1);
        match &message.answers[0].rdata {
            DnsRdata::Aaaa(ip) => assert_eq!(ip.to_string(), "2001:db8::1"),
            other => panic!("se esperaba AAAA, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn rejects_truncated_header() {
        let result = parse_dns(&[0u8; 8]);
        assert!(matches!(result, Err(DnsError::TruncatedHeader)));
    }

    #[test]
    fn rejects_truncated_name() {
        let mut bytes = build_query("example.com", 1);
        bytes.truncate(14);
        let result = parse_dns(&bytes);
        assert!(matches!(result, Err(DnsError::TruncatedName)));
    }

    #[test]
    fn rejects_forward_compression_pointer() {
        // La primera etiqueta del QNAME apunta hacia delante.
        let mut data = Vec::new();
        data.extend_from_slice(&0x0001u16.to_be_bytes());
        data.extend_from_slice(&0x0100u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&[0xC0, 0x14]); // puntero a offset 20 (aún no leído)
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());

        let result = parse_dns(&data);
        assert!(matches!(result, Err(DnsError::InvalidCompression)));
    }

    #[test]
    fn rejects_self_referential_pointer() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0001u16.to_be_bytes());
        data.extend_from_slice(&0x0100u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&[0xC0, 0x0C]); // apunta a sí mismo
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());

        let result = parse_dns(&data);
        assert!(matches!(result, Err(DnsError::InvalidCompression)));
    }

    #[test]
    fn keeps_non_utf8_labels_using_lossy_conversion() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x0001u16.to_be_bytes());
        data.extend_from_slice(&0x0100u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.push(3);
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        data.push(0);
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());

        let message = parse_dns(&data).unwrap();
        assert!(message.questions[0].name.contains('\u{FFFD}'));
    }

    #[test]
    fn summarizes_query_and_response() {
        let query = parse_dns(&build_query("example.com", 1)).unwrap();
        let q_summary = summarize(&query);
        assert!(q_summary.contains("consulta"));
        assert!(q_summary.contains("example.com A"));

        let response = parse_dns(&build_response_with_a()).unwrap();
        let r_summary = summarize(&response);
        assert!(r_summary.contains("respuesta"));
        assert!(r_summary.contains("1.2.3.4"));
    }

    #[test]
    fn does_not_panic_on_random_bytes() {
        let mut data = vec![0u8; 12];
        data[4] = 0xFF;
        data[5] = 0xFF;
        let _ = parse_dns(&data);

        let truncated = parse_dns(&[]);
        assert!(truncated.is_err());
    }
}```


## Archivo: `nextrace-core/src/http.rs`

```rust
// Parser de metadatos HTTP/1.x a nivel de paquete.
//
// Deliberadamente limitado a la primera línea + cabeceras:
//   * no reensambla cuerpos
//   * no parsea chunked, ni compresión, ni cookies
//   * no interpreta HTTP/2 (binario)
//
// Estas limitaciones son visibles en el informe: la sección
// HTTP muestra "primer segmento" y no se inventan cuerpos que
// no estén completos en el paquete.

use std::fmt;

const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;
const KNOWN_METHODS: &[&str] = &[
    "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub host: Option<String>,
    pub user_agent: Option<String>,
}

impl HttpRequest {
    pub fn summary(&self) -> String {
        match &self.host {
            Some(host) => format!(
                "HTTP {} {} (host {})",
                self.method, self.uri, host
            ),
            None => format!("HTTP {} {}", self.method, self.uri),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
}

impl HttpResponse {
    pub fn summary(&self) -> String {
        format!("HTTP {} {}", self.status, self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
}

impl HttpMessage {
    pub fn summary(&self) -> String {
        match self {
            Self::Request(r) => r.summary(),
            Self::Response(r) => r.summary(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpParseError {
    Truncated,
    InvalidLine,
    NotHttp,
    TooManyHeaders,
}

impl fmt::Display for HttpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "mensaje HTTP truncado"),
            Self::InvalidLine => write!(f, "línea HTTP inválida"),
            Self::NotHttp => write!(f, "no parece HTTP/1.x"),
            Self::TooManyHeaders => write!(f, "demasiadas cabeceras HTTP"),
        }
    }
}

impl std::error::Error for HttpParseError {}

pub fn parse_http(bytes: &[u8]) -> Result<HttpMessage, HttpParseError> {
    if bytes.is_empty() {
        return Err(HttpParseError::Truncated);
    }

    // Respuesta: empieza por "HTTP/"
    if bytes.starts_with(b"HTTP/") {
        return parse_response(bytes).map(HttpMessage::Response);
    }

    // Petición: método conocido seguido de un espacio.
    for method in KNOWN_METHODS {
        let prefix_len = method.len();
        if bytes.len() > prefix_len
            && &bytes[..prefix_len] == method.as_bytes()
            && bytes[prefix_len] == b' '
        {
            return parse_request(bytes).map(HttpMessage::Request);
        }
    }

    Err(HttpParseError::NotHttp)
}

fn parse_request(bytes: &[u8]) -> Result<HttpRequest, HttpParseError> {
    let headers = split_headers(bytes)?;
    let first_line = headers.first_line;

    let mut parts = first_line.split(' ');
    let method = parts.next().ok_or(HttpParseError::InvalidLine)?;
    let uri = parts.next().ok_or(HttpParseError::InvalidLine)?;
    let version = parts.next().ok_or(HttpParseError::InvalidLine)?;

    if parts.next().is_some() {
        return Err(HttpParseError::InvalidLine);
    }
    if !version.starts_with("HTTP/1.") {
        return Err(HttpParseError::InvalidLine);
    }
    if !uri.starts_with('/')
        && !uri.starts_with('*')
        && !uri.starts_with("http://")
        && !uri.starts_with("https://")
    {
        return Err(HttpParseError::InvalidLine);
    }

    let mut host = None;
    let mut user_agent = None;

    for (name, value) in headers.lines {
        let name_lower = name.to_ascii_lowercase();
        match name_lower.as_str() {
            "host" => host = Some(value.to_string()),
            "user-agent" => user_agent = Some(value.to_string()),
            _ => {}
        }
    }

    Ok(HttpRequest {
        method: method.to_string(),
        uri: uri.to_string(),
        version: version.to_string(),
        host,
        user_agent,
    })
}

fn parse_response(bytes: &[u8]) -> Result<HttpResponse, HttpParseError> {
    let headers = split_headers(bytes)?;
    let first_line = headers.first_line;

    // Formato: "HTTP/1.1 200 OK"
    let mut parts = first_line.splitn(3, ' ');
    let version = parts.next().ok_or(HttpParseError::InvalidLine)?;
    let status_str = parts.next().ok_or(HttpParseError::InvalidLine)?;
    let reason = parts.next().unwrap_or("");

    if !version.starts_with("HTTP/1.") {
        return Err(HttpParseError::InvalidLine);
    }
    if status_str.len() != 3 || !status_str.bytes().all(|b| b.is_ascii_digit()) {
        return Err(HttpParseError::InvalidLine);
    }
    let status: u16 = status_str.parse().map_err(|_| HttpParseError::InvalidLine)?;

    Ok(HttpResponse {
        version: version.to_string(),
        status,
        reason: reason.to_string(),
    })
}

struct HeaderBlock<'a> {
    first_line: &'a str,
    lines: Vec<(&'a str, &'a str)>,
}

fn split_headers(bytes: &[u8]) -> Result<HeaderBlock<'_>, HttpParseError> {
    if bytes.len() > MAX_HEADER_BYTES {
        // No miramos más allá del tope: consideramos que no podemos parsear
        // de forma segura y devolvemos error, en vez de intentar adivinar.
        return Err(HttpParseError::TooManyHeaders);
    }

    // Solo procesamos cabeceras completas: requerimos CRLFCRLF.
    let split = find_crlfcrlf(bytes).ok_or(HttpParseError::Truncated)?;
    let header_bytes = &bytes[..split];

    let text = std::str::from_utf8(header_bytes).map_err(|_| HttpParseError::InvalidLine)?;

    let mut iter = text.split("\r\n");
    let first_line = iter.next().ok_or(HttpParseError::InvalidLine)?;

    let mut lines = Vec::new();
    for line in iter {
        if lines.len() >= MAX_HEADERS {
            return Err(HttpParseError::TooManyHeaders);
        }
        if let Some((name, value)) = line.split_once(':') {
            lines.push((name.trim(), value.trim_start()));
        }
    }

    Ok(HeaderBlock { first_line, lines })
}

fn find_crlfcrlf(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_request_with_host_and_user_agent() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NEXTRACE-Test/1.0\r\n\r\n";
        let msg = parse_http(payload).unwrap();
        match msg {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "GET");
                assert_eq!(req.uri, "/index.html");
                assert_eq!(req.version, "HTTP/1.1");
                assert_eq!(req.host.as_deref(), Some("example.com"));
                assert_eq!(req.user_agent.as_deref(), Some("NEXTRACE-Test/1.0"));
            }
            _ => panic!("se esperaba una petición"),
        }
    }

    #[test]
    fn parses_post_request() {
        let payload = b"POST /api/v1/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
        let msg = parse_http(payload).unwrap();
        match msg {
            HttpMessage::Request(req) => {
                assert_eq!(req.method, "POST");
                assert_eq!(req.uri, "/api/v1/login");
            }
            _ => panic!("se esperaba una petición"),
        }
    }

    #[test]
    fn parses_response_200() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let msg = parse_http(payload).unwrap();
        match msg {
            HttpMessage::Response(resp) => {
                assert_eq!(resp.status, 200);
                assert_eq!(resp.reason, "OK");
            }
            _ => panic!("se esperaba una respuesta"),
        }
    }

    #[test]
    fn parses_response_404() {
        let payload = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let msg = parse_http(payload).unwrap();
        match msg {
            HttpMessage::Response(resp) => {
                assert_eq!(resp.status, 404);
                assert_eq!(resp.reason, "Not Found");
            }
            _ => panic!("se esperaba una respuesta"),
        }
    }

    #[test]
    fn rejects_incomplete_headers() {
        // Sin CRLFCRLF final: el paquete no contiene las cabeceras completas.
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert!(matches!(parse_http(payload), Err(HttpParseError::Truncated)));
    }

    #[test]
    fn rejects_non_http_payload() {
        assert!(matches!(
            parse_http(b"\x16\x03\x01\x00\x50"),
            Err(HttpParseError::NotHttp)
        ));
        assert!(matches!(parse_http(b"NOTHTTP"), Err(HttpParseError::NotHttp)));
    }
}```

