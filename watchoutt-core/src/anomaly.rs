// Motor de detección de anomalías.
//
// Cada regla es una función pura: recibe `&Investigation` y devuelve
// una lista de hallazgos propuestos. No toca el modelo. El motor
// central los valida, deduplica contra hallazgos existentes y los
// registra citando la evidencia exacta.
//
// Reglas activas en v1.1:
//
//   1. HTTP en puerto no estándar.               (eventos HTTP)
//   2. TLS sobre puerto 80.                      (eventos TLS)
//   3. Flujo con volumen elevado.                (flujos)
//   4. Beaconing / C2.                           (flujos)
//   5. DNS tunneling.                            (eventos DNS)
//   6. Port scanning.                            (flujos)
//
// Cuando en el futuro se añadan logs de firewall o auth, basta con
// añadir una función nueva `rule_*` y llamarla desde
// `collect_proposals` si `config.enable_*` está activo.

use std::collections::{HashMap, HashSet};

use crate::{
    AssetId, DomainError, EventKind, Finding, FindingId, FindingKind, Investigation, NetworkFlow,
    Severity,
};

// ---------------------------------------------------------------------
// Configuración
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyConfig {
    // Regla 1: HTTP en puerto no estándar.
    pub enable_http_on_unusual_port: bool,
    pub standard_http_ports: Vec<u16>,

    // Regla 2: TLS sobre puerto 80.
    pub enable_tls_on_plain_port: bool,

    // Regla 3: flujo con volumen elevado.
    pub enable_large_flow: bool,
    pub large_flow_threshold_bytes: u64,

    // Regla 4: beaconing.
    pub enable_beaconing: bool,
    pub beacon_min_connections: usize,
    pub beacon_min_interval_ns: i64,
    pub beacon_max_interval_ns: i64,
    pub beacon_max_cv: f64,

    // Regla 5: DNS tunneling.
    pub enable_dns_tunneling: bool,
    pub dns_long_name_threshold: usize,
    pub dns_max_unique_subdomains: usize,

    // Regla 6: port scanning.
    pub enable_port_scanning: bool,
    pub portscan_max_distinct_destinations: usize,
    pub portscan_window_ns: i64,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            enable_http_on_unusual_port: true,
            standard_http_ports: vec![80, 8080, 8000, 3128],

            enable_tls_on_plain_port: true,

            enable_large_flow: true,
            large_flow_threshold_bytes: 10 * 1024 * 1024,

            enable_beaconing: true,
            beacon_min_connections: 6,
            beacon_min_interval_ns: 10_000_000_000,
            beacon_max_interval_ns: 3_600_000_000_000,
            beacon_max_cv: 0.10,

            enable_dns_tunneling: true,
            dns_long_name_threshold: 80,
            dns_max_unique_subdomains: 20,

            enable_port_scanning: true,
            portscan_max_distinct_destinations: 20,
            portscan_window_ns: 60_000_000_000,
        }
    }
}

// ---------------------------------------------------------------------
// Reporte y error
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyReport {
    pub findings_proposed: usize,
    pub findings_added: Vec<FindingId>,
    pub findings_skipped_duplicate: usize,
    pub rules_evaluated: usize,
}

impl Default for AnomalyReport {
    fn default() -> Self {
        Self {
            findings_proposed: 0,
            findings_added: Vec::new(),
            findings_skipped_duplicate: 0,
            rules_evaluated: 0,
        }
    }
}

#[derive(Debug)]
pub enum AnomalyError {
    Domain(DomainError),
}

impl std::fmt::Display for AnomalyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(error) => write!(f, "Error al registrar hallazgo: {error}"),
        }
    }
}

impl std::error::Error for AnomalyError {}

impl From<DomainError> for AnomalyError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

// ---------------------------------------------------------------------
// Representación interna de un hallazgo propuesto
// ---------------------------------------------------------------------

struct ProposedFinding {
    kind: FindingKind,
    severity: Severity,
    title: String,
    description: String,
    evidence_ids: Vec<crate::EvidenceId>,
    confidence_percent: Option<u8>,
}

// ---------------------------------------------------------------------
// Punto de entrada
// ---------------------------------------------------------------------

pub fn detect_anomalies(investigation: &mut Investigation) -> Result<AnomalyReport, AnomalyError> {
    detect_anomalies_with_config(investigation, &AnomalyConfig::default())
}

pub fn detect_anomalies_with_config(
    investigation: &mut Investigation,
    config: &AnomalyConfig,
) -> Result<AnomalyReport, AnomalyError> {
    let mut working = investigation.clone();
    let mut report = AnomalyReport::default();

    let (proposals, rules) = collect_proposals(&working, config);
    report.rules_evaluated = rules;

    for proposal in proposals {
        report.findings_proposed += 1;

        if is_duplicate(&working, &proposal) {
            report.findings_skipped_duplicate += 1;
            continue;
        }

        let id = FindingId(next_finding_id(&working));
        let finding = Finding {
            id,
            kind: proposal.kind,
            severity: proposal.severity,
            title: proposal.title,
            description: proposal.description,
            evidence_ids: proposal.evidence_ids,
            confidence_percent: proposal.confidence_percent,
        };

        working.add_finding(finding)?;
        report.findings_added.push(id);
    }

    *investigation = working;
    Ok(report)
}

// ---------------------------------------------------------------------
// Dispatcher de reglas
// ---------------------------------------------------------------------

fn collect_proposals(
    investigation: &Investigation,
    config: &AnomalyConfig,
) -> (Vec<ProposedFinding>, usize) {
    let mut proposals = Vec::new();
    let mut rules_evaluated = 0usize;

    if config.enable_http_on_unusual_port {
        proposals.extend(rule_http_on_unusual_port(investigation, config));
        rules_evaluated += 1;
    }

    if config.enable_tls_on_plain_port {
        proposals.extend(rule_tls_on_plain_port(investigation));
        rules_evaluated += 1;
    }

    if config.enable_large_flow {
        proposals.extend(rule_large_flow(investigation, config));
        rules_evaluated += 1;
    }

    if config.enable_beaconing {
        proposals.extend(rule_beaconing(investigation, config));
        rules_evaluated += 1;
    }

    if config.enable_dns_tunneling {
        proposals.extend(rule_dns_tunneling(investigation, config));
        rules_evaluated += 1;
    }

    if config.enable_port_scanning {
        proposals.extend(rule_port_scanning(investigation, config));
        rules_evaluated += 1;
    }

    (proposals, rules_evaluated)
}

// ---------------------------------------------------------------------
// Regla 1: HTTP en puerto no estándar
// ---------------------------------------------------------------------

fn rule_http_on_unusual_port(
    investigation: &Investigation,
    config: &AnomalyConfig,
) -> Vec<ProposedFinding> {
    let mut out = Vec::new();

    for event in investigation.events() {
        let port = match event.kind {
            EventKind::HttpRequest => event.destination_port,
            EventKind::HttpResponse => event.source_port,
            _ => continue,
        };

        let Some(port) = port else { continue };

        if config.standard_http_ports.contains(&port) {
            continue;
        }

        out.push(ProposedFinding {
            kind: FindingKind::Observation,
            severity: Severity::Low,
            title: "HTTP en puerto no estándar".to_string(),
            description: format!(
                "Se observó {} en el puerto {} (puertos estándar para HTTP: {:?}).",
                match event.kind {
                    EventKind::HttpRequest => "una petición HTTP",
                    EventKind::HttpResponse => "una respuesta HTTP",
                    _ => unreachable!(),
                },
                port,
                config.standard_http_ports,
            ),
            evidence_ids: event.evidence_ids.clone(),
            confidence_percent: Some(100),
        });
    }

    out
}

// ---------------------------------------------------------------------
// Regla 2: TLS sobre puerto 80
// ---------------------------------------------------------------------

fn rule_tls_on_plain_port(investigation: &Investigation) -> Vec<ProposedFinding> {
    let mut out = Vec::new();

    for event in investigation.events() {
        if !matches!(event.kind, EventKind::TlsClientHello) {
            continue;
        }

        let is_port_80 = event.destination_port == Some(80) || event.source_port == Some(80);

        if !is_port_80 {
            continue;
        }

        out.push(ProposedFinding {
            kind: FindingKind::Observation,
            severity: Severity::Low,
            title: "TLS sobre puerto 80".to_string(),
            description: format!(
                "Se observó un ClientHello TLS en el puerto 80 (habitualmente HTTP en claro). {}",
                event.summary
            ),
            evidence_ids: event.evidence_ids.clone(),
            confidence_percent: Some(100),
        });
    }

    out
}

// ---------------------------------------------------------------------
// Regla 3: flujo con volumen elevado
// ---------------------------------------------------------------------

fn rule_large_flow(investigation: &Investigation, config: &AnomalyConfig) -> Vec<ProposedFinding> {
    let mut out = Vec::new();

    for flow in investigation.flows() {
        let max_direction_bytes = flow.captured_bytes_a_to_b.max(flow.captured_bytes_b_to_a);

        if max_direction_bytes < config.large_flow_threshold_bytes {
            continue;
        }

        let direction = if flow.captured_bytes_a_to_b >= flow.captured_bytes_b_to_a {
            "A → B"
        } else {
            "B → A"
        };

        out.push(ProposedFinding {
            kind: FindingKind::Observation,
            severity: Severity::Medium,
            title: "Flujo con volumen elevado".to_string(),
            description: format!(
                "El flujo {} (protocolo {:?}) transmitió {} bytes en la dirección {} (umbral: {} bytes). \
                 Revisar el contexto del flujo antes de interpretar.",
                flow.id.0,
                flow.protocol,
                max_direction_bytes,
                direction,
                config.large_flow_threshold_bytes,
            ),
            evidence_ids: flow.evidence_ids.clone(),
            confidence_percent: Some(100),
        });
    }

    out
}

// ---------------------------------------------------------------------
// Regla 4: beaconing / C2
// ---------------------------------------------------------------------
//
// Heurística: agrupar flujos por (cliente, servidor, puerto servidor)
// ignorando el puerto efímero del cliente. Si un par se repite N veces
// con intervalos regulares (coeficiente de variación bajo), marcar.
//
// El CV < 10 % es conservador: tráfico humano navegando suele tener
// mucha más varianza. Beacons reales suelen tener CV < 5 %.

fn rule_beaconing(investigation: &Investigation, config: &AnomalyConfig) -> Vec<ProposedFinding> {
    struct Occurrence {
        timestamp_ns: i64,
        evidence_ids: Vec<crate::EvidenceId>,
    }

    let mut groups: HashMap<(String, String, u16), Vec<Occurrence>> = HashMap::new();

    for flow in investigation.flows() {
        let Some((client_ip, server_ip, server_port)) = infer_client_server(flow, investigation)
        else {
            continue;
        };

        let key = (client_ip.to_string(), server_ip.to_string(), server_port);
        groups.entry(key).or_default().push(Occurrence {
            timestamp_ns: flow.first_seen_unix_ns,
            evidence_ids: first_evidence_ids(flow, 2),
        });
    }

    let mut out = Vec::new();

    for ((client, server, port), mut occurrences) in groups {
        if occurrences.len() < config.beacon_min_connections {
            continue;
        }

        occurrences.sort_by_key(|o| o.timestamp_ns);

        let mut intervals: Vec<i64> = Vec::with_capacity(occurrences.len() - 1);
        for pair in occurrences.windows(2) {
            let delta = pair[1].timestamp_ns - pair[0].timestamp_ns;
            if delta > 0 {
                intervals.push(delta);
            }
        }

        if intervals.is_empty() {
            continue;
        }

        let mean = intervals.iter().map(|v| *v as f64).sum::<f64>() / intervals.len() as f64;

        if mean < config.beacon_min_interval_ns as f64
            || mean > config.beacon_max_interval_ns as f64
        {
            continue;
        }

        let variance = intervals
            .iter()
            .map(|v| (*v as f64 - mean).powi(2))
            .sum::<f64>()
            / intervals.len() as f64;

        let cv = variance.sqrt() / mean;
        if cv >= config.beacon_max_cv {
            continue;
        }

        let mut evidence_ids = Vec::new();
        for occ in occurrences.iter().take(6) {
            for id in &occ.evidence_ids {
                if !evidence_ids.contains(id) {
                    evidence_ids.push(*id);
                }
            }
        }

        out.push(ProposedFinding {
            kind: FindingKind::Observation,
            severity: Severity::Medium,
            title: "Posible beaconing (comunicación periódica)".to_string(),
            description: format!(
                "El cliente {} se conectó {} veces a {}:{} con intervalo medio {:.1} s \
                 y coeficiente de variación {:.2} % (umbral {:.0} %). \
                 Patrón compatible con balizas C2; verificar el destino antes de concluir.",
                client,
                occurrences.len(),
                server,
                port,
                mean / 1_000_000_000.0,
                cv * 100.0,
                config.beacon_max_cv * 100.0,
            ),
            evidence_ids,
            confidence_percent: Some(70),
        });
    }

    out
}

// ---------------------------------------------------------------------
// Regla 5: DNS tunneling
// ---------------------------------------------------------------------
//
// Dos heurísticas independientes:
//   * Nombre > threshold: codifica datos en el subdominio.
//   * Muchos subdominios bajo el mismo dominio base: exfiltración por
//     fragmentación.

fn rule_dns_tunneling(
    investigation: &Investigation,
    config: &AnomalyConfig,
) -> Vec<ProposedFinding> {
    struct DnsObservation {
        name: String,
        evidence_ids: Vec<crate::EvidenceId>,
    }

    let mut observations: Vec<DnsObservation> = Vec::new();

    for event in investigation.events() {
        match event.kind {
            EventKind::DnsQuery => {
                if let Some(name) = extract_dns_query_name(&event.summary) {
                    observations.push(DnsObservation {
                        name,
                        evidence_ids: event.evidence_ids.clone(),
                    });
                }
            }
            EventKind::DnsResolution => {
                if let Some(asset_id) = event.source_asset {
                    if let Some(name) = resolve_asset(investigation, asset_id) {
                        observations.push(DnsObservation {
                            name: name.to_string(),
                            evidence_ids: event.evidence_ids.clone(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    let mut out = Vec::new();

    // Heurística 5a: nombre anómalamente largo.
    for obs in &observations {
        if obs.name.len() > config.dns_long_name_threshold {
            out.push(ProposedFinding {
                kind: FindingKind::Observation,
                severity: Severity::Medium,
                title: "Consulta DNS con nombre anómalamente largo".to_string(),
                description: format!(
                    "Se observó una consulta DNS con {} caracteres (umbral: {}). \
                     Los nombres largos pueden codificar datos (DNS tunneling). \
                     Nombre: {}",
                    obs.name.len(),
                    config.dns_long_name_threshold,
                    truncate_for_display(&obs.name, 120),
                ),
                evidence_ids: obs.evidence_ids.clone(),
                confidence_percent: Some(60),
            });
        }
    }

    // Heurística 5b: muchos subdominios bajo el mismo dominio base.
    let mut subdomains_by_base: HashMap<String, HashSet<String>> = HashMap::new();
    let mut evidence_by_base: HashMap<String, Vec<crate::EvidenceId>> = HashMap::new();

    for obs in &observations {
        let Some(base) = base_domain(&obs.name) else {
            continue;
        };

        if obs.name.eq_ignore_ascii_case(&base) {
            continue;
        }

        subdomains_by_base
            .entry(base.clone())
            .or_default()
            .insert(obs.name.clone());

        let evidence = evidence_by_base.entry(base).or_default();
        if evidence.len() < 10 {
            for id in &obs.evidence_ids {
                if !evidence.contains(id) {
                    evidence.push(*id);
                }
            }
        }
    }

    for (base, subs) in subdomains_by_base {
        if subs.len() <= config.dns_max_unique_subdomains {
            continue;
        }

        let evidence = evidence_by_base.remove(&base).unwrap_or_default();

        out.push(ProposedFinding {
            kind: FindingKind::Observation,
            severity: Severity::Medium,
            title: "Múltiples subdominios bajo un mismo dominio".to_string(),
            description: format!(
                "Se observaron {} subdominios distintos bajo {} (umbral: {}). \
                 La fragmentación en muchos subdominios es un patrón típico de DNS tunneling. \
                 Ejemplos: {}",
                subs.len(),
                base,
                config.dns_max_unique_subdomains,
                subs.iter().take(3).cloned().collect::<Vec<_>>().join(", "),
            ),
            evidence_ids: evidence,
            confidence_percent: Some(55),
        });
    }

    out
}

// ---------------------------------------------------------------------
// Regla 6: port scanning
// ---------------------------------------------------------------------
//
// Sliding window real (no buckets) para evitar falsos negativos en
// los bordes. Complejidad O(n log n) por cliente.

fn rule_port_scanning(
    investigation: &Investigation,
    config: &AnomalyConfig,
) -> Vec<ProposedFinding> {
    struct FlowSummary {
        timestamp_ns: i64,
        server_ip: String,
        server_port: u16,
        evidence_ids: Vec<crate::EvidenceId>,
    }

    let mut by_client: HashMap<String, Vec<FlowSummary>> = HashMap::new();

    for flow in investigation.flows() {
        let Some((client_ip, server_ip, server_port)) = infer_client_server(flow, investigation)
        else {
            continue;
        };

        by_client
            .entry(client_ip.to_string())
            .or_default()
            .push(FlowSummary {
                timestamp_ns: flow.first_seen_unix_ns,
                server_ip: server_ip.to_string(),
                server_port,
                evidence_ids: first_evidence_ids(flow, 2),
            });
    }

    let mut out = Vec::new();

    for (client_ip, mut flows) in by_client {
        flows.sort_by_key(|f| f.timestamp_ns);

        let mut left = 0usize;
        let mut counts: HashMap<(String, u16), usize> = HashMap::new();
        let mut triggered = false;

        for right in 0..flows.len() {
            let current_ts = flows[right].timestamp_ns;
            let key = (flows[right].server_ip.clone(), flows[right].server_port);
            *counts.entry(key).or_insert(0) += 1;

            while flows[left].timestamp_ns < current_ts - config.portscan_window_ns {
                let expired_key = (flows[left].server_ip.clone(), flows[left].server_port);
                if let Some(c) = counts.get_mut(&expired_key) {
                    *c -= 1;
                    if *c == 0 {
                        counts.remove(&expired_key);
                    }
                }
                left += 1;
            }

            if counts.len() > config.portscan_max_distinct_destinations {
                let mut evidence_ids = Vec::new();
                for flow in flows.iter().skip(left).take(10) {
                    for id in &flow.evidence_ids {
                        if !evidence_ids.contains(id) {
                            evidence_ids.push(*id);
                        }
                    }
                }

                out.push(ProposedFinding {
                    kind: FindingKind::Observation,
                    severity: Severity::Medium,
                    title: "Posible port scanning".to_string(),
                    description: format!(
                        "El cliente {} contactó {} destinos (ip:puerto) distintos en una ventana de {:.0} s \
                         (umbral: {}). Patrón compatible con reconocimiento; verificar si el \
                         destino es un servicio legítimo antes de concluir.",
                        client_ip,
                        counts.len(),
                        config.portscan_window_ns as f64 / 1_000_000_000.0,
                        config.portscan_max_distinct_destinations,
                    ),
                    evidence_ids,
                    confidence_percent: Some(65),
                });

                triggered = true;
                break;
            }
        }

        if triggered {
            // Ya hemos añadido un finding; evitar más por el mismo cliente.
            continue;
        }
    }

    out
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

fn is_duplicate(investigation: &Investigation, proposal: &ProposedFinding) -> bool {
    investigation.findings().iter().any(|existing| {
        existing.title == proposal.title && existing.evidence_ids == proposal.evidence_ids
    })
}

fn next_finding_id(investigation: &Investigation) -> u64 {
    investigation
        .findings()
        .iter()
        .map(|f| f.id.0)
        .max()
        .unwrap_or(0)
        + 1
}

fn resolve_asset(investigation: &Investigation, id: AssetId) -> Option<&str> {
    investigation
        .assets()
        .iter()
        .find(|a| a.id == id)
        .map(|a| a.value.as_str())
}

fn first_evidence_ids(flow: &NetworkFlow, limit: usize) -> Vec<crate::EvidenceId> {
    flow.evidence_ids.iter().take(limit).copied().collect()
}

/// Determina, de forma heurística, quién es cliente y quién servidor
/// en un flujo ya canónicamente ordenado.
///
/// Regla: el puerto más bajo es el servidor (well-known). Si los dos
/// puertos son iguales, no podemos decidir y se descarta el flujo.
fn infer_client_server<'a>(
    flow: &NetworkFlow,
    investigation: &'a Investigation,
) -> Option<(&'a str, &'a str, u16)> {
    let a_ip = resolve_asset(investigation, flow.endpoint_a)?;
    let b_ip = resolve_asset(investigation, flow.endpoint_b)?;
    let a_port = flow.endpoint_a_port?;
    let b_port = flow.endpoint_b_port?;

    if a_port == b_port {
        return None;
    }

    if a_port < b_port {
        // A es servidor, B es cliente.
        Some((b_ip, a_ip, a_port))
    } else {
        // B es servidor, A es cliente.
        Some((a_ip, b_ip, b_port))
    }
}

/// Extrae el nombre de un summary de consulta DNS.
/// Formato actual: "DNS consulta: <name> <qtype>".
fn extract_dns_query_name(summary: &str) -> Option<String> {
    let rest = summary.strip_prefix("DNS consulta: ")?;
    let (name, _qtype) = rest.rsplit_once(' ')?;
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

/// Devuelve el dominio base (últimos dos labels) o `None`.
///
/// Limitación conocida: TLDs compuestos como `.co.uk` se agruparían
/// incorrectamente bajo `co.uk`. Es aceptable para detección de
/// tunneling porque lo importante es agrupar subdominios bajo el mismo
/// sufijo, no obtener el dominio registrable exacto.
fn base_domain(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let n = parts.len();
    Some(format!("{}.{}", parts[n - 2], parts[n - 1]))
}

fn truncate_for_display(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Asset, AssetId, AssetKind, Evidence, EvidenceId, EvidenceLocation, FlowId, InvestigationId,
        NetworkEvent, NetworkFlow, Protocol, SourceFile, SourceFormat, SourceId,
    };
    use std::path::PathBuf;

    fn empty_investigation() -> Investigation {
        let mut investigation =
            Investigation::new(InvestigationId(1), "Prueba de anomalías", None, 0).unwrap();

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

        // Evidencias numeradas 1..=200 para tests.
        for id in 1..=200u64 {
            investigation
                .add_evidence(Evidence {
                    id: EvidenceId(id),
                    source_id: SourceId(1),
                    location: EvidenceLocation::PacketFrame { frame_number: id },
                    excerpt: None,
                })
                .unwrap();
        }

        investigation
            .add_asset(Asset {
                id: AssetId(1),
                kind: AssetKind::IpAddress,
                value: "192.168.1.10".to_string(),
                label: None,
            })
            .unwrap();

        investigation
            .add_asset(Asset {
                id: AssetId(2),
                kind: AssetKind::IpAddress,
                value: "93.184.216.34".to_string(),
                label: None,
            })
            .unwrap();

        investigation
    }

    fn add_event(
        investigation: &mut Investigation,
        id: u64,
        kind: EventKind,
        summary: &str,
        source_asset: Option<AssetId>,
        dest_asset: Option<AssetId>,
        source_port: Option<u16>,
        dest_port: Option<u16>,
        evidence_id: u64,
    ) {
        investigation
            .add_event(NetworkEvent {
                id: crate::EventId(id),
                timestamp_unix_ns: Some(id as i64 * 1_000_000_000),
                kind,
                summary: summary.to_string(),
                source_asset,
                destination_asset: dest_asset,
                source_port,
                destination_port: dest_port,
                protocol: Some(Protocol::Tcp),
                evidence_ids: vec![EvidenceId(evidence_id)],
                tcp_flags: None,
            })
            .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn add_flow(
        investigation: &mut Investigation,
        id: u64,
        endpoint_a: AssetId,
        endpoint_b: AssetId,
        a_port: u16,
        b_port: u16,
        first_seen_ns: i64,
        evidence_id: u64,
    ) {
        investigation
            .add_flow(NetworkFlow {
                id: FlowId(id),
                endpoint_a,
                endpoint_b,
                endpoint_a_port: Some(a_port),
                endpoint_b_port: Some(b_port),
                protocol: Protocol::Tcp,
                first_seen_unix_ns: first_seen_ns,
                last_seen_unix_ns: first_seen_ns + 1_000_000,
                packet_count: 2,
                captured_bytes: 200,
                original_bytes: 200,
                packets_a_to_b: 1,
                packets_b_to_a: 1,
                captured_bytes_a_to_b: 100,
                captured_bytes_b_to_a: 100,
                evidence_ids: vec![EvidenceId(evidence_id)],
            })
            .unwrap();
    }

    // ---------------- Regla 1: HTTP en puerto no estándar ----------------

    #[test]
    fn detects_http_on_unusual_port() {
        let mut inv = empty_investigation();
        add_event(
            &mut inv,
            1,
            EventKind::HttpRequest,
            "HTTP GET /",
            Some(AssetId(1)),
            Some(AssetId(2)),
            Some(50000),
            Some(8081),
            1,
        );

        let report = detect_anomalies(&mut inv).unwrap();
        assert!(report.findings_added.len() >= 1);
        assert!(
            inv.findings()
                .iter()
                .any(|f| f.title.contains("HTTP en puerto no estándar"))
        );
    }

    #[test]
    fn does_not_flag_http_on_standard_port() {
        let mut inv = empty_investigation();
        add_event(
            &mut inv,
            1,
            EventKind::HttpRequest,
            "HTTP GET /",
            Some(AssetId(1)),
            Some(AssetId(2)),
            Some(50000),
            Some(80),
            1,
        );

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .all(|f| !f.title.contains("HTTP en puerto"))
        );
    }

    // ---------------- Regla 2: TLS sobre 80 ----------------

    #[test]
    fn detects_tls_on_plain_port() {
        let mut inv = empty_investigation();
        add_event(
            &mut inv,
            1,
            EventKind::TlsClientHello,
            "TLS ClientHello SNI=example.com",
            Some(AssetId(1)),
            Some(AssetId(2)),
            Some(50000),
            Some(80),
            1,
        );

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .any(|f| f.title.contains("TLS sobre puerto 80"))
        );
    }

    // ---------------- Regla 3: flujo grande ----------------

    #[test]
    fn detects_large_flow() {
        let mut inv = empty_investigation();
        inv.add_flow(NetworkFlow {
            id: FlowId(1),
            endpoint_a: AssetId(1),
            endpoint_b: AssetId(2),
            endpoint_a_port: Some(50000),
            endpoint_b_port: Some(443),
            protocol: Protocol::Tcp,
            first_seen_unix_ns: 0,
            last_seen_unix_ns: 1_000_000_000,
            packet_count: 1000,
            captured_bytes: 20 * 1024 * 1024,
            original_bytes: 20 * 1024 * 1024,
            packets_a_to_b: 500,
            packets_b_to_a: 500,
            captured_bytes_a_to_b: 15 * 1024 * 1024,
            captured_bytes_b_to_a: 5 * 1024 * 1024,
            evidence_ids: vec![EvidenceId(1)],
        })
        .unwrap();

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .any(|f| f.title.contains("volumen elevado"))
        );
    }

    // ---------------- Regla 4: beaconing ----------------

    #[test]
    fn detects_regular_beaconing() {
        let mut inv = empty_investigation();
        // 6 flujos del cliente (AssetId 1) al servidor (AssetId 2), puerto 443,
        // cada 60 segundos exactos. CV = 0.
        for i in 0..6u64 {
            add_flow(
                &mut inv,
                i + 1,
                AssetId(2), // server (IP 93.x < 192.x, va primero)
                AssetId(1), // client
                443,
                50000 + i as u16, // client port distinto (efímero)
                i as i64 * 60_000_000_000,
                i + 1,
            );
        }

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings().iter().any(|f| f.title.contains("beaconing")),
            "debe detectar beaconing regular"
        );
    }

    #[test]
    fn does_not_flag_beaconing_with_irregular_intervals() {
        let mut inv = empty_investigation();
        // Intervalos muy variables: 10s, 300s, 20s, 500s, 15s. CV alto.
        let intervals = [10, 300, 20, 500, 15];
        let mut t: i64 = 0;
        for (i, delta) in intervals.iter().enumerate() {
            add_flow(
                &mut inv,
                i as u64 + 1,
                AssetId(2),
                AssetId(1),
                443,
                50000 + i as u16,
                t,
                i as u64 + 1,
            );
            t += delta * 1_000_000_000;
        }

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .all(|f| !f.title.contains("beaconing")),
            "no debe marcar tráfico irregular como beaconing"
        );
    }

    #[test]
    fn does_not_flag_beaconing_with_too_few_connections() {
        let mut inv = empty_investigation();
        // Solo 3 conexiones: por debajo del mínimo.
        for i in 0..3u64 {
            add_flow(
                &mut inv,
                i + 1,
                AssetId(2),
                AssetId(1),
                443,
                50000 + i as u16,
                i as i64 * 60_000_000_000,
                i + 1,
            );
        }

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .all(|f| !f.title.contains("beaconing"))
        );
    }

    // ---------------- Regla 5: DNS tunneling ----------------

    #[test]
    fn detects_dns_query_with_long_name() {
        let mut inv = empty_investigation();
        let long_name = format!("{}.{}.example.com", "a".repeat(50), "b".repeat(50),);
        add_event(
            &mut inv,
            1,
            EventKind::DnsQuery,
            &format!("DNS consulta: {} A", long_name),
            Some(AssetId(1)),
            Some(AssetId(2)),
            Some(50000),
            Some(53),
            1,
        );

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .any(|f| f.title.contains("nombre anómalamente largo")),
        );
    }

    #[test]
    fn detects_many_subdomains_under_same_base() {
        let mut inv = empty_investigation();
        for i in 0..25u64 {
            let name = format!("sub{}.example.com", i);
            add_event(
                &mut inv,
                i + 1,
                EventKind::DnsQuery,
                &format!("DNS consulta: {} A", name),
                Some(AssetId(1)),
                Some(AssetId(2)),
                Some(50000),
                Some(53),
                i + 1,
            );
        }

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .any(|f| f.title.contains("Múltiples subdominios")),
            "debe detectar muchos subdominios bajo example.com",
        );
    }

    #[test]
    fn does_not_flag_normal_dns_activity() {
        let mut inv = empty_investigation();
        for (i, name) in ["www.example.com", "api.example.com", "mail.example.com"]
            .iter()
            .enumerate()
        {
            add_event(
                &mut inv,
                i as u64 + 1,
                EventKind::DnsQuery,
                &format!("DNS consulta: {} A", name),
                Some(AssetId(1)),
                Some(AssetId(2)),
                Some(50000),
                Some(53),
                i as u64 + 1,
            );
        }

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .all(|f| !f.title.contains("DNS tunneling")
                    && !f.title.contains("subdominios")
                    && !f.title.contains("nombre anómalamente"))
        );
    }

    // ---------------- Regla 6: port scanning ----------------

    #[test]
    fn detects_port_scanning() {
        let mut inv = empty_investigation();
        // 25 flujos del cliente hacia 25 PUERTOS DESTINO distintos
        // en 30 s. Escaneo vertical clásico: mismo servidor, puertos
        // 1000..1025.
        for i in 0..25u64 {
            add_flow(
                &mut inv,
                i + 1,
                AssetId(2),      // servidor
                AssetId(1),      // cliente
                1000 + i as u16, // <-- PUERTO SERVIDOR variable
                50000,           // puerto cliente fijo
                i as i64 * 1_000_000_000,
                i + 1,
            );
        }

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .any(|f| f.title.contains("port scanning")),
            "debe detectar port scanning"
        );
    }

    #[test]
    fn does_not_flag_normal_connections_as_port_scanning() {
        let mut inv = empty_investigation();
        // 5 flujos: por debajo del umbral de 20.
        for i in 0..5u64 {
            add_flow(
                &mut inv,
                i + 1,
                AssetId(2),
                AssetId(1),
                443,
                50000 + i as u16,
                i as i64 * 1_000_000_000,
                i + 1,
            );
        }

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .all(|f| !f.title.contains("port scanning"))
        );
    }

    #[test]
    fn does_not_flag_port_scanning_across_long_time_spans() {
        let mut inv = empty_investigation();
        // 25 flujos, pero espaciados 5 minutos cada uno: fuera de la
        // ventana de 60s. No debe disparar.
        for i in 0..25u64 {
            add_flow(
                &mut inv,
                i + 1,
                AssetId(2),
                AssetId(1),
                80,
                50000 + i as u16,
                i as i64 * 300_000_000_000,
                i + 1,
            );
        }

        detect_anomalies(&mut inv).unwrap();
        assert!(
            inv.findings()
                .iter()
                .all(|f| !f.title.contains("port scanning"))
        );
    }

    // ---------------- Comportamiento general ----------------

    #[test]
    fn does_not_duplicate_findings_across_runs() {
        let mut inv = empty_investigation();
        add_event(
            &mut inv,
            1,
            EventKind::HttpRequest,
            "HTTP GET /",
            Some(AssetId(1)),
            Some(AssetId(2)),
            Some(50000),
            Some(8081),
            1,
        );

        detect_anomalies(&mut inv).unwrap();
        let count = inv.findings().len();
        assert!(count >= 1);

        let report = detect_anomalies(&mut inv).unwrap();
        assert_eq!(report.findings_added.len(), 0);
        assert!(report.findings_skipped_duplicate >= 1);
        assert_eq!(inv.findings().len(), count);
    }

    #[test]
    fn disabled_rules_are_not_evaluated() {
        let mut inv = empty_investigation();
        add_event(
            &mut inv,
            1,
            EventKind::HttpRequest,
            "HTTP GET /",
            Some(AssetId(1)),
            Some(AssetId(2)),
            Some(50000),
            Some(8081),
            1,
        );

        let mut config = AnomalyConfig::default();
        config.enable_http_on_unusual_port = false;
        config.enable_tls_on_plain_port = false;
        config.enable_large_flow = false;
        config.enable_beaconing = false;
        config.enable_dns_tunneling = false;
        config.enable_port_scanning = false;

        let report = detect_anomalies_with_config(&mut inv, &config).unwrap();
        assert_eq!(report.rules_evaluated, 0);
        assert_eq!(report.findings_added.len(), 0);
        assert!(inv.findings().is_empty());
    }

    #[test]
    fn only_enabled_rules_are_counted() {
        let mut inv = empty_investigation();
        let mut config = AnomalyConfig::default();
        config.enable_http_on_unusual_port = false;
        config.enable_tls_on_plain_port = false;
        config.enable_large_flow = false;

        let report = detect_anomalies_with_config(&mut inv, &config).unwrap();
        assert_eq!(report.rules_evaluated, 3); // beaconing + dns + portscan
    }
}
