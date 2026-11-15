use std::collections::HashMap;

use crate::{
    AssetId, AssetKind, DomainError, Finding, FindingId, FindingKind,
    Investigation, Severity,
};

#[derive(Debug, Clone, PartialEq)]
pub struct BaselineConfig {
    pub min_entities_per_kind: usize,
    pub modified_zscore_threshold: f64,
    pub high_zscore_threshold: f64,
    pub min_flows_per_asset: u64,
    pub enable_bytes_baseline: bool,
    pub enable_flow_count_baseline: bool,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            min_entities_per_kind: 5,
            modified_zscore_threshold: 3.5,
            high_zscore_threshold: 5.0,
            min_flows_per_asset: 3,
            enable_bytes_baseline: true,
            enable_flow_count_baseline: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineReport {
    pub rules_evaluated: usize,
    pub asset_kinds_with_enough_data: usize,
    pub findings_added: Vec<FindingId>,
    pub findings_skipped_duplicate: usize,
}

impl Default for BaselineReport {
    fn default() -> Self {
        Self {
            rules_evaluated: 0,
            asset_kinds_with_enough_data: 0,
            findings_added: Vec::new(),
            findings_skipped_duplicate: 0,
        }
    }
}

#[derive(Debug)]
pub enum BaselineError {
    Domain(DomainError),
}

impl std::fmt::Display for BaselineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(e) => write!(f, "Error al registrar hallazgo: {e}"),
        }
    }
}

impl std::error::Error for BaselineError {}
impl From<DomainError> for BaselineError {
    fn from(error: DomainError) -> Self { Self::Domain(error) }
}

pub fn detect_baseline_anomalies(
    investigation: &mut Investigation,
) -> Result<BaselineReport, BaselineError> {
    detect_baseline_anomalies_with_config(investigation, &BaselineConfig::default())
}

pub fn detect_baseline_anomalies_with_config(
    investigation: &mut Investigation,
    config: &BaselineConfig,
) -> Result<BaselineReport, BaselineError> {
    let mut working = investigation.clone();
    let mut report = BaselineReport::default();

    let kind_groups: [(AssetKind, &str); 3] = [
        (AssetKind::IpAddress, "dirección IP"),
        (AssetKind::Hostname, "nombre de host"),
        (AssetKind::MacAddress, "dirección MAC"),
    ];

    for (kind, label) in kind_groups {
        let metrics = compute_asset_metrics(&working, &kind);
        if metrics.len() < config.min_entities_per_kind { continue; }
        report.asset_kinds_with_enough_data += 1;

        if config.enable_bytes_baseline {
            report.rules_evaluated += 1;
            let proposals = baseline_rule(&metrics, Metric::TotalBytes, label, "volumen de bytes", config);
            apply_proposals(&mut working, &mut report, proposals)?;
        }
        if config.enable_flow_count_baseline {
            report.rules_evaluated += 1;
            let proposals = baseline_rule(&metrics, Metric::FlowCount, label, "número de flujos", config);
            apply_proposals(&mut working, &mut report, proposals)?;
        }
    }

    *investigation = working;
    Ok(report)
}

#[derive(Debug, Clone, Copy)]
enum Metric { TotalBytes, FlowCount }

struct AssetMetrics { asset_id: AssetId, total_bytes: u64, flow_count: u64 }

impl AssetMetrics {
    fn value(&self, m: Metric) -> f64 {
        match m { Metric::TotalBytes => self.total_bytes as f64, Metric::FlowCount => self.flow_count as f64 }
    }
}

fn compute_asset_metrics(inv: &Investigation, kind: &AssetKind) -> Vec<AssetMetrics> {
    let ids: Vec<AssetId> = inv.assets().iter().filter(|a| &a.kind == kind).map(|a| a.id).collect();
    let mut map: HashMap<AssetId, AssetMetrics> = ids.iter().map(|id| (*id, AssetMetrics { asset_id: *id, total_bytes: 0, flow_count: 0 })).collect();
    for flow in inv.flows() {
        if let Some(m) = map.get_mut(&flow.endpoint_a) {
            m.total_bytes = m.total_bytes.saturating_add(flow.captured_bytes);
            m.flow_count = m.flow_count.saturating_add(1);
        }
        if let Some(m) = map.get_mut(&flow.endpoint_b) {
            m.total_bytes = m.total_bytes.saturating_add(flow.captured_bytes);
            m.flow_count = m.flow_count.saturating_add(1);
        }
    }
    map.into_values().collect()
}

fn median(v: &[f64]) -> f64 {
    if v.is_empty() { return 0.0; }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = s.len();
    if n % 2 == 1 { s[n / 2] } else { (s[n / 2 - 1] + s[n / 2]) / 2.0 }
}

fn mad(v: &[f64], med: f64) -> f64 {
    if v.is_empty() { return 0.0; }
    let dev: Vec<f64> = v.iter().map(|x| (x - med).abs()).collect();
    median(&dev)
}

fn modified_zscore(x: f64, med: f64, mad: f64) -> Option<f64> {
    if mad <= 0.0 { None } else { Some(0.6745 * (x - med) / mad) }
}

struct ProposedFinding {
    kind: FindingKind, severity: Severity, title: String, description: String,
    evidence_ids: Vec<crate::EvidenceId>, confidence_percent: Option<u8>,
}

fn baseline_rule(metrics: &[AssetMetrics], metric: Metric, kind_label: &str, metric_label: &str, config: &BaselineConfig) -> Vec<ProposedFinding> {
    let values: Vec<f64> = metrics.iter().map(|m| m.value(metric)).collect();
    let med = median(&values);
    let m = mad(&values, med);
    if m <= 0.0 { return Vec::new(); }

    let mut out = Vec::new();
    for x in metrics {
        if x.flow_count < config.min_flows_per_asset { continue; }
        let v = x.value(metric);
        let Some(z) = modified_zscore(v, med, m) else { continue };
        if z < config.modified_zscore_threshold { continue; }

        let severity = if z >= config.high_zscore_threshold { Severity::Medium } else { Severity::Low };
        let confidence = ((z - config.modified_zscore_threshold) / config.modified_zscore_threshold * 40.0 + 50.0).min(90.0) as u8;

        out.push(ProposedFinding {
            kind: FindingKind::Observation,
            severity,
            title: format!("Desviación estadística en {} ({})", metric_label, kind_label),
            description: format!(
                "El activo {} ({}) presenta un {} de {:.0}, frente a mediana {:.0} del mismo tipo \
                 (modified z-score = {:.2}, umbral {:.1}). Desviación estadística; revisar contexto \
                 antes de concluir.",
                x.asset_id.0, kind_label, metric_label, v, med, z, config.modified_zscore_threshold
            ),
            evidence_ids: Vec::new(),
            confidence_percent: Some(confidence),
        });
    }
    out
}

fn apply_proposals(working: &mut Investigation, report: &mut BaselineReport, proposals: Vec<ProposedFinding>) -> Result<(), BaselineError> {
    for p in proposals {
        if is_duplicate(working, &p) { report.findings_skipped_duplicate += 1; continue; }
        let id = FindingId(next_finding_id(working));
        working.add_finding(Finding {
            id, kind: p.kind, severity: p.severity, title: p.title,
            description: p.description, evidence_ids: p.evidence_ids,
            confidence_percent: p.confidence_percent,
        })?;
        report.findings_added.push(id);
    }
    Ok(())
}

fn is_duplicate(inv: &Investigation, p: &ProposedFinding) -> bool {
    inv.findings().iter().any(|e| e.title == p.title && e.evidence_ids == p.evidence_ids)
}

fn next_finding_id(inv: &Investigation) -> u64 {
    inv.findings().iter().map(|f| f.id.0).max().unwrap_or(0) + 1
}