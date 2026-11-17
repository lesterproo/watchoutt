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
    DuplicateId { entity: &'static str, id: u64 },
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
    PacketFrame { frame_number: u64 },
    LogLine { line_number: u64 },
    ByteRange { offset: u64, length: u64 },
    JsonPath { path: String },
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
            let valid = hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit());

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
        if !self
            .sources
            .iter()
            .any(|item| item.id == evidence.source_id)
        {
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

        let (packets_a_to_b, packets_b_to_a, captured_bytes_a_to_b, captured_bytes_b_to_a) =
            if a_to_b {
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
}
