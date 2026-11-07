
use std::fmt;
use std::path::PathBuf;

// Identificadores tipados: evitan confundir el ID de un evento
// con el ID de una fuente o una evidencia.
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

// Errores que puede producir el modelo de datos.
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
    MissingEvidence(&'static str),
    InvalidConfidence(u8),
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
            Self::MissingEvidence(entity) => {
                write!(f, "{entity} debe tener al menos una evidencia")
            }
            Self::InvalidConfidence(value) => {
                write!(f, "Confianza inválida: {value}. Debe estar entre 0 y 100")
            }
        }
    }
}

impl std::error::Error for DomainError {}

// Formatos que NEXTRACE podrá incorporar como fuentes.
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

// Archivo original incorporado a una investigación.
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

// Tipos de activos o entidades identificables en la red.
#[derive(Debug, Clone, PartialEq, Eq)]
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

// Localización exacta de un dato dentro de su fuente.
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

// Evidencia extraída de un archivo original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub id: EvidenceId,
    pub source_id: SourceId,
    pub location: EvidenceLocation,
    pub excerpt: Option<String>,
}

// Protocolos que el motor puede identificar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(String),
}

// Tipos de eventos que pueden aparecer en una investigación.
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
    Other(String),
}

// Suceso normalizado y relacionado con sus evidencias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEvent {
    pub id: EventId,
    // Nanosegundos desde Unix epoch, en UTC.
    pub timestamp_unix_ns: Option<i64>,
    pub kind: EventKind,
    pub summary: String,
    pub source_asset: Option<AssetId>,
    pub destination_asset: Option<AssetId>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<Protocol>,
    pub evidence_ids: Vec<EvidenceId>,
}

// Diferencia un hecho observado de una interpretación.
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

// Resultado del análisis que debe poder justificarse con evidencias.
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

// Contenedor principal de una investigación.
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

        if event.evidence_ids.is_empty() {
            return Err(DomainError::MissingEvidence("El evento"));
        }

        for evidence_id in &event.evidence_ids {
            if !self.evidences.iter().any(|item| item.id == *evidence_id) {
                return Err(DomainError::UnknownEvidence(*evidence_id));
            }
        }

        self.events.push(event);
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

        if finding.evidence_ids.is_empty() {
            return Err(DomainError::MissingEvidence("El hallazgo"));
        }

        for evidence_id in &finding.evidence_ids {
            if !self.evidences.iter().any(|item| item.id == *evidence_id) {
                return Err(DomainError::UnknownEvidence(*evidence_id));
            }
        }

        self.findings.push(finding);
        Ok(())
    }

    // Acceso de solo lectura a los elementos de la investigación.
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

    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
}
