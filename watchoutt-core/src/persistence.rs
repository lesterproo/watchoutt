use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{
    Asset, AssetId, AssetKind, DomainError, EventId, EventKind, Evidence, EvidenceId,
    EvidenceLocation, Finding, FindingId, FindingKind, FlowId, Investigation, InvestigationId,
    NetworkEvent, NetworkFlow, Protocol, Severity, SourceFile, SourceFormat, SourceId,
};

const MAGIC: &[u8; 8] = b"NEXTRC01";
const FORMAT_VERSION: u32 = 2; // V2 por el campo tcp_flags

const MAX_PROJECT_SIZE: u64 = 256 * 1024 * 1024;
const MAX_STRING_SIZE: u32 = 16 * 1024 * 1024;
const MAX_COLLECTION_ITEMS: u32 = 1_000_000;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum PersistenceError {
    Io(io::Error),
    Domain(DomainError),
    InvalidMagic,
    UnsupportedVersion(u32),
    InvalidData(String),
    LimitExceeded(&'static str),
    NonUtf8Path,
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Error de almacenamiento: {error}"),
            Self::Domain(error) => write!(f, "Datos de investigación inválidos: {error}"),
            Self::InvalidMagic => write!(f, "El archivo no es un proyecto NEXTRACE válido"),
            Self::UnsupportedVersion(version) => {
                write!(f, "Versión de proyecto no compatible: {version}")
            }
            Self::InvalidData(message) => {
                write!(f, "Datos de proyecto corruptos: {message}")
            }
            Self::LimitExceeded(item) => {
                write!(f, "Se excedió el límite permitido para {item}")
            }
            Self::NonUtf8Path => {
                write!(f, "No se puede guardar una ruta que no sea UTF-8")
            }
        }
    }
}

impl std::error::Error for PersistenceError {}

impl From<io::Error> for PersistenceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<DomainError> for PersistenceError {
    fn from(error: DomainError) -> Self {
        Self::Domain(error)
    }
}

pub fn save_investigation(
    investigation: &Investigation,
    destination: impl AsRef<Path>,
) -> Result<(), PersistenceError> {
    let destination = destination.as_ref();

    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    fs::create_dir_all(parent)?;

    let temporary = temporary_path(destination)?;

    let result = (|| {
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(&temporary)?;

        {
            let mut writer = BufWriter::new(&file);
            encode_investigation(&mut writer, investigation)?;
            writer.flush()?;
        }

        file.sync_all()?;

        fs::rename(&temporary, destination)?;

        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }

        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }

    result
}

pub fn load_investigation(source: impl AsRef<Path>) -> Result<Investigation, PersistenceError> {
    let file = File::open(source)?;

    let metadata = file.metadata()?;

    if metadata.len() > MAX_PROJECT_SIZE {
        return Err(PersistenceError::LimitExceeded(
            "tamaño del archivo de proyecto",
        ));
    }

    let mut reader = Decoder::new(BufReader::new(file));

    let mut magic = [0u8; 8];
    reader.inner.read_exact(&mut magic)?;

    if &magic != MAGIC {
        return Err(PersistenceError::InvalidMagic);
    }

    let version = reader.read_u32()?;

    if version != FORMAT_VERSION {
        return Err(PersistenceError::UnsupportedVersion(version));
    }

    let investigation_id = InvestigationId(reader.read_u64()?);
    let name = reader.read_string()?;
    let description = reader.read_option_string()?;
    let created_at = reader.read_i64()?;

    let mut investigation = Investigation::new(investigation_id, name, description, created_at)?;

    let source_count = reader.read_count("fuentes")?;

    for _ in 0..source_count {
        investigation.add_source(read_source(&mut reader)?)?;
    }

    let asset_count = reader.read_count("activos")?;

    for _ in 0..asset_count {
        investigation.add_asset(read_asset(&mut reader)?)?;
    }

    let evidence_count = reader.read_count("evidencias")?;

    for _ in 0..evidence_count {
        investigation.add_evidence(read_evidence(&mut reader)?)?;
    }

    let event_count = reader.read_count("eventos")?;

    for _ in 0..event_count {
        investigation.add_event(read_event(&mut reader)?)?;
    }

    let flow_count = reader.read_count("flujos")?;

    for _ in 0..flow_count {
        investigation.add_flow(read_flow(&mut reader)?)?;
    }

    let finding_count = reader.read_count("hallazgos")?;

    for _ in 0..finding_count {
        investigation.add_finding(read_finding(&mut reader)?)?;
    }

    let mut trailing = [0u8; 1];

    if reader.inner.read(&mut trailing)? != 0 {
        return Err(PersistenceError::InvalidData(
            "hay datos adicionales al final del archivo".to_string(),
        ));
    }

    Ok(investigation)
}

fn temporary_path(destination: &Path) -> Result<PathBuf, PersistenceError> {
    let file_name = destination.file_name().ok_or_else(|| {
        PersistenceError::InvalidData(
            "la ruta de destino no contiene un nombre de archivo".to_string(),
        )
    })?;

    let mut temporary_name = file_name.to_os_string();

    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);

    temporary_name.push(format!(".tmp.{}.{}", std::process::id(), counter));

    Ok(destination.with_file_name(temporary_name))
}

struct Encoder<W: Write> {
    inner: W,
}

impl<W: Write> Encoder<W> {
    fn new(inner: W) -> Self {
        Self { inner }
    }

    fn write_u8(&mut self, value: u8) -> Result<(), PersistenceError> {
        self.inner.write_all(&[value])?;
        Ok(())
    }

    fn write_u16(&mut self, value: u16) -> Result<(), PersistenceError> {
        self.inner.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    fn write_u32(&mut self, value: u32) -> Result<(), PersistenceError> {
        self.inner.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    fn write_u64(&mut self, value: u64) -> Result<(), PersistenceError> {
        self.inner.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    fn write_i64(&mut self, value: i64) -> Result<(), PersistenceError> {
        self.inner.write_all(&value.to_le_bytes())?;
        Ok(())
    }

    fn write_bool(&mut self, value: bool) -> Result<(), PersistenceError> {
        self.write_u8(u8::from(value))
    }

    fn write_string(&mut self, value: &str) -> Result<(), PersistenceError> {
        let length =
            u32::try_from(value.len()).map_err(|_| PersistenceError::LimitExceeded("cadena"))?;

        if length > MAX_STRING_SIZE {
            return Err(PersistenceError::LimitExceeded("cadena"));
        }

        self.write_u32(length)?;
        self.inner.write_all(value.as_bytes())?;

        Ok(())
    }

    fn write_option_string(&mut self, value: &Option<String>) -> Result<(), PersistenceError> {
        self.write_bool(value.is_some())?;

        if let Some(value) = value {
            self.write_string(value)?;
        }

        Ok(())
    }

    fn write_count(&mut self, count: usize) -> Result<(), PersistenceError> {
        let count =
            u32::try_from(count).map_err(|_| PersistenceError::LimitExceeded("colección"))?;

        if count > MAX_COLLECTION_ITEMS {
            return Err(PersistenceError::LimitExceeded("colección"));
        }

        self.write_u32(count)
    }
}

struct Decoder<R: Read> {
    inner: R,
}

impl<R: Read> Decoder<R> {
    fn new(inner: R) -> Self {
        Self { inner }
    }

    fn read_u8(&mut self) -> Result<u8, PersistenceError> {
        let mut bytes = [0u8; 1];
        self.inner.read_exact(&mut bytes)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, PersistenceError> {
        let mut bytes = [0u8; 2];
        self.inner.read_exact(&mut bytes)?;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, PersistenceError> {
        let mut bytes = [0u8; 4];
        self.inner.read_exact(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, PersistenceError> {
        let mut bytes = [0u8; 8];
        self.inner.read_exact(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn read_i64(&mut self) -> Result<i64, PersistenceError> {
        let mut bytes = [0u8; 8];
        self.inner.read_exact(&mut bytes)?;
        Ok(i64::from_le_bytes(bytes))
    }

    fn read_bool(&mut self) -> Result<bool, PersistenceError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(PersistenceError::InvalidData(
                "valor booleano inválido".to_string(),
            )),
        }
    }

    fn read_string(&mut self) -> Result<String, PersistenceError> {
        let length = self.read_u32()?;

        if length > MAX_STRING_SIZE {
            return Err(PersistenceError::LimitExceeded("cadena"));
        }

        let mut bytes = vec![0u8; length as usize];
        self.inner.read_exact(&mut bytes)?;

        String::from_utf8(bytes).map_err(|_| {
            PersistenceError::InvalidData("una cadena no contiene UTF-8 válido".to_string())
        })
    }

    fn read_option_string(&mut self) -> Result<Option<String>, PersistenceError> {
        if self.read_bool()? {
            Ok(Some(self.read_string()?))
        } else {
            Ok(None)
        }
    }

    fn read_count(&mut self, collection: &'static str) -> Result<u32, PersistenceError> {
        let count = self.read_u32()?;

        if count > MAX_COLLECTION_ITEMS {
            return Err(PersistenceError::LimitExceeded(collection));
        }

        Ok(count)
    }
}

fn encode_investigation<W: Write>(
    writer: &mut W,
    investigation: &Investigation,
) -> Result<(), PersistenceError> {
    let mut encoder = Encoder::new(writer);

    encoder.inner.write_all(MAGIC)?;
    encoder.write_u32(FORMAT_VERSION)?;

    encoder.write_u64(investigation.id.0)?;
    encoder.write_string(&investigation.name)?;
    encoder.write_option_string(&investigation.description)?;
    encoder.write_i64(investigation.created_at_unix_ns)?;

    encoder.write_count(investigation.sources().len())?;

    for source in investigation.sources() {
        write_source(&mut encoder, source)?;
    }

    encoder.write_count(investigation.assets().len())?;

    for asset in investigation.assets() {
        write_asset(&mut encoder, asset)?;
    }

    encoder.write_count(investigation.evidences().len())?;

    for evidence in investigation.evidences() {
        write_evidence(&mut encoder, evidence)?;
    }

    encoder.write_count(investigation.events().len())?;

    for event in investigation.events() {
        write_event(&mut encoder, event)?;
    }

    encoder.write_count(investigation.flows().len())?;

    for flow in investigation.flows() {
        write_flow(&mut encoder, flow)?;
    }

    encoder.write_count(investigation.findings().len())?;

    for finding in investigation.findings() {
        write_finding(&mut encoder, finding)?;
    }

    Ok(())
}

fn write_source<W: Write>(
    writer: &mut Encoder<W>,
    source: &SourceFile,
) -> Result<(), PersistenceError> {
    writer.write_u64(source.id.0)?;
    writer.write_string(&source.file_name)?;

    let path = source
        .relative_path
        .to_str()
        .ok_or(PersistenceError::NonUtf8Path)?;

    writer.write_string(path)?;
    write_source_format(writer, &source.format)?;
    writer.write_u64(source.size_bytes)?;
    writer.write_option_string(&source.sha256)?;
    writer.write_i64(source.imported_at_unix_ns)?;

    Ok(())
}

fn read_source<R: Read>(reader: &mut Decoder<R>) -> Result<SourceFile, PersistenceError> {
    Ok(SourceFile {
        id: SourceId(reader.read_u64()?),
        file_name: reader.read_string()?,
        relative_path: PathBuf::from(reader.read_string()?),
        format: read_source_format(reader)?,
        size_bytes: reader.read_u64()?,
        sha256: reader.read_option_string()?,
        imported_at_unix_ns: reader.read_i64()?,
    })
}

fn write_source_format<W: Write>(
    writer: &mut Encoder<W>,
    format: &SourceFormat,
) -> Result<(), PersistenceError> {
    match format {
        SourceFormat::Pcap => writer.write_u8(0)?,
        SourceFormat::PcapNg => writer.write_u8(1)?,
        SourceFormat::FirewallLog => writer.write_u8(2)?,
        SourceFormat::RouterConfig => writer.write_u8(3)?,
        SourceFormat::SwitchConfig => writer.write_u8(4)?,
        SourceFormat::ServerLog => writer.write_u8(5)?,
        SourceFormat::Csv => writer.write_u8(6)?,
        SourceFormat::Json => writer.write_u8(7)?,
        SourceFormat::Text => writer.write_u8(8)?,
        SourceFormat::Unknown => writer.write_u8(9)?,
    }

    Ok(())
}

fn read_source_format<R: Read>(reader: &mut Decoder<R>) -> Result<SourceFormat, PersistenceError> {
    match reader.read_u8()? {
        0 => Ok(SourceFormat::Pcap),
        1 => Ok(SourceFormat::PcapNg),
        2 => Ok(SourceFormat::FirewallLog),
        3 => Ok(SourceFormat::RouterConfig),
        4 => Ok(SourceFormat::SwitchConfig),
        5 => Ok(SourceFormat::ServerLog),
        6 => Ok(SourceFormat::Csv),
        7 => Ok(SourceFormat::Json),
        8 => Ok(SourceFormat::Text),
        9 => Ok(SourceFormat::Unknown),
        _ => Err(invalid_tag("formato de fuente")),
    }
}

fn write_asset<W: Write>(writer: &mut Encoder<W>, asset: &Asset) -> Result<(), PersistenceError> {
    writer.write_u64(asset.id.0)?;
    write_asset_kind(writer, &asset.kind)?;
    writer.write_string(&asset.value)?;
    writer.write_option_string(&asset.label)?;

    Ok(())
}

fn read_asset<R: Read>(reader: &mut Decoder<R>) -> Result<Asset, PersistenceError> {
    Ok(Asset {
        id: AssetId(reader.read_u64()?),
        kind: read_asset_kind(reader)?,
        value: reader.read_string()?,
        label: reader.read_option_string()?,
    })
}

fn write_asset_kind<W: Write>(
    writer: &mut Encoder<W>,
    kind: &AssetKind,
) -> Result<(), PersistenceError> {
    match kind {
        AssetKind::IpAddress => writer.write_u8(0)?,
        AssetKind::MacAddress => writer.write_u8(1)?,
        AssetKind::Hostname => writer.write_u8(2)?,
        AssetKind::Network => writer.write_u8(3)?,
        AssetKind::Device => writer.write_u8(4)?,
        AssetKind::Service => writer.write_u8(5)?,
    }

    Ok(())
}

fn read_asset_kind<R: Read>(reader: &mut Decoder<R>) -> Result<AssetKind, PersistenceError> {
    match reader.read_u8()? {
        0 => Ok(AssetKind::IpAddress),
        1 => Ok(AssetKind::MacAddress),
        2 => Ok(AssetKind::Hostname),
        3 => Ok(AssetKind::Network),
        4 => Ok(AssetKind::Device),
        5 => Ok(AssetKind::Service),
        _ => Err(invalid_tag("tipo de activo")),
    }
}

fn write_evidence<W: Write>(
    writer: &mut Encoder<W>,
    evidence: &Evidence,
) -> Result<(), PersistenceError> {
    writer.write_u64(evidence.id.0)?;
    writer.write_u64(evidence.source_id.0)?;

    match &evidence.location {
        EvidenceLocation::PacketFrame { frame_number } => {
            writer.write_u8(0)?;
            writer.write_u64(*frame_number)?;
        }
        EvidenceLocation::LogLine { line_number } => {
            writer.write_u8(1)?;
            writer.write_u64(*line_number)?;
        }
        EvidenceLocation::ByteRange { offset, length } => {
            writer.write_u8(2)?;
            writer.write_u64(*offset)?;
            writer.write_u64(*length)?;
        }
        EvidenceLocation::JsonPath { path } => {
            writer.write_u8(3)?;
            writer.write_string(path)?;
        }
    }

    writer.write_option_string(&evidence.excerpt)?;

    Ok(())
}

fn read_evidence<R: Read>(reader: &mut Decoder<R>) -> Result<Evidence, PersistenceError> {
    let id = EvidenceId(reader.read_u64()?);
    let source_id = SourceId(reader.read_u64()?);

    let location = match reader.read_u8()? {
        0 => EvidenceLocation::PacketFrame {
            frame_number: reader.read_u64()?,
        },
        1 => EvidenceLocation::LogLine {
            line_number: reader.read_u64()?,
        },
        2 => EvidenceLocation::ByteRange {
            offset: reader.read_u64()?,
            length: reader.read_u64()?,
        },
        3 => EvidenceLocation::JsonPath {
            path: reader.read_string()?,
        },
        _ => return Err(invalid_tag("ubicación de evidencia")),
    };

    Ok(Evidence {
        id,
        source_id,
        location,
        excerpt: reader.read_option_string()?,
    })
}

fn write_protocol<W: Write>(
    writer: &mut Encoder<W>,
    protocol: &Protocol,
) -> Result<(), PersistenceError> {
    match protocol {
        Protocol::Tcp => writer.write_u8(0)?,
        Protocol::Udp => writer.write_u8(1)?,
        Protocol::Icmp => writer.write_u8(2)?,
        Protocol::IcmpV6 => writer.write_u8(3)?,
        Protocol::Other(value) => {
            writer.write_u8(4)?;
            writer.write_string(value)?;
        }
    }

    Ok(())
}

fn read_protocol<R: Read>(reader: &mut Decoder<R>) -> Result<Protocol, PersistenceError> {
    match reader.read_u8()? {
        0 => Ok(Protocol::Tcp),
        1 => Ok(Protocol::Udp),
        2 => Ok(Protocol::Icmp),
        3 => Ok(Protocol::IcmpV6),
        4 => Ok(Protocol::Other(reader.read_string()?)),
        _ => Err(invalid_tag("protocolo")),
    }
}

fn write_event_kind<W: Write>(
    writer: &mut Encoder<W>,
    kind: &EventKind,
) -> Result<(), PersistenceError> {
    match kind {
        EventKind::Packet => writer.write_u8(0)?,
        EventKind::NetworkFlow => writer.write_u8(1)?,
        EventKind::FirewallAllow => writer.write_u8(2)?,
        EventKind::FirewallDeny => writer.write_u8(3)?,
        EventKind::AuthenticationSuccess => writer.write_u8(4)?,
        EventKind::AuthenticationFailure => writer.write_u8(5)?,
        EventKind::ConfigurationChange => writer.write_u8(6)?,
        EventKind::ServiceState => writer.write_u8(7)?,
        EventKind::Other(value) => {
            writer.write_u8(8)?;
            writer.write_string(value)?;
        }
        EventKind::DnsQuery => writer.write_u8(9)?,
        EventKind::DnsResponse => writer.write_u8(10)?,
        EventKind::TlsClientHello => writer.write_u8(11)?,
        EventKind::HttpRequest => writer.write_u8(12)?,
        EventKind::HttpResponse => writer.write_u8(13)?,
        EventKind::DnsResolution => writer.write_u8(14)?,
    }

    Ok(())
}

fn read_event_kind<R: Read>(reader: &mut Decoder<R>) -> Result<EventKind, PersistenceError> {
    match reader.read_u8()? {
        0 => Ok(EventKind::Packet),
        1 => Ok(EventKind::NetworkFlow),
        2 => Ok(EventKind::FirewallAllow),
        3 => Ok(EventKind::FirewallDeny),
        4 => Ok(EventKind::AuthenticationSuccess),
        5 => Ok(EventKind::AuthenticationFailure),
        6 => Ok(EventKind::ConfigurationChange),
        7 => Ok(EventKind::ServiceState),
        8 => Ok(EventKind::Other(reader.read_string()?)),
        9 => Ok(EventKind::DnsQuery),
        10 => Ok(EventKind::DnsResponse),
        11 => Ok(EventKind::TlsClientHello),
        12 => Ok(EventKind::HttpRequest),
        13 => Ok(EventKind::HttpResponse),
        14 => Ok(EventKind::DnsResolution),
        _ => Err(invalid_tag("tipo de evento")),
    }
}

fn write_event<W: Write>(
    writer: &mut Encoder<W>,
    event: &NetworkEvent,
) -> Result<(), PersistenceError> {
    writer.write_u64(event.id.0)?;

    writer.write_bool(event.timestamp_unix_ns.is_some())?;

    if let Some(timestamp) = event.timestamp_unix_ns {
        writer.write_i64(timestamp)?;
    }

    write_event_kind(writer, &event.kind)?;
    writer.write_string(&event.summary)?;

    write_option_id(writer, event.source_asset.map(|id| id.0))?;
    write_option_id(writer, event.destination_asset.map(|id| id.0))?;

    write_option_u16(writer, event.source_port)?;
    write_option_u16(writer, event.destination_port)?;

    writer.write_bool(event.protocol.is_some())?;

    if let Some(protocol) = &event.protocol {
        write_protocol(writer, protocol)?;
    }

    writer.write_bool(event.tcp_flags.is_some())?;
    if let Some(flags) = &event.tcp_flags {
        writer.write_string(flags)?;
    }

    writer.write_count(event.evidence_ids.len())?;

    for id in &event.evidence_ids {
        writer.write_u64(id.0)?;
    }

    Ok(())
}

fn read_event<R: Read>(reader: &mut Decoder<R>) -> Result<NetworkEvent, PersistenceError> {
    let id = EventId(reader.read_u64()?);

    let timestamp_unix_ns = if reader.read_bool()? {
        Some(reader.read_i64()?)
    } else {
        None
    };

    let kind = read_event_kind(reader)?;
    let summary = reader.read_string()?;

    let source_asset = read_option_id(reader)?.map(AssetId);
    let destination_asset = read_option_id(reader)?.map(AssetId);

    let source_port = read_option_u16(reader)?;
    let destination_port = read_option_u16(reader)?;

    let protocol = if reader.read_bool()? {
        Some(read_protocol(reader)?)
    } else {
        None
    };

    let tcp_flags = if reader.read_bool()? {
        Some(reader.read_string()?)
    } else {
        None
    };

    let count = reader.read_count("evidencias de evento")?;
    let mut evidence_ids = Vec::with_capacity(count as usize);

    for _ in 0..count {
        evidence_ids.push(EvidenceId(reader.read_u64()?));
    }

    Ok(NetworkEvent {
        id,
        timestamp_unix_ns,
        kind,
        summary,
        source_asset,
        destination_asset,
        source_port,
        destination_port,
        protocol,
        evidence_ids,
        tcp_flags,
    })
}

fn write_flow<W: Write>(
    writer: &mut Encoder<W>,
    flow: &NetworkFlow,
) -> Result<(), PersistenceError> {
    writer.write_u64(flow.id.0)?;
    writer.write_u64(flow.endpoint_a.0)?;
    writer.write_u64(flow.endpoint_b.0)?;

    write_option_u16(writer, flow.endpoint_a_port)?;
    write_option_u16(writer, flow.endpoint_b_port)?;

    write_protocol(writer, &flow.protocol)?;

    writer.write_i64(flow.first_seen_unix_ns)?;
    writer.write_i64(flow.last_seen_unix_ns)?;

    writer.write_u64(flow.packet_count)?;
    writer.write_u64(flow.captured_bytes)?;
    writer.write_u64(flow.original_bytes)?;

    writer.write_u64(flow.packets_a_to_b)?;
    writer.write_u64(flow.packets_b_to_a)?;

    writer.write_u64(flow.captured_bytes_a_to_b)?;
    writer.write_u64(flow.captured_bytes_b_to_a)?;

    writer.write_count(flow.evidence_ids.len())?;

    for id in &flow.evidence_ids {
        writer.write_u64(id.0)?;
    }

    Ok(())
}

fn read_flow<R: Read>(reader: &mut Decoder<R>) -> Result<NetworkFlow, PersistenceError> {
    let id = FlowId(reader.read_u64()?);
    let endpoint_a = AssetId(reader.read_u64()?);
    let endpoint_b = AssetId(reader.read_u64()?);

    let endpoint_a_port = read_option_u16(reader)?;
    let endpoint_b_port = read_option_u16(reader)?;

    let protocol = read_protocol(reader)?;

    let first_seen_unix_ns = reader.read_i64()?;
    let last_seen_unix_ns = reader.read_i64()?;

    let packet_count = reader.read_u64()?;
    let captured_bytes = reader.read_u64()?;
    let original_bytes = reader.read_u64()?;

    let packets_a_to_b = reader.read_u64()?;
    let packets_b_to_a = reader.read_u64()?;

    let captured_bytes_a_to_b = reader.read_u64()?;
    let captured_bytes_b_to_a = reader.read_u64()?;

    let count = reader.read_count("evidencias de flujo")?;
    let mut evidence_ids = Vec::with_capacity(count as usize);

    for _ in 0..count {
        evidence_ids.push(EvidenceId(reader.read_u64()?));
    }

    Ok(NetworkFlow {
        id,
        endpoint_a,
        endpoint_b,
        endpoint_a_port,
        endpoint_b_port,
        protocol,
        first_seen_unix_ns,
        last_seen_unix_ns,
        packet_count,
        captured_bytes,
        original_bytes,
        packets_a_to_b,
        packets_b_to_a,
        captured_bytes_a_to_b,
        captured_bytes_b_to_a,
        evidence_ids,
    })
}

fn write_finding_kind<W: Write>(
    writer: &mut Encoder<W>,
    kind: &FindingKind,
) -> Result<(), PersistenceError> {
    match kind {
        FindingKind::Observation => writer.write_u8(0)?,
        FindingKind::Hypothesis => writer.write_u8(1)?,
        FindingKind::Conclusion => writer.write_u8(2)?,
    }

    Ok(())
}

fn read_finding_kind<R: Read>(reader: &mut Decoder<R>) -> Result<FindingKind, PersistenceError> {
    match reader.read_u8()? {
        0 => Ok(FindingKind::Observation),
        1 => Ok(FindingKind::Hypothesis),
        2 => Ok(FindingKind::Conclusion),
        _ => Err(invalid_tag("tipo de hallazgo")),
    }
}

fn write_severity<W: Write>(
    writer: &mut Encoder<W>,
    severity: &Severity,
) -> Result<(), PersistenceError> {
    match severity {
        Severity::Info => writer.write_u8(0)?,
        Severity::Low => writer.write_u8(1)?,
        Severity::Medium => writer.write_u8(2)?,
        Severity::High => writer.write_u8(3)?,
        Severity::Critical => writer.write_u8(4)?,
    }

    Ok(())
}

fn read_severity<R: Read>(reader: &mut Decoder<R>) -> Result<Severity, PersistenceError> {
    match reader.read_u8()? {
        0 => Ok(Severity::Info),
        1 => Ok(Severity::Low),
        2 => Ok(Severity::Medium),
        3 => Ok(Severity::High),
        4 => Ok(Severity::Critical),
        _ => Err(invalid_tag("severidad")),
    }
}

fn write_finding<W: Write>(
    writer: &mut Encoder<W>,
    finding: &Finding,
) -> Result<(), PersistenceError> {
    writer.write_u64(finding.id.0)?;
    write_finding_kind(writer, &finding.kind)?;
    write_severity(writer, &finding.severity)?;

    writer.write_string(&finding.title)?;
    writer.write_string(&finding.description)?;

    writer.write_count(finding.evidence_ids.len())?;

    for id in &finding.evidence_ids {
        writer.write_u64(id.0)?;
    }

    writer.write_bool(finding.confidence_percent.is_some())?;

    if let Some(confidence) = finding.confidence_percent {
        writer.write_u8(confidence)?;
    }

    Ok(())
}

fn read_finding<R: Read>(reader: &mut Decoder<R>) -> Result<Finding, PersistenceError> {
    let id = FindingId(reader.read_u64()?);
    let kind = read_finding_kind(reader)?;
    let severity = read_severity(reader)?;

    let title = reader.read_string()?;
    let description = reader.read_string()?;

    let count = reader.read_count("evidencias de hallazgo")?;
    let mut evidence_ids = Vec::with_capacity(count as usize);

    for _ in 0..count {
        evidence_ids.push(EvidenceId(reader.read_u64()?));
    }

    let confidence_percent = if reader.read_bool()? {
        Some(reader.read_u8()?)
    } else {
        None
    };

    Ok(Finding {
        id,
        kind,
        severity,
        title,
        description,
        evidence_ids,
        confidence_percent,
    })
}

fn write_option_id<W: Write>(
    writer: &mut Encoder<W>,
    value: Option<u64>,
) -> Result<(), PersistenceError> {
    writer.write_bool(value.is_some())?;

    if let Some(value) = value {
        writer.write_u64(value)?;
    }

    Ok(())
}

fn read_option_id<R: Read>(reader: &mut Decoder<R>) -> Result<Option<u64>, PersistenceError> {
    if reader.read_bool()? {
        Ok(Some(reader.read_u64()?))
    } else {
        Ok(None)
    }
}

fn write_option_u16<W: Write>(
    writer: &mut Encoder<W>,
    value: Option<u16>,
) -> Result<(), PersistenceError> {
    writer.write_bool(value.is_some())?;

    if let Some(value) = value {
        writer.write_u16(value)?;
    }

    Ok(())
}

fn read_option_u16<R: Read>(reader: &mut Decoder<R>) -> Result<Option<u16>, PersistenceError> {
    if reader.read_bool()? {
        Ok(Some(reader.read_u16()?))
    } else {
        Ok(None)
    }
}

fn invalid_tag(name: &str) -> PersistenceError {
    PersistenceError::InvalidData(format!("etiqueta inválida para {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temporary_file() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

        std::env::temp_dir().join(format!(
            "nextrace_persistence_test_{}_{}.nxt",
            std::process::id(),
            counter
        ))
    }

    fn sample_investigation() -> Investigation {
        let mut investigation = Investigation::new(
            InvestigationId(7),
            "Investigación de prueba",
            Some("Prueba completa de persistencia".to_string()),
            1_700_000_000_000_000_000,
        )
        .unwrap();

        investigation
            .add_source(SourceFile {
                id: SourceId(1),
                file_name: "captura.pcap".to_string(),
                relative_path: PathBuf::from("sources/captura.pcap"),
                format: SourceFormat::Pcap,
                size_bytes: 128,
                sha256: Some("a".repeat(64)),
                imported_at_unix_ns: 1_700_000_000_000_000_100,
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
            .add_asset(Asset {
                id: AssetId(2),
                kind: AssetKind::IpAddress,
                value: "1.1.1.1".to_string(),
                label: None,
            })
            .unwrap();

        investigation
            .add_evidence(Evidence {
                id: EvidenceId(1),
                source_id: SourceId(1),
                location: EvidenceLocation::PacketFrame { frame_number: 1 },
                excerpt: Some("Paquete de prueba".to_string()),
            })
            .unwrap();

        investigation
            .add_event(NetworkEvent {
                id: EventId(1),
                timestamp_unix_ns: Some(1_700_000_000_000_000_200),
                kind: EventKind::Packet,
                summary: "Comunicación TCP observada".to_string(),
                source_asset: Some(AssetId(1)),
                destination_asset: Some(AssetId(2)),
                source_port: Some(50000),
                destination_port: Some(443),
                protocol: Some(Protocol::Tcp),
                evidence_ids: vec![EvidenceId(1)],
                tcp_flags: Some("SYN, ACK".to_string()),
            })
            .unwrap();

        investigation
            .add_flow(NetworkFlow {
                id: FlowId(1),
                endpoint_a: AssetId(1),
                endpoint_b: AssetId(2),
                endpoint_a_port: Some(50000),
                endpoint_b_port: Some(443),
                protocol: Protocol::Tcp,
                first_seen_unix_ns: 1_700_000_000_000_000_200,
                last_seen_unix_ns: 1_700_000_000_000_000_300,
                packet_count: 2,
                captured_bytes: 120,
                original_bytes: 120,
                packets_a_to_b: 1,
                packets_b_to_a: 1,
                captured_bytes_a_to_b: 60,
                captured_bytes_b_to_a: 60,
                evidence_ids: vec![EvidenceId(1)],
            })
            .unwrap();

        investigation
            .add_finding(Finding {
                id: FindingId(1),
                kind: FindingKind::Observation,
                severity: Severity::Info,
                title: "Comunicación identificada".to_string(),
                description: "Se observó tráfico TCP entre dos activos.".to_string(),
                evidence_ids: vec![EvidenceId(1)],
                confidence_percent: Some(100),
            })
            .unwrap();

        investigation
    }

    #[test]
    fn saves_and_restores_complete_investigation() {
        let original = sample_investigation();
        let path = temporary_file();

        save_investigation(&original, &path).unwrap();

        let restored = load_investigation(&path).unwrap();

        assert_eq!(restored, original);

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_invalid_project_magic() {
        let path = temporary_file();

        fs::write(&path, b"NOTANXTR").unwrap();

        let result = load_investigation(&path);

        assert!(matches!(result, Err(PersistenceError::InvalidMagic)));

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_truncated_project_file() {
        let path = temporary_file();

        fs::write(&path, MAGIC).unwrap();

        let result = load_investigation(&path);

        assert!(result.is_err());

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_unsupported_project_version() {
        let path = temporary_file();

        let mut data = Vec::new();
        data.extend_from_slice(MAGIC);
        data.extend_from_slice(&999u32.to_le_bytes());

        fs::write(&path, data).unwrap();

        let result = load_investigation(&path);

        assert!(matches!(
            result,
            Err(PersistenceError::UnsupportedVersion(999))
        ));

        fs::remove_file(path).unwrap();
    }
}
