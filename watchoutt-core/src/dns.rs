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
    Mx {
        preference: u16,
        exchange: String,
    },
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
            Self::Mx {
                preference,
                exchange,
            } => {
                format!("{preference} {exchange}")
            }
            Self::Txt(strings) => strings
                .iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" "),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
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

        let qtype = DnsRecordType::from_u16(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        let qclass = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
        offset += 4;

        questions.push(DnsQuestion {
            name,
            qtype,
            qclass,
        });
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
            let label = String::from_utf8_lossy(&bytes[pos + 1..pos + 1 + label_len]).into_owned();
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

    let rtype = DnsRecordType::from_u16(u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
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
        DnsRecord {
            name,
            rtype,
            class,
            ttl,
            rdata,
        },
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
                Ok((exchange, _)) => DnsRdata::Mx {
                    preference,
                    exchange,
                },
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
                Ok((target, _)) => DnsRdata::Srv {
                    priority,
                    weight,
                    port,
                    target,
                },
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
    let kind = if message.is_response {
        "respuesta"
    } else {
        "consulta"
    };

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
        format!(
            "DNS respuesta: {q} sin respuestas (rcode {})",
            message.rcode
        )
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
            5, b'h', b'e', b'l', b'l', b'o', 5, b'w', b'o', b'r', b'l', b'd',
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
            DnsRdata::Mx {
                preference,
                exchange,
            } => {
                assert_eq!(*preference, 10);
                assert_eq!(exchange, "example.com");
            }
            other => panic!("se esperaba MX, se obtuvo {other:?}"),
        }
    }

    #[test]
    fn parses_aaaa_record() {
        // 2001:db8::1
        let rdata: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
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
}
