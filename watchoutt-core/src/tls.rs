// Parser mínimo de ClientHello TLS.
//
// No descifra, no valida certificados, no verifica MACs. Solo
// extrae información visible en claro del primer mensaje:
//
//   * server_name (SNI, extensión 0x0000)
//   * supported_versions (extensión 0x002B)
//   * ALPN (extensión 0x0010)
//
// Todos los límites están acotados para que un cliente malicioso
// no pueda provocar asignaciones desproporcionadas.
//
// Referencias: RFC 8446 §4.1.2 (ClientHello), RFC 6066 §3 (SNI).

use std::fmt;

const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_MAX_RECORD_LEN: usize = 16 * 1024 + 2048;
const TLS_MAX_EXTENSION_LEN: usize = 8 * 1024;
const TLS_MAX_SNI_LEN: usize = 255;
const TLS_MAX_ALPN_COUNT: usize = 32;
const TLS_MAX_ALPN_LEN: usize = 255;
const TLS_MAX_SUPPORTED_VERSIONS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHello {
    pub record_version: u16,
    pub client_version: u16,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
}

impl TlsClientHello {
    /// Representación corta para `event.summary` y `evidence.excerpt`.
    pub fn summary(&self) -> String {
        let sni = self.server_name.as_deref().unwrap_or("(sin SNI)");

        let mut parts = vec![format!("TLS ClientHello SNI={sni}")];

        if !self.supported_versions.is_empty() {
            let versions = self
                .supported_versions
                .iter()
                .map(|v| format_version(*v))
                .collect::<Vec<_>>()
                .join(",");
            parts.push(format!("versions={versions}"));
        } else {
            parts.push(format!("version={}", format_version(self.client_version)));
        }

        if !self.alpn.is_empty() {
            parts.push(format!("alpn={}", self.alpn.join(",")));
        }

        parts.join(" ")
    }
}

fn format_version(value: u16) -> String {
    // En supported_versions, 0x0304 = TLS 1.3, 0x0303 = TLS 1.2, etc.
    match value {
        0x0300 => "1.0".to_string(),
        0x0301 => "1.1".to_string(),
        0x0302 => "1.2".to_string(),
        0x0303 => "1.2".to_string(),
        0x0304 => "1.3".to_string(),
        other => format!("0x{other:04x}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TlsParseError {
    Truncated,
    NotClientHello,
    InvalidRecord,
    InvalidExtension,
}

impl fmt::Display for TlsParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "mensaje TLS truncado"),
            Self::NotClientHello => write!(f, "no es un ClientHello"),
            Self::InvalidRecord => write!(f, "registro TLS inválido"),
            Self::InvalidExtension => write!(f, "extensión TLS inválida"),
        }
    }
}

impl std::error::Error for TlsParseError {}

/// Parser principal. Rechaza rápidamente cualquier byte que no
/// empiece como un registro Handshake de TLS.
pub fn parse_tls_client_hello(bytes: &[u8]) -> Result<TlsClientHello, TlsParseError> {
    // Cabecera de registro TLS: 1 byte tipo, 2 bytes versión, 2 bytes longitud.
    if bytes.len() < 5 {
        return Err(TlsParseError::Truncated);
    }
    if bytes[0] != TLS_HANDSHAKE_CONTENT_TYPE {
        return Err(TlsParseError::NotClientHello);
    }
    let record_version = u16::from_be_bytes([bytes[1], bytes[2]]);
    let record_length = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;

    if record_length > TLS_MAX_RECORD_LEN {
        return Err(TlsParseError::InvalidRecord);
    }
    if bytes.len() < 5 + record_length {
        return Err(TlsParseError::Truncated);
    }

    // Handshake: 1 byte tipo + 3 bytes longitud + cuerpo.
    let handshake = &bytes[5..5 + record_length];
    if handshake.len() < 4 {
        return Err(TlsParseError::Truncated);
    }
    if handshake[0] != TLS_HANDSHAKE_CLIENT_HELLO {
        return Err(TlsParseError::NotClientHello);
    }
    let hs_len = read_u24(&handshake[1..4]) as usize;
    if handshake.len() < 4 + hs_len {
        return Err(TlsParseError::Truncated);
    }
    let body = &handshake[4..4 + hs_len];

    parse_client_hello_body(record_version, body)
}

fn parse_client_hello_body(
    record_version: u16,
    body: &[u8],
) -> Result<TlsClientHello, TlsParseError> {
    // client_version (2) + random (32) + session_id_len (1).
    if body.len() < 35 {
        return Err(TlsParseError::Truncated);
    }

    let client_version = u16::from_be_bytes([body[0], body[1]]);
    let mut offset = 2 + 32; // saltamos random

    let session_id_len = body[offset] as usize;
    offset += 1;
    if body.len() < offset + session_id_len {
        return Err(TlsParseError::Truncated);
    }
    offset += session_id_len;

    // cipher_suites
    if body.len() < offset + 2 {
        return Err(TlsParseError::Truncated);
    }
    let cs_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    offset += 2;
    if body.len() < offset + cs_len {
        return Err(TlsParseError::Truncated);
    }
    offset += cs_len;

    // compression_methods
    if body.len() < offset + 1 {
        return Err(TlsParseError::Truncated);
    }
    let cm_len = body[offset] as usize;
    offset += 1;
    if body.len() < offset + cm_len {
        return Err(TlsParseError::Truncated);
    }
    offset += cm_len;

    // Extensions: opcional en TLS 1.0/1.1, obligatoria en 1.2/1.3.
    let mut server_name = None;
    let mut alpn = Vec::new();
    let mut supported_versions = Vec::new();

    if body.len() >= offset + 2 {
        let ext_total = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;

        if body.len() < offset + ext_total {
            return Err(TlsParseError::Truncated);
        }

        let mut ext_end = offset + ext_total;
        let mut cursor = offset;

        while cursor + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([body[cursor], body[cursor + 1]]);
            let ext_len = u16::from_be_bytes([body[cursor + 2], body[cursor + 3]]) as usize;
            cursor += 4;

            if ext_len > TLS_MAX_EXTENSION_LEN {
                return Err(TlsParseError::InvalidExtension);
            }
            if cursor + ext_len > ext_end {
                return Err(TlsParseError::Truncated);
            }

            let ext_data = &body[cursor..cursor + ext_len];

            match ext_type {
                0x0000 => {
                    if let Some(name) = parse_sni(ext_data) {
                        server_name = Some(name);
                    }
                }
                0x0010 => {
                    if let Some(list) = parse_alpn(ext_data) {
                        alpn = list;
                    }
                }
                0x002B => {
                    if let Some(versions) = parse_supported_versions(ext_data) {
                        supported_versions = versions;
                    }
                }
                _ => {}
            }

            cursor += ext_len;
        }

        ext_end = cursor; // silencia unused mut si el compilador se queja
        let _ = ext_end;
    }

    Ok(TlsClientHello {
        record_version,
        client_version,
        server_name,
        alpn,
        supported_versions,
    })
}

fn parse_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }
    let mut cursor = 2;
    let end = 2 + list_len;

    while cursor + 3 <= end {
        let name_type = data[cursor];
        let name_len = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        cursor += 3;
        if name_type == 0 && name_len > 0 && name_len <= TLS_MAX_SNI_LEN {
            if cursor + name_len > end {
                return None;
            }
            return String::from_utf8(data[cursor..cursor + name_len].to_vec()).ok();
        }
        cursor += name_len;
    }
    None
}

fn parse_alpn(data: &[u8]) -> Option<Vec<String>> {
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return None;
    }
    let mut cursor = 2;
    let end = 2 + list_len;
    let mut out = Vec::new();

    while cursor < end && out.len() < TLS_MAX_ALPN_COUNT {
        let len = data[cursor] as usize;
        cursor += 1;
        if len == 0 || len > TLS_MAX_ALPN_LEN {
            return None;
        }
        if cursor + len > end {
            return None;
        }
        if let Ok(s) = std::str::from_utf8(&data[cursor..cursor + len]) {
            out.push(s.to_string());
        }
        cursor += len;
    }
    Some(out)
}

fn parse_supported_versions(data: &[u8]) -> Option<Vec<u16>> {
    if data.len() < 1 {
        return None;
    }
    let list_len = data[0] as usize;
    if data.len() < 1 + list_len || list_len % 2 != 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut cursor = 1;
    while cursor + 2 <= 1 + list_len && out.len() < TLS_MAX_SUPPORTED_VERSIONS {
        out.push(u16::from_be_bytes([data[cursor], data[cursor + 1]]));
        cursor += 2;
    }
    Some(out)
}

fn read_u24(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye un ClientHello de prueba con SNI y ALPN opcionales.
    fn build_client_hello(sni: Option<&str>, alpn: &[&str], versions: &[u16]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_len = 0
        body.extend_from_slice(&[0x00, 0x02]); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.push(1); // compression_methods
        body.push(0);

        let mut extensions = Vec::new();

        if let Some(name) = sni {
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len() as u16;
            let mut sni_data = Vec::new();
            sni_data.extend_from_slice(&(name_len + 3).to_be_bytes());
            sni_data.push(0);
            sni_data.extend_from_slice(&name_len.to_be_bytes());
            sni_data.extend_from_slice(name_bytes);
            extensions.extend_from_slice(&[0x00, 0x00]);
            extensions.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sni_data);
        }

        if !alpn.is_empty() {
            let mut alpn_data = Vec::new();
            let mut list_inner = Vec::new();
            for proto in alpn {
                list_inner.push(proto.len() as u8);
                list_inner.extend_from_slice(proto.as_bytes());
            }
            alpn_data.extend_from_slice(&(list_inner.len() as u16).to_be_bytes());
            alpn_data.extend_from_slice(&list_inner);
            extensions.extend_from_slice(&[0x00, 0x10]);
            extensions.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&alpn_data);
        }

        if !versions.is_empty() {
            let mut sv = Vec::new();
            sv.push((versions.len() * 2) as u8);
            for v in versions {
                sv.extend_from_slice(&v.to_be_bytes());
            }
            extensions.extend_from_slice(&[0x00, 0x2B]);
            extensions.extend_from_slice(&(sv.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&sv);
        }

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

    #[test]
    fn parses_client_hello_with_sni() {
        let payload = build_client_hello(Some("example.com"), &[], &[]);
        let hello = parse_tls_client_hello(&payload).unwrap();
        assert_eq!(hello.server_name.as_deref(), Some("example.com"));
        assert_eq!(hello.client_version, 0x0303);
    }

    #[test]
    fn parses_alpn_extension() {
        let payload = build_client_hello(Some("example.com"), &["h2", "http/1.1"], &[]);
        let hello = parse_tls_client_hello(&payload).unwrap();
        assert_eq!(hello.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    }

    #[test]
    fn parses_supported_versions() {
        let payload = build_client_hello(Some("example.com"), &[], &[0x0304, 0x0303]);
        let hello = parse_tls_client_hello(&payload).unwrap();
        assert_eq!(hello.supported_versions, vec![0x0304, 0x0303]);
        assert!(hello.summary().contains("1.3"));
    }

    #[test]
    fn rejects_non_tls_payload() {
        assert!(parse_tls_client_hello(b"GET / HTTP/1.1").is_err());
        assert!(parse_tls_client_hello(&[]).is_err());
    }

    #[test]
    fn rejects_truncated_record() {
        let payload = build_client_hello(Some("example.com"), &[], &[]);
        assert!(parse_tls_client_hello(&payload[..payload.len() - 5]).is_err());
    }

    #[test]
    fn handles_missing_sni() {
        let payload = build_client_hello(None, &[], &[]);
        let hello = parse_tls_client_hello(&payload).unwrap();
        assert!(hello.server_name.is_none());
    }
}
