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
}