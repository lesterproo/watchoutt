
use crate::Protocol;

/// Datos de transporte extraídos de un frame Ethernet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportPayload {
    pub protocol: Protocol,
    pub source_port: u16,
    pub destination_port: u16,
    pub bytes: Vec<u8>,
}

/// Extrae el payload TCP o UDP de un frame Ethernet.
///
/// Devuelve None ante protocolos no compatibles, fragmentación,
/// cabeceras incompletas o longitudes inválidas.
pub fn extract_transport_payload(frame: &[u8]) -> Option<TransportPayload> {
    if frame.len() < 14 {
        return None;
    }

    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;

    // VLAN: 802.1Q, 802.1ad y QinQ.
    for _ in 0..4 {
        if !matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }

        let tag_end = offset.checked_add(4)?;
        if frame.len() < tag_end {
            return None;
        }

        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset = tag_end;
    }

    let (ip_protocol, transport_offset, ip_end) = match ether_type {
        // IPv4
        0x0800 => {
            let header_end = offset.checked_add(20)?;
            if frame.len() < header_end {
                return None;
            }

            let version_ihl = frame[offset];
            if version_ihl >> 4 != 4 {
                return None;
            }

            let ihl = ((version_ihl & 0x0f) as usize).checked_mul(4)?;
            if ihl < 20 {
                return None;
            }

            let ip_header_end = offset.checked_add(ihl)?;
            if frame.len() < ip_header_end {
                return None;
            }

            let total_length = u16::from_be_bytes([
                frame[offset + 2],
                frame[offset + 3],
            ]) as usize;

            if total_length < ihl {
                return None;
            }

            // No interpretar fragmentos como segmentos completos.
            let fragment = u16::from_be_bytes([
                frame[offset + 6],
                frame[offset + 7],
            ]);
            if fragment & 0x3fff != 0 {
                return None;
            }

            let ip_end = offset.checked_add(total_length)?;
            if ip_end > frame.len() {
                return None;
            }

            (frame[offset + 9], ip_header_end, ip_end)
        }

        // IPv6 básico: sin cabeceras de extensión.
        0x86dd => {
            let header_end = offset.checked_add(40)?;
            if frame.len() < header_end || frame[offset] >> 4 != 6 {
                return None;
            }

            let payload_length = u16::from_be_bytes([
                frame[offset + 4],
                frame[offset + 5],
            ]) as usize;

            // Payload length cero (jumbogramas) queda fuera de esta versión.
            if payload_length == 0 {
                return None;
            }

            let ip_end = header_end.checked_add(payload_length)?;
            if ip_end > frame.len() {
                return None;
            }

            (frame[offset + 6], header_end, ip_end)
        }

        _ => return None,
    };

    if transport_offset > ip_end {
        return None;
    }

    let available = &frame[transport_offset..ip_end];

    match ip_protocol {
        // TCP
        6 => {
            if available.len() < 20 {
                return None;
            }

            let source_port =
                u16::from_be_bytes([available[0], available[1]]);
            let destination_port =
                u16::from_be_bytes([available[2], available[3]]);

            let tcp_header_length =
                ((available[12] >> 4) as usize).checked_mul(4)?;

            if tcp_header_length < 20 || tcp_header_length > available.len() {
                return None;
            }

            Some(TransportPayload {
                protocol: Protocol::Tcp,
                source_port,
                destination_port,
                bytes: available[tcp_header_length..].to_vec(),
            })
        }

        // UDP
        17 => {
            if available.len() < 8 {
                return None;
            }

            let source_port =
                u16::from_be_bytes([available[0], available[1]]);
            let destination_port =
                u16::from_be_bytes([available[2], available[3]]);
            let udp_length =
                u16::from_be_bytes([available[4], available[5]]) as usize;

            if udp_length < 8 || udp_length > available.len() {
                return None;
            }

            Some(TransportPayload {
                protocol: Protocol::Udp,
                source_port,
                destination_port,
                bytes: available[8..udp_length].to_vec(),
            })
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_frame(protocol: u8, transport: &[u8]) -> Vec<u8> {
        let total_length = 20 + transport.len();
        let mut frame = vec![0u8; 14];

        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(total_length as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&[192, 168, 1, 10]);
        ip[16..20].copy_from_slice(&[192, 168, 1, 20]);

        frame.extend_from_slice(&ip);
        frame.extend_from_slice(transport);
        frame
    }

    #[test]
    fn extracts_tcp_payload() {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&50000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&443u16.to_be_bytes());
        tcp[12] = 0x50;
        tcp.extend_from_slice(b"HELLO");

        let frame = ipv4_frame(6, &tcp);
        let result = extract_transport_payload(&frame).unwrap();

        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.source_port, 50000);
        assert_eq!(result.destination_port, 443);
        assert_eq!(result.bytes, b"HELLO");
    }

    #[test]
    fn extracts_udp_payload() {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&53000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp[4..6].copy_from_slice(&11u16.to_be_bytes());
        udp.extend_from_slice(b"DNS");

        let frame = ipv4_frame(17, &udp);
        let result = extract_transport_payload(&frame).unwrap();

        assert_eq!(result.protocol, Protocol::Udp);
        assert_eq!(result.source_port, 53000);
        assert_eq!(result.destination_port, 53);
        assert_eq!(result.bytes, b"DNS");
    }

    #[test]
    fn rejects_non_initial_ipv4_fragment() {
        let mut udp = vec![0u8; 8];
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());

        let mut frame = ipv4_frame(17, &udp);
        frame[14 + 6..14 + 8].copy_from_slice(&1u16.to_be_bytes());

        assert!(extract_transport_payload(&frame).is_none());
    }

    #[test]
    fn rejects_truncated_tcp_header() {
        let frame = ipv4_frame(6, &[0u8; 10]);
        assert!(extract_transport_payload(&frame).is_none());
    }

    #[test]
    fn rejects_unknown_ethertype() {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert!(extract_transport_payload(&frame).is_none());
    }
}
