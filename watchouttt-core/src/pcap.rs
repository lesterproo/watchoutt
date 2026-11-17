use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::tcp_reassembly::TcpFlags;
use crate::Protocol;

const PCAP_GLOBAL_HEADER_SIZE: usize = 24;
const PCAP_PACKET_HEADER_SIZE: usize = 16;
const MAX_PACKET_SIZE: u32 = 16 * 1024 * 1024;
const LINKTYPE_ETHERNET: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapTimestampResolution {
    Microseconds,
    Nanoseconds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub link_type: u32,
    pub timestamp_resolution: PcapTimestampResolution,
}

#[derive(Debug)]
pub enum PcapError {
    Io(io::Error),
    InvalidMagic,
    UnsupportedVersion(u16, u16),
    InvalidSnaplen,
    UnsupportedLinkType(u32),
    InvalidTimestampFraction(u32),
    InvalidPacketLengths {
        captured: u32,
        original: u32,
        snaplen: u32,
    },
    PacketTooLarge(u32),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Error leyendo PCAP: {error}"),
            Self::InvalidMagic => write!(f, "Firma PCAP no reconocida"),
            Self::UnsupportedVersion(major, minor) => {
                write!(f, "Versión PCAP no compatible: {major}.{minor}")
            }
            Self::InvalidSnaplen => write!(f, "El tamaño máximo de captura es inválido"),
            Self::UnsupportedLinkType(link) => {
                write!(f, "Tipo de enlace no compatible: {link}")
            }
            Self::InvalidTimestampFraction(value) => {
                write!(f, "Fracción de tiempo inválida: {value}")
            }
            Self::InvalidPacketLengths {
                captured,
                original,
                snaplen,
            } => write!(
                f,
                "Longitudes de paquete inválidas: capturado={captured}, original={original}, snaplen={snaplen}"
            ),
            Self::PacketTooLarge(size) => {
                write!(f, "Paquete demasiado grande: {size} bytes")
            }
        }
    }
}

impl std::error::Error for PcapError {}

impl From<io::Error> for PcapError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetInfo {
    pub source_mac: String,
    pub destination_mac: String,
    pub ether_type: u16,
    pub vlan_ids: Vec<u16>,
    pub network: Option<NetworkInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpMetadata {
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkInfo {
    pub ip_version: u8,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub protocol: Protocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    /// Poblado solo para TCP.
    pub tcp: Option<TcpMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapPacket {
    pub number: u64,
    pub timestamp_unix_ns: i64,
    pub captured_len: u32,
    pub original_len: u32,
    pub ethernet: Option<EthernetInfo>,
    pub raw_frame: Vec<u8>,
}

pub struct PcapReader<R: Read> {
    reader: R,
    header: PcapHeader,
    byte_order: ByteOrder,
    packet_number: u64,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut reader: R) -> Result<Self, PcapError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;

        let (byte_order, resolution) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (
                ByteOrder::Little,
                PcapTimestampResolution::Microseconds,
            ),
            [0xa1, 0xb2, 0xc3, 0xd4] => (
                ByteOrder::Big,
                PcapTimestampResolution::Microseconds,
            ),
            [0x4d, 0x3c, 0xb2, 0xa1] => (
                ByteOrder::Little,
                PcapTimestampResolution::Nanoseconds,
            ),
            [0xa1, 0xb2, 0x3c, 0x4d] => (
                ByteOrder::Big,
                PcapTimestampResolution::Nanoseconds,
            ),
            _ => return Err(PcapError::InvalidMagic),
        };

        let mut rest = [0u8; PCAP_GLOBAL_HEADER_SIZE - 4];
        reader.read_exact(&mut rest)?;

        let major = read_u16(&rest[0..2], byte_order);
        let minor = read_u16(&rest[2..4], byte_order);
        let snaplen = read_u32(&rest[12..16], byte_order);
        let link_type = read_u32(&rest[16..20], byte_order);

        if major != 2 || minor != 4 {
            return Err(PcapError::UnsupportedVersion(major, minor));
        }

        if snaplen == 0 {
            return Err(PcapError::InvalidSnaplen);
        }

        if link_type != LINKTYPE_ETHERNET {
            return Err(PcapError::UnsupportedLinkType(link_type));
        }

        Ok(Self {
            reader,
            header: PcapHeader {
                version_major: major,
                version_minor: minor,
                snaplen,
                link_type,
                timestamp_resolution: resolution,
            },
            byte_order,
            packet_number: 0,
        })
    }

    pub fn header(&self) -> &PcapHeader {
        &self.header
    }

    pub fn next_packet(&mut self) -> Result<Option<PcapPacket>, PcapError> {
        let mut packet_header = [0u8; PCAP_PACKET_HEADER_SIZE];

        let first_byte = loop {
            match self.reader.read(&mut packet_header[0..1]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };

        if first_byte == 0 {
            return Ok(None);
        }

        self.reader.read_exact(&mut packet_header[1..])?;

        let seconds = read_u32(&packet_header[0..4], self.byte_order);
        let fraction = read_u32(&packet_header[4..8], self.byte_order);
        let captured_len = read_u32(&packet_header[8..12], self.byte_order);
        let original_len = read_u32(&packet_header[12..16], self.byte_order);

        let fraction_limit = match self.header.timestamp_resolution {
            PcapTimestampResolution::Microseconds => 1_000_000,
            PcapTimestampResolution::Nanoseconds => 1_000_000_000,
        };

        if fraction >= fraction_limit {
            return Err(PcapError::InvalidTimestampFraction(fraction));
        }

        if captured_len > self.header.snaplen || original_len < captured_len {
            return Err(PcapError::InvalidPacketLengths {
                captured: captured_len,
                original: original_len,
                snaplen: self.header.snaplen,
            });
        }

        if captured_len > MAX_PACKET_SIZE {
            return Err(PcapError::PacketTooLarge(captured_len));
        }

        let fraction_ns = match self.header.timestamp_resolution {
            PcapTimestampResolution::Microseconds => fraction as i64 * 1_000,
            PcapTimestampResolution::Nanoseconds => fraction as i64,
        };

        let timestamp_unix_ns = seconds as i64 * 1_000_000_000 + fraction_ns;

        let mut frame = vec![0u8; captured_len as usize];
        self.reader.read_exact(&mut frame)?;

        self.packet_number += 1;

        Ok(Some(PcapPacket {
            number: self.packet_number,
            timestamp_unix_ns,
            captured_len,
            original_len,
            ethernet: parse_ethernet(&frame),
            raw_frame: frame,
        }))
    }
}

fn read_u16(bytes: &[u8], order: ByteOrder) -> u16 {
    let pair = [bytes[0], bytes[1]];
    match order {
        ByteOrder::Little => u16::from_le_bytes(pair),
        ByteOrder::Big => u16::from_be_bytes(pair),
    }
}

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    let array = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match order {
        ByteOrder::Little => u32::from_le_bytes(array),
        ByteOrder::Big => u32::from_be_bytes(array),
    }
}

fn format_mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(crate) fn parse_ethernet(frame: &[u8]) -> Option<EthernetInfo> {
    if frame.len() < 14 {
        return None;
    }

    let destination_mac = format_mac(&frame[0..6]);
    let source_mac = format_mac(&frame[6..12]);

    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14;
    let mut vlan_ids = Vec::new();

    for _ in 0..4 {
        if !matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if frame.len() < offset + 4 {
            break;
        }
        let tag_control = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        vlan_ids.push(tag_control & 0x0fff);
        ether_type = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }

    let network = match ether_type {
        0x0800 => parse_ipv4(frame, offset),
        0x86dd => parse_ipv6(frame, offset),
        _ => None,
    };

    Some(EthernetInfo {
        source_mac,
        destination_mac,
        ether_type,
        vlan_ids,
        network,
    })
}

fn parse_ipv4(frame: &[u8], offset: usize) -> Option<NetworkInfo> {
    if frame.len() < offset + 20 {
        return None;
    }

    let first = frame[offset];
    if first >> 4 != 4 {
        return None;
    }

    let header_length = ((first & 0x0f) as usize) * 4;
    if header_length < 20 || frame.len() < offset + header_length {
        return None;
    }

    let total_length = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]) as usize;
    if total_length < header_length {
        return None;
    }

    let packet_end = offset.saturating_add(total_length).min(frame.len());
    let protocol_number = frame[offset + 9];

    let fragment_field = u16::from_be_bytes([frame[offset + 6], frame[offset + 7]]);
    let fragment_offset = fragment_field & 0x1fff;

    let source_ip = IpAddr::V4(Ipv4Addr::new(
        frame[offset + 12],
        frame[offset + 13],
        frame[offset + 14],
        frame[offset + 15],
    ));
    let destination_ip = IpAddr::V4(Ipv4Addr::new(
        frame[offset + 16],
        frame[offset + 17],
        frame[offset + 18],
        frame[offset + 19],
    ));

    let protocol = match protocol_number {
        1 => Protocol::Icmp,
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        58 => Protocol::IcmpV6,
        value => Protocol::Other(format!("IPv4 protocol {value}")),
    };

    let transport_offset = offset + header_length;
    let (source_port, destination_port, tcp) = if fragment_offset == 0 {
        let (sp, dp) = parse_ports(frame, transport_offset, packet_end, protocol_number);
        let tcp = if protocol_number == 6 {
            parse_tcp_metadata(frame, transport_offset, packet_end)
        } else {
            None
        };
        (sp, dp, tcp)
    } else {
        (None, None, None)
    };

    Some(NetworkInfo {
        ip_version: 4,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        tcp,
    })
}

fn parse_ipv6(frame: &[u8], offset: usize) -> Option<NetworkInfo> {
    if frame.len() < offset + 40 || frame[offset] >> 4 != 6 {
        return None;
    }

    let payload_length = u16::from_be_bytes([frame[offset + 4], frame[offset + 5]]) as usize;
    let packet_end = offset
        .saturating_add(40)
        .saturating_add(payload_length)
        .min(frame.len());

    let next_header = frame[offset + 6];

    let mut source_bytes = [0u8; 16];
    source_bytes.copy_from_slice(&frame[offset + 8..offset + 24]);
    let mut destination_bytes = [0u8; 16];
    destination_bytes.copy_from_slice(&frame[offset + 24..offset + 40]);

    let source_ip = IpAddr::V6(Ipv6Addr::from(source_bytes));
    let destination_ip = IpAddr::V6(Ipv6Addr::from(destination_bytes));

    let protocol = match next_header {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        58 => Protocol::IcmpV6,
        value => Protocol::Other(format!("IPv6 next header {value}")),
    };

    let transport_offset = offset + 40;
    let (source_port, destination_port) =
        parse_ports(frame, transport_offset, packet_end, next_header);
    let tcp = if next_header == 6 {
        parse_tcp_metadata(frame, transport_offset, packet_end)
    } else {
        None
    };

    Some(NetworkInfo {
        ip_version: 6,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        tcp,
    })
}

fn parse_ports(
    frame: &[u8],
    offset: usize,
    packet_end: usize,
    protocol_number: u8,
) -> (Option<u16>, Option<u16>) {
    if !matches!(protocol_number, 6 | 17) {
        return (None, None);
    }
    if packet_end < offset + 4 {
        return (None, None);
    }

    let source = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    let destination = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);

    (Some(source), Some(destination))
}

fn parse_tcp_metadata(
    frame: &[u8],
    offset: usize,
    packet_end: usize,
) -> Option<TcpMetadata> {
    if packet_end < offset + 20 {
        return None;
    }
    let seq = u32::from_be_bytes([
        frame[offset + 4],
        frame[offset + 5],
        frame[offset + 6],
        frame[offset + 7],
    ]);
    let ack = u32::from_be_bytes([
        frame[offset + 8],
        frame[offset + 9],
        frame[offset + 10],
        frame[offset + 11],
    ]);
    let flags_byte = frame[offset + 13];
    Some(TcpMetadata {
        seq,
        ack,
        flags: TcpFlags::from_byte(flags_byte),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0, 1, 2, 3, 4, 5]);
        frame.extend_from_slice(&[6, 7, 8, 9, 10, 11]);
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&[
            0x45, 0x00, 0x00, 0x28,
            0x00, 0x01, 0x40, 0x00,
            64, 6, 0, 0,
            192, 168, 1, 10,
            1, 1, 1, 1,
        ]);
        frame.extend_from_slice(&[
            0xc3, 0x50, 0x01, 0xbb,
            0, 0, 0, 1,
            0, 0, 0, 0,
            0x50, 0x02, 0x20, 0,
            0, 0, 0, 0,
        ]);
        frame
    }

    fn sample_pcap() -> Vec<u8> {
        let frame = sample_frame();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        bytes.extend_from_slice(&2u16.to_le_bytes());
        bytes.extend_from_slice(&4u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&65535u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&500_000u32.to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&frame);
        bytes
    }

    #[test]
    fn reads_pcap_header_and_packet() {
        let data = sample_pcap();
        let mut reader = PcapReader::new(Cursor::new(data)).unwrap();
        assert_eq!(reader.header().version_major, 2);
        assert_eq!(reader.header().version_minor, 4);
        assert_eq!(reader.header().link_type, LINKTYPE_ETHERNET);
        let packet = reader.next_packet().unwrap().unwrap();
        assert_eq!(packet.number, 1);
        assert_eq!(packet.timestamp_unix_ns, 1_500_000_000);
        assert_eq!(packet.captured_len, 54);
        assert_eq!(packet.original_len, 54);
        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn extracts_ethernet_ipv4_and_tcp_information() {
        let mut reader = PcapReader::new(Cursor::new(sample_pcap())).unwrap();
        let packet = reader.next_packet().unwrap().unwrap();
        let ethernet = packet.ethernet.unwrap();
        assert_eq!(ethernet.source_mac, "06:07:08:09:0a:0b");
        assert_eq!(ethernet.destination_mac, "00:01:02:03:04:05");
        assert_eq!(ethernet.ether_type, 0x0800);
        let network = ethernet.network.unwrap();
        assert_eq!(network.ip_version, 4);
        assert_eq!(network.source_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        assert_eq!(network.destination_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(network.protocol, Protocol::Tcp);
        assert_eq!(network.source_port, Some(50000));
        assert_eq!(network.destination_port, Some(443));
        let tcp = network.tcp.expect("TCP metadata");
        assert_eq!(tcp.seq, 1);
        assert!(tcp.flags.syn);
    }

    #[test]
    fn rejects_unsupported_link_type() {
        let mut data = sample_pcap();
        data[20..24].copy_from_slice(&113u32.to_le_bytes());
        let result = PcapReader::new(Cursor::new(data));
        assert!(matches!(result, Err(PcapError::UnsupportedLinkType(113))));
    }

    #[test]
    fn rejects_invalid_timestamp_fraction() {
        let mut data = sample_pcap();
        data[28..32].copy_from_slice(&1_000_000u32.to_le_bytes());
        let mut reader = PcapReader::new(Cursor::new(data)).unwrap();
        assert!(matches!(
            reader.next_packet(),
            Err(PcapError::InvalidTimestampFraction(1_000_000))
        ));
    }
}