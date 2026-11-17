use std::io::{self, Read};

use crate::PcapPacket;
use crate::pcap::parse_ethernet;

const SECTION_HEADER_BLOCK: u32 = 0x0A0D0D0A;
const INTERFACE_DESCRIPTION_BLOCK: u32 = 0x00000001;
const ENHANCED_PACKET_BLOCK: u32 = 0x00000006;

const BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D;
const LINKTYPE_ETHERNET: u16 = 1;
const MAX_BLOCK_SIZE: u32 = 64 * 1024 * 1024;
const MAX_PACKET_SIZE: u32 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy)]
struct Interface {
    link_type: u16,
    snaplen: u32,
    timestamp_base: u8,
    timestamp_exponent: u8,
    timestamp_offset_seconds: i64,
}

#[derive(Debug)]
pub enum PcapNgError {
    Io(io::Error),
    InvalidSectionHeader,
    UnsupportedVersion(u16, u16),
    InvalidBlockLength(u32),
    InvalidBlockTrailer,
    InvalidByteOrder,
    InvalidInterface,
    UnsupportedLinkType(u16),
    InvalidPacketLength,
    PacketTooLarge(u32),
    InvalidTimestampResolution,
    TimestampOverflow,
}

impl std::fmt::Display for PcapNgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "Error leyendo PCAPNG: {error}"),
            Self::InvalidSectionHeader => write!(f, "Cabecera de sección PCAPNG inválida"),
            Self::UnsupportedVersion(major, minor) => {
                write!(f, "Versión PCAPNG no compatible: {major}.{minor}")
            }
            Self::InvalidBlockLength(length) => {
                write!(f, "Longitud de bloque PCAPNG inválida: {length}")
            }
            Self::InvalidBlockTrailer => {
                write!(f, "La longitud final del bloque no coincide")
            }
            Self::InvalidByteOrder => write!(f, "Orden de bytes PCAPNG inválido"),
            Self::InvalidInterface => write!(f, "Interfaz PCAPNG inválida"),
            Self::UnsupportedLinkType(link) => {
                write!(f, "Tipo de enlace PCAPNG no compatible: {link}")
            }
            Self::InvalidPacketLength => {
                write!(f, "Longitud de paquete PCAPNG inválida")
            }
            Self::PacketTooLarge(size) => {
                write!(f, "Paquete PCAPNG demasiado grande: {size} bytes")
            }
            Self::InvalidTimestampResolution => {
                write!(f, "Resolución temporal PCAPNG inválida")
            }
            Self::TimestampOverflow => {
                write!(f, "El timestamp PCAPNG excede el rango admitido")
            }
        }
    }
}

impl std::error::Error for PcapNgError {}

impl From<io::Error> for PcapNgError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct PcapNgReader<R: Read> {
    reader: R,
    byte_order: Option<ByteOrder>,
    interfaces: Vec<Interface>,
    packet_number: u64,
}

impl<R: Read> PcapNgReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            byte_order: None,
            interfaces: Vec::new(),
            packet_number: 0,
        }
    }

    /// Lee el siguiente Enhanced Packet Block.
    /// Los bloques de metadatos se procesan internamente.
    /// Devuelve None al alcanzar el final del archivo.
    pub fn next_packet(&mut self) -> Result<Option<PcapPacket>, PcapNgError> {
        loop {
            let mut first = [0u8; 4];

            let read = loop {
                match self.reader.read(&mut first) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => break result?,
                }
            };

            if read == 0 {
                return Ok(None);
            }

            if read != 4 {
                return Err(PcapNgError::InvalidBlockLength(0));
            }

            let block_type = u32::from_le_bytes(first);

            if block_type == SECTION_HEADER_BLOCK {
                self.read_section()?;
                continue;
            }

            let order = self.byte_order.ok_or(PcapNgError::InvalidSectionHeader)?;

            let mut length_bytes = [0u8; 4];
            self.reader.read_exact(&mut length_bytes)?;

            let block_length = read_u32(&length_bytes, order);

            let body_length = validate_block_length(block_length)?;

            let mut body = vec![0u8; body_length];
            self.reader.read_exact(&mut body)?;

            let trailer = read_u32(&body[body.len() - 4..], order);

            if trailer != block_length {
                return Err(PcapNgError::InvalidBlockTrailer);
            }

            match block_type {
                INTERFACE_DESCRIPTION_BLOCK => {
                    self.read_interface(&body, order)?;
                }

                ENHANCED_PACKET_BLOCK => {
                    if let Some(packet) = self.read_enhanced_packet(&body, order)? {
                        return Ok(Some(packet));
                    }
                }

                // Los demás bloques se ignoran sin detener la lectura.
                _ => {}
            }
        }
    }

    fn read_section(&mut self) -> Result<(), PcapNgError> {
        let mut initial = [0u8; 8];

        // Después del tipo de bloque vienen:
        // longitud inicial y magic de orden de bytes.
        self.reader.read_exact(&mut initial)?;

        let magic = u32::from_be_bytes([initial[4], initial[5], initial[6], initial[7]]);

        let order = match magic {
            BYTE_ORDER_MAGIC => ByteOrder::Big,
            0x4D3C2B1A => ByteOrder::Little,
            _ => return Err(PcapNgError::InvalidByteOrder),
        };

        let block_length = read_u32(&initial[0..4], order);

        if block_length < 28 || block_length > MAX_BLOCK_SIZE {
            return Err(PcapNgError::InvalidBlockLength(block_length));
        }

        let remaining_length = block_length as usize - 12;
        let mut remaining = vec![0u8; remaining_length];

        self.reader.read_exact(&mut remaining)?;

        let trailer = read_u32(&remaining[remaining.len() - 4..], order);

        if trailer != block_length {
            return Err(PcapNgError::InvalidBlockTrailer);
        }

        let major = read_u16(&remaining[0..2], order);
        let minor = read_u16(&remaining[2..4], order);

        if major != 1 || minor != 0 {
            return Err(PcapNgError::UnsupportedVersion(major, minor));
        }

        self.byte_order = Some(order);
        self.interfaces.clear();

        Ok(())
    }

    fn read_interface(&mut self, body: &[u8], order: ByteOrder) -> Result<(), PcapNgError> {
        if body.len() < 12 {
            return Err(PcapNgError::InvalidInterface);
        }

        let link_type = read_u16(&body[0..2], order);
        let snaplen = read_u32(&body[4..8], order);

        if link_type != LINKTYPE_ETHERNET {
            return Err(PcapNgError::UnsupportedLinkType(link_type));
        }

        if snaplen == 0 {
            return Err(PcapNgError::InvalidInterface);
        }

        let mut interface = Interface {
            link_type,
            snaplen,
            timestamp_base: 10,
            timestamp_exponent: 6,
            timestamp_offset_seconds: 0,
        };

        let options_end = body.len() - 4;
        let mut offset = 8;

        while offset + 4 <= options_end {
            let code = read_u16(&body[offset..offset + 2], order);
            let length = read_u16(&body[offset + 2..offset + 4], order) as usize;
            offset += 4;

            if code == 0 {
                break;
            }

            let padded_length = (length + 3) & !3;

            if offset + padded_length > options_end {
                return Err(PcapNgError::InvalidInterface);
            }

            let value = &body[offset..offset + length];

            match code {
                // if_tsresol
                9 => {
                    if value.len() != 1 {
                        return Err(PcapNgError::InvalidTimestampResolution);
                    }

                    let resolution = value[0];

                    if resolution & 0x80 == 0 {
                        interface.timestamp_base = 10;
                        interface.timestamp_exponent = resolution;
                    } else {
                        interface.timestamp_base = 2;
                        interface.timestamp_exponent = resolution & 0x7f;
                    }
                }

                // if_tsoffset
                14 => {
                    if value.len() != 8 {
                        return Err(PcapNgError::InvalidInterface);
                    }

                    interface.timestamp_offset_seconds = read_i64(value, order);
                }

                _ => {}
            }

            offset += padded_length;
        }

        self.interfaces.push(interface);

        Ok(())
    }

    fn read_enhanced_packet(
        &mut self,
        body: &[u8],
        order: ByteOrder,
    ) -> Result<Option<PcapPacket>, PcapNgError> {
        if body.len() < 24 {
            return Err(PcapNgError::InvalidPacketLength);
        }

        let interface_id = read_u32(&body[0..4], order) as usize;

        let interface = *self
            .interfaces
            .get(interface_id)
            .ok_or(PcapNgError::InvalidInterface)?;

        let timestamp_high = read_u32(&body[4..8], order);
        let timestamp_low = read_u32(&body[8..12], order);

        let captured_len = read_u32(&body[12..16], order);
        let original_len = read_u32(&body[16..20], order);

        if captured_len > MAX_PACKET_SIZE {
            return Err(PcapNgError::PacketTooLarge(captured_len));
        }

        if captured_len > interface.snaplen || original_len < captured_len {
            return Err(PcapNgError::InvalidPacketLength);
        }

        let padded_length = (captured_len as usize + 3) & !3;
        let data_end = 20usize
            .checked_add(padded_length)
            .ok_or(PcapNgError::InvalidPacketLength)?;

        if data_end > body.len() - 4 {
            return Err(PcapNgError::InvalidPacketLength);
        }

        let frame = &body[20..20 + captured_len as usize];

        if interface.link_type != LINKTYPE_ETHERNET {
            return Err(PcapNgError::UnsupportedLinkType(interface.link_type));
        }

        let timestamp_ticks = ((timestamp_high as u64) << 32) | timestamp_low as u64;

        let timestamp_unix_ns = convert_timestamp(timestamp_ticks, interface)?;

        self.packet_number = self
            .packet_number
            .checked_add(1)
            .ok_or(PcapNgError::TimestampOverflow)?;

        Ok(Some(PcapPacket {
            number: self.packet_number,
            timestamp_unix_ns,
            captured_len,
            original_len,
            ethernet: parse_ethernet(frame),
            raw_frame: frame.to_vec(),
        }))
    }
}

#[cfg(test)]
pub(crate) fn sample_capture_for_tests() -> Vec<u8> {
    tests::sample_pcapng()
}

fn validate_block_length(length: u32) -> Result<usize, PcapNgError> {
    if length < 12 || length > MAX_BLOCK_SIZE || length % 4 != 0 {
        return Err(PcapNgError::InvalidBlockLength(length));
    }

    Ok(length as usize - 8)
}

fn convert_timestamp(ticks: u64, interface: Interface) -> Result<i64, PcapNgError> {
    let exponent = interface.timestamp_exponent as u32;

    let denominator = match interface.timestamp_base {
        10 => 10u128.checked_pow(exponent),
        2 => 2u128.checked_pow(exponent),
        _ => None,
    }
    .ok_or(PcapNgError::InvalidTimestampResolution)?;

    let nanos = (ticks as u128)
        .checked_mul(1_000_000_000)
        .ok_or(PcapNgError::TimestampOverflow)?
        / denominator;

    let offset = (interface.timestamp_offset_seconds as i128)
        .checked_mul(1_000_000_000)
        .ok_or(PcapNgError::TimestampOverflow)?;

    let result = (nanos as i128)
        .checked_add(offset)
        .ok_or(PcapNgError::TimestampOverflow)?;

    i64::try_from(result).map_err(|_| PcapNgError::TimestampOverflow)
}

fn read_u16(bytes: &[u8], order: ByteOrder) -> u16 {
    let bytes = [bytes[0], bytes[1]];

    match order {
        ByteOrder::Little => u16::from_le_bytes(bytes),
        ByteOrder::Big => u16::from_be_bytes(bytes),
    }
}

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];

    match order {
        ByteOrder::Little => u32::from_le_bytes(bytes),
        ByteOrder::Big => u32::from_be_bytes(bytes),
    }
}

fn read_i64(bytes: &[u8], order: ByteOrder) -> i64 {
    let bytes = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ];

    match order {
        ByteOrder::Little => i64::from_le_bytes(bytes),
        ByteOrder::Big => i64::from_be_bytes(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn append_block(data: &mut Vec<u8>, block_type: u32, body: &[u8]) {
        let total_length = (body.len() + 12) as u32;

        data.extend_from_slice(&block_type.to_le_bytes());
        data.extend_from_slice(&total_length.to_le_bytes());
        data.extend_from_slice(body);
        data.extend_from_slice(&total_length.to_le_bytes());
    }

    pub(super) fn sample_pcapng() -> Vec<u8> {
        let mut data = Vec::new();

        // Section Header Block.
        data.extend_from_slice(&SECTION_HEADER_BLOCK.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&(-1i64).to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());

        // Interface Description Block: Ethernet, snaplen 65535.
        let mut interface = Vec::new();
        interface.extend_from_slice(&1u16.to_le_bytes());
        interface.extend_from_slice(&0u16.to_le_bytes());
        interface.extend_from_slice(&65535u32.to_le_bytes());
        append_block(&mut data, INTERFACE_DESCRIPTION_BLOCK, &interface);

        // Ethernet + IPv4 + TCP.
        let frame = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6,
            0, 0, 192, 168, 1, 10, 1, 1, 1, 1, 0xc3, 0x50, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0,
            0x50, 0x02, 0x20, 0, 0, 0, 0, 0,
        ];

        // Enhanced Packet Block.
        let mut packet = Vec::new();
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet.extend_from_slice(&1_500_000u32.to_le_bytes());
        packet.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        packet.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        packet.extend_from_slice(&frame);

        while packet.len() % 4 != 0 {
            packet.push(0);
        }

        append_block(&mut data, ENHANCED_PACKET_BLOCK, &packet);

        data
    }

    #[test]
    fn reads_section_interface_and_enhanced_packet() {
        let mut reader = PcapNgReader::new(Cursor::new(sample_pcapng()));

        let packet = reader.next_packet().unwrap().unwrap();

        assert_eq!(packet.number, 1);
        assert_eq!(packet.timestamp_unix_ns, 1_500_000_000);
        assert_eq!(packet.captured_len, 54);
        assert_eq!(packet.original_len, 54);

        let network = packet.ethernet.unwrap().network.unwrap();

        assert_eq!(network.protocol, crate::Protocol::Tcp);
        assert_eq!(network.source_port, Some(50000));
        assert_eq!(network.destination_port, Some(443));

        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn rejects_invalid_section_header() {
        let data = [0u8; 20];
        let mut reader = PcapNgReader::new(Cursor::new(data));

        assert!(reader.next_packet().is_err());
    }

    #[test]
    fn rejects_packet_without_interface() {
        let mut data = Vec::new();

        // Sección válida.
        data.extend_from_slice(&SECTION_HEADER_BLOCK.to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());
        data.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&(-1i64).to_le_bytes());
        data.extend_from_slice(&28u32.to_le_bytes());

        let mut packet = Vec::new();
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet.extend_from_slice(&0u32.to_le_bytes());
        packet.extend_from_slice(&0u32.to_le_bytes());

        append_block(&mut data, ENHANCED_PACKET_BLOCK, &packet);

        let mut reader = PcapNgReader::new(Cursor::new(data));

        assert!(matches!(
            reader.next_packet(),
            Err(PcapNgError::InvalidInterface)
        ));
    }
}
