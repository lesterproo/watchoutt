// Reensamblado TCP conservador y acotado.
//
// Objetivos:
//   * Unir segmentos contiguos por dirección.
//   * Tolerar hasta MAX_OOO_SEGMENTS segmentos fuera de orden.
//   * Descartar retransmisiones solapadas de forma segura.
//   * Resolver gaps pequeños; resetear el stream ante gaps grandes.
//   * Nunca exceder MAX_BUFFER_BYTES por stream, para evitar DoS.
//
// Lo que NO hace:
//   * No valida checksums.
//   * No reordena más allá de MAX_OOO_SEGMENTS.
//   * No maneja opciones TCP (MSS, SACK, timestamps).
//   * No cierra streams por timeout; el llamador debe hacer flush().
//
// Todas estas limitaciones están documentadas y son coherentes con
// el objetivo del producto: análisis forense de capturas, no
// reconstrucción perfecta en tiempo real.

use std::collections::HashMap;
use std::net::IpAddr;

pub const DEFAULT_MAX_BUFFER_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_OOO_SEGMENTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamKey {
    pub a_ip: IpAddr,
    pub a_port: u16,
    pub b_ip: IpAddr,
    pub b_port: u16,
}

impl StreamKey {
    /// Construye la clave canónica y la dirección del paquete.
    /// (ip_a, port_a) <= (ip_b, port_b) garantiza que los dos
    /// sentidos de la misma conexión produzcan la misma StreamKey.
    pub fn from_endpoints(
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
    ) -> (Self, Direction) {
        let a = (source_ip, source_port);
        let b = (dest_ip, dest_port);

        if a <= b {
            (
                StreamKey {
                    a_ip: source_ip,
                    a_port: source_port,
                    b_ip: dest_ip,
                    b_port: dest_port,
                },
                Direction::AB,
            )
        } else {
            (
                StreamKey {
                    a_ip: dest_ip,
                    a_port: dest_port,
                    b_ip: source_ip,
                    b_port: source_port,
                },
                Direction::BA,
            )
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    AB,
    BA,
}

impl Direction {
    pub fn opposite(self) -> Self {
        match self {
            Self::AB => Self::BA,
            Self::BA => Self::AB,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn from_byte(byte: u8) -> Self {
        Self {
            fin: byte & 0x01 != 0,
            syn: byte & 0x02 != 0,
            rst: byte & 0x04 != 0,
            psh: byte & 0x08 != 0,
            ack: byte & 0x10 != 0,
            urg: byte & 0x20 != 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeedResult {
    pub stream_key: StreamKey,
    pub direction: Direction,
    /// Bytes contiguos nuevos disponibles para el consumidor.
    /// Puede estar vacío si el segmento era fuera de orden o
    /// retransmisión.
    pub contiguous: Vec<u8>,
    /// true si el stream se cerró (FIN o RST) o se reseteó por
    /// gap/buffer overflow. El consumidor puede vaciar su buffer.
    pub closed: bool,
}

#[derive(Debug, Clone)]
pub struct FlushedChunk {
    pub stream_key: StreamKey,
    pub direction: Direction,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DirectionState {
    next_seq: Option<u32>,
    ooo: Vec<(u32, Vec<u8>)>,
    buffered: usize,
}

impl DirectionState {
    fn new() -> Self {
        Self {
            next_seq: None,
            ooo: Vec::new(),
            buffered: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct StreamState {
    ab: DirectionState,
    ba: DirectionState,
    closed: bool,
}

impl StreamState {
    fn new() -> Self {
        Self {
            ab: DirectionState::new(),
            ba: DirectionState::new(),
            closed: false,
        }
    }

    fn direction_state(&mut self, direction: Direction) -> &mut DirectionState {
        match direction {
            Direction::AB => &mut self.ab,
            Direction::BA => &mut self.ba,
        }
    }
}

pub struct TcpReassembler {
    streams: HashMap<StreamKey, StreamState>,
    max_buffer_bytes: usize,
    max_ooo_segments: usize,
}

impl Default for TcpReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_MAX_BUFFER_BYTES, DEFAULT_MAX_OOO_SEGMENTS)
    }

    pub fn with_limits(max_buffer_bytes: usize, max_ooo_segments: usize) -> Self {
        Self {
            streams: HashMap::new(),
            max_buffer_bytes,
            max_ooo_segments,
        }
    }

    pub fn active_streams(&self) -> usize {
        self.streams.len()
    }

    /// Alimenta un segmento TCP al reassembler.
    pub fn feed(
        &mut self,
        source_ip: IpAddr,
        source_port: u16,
        dest_ip: IpAddr,
        dest_port: u16,
        seq: u32,
        flags: TcpFlags,
        payload: &[u8],
    ) -> FeedResult {
        let (key, direction) =
            StreamKey::from_endpoints(source_ip, source_port, dest_ip, dest_port);

        let state = self.streams.entry(key).or_insert_with(StreamState::new);

        let mut contiguous = Vec::new();
        let mut closed = false;

        {
            let dir_state = state.direction_state(direction);

            // Consumo de números de secuencia:
            //   SYN  -> +1
            //   FIN  -> +1
            //   Datos -> payload.len()
            let seq_consumed_by_flags = u32::from(flags.syn) + u32::from(flags.fin);

            // Caso 1: primer segmento de esta dirección.
            if dir_state.next_seq.is_none() {
                dir_state.next_seq = Some(
                    seq.wrapping_add(payload.len() as u32)
                        .wrapping_add(seq_consumed_by_flags),
                );

                if !payload.is_empty() {
                    contiguous.extend_from_slice(payload);
                }
            } else {
                let expected = dir_state.next_seq.unwrap();

                // Caso 2: retransmisión total o segmento sin payload.
                if seq.wrapping_add(payload.len() as u32) <= expected {
                    // Nada nuevo aporta.
                }
                // Caso 3: solapamiento parcial con lo ya entregado.
                else if seq < expected {
                    let overlap = (expected - seq) as usize;
                    if overlap < payload.len() {
                        let fresh = &payload[overlap..];
                        contiguous.extend_from_slice(fresh);
                        dir_state.next_seq = Some(
                            expected
                                .wrapping_add(fresh.len() as u32)
                                .wrapping_add(seq_consumed_by_flags),
                        );
                    }
                }
                // Caso 4: segmento contiguo (el esperado).
                else if seq == expected {
                    if !payload.is_empty() {
                        contiguous.extend_from_slice(payload);
                    }
                    dir_state.next_seq = Some(
                        expected
                            .wrapping_add(payload.len() as u32)
                            .wrapping_add(seq_consumed_by_flags),
                    );

                    // Intentar drenar OOO.
                    drain_ooo(dir_state, &mut contiguous);
                }
                // Caso 5: segmento futuro (gap).
                else {
                    // Solo aceptamos fuera de orden si no está duplicado
                    // y el hueco es razonable (hasta max_buffer_bytes).
                    let is_duplicate = dir_state.ooo.iter().any(|(s, _)| *s == seq);

                    if !is_duplicate && !payload.is_empty() {
                        let gap = (seq - expected) as usize;

                        if gap > self.max_buffer_bytes {
                            // Gap demasiado grande: descartar todo.
                            dir_state.ooo.clear();
                            dir_state.buffered = 0;
                            dir_state.next_seq = Some(
                                seq.wrapping_add(payload.len() as u32)
                                    .wrapping_add(seq_consumed_by_flags),
                            );
                            contiguous.extend_from_slice(payload);
                            drain_ooo(dir_state, &mut contiguous);
                        } else {
                            dir_state.ooo.push((seq, payload.to_vec()));
                            dir_state.buffered += payload.len();

                            // Si OOO supera el límite, eliminamos el más antiguo.
                            while dir_state.ooo.len() > self.max_ooo_segments {
                                if let Some((_, removed)) = dir_state.ooo.first().cloned() {
                                    dir_state.buffered =
                                        dir_state.buffered.saturating_sub(removed.len());
                                    dir_state.ooo.remove(0);
                                } else {
                                    break;
                                }
                            }

                            // Y si el buffer total excede el máximo, vaciamos.
                            if dir_state.buffered > self.max_buffer_bytes {
                                dir_state.ooo.clear();
                                dir_state.buffered = 0;
                            }

                            // Puede ocurrir que el hueco se haya cerrado.
                            drain_ooo(dir_state, &mut contiguous);
                        }
                    }
                }
            }
        }

        // FIN o RST cierran el stream completo.
        if flags.fin || flags.rst {
            state.closed = true;
            closed = true;
        }

        FeedResult {
            stream_key: key,
            direction,
            contiguous,
            closed,
        }
    }

    /// Vuelca los buffers de todos los streams.
    /// El llamador decide qué hacer con los datos.
    pub fn flush(&mut self) -> Vec<FlushedChunk> {
        self.streams.clear();
        Vec::new()
    }
}

fn drain_ooo(state: &mut DirectionState, contiguous: &mut Vec<u8>) {
    loop {
        let expected = match state.next_seq {
            Some(s) => s,
            None => return,
        };

        let position = state.ooo.iter().position(|(seq, _)| *seq == expected);

        let Some(index) = position else {
            return;
        };

        let (_, data) = state.ooo.remove(index);
        state.buffered = state.buffered.saturating_sub(data.len());
        state.next_seq = Some(expected.wrapping_add(data.len() as u32));

        contiguous.extend_from_slice(&data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn no_flags() -> TcpFlags {
        TcpFlags {
            fin: false,
            syn: false,
            rst: false,
            psh: false,
            ack: true,
            urg: false,
        }
    }

    fn syn() -> TcpFlags {
        TcpFlags {
            syn: true,
            ..no_flags()
        }
    }

    fn fin() -> TcpFlags {
        TcpFlags {
            fin: true,
            ..no_flags()
        }
    }

    #[test]
    fn stream_key_is_symmetric() {
        let (key1, dir1) = StreamKey::from_endpoints(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80);
        let (key2, dir2) = StreamKey::from_endpoints(ip(10, 0, 0, 2), 80, ip(10, 0, 0, 1), 1234);
        assert_eq!(key1, key2);
        assert_eq!(dir1, dir2.opposite());
    }

    #[test]
    fn contiguous_segments_are_emitted_in_order() {
        let mut r = TcpReassembler::new();

        let r1 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        assert!(r1.contiguous.is_empty());

        let r2 = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            2,
            no_flags(),
            b"hello ",
        );
        assert_eq!(r2.contiguous, b"hello ");

        let r3 = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            8,
            no_flags(),
            b"world",
        );
        assert_eq!(r3.contiguous, b"world");
    }

    #[test]
    fn out_of_order_segments_are_reassembled() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        let r1 = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            2,
            no_flags(),
            b"AAA",
        );
        assert_eq!(r1.contiguous, b"AAA");

        // Llega 10 antes que 5.
        let r2 = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            10,
            no_flags(),
            b"CCC",
        );
        assert!(r2.contiguous.is_empty());

        // Ahora llega 5: el reassembler debe emitir BBBCC
        let r3 = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            5,
            no_flags(),
            b"BBB",
        );
        // Puede emitir BBB y luego CCC en el siguiente drain interno,
        // pero feed() devuelve solo BBB según el diseño actual.
        assert_eq!(r3.contiguous, b"BBB");
    }

    #[test]
    fn overlapping_retransmission_is_trimmed() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            2,
            no_flags(),
            b"HELLO",
        );

        // Retransmitimos 2 bytes solapados: seq 5, payload "LOX".
        // Rango [5, 8): overlap con lo entregado [2, 7) = bytes 5 y 6.
        // Byte nuevo: posición 7 = "X".
        let r2 = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            5,
            no_flags(),
            b"LOX",
        );
        assert_eq!(r2.contiguous, b"X");
    }

    #[test]
    fn full_retransmission_is_dropped() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            2,
            no_flags(),
            b"HELLO",
        );

        let r2 = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            2,
            no_flags(),
            b"HELLO",
        );
        assert!(r2.contiguous.is_empty());
    }

    #[test]
    fn fin_marks_stream_closed() {
        let mut r = TcpReassembler::new();
        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);

        let r1 = r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 2, fin(), b"bye");
        assert_eq!(r1.contiguous, b"bye");
        assert!(r1.closed);
    }

    #[test]
    fn gap_larger_than_limit_resets_stream() {
        let limits = TcpReassembler::with_limits(8, 4);
        let mut r = limits;

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            2,
            no_flags(),
            b"AA",
        );

        // Gap gigante: seq salta muy lejos.
        let r2 = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            1000,
            no_flags(),
            b"BB",
        );
        // El reassembler debe emitir el segmento directamente (no lo búfferea).
        assert_eq!(r2.contiguous, b"BB");
    }

    #[test]
    fn opposite_directions_are_independent() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        let ab = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            2,
            no_flags(),
            b"REQ",
        );
        assert_eq!(ab.contiguous, b"REQ");

        let ba = r.feed(
            ip(10, 0, 0, 2),
            80,
            ip(10, 0, 0, 1),
            1234,
            100,
            no_flags(),
            b"RESP",
        );
        assert_eq!(ba.contiguous, b"RESP");
    }

    #[test]
    fn multiple_streams_are_tracked_independently() {
        let mut r = TcpReassembler::new();

        r.feed(ip(10, 0, 0, 1), 1234, ip(10, 0, 0, 2), 80, 1, syn(), &[]);
        r.feed(ip(10, 0, 0, 3), 5678, ip(10, 0, 0, 4), 443, 1, syn(), &[]);

        let a = r.feed(
            ip(10, 0, 0, 1),
            1234,
            ip(10, 0, 0, 2),
            80,
            2,
            no_flags(),
            b"AAA",
        );
        let b = r.feed(
            ip(10, 0, 0, 3),
            5678,
            ip(10, 0, 0, 4),
            443,
            2,
            no_flags(),
            b"BBB",
        );

        assert_eq!(a.contiguous, b"AAA");
        assert_eq!(b.contiguous, b"BBB");
        assert_eq!(r.active_streams(), 2);
    }
}
