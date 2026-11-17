use std::collections::HashMap;

use crate::{AssetId, Investigation, Protocol};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolStatistics {
    pub protocol: Protocol,
    pub flow_count: u64,
    pub packet_count: u64,
    pub captured_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointStatistics {
    pub asset_id: AssetId,
    pub flow_count: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl EndpointStatistics {
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.saturating_add(self.bytes_received)
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_sent.saturating_add(self.packets_received)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowStatistics {
    pub flow_count: u64,
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
    pub bidirectional_flow_count: u64,
    pub protocols: Vec<ProtocolStatistics>,
    pub endpoints: Vec<EndpointStatistics>,
}

pub fn analyze_flows(investigation: &Investigation) -> FlowStatistics {
    let mut result = FlowStatistics {
        flow_count: 0,
        packet_count: 0,
        captured_bytes: 0,
        original_bytes: 0,
        bidirectional_flow_count: 0,
        protocols: Vec::new(),
        endpoints: Vec::new(),
    };

    let mut protocol_map: HashMap<Protocol, ProtocolStatistics> = HashMap::new();

    let mut endpoint_map: HashMap<AssetId, EndpointStatistics> = HashMap::new();

    for flow in investigation.flows() {
        result.flow_count = result.flow_count.saturating_add(1);

        result.packet_count = result.packet_count.saturating_add(flow.packet_count);

        result.captured_bytes = result.captured_bytes.saturating_add(flow.captured_bytes);

        result.original_bytes = result.original_bytes.saturating_add(flow.original_bytes);

        if flow.is_bidirectional() {
            result.bidirectional_flow_count += 1;
        }

        // Estadísticas por protocolo.
        let protocol_stats = protocol_map
            .entry(flow.protocol.clone())
            .or_insert_with(|| ProtocolStatistics {
                protocol: flow.protocol.clone(),
                flow_count: 0,
                packet_count: 0,
                captured_bytes: 0,
            });

        protocol_stats.flow_count = protocol_stats.flow_count.saturating_add(1);

        protocol_stats.packet_count = protocol_stats
            .packet_count
            .saturating_add(flow.packet_count);

        protocol_stats.captured_bytes = protocol_stats
            .captured_bytes
            .saturating_add(flow.captured_bytes);

        // Extremo A: tráfico enviado hacia B y recibido desde B.
        let endpoint_a = endpoint_map
            .entry(flow.endpoint_a)
            .or_insert(EndpointStatistics {
                asset_id: flow.endpoint_a,
                flow_count: 0,
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
            });

        endpoint_a.flow_count = endpoint_a.flow_count.saturating_add(1);

        endpoint_a.packets_sent = endpoint_a.packets_sent.saturating_add(flow.packets_a_to_b);

        endpoint_a.packets_received = endpoint_a
            .packets_received
            .saturating_add(flow.packets_b_to_a);

        endpoint_a.bytes_sent = endpoint_a
            .bytes_sent
            .saturating_add(flow.captured_bytes_a_to_b);

        endpoint_a.bytes_received = endpoint_a
            .bytes_received
            .saturating_add(flow.captured_bytes_b_to_a);

        // Extremo B: dirección inversa.
        let endpoint_b = endpoint_map
            .entry(flow.endpoint_b)
            .or_insert(EndpointStatistics {
                asset_id: flow.endpoint_b,
                flow_count: 0,
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
            });

        endpoint_b.flow_count = endpoint_b.flow_count.saturating_add(1);

        endpoint_b.packets_sent = endpoint_b.packets_sent.saturating_add(flow.packets_b_to_a);

        endpoint_b.packets_received = endpoint_b
            .packets_received
            .saturating_add(flow.packets_a_to_b);

        endpoint_b.bytes_sent = endpoint_b
            .bytes_sent
            .saturating_add(flow.captured_bytes_b_to_a);

        endpoint_b.bytes_received = endpoint_b
            .bytes_received
            .saturating_add(flow.captured_bytes_a_to_b);
    }

    result.protocols = protocol_map.into_values().collect();

    result
        .protocols
        .sort_by_key(|item| format!("{:?}", item.protocol));

    result.endpoints = endpoint_map.into_values().collect();

    // Los equipos con mayor volumen de tráfico aparecen primero.
    result.endpoints.sort_by(|a, b| {
        b.total_bytes()
            .cmp(&a.total_bytes())
            .then_with(|| a.asset_id.cmp(&b.asset_id))
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        Asset, AssetKind, Evidence, EvidenceId, EvidenceLocation, FlowId, InvestigationId,
        NetworkFlow, SourceFile, SourceFormat, SourceId,
    };

    use std::path::PathBuf;

    #[test]
    fn calculates_flow_protocol_and_endpoint_statistics() {
        let mut investigation =
            Investigation::new(InvestigationId(1), "Prueba de estadísticas", None, 0).unwrap();

        investigation
            .add_source(SourceFile {
                id: SourceId(1),
                file_name: "test.pcap".to_string(),
                relative_path: PathBuf::from("sources/test.pcap"),
                format: SourceFormat::Pcap,
                size_bytes: 0,
                sha256: None,
                imported_at_unix_ns: 0,
            })
            .unwrap();

        investigation
            .add_asset(Asset {
                id: AssetId(1),
                kind: AssetKind::IpAddress,
                value: "192.168.1.10".to_string(),
                label: None,
            })
            .unwrap();

        investigation
            .add_asset(Asset {
                id: AssetId(2),
                kind: AssetKind::IpAddress,
                value: "192.168.1.20".to_string(),
                label: None,
            })
            .unwrap();

        investigation
            .add_evidence(Evidence {
                id: EvidenceId(1),
                source_id: SourceId(1),
                location: EvidenceLocation::PacketFrame { frame_number: 1 },
                excerpt: None,
            })
            .unwrap();

        investigation
            .add_flow(NetworkFlow {
                id: FlowId(1),
                endpoint_a: AssetId(1),
                endpoint_b: AssetId(2),
                endpoint_a_port: Some(50000),
                endpoint_b_port: Some(53),
                protocol: Protocol::Udp,
                first_seen_unix_ns: 0,
                last_seen_unix_ns: 2_000_000_000,
                packet_count: 3,
                captured_bytes: 300,
                original_bytes: 330,
                packets_a_to_b: 2,
                packets_b_to_a: 1,
                captured_bytes_a_to_b: 200,
                captured_bytes_b_to_a: 100,
                evidence_ids: vec![EvidenceId(1)],
            })
            .unwrap();

        let stats = analyze_flows(&investigation);

        assert_eq!(stats.flow_count, 1);
        assert_eq!(stats.packet_count, 3);
        assert_eq!(stats.captured_bytes, 300);
        assert_eq!(stats.original_bytes, 330);
        assert_eq!(stats.bidirectional_flow_count, 1);

        assert_eq!(stats.protocols.len(), 1);
        assert_eq!(stats.protocols[0].protocol, Protocol::Udp);
        assert_eq!(stats.protocols[0].packet_count, 3);

        assert_eq!(stats.endpoints.len(), 2);

        let endpoint_a = stats
            .endpoints
            .iter()
            .find(|item| item.asset_id == AssetId(1))
            .unwrap();

        assert_eq!(endpoint_a.packets_sent, 2);
        assert_eq!(endpoint_a.packets_received, 1);
        assert_eq!(endpoint_a.bytes_sent, 200);
        assert_eq!(endpoint_a.bytes_received, 100);
        assert_eq!(endpoint_a.total_bytes(), 300);
    }
}
