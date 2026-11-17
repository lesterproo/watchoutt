
use crate::{
    EventId, EvidenceId, FlowId, Investigation, NetworkEvent, NetworkFlow,
};

/// Sentido en el que un evento coincide con un flujo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    AtoB,
    BtoA,
}

/// Asociación verificable entre un evento y un flujo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEventAssociation {
    pub event_id: EventId,
    pub flow_id: FlowId,
    pub direction: FlowDirection,
}

/// Tipo de elemento que aparece en la línea temporal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimelineEntryKind {
    Event {
        event_id: EventId,
        associated_flow_ids: Vec<FlowId>,
        summary: String,
        evidence_ids: Vec<EvidenceId>,
    },
    Flow {
        flow_id: FlowId,
        endpoint_a: crate::AssetId,
        endpoint_b: crate::AssetId,
        packet_count: u64,
        captured_bytes: u64,
        evidence_ids: Vec<EvidenceId>,
    },
}

/// Elemento ordenable de una investigación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    pub timestamp_unix_ns: i64,
    pub kind: TimelineEntryKind,
}

/// Resultado de construir una línea temporal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineReport {
    pub entries: Vec<TimelineEntry>,
    pub associations: Vec<FlowEventAssociation>,
    pub events_without_timestamp: usize,
}

/// Comprueba si un evento pertenece temporal y técnicamente a un flujo.
fn match_event_to_flow(
    event: &NetworkEvent,
    flow: &NetworkFlow,
) -> Option<FlowDirection> {
    let timestamp = event.timestamp_unix_ns?;

    // Sin protocolo o sin ambos extremos no existe información
    // suficiente para establecer una asociación fiable.
    let event_protocol = event.protocol.as_ref()?;

    if event_protocol != &flow.protocol {
        return None;
    }

    let source = event.source_asset?;
    let destination = event.destination_asset?;

    let forward = source == flow.endpoint_a
        && destination == flow.endpoint_b
        && event.source_port == flow.endpoint_a_port
        && event.destination_port == flow.endpoint_b_port;

    let reverse = source == flow.endpoint_b
        && destination == flow.endpoint_a
        && event.source_port == flow.endpoint_b_port
        && event.destination_port == flow.endpoint_a_port;

    if !forward && !reverse {
        return None;
    }

    if timestamp < flow.first_seen_unix_ns
        || timestamp > flow.last_seen_unix_ns
    {
        return None;
    }

    if forward {
        Some(FlowDirection::AtoB)
    } else {
        Some(FlowDirection::BtoA)
    }
}

/// Asocia eventos con flujos utilizando extremos, protocolo,
/// puertos e intervalo temporal.
pub fn associate_events_with_flows(
    events: &[NetworkEvent],
    flows: &[NetworkFlow],
) -> Vec<FlowEventAssociation> {
    let mut associations = Vec::new();

    for event in events {
        for flow in flows {
            if let Some(direction) = match_event_to_flow(event, flow) {
                associations.push(FlowEventAssociation {
                    event_id: event.id,
                    flow_id: flow.id,
                    direction,
                });
            }
        }
    }

    associations.sort_by_key(|association| {
        (association.event_id, association.flow_id)
    });

    associations
}

/// Construye una línea temporal con eventos y flujos.
///
/// Los flujos se representan en su instante de inicio.
pub fn build_investigation_timeline(
    investigation: &Investigation,
) -> TimelineReport {
    let events = investigation.events();
    let flows = investigation.flows();

    let associations = associate_events_with_flows(events, flows);

    let events_without_timestamp = events
        .iter()
        .filter(|event| event.timestamp_unix_ns.is_none())
        .count();

    let mut entries = Vec::new();

    // Índice de asociaciones por evento.
    for event in events {
        let Some(timestamp) = event.timestamp_unix_ns else {
            continue;
        };

        let associated_flow_ids = associations
            .iter()
            .filter(|association| association.event_id == event.id)
            .map(|association| association.flow_id)
            .collect();

        entries.push(TimelineEntry {
            timestamp_unix_ns: timestamp,
            kind: TimelineEntryKind::Event {
                event_id: event.id,
                associated_flow_ids,
                summary: event.summary.clone(),
                evidence_ids: event.evidence_ids.clone(),
            },
        });
    }

    // Cada flujo aparece en el instante de su primera observación.
    for flow in flows {
        entries.push(TimelineEntry {
            timestamp_unix_ns: flow.first_seen_unix_ns,
            kind: TimelineEntryKind::Flow {
                flow_id: flow.id,
                endpoint_a: flow.endpoint_a,
                endpoint_b: flow.endpoint_b,
                packet_count: flow.packet_count,
                captured_bytes: flow.captured_bytes,
                evidence_ids: flow.evidence_ids.clone(),
            },
        });
    }

    // Orden cronológico determinista:
    // primero eventos y después flujos cuando coinciden los tiempos.
    entries.sort_by_key(|entry| {
        let (priority, id) = match &entry.kind {
            TimelineEntryKind::Event { event_id, .. } => {
                (0u8, event_id.0)
            }
            TimelineEntryKind::Flow { flow_id, .. } => {
                (1u8, flow_id.0)
            }
        };

        (entry.timestamp_unix_ns, priority, id)
    });

    TimelineReport {
        entries,
        associations,
        events_without_timestamp,
    }
}

#[cfg(test)]
mod tests {
    use crate::Protocol;
    use super::*;
    use crate::{AssetId, EventKind};

    fn sample_flow() -> NetworkFlow {
        NetworkFlow {
            id: FlowId(1),
            endpoint_a: AssetId(10),
            endpoint_b: AssetId(20),
            endpoint_a_port: Some(50000),
            endpoint_b_port: Some(443),
            protocol: Protocol::Tcp,
            first_seen_unix_ns: 1_000,
            last_seen_unix_ns: 5_000,
            packet_count: 3,
            captured_bytes: 300,
            original_bytes: 300,
            packets_a_to_b: 2,
            packets_b_to_a: 1,
            captured_bytes_a_to_b: 200,
            captured_bytes_b_to_a: 100,
            evidence_ids: vec![EvidenceId(101), EvidenceId(102)],
        }
    }

    fn sample_event(
        id: u64,
        timestamp: i64,
        source: u64,
        destination: u64,
        source_port: u16,
        destination_port: u16,
    ) -> NetworkEvent {
        NetworkEvent {
            id: EventId(id),
            timestamp_unix_ns: Some(timestamp),
            kind: EventKind::Packet,
            summary: format!("Paquete {id}"),
            source_asset: Some(AssetId(source)),
            destination_asset: Some(AssetId(destination)),
            source_port: Some(source_port),
            destination_port: Some(destination_port),
            protocol: Some(Protocol::Tcp),
            evidence_ids: vec![EvidenceId(100 + id)],
        }
    }

    #[test]
    fn associates_forward_event_with_flow() {
        let flow = sample_flow();
        let event = sample_event(1, 2_000, 10, 20, 50000, 443);

        let result = associate_events_with_flows(
            &[event],
            &[flow],
        );

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].flow_id, FlowId(1));
        assert_eq!(result[0].direction, FlowDirection::AtoB);
    }

    #[test]
    fn associates_reverse_event_with_flow() {
        let flow = sample_flow();
        let event = sample_event(2, 3_000, 20, 10, 443, 50000);

        let result = associate_events_with_flows(
            &[event],
            &[flow],
        );

        assert_eq!(result.len(), 1);
        assert_eq!(result[0].direction, FlowDirection::BtoA);
    }

    #[test]
    fn rejects_event_with_different_ports() {
        let flow = sample_flow();
        let event = sample_event(1, 2_000, 10, 20, 50001, 443);

        let result = associate_events_with_flows(
            &[event],
            &[flow],
        );

        assert!(result.is_empty());
    }

    #[test]
    fn rejects_event_outside_flow_time_interval() {
        let flow = sample_flow();
        let event = sample_event(1, 6_000, 10, 20, 50000, 443);

        let result = associate_events_with_flows(
            &[event],
            &[flow],
        );

        assert!(result.is_empty());
    }

    #[test]
    fn rejects_event_with_different_protocol() {
        let flow = sample_flow();
        let mut event = sample_event(1, 2_000, 10, 20, 50000, 443);
        event.protocol = Some(Protocol::Udp);

        let result = associate_events_with_flows(
            &[event],
            &[flow],
        );

        assert!(result.is_empty());
    }

    #[test]
    fn rejects_event_without_protocol() {
        let flow = sample_flow();
        let mut event = sample_event(1, 2_000, 10, 20, 50000, 443);
        event.protocol = None;

        let result = associate_events_with_flows(
            &[event],
            &[flow],
        );

        assert!(result.is_empty());
    }
}
