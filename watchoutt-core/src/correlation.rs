use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{AssetId, EventId, NetworkEvent};

/// Motivo observable por el que dos eventos se relacionan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CorrelationBasis {
    SharedAssetWithinTimeWindow,
}

/// Relación entre dos eventos respaldada por activos y tiempo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedCorrelation {
    pub first_event: EventId,
    pub second_event: EventId,
    pub shared_assets: Vec<AssetId>,
    pub time_delta_ns: u64,
    pub evidence_ids: Vec<crate::EvidenceId>,
    pub basis: CorrelationBasis,
}

/// Resultado general de una ejecución del motor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationReport {
    pub window_ns: u64,
    pub events_considered: usize,
    pub events_without_timestamp: usize,
    pub correlations: Vec<ObservedCorrelation>,
}

/// Obtiene los activos asociados a un evento sin duplicarlos.
fn event_assets(event: &NetworkEvent) -> BTreeSet<AssetId> {
    let mut assets = BTreeSet::new();

    if let Some(asset_id) = event.source_asset {
        assets.insert(asset_id);
    }

    if let Some(asset_id) = event.destination_asset {
        assets.insert(asset_id);
    }

    assets
}

/// Correlaciona eventos que comparten al menos un activo dentro
/// de una ventana temporal.
///
/// Esta función identifica relaciones observables. No determina
/// por sí sola que exista un ataque ni establece causalidad.
pub fn correlate_events(events: &[NetworkEvent], window_ns: u64) -> CorrelationReport {
    let mut events_by_asset: HashMap<AssetId, Vec<&NetworkEvent>> = HashMap::new();

    let mut events_considered = 0usize;
    let mut events_without_timestamp = 0usize;

    // Indexar cada evento por sus activos.
    for event in events {
        let Some(timestamp) = event.timestamp_unix_ns else {
            events_without_timestamp += 1;
            continue;
        };

        events_considered += 1;

        for asset_id in event_assets(event) {
            events_by_asset.entry(asset_id).or_default().push(event);
        }

        // El timestamp se comprueba aquí para dejar explícito
        // que solo se indexan eventos temporalmente válidos.
        let _ = timestamp;
    }

    // La clave ordenada evita duplicar una relación cuando
    // los eventos comparten más de un activo.
    let mut relationships: BTreeMap<
        (EventId, EventId),
        (BTreeSet<AssetId>, u64, BTreeSet<crate::EvidenceId>),
    > = BTreeMap::new();

    for (asset_id, mut asset_events) in events_by_asset {
        asset_events.sort_by_key(|event| (event.timestamp_unix_ns.unwrap_or_default(), event.id));

        for first_index in 0..asset_events.len() {
            let first = asset_events[first_index];

            let Some(first_timestamp) = first.timestamp_unix_ns else {
                continue;
            };

            for second in asset_events.iter().skip(first_index + 1) {
                let Some(second_timestamp) = second.timestamp_unix_ns else {
                    continue;
                };

                let delta = first_timestamp.abs_diff(second_timestamp);

                // Los eventos posteriores ya están ordenados.
                // Si exceden la ventana, los siguientes también.
                if delta > window_ns {
                    break;
                }

                // No relacionar un evento consigo mismo.
                if first.id == second.id {
                    continue;
                }

                let (first_id, second_id, first_event, second_event) = if first.id < second.id {
                    (first.id, second.id, first, *second)
                } else {
                    (second.id, first.id, *second, first)
                };

                let entry = relationships
                    .entry((first_id, second_id))
                    .or_insert_with(|| {
                        let mut evidence = BTreeSet::new();
                        evidence.extend(first_event.evidence_ids.iter().copied());
                        evidence.extend(second_event.evidence_ids.iter().copied());

                        (BTreeSet::new(), delta, evidence)
                    });

                entry.0.insert(asset_id);
                entry.1 = entry.1.min(delta);
                entry.2.extend(first.evidence_ids.iter().copied());
                entry.2.extend(second.evidence_ids.iter().copied());
            }
        }
    }

    let correlations = relationships
        .into_iter()
        .map(
            |((first_event, second_event), (assets, time_delta_ns, evidence))| {
                ObservedCorrelation {
                    first_event,
                    second_event,
                    shared_assets: assets.into_iter().collect(),
                    time_delta_ns,
                    evidence_ids: evidence.into_iter().collect(),
                    basis: CorrelationBasis::SharedAssetWithinTimeWindow,
                }
            },
        )
        .collect();

    CorrelationReport {
        window_ns,
        events_considered,
        events_without_timestamp,
        correlations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, EvidenceId, Protocol};

    fn event(
        id: u64,
        timestamp: Option<i64>,
        source: Option<AssetId>,
        destination: Option<AssetId>,
        evidence_id: u64,
    ) -> NetworkEvent {
        NetworkEvent {
            id: EventId(id),
            timestamp_unix_ns: timestamp,
            kind: EventKind::Packet,
            summary: format!("Evento de prueba {id}"),
            source_asset: source,
            destination_asset: destination,
            source_port: Some(50000),
            destination_port: Some(443),
            protocol: Some(Protocol::Tcp),
            evidence_ids: vec![EvidenceId(evidence_id)],
            tcp_flags: None,
        }
    }

    #[test]
    fn correlates_events_that_share_an_asset_within_window() {
        let shared_asset = AssetId(10);

        let events = vec![
            event(1, Some(1_000), Some(shared_asset), Some(AssetId(20)), 101),
            event(2, Some(5_000), Some(AssetId(30)), Some(shared_asset), 102),
        ];

        let report = correlate_events(&events, 5_000);

        assert_eq!(report.events_considered, 2);
        assert_eq!(report.correlations.len(), 1);

        let correlation = &report.correlations[0];

        assert_eq!(correlation.first_event, EventId(1));
        assert_eq!(correlation.second_event, EventId(2));
        assert_eq!(correlation.shared_assets, vec![shared_asset]);
        assert_eq!(correlation.time_delta_ns, 4_000);
        assert_eq!(
            correlation.evidence_ids,
            vec![EvidenceId(101), EvidenceId(102)]
        );
    }

    #[test]
    fn does_not_correlate_events_outside_time_window() {
        let shared_asset = AssetId(10);

        let events = vec![
            event(1, Some(1_000), Some(shared_asset), None, 101),
            event(2, Some(20_000), None, Some(shared_asset), 102),
        ];

        let report = correlate_events(&events, 5_000);

        assert!(report.correlations.is_empty());
    }

    #[test]
    fn does_not_correlate_events_without_shared_assets() {
        let events = vec![
            event(1, Some(1_000), Some(AssetId(10)), None, 101),
            event(2, Some(2_000), Some(AssetId(20)), None, 102),
        ];

        let report = correlate_events(&events, 5_000);

        assert!(report.correlations.is_empty());
    }

    #[test]
    fn excludes_events_without_timestamp() {
        let shared_asset = AssetId(10);

        let events = vec![
            event(1, None, Some(shared_asset), None, 101),
            event(2, Some(2_000), None, Some(shared_asset), 102),
        ];

        let report = correlate_events(&events, 5_000);

        assert_eq!(report.events_considered, 1);
        assert_eq!(report.events_without_timestamp, 1);
        assert!(report.correlations.is_empty());
    }

    #[test]
    fn combines_multiple_shared_assets_without_duplicate_relationships() {
        let events = vec![
            event(1, Some(1_000), Some(AssetId(10)), Some(AssetId(20)), 101),
            event(2, Some(2_000), Some(AssetId(20)), Some(AssetId(10)), 102),
        ];

        let report = correlate_events(&events, 5_000);

        assert_eq!(report.correlations.len(), 1);
        assert_eq!(
            report.correlations[0].shared_assets,
            vec![AssetId(10), AssetId(20)]
        );
    }
}
