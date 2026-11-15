mod pcapng;
pub use pcapng::{PcapNgError, PcapNgReader};

mod project;
pub use project::*;

mod correlation;
pub use correlation::*;

mod flow_analysis;
pub use flow_analysis::*;

mod analyzer;
pub use analyzer::*;

mod model;

pub use model::*;
mod source_store;

mod pcap;
mod payload;

pub use payload::{extract_transport_payload, TransportPayload};

mod dns;
pub use dns::*;

mod tls;
pub use tls::*;

mod http;
pub use http::*;

mod tcp_reassembly;
pub use tcp_reassembly::*;

mod anomaly;
pub use anomaly::*;

mod query;
pub use query::*;

mod export;
pub use export::*;

pub use pcap::*;

pub use source_store::{import_source, SourceImportError};

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn creates_a_complete_investigation() {
        let mut investigation = Investigation::new(
            InvestigationId(1),
            "Investigación de prueba",
            Some("Prueba del modelo de datos".to_string()),
            1_798_000_000_000_000_000,
        )
        .unwrap();

        investigation
            .add_source(SourceFile {
                id: SourceId(1),
                file_name: "capture.pcap".to_string(),
                relative_path: PathBuf::from("sources/capture.pcap"),
                format: SourceFormat::Pcap,
                size_bytes: 1024,
                sha256: None,
                imported_at_unix_ns: 1_798_000_000_000_000_000,
            })
            .unwrap();

        investigation
            .add_asset(Asset {
                id: AssetId(1),
                kind: AssetKind::IpAddress,
                value: "192.168.1.10".to_string(),
                label: Some("Equipo de prueba".to_string()),
            })
            .unwrap();

        investigation
            .add_evidence(Evidence {
                id: EvidenceId(1),
                source_id: SourceId(1),
                location: EvidenceLocation::PacketFrame { frame_number: 1 },
                excerpt: Some("Primer paquete de la captura".to_string()),
            })
            .unwrap();

        investigation
            .add_event(NetworkEvent {
                id: EventId(1),
                timestamp_unix_ns: None,
                kind: EventKind::NetworkFlow,
                summary: "Conexión TCP observada".to_string(),
                source_asset: Some(AssetId(1)),
                destination_asset: None,
                source_port: Some(51000),
                destination_port: Some(443),
                protocol: Some(Protocol::Tcp),
                evidence_ids: vec![EvidenceId(1)],
            })
            .unwrap();

        investigation
            .add_finding(Finding {
                id: FindingId(1),
                kind: FindingKind::Observation,
                severity: Severity::Info,
                title: "Conexión identificada".to_string(),
                description: "Se observó una conexión TCP en la captura".to_string(),
                evidence_ids: vec![EvidenceId(1)],
                confidence_percent: Some(100),
            })
            .unwrap();

        assert_eq!(investigation.sources().len(), 1);
        assert_eq!(investigation.assets().len(), 1);
        assert_eq!(investigation.evidences().len(), 1);
        assert_eq!(investigation.events().len(), 1);
        assert_eq!(investigation.findings().len(), 1);
    }

    #[test]
    fn rejects_evidence_without_a_valid_source() {
        let mut investigation =
            Investigation::new(InvestigationId(1), "Prueba", None, 0).unwrap();

        let evidence = Evidence {
            id: EvidenceId(1),
            source_id: SourceId(99),
            location: EvidenceLocation::LogLine { line_number: 10 },
            excerpt: None,
        };

        let result = investigation.add_evidence(evidence);

        assert_eq!(result, Err(DomainError::UnknownSource(SourceId(99))));
    }

    #[test]
    fn rejects_an_event_without_evidence() {
        let mut investigation =
            Investigation::new(InvestigationId(1), "Prueba", None, 0).unwrap();

        let event = NetworkEvent {
            id: EventId(1),
            timestamp_unix_ns: None,
            kind: EventKind::Packet,
            summary: "Evento sin procedencia".to_string(),
            source_asset: None,
            destination_asset: None,
            source_port: None,
            destination_port: None,
            protocol: None,
            evidence_ids: Vec::new(),
        };

        let result = investigation.add_event(event);

        assert_eq!(result, Err(DomainError::MissingEvidence("El evento")));
    }
}

mod timeline;
pub use timeline::*;

mod report;
pub use report::*;

mod baseline;
pub use baseline::*;

mod persistence;
pub use persistence::*;

pub mod live;
pub use live::*;