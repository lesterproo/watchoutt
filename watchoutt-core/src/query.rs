use crate::{AssetId, EventKind, Investigation, NetworkEvent, Protocol};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventQuery {
    pub time_range: Option<(i64, i64)>,
    pub kinds: Vec<EventKind>,
    pub protocols: Vec<Protocol>,
    pub asset_ids: Vec<AssetId>,
    pub ports: Vec<u16>,
    pub text_contains: Option<String>,
    pub min_port: Option<u16>,
    pub max_port: Option<u16>,
    pub limit: Option<usize>,
    pub tcp_flags: Vec<String>,
}

impl EventQuery {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_kind(mut self, kind: EventKind) -> Self {
        self.kinds.push(kind);
        self
    }

    pub fn with_protocol(mut self, protocol: Protocol) -> Self {
        self.protocols.push(protocol);
        self
    }

    pub fn with_asset(mut self, asset: AssetId) -> Self {
        self.asset_ids.push(asset);
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.ports.push(port);
        self
    }

    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text_contains = Some(text.into());
        self
    }

    pub fn with_time_range(mut self, start: i64, end: i64) -> Self {
        self.time_range = Some((start, end));
        self
    }

    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_tcp_flags(mut self, flags: Vec<String>) -> Self {
        self.tcp_flags = flags;
        self
    }

    pub fn run<'a>(&self, investigation: &'a Investigation) -> Vec<&'a NetworkEvent> {
        let cap = self.limit.unwrap_or(usize::MAX);
        let mut out = Vec::new();

        for event in investigation.events() {
            if !self.matches(event) {
                continue;
            }
            out.push(event);
            if out.len() >= cap {
                break;
            }
        }

        out
    }

    pub fn count(&self, investigation: &Investigation) -> usize {
        self.run(investigation).len()
    }

    pub fn matches(&self, event: &NetworkEvent) -> bool {
        if let Some((start, end)) = self.time_range {
            let Some(ts) = event.timestamp_unix_ns else {
                return false;
            };
            if ts < start || ts > end {
                return false;
            }
        }

        if !self.kinds.is_empty() && !self.kinds.iter().any(|k| k == &event.kind) {
            return false;
        }

        if !self.protocols.is_empty() {
            let Some(protocol) = &event.protocol else {
                return false;
            };
            if !self.protocols.iter().any(|p| p == protocol) {
                return false;
            }
        }

        if !self.asset_ids.is_empty() {
            let source_hit = event
                .source_asset
                .map(|id| self.asset_ids.contains(&id))
                .unwrap_or(false);
            let destination_hit = event
                .destination_asset
                .map(|id| self.asset_ids.contains(&id))
                .unwrap_or(false);
            if !source_hit && !destination_hit {
                return false;
            }
        }

        if !self.ports.is_empty() {
            let source_hit = event
                .source_port
                .map(|p| self.ports.contains(&p))
                .unwrap_or(false);
            let destination_hit = event
                .destination_port
                .map(|p| self.ports.contains(&p))
                .unwrap_or(false);
            if !source_hit && !destination_hit {
                return false;
            }
        }

        if let Some(min) = self.min_port {
            let source_ok = event.source_port.map(|p| p >= min).unwrap_or(false);
            let dest_ok = event.destination_port.map(|p| p >= min).unwrap_or(false);
            if !source_ok && !dest_ok {
                return false;
            }
        }

        if let Some(max) = self.max_port {
            let source_ok = event.source_port.map(|p| p <= max).unwrap_or(false);
            let dest_ok = event.destination_port.map(|p| p <= max).unwrap_or(false);
            if !source_ok && !dest_ok {
                return false;
            }
        }

        if let Some(needle) = &self.text_contains {
            if !needle.is_empty() {
                let needle_lower = needle.to_lowercase();
                if !event.summary.to_lowercase().contains(&needle_lower) {
                    return false;
                }
            }
        }

        if !self.tcp_flags.is_empty() {
            let Some(flags_str) = &event.tcp_flags else {
                return false;
            };
            let has_any = self.tcp_flags.iter().any(|f| flags_str.contains(f));
            if !has_any {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AssetId, EventId, EvidenceId, InvestigationId, NetworkEvent};

    fn sample_event(
        id: u64,
        timestamp: i64,
        kind: EventKind,
        protocol: Protocol,
        source_port: u16,
        destination_port: u16,
        summary: &str,
        tcp_flags: Option<&str>,
    ) -> NetworkEvent {
        NetworkEvent {
            id: EventId(id),
            timestamp_unix_ns: Some(timestamp),
            kind,
            summary: summary.to_string(),
            source_asset: Some(AssetId(10)),
            destination_asset: Some(AssetId(20)),
            source_port: Some(source_port),
            destination_port: Some(destination_port),
            protocol: Some(protocol),
            evidence_ids: vec![EvidenceId(id)],
            tcp_flags: tcp_flags.map(|s| s.to_string()),
        }
    }

    fn investigation_with_events() -> Investigation {
        let mut investigation =
            Investigation::new(InvestigationId(1), "Query test", None, 0).unwrap();

        investigation
            .add_source(crate::SourceFile {
                id: crate::SourceId(1),
                file_name: "test.pcap".to_string(),
                relative_path: std::path::PathBuf::from("sources/test.pcap"),
                format: crate::SourceFormat::Pcap,
                size_bytes: 0,
                sha256: None,
                imported_at_unix_ns: 0,
            })
            .unwrap();

        investigation
            .add_asset(crate::Asset {
                id: AssetId(10),
                kind: crate::AssetKind::IpAddress,
                value: "10.0.0.1".to_string(),
                label: None,
            })
            .unwrap();

        investigation
            .add_asset(crate::Asset {
                id: AssetId(20),
                kind: crate::AssetKind::IpAddress,
                value: "10.0.0.2".to_string(),
                label: None,
            })
            .unwrap();

        for id in 1..=3 {
            investigation
                .add_evidence(crate::Evidence {
                    id: EvidenceId(id),
                    source_id: crate::SourceId(1),
                    location: crate::EvidenceLocation::PacketFrame { frame_number: id },
                    excerpt: None,
                })
                .unwrap();
        }

        investigation
            .add_event(sample_event(
                1,
                1_000,
                EventKind::HttpRequest,
                Protocol::Tcp,
                50000,
                80,
                "HTTP GET /index",
                Some("PSH, ACK"),
            ))
            .unwrap();

        investigation
            .add_event(sample_event(
                2,
                2_000,
                EventKind::TlsClientHello,
                Protocol::Tcp,
                50001,
                443,
                "TLS ClientHello SNI=example.com",
                Some("SYN"),
            ))
            .unwrap();

        investigation
            .add_event(sample_event(
                3,
                3_000,
                EventKind::DnsQuery,
                Protocol::Udp,
                50002,
                53,
                "DNS consulta: example.com A",
                None,
            ))
            .unwrap();

        investigation
    }

    #[test]
    fn empty_query_matches_all_events() {
        let investigation = investigation_with_events();
        let query = EventQuery::new();
        let results = query.run(&investigation);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn filters_by_kind() {
        let investigation = investigation_with_events();
        let query = EventQuery::new().with_kind(EventKind::DnsQuery);
        let results = query.run(&investigation);
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].kind, EventKind::DnsQuery));
    }

    #[test]
    fn filters_by_time_range() {
        let investigation = investigation_with_events();
        let query = EventQuery::new().with_time_range(1_500, 2_500);
        let results = query.run(&investigation);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, EventId(2));
    }

    #[test]
    fn filters_by_asset() {
        let investigation = investigation_with_events();
        let query = EventQuery::new().with_asset(AssetId(20));
        let results = query.run(&investigation);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn filters_by_text_case_insensitive() {
        let investigation = investigation_with_events();
        let query = EventQuery::new().with_text("EXAMPLE.COM");
        let results = query.run(&investigation);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn respects_limit() {
        let investigation = investigation_with_events();
        let query = EventQuery::new().with_limit(2);
        let results = query.run(&investigation);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn combines_multiple_filters() {
        let investigation = investigation_with_events();
        let query = EventQuery::new().with_protocol(Protocol::Tcp).with_port(80);
        let results = query.run(&investigation);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, EventId(1));
    }

    #[test]
    fn filters_by_tcp_flags() {
        let investigation = investigation_with_events();
        let query = EventQuery::new().with_tcp_flags(vec!["SYN".to_string()]);
        let results = query.run(&investigation);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, EventId(2));
    }
}
