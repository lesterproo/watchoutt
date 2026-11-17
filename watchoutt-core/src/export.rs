// Exportación de eventos a CSV y JSON sin dependencias externas.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use crate::{AssetId, Investigation, NetworkEvent};

pub fn export_events_csv(
    investigation: &Investigation,
    events: &[&NetworkEvent],
    destination: impl AsRef<Path>,
) -> io::Result<()> {
    let file = File::create(destination)?;
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "id,timestamp_unix_ns,kind,summary,source_asset,destination_asset,source_port,destination_port,protocol,evidence_ids"
    )?;

    for event in events {
        let source = resolve_asset(investigation, event.source_asset);
        let destination_asset = resolve_asset(investigation, event.destination_asset);
        let timestamp = event
            .timestamp_unix_ns
            .map(|v| v.to_string())
            .unwrap_or_default();
        let kind = format!("{:?}", event.kind);
        let protocol = event
            .protocol
            .as_ref()
            .map(|p| format!("{p:?}"))
            .unwrap_or_default();
        let source_port = event.source_port.map(|p| p.to_string()).unwrap_or_default();
        let destination_port = event
            .destination_port
            .map(|p| p.to_string())
            .unwrap_or_default();
        let evidence = event
            .evidence_ids
            .iter()
            .map(|id| id.0.to_string())
            .collect::<Vec<_>>()
            .join("|");

        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{},{}",
            event.id.0,
            csv_field(&timestamp),
            csv_field(&kind),
            csv_field(&event.summary),
            csv_field(&source),
            csv_field(&destination_asset),
            csv_field(&source_port),
            csv_field(&destination_port),
            csv_field(&protocol),
            csv_field(&evidence),
        )?;
    }

    writer.flush()?;
    Ok(())
}

pub fn export_events_json(
    investigation: &Investigation,
    events: &[&NetworkEvent],
    destination: impl AsRef<Path>,
) -> io::Result<()> {
    let file = File::create(destination)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "[")?;

    let total = events.len();

    for (index, event) in events.iter().enumerate() {
        let source = resolve_asset(investigation, event.source_asset);
        let destination_asset = resolve_asset(investigation, event.destination_asset);

        write!(writer, "  {{")?;
        write!(writer, "\"id\":{},", event.id.0)?;

        match event.timestamp_unix_ns {
            Some(ts) => write!(writer, "\"timestamp_unix_ns\":{ts},")?,
            None => write!(writer, "\"timestamp_unix_ns\":null,")?,
        }

        write!(
            writer,
            "\"kind\":{},",
            json_string(&format!("{:?}", event.kind))
        )?;
        write!(writer, "\"summary\":{},", json_string(&event.summary))?;
        write!(
            writer,
            "\"source_asset\":{},",
            json_optional_string(Some(&source))
        )?;
        write!(
            writer,
            "\"destination_asset\":{},",
            json_optional_string(Some(&destination_asset))
        )?;

        match event.source_port {
            Some(port) => write!(writer, "\"source_port\":{port},")?,
            None => write!(writer, "\"source_port\":null,")?,
        }

        match event.destination_port {
            Some(port) => write!(writer, "\"destination_port\":{port},")?,
            None => write!(writer, "\"destination_port\":null,")?,
        }

        match &event.protocol {
            Some(protocol) => write!(
                writer,
                "\"protocol\":{},",
                json_string(&format!("{protocol:?}"))
            )?,
            None => write!(writer, "\"protocol\":null,")?,
        }

        write!(writer, "\"evidence_ids\":[")?;
        for (i, evidence_id) in event.evidence_ids.iter().enumerate() {
            if i > 0 {
                write!(writer, ",")?;
            }
            write!(writer, "{}", evidence_id.0)?;
        }
        write!(writer, "]")?;

        write!(writer, "}}")?;

        if index + 1 < total {
            writeln!(writer, ",")?;
        } else {
            writeln!(writer)?;
        }
    }

    writeln!(writer, "]")?;
    writer.flush()?;
    Ok(())
}

fn resolve_asset(investigation: &Investigation, asset_id: Option<AssetId>) -> String {
    asset_id
        .and_then(|id| {
            investigation
                .assets()
                .iter()
                .find(|a| a.id == id)
                .map(|a| a.value.clone())
        })
        .unwrap_or_default()
}

fn csv_field(value: &str) -> String {
    let needs_quotes =
        value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r');

    if !needs_quotes {
        return value.to_string();
    }

    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');

    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }

    out.push('"');
    out
}

fn json_optional_string(value: Option<&str>) -> String {
    match value {
        Some(text) if !text.is_empty() => json_string(text),
        _ => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Asset, AssetId, AssetKind, EventId, EventKind, Evidence, EvidenceId, EvidenceLocation,
        InvestigationId, NetworkEvent, Protocol, SourceFile, SourceFormat, SourceId,
    };
    use std::path::PathBuf;

    fn sample_investigation() -> Investigation {
        let mut investigation =
            Investigation::new(InvestigationId(1), "Export test", None, 0).unwrap();

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
                value: "10.0.0.1".to_string(),
                label: None,
            })
            .unwrap();

        investigation
            .add_asset(Asset {
                id: AssetId(2),
                kind: AssetKind::IpAddress,
                value: "10.0.0.2".to_string(),
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
            .add_event(NetworkEvent {
                id: EventId(1),
                timestamp_unix_ns: Some(1_000),
                kind: EventKind::HttpRequest,
                summary: "HTTP GET /, \"test\"".to_string(),
                source_asset: Some(AssetId(1)),
                destination_asset: Some(AssetId(2)),
                source_port: Some(50000),
                destination_port: Some(80),
                protocol: Some(Protocol::Tcp),
                evidence_ids: vec![EvidenceId(1)],
                tcp_flags: None,
            })
            .unwrap();

        investigation
    }

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "nextrace_export_test_{}_{}",
            std::process::id(),
            name
        ))
    }

    #[test]
    fn csv_contains_header_and_row() {
        let investigation = sample_investigation();
        let events: Vec<&NetworkEvent> = investigation.events().iter().collect();
        let path = temp_path("events.csv");

        export_events_csv(&investigation, &events, &path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(text.contains("id,timestamp_unix_ns,kind"));
        assert!(text.contains("\"HTTP GET /, \"\"test\"\"\""));
        assert!(text.contains("10.0.0.1,10.0.0.2"));
        assert!(text.contains("50000,80"));
    }

    #[test]
    fn json_contains_well_formed_object() {
        let investigation = sample_investigation();
        let events: Vec<&NetworkEvent> = investigation.events().iter().collect();
        let path = temp_path("events.json");

        export_events_json(&investigation, &events, &path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(text.starts_with('['));
        assert!(text.trim_end().ends_with(']'));
        assert!(text.contains("\"id\":1"));
        assert!(text.contains("\"source_asset\":\"10.0.0.1\""));
        assert!(text.contains("\"destination_port\":80"));
        assert!(text.contains("\"evidence_ids\":[1]"));
    }

    #[test]
    fn empty_export_produces_valid_files() {
        let investigation = sample_investigation();
        let events: Vec<&NetworkEvent> = Vec::new();
        let path = temp_path("empty.json");

        export_events_json(&investigation, &events, &path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(text.starts_with('['));
        assert!(text.trim_end().ends_with(']'));
    }
}
