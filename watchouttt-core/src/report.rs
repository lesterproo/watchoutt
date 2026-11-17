use std::fs;
use std::io;
use std::path::Path;

use crate::{
    correlate_events,
    analyze_flows,
    build_investigation_timeline,
    AssetId,
    EventKind,
    Evidence,
    EvidenceLocation,
    Finding,
    Investigation,
    NetworkEvent,
    NetworkFlow,
    ObservedCorrelation,
    TimelineEntryKind,
};

pub fn render_markdown_report(
    investigation: &Investigation,
    correlation_window_ns: u64,
) -> String {
    let mut output = String::new();

    let statistics = analyze_flows(investigation);

    let correlations = correlate_events(
        investigation.events(),
        correlation_window_ns,
    );

    let timeline = build_investigation_timeline(investigation);

    output.push_str("# Informe de investigación NEXTRACE\n\n");

    output.push_str("## 1. Información general\n\n");

    output.push_str(&format!(
        "- **Investigación:** {}\n",
        escape_markdown(&investigation.name)
    ));

    output.push_str(&format!(
        "- **Identificador:** {}\n",
        investigation.id.0
    ));

    output.push_str(&format!(
        "- **Creada:** {}\n",
        format_timestamp(investigation.created_at_unix_ns)
    ));

    if let Some(description) = &investigation.description {
        output.push_str(&format!(
            "- **Descripción:** {}\n",
            escape_markdown(description)
        ));
    }

    output.push_str("\n## 2. Resumen de resultados\n\n");

    output.push_str(&format!(
        "- Fuentes importadas: {}\n",
        investigation.sources().len()
    ));

    output.push_str(&format!(
        "- Activos identificados: {}\n",
        investigation.assets().len()
    ));

    output.push_str(&format!(
        "- Evidencias registradas: {}\n",
        investigation.evidences().len()
    ));

    output.push_str(&format!(
        "- Eventos observados: {}\n",
        investigation.events().len()
    ));

    output.push_str(&format!(
        "- Flujos identificados: {}\n",
        statistics.flow_count
    ));

    let dns_query_count = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::DnsQuery))
        .count();

    let dns_response_count = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::DnsResponse))
        .count();

    let dns_resolution_count = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::DnsResolution))
        .count();

    let tls_count = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::TlsClientHello))
        .count();
    let http_req_count = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::HttpRequest))
        .count();
    let http_resp_count = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::HttpResponse))
        .count();

    output.push_str(&format!(
        "- Consultas DNS observadas: {}\n",
        dns_query_count
    ));

    output.push_str(&format!(
        "- Respuestas DNS observadas: {}\n",
        dns_response_count
    ));

    output.push_str(&format!(
        "- Resoluciones DNS nombre→IP registradas: {}\n",
        dns_resolution_count
    ));

    output.push_str(&format!(
        "- ClientHello TLS observados: {}\n",
        tls_count
    ));
    output.push_str(&format!(
        "- Peticiones HTTP observadas: {}\n",
        http_req_count
    ));
    output.push_str(&format!(
        "- Respuestas HTTP observadas: {}\n",
        http_resp_count
    ));

    output.push_str(&format!(
        "- Hallazgos registrados: {}\n",
        investigation.findings().len()
    ));

    output.push_str(&format!(
        "- Correlaciones observadas: {}\n",
        correlations.correlations.len()
    ));

    output.push_str("\n### Estadísticas del tráfico\n\n");

    output.push_str(&format!(
        "- Paquetes contabilizados en flujos: {}\n",
        statistics.packet_count
    ));

    output.push_str(&format!(
        "- Bytes capturados: {}\n",
        statistics.captured_bytes
    ));

    output.push_str(&format!(
        "- Bytes originales: {}\n",
        statistics.original_bytes
    ));

    output.push_str(&format!(
        "- Flujos bidireccionales: {}\n",
        statistics.bidirectional_flow_count
    ));

    output.push_str("\n## 3. Fuentes de información\n\n");

    if investigation.sources().is_empty() {
        output.push_str("No hay fuentes registradas.\n");
    } else {
        for source in investigation.sources() {
            output.push_str(&format!(
                "### {}\n\n",
                escape_markdown(&source.file_name)
            ));

            output.push_str(&format!(
                "- Identificador: {}\n",
                source.id.0
            ));

            output.push_str(&format!(
                "- Formato: {:?}\n",
                source.format
            ));

            output.push_str(&format!(
                "- Ruta dentro de la investigación: `{}`\n",
                escape_code(&source.relative_path.display().to_string())
            ));

            output.push_str(&format!(
                "- Tamaño: {} bytes\n",
                source.size_bytes
            ));

            output.push_str(&format!(
                "- Fecha de importación: {}\n",
                format_timestamp(source.imported_at_unix_ns)
            ));

            match &source.sha256 {
                Some(hash) => {
                    output.push_str(&format!(
                        "- SHA-256: `{}`\n",
                        hash
                    ));
                }
                None => {
                    output.push_str("- SHA-256: no disponible\n");
                }
            }

            output.push('\n');
        }
    }

    output.push_str("## 4. Activos identificados\n\n");

    if investigation.assets().is_empty() {
        output.push_str("No se identificaron activos.\n");
    } else {
        for asset in investigation.assets() {
            output.push_str(&format!(
                "- **{}** — `{}` (ID {})",
                format!("{:?}", asset.kind),
                escape_code(&asset.value),
                asset.id.0
            ));

            if let Some(label) = &asset.label {
                output.push_str(&format!(
                    " — {}",
                    escape_markdown(label)
                ));
            }

            output.push('\n');
        }
    }

    output.push_str("\n## 5. Estadísticas por protocolo\n\n");

    if statistics.protocols.is_empty() {
        output.push_str("No hay estadísticas de protocolos disponibles.\n");
    } else {
        for protocol in &statistics.protocols {
            output.push_str(&format!(
                "- **{:?}:** {} flujos, {} paquetes, {} bytes capturados\n",
                protocol.protocol,
                protocol.flow_count,
                protocol.packet_count,
                protocol.captured_bytes
            ));
        }
    }

    output.push_str("\n## 6. Flujos de comunicación\n\n");

    if investigation.flows().is_empty() {
        output.push_str("No se identificaron flujos.\n");
    } else {
        for flow in investigation.flows() {
            write_flow(
                &mut output,
                flow,
                investigation,
            );
        }
    }

    output.push_str("\n## 7. Actividad DNS\n\n");

    let dns_queries: Vec<&NetworkEvent> = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::DnsQuery))
        .collect();

    let dns_responses: Vec<&NetworkEvent> = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::DnsResponse))
        .collect();

    if dns_queries.is_empty() && dns_responses.is_empty() {
        output.push_str("No se observó actividad DNS en puerto 53.\n");
    } else {
        output.push_str(&format!("- Consultas: {}\n", dns_queries.len()));
        output.push_str(&format!("- Respuestas: {}\n\n", dns_responses.len()));

        if !dns_queries.is_empty() {
            output.push_str("### Consultas observadas\n\n");

            for event in &dns_queries {
                output.push_str(&format!(
                    "- {} — {}\n",
                    escape_code(&event.summary),
                    event
                        .timestamp_unix_ns
                        .map(format_timestamp)
                        .unwrap_or_else(|| "sin marca temporal".to_string())
                ));
            }

            output.push('\n');
        }

        if !dns_responses.is_empty() {
            output.push_str("### Respuestas observadas\n\n");

            for event in &dns_responses {
                output.push_str(&format!(
                    "- {} — {}\n",
                    escape_code(&event.summary),
                    event
                        .timestamp_unix_ns
                        .map(format_timestamp)
                        .unwrap_or_else(|| "sin marca temporal".to_string())
                ));
            }

            output.push('\n');
        }
    }

    let dns_resolutions: Vec<&NetworkEvent> = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::DnsResolution))
        .collect();

    if !dns_resolutions.is_empty() {
        output.push_str("### Resoluciones nombre → IP observadas\n\n");

        for event in &dns_resolutions {
            output.push_str(&format!(
                "- {} — {}\n",
                escape_code(&event.summary),
                event
                    .timestamp_unix_ns
                    .map(format_timestamp)
                    .unwrap_or_else(|| "sin marca temporal".to_string())
            ));
        }

        output.push('\n');
    }

    output.push_str("\n## 8. HTTP y metadatos TLS\n\n");

    let tls_events: Vec<&NetworkEvent> = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::TlsClientHello))
        .collect();
    let http_requests: Vec<&NetworkEvent> = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::HttpRequest))
        .collect();
    let http_responses: Vec<&NetworkEvent> = investigation
        .events()
        .iter()
        .filter(|event| matches!(event.kind, EventKind::HttpResponse))
        .collect();

    if tls_events.is_empty() && http_requests.is_empty() && http_responses.is_empty() {
        output.push_str("No se observaron metadatos TLS ni HTTP en claro.\n");
    } else {
        if !tls_events.is_empty() {
            output.push_str("### ClientHello TLS\n\n");
            for event in &tls_events {
                output.push_str(&format!(
                    "- {} — {}\n",
                    escape_code(&event.summary),
                    event
                        .timestamp_unix_ns
                        .map(format_timestamp)
                        .unwrap_or_else(|| "sin marca temporal".to_string())
                ));
            }
            output.push('\n');
        }

        if !http_requests.is_empty() {
            output.push_str("### Peticiones HTTP\n\n");
            for event in &http_requests {
                output.push_str(&format!(
                    "- {} — {}\n",
                    escape_code(&event.summary),
                    event
                        .timestamp_unix_ns
                        .map(format_timestamp)
                        .unwrap_or_else(|| "sin marca temporal".to_string())
                ));
            }
            output.push('\n');
        }

        if !http_responses.is_empty() {
            output.push_str("### Respuestas HTTP\n\n");
            for event in &http_responses {
                output.push_str(&format!(
                    "- {} — {}\n",
                    escape_code(&event.summary),
                    event
                        .timestamp_unix_ns
                        .map(format_timestamp)
                        .unwrap_or_else(|| "sin marca temporal".to_string())
                ));
            }
            output.push('\n');
        }

        output.push_str(
            "**Limitación:** sin reensamblado TCP, solo se muestran \
             peticiones y respuestas cuyo bloque inicial de cabeceras \
             está completo en un único segmento. Los cuerpos HTTP no \
             se interpretan.\n\n",
        );
    }

    output.push_str("\n## 9. Eventos observados\n\n");

    if investigation.events().is_empty() {
        output.push_str("No hay eventos registrados.\n");
    } else {
        for event in investigation.events() {
            output.push_str(&format!(
                "### Evento {}\n\n",
                event.id.0
            ));

            output.push_str(&format!(
                "- Tipo: {:?}\n",
                event.kind
            ));

            output.push_str(&format!(
                "- Momento: {}\n",
                event.timestamp_unix_ns
                    .map(format_timestamp)
                    .unwrap_or_else(|| "Sin marca temporal".to_string())
            ));

            output.push_str(&format!(
                "- Resumen: {}\n",
                escape_markdown(&event.summary)
            ));

            output.push_str(&format!(
                "- Origen: {}\n",
                format_optional_asset(
                    event.source_asset,
                    investigation
                )
            ));

            output.push_str(&format!(
                "- Destino: {}\n",
                format_optional_asset(
                    event.destination_asset,
                    investigation
                )
            ));

            output.push_str(&format!(
                "- Protocolo: {}\n",
                event.protocol
                    .as_ref()
                    .map(|protocol| format!("{protocol:?}"))
                    .unwrap_or_else(|| "No identificado".to_string())
            ));

            output.push_str(&format!(
                "- Puertos: {} -> {}\n",
                format_optional_port(event.source_port),
                format_optional_port(event.destination_port)
            ));

            output.push_str(&format!(
                "- Evidencias: {}\n",
                format_id_list(
                    event.evidence_ids.iter().map(|id| id.0)
                )
            ));

            output.push('\n');
        }
    }

    output.push_str("\n## 10. Correlaciones observadas\n\n");

    output.push_str(&format!(
        "Ventana temporal utilizada: {} nanosegundos.\n\n",
        correlation_window_ns
    ));

    if correlations.correlations.is_empty() {
        output.push_str("No se encontraron relaciones dentro de la ventana temporal.\n");
    } else {
        for correlation in &correlations.correlations {
            write_correlation(
                &mut output,
                correlation,
                investigation,
            );
        }
    }

    output.push_str("\n## 11. Cronología de la investigación\n\n");

    if timeline.entries.is_empty() {
        output.push_str("No hay elementos temporales disponibles.\n");
    } else {
        for entry in &timeline.entries {
            output.push_str(&format!(
                "### {}\n\n",
                format_timestamp(entry.timestamp_unix_ns)
            ));

            match &entry.kind {
                TimelineEntryKind::Event {
                    event_id,
                    associated_flow_ids,
                    summary,
                    evidence_ids,
                } => {
                    output.push_str(&format!(
                        "- Evento: {}\n",
                        event_id.0
                    ));

                    output.push_str(&format!(
                        "- Descripción: {}\n",
                        escape_markdown(summary)
                    ));

                    output.push_str(&format!(
                        "- Flujos relacionados: {}\n",
                        format_id_list(
                            associated_flow_ids.iter().map(|id| id.0)
                        )
                    ));

                    output.push_str(&format!(
                        "- Evidencias: {}\n",
                        format_id_list(
                            evidence_ids.iter().map(|id| id.0)
                        )
                    ));
                }

                TimelineEntryKind::Flow {
                    flow_id,
                    endpoint_a,
                    endpoint_b,
                    packet_count,
                    captured_bytes,
                    evidence_ids,
                } => {
                    output.push_str(&format!(
                        "- Flujo: {}\n",
                        flow_id.0
                    ));

                    output.push_str(&format!(
                        "- Extremos: {} <-> {}\n",
                        format_asset(*endpoint_a, investigation),
                        format_asset(*endpoint_b, investigation)
                    ));

                    output.push_str(&format!(
                        "- Paquetes: {}\n",
                        packet_count
                    ));

                    output.push_str(&format!(
                        "- Bytes capturados: {}\n",
                        captured_bytes
                    ));

                    output.push_str(&format!(
                        "- Evidencias: {}\n",
                        format_id_list(
                            evidence_ids.iter().map(|id| id.0)
                        )
                    ));
                }
            }

            output.push('\n');
        }
    }

    if timeline.events_without_timestamp > 0 {
        output.push_str(&format!(
            "**Aviso:** {} eventos no tienen marca temporal y no aparecen en la cronología.\n\n",
            timeline.events_without_timestamp
        ));
    }

    output.push_str("\n## 12. Hallazgos\n\n");

    if investigation.findings().is_empty() {
        output.push_str("No se han registrado hallazgos.\n");
    } else {
        for finding in investigation.findings() {
            write_finding(
                &mut output,
                finding,
            );
        }
    }

    output.push_str("\n## 13. Evidencias\n\n");

    if investigation.evidences().is_empty() {
        output.push_str("No hay evidencias registradas.\n");
    } else {
        for evidence in investigation.evidences() {
            write_evidence(
                &mut output,
                evidence,
                investigation,
            );
        }
    }

    output.push_str(
        "\n---\n\n\
         Informe generado por NEXTRACE.\n\n\
         Las observaciones y correlaciones aquí presentadas \
         describen relaciones respaldadas por los datos disponibles. \
         No constituyen por sí solas una atribución de ataque ni \
         una demostración de causalidad.\n"
    );

    output
}

pub fn write_markdown_report(
    investigation: &Investigation,
    correlation_window_ns: u64,
    destination: impl AsRef<Path>,
) -> io::Result<()> {
    let report = render_markdown_report(
        investigation,
        correlation_window_ns,
    );

    fs::write(destination, report)
}

fn write_flow(
    output: &mut String,
    flow: &NetworkFlow,
    investigation: &Investigation,
) {
    output.push_str(&format!(
        "### Flujo {}\n\n",
        flow.id.0
    ));

    output.push_str(&format!(
        "- Protocolo: {:?}\n",
        flow.protocol
    ));

    output.push_str(&format!(
        "- Extremo A: {}:{}\n",
        format_asset(flow.endpoint_a, investigation),
        format_optional_port(flow.endpoint_a_port)
    ));

    output.push_str(&format!(
        "- Extremo B: {}:{}\n",
        format_asset(flow.endpoint_b, investigation),
        format_optional_port(flow.endpoint_b_port)
    ));

    output.push_str(&format!(
        "- Primera observación: {}\n",
        format_timestamp(flow.first_seen_unix_ns)
    ));

    output.push_str(&format!(
        "- Última observación: {}\n",
        format_timestamp(flow.last_seen_unix_ns)
    ));

    output.push_str(&format!(
        "- Paquetes: {}\n",
        flow.packet_count
    ));

    output.push_str(&format!(
        "- Bytes capturados: {}\n",
        flow.captured_bytes
    ));

    output.push_str(&format!(
        "- Bytes originales: {}\n",
        flow.original_bytes
    ));

    output.push_str(&format!(
        "- Paquetes A -> B: {}\n",
        flow.packets_a_to_b
    ));

    output.push_str(&format!(
        "- Paquetes B -> A: {}\n",
        flow.packets_b_to_a
    ));

    output.push_str(&format!(
        "- Bidireccional: {}\n",
        if flow.is_bidirectional() { "Sí" } else { "No" }
    ));

    output.push_str(&format!(
        "- Evidencias: {}\n\n",
        format_id_list(
            flow.evidence_ids.iter().map(|id| id.0)
        )
    ));
}

fn write_correlation(
    output: &mut String,
    correlation: &ObservedCorrelation,
    investigation: &Investigation,
) {
    output.push_str(&format!(
        "### Eventos {} y {}\n\n",
        correlation.first_event.0,
        correlation.second_event.0
    ));

    output.push_str(&format!(
        "- Base de la relación: {:?}\n",
        correlation.basis
    ));

    output.push_str(&format!(
        "- Diferencia temporal: {} ns\n",
        correlation.time_delta_ns
    ));

    output.push_str("- Activos compartidos: ");

    if correlation.shared_assets.is_empty() {
        output.push_str("Ninguno");
    } else {
        let assets = correlation
            .shared_assets
            .iter()
            .map(|id| format_asset(*id, investigation))
            .collect::<Vec<_>>()
            .join(", ");

        output.push_str(&assets);
    }

    output.push('\n');

    output.push_str(&format!(
        "- Evidencias: {}\n\n",
        format_id_list(
            correlation.evidence_ids.iter().map(|id| id.0)
        )
    ));
}

fn write_finding(
    output: &mut String,
    finding: &Finding,
) {
    output.push_str(&format!(
        "### {} — {}\n\n",
        finding.id.0,
        escape_markdown(&finding.title)
    ));

    output.push_str(&format!(
        "- Clasificación: {:?}\n",
        finding.kind
    ));

    output.push_str(&format!(
        "- Severidad: {:?}\n",
        finding.severity
    ));

    output.push_str(&format!(
        "- Descripción: {}\n",
        escape_markdown(&finding.description)
    ));

    match finding.confidence_percent {
        Some(value) => {
            output.push_str(&format!(
                "- Confianza indicada: {}%\n",
                value
            ));
        }
        None => {
            output.push_str("- Confianza indicada: No especificada\n");
        }
    }

    output.push_str(&format!(
        "- Evidencias: {}\n\n",
        format_id_list(
            finding.evidence_ids.iter().map(|id| id.0)
        )
    ));
}

fn write_evidence(
    output: &mut String,
    evidence: &Evidence,
    investigation: &Investigation,
) {
    output.push_str(&format!(
        "### Evidencia {}\n\n",
        evidence.id.0
    ));

    output.push_str(&format!(
        "- Fuente: {}\n",
        investigation.sources()
            .iter()
            .find(|source| source.id == evidence.source_id)
            .map(|source| escape_markdown(&source.file_name))
            .unwrap_or_else(|| "Fuente desconocida".to_string())
    ));

    output.push_str(&format!(
        "- Identificador de fuente: {}\n",
        evidence.source_id.0
    ));

    match &evidence.location {
        EvidenceLocation::PacketFrame { frame_number } => {
            output.push_str(&format!(
                "- Ubicación: paquete {}\n",
                frame_number
            ));
        }

        EvidenceLocation::LogLine { line_number } => {
            output.push_str(&format!(
                "- Ubicación: línea {}\n",
                line_number
            ));
        }

        EvidenceLocation::ByteRange { offset, length } => {
            output.push_str(&format!(
                "- Ubicación: bytes {} a {}\n",
                offset,
                offset.saturating_add(*length)
            ));
        }

        EvidenceLocation::JsonPath { path } => {
            output.push_str(&format!(
                "- Ubicación: `{}`\n",
                escape_code(path)
            ));
        }
    }

    if let Some(excerpt) = &evidence.excerpt {
        output.push_str(&format!(
            "- Extracto: {}\n",
            escape_markdown(excerpt)
        ));
    }

    output.push('\n');
}

fn format_asset(
    asset_id: AssetId,
    investigation: &Investigation,
) -> String {
    investigation.assets()
        .iter()
        .find(|asset| asset.id == asset_id)
        .map(|asset| {
            format!(
                "{} (ID {})",
                escape_code(&asset.value),
                asset.id.0
            )
        })
        .unwrap_or_else(|| format!("Activo desconocido (ID {})", asset_id.0))
}

fn format_optional_asset(
    asset_id: Option<AssetId>,
    investigation: &Investigation,
) -> String {
    asset_id
        .map(|id| format_asset(id, investigation))
        .unwrap_or_else(|| "No identificado".to_string())
}

fn format_optional_port(port: Option<u16>) -> String {
    port.map(|value| value.to_string())
        .unwrap_or_else(|| "—".to_string())
}

fn format_id_list(
    ids: impl Iterator<Item = u64>,
) -> String {
    let values = ids
        .map(|id| id.to_string())
        .collect::<Vec<_>>();

    if values.is_empty() {
        "Ninguna".to_string()
    } else {
        values.join(", ")
    }
}

fn format_timestamp(timestamp_ns: i64) -> String {
    let seconds = timestamp_ns.div_euclid(1_000_000_000);
    let nanoseconds = timestamp_ns.rem_euclid(1_000_000_000);

    format!("{seconds}.{nanoseconds:09} UTC (Unix)")
}

fn escape_code(value: &str) -> String {
    value.replace('`', "\\`")
        .replace('\n', " ")
        .replace('\r', " ")
}

fn escape_markdown(value: &str) -> String {
    let mut result = String::with_capacity(value.len());

    for character in value.chars() {
        if matches!(
            character,
            '\\' | '*' | '_' | '[' | ']' | '<' | '>' | '#' | '|'
        ) {
            result.push('\\');
        }

        if character == '\n' || character == '\r' {
            result.push(' ');
        } else {
            result.push(character);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        InvestigationId,
    };

    #[test]
    fn generates_report_for_empty_investigation() {
        let investigation = Investigation::new(
            InvestigationId(1),
            "Investigación vacía",
            None,
            0,
        )
        .unwrap();

        let report = render_markdown_report(
            &investigation,
            60_000_000_000,
        );

        assert!(report.contains("# Informe de investigación NEXTRACE"));
        assert!(report.contains("Investigación vacía"));
        assert!(report.contains("## 3. Fuentes de información"));
        assert!(report.contains("## 7. Actividad DNS"));
        assert!(report.contains("## 8. HTTP y metadatos TLS"));
        assert!(report.contains("## 10. Correlaciones observadas"));
        assert!(report.contains("## 12. Hallazgos"));
        assert!(report.contains("## 13. Evidencias"));
    }

    #[test]
    fn escapes_markdown_in_user_supplied_text() {
        let investigation = Investigation::new(
            InvestigationId(1),
            "Caso *importante*",
            Some("Texto con [enlaces] y | separadores".to_string()),
            0,
        )
        .unwrap();

        let report = render_markdown_report(
            &investigation,
            0,
        );

        assert!(report.contains("Caso \\*importante\\*"));
        assert!(report.contains("\\[enlaces\\]"));
        assert!(report.contains("\\| separadores"));
    }

    #[test]
    fn formats_negative_unix_timestamps() {
        assert_eq!(
            format_timestamp(-1),
            "-1.999999999 UTC (Unix)"
        );
    }
}