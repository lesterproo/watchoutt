import { invoke } from "@tauri-apps/api/core";
import { open, save } from "@tauri-apps/plugin-dialog";

interface TopAsset { id: number; value: string; kind: string; total_bytes: number; flow_count: number }
interface KindCount { kind: string; count: number }
interface ProtocolStat { protocol: string; flow_count: number; packet_count: number; captured_bytes: number }
interface EndpointStat { asset_id: number; value: string; flow_count: number; packets_sent: number; packets_received: number; bytes_sent: number; bytes_received: number }
interface FlowStats { flow_count: number; packet_count: number; captured_bytes: number; original_bytes: number; bidirectional_flow_count: number; protocols: ProtocolStat[]; endpoints: EndpointStat[] }
interface Overview { sources: number; sources_analyzed: number; assets: number; events: number; flows: number; findings: number; dns_queries: number; dns_responses: number; dns_resolutions: number; tls_client_hellos: number; http_requests: number; http_responses: number; top_assets: TopAsset[]; kind_distribution: KindCount[]; flow_stats: FlowStats }
interface EventDto { id: number; timestamp_ns: number | null; kind: string; summary: string; source_asset: string | null; destination_asset: string | null; source_port: number | null; destination_port: number | null; protocol: string | null; evidence_ids: number[]; tcp_flags: string | null; }
interface FlowDto { id: number; protocol: string; endpoint_a: string; endpoint_a_port: number | null; endpoint_b: string; endpoint_b_port: number | null; service_a: string | null; service_b: string | null; flags: string | null; first_seen_ns: number; last_seen_ns: number; duration_ns: number | null; packets_per_second: number | null; bytes_per_second: number | null; packet_count: number; captured_bytes: number; bidirectional: boolean }
interface FindingDto { id: number; severity: string; kind: string; title: string; description: string; confidence_percent: number | null; evidence_ids: number[] }
interface SourceDto { id: number; file_name: string; format: string; size_bytes: number; sha256: string | null; imported_at_ns: number; analyzed: boolean }
interface AssetDto { id: number; value: string; kind: string; label: string | null; flow_count: number; packets_sent: number; packets_received: number; bytes_sent: number; bytes_received: number; event_count: number }
interface AssetDetailDto { asset: AssetDto; flows: FlowDto[]; events: EventDto[] }
interface EvidenceExcerptDto { id: number; frame_number: number; excerpt: string | null }
interface EventDetailDto { event: EventDto; evidence: EvidenceExcerptDto[]; related_events: EventDto[]; flow: FlowDto | null; tcp_flags: string | null; }
interface CorrelationGroupDto { shared_asset: string; event_count: number; events: EventDto[]; evidence_ids: number[]; time_min_ns: number; time_max_ns: number; }
interface CorrelationDto { window_ns: number; events_considered: number; events_without_timestamp: number; total_events: number; total_candidates: number; truncated: boolean; total_found: number; groups: CorrelationGroupDto[]; }
interface TimelineEntryV2Dto { timestamp_ns: number; kind: string; event_id: number | null; event_summary: string | null; event_kind: string | null; associated_flow_ids: number[] | null; flow_id: number | null; flow_endpoint_a: string | null; flow_endpoint_b: string | null; flow_packet_count: number | null; flow_captured_bytes: number | null; evidence_ids: number[] }
interface TimelineV2Dto { events_without_timestamp: number; entries: TimelineEntryV2Dto[] }
interface DnsResolutionDto { hostname: string; ip: string; timestamp_ns: number | null; event_id: number; summary: string }
interface HttpHostDto { host: string; request_count: number; methods: string[]; sample_uris: string[] }
interface TlsSniDto { sni: string; count: number; versions: string[]; alpn: string[]; client_ips: string[] }
interface ProjectInfoDto { name: string; description: string | null; created_at_ns: number; investigation_id: number }
interface IntegrityReportDto { sources_verified: number; sources_without_hash: number; total_sources: number; all_ok: boolean }
interface AnomalyConfigDto { enable_http_on_unusual_port: boolean; enable_tls_on_plain_port: boolean; enable_large_flow: boolean; large_flow_threshold_bytes: number; enable_beaconing: boolean; beacon_min_connections: number; beacon_max_cv: number; enable_dns_tunneling: boolean; dns_long_name_threshold: number; dns_max_unique_subdomains: number; enable_port_scanning: boolean; portscan_max_distinct_destinations: number; portscan_window_ns: number }
interface BaselineConfigDto { min_entities_per_kind: number; modified_zscore_threshold: number; high_zscore_threshold: number; min_flows_per_asset: number; enable_bytes_baseline: boolean; enable_flow_count_baseline: boolean }
interface NoteDto { id: number; target_type: string; target_id: number; text: string; created_at_ns: number }
interface DiffDto { name_a: string; name_b: string; assets_only_in_a: string[]; assets_only_in_b: string[]; assets_shared: string[]; flows_only_in_a: string[]; flows_only_in_b: string[] }

let currentProjectDir: string | null = null;
let allFindings: FindingDto[] = [];
let currentFlows: FlowDto[] = [];
let selectedEventId: number | null = null;
let selectedAssetId: number | null = null;
let anomalyConfigCache: AnomalyConfigDto | null = null;
let baselineConfigCache: BaselineConfigDto | null = null;
let pivotAssetValue: string | null = null;
let iocActive: string[] = [];
let currentEventsInTable: EventDto[] = [];
let currentEventFilter: any = {};

function $(id: string): HTMLElement { const el = document.getElementById(id); if (!el) throw new Error(`Missing ${id}`); return el; }
function setStatus(msg: string) { $("status-message").textContent = msg; }
function fmtBytes(b: number): string { if (b < 1024) return `${b} B`; if (b < 1048576) return `${(b/1024).toFixed(1)} KB`; if (b < 1073741824) return `${(b/1048576).toFixed(1)} MB`; return `${(b/1073741824).toFixed(2)} GB`; }
function fmtTs(ns: number | null): string { if (ns === null) return "—"; const d = new Date(ns / 1e6); return d.toISOString().replace("T", " ").substring(0, 19); }
function fmtTsShort(ns: number | null): string { if (ns === null) return "—"; const d = new Date(ns / 1e6); return d.toISOString().substring(11, 23); }
function fmtDuration(ns: number | null): string { if (ns === null) return "—"; if (ns < 1000) return `${ns} ns`; if (ns < 1e6) return `${(ns/1e3).toFixed(1)} µs`; if (ns < 1e9) return `${(ns/1e6).toFixed(1)} ms`; return `${(ns/1e9).toFixed(2)} s`; }
function esc(s: string): string { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }

function showLoading(msg: string) { const ov = document.getElementById("loading-overlay"); const t = document.getElementById("loading-text"); if (ov && t) { t.textContent = msg; ov.classList.remove("hidden"); } }
function hideLoading() { document.getElementById("loading-overlay")?.classList.add("hidden"); }

function kindPill(k: string): string {
    const c = k === "Packet" ? "pill-packet" : k === "DnsQuery" || k === "DnsResponse" ? "pill-dns" : k === "DnsResolution" ? "pill-dnsres" : k === "TlsClientHello" ? "pill-tls" : k === "HttpRequest" || k === "HttpResponse" ? "pill-http" : "pill-packet";
    return `<span class="pill ${c}">${k}</span>`;
}
function protoPill(p: string | null): string { if (!p) return "—"; const c = p === "TCP" ? "pill-tcp" : p === "UDP" ? "pill-udp" : "pill-packet"; return `<span class="pill ${c}">${p}</span>`; }
function sevPill(s: string): string { return `<span class="pill pill-sev-${s.toLowerCase()}">${s}</span>`; }
function flagPill(f: string | null): string { if (!f) return "—"; return `<span class="pill pill-flag">${f}</span>`; }
function assetSpan(v: string | null): string { if (!v) return `<span style="color:var(--text-muted)">—</span>`; return `<button class="pivot-link" data-pivot-asset="${esc(v)}">${esc(v)}</button>`; }

async function run<T>(label: string, fn: () => Promise<T>, showOverlay = false): Promise<T | null> {
    if (showOverlay) showLoading(label);
    setStatus(`${label}…`);
    try { const r = await fn(); setStatus(`OK · ${label}`); return r; }
    catch (e) { setStatus(`Error · ${label}: ${String(e)}`); return null; }
    finally { if (showOverlay) hideLoading(); }
}

document.addEventListener("click", async (ev) => {
    const t = (ev.target as HTMLElement).closest("[data-pivot-asset]");
    if (t) { const v = t.getAttribute("data-pivot-asset"); if (v) await applyPivot(v); }
});

function switchTab(name: string) {
    document.querySelectorAll<HTMLButtonElement>(".tab").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
    document.querySelectorAll<HTMLElement>(".panel").forEach(p => {
        const isActive = p.dataset.panel === name;
        p.classList.toggle("active", isActive);
        if (isActive) {
            const hasSplitView = p.querySelector('.split-view') !== null;
            const isProtocols = p.dataset.panel === 'protocols';
            const isTimeline = p.dataset.panel === 'timeline';
            if (hasSplitView || isProtocols || isTimeline) { p.style.overflow = 'hidden'; } 
            else { p.style.overflowY = 'auto'; }
        }
    });

    if (!currentProjectDir && name !== "live") return;

    switch (name) {
        case "overview": refreshOverview(); break;
        case "sources": refreshSources(); break;
        case "events": refreshEvents(); break;
        case "assets": refreshAssets(); break;
        case "flows": refreshFlows(); break;
        case "correlations": refreshCorrelations(); break;
        case "protocols": refreshProtocols(); break;
        case "diff": populateDiffSources(); break;
        case "findings": refreshFindings(); break;
        case "timeline": refreshTimeline(); break;
        case "live": loadInterfaces(); break;
    }
}
document.querySelectorAll<HTMLButtonElement>(".tab").forEach(b => b.addEventListener("click", () => switchTab(b.dataset.tab!)));

function switchSubtab(name: string) {
    document.querySelectorAll<HTMLButtonElement>(".subtab").forEach(b => b.classList.toggle("active", b.dataset.subtab === name));
    document.querySelectorAll<HTMLElement>(".subpanel").forEach(p => p.classList.toggle("active", p.dataset.subpanel === name));
}
document.querySelectorAll<HTMLButtonElement>(".subtab").forEach(b => b.addEventListener("click", () => switchSubtab(b.dataset.subtab!)));

async function setProject(dir: string) {
    currentProjectDir = dir;
    pivotAssetValue = null;
    iocActive = [];
    updatePivotIndicator();
    const info = await invoke<ProjectInfoDto>("cmd_get_project_info", { projectDir: dir }).catch(() => null);
    if (info) {
        $("case-name").textContent = info.name;
        $("project-info").textContent = `${dir} · creado ${fmtTs(info.created_at_ns)}`;
    } else {
        $("case-name").textContent = dir.split("/").pop() || dir;
        $("project-info").textContent = dir;
    }
    await refreshFindingsBadge();
    switchTab("overview");
}

async function refreshFindingsBadge() {
    if (!currentProjectDir) return;
    const f = await invoke<FindingDto[]>("cmd_list_findings", { projectDir: currentProjectDir }).catch(() => []);
    const badge = $("findings-badge");
    const tabBadge = $("findings-tab-badge");
    badge.textContent = String(f.length);
    badge.classList.toggle("hidden", f.length === 0);
    if (f.length > 0) { tabBadge.textContent = String(f.length); tabBadge.classList.add("visible"); }
    else { tabBadge.classList.remove("visible"); }
}

$("btn-new-project").addEventListener("click", async () => {
    const dir = await open({ directory: true, multiple: false });
    if (!dir) return;
    const name = prompt("Nombre del nuevo caso:", "Caso sin título");
    if (!name) return;
    const r = await run("Creando proyecto", () => invoke<string>("cmd_create_project", { projectDir: dir, name }));
    if (r) await setProject(dir as string);
});

$("btn-open-project").addEventListener("click", async () => {
    const dir = await open({ directory: true, multiple: false });
    if (!dir) return;
    const r = await run("Abriendo proyecto", () => invoke<string>("cmd_open_project", { projectDir: dir }));
    if (r) await setProject(dir as string);
});

async function importPcapFlow() {
    if (!currentProjectDir) {
        const dir = await open({ directory: true, multiple: false });
        if (!dir) return;
        const name = prompt("Nombre del nuevo caso:", dir.split("/").pop() || "Caso");
        if (!name) return;
        const r = await run("Creando proyecto", () => invoke<string>("cmd_create_project", { projectDir: dir, name }));
        if (!r) return;
        await setProject(dir as string);
    }
    const file = await open({ multiple: false, filters: [{ name: "Capturas", extensions: ["pcap", "pcapng", "cap"] }] });
    if (!file) return;
    const r = await run("Importando captura", () => invoke<string>("cmd_import_source", { projectDir: currentProjectDir, filePath: file }), true);
    if (r) {
        setStatus(r);
        switchTab("sources");
        const a = await run("Analizando captura", () => invoke<string>("cmd_analyze", { projectDir: currentProjectDir! }), true);
        if (a) { setStatus(a.replace(/\n/g, " · ")); await refreshSources(); }
    }
}
$("btn-import-capture").addEventListener("click", importPcapFlow);

async function refreshOverview() {
    if (!currentProjectDir) return;
    const data = await run("Cargando vista general", () => invoke<Overview>("cmd_get_overview", { projectDir: currentProjectDir }), true);
    if (!data) return;
    const info = await invoke<ProjectInfoDto>("cmd_get_project_info", { projectDir: currentProjectDir }).catch(() => null);
    $("overview-empty").classList.add("hidden");
    $("overview-content").classList.remove("hidden");

    if (info) {
        $("project-banner").innerHTML = `
            <div class="banner-name" style="font-size:1.2rem;font-weight:600;margin-bottom:0.25rem">${esc(info.name)}</div>
            <div class="banner-desc" style="color:var(--text-muted);margin-bottom:0.5rem">${info.description ? esc(info.description) : "<em>Sin descripción</em>"} <button class="pivot-link" id="btn-edit-description" style="font-size:0.75rem">editar</button></div>
            <div class="banner-meta" style="font-size:0.75rem;color:var(--text-muted)">ID ${info.investigation_id} · creado ${fmtTs(info.created_at_ns)}</div>
            <hr style="border-color:var(--border);margin:1rem 0">`;
        $("btn-edit-description").addEventListener("click", async () => {
            const current = info.description || "";
            const next = prompt("Descripción del proyecto:", current);
            if (next === null) return;
            const r = await run("Actualizando", () => invoke<string>("cmd_update_project_description", { projectDir: currentProjectDir, description: next }));
            if (r) { setStatus(r); refreshOverview(); }
        });
    }

    const cards = [
        { label: "Fuentes", value: data.sources, detail: `${data.sources_analyzed} analizadas` },
        { label: "Activos", value: data.assets, detail: "IPs, MACs, hostnames" },
        { label: "Eventos", value: data.events, detail: "observaciones" },
        { label: "Flujos", value: data.flows, detail: `${data.flow_stats.bidirectional_flow_count} bidir.` },
        { label: "Hallazgos", value: data.findings, detail: "con evidencia" },
        { label: "DNS", value: data.dns_queries + data.dns_responses, detail: `${data.dns_resolutions} res.` },
        { label: "HTTP", value: data.http_requests + data.http_responses, detail: "req+resp" },
        { label: "TLS", value: data.tls_client_hellos, detail: "ClientHellos" },
    ];
    $("stats-grid").innerHTML = cards.map(c => `<div class="stat-card"><div class="stat-label">${c.label}</div><div class="stat-value">${c.value}</div><div class="stat-detail">${c.detail}</div></div>`).join("");

    const maxKind = Math.max(1, ...data.kind_distribution.map(k => k.count));
    $("kind-chart").innerHTML = data.kind_distribution.slice(0, 8).map(({ kind, count }) => {
        const col = kind === "DnsResolution" ? "var(--kind-dnsres)" : kind === "DnsQuery" || kind === "DnsResponse" ? "var(--kind-dns)" : kind === "TlsClientHello" ? "var(--kind-tls)" : kind === "HttpRequest" || kind === "HttpResponse" ? "var(--kind-http)" : "var(--kind-packet)";
        return `<div class="bar-row"><div class="bar-label">${kind}</div><div class="bar-track"><div class="bar-fill" style="width:${(count/maxKind)*100}%;background:${col}"></div></div><div class="bar-value">${count}</div></div>`;
    }).join("");

    const maxB = Math.max(1, ...data.top_assets.map(a => a.total_bytes));
    $("top-assets").innerHTML = data.top_assets.slice(0, 8).map(a => `<div class="bar-row"><div class="bar-label" title="${esc(a.value)}">${esc(a.value)}</div><div class="bar-track"><div class="bar-fill" style="width:${(a.total_bytes/maxB)*100}%;background:var(--accent)"></div></div><div class="bar-value">${fmtBytes(a.total_bytes)}</div></div>`).join("");

    const maxProto = Math.max(1, ...data.flow_stats.protocols.map(p => p.captured_bytes));
    $("protocol-stats").innerHTML = data.flow_stats.protocols.slice(0, 8).map(p => `<div class="bar-row"><div class="bar-label">${esc(p.protocol)}</div><div class="bar-track"><div class="bar-fill" style="width:${(p.captured_bytes/maxProto)*100}%;background:var(--accent)"></div></div><div class="bar-value">${fmtBytes(p.captured_bytes)}</div></div>`).join("");

    const maxEp = Math.max(1, ...data.flow_stats.endpoints.map(e => Math.max(e.bytes_sent, e.bytes_received)));
    $("endpoint-stats").innerHTML = data.flow_stats.endpoints.slice(0, 5).map(e => `
        <div style="margin-bottom:0.75rem">
            <div style="font-size:0.8rem;margin-bottom:0.25rem;font-weight:600;">${esc(e.value)}</div>
            <div class="bar-row" style="grid-template-columns:30px 1fr 60px;gap:0.5rem"><div style="font-size:0.7rem;color:var(--text-muted)">env</div><div class="bar-track"><div class="bar-fill" style="width:${(e.bytes_sent/maxEp)*100}%;background:var(--proto-tcp)"></div></div><div class="bar-value">${fmtBytes(e.bytes_sent)}</div></div>
            <div class="bar-row" style="grid-template-columns:30px 1fr 60px;gap:0.5rem"><div style="font-size:0.7rem;color:var(--text-muted)">recv</div><div class="bar-track"><div class="bar-fill" style="width:${(e.bytes_received/maxEp)*100}%;background:var(--proto-udp)"></div></div><div class="bar-value">${fmtBytes(e.bytes_received)}</div></div>
        </div>`).join("");
}

async function refreshSources() {
    if (!currentProjectDir) return;
    const s = await run("Cargando fuentes", () => invoke<SourceDto[]>("cmd_list_sources", { projectDir: currentProjectDir }));
    if (!s) return;
    const tb = $("sources-table").querySelector("tbody")!;
    tb.innerHTML = s.map(x => `<tr><td>${x.id}</td><td>${esc(x.file_name)}</td><td>${x.format}</td><td>${fmtBytes(x.size_bytes)}</td><td><span class="pill ${x.analyzed ? "pill-sev-info" : "pill-sev-low"}">${x.analyzed ? "Analizada" : "Pendiente"}</span></td><td style="color:var(--text-muted);font-size:0.72rem">${(x.sha256 || "—").substring(0, 16)}…</td></tr>`).join("");
}
$("btn-analyze").addEventListener("click", async () => {
    if (!currentProjectDir) return;
    const r = await run("Analizando", () => invoke<string>("cmd_analyze", { projectDir: currentProjectDir }), true);
    if (r) { setStatus(r.replace(/\n/g, " · ")); refreshSources(); }
});
$("btn-verify-integrity").addEventListener("click", async () => {
    if (!currentProjectDir) return;
    const r = await run("Verificando integridad", () => invoke<IntegrityReportDto>("cmd_verify_integrity", { projectDir: currentProjectDir }), true);
    if (!r) return;
    const box = $("integrity-status");
    box.classList.remove("hidden", "ok", "warn");
    box.classList.add(r.all_ok ? "ok" : "warn");
    box.textContent = r.all_ok ? `✓ Integridad: ${r.sources_verified}/${r.total_sources} fuentes.` : `⚠ ${r.sources_verified} verificadas · ${r.sources_without_hash} sin hash · ${r.total_sources} totales.`;
});

function localToNs(v: string): number | null { if (!v) return null; const ms = new Date(v).getTime(); return isNaN(ms) ? null : ms * 1e6; }
function buildEventFilter() {
    const tcp_flags = Array.from(document.querySelectorAll<HTMLInputElement>(".flag-filter:checked")).map(el => el.value);
    return { text: ($("filter-text") as HTMLInputElement).value || null, kind: ($("filter-kind") as HTMLSelectElement).value || null, protocol: ($("filter-protocol") as HTMLSelectElement).value || null, min_port: Number(($("filter-min-port") as HTMLInputElement).value) || null, max_port: Number(($("filter-max-port") as HTMLInputElement).value) || null, time_start_ns: localToNs(($("filter-time-start") as HTMLInputElement).value), time_end_ns: localToNs(($("filter-time-end") as HTMLInputElement).value), exclude_loopback: ($("filter-exclude-loopback") as HTMLInputElement).checked, asset_ids: [], asset_value: pivotAssetValue, ioc_tokens: iocActive, tcp_flags };
}

async function refreshEvents() {
    if (!currentProjectDir) return;
    currentEventFilter = buildEventFilter();
    const ev = await run("Cargando eventos", () => invoke<EventDto[]>("cmd_list_events", { projectDir: currentProjectDir, filter: currentEventFilter }));
    if (!ev) return;
    currentEventsInTable = ev;
    renderEventsTable(); updateEventsCount();
}

function renderEventsTable() {
    const tb = $("events-table").querySelector("tbody")!;
    tb.innerHTML = currentEventsInTable.map(e => `<tr data-id="${e.id}" class="${e.id === selectedEventId ? "selected" : ""}"><td style="white-space:nowrap;color:var(--text-muted)">${fmtTsShort(e.timestamp_ns)}</td><td>${kindPill(e.kind)}</td><td>${e.tcp_flags ? flagPill(e.tcp_flags) : "—"}</td><td title="${esc(e.summary)}">${esc(e.summary).substring(0, 80)}</td></tr>`).join("");
    tb.querySelectorAll<HTMLTableRowElement>("tr").forEach(r => r.addEventListener("click", () => selectEvent(Number(r.dataset.id))));
}
function updateEventsCount() { $("events-count").textContent = `${currentEventsInTable.length} eventos totales`; }
function updatePivotIndicator() {
    const ind = document.getElementById("pivot-indicator"); const lbl = document.getElementById("pivot-label");
    if (!ind || !lbl) return;
    if (pivotAssetValue || iocActive.length > 0) {
        ind.style.display = "flex";
        const p: string[] = [];
        if (pivotAssetValue) p.push(`"${pivotAssetValue}"`);
        if (iocActive.length > 0) p.push(`${iocActive.length} IoC`);
        lbl.textContent = p.join(" + ");
    } else ind.style.display = "none";
}

async function applyPivot(v: string) {
    pivotAssetValue = v;
    ($("filter-text") as HTMLInputElement).value = "";
    ($("filter-kind") as HTMLSelectElement).value = "";
    ($("filter-protocol") as HTMLSelectElement).value = "";
    ($("filter-min-port") as HTMLInputElement).value = "";
    ($("filter-max-port") as HTMLInputElement).value = "";
    ($("filter-time-start") as HTMLInputElement).value = "";
    ($("filter-time-end") as HTMLInputElement).value = "";
    ($("filter-iocs") as HTMLTextAreaElement).value = "";
    ($("filter-exclude-loopback") as HTMLInputElement).checked = false;
    document.querySelectorAll<HTMLInputElement>(".flag-filter").forEach(el => el.checked = false);
    iocActive = [];
    updatePivotIndicator();
    switchTab("events");
    setTimeout(() => refreshEvents(), 50);
}

$("btn-clear-pivot").addEventListener("click", () => { pivotAssetValue = null; iocActive = []; updatePivotIndicator(); refreshEvents(); });
$("btn-filter").addEventListener("click", () => refreshEvents());
$("btn-clear-filters").addEventListener("click", () => {
    ($("filter-text") as HTMLInputElement).value = "";
    ($("filter-kind") as HTMLSelectElement).value = "";
    ($("filter-protocol") as HTMLSelectElement).value = "";
    ($("filter-min-port") as HTMLInputElement).value = "";
    ($("filter-max-port") as HTMLInputElement).value = "";
    ($("filter-time-start") as HTMLInputElement).value = "";
    ($("filter-time-end") as HTMLInputElement).value = "";
    ($("filter-iocs") as HTMLTextAreaElement).value = "";
    ($("filter-exclude-loopback") as HTMLInputElement).checked = false;
    document.querySelectorAll<HTMLInputElement>(".flag-filter").forEach(el => el.checked = false);
    pivotAssetValue = null; iocActive = []; updatePivotIndicator(); refreshEvents();
});

async function selectEvent(id: number) {
    if (!currentProjectDir) return;
    selectedEventId = id;
    document.querySelectorAll<HTMLTableRowElement>("#events-table tbody tr").forEach(r => r.classList.toggle("selected", Number(r.dataset.id) === id));
    const d = await invoke<EventDetailDto>("cmd_get_event_detail", { projectDir: currentProjectDir, eventId: id });
    await renderEventDetail(d);
}

async function renderEventDetail(d: EventDetailDto) {
    if (!currentProjectDir) return;
    const e = d.event;
    const notes = await invoke<NoteDto[]>("cmd_list_notes", { projectDir: currentProjectDir, targetType: "event", targetId: e.id }).catch(() => []);

    const flowHtml = d.flow ? `<div class="detail-section"><div class="detail-label">Flujo asociado</div>
        <div class="detail-row"><div class="detail-row-key">Proto</div><div class="detail-row-value">${protoPill(d.flow.protocol)}</div></div>
        <div class="detail-row"><div class="detail-row-key">A</div><div class="detail-row-value">${assetSpan(d.flow.endpoint_a)}:${d.flow.endpoint_a_port ?? "—"} ${d.flow.service_a ? `<span class="pill pill-tcp">${d.flow.service_a}</span>` : ""}</div></div>
        <div class="detail-row"><div class="detail-row-key">B</div><div class="detail-row-value">${assetSpan(d.flow.endpoint_b)}:${d.flow.endpoint_b_port ?? "—"} ${d.flow.service_b ? `<span class="pill pill-tcp">${d.flow.service_b}</span>` : ""}</div></div>
        <div class="detail-row"><div class="detail-row-key">Paquetes</div><div class="detail-row-value">${d.flow.packet_count}</div></div>
        <div class="detail-row"><div class="detail-row-key">Bytes</div><div class="detail-row-value">${fmtBytes(d.flow.captured_bytes)}</div></div>
        </div>` : "";

    const evidenceHtml = d.evidence.map(ev => `<div class="detail-row"><div class="detail-row-key">Frame ${ev.frame_number}</div><div class="detail-row-value">${esc(ev.excerpt || "—")} <button class="pivot-link" data-hexdump="${ev.id}" style="margin-left:0.5rem;font-size:0.72rem">hexdump</button></div></div>`).join("") || "<div style='color:var(--text-muted);font-size:0.8rem'>Sin evidencias</div>";

    const notesHtml = notes.length === 0 ? `<div style="color:var(--text-muted);font-size:0.8rem">Sin notas</div>` : notes.map(n => `<div class="note-item" style="margin-bottom:0.5rem"><div style="font-size:0.85rem">${esc(n.text)}</div><div style="font-size:0.7rem;color:var(--text-muted)">${fmtTs(n.created_at_ns)} <button class="pivot-link" data-delete-note="${n.id}" style="font-size:0.7rem">eliminar</button></div></div>`).join("");

    $("event-detail").innerHTML = `
        <div class="detail-title">${kindPill(e.kind)} #${e.id}</div>
        <div class="detail-meta"><span>${fmtTs(e.timestamp_ns)}</span>${e.protocol ? protoPill(e.protocol) : ""}</div>
        <div class="detail-section"><div class="detail-label">Resumen</div><div style="font-size:0.85rem;line-height:1.5">${esc(e.summary)}</div></div>
        <div class="detail-section"><div class="detail-label">Extremos</div><div class="detail-row"><div class="detail-row-key">Origen</div><div class="detail-row-value">${assetSpan(e.source_asset)}:${e.source_port ?? "—"}</div></div><div class="detail-row"><div class="detail-row-key">Destino</div><div class="detail-row-value">${assetSpan(e.destination_asset)}:${e.destination_port ?? "—"}</div></div>
        ${d.tcp_flags ? `<div class="detail-row"><div class="detail-row-key">Flags TCP</div><div class="detail-row-value">${flagPill(d.tcp_flags)}</div></div>` : ""}
        </div>
        ${flowHtml}
        <div class="detail-section"><div class="detail-label">Evidencias</div>${evidenceHtml}</div>
        <div class="detail-section"><div class="detail-label">Notas del analista</div>${notesHtml}
            <div style="margin-top:0.5rem"><textarea id="new-note-text" placeholder="Añadir nota…" rows="2" style="width:100%"></textarea>
            <button class="btn-secondary" id="btn-add-note" style="margin-top:0.5rem;width:100%">Añadir nota</button></div></div>`;

    $("event-detail").querySelectorAll<HTMLElement>("[data-hexdump]").forEach(el => {
        el.addEventListener("click", async () => {
            const id = Number(el.getAttribute("data-hexdump"));
            const hex = await run("Hexdump", () => invoke<string>("cmd_get_frame_hex", { projectDir: currentProjectDir, evidenceId: id }), true);
            if (hex) { $("hexdump-content").textContent = hex; $("modal-hexdump").classList.remove("hidden"); }
        });
    });
    const btnAdd = document.getElementById("btn-add-note");
    if (btnAdd) btnAdd.addEventListener("click", async () => {
        const t = ($("new-note-text") as HTMLTextAreaElement).value;
        if (!t.trim()) return;
        await run("Añadiendo nota", () => invoke<NoteDto>("cmd_add_note", { projectDir: currentProjectDir, targetType: "event", targetId: e.id, text: t }), true);
        selectEvent(e.id);
    });
    $("event-detail").querySelectorAll<HTMLElement>("[data-delete-note]").forEach(el => {
        el.addEventListener("click", async () => {
            const id = Number(el.getAttribute("data-delete-note"));
            await run("Eliminando", () => invoke<void>("cmd_delete_note", { projectDir: currentProjectDir, noteId: id }), true);
            selectEvent(e.id);
        });
    });
}
$("modal-close-hexdump").addEventListener("click", () => $("modal-hexdump").classList.add("hidden"));

async function refreshAssets() {
    if (!currentProjectDir) return;
    const a = await run("Cargando activos", () => invoke<AssetDto[]>("cmd_list_assets", { projectDir: currentProjectDir }));
    if (!a) return;
    $("assets-count").textContent = `${a.length} activos`;
    const tb = $("assets-table").querySelector("tbody")!;
    tb.innerHTML = a.map(x => `<tr data-id="${x.id}" class="${x.id === selectedAssetId ? "selected" : ""}"><td><button class="pivot-link" data-pivot-asset="${esc(x.value)}">${esc(x.value)}</button></td><td><span class="pill pill-packet">${x.kind}</span></td><td>${x.flow_count}</td><td>${x.event_count}</td></tr>`).join("");
    tb.querySelectorAll<HTMLTableRowElement>("tr").forEach(r => r.addEventListener("click", (ev) => { if ((ev.target as HTMLElement).classList.contains("pivot-link")) return; selectAsset(Number(r.dataset.id)); }));
}

async function selectAsset(id: number) {
    if (!currentProjectDir) return;
    selectedAssetId = id;
    document.querySelectorAll<HTMLTableRowElement>("#assets-table tbody tr").forEach(r => r.classList.toggle("selected", Number(r.dataset.id) === id));
    const d = await invoke<AssetDetailDto>("cmd_get_asset_detail", { projectDir: currentProjectDir, assetId: id });
    const a = d.asset;
    $("asset-detail").innerHTML = `
        <div class="detail-title">${esc(a.value)}</div>
        <div class="detail-meta"><span class="pill pill-packet">${a.kind}</span>${a.label ? `<span>${esc(a.label)}</span>` : ""}</div>
        <div class="detail-section"><div class="detail-label">Estadísticas</div><div class="detail-row"><div class="detail-row-key">Flujos</div><div class="detail-row-value">${a.flow_count}</div></div><div class="detail-row"><div class="detail-row-key">Eventos</div><div class="detail-row-value">${a.event_count}</div></div><div class="detail-row"><div class="detail-row-key">Bytes env.</div><div class="detail-row-value">${fmtBytes(a.bytes_sent)}</div></div><div class="detail-row"><div class="detail-row-key">Bytes recv.</div><div class="detail-row-value">${fmtBytes(a.bytes_received)}</div></div></div>
        <div class="detail-section"><div class="detail-label">Flujos recientes (${d.flows.length})</div>${d.flows.slice(0, 10).map(f => `<div style="margin-bottom:0.5rem;border-bottom:1px solid var(--border);padding-bottom:0.5rem"><div style="display:flex;gap:0.4rem;align-items:center;margin-bottom:0.25rem">${protoPill(f.protocol)}<span style="color:var(--text-muted);font-size:0.72rem">${f.packet_count} pkts · ${fmtBytes(f.captured_bytes)}</span>${f.flags ? flagPill(f.flags) : ""}</div><div style="font-size:0.78rem">${assetSpan(f.endpoint_a)}:${f.endpoint_a_port ?? "—"} ↔ ${assetSpan(f.endpoint_b)}:${f.endpoint_b_port ?? "—"}</div></div>`).join("") || "<div class='empty-state'>Sin flujos</div>"}</div>`;
}

async function refreshFlows() {
    if (!currentProjectDir) return;
    const f = await run("Cargando flujos", () => invoke<FlowDto[]>("cmd_list_flows", { projectDir: currentProjectDir }));
    if (!f) return;
    currentFlows = f;
    applyFlowFilters();
}
function applyFlowFilters() {
    const proto = ($("filter-flow-proto") as HTMLSelectElement).value;
    const minB = Number(($("filter-flow-min-bytes") as HTMLInputElement).value) || 0;
    const filtered = currentFlows.filter(x => (!proto || x.protocol === proto) && x.captured_bytes >= minB);
    $("flows-count").textContent = `${filtered.length} flujos (de ${currentFlows.length})`;
    const tb = $("flows-table").querySelector("tbody")!;
    tb.innerHTML = filtered.map(x => `<tr data-flow-id="${x.id}"><td>${protoPill(x.protocol)}</td><td>${assetSpan(x.endpoint_a)}:${x.endpoint_a_port ?? "—"}</td><td>${assetSpan(x.endpoint_b)}:${x.endpoint_b_port ?? "—"}</td><td>${flagPill(x.flags)}</td><td>${x.packet_count}</td><td>${fmtBytes(x.captured_bytes)}</td></tr>`).join("");
    tb.querySelectorAll<HTMLTableRowElement>("tr").forEach(r => r.addEventListener("click", (ev) => { if ((ev.target as HTMLElement).classList.contains("pivot-link")) return; selectFlow(Number(r.dataset.flowId)); }));
}
$("btn-filter-flows").addEventListener("click", () => applyFlowFilters());

async function selectFlow(id: number) {
    if (!currentProjectDir) return;
    document.querySelectorAll<HTMLTableRowElement>("#flows-table tbody tr").forEach(r => r.classList.toggle("selected", Number(r.dataset.flowId) === id));
    const flow = currentFlows.find(f => f.id === id);
    const events = await run("Cargando sesión", () => invoke<EventDto[]>("cmd_list_flow_events", { projectDir: currentProjectDir, flowId: id }), true);
    if (!events) return;
    const info = flow ? `<div class="detail-title">${protoPill(flow.protocol)} ${esc(flow.endpoint_a)}:${flow.endpoint_a_port ?? "—"} ↔ ${esc(flow.endpoint_b)}:${flow.endpoint_b_port ?? "—"}</div><div class="detail-meta"><span>${flow.packet_count} paquetes · ${fmtBytes(flow.captured_bytes)} · ${fmtDuration(flow.duration_ns)}</span> ${flow.flags ? flagPill(flow.flags) : ""}</div>` : "";
    const evHtml = events.length === 0 ? `<div class="empty-state">Sin eventos para este flujo</div>` : events.map(e => `<div style="margin-bottom:0.5rem;border-bottom:1px solid var(--border);padding-bottom:0.5rem"><div style="display:flex;gap:0.4rem;align-items:center;margin-bottom:0.25rem">${kindPill(e.kind)}<span style="color:var(--text-muted);font-size:0.72rem">${fmtTsShort(e.timestamp_ns)}</span>${e.tcp_flags ? flagPill(e.tcp_flags) : ""}</div><div style="font-size:0.78rem">${esc(e.summary)}</div></div>`).join("");
    $("flow-session-detail").innerHTML = `${info}<div class="detail-section"><div class="detail-label">Eventos (${events.length})</div>${evHtml}</div>`;
}

async function refreshCorrelations() {
    if (!currentProjectDir) return;
    const w = Number(($("correlation-window") as HTMLSelectElement).value);
    const d = await run("Calculando", () => invoke<CorrelationDto>("cmd_get_correlations", { projectDir: currentProjectDir, windowNs: w }), true);
    if (!d) return;
    const p: string[] = []; p.push(`${d.groups.length}${d.total_found > d.groups.length ? ` de ${d.total_found}` : ""} grupos`); p.push(`${d.events_considered} eventos`); if (d.truncated) p.push(`${d.total_candidates} candidatos → top ${d.events_considered}`); if (d.events_without_timestamp > 0) p.push(`${d.events_without_timestamp} sin ts`);
    $("correlations-count").textContent = p.join(" · ");
    $("correlations-list").innerHTML = d.groups.length === 0 ? `<div class="empty-state">Sin correlaciones en esta ventana</div>` : d.groups.map(g => `
        <div class="correlation-item" style="background:var(--bg-panel);padding:1rem;border-radius:8px;margin-bottom:1rem;border:1px solid var(--border)">
            <div class="corr-header" style="margin-bottom:0.5rem"><strong>${esc(g.shared_asset)}</strong> <span style="color:var(--text-muted)"> · ${g.event_count} eventos · ${fmtTsShort(g.time_min_ns)} → ${fmtTsShort(g.time_max_ns)}</span></div>
            <div class="corr-events" style="margin-bottom:0.5rem">${g.events.map(e => `<div class="corr-event" style="margin-bottom:0.5rem;border-bottom:1px solid var(--border);padding-bottom:0.5rem"><div>${kindPill(e.kind)} <strong>#${e.id}</strong> <span style="color:var(--text-muted);font-size:0.72rem">${fmtTsShort(e.timestamp_ns)}</span></div><div style="margin-top:0.25rem;font-size:0.85rem">${esc(e.summary).substring(0, 120)}</div></div>`).join("")}</div>
        </div>`).join("");
}
$("btn-correlate").addEventListener("click", () => refreshCorrelations());

async function refreshProtocols() {
    if (!currentProjectDir) return;
    const [dns, http, tls] = await Promise.all([
        invoke<DnsResolutionDto[]>("cmd_list_dns_resolutions", { projectDir: currentProjectDir }).catch(() => []),
        invoke<HttpHostDto[]>("cmd_list_http_hosts", { projectDir: currentProjectDir }).catch(() => []),
        invoke<TlsSniDto[]>("cmd_list_tls_snis", { projectDir: currentProjectDir }).catch(() => []),
    ]);
    $("dns-table").querySelector("tbody")!.innerHTML = dns.map(d => `<tr><td>${assetSpan(d.hostname)}</td><td>${assetSpan(d.ip)}</td><td style="color:var(--text-muted)">${fmtTsShort(d.timestamp_ns)}</td><td>${esc(d.summary)}</td></tr>`).join("") || `<tr><td colspan="4" class="empty-state">Sin resoluciones</td></tr>`;
    $("http-table").querySelector("tbody")!.innerHTML = http.map(h => `<tr><td><strong>${esc(h.host)}</strong></td><td>${h.request_count}</td><td>${h.methods.map(m => `<span class="pill pill-http">${m}</span>`).join(" ")}</td><td style="font-size:0.72rem;color:var(--text-muted)">${h.sample_uris.map(u => esc(u)).join(" · ")}</td></tr>`).join("") || `<tr><td colspan="4" class="empty-state">Sin peticiones</td></tr>`;
    $("tls-table").querySelector("tbody")!.innerHTML = tls.map(t => `<tr><td><strong>${esc(t.sni)}</strong></td><td>${t.count}</td><td>${t.versions.join(", ")}</td><td>${t.alpn.join(", ")}</td><td style="font-size:0.72rem;color:var(--text-muted)">${t.client_ips.slice(0, 3).join(", ")}${t.client_ips.length > 3 ? "…" : ""}</td></tr>`).join("") || `<tr><td colspan="5" class="empty-state">Sin ClientHellos</td></tr>`;
}

async function populateDiffSources() {
    if (!currentProjectDir) return;
    const sources = await invoke<SourceDto[]>("cmd_list_sources", { projectDir: currentProjectDir });
    const sa = $("diff-source-a") as HTMLSelectElement; const sb = $("diff-source-b") as HTMLSelectElement;
    const opts = sources.map(s => `<option value="${s.id}">${esc(s.file_name)} (ID ${s.id})</option>`).join("");
    sa.innerHTML = opts; sb.innerHTML = opts;
    if (sources.length > 1) sa.value = String(sources[0].id); sb.value = String(sources[1].id);
}
$("btn-run-diff").addEventListener("click", async () => {
    if (!currentProjectDir) return;
    const sa = Number(($("diff-source-a") as HTMLSelectElement).value); const sb = Number(($("diff-source-b") as HTMLSelectElement).value);
    if (!sa || !sb || sa === sb) { setStatus("Selecciona dos fuentes distintas"); return; }
    const d = await run("Comparando fuentes", () => invoke<DiffDto>("cmd_diff_sources", { projectDir: currentProjectDir, sourceA: sa, sourceB: sb }), true);
    if (!d) return;
    const listHtml = (items: string[], empty: string) => items.length === 0 ? `<div style="color:var(--text-muted);font-size:0.8rem">${empty}</div>` : items.map(i => `<div style="margin-bottom:0.25rem"><code>${esc(i)}</code></div>`).join("");
    
    $("diff-result").innerHTML = `
        <div class="diff-section" style="margin-bottom:2rem">
            <h2 style="color:var(--accent);margin-bottom:1rem;border-bottom:1px solid var(--border);padding-bottom:0.5rem">Activos</h2>
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem">
                <div class="diff-card"><h4>Solo en A (${d.assets_only_in_a.length})</h4><div class="diff-list">${listHtml(d.assets_only_in_a, "Ninguno")}</div></div>
                <div class="diff-card"><h4>Solo en B (${d.assets_only_in_b.length})</h4><div class="diff-list">${listHtml(d.assets_only_in_b, "Ninguno")}</div></div>
                <div class="diff-card"><h4>Compartidos (${d.assets_shared.length})</h4><div class="diff-list">${listHtml(d.assets_shared, "Ninguno")}</div></div>
            </div>
        </div>
        <div class="diff-section">
            <h2 style="color:var(--accent);margin-bottom:1rem;border-bottom:1px solid var(--border);padding-bottom:0.5rem">Flujos</h2>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem">
                <div class="diff-card"><h4>Solo en A (${d.flows_only_in_a.length})</h4><div class="diff-list">${listHtml(d.flows_only_in_a, "Ninguno")}</div></div>
                <div class="diff-card"><h4>Solo en B (${d.flows_only_in_b.length})</h4><div class="diff-list">${listHtml(d.flows_only_in_b, "Ninguno")}</div></div>
            </div>
        </div>`;
});

async function refreshFindings() {
    if (!currentProjectDir) return;
    const f = await run("Cargando hallazgos", () => invoke<FindingDto[]>("cmd_list_findings", { projectDir: currentProjectDir }));
    if (!f) return;
    allFindings = f;
    $("findings-list").innerHTML = f.length === 0 ? `<div class="empty-state">Sin hallazgos. Pulsa "Detectar anomalías".</div>` : f.map(x => `<div class="finding-item" data-id="${x.id}" style="padding:0.75rem;border-bottom:1px solid var(--border);cursor:pointer"><div class="finding-title" style="font-weight:600;font-size:0.9rem;margin-bottom:0.25rem">${esc(x.title)}</div><div class="finding-meta" style="display:flex;gap:0.5rem;font-size:0.75rem">${sevPill(x.severity)}<span>${x.confidence_percent ?? 0}% conf.</span></div></div>`).join("");
    document.querySelectorAll<HTMLElement>(".finding-item").forEach(el => el.addEventListener("click", () => showFindingDetail(Number(el.dataset.id))));
    await refreshFindingsBadge();
}
function showFindingDetail(id: number) {
    const f = allFindings.find(x => x.id === id);
    if (!f) return;
    document.querySelectorAll<HTMLElement>(".finding-item").forEach(el => el.classList.toggle("selected", Number(el.dataset.id) === id));
    $("finding-detail").innerHTML = `<div class="detail-title">${esc(f.title)}</div><div class="detail-meta">${sevPill(f.severity)}<span>${f.confidence_percent ?? 0}%</span><span>· ${f.kind}</span></div><div class="detail-section"><div class="detail-label">Descripción</div><div style="font-size:0.85rem;line-height:1.6">${esc(f.description)}</div></div><div class="detail-section"><div class="detail-label">Evidencias</div><div>${f.evidence_ids.map(eid => `<span class="pill pill-packet" style="margin-right:0.25rem">Frame ${eid}</span>`).join("") || "—"}</div></div>`;
}
$("btn-detect-now").addEventListener("click", async () => {
    if (!currentProjectDir) { setStatus("Abre un proyecto primero"); return; }
    const cfg = anomalyConfigCache ?? await invoke<AnomalyConfigDto>("cmd_get_anomaly_config");
    const r = await run("Detectando anomalías", () => invoke<string>("cmd_detect_anomalies_with_config", { projectDir: currentProjectDir, config: cfg }), true);
    if (r) { setStatus(r); refreshFindings(); }
});
$("btn-config-anomalies").addEventListener("click", async () => {
    if (!anomalyConfigCache) anomalyConfigCache = await invoke<AnomalyConfigDto>("cmd_get_anomaly_config");
    renderAnomalyConfigModal(anomalyConfigCache);
    $("modal-anomaly-config").classList.remove("hidden");
});
function renderAnomalyConfigModal(c: AnomalyConfigDto) {
    $("modal-body").innerHTML = `
        <div class="config-section"><h4>HTTP en puerto no estándar</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_http_on_unusual_port" ${c.enable_http_on_unusual_port ? "checked" : ""} /></div></div>
        <div class="config-section"><h4>TLS sobre puerto 80</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_tls_on_plain_port" ${c.enable_tls_on_plain_port ? "checked" : ""} /></div></div>
        <div class="config-section"><h4>Flujo grande</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_large_flow" ${c.enable_large_flow ? "checked" : ""} /></div><div class="config-row"><label>Umbral (bytes)</label><input type="number" data-key="large_flow_threshold_bytes" value="${c.large_flow_threshold_bytes}" min="1024" /></div></div>
        <div class="config-section"><h4>Beaconing</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_beaconing" ${c.enable_beaconing ? "checked" : ""} /></div><div class="config-row"><label>Conexiones mín.</label><input type="number" data-key="beacon_min_connections" value="${c.beacon_min_connections}" min="3" /></div><div class="config-row"><label>CV máx.</label><input type="number" data-key="beacon_max_cv" value="${c.beacon_max_cv}" step="0.01" min="0.01" max="1" /></div></div>
        <div class="config-section"><h4>DNS tunneling</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_dns_tunneling" ${c.enable_dns_tunneling ? "checked" : ""} /></div><div class="config-row"><label>Long. nombre máx.</label><input type="number" data-key="dns_long_name_threshold" value="${c.dns_long_name_threshold}" min="20" /></div><div class="config-row"><label>Subdominios máx.</label><input type="number" data-key="dns_max_unique_subdomains" value="${c.dns_max_unique_subdomains}" min="5" /></div></div>
        <div class="config-section"><h4>Port scanning</h4><div class="config-row"><label>Activar</label><input type="checkbox" data-key="enable_port_scanning" ${c.enable_port_scanning ? "checked" : ""} /></div><div class="config-row"><label>Destinos máx.</label><input type="number" data-key="portscan_max_distinct_destinations" value="${c.portscan_max_distinct_destinations}" min="5" /></div><div class="config-row"><label>Ventana (ns)</label><input type="number" data-key="portscan_window_ns" value="${c.portscan_window_ns}" min="1000000000" /></div></div>`;
}
function readAnomalyConfigFromModal(): AnomalyConfigDto {
    const r = (k: string, c: boolean): any => { const el = document.querySelector<HTMLInputElement>(`[data-key="${k}"]`); return !el ? null : (c ? el.checked : Number(el.value)); };
    return { enable_http_on_unusual_port: r("enable_http_on_unusual_port", true), enable_tls_on_plain_port: r("enable_tls_on_plain_port", true), enable_large_flow: r("enable_large_flow", true), large_flow_threshold_bytes: r("large_flow_threshold_bytes", false), enable_beaconing: r("enable_beaconing", true), beacon_min_connections: r("beacon_min_connections", false), beacon_max_cv: r("beacon_max_cv", false), enable_dns_tunneling: r("enable_dns_tunneling", true), dns_long_name_threshold: r("dns_long_name_threshold", false), dns_max_unique_subdomains: r("dns_max_unique_subdomains", false), enable_port_scanning: r("enable_port_scanning", true), portscan_max_distinct_destinations: r("portscan_max_distinct_destinations", false), portscan_window_ns: r("portscan_window_ns", false) };
}
$("modal-close").addEventListener("click", () => $("modal-anomaly-config").classList.add("hidden"));
$("btn-config-cancel").addEventListener("click", () => $("modal-anomaly-config").classList.add("hidden"));
$("btn-config-reset").addEventListener("click", async () => { anomalyConfigCache = await invoke<AnomalyConfigDto>("cmd_get_anomaly_config"); renderAnomalyConfigModal(anomalyConfigCache); });
$("btn-config-apply").addEventListener("click", async () => {
    if (!currentProjectDir) { setStatus("Abre un proyecto primero"); return; }
    anomalyConfigCache = readAnomalyConfigFromModal();
    $("modal-anomaly-config").classList.add("hidden");
    const r = await run("Detectando anomalías", () => invoke<string>("cmd_detect_anomalies_with_config", { projectDir: currentProjectDir, config: anomalyConfigCache }), true);
    if (r) { setStatus(r); switchTab("findings"); }
});

async function runBaselineDetection() {
    if (!currentProjectDir) return;
    if (!baselineConfigCache) baselineConfigCache = await invoke<BaselineConfigDto>("cmd_get_baseline_config");
    const r = await run("Detectando baseline", () => invoke<string>("cmd_detect_baseline_anomalies", { projectDir: currentProjectDir, config: baselineConfigCache }), true);
    if (!r) return;
    setStatus(r); $("baseline-message").textContent = r;
    const all = await invoke<FindingDto[]>("cmd_list_findings", { projectDir: currentProjectDir });
    const baselineFindings = all.filter(f => f.title.includes("Desviación estadística"));
    const container = $("baseline-findings-container");
    if (baselineFindings.length === 0) { container.classList.add("hidden"); } else {
        container.classList.remove("hidden");
        $("baseline-findings-table").querySelector("tbody")!.innerHTML = baselineFindings.map(f => `<tr><td>${sevPill(f.severity)}</td><td>${esc(f.title)}</td><td style="font-size:0.78rem">${esc(f.description)}</td></tr>`).join("");
    }
    refreshFindingsBadge();
}
$("btn-detect-baseline").addEventListener("click", runBaselineDetection);
$("btn-config-baseline").addEventListener("click", async () => {
    if (!baselineConfigCache) baselineConfigCache = await invoke<BaselineConfigDto>("cmd_get_baseline_config");
    renderBaselineConfigModal(baselineConfigCache); $("modal-baseline-config").classList.remove("hidden");
});
function renderBaselineConfigModal(c: BaselineConfigDto) {
    $("modal-body-baseline").innerHTML = `
        <div class="config-section"><h4>Muestra mínima</h4><div class="config-row"><label>Activos del mismo tipo</label><input type="number" data-bkey="min_entities_per_kind" value="${c.min_entities_per_kind}" min="2" /></div><div class="config-hint">Por debajo de este número, no se calcula baseline para ese tipo.</div></div>
        <div class="config-section"><h4>Umbrales z-score</h4><div class="config-row"><label>Outlier (bajo)</label><input type="number" data-bkey="modified_zscore_threshold" value="${c.modified_zscore_threshold}" step="0.1" min="1" /></div><div class="config-row"><label>Outlier fuerte (medio)</label><input type="number" data-bkey="high_zscore_threshold" value="${c.high_zscore_threshold}" step="0.1" min="2" /></div><div class="config-hint">Iglewicz-Hoaglin recomienda 3.5 y 5.0.</div></div>
        <div class="config-section"><h4>Flujos mínimos por activo</h4><div class="config-row"><label>Ignorar activos con menos de</label><input type="number" data-bkey="min_flows_per_asset" value="${c.min_flows_per_asset}" min="0" /></div></div>
        <div class="config-section"><h4>Métricas</h4><div class="config-row"><label>Volumen de bytes</label><input type="checkbox" data-bkey="enable_bytes_baseline" ${c.enable_bytes_baseline ? "checked" : ""} /></div><div class="config-row"><label>Número de flujos</label><input type="checkbox" data-bkey="enable_flow_count_baseline" ${c.enable_flow_count_baseline ? "checked" : ""} /></div></div>`;
}
function readBaselineConfigFromModal(): BaselineConfigDto {
    const get = (k: string, c: boolean): any => { const el = document.querySelector<HTMLInputElement>(`[data-bkey="${k}"]`); return !el ? null : (c ? el.checked : Number(el.value)); };
    return { min_entities_per_kind: get("min_entities_per_kind", false), modified_zscore_threshold: get("modified_zscore_threshold", false), high_zscore_threshold: get("high_zscore_threshold", false), min_flows_per_asset: get("min_flows_per_asset", false), enable_bytes_baseline: get("enable_bytes_baseline", true), enable_flow_count_baseline: get("enable_flow_count_baseline", true) };
}
$("modal-close-baseline").addEventListener("click", () => $("modal-baseline-config").classList.add("hidden"));
$("btn-baseline-cancel").addEventListener("click", () => $("modal-baseline-config").classList.add("hidden"));
$("btn-baseline-reset").addEventListener("click", async () => { baselineConfigCache = await invoke<BaselineConfigDto>("cmd_get_baseline_config"); renderBaselineConfigModal(baselineConfigCache); });
$("btn-baseline-apply").addEventListener("click", async () => { baselineConfigCache = readBaselineConfigFromModal(); $("modal-baseline-config").classList.add("hidden"); await runBaselineDetection(); });

async function refreshTimeline() {
    if (!currentProjectDir) return;
    const d = await run("Cargando cronología", () => invoke<TimelineV2Dto>("cmd_get_timeline_v2", { projectDir: currentProjectDir }), true);
    if (!d) return;
    const entries = d.entries;
    $("timeline-meta").textContent = `${entries.length} entradas${d.events_without_timestamp > 0 ? ` · ${d.events_without_timestamp} sin ts` : ""}`;
    const bucketCount = 60;
    if (entries.length > 0) {
        const minTs = entries[entries.length - 1].timestamp_ns; const maxTs = entries[0].timestamp_ns; const span = maxTs - minTs;
        const buckets = Array.from({ length: bucketCount }, () => ({ e: 0, f: 0, start: 0 }));
        if (span > 0) {
            const step = span / bucketCount;
            for (const e of entries) {
                const i = Math.min(bucketCount - 1, Math.floor((e.timestamp_ns - minTs) / step));
                buckets[i].start = minTs + i * step;
                if (e.kind === "Event") buckets[i].e++; else buckets[i].f++;
            }
        }
        const maxC = Math.max(1, ...buckets.map(b => b.e + b.f));
        $("timeline-histogram").innerHTML = buckets.map(b => `<div style="flex:1;background:${b.f > b.e ? "var(--accent)" : "var(--text-muted)"};height:${Math.max(1, ((b.e + b.f) / maxC) * 100)}%;opacity:0.8;border-radius:2px 2px 0 0;transition:height 0.3s" title="${b.e} ev · ${b.f} fl · ${fmtTsShort(b.start)}"></div>`).join("");
    }
    const tb = $("timeline-table").querySelector("tbody")!;
    tb.innerHTML = entries.map(e => {
        if (e.kind === "Event") return `<tr><td style="white-space:nowrap;color:var(--text-muted)">${fmtTsShort(e.timestamp_ns)}</td><td>${kindPill(e.event_kind || "Event")}</td><td>${esc(e.event_summary || "")}</td><td style="font-size:0.72rem;color:var(--text-muted)">${e.evidence_ids.map(id => `F${id}`).join(", ")}</td></tr>`;
        return `<tr><td style="white-space:nowrap;color:var(--text-muted)">${fmtTsShort(e.timestamp_ns)}</td><td><span class="pill pill-tls">Flow</span></td><td>${esc(e.flow_endpoint_a || "")} ↔ ${esc(e.flow_endpoint_b || "")} · ${e.flow_packet_count} pkts · ${fmtBytes(e.flow_captured_bytes || 0)}</td><td style="font-size:0.72rem;color:var(--text-muted)">${e.evidence_ids.map(id => `F${id}`).join(", ")}</td></tr>`;
    }).join("");
}

// ==========================================
// LIVE CAPTURE
// ==========================================
async function loadInterfaces() {
    const select = $("live-interface") as HTMLSelectElement;
    select.innerHTML = `<option value="">Buscando interfaces...</option>`;
    
    try {
        const interfaces = await invoke<string[]>("cmd_list_interfaces");
        if (interfaces.length === 0) { 
            select.innerHTML = `<option value="">No se encontraron interfaces</option>`; 
            return; 
        }
        select.innerHTML = interfaces.map(i => `<option value="${i}">${i}</option>`).join("");
    } catch (e) {
        console.error(e);
        select.innerHTML = `<option value="">Error al cargar</option>`;
        alert(`Error al listar interfaces:\n${e}`);
    }
}

$("btn-start-live").addEventListener("click", async () => {
    if (!currentProjectDir) { alert("Por favor, abre o crea un proyecto primero."); return; }
    const iface = ($("live-interface") as HTMLSelectElement).value;
    if (!iface) return;
    showLoading(`Iniciando captura en ${iface}...`);
    try {
        await invoke("cmd_start_live_capture", { projectDir: currentProjectDir, interface: iface });
        hideLoading();
        $("btn-start-live").classList.add("hidden"); $("btn-stop-live").classList.remove("hidden");
        const status = $("live-status"); status.textContent = `Capturando...`; status.classList.add("active");
    } catch (e) { hideLoading(); alert(`Error al iniciar: ${e}`); }
});

$("btn-stop-live").addEventListener("click", async () => {
    showLoading("Procesando captura... Esto puede tardar unos segundos.");
    try {
        const r = await invoke<string>("cmd_stop_live_capture", { projectDir: currentProjectDir });
        hideLoading();
        
        $("btn-start-live").classList.remove("hidden"); $("btn-stop-live").classList.add("hidden");
        const status = $("live-status"); status.textContent = `Inactivo`; status.classList.remove("active");
        
        alert(r); // Mensaje de éxito
        switchTab("events"); // Llevar al usuario a ver los eventos
        refreshEvents(); // Actualizar los datos
        refreshFindingsBadge();
    } catch (e) {
        hideLoading();
        alert(`Error al detener: ${e}`);
    }
});

async function exportAs(kind: "md" | "csv" | "json" | "html") {
    if (!currentProjectDir) { setStatus("Abre un proyecto primero"); return; }
    const ext = kind;
    const name = kind === "md" ? "informe.md" : kind === "html" ? "informe.html" : `eventos.${ext}`;
    const path = await save({ defaultPath: name, filters: [{ name: kind.toUpperCase(), extensions: [ext] }] });
    if (!path) return;
    const cmd = kind === "md" ? "cmd_export_markdown" : kind === "csv" ? "cmd_export_csv" : kind === "json" ? "cmd_export_json" : "cmd_export_report_html";
    const r = await run(`Exportando ${ext.toUpperCase()}`, () => invoke<string>(cmd, { projectDir: currentProjectDir, outputPath: path }), true);
    if (r) setStatus(r);
}
$("btn-export-md").addEventListener("click", () => exportAs("md"));
$("btn-export-html").addEventListener("click", () => exportAs("html"));
$("btn-export-csv").addEventListener("click", () => exportAs("csv"));
$("btn-export-json").addEventListener("click", () => exportAs("json"));

setStatus("Listo · Importa un PCAP o abre un proyecto");