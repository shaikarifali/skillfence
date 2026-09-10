"""The dashboard's single HTML page. Deliberately self-contained -- no CDN
script, no build step, no external network request of any kind. This is a
local, offline-first tool (same reasoning as the Docker network-isolated
install path): it must render correctly on a machine with no internet
access, air-gapped or not.
"""

from __future__ import annotations

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SkillFence Dashboard</title>
<style>
  :root {
    --bg: #0f1115; --panel: #171a21; --border: #2a2e3a; --text: #e6e8ec;
    --dim: #8b93a3; --accent: #4f8cff;
    --low: #5b8c5a; --medium: #c9a227; --high: #d9772b; --critical: #d9455a; --none: #4a5060;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--text);
    font: 14px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  header {
    display: flex; align-items: center; gap: 12px; padding: 12px 18px;
    border-bottom: 1px solid var(--border); background: var(--panel);
  }
  header h1 { font-size: 15px; margin: 0; font-weight: 600; }
  header .root { color: var(--dim); font-size: 12px; font-family: monospace; }
  header .spacer { flex: 1; }
  header label { color: var(--dim); font-size: 12px; display: flex; align-items: center; gap: 6px; }
  #layout { display: flex; height: calc(100vh - 46px); }
  #sidebar {
    width: 300px; flex-shrink: 0; overflow-y: auto; border-right: 1px solid var(--border);
    background: var(--panel);
  }
  .session-row {
    padding: 10px 14px; border-bottom: 1px solid var(--border); cursor: pointer;
  }
  .session-row:hover { background: #1e222c; }
  .session-row.selected { background: #1c2433; border-left: 3px solid var(--accent); }
  .session-row .skill { font-weight: 600; font-size: 13px; }
  .session-row .meta { color: var(--dim); font-size: 11px; margin-top: 2px; }
  .badge {
    display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 11px;
    font-weight: 600; text-transform: uppercase; color: #0f1115;
  }
  .badge.low { background: var(--low); }
  .badge.medium { background: var(--medium); }
  .badge.high { background: var(--high); }
  .badge.critical { background: var(--critical); color: #fff; }
  .badge.none { background: var(--none); color: var(--text); }
  #main { flex: 1; overflow-y: auto; padding: 18px 24px; }
  #empty { color: var(--dim); padding: 40px; text-align: center; }
  h2 { font-size: 14px; text-transform: uppercase; letter-spacing: .04em; color: var(--dim);
       margin: 24px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
  h2:first-child { margin-top: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; color: var(--dim); font-weight: 500; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  td { padding: 6px 8px; border-bottom: 1px solid #1c1f28; vertical-align: top; }
  tr.finding-row.critical td:first-child { border-left: 3px solid var(--critical); }
  tr.finding-row.high td:first-child { border-left: 3px solid var(--high); }
  tr.finding-row.medium td:first-child { border-left: 3px solid var(--medium); }
  tr.finding-row.low td:first-child { border-left: 3px solid var(--low); }
  .cds-bar-track { width: 90px; height: 8px; background: #262b36; border-radius: 4px; overflow: hidden; display: inline-block; vertical-align: middle; }
  .cds-bar-fill { height: 100%; }
  .why { color: var(--dim); font-size: 12px; }
  .why ul { margin: 2px 0 0; padding-left: 16px; }
  .tag { display: inline-block; background: #262b36; color: var(--dim); border-radius: 4px; padding: 0 5px; margin-right: 3px; font-size: 11px; font-family: monospace; }
  .prov-tree { font-family: monospace; font-size: 12px; }
  .prov-node { padding: 3px 0 3px 0; }
  .prov-node .prov-type { color: var(--accent); }
  .prov-node .prov-resource { color: var(--dim); }
  .prov-node .prov-decision { float: right; font-size: 11px; }
  .decision-allowed, .decision-approved_once { color: var(--low); }
  .decision-rejected, .decision-quarantined { color: var(--critical); }
  .decision-pending { color: var(--dim); }
  details.prov-node > summary { cursor: pointer; list-style: none; }
  details.prov-node > summary::-webkit-details-marker { display: none; }
  .prov-children { margin-left: 18px; border-left: 1px dashed var(--border); padding-left: 10px; }
  #events-log { max-height: 280px; overflow-y: auto; font-family: monospace; font-size: 11.5px; }
  #events-log div { padding: 2px 0; border-bottom: 1px solid #1c1f28; }
  #events-log .ts { color: var(--dim); }
  button, select {
    background: #1c2029; color: var(--text); border: 1px solid var(--border);
    border-radius: 4px; padding: 4px 10px; font-size: 12px; cursor: pointer;
  }
  button:hover { border-color: var(--accent); }
</style>
</head>
<body>
<header>
  <h1>SkillFence Dashboard</h1>
  <span class="root" id="root-path"></span>
  <div class="spacer"></div>
  <label><input type="checkbox" id="auto-refresh" checked> auto-refresh</label>
  <button id="refresh-btn">Refresh</button>
</header>
<div id="layout">
  <div id="sidebar"></div>
  <div id="main"><div id="empty">Select a session on the left.</div></div>
</div>
<script>
const SEV_ORDER = {critical: 4, high: 3, medium: 2, low: 1, none: 0};
let selectedId = null;
let pollTimer = null;

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return res.json();
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}

function fmtTime(ts) {
  if (!ts) return "";
  return ts.replace("T", " ").replace(/\\.\\d+.*/, "").replace("+00:00", "Z");
}

async function loadSessions() {
  const root = await fetchJSON("/api/root");
  document.getElementById("root-path").textContent = root.path;

  const sessions = await fetchJSON("/api/sessions");
  const sidebar = document.getElementById("sidebar");
  sidebar.innerHTML = "";
  if (sessions.length === 0) {
    sidebar.innerHTML = '<div style="padding:16px;color:var(--dim);font-size:12px;">No sessions found yet under this root.</div>';
    return;
  }
  for (const s of sessions) {
    const row = document.createElement("div");
    row.className = "session-row" + (s.session_id === selectedId ? " selected" : "");
    row.onclick = () => selectSession(s.session_id);
    row.innerHTML = `
      <div class="skill">${esc(s.skill || s.session_id)}</div>
      <div class="meta">${esc(s.source_dir)}</div>
      <div class="meta">
        <span class="badge ${esc(s.highest_severity)}">${esc(s.highest_severity)}</span>
        &nbsp;${s.finding_count} finding(s) &middot; ${s.event_count} event(s)
      </div>
      <div class="meta">${fmtTime(s.last_timestamp)}</div>
    `;
    sidebar.appendChild(row);
  }
  if (selectedId && !sessions.some(s => s.session_id === selectedId)) selectedId = null;
}

function severityRank(sev) { return SEV_ORDER[sev] ?? 0; }

function renderFindings(findings) {
  if (findings.length === 0) return '<div style="color:var(--dim);font-size:13px;">No findings recorded for this session.</div>';
  const sorted = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const rows = sorted.map(f => {
    const cdsPct = Math.round((f.cds || 0) * 100);
    const cdsColor = {ALLOW: "var(--low)", WARN: "var(--medium)", GATE: "var(--high)", BLOCK: "var(--critical)"}[f.cds_band] || "var(--dim)";
    const tags = (f.ast || []).map(t => `<span class="tag">${esc(t)}</span>`).join("");
    const why = (f.why_flagged || []).map(r => `<li>${esc(r)}</li>`).join("");
    return `
      <tr class="finding-row ${esc(f.severity)}">
        <td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
        <td>
          <div><strong>${esc(f.title)}</strong></div>
          <div>${tags}</div>
          <div class="why"><ul>${why}</ul></div>
        </td>
        <td>${esc(f.resource || "-")}</td>
        <td>
          <span class="cds-bar-track"><span class="cds-bar-fill" style="width:${cdsPct}%;background:${cdsColor}"></span></span>
          <div style="font-size:11px;color:var(--dim);">${(f.cds ?? 0).toFixed(2)} (${esc(f.cds_band || "-")})</div>
        </td>
        <td>${esc(f.human_decision || f.status || "pending")}</td>
      </tr>`;
  }).join("");
  return `<table><thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Drift Score</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function buildTree(events) {
  const byId = {};
  events.forEach(e => byId[e.event_id] = {event: e, children: []});
  const roots = [];
  events.forEach(e => {
    const node = byId[e.event_id];
    if (e.parent_event && byId[e.parent_event]) byId[e.parent_event].children.push(node);
    else roots.push(node);
  });
  return roots;
}

function renderNode(node) {
  const e = node.event;
  const label = `<span class="prov-type">${esc(e.event_type)}</span> <span class="prov-resource">${esc(e.resource || "")}</span>`;
  // "pending" only ever persists for events that are never individually
  // gated (skill.load, human_decision.made, tool.denied, ...) -- the one
  // gated action in a chain always resolves to a real decision. Showing
  // "pending" next to those non-gated events reads as unfinished business
  // it isn't, so it's omitted rather than displayed.
  const decision = e.decision === "pending" ? "" : `<span class="prov-decision decision-${esc(e.decision)}">${esc(e.decision)}</span>`;
  if (node.children.length === 0) {
    return `<div class="prov-node">${label}${decision}</div>`;
  }
  const children = node.children.map(renderNode).join("");
  return `<details class="prov-node" open><summary>${label}${decision}</summary><div class="prov-children">${children}</div></details>`;
}

function renderProvenance(events) {
  if (events.length === 0) return '<div style="color:var(--dim);font-size:13px;">No events recorded.</div>';
  const roots = buildTree(events);
  return `<div class="prov-tree">${roots.map(renderNode).join("")}</div>`;
}

function renderEventsLog(events) {
  if (events.length === 0) return "";
  return events.map(e =>
    `<div><span class="ts">${fmtTime(e.timestamp)}</span> &nbsp;${esc(e.event_type)} &nbsp;<span style="color:var(--dim)">${esc(e.resource || "")}</span> &nbsp;<strong>${e.decision === "pending" ? "" : esc(e.decision)}</strong></div>`
  ).join("");
}

async function selectSession(id) {
  selectedId = id;
  await loadSessions();
  const detail = await fetchJSON(`/api/session/${encodeURIComponent(id)}`);
  const main = document.getElementById("main");
  const s = detail.session;
  main.innerHTML = `
    <h2>${esc(s.skill || s.session_id)} — Findings</h2>
    ${renderFindings(detail.findings)}
    <h2>Provenance</h2>
    ${renderProvenance(detail.events)}
    <h2>Raw Events (${detail.events.length})</h2>
    <div id="events-log">${renderEventsLog(detail.events)}</div>
  `;
}

async function refresh() {
  await loadSessions();
  if (selectedId) {
    try { await selectSession(selectedId); } catch (e) { /* session may have been removed */ }
  }
}

document.getElementById("refresh-btn").onclick = refresh;
document.getElementById("auto-refresh").onchange = (e) => {
  if (e.target.checked) pollTimer = setInterval(refresh, 3000);
  else clearInterval(pollTimer);
};

refresh();
pollTimer = setInterval(refresh, 3000);
</script>
</body>
</html>
"""
