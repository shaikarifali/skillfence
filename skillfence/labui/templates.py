"""The Lab Explorer's single HTML page.

Visual identity matches `docs/DVAS-Labs-Demo.html` (the case-file catalog)
deliberately — same tokens, same serif/mono pairing, same devcard/editor/
terminal components — because this is meant to feel like the live version
of that same tool, not a different-looking one. The one real difference:
that catalog is a browser Artifact and can load Google Fonts from a CDN.
This page ships inside the pip package and has to render correctly with
no internet access at all (same reasoning as `dashboard.templates` — an
air-gapped machine is a real, supported case), so the serif/mono stacks
here lean on their own system-font fallbacks instead of a webfont.
"""

from __future__ import annotations

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SkillFence Lab Explorer</title>
<style>
:root{
  --bg:#EEF0EC; --surface:#FFFFFF; --surface-2:#E4E7E1; --surface-3:#DCE0D8;
  --ink:#16201D; --ink-dim:#5C6B62; --ink-faint:#8A968E;
  --rule:#CBD1C7; --rule-strong:#AEB6A9;
  --accent:#0E6E5C; --accent-strong:#0A4F42; --accent-wash:#DFEDE8;
  --sev-critical:#B3261E; --sev-critical-wash:#F6DEDB;
  --sev-high:#A15A16; --sev-high-wash:#F3E4D2;
  --sev-medium:#7A6A16; --sev-medium-wash:#EFE9CE;
  --sev-allow:#2E7D4F; --sev-allow-wash:#DCEEE1;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Consolas, monospace;
  --serif: Georgia, "Source Serif 4", "Times New Roman", serif;
  --shadow: 0 1px 2px rgba(22,32,29,.06), 0 6px 20px -8px rgba(22,32,29,.18);
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#101715; --surface:#182220; --surface-2:#1F2B28; --surface-3:#26332F;
    --ink:#E7ECE7; --ink-dim:#93A69C; --ink-faint:#647670;
    --rule:#2B3733; --rule-strong:#3A4844;
    --accent:#4FD8B8; --accent-strong:#7FE6CB; --accent-wash:#1B3833;
    --sev-critical:#FF8A7A; --sev-critical-wash:#3A211D;
    --sev-high:#F0B15C; --sev-high-wash:#382C18;
    --sev-medium:#E3D27E; --sev-medium-wash:#33301A;
    --sev-allow:#7FE0A6; --sev-allow-wash:#1B3527;
    --shadow: 0 1px 2px rgba(0,0,0,.3), 0 10px 28px -10px rgba(0,0,0,.55);
  }
}
/* fixed-dark editor/terminal palette -- deliberately NOT theme-tokenized:
   a code-editor/terminal surface reads the same in both page themes, the
   way an IDE panel does. */
:root{
  --ed-bg:#151A18; --ed-bg-2:#1B211E; --ed-text:#D6DCD6;
  --ed-rule:#2A322E; --ed-accent:#7FE6CB; --ed-heading:#E8B36B;
  --term-bg:#0E1412; --term-text:#CBD3CD; --term-dim:#7C8A83; --term-accent:#7FE6CB;
  --term-warn:#F0B15C; --term-crit:#FF8A7A; --term-ok:#8FE0A6;
}

*{box-sizing:border-box;}
html,body{height:100%;}
body{ background:var(--bg); color:var(--ink); margin:0; font-family:var(--serif); font-size:15px; line-height:1.6; }
h1,h2,h3,h4,.mono,.chip,.tag,.wordmark,.evidence-th{ font-family:var(--mono); }
h1,h2,h3{ text-wrap:balance; font-weight:600; margin:0; }
p{ margin:0; }
::selection{ background:var(--accent-wash); }
button,select,input{ font:inherit; }

.topbar{ display:flex; align-items:center; gap:16px; padding:12px 22px; border-bottom:1px solid var(--rule); background:var(--surface); box-shadow:var(--shadow); position:relative; z-index:2; }
.wordmark{ font-weight:700; font-size:14px; letter-spacing:.02em; white-space:nowrap; }
.wordmark span{ color:var(--accent-strong); }
.root-path{ color:var(--ink-faint); font-size:11.5px; font-family:var(--mono); }
.spacer{ flex:1; }
.topbar button{ background:var(--surface-2); color:var(--ink); border:1px solid var(--rule); border-radius:6px; padding:6px 12px; font-size:12px; cursor:pointer; }
.topbar button:hover{ border-color:var(--accent); color:var(--accent-strong); }

.shell{ display:flex; height:calc(100vh - 49px); }
#sidebar{ width:340px; flex-shrink:0; overflow-y:auto; border-right:1px solid var(--rule); background:var(--surface); }
.filter-wrap{ padding:12px 14px; border-bottom:1px solid var(--rule); position:sticky; top:0; background:var(--surface); z-index:1; }
.filter-wrap input{ width:100%; background:var(--surface-2); color:var(--ink); border:1px solid var(--rule); border-radius:6px; padding:7px 10px; font-size:12.5px; }
.filter-wrap input:focus{ outline:none; border-color:var(--accent); }
.cat-header{ padding:9px 14px; font-size:10.5px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; color:var(--ink-faint); background:var(--surface-2); border-bottom:1px solid var(--rule); border-top:1px solid var(--rule); }
.lab-row{ padding:10px 14px; border-bottom:1px solid var(--rule); cursor:pointer; transition:background .1s ease; }
.lab-row:hover{ background:var(--surface-2); }
.lab-row.selected{ background:var(--accent-wash); border-left:3px solid var(--accent); padding-left:11px; }
.lab-row .skill{ font-family:var(--serif); font-weight:600; font-size:13.5px; color:var(--ink); }
.lab-row .meta{ color:var(--ink-faint); font-size:11px; font-family:var(--mono); margin-top:3px; }

#main{ flex:1; overflow-y:auto; padding:32px 40px 60px; }
#empty{ max-width:60ch; margin:80px auto; color:var(--ink-dim); font-size:15px; text-align:center; line-height:1.7; }
#empty code{ background:var(--surface-2); border:1px solid var(--rule); border-radius:4px; padding:1px 5px; font-size:.9em; }

.case-id{ font-family:var(--mono); font-size:12px; font-weight:700; color:var(--accent-strong); letter-spacing:.04em; }
.case-title{ font-family:var(--serif); font-weight:600; font-size:30px; margin-top:4px; }
.case-sub{ color:var(--ink-dim); font-size:13px; font-family:var(--mono); margin-top:6px; }
.case-meta{ margin-top:14px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }

.chip{ display:inline-flex; align-items:center; gap:5px; font-size:11px; font-weight:600; letter-spacing:.03em; padding:3px 9px; border-radius:100px; white-space:nowrap; }
.chip::before{ content:''; width:6px; height:6px; border-radius:50%; background:currentColor; }
.chip-critical{ color:var(--sev-critical); background:var(--sev-critical-wash); }
.chip-high{ color:var(--sev-high); background:var(--sev-high-wash); }
.chip-medium{ color:var(--sev-medium); background:var(--sev-medium-wash); }
.chip-low, .chip-allow{ color:var(--sev-allow); background:var(--sev-allow-wash); }
.chip-none{ color:var(--ink-faint); background:var(--surface-2); }
.tag{ display:inline-block; font-size:10.5px; font-weight:600; letter-spacing:.02em; color:var(--ink-dim); background:var(--surface-2); border:1px solid var(--rule); padding:2px 7px; border-radius:4px; }

.story{ margin-top:22px; padding:20px 24px; background:var(--surface); border:1px solid var(--rule); border-left:3px solid var(--accent); border-radius:2px 8px 8px 2px; box-shadow:var(--shadow); }
.story-label{ font-size:10.5px; font-weight:600; letter-spacing:.08em; text-transform:uppercase; color:var(--accent-strong); margin-bottom:10px; }
.story p{ font-family:var(--serif); font-size:15px; color:var(--ink); max-width:74ch; }

.section-label{ margin-top:30px; margin-bottom:10px; font-size:11px; font-weight:600; letter-spacing:.08em; text-transform:uppercase; color:var(--ink-faint); border-bottom:1px solid var(--rule); padding-bottom:6px; }

.ledger{ border:1px solid var(--rule); border-radius:8px; overflow:hidden; background:var(--surface); box-shadow:var(--shadow); }
table.evidence{ width:100%; border-collapse:collapse; }
.evidence-th{ text-align:left; font-size:10.5px; font-weight:600; letter-spacing:.06em; text-transform:uppercase; color:var(--ink-faint); padding:9px 14px; border-bottom:1px solid var(--rule); background:var(--surface-2); }
.evidence-cell{ padding:9px 14px; border-bottom:1px solid var(--rule); font-size:13px; vertical-align:top; font-family:var(--mono); }
tr:last-child .evidence-cell{ border-bottom:none; }
.evidence-cell.k{ color:var(--ink-dim); font-family:var(--serif); width:160px; }

.editor{ margin-top:6px; border:1px solid var(--ed-rule); border-radius:8px; overflow:hidden; box-shadow:var(--shadow); }
.editor-tabs{ display:flex; background:var(--ed-bg-2); border-bottom:1px solid var(--ed-rule); }
.editor-tab{ font-family:var(--mono); font-size:11.5px; color:var(--term-dim); padding:9px 16px; cursor:pointer; border-right:1px solid var(--ed-rule); background:transparent; }
.editor-tab.active{ color:var(--ed-text); background:var(--ed-bg); font-weight:600; }
.editor-tab:hover:not(.active){ color:var(--ed-text); }
.editor-body{ background:var(--ed-bg); max-height:360px; overflow-y:auto; padding:14px 16px; }
.editor-body pre{ margin:0; font-family:var(--mono); font-size:12.5px; line-height:1.65; white-space:pre-wrap; word-break:break-word; color:var(--ed-text); }
.code-panel{ display:none; } .code-panel.active{ display:block; }

.run-bar{ margin-top:26px; display:flex; align-items:center; gap:12px; padding:14px 18px; background:var(--accent-wash); border:1px solid var(--rule); border-radius:8px; flex-wrap:wrap; }
.run-bar label{ color:var(--ink-dim); font-size:12px; font-family:var(--mono); }
.run-bar select{ background:var(--surface); color:var(--ink); border:1px solid var(--rule-strong); border-radius:6px; padding:6px 10px; font-size:12.5px; }
.run-btn{ display:flex; align-items:center; gap:8px; background:var(--accent); color:#fff; border:1px solid var(--accent-strong); border-radius:6px; padding:7px 16px; font-size:12.5px; font-weight:700; cursor:pointer; }
.run-btn:hover:not(:disabled){ background:var(--accent-strong); }
.run-btn:disabled{ opacity:.45; cursor:default; }
#run-status{ font-size:12px; color:var(--ink-dim); font-family:var(--mono); }

.steps-table, .findings-table{ width:100%; border-collapse:collapse; font-size:13px; }
.steps-table th, .findings-table th{ text-align:left; color:var(--ink-faint); font-weight:600; font-size:10.5px; letter-spacing:.05em; text-transform:uppercase; padding:8px 12px; border-bottom:1px solid var(--rule); }
.steps-table td, .findings-table td{ padding:9px 12px; border-bottom:1px solid var(--rule); vertical-align:top; }
tr.finding-row.critical td:first-child{ border-left:3px solid var(--sev-critical); }
tr.finding-row.high td:first-child{ border-left:3px solid var(--sev-high); }
tr.finding-row.medium td:first-child{ border-left:3px solid var(--sev-medium); }
tr.finding-row.low td:first-child{ border-left:3px solid var(--sev-allow); }
.status-ok{ color:var(--sev-allow); font-weight:600; } .status-blocked{ color:var(--sev-critical); font-weight:700; } .status-error{ color:var(--sev-medium); font-weight:600; }
.cds-track{ width:80px; height:7px; background:var(--surface-3); border-radius:4px; overflow:hidden; display:inline-block; vertical-align:middle; }
.cds-fill{ height:100%; }
.why ul{ margin:4px 0 0; padding-left:16px; color:var(--ink-dim); font-size:12px; font-family:var(--serif); }
.no-findings{ color:var(--sev-allow); font-size:13.5px; font-weight:600; padding:14px 0; }

.terminal{ margin-top:14px; border-radius:8px; overflow:hidden; border:1px solid var(--ed-rule); box-shadow:var(--shadow); }
.terminal-bar{ display:flex; align-items:center; gap:6px; padding:8px 12px; background:var(--ed-bg-2); border-bottom:1px solid var(--ed-rule); }
.terminal-dot{ width:8px; height:8px; border-radius:50%; background:#3A4440; }
.terminal-bar span{ font-family:var(--mono); font-size:10.5px; color:var(--term-dim); margin-left:6px; }
.terminal-body{ background:var(--term-bg); padding:14px 16px; font-family:var(--mono); font-size:12px; line-height:1.7; white-space:pre-wrap; color:var(--term-text); max-height:340px; overflow-y:auto; }

@media (prefers-reduced-motion: reduce){ *{ transition:none !important; } }
button:focus-visible, .lab-row:focus-visible, .editor-tab:focus-visible{ outline:2px solid var(--accent); outline-offset:2px; }
@media (max-width: 760px){ #sidebar{ width:220px; } #main{ padding:20px 18px; } }
</style>
</head>
<body>
<div class="topbar">
  <div class="wordmark">SkillFence<span>/</span>LAB EXPLORER</div>
  <div class="root-path" id="root-path"></div>
  <div class="spacer"></div>
  <button id="refresh-btn">&#8635; Refresh</button>
</div>
<div class="shell">
  <div id="sidebar">
    <div class="filter-wrap"><input id="filter" type="text" placeholder="Filter labs by name or skill…"></div>
    <div id="lab-list"></div>
  </div>
  <div id="main">
    <div id="empty">Select a lab on the left. Every field shown is read live from its real files —
    <code>skill/manifest.yaml</code>, <code>skill/SKILL.md</code>, <code>README.md</code>, <code>ground-truth.yaml</code> —
    and <strong>Run</strong> actually executes it through the real SkillFence engine, the same as
    <code>skillfence run</code> from a terminal.</div>
  </div>
</div>
<script>
let ALL_LABS = [];
let selectedName = null;

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || (url + ": " + res.status));
  return body;
}
function esc(s) {
  return String(s === undefined || s === null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
}
function sevChip(sev) {
  const s = (sev || "none").toLowerCase();
  return `<span class="chip chip-${esc(s)}">${esc(s)}</span>`;
}

async function loadLabs() {
  const root = await fetchJSON("/api/root");
  document.getElementById("root-path").textContent = root.path;
  ALL_LABS = await fetchJSON("/api/labs");
  renderSidebar();
}

function renderSidebar() {
  const filterText = document.getElementById("filter").value.trim().toLowerCase();
  const list = document.getElementById("lab-list");
  list.innerHTML = "";
  if (ALL_LABS.length === 0) {
    list.innerHTML = '<div style="padding:18px;color:var(--ink-faint);font-size:12px;">No labs found under this root.</div>';
    return;
  }
  const byAst = {};
  for (const lab of ALL_LABS) {
    if (filterText && !(lab.name.toLowerCase().includes(filterText) || (lab.skill_name || "").toLowerCase().includes(filterText))) continue;
    (byAst[lab.ast] = byAst[lab.ast] || []).push(lab);
  }
  const asts = Object.keys(byAst).sort();
  if (asts.length === 0) {
    list.innerHTML = '<div style="padding:18px;color:var(--ink-faint);font-size:12px;">No labs match that filter.</div>';
    return;
  }
  for (const ast of asts) {
    const header = document.createElement("div");
    header.className = "cat-header";
    header.textContent = `${ast} (${byAst[ast].length})`;
    list.appendChild(header);
    for (const lab of byAst[ast]) {
      const row = document.createElement("div");
      row.className = "lab-row" + (lab.name === selectedName ? " selected" : "");
      row.onclick = () => selectLab(lab.name);
      const verdict = lab.malicious === null ? "" : `<span class="chip ${lab.malicious ? "chip-critical" : "chip-low"}">${lab.malicious ? "malicious" : "benign"}</span>`;
      row.innerHTML = `<div class="skill">${esc(lab.title || lab.skill_name)}</div>
        <div class="meta">${esc(lab.name)}</div>
        <div style="margin-top:5px;">${verdict}</div>`;
      list.appendChild(row);
    }
  }
}

function evRow(k, v) { return `<tr><td class="evidence-cell k">${esc(k)}</td><td class="evidence-cell">${v}</td></tr>`; }

function renderCapabilities(caps, security) {
  const fs = caps.filesystem || {}, proc = caps.process || {}, net = caps.network || {}, sec = caps.secrets || {};
  const netVal = net.enabled ? (net.domains && net.domains.length ? esc(net.domains.join(", ")) : "<em>enabled, unrestricted</em>") : "disabled";
  let rows = [
    evRow("filesystem.read", esc((fs.read || []).join(", ")) || "[]"),
    evRow("filesystem.write", esc((fs.write || []).join(", ")) || "[]"),
    evRow("process.execute", esc((proc.execute || []).join(", ")) || "[]"),
    evRow("network", netVal),
    evRow("secrets.access", sec.access ? "true" : "false"),
  ];
  if (security && security.scanned) {
    rows.push(evRow("security.scanned", `true (${esc(security.scan_tool || "unspecified tool")})`));
  }
  return `<div class="ledger"><table class="evidence"><tbody>${rows.join("")}</tbody></table></div>`;
}

function renderFileTabs(name, skillMd, readme) {
  const tabs = [], panels = [];
  if (skillMd) { tabs.push(["skillmd", "SKILL.md"]); panels.push(["skillmd", skillMd]); }
  if (readme) { tabs.push(["readme", "README.md"]); panels.push(["readme", readme]); }
  if (tabs.length === 0) return "";
  const key = name.replace(/[^a-zA-Z0-9]/g, "-");
  const tabsHtml = tabs.map((t, i) => `<div class="editor-tab${i === 0 ? " active" : ""}" data-panel="ft-${key}-${t[0]}">${t[1]}</div>`).join("");
  const panelsHtml = panels.map((p, i) => `<div class="code-panel${i === 0 ? " active" : ""}" id="ft-${key}-${p[0]}"><pre>${esc(p[1])}</pre></div>`).join("");
  return `<div class="editor"><div class="editor-tabs">${tabsHtml}</div><div class="editor-body">${panelsHtml}</div></div>`;
}

function renderGroundTruth(gt) {
  if (!gt) return "";
  const ef = gt.expected_finding || {};
  const isMalicious = gt.ground_truth && gt.ground_truth.malicious;
  return `<div class="case-meta" style="margin-top:10px;">
    <span class="tag">expected: ${isMalicious ? "malicious" : "benign"}</span>
    ${(ef.ast || []).map(t => `<span class="tag">${esc(t)}</span>`).join("")}
    ${ef.severity_at_least ? `<span class="tag">severity &ge; ${esc(ef.severity_at_least)}</span>` : ""}
  </div>`;
}

async function selectLab(name) {
  selectedName = name;
  renderSidebar();
  const detail = await fetchJSON(`/api/lab/${name.split("/").map(encodeURIComponent).join("/")}`);
  const main = document.getElementById("main");
  main.innerHTML = `
    <div class="case-id">${esc(detail.ast)}</div>
    <div class="case-title">${esc(detail.skill_name)}</div>
    <div class="case-sub">${esc(detail.name)} &middot; v${esc(detail.version)}${detail.session_count ? ` &middot; ${detail.session_count} run(s) recorded` : " &middot; never run"}</div>
    <div class="case-meta">${(detail.purpose || []).map(p => `<span class="tag">${esc(p)}</span>`).join("")}</div>
    ${renderGroundTruth(detail.ground_truth)}
    <div class="story"><div class="story-label">Declared capabilities</div>${renderCapabilities(detail.capabilities, detail.security)}</div>
    <div class="section-label">Files</div>
    ${renderFileTabs(detail.name, detail.skill_md, detail.readme) || "<p style='color:var(--ink-faint);font-size:13px;'>No SKILL.md or README.md found.</p>"}
    <div class="section-label">Run</div>
    <div class="run-bar">
      <label>Decision on gate</label>
      <select id="decision-select">
        <option value="reject">reject</option>
        <option value="approve_once">approve_once</option>
        <option value="allow_for_session">allow_for_session</option>
        <option value="allow_scoped">allow_scoped</option>
        <option value="quarantine_skill">quarantine_skill</option>
      </select>
      <button class="run-btn" id="run-btn" ${detail.runnable ? "" : "disabled"}>&#9654; Run</button>
      <span id="run-status"></span>
    </div>
    <div id="run-result"></div>
  `;
  document.querySelectorAll(".editor-tab").forEach(tab => {
    tab.onclick = () => {
      const tabs = tab.parentElement, body = tabs.nextElementSibling;
      tabs.querySelectorAll(".editor-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      body.querySelectorAll(".code-panel").forEach(p => p.classList.remove("active"));
      document.getElementById(tab.getAttribute("data-panel")).classList.add("active");
    };
  });
  if (detail.runnable) document.getElementById("run-btn").onclick = () => runLab(detail.name);
}

function renderSteps(steps) {
  if (!steps.length) return "";
  const rows = steps.map(s => `<tr><td>${esc(s.action)}</td><td class="status-${esc(s.status)}">${esc(s.status)}</td><td>${esc(s.detail || "")}</td></tr>`).join("");
  return `<div class="section-label">Run steps</div><table class="steps-table"><thead><tr><th>Action</th><th>Status</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderFindings(findings) {
  if (!findings.length) return '<div class="no-findings">&#10003; No findings — every action stayed within declared capability / low risk.</div>';
  const rank = {critical:4, high:3, medium:2, low:1, none:0};
  const sorted = [...findings].sort((a, b) => (rank[b.severity]||0) - (rank[a.severity]||0));
  const rows = sorted.map(f => {
    const cdsPct = Math.round((f.cds || 0) * 100);
    const cdsColor = {ALLOW:"var(--sev-allow)", WARN:"var(--sev-medium)", GATE:"var(--sev-high)", BLOCK:"var(--sev-critical)"}[f.cds_band] || "var(--ink-faint)";
    const tags = (f.ast || []).map(t => `<span class="tag">${esc(t)}</span>`).join(" ");
    const why = (f.why_flagged || []).map(r => `<li>${esc(r)}</li>`).join("");
    return `<tr class="finding-row ${esc(f.severity)}">
      <td>${sevChip(f.severity)}</td>
      <td><div style="font-weight:600;">${esc(f.title)}</div><div style="margin-top:3px;">${tags}</div><div class="why"><ul>${why}</ul></div></td>
      <td style="font-family:var(--mono);font-size:12px;">${esc(f.resource || "-")}</td>
      <td><span class="cds-track"><span class="cds-fill" style="width:${cdsPct}%;background:${cdsColor}"></span></span>
          <div style="font-size:11px;color:var(--ink-faint);margin-top:2px;">${((f.cds === undefined || f.cds === null) ? 0 : f.cds).toFixed(2)} (${esc(f.cds_band || "-")})</div></td>
      <td style="font-size:12.5px;">${esc(f.human_decision || f.status || "pending")}</td>
    </tr>`;
  }).join("");
  const explainBlocks = sorted.map(f => esc(f.explain)).join("\\n\\n---\\n\\n");
  return `<table class="findings-table"><thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Drift Score</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="terminal">
      <div class="terminal-bar"><div class="terminal-dot"></div><div class="terminal-dot"></div><div class="terminal-dot"></div><span>skillfence findings &mdash; raw output</span></div>
      <div class="terminal-body">${explainBlocks}</div>
    </div>`;
}

async function runLab(name) {
  const btn = document.getElementById("run-btn"), status = document.getElementById("run-status");
  const decision = document.getElementById("decision-select").value;
  btn.disabled = true;
  status.textContent = "running…";
  try {
    const result = await fetchJSON(`/api/lab/${name.split("/").map(encodeURIComponent).join("/")}/run?decision=${encodeURIComponent(decision)}`, {method: "POST"});
    status.textContent = `invocation #${result.invocation_number}`;
    document.getElementById("run-result").innerHTML = renderSteps(result.steps) + '<div class="section-label">Findings</div>' + renderFindings(result.findings);
  } catch (e) {
    status.textContent = "error: " + e.message;
  } finally {
    btn.disabled = false;
  }
}

document.getElementById("refresh-btn").onclick = loadLabs;
document.getElementById("filter").oninput = renderSidebar;
loadLabs();
</script>
</body>
</html>
"""
