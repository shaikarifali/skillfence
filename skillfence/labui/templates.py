"""The Lab Explorer's single HTML page. Same reasoning as
`skillfence.dashboard.templates`: self-contained, no CDN script, no build
step, no external network request of any kind -- has to render correctly
offline. Visually matches the dashboard's dark theme (same color tokens)
since this is the same tool's web surface, not a separate product.
"""

from __future__ import annotations

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SkillFence Lab Explorer</title>
<style>
  :root {
    --bg: #0f1115; --panel: #171a21; --panel-2: #1c2029; --border: #2a2e3a; --text: #e6e8ec;
    --dim: #8b93a3; --accent: #4f8cff; --mono: ui-monospace, SFMono-Regular, Consolas, monospace;
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
  header .root { color: var(--dim); font-size: 12px; font-family: var(--mono); }
  header .spacer { flex: 1; }
  #layout { display: flex; height: calc(100vh - 46px); }
  #sidebar { width: 320px; flex-shrink: 0; overflow-y: auto; border-right: 1px solid var(--border); background: var(--panel); }
  #filter-wrap { padding: 10px 12px; border-bottom: 1px solid var(--border); }
  #filter {
    width: 100%; background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
    border-radius: 4px; padding: 6px 8px; font-size: 12px;
  }
  .cat-header {
    padding: 8px 14px; font-size: 11px; font-weight: 700; letter-spacing: .05em;
    text-transform: uppercase; color: var(--dim); background: var(--panel-2);
    border-bottom: 1px solid var(--border); border-top: 1px solid var(--border);
    position: sticky; top: 0;
  }
  .lab-row { padding: 9px 14px; border-bottom: 1px solid var(--border); cursor: pointer; }
  .lab-row:hover { background: #1e222c; }
  .lab-row.selected { background: #1c2433; border-left: 3px solid var(--accent); }
  .lab-row .skill { font-weight: 600; font-size: 13px; }
  .lab-row .meta { color: var(--dim); font-size: 11px; margin-top: 2px; }
  .badge {
    display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 10.5px;
    font-weight: 600; text-transform: uppercase; color: #0f1115;
  }
  .badge.low { background: var(--low); } .badge.medium { background: var(--medium); }
  .badge.high { background: var(--high); } .badge.critical { background: var(--critical); color: #fff; }
  .badge.none { background: var(--none); color: var(--text); }
  .badge.malicious { background: var(--critical); color: #fff; }
  .badge.benign { background: var(--low); }
  #main { flex: 1; overflow-y: auto; padding: 20px 26px; }
  #empty { color: var(--dim); padding: 60px; text-align: center; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .05em; color: var(--dim);
       margin: 22px 0 10px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
  h2:first-of-type { margin-top: 0; }
  .lab-title { font-size: 20px; font-weight: 700; margin: 0; }
  .lab-sub { color: var(--dim); font-size: 13px; margin-top: 4px; }
  .cap-grid { display: grid; grid-template-columns: 140px 1fr; gap: 6px 14px; font-size: 13px; }
  .cap-grid .k { color: var(--dim); }
  .cap-grid .v { font-family: var(--mono); font-size: 12.5px; }
  .tag { display: inline-block; background: var(--panel-2); color: var(--dim); border: 1px solid var(--border);
         border-radius: 4px; padding: 1px 6px; margin-right: 4px; font-size: 11px; font-family: var(--mono); }
  .editor-tabs { display: flex; border: 1px solid var(--border); border-bottom: none; border-radius: 6px 6px 0 0; overflow: hidden; }
  .editor-tab { font-family: var(--mono); font-size: 11.5px; color: var(--dim); padding: 7px 14px; cursor: pointer;
                background: var(--panel-2); border-right: 1px solid var(--border); }
  .editor-tab.active { color: var(--text); background: var(--bg); font-weight: 600; }
  .editor-body { border: 1px solid var(--border); border-radius: 0 0 6px 6px; background: var(--bg);
                 max-height: 340px; overflow-y: auto; padding: 12px 14px; }
  .editor-body pre { margin: 0; font-family: var(--mono); font-size: 12px; white-space: pre-wrap; word-break: break-word; color: var(--text); }
  .code-panel { display: none; } .code-panel.active { display: block; }
  .run-bar { display: flex; align-items: center; gap: 10px; margin: 18px 0; padding: 12px 14px;
             background: var(--panel); border: 1px solid var(--border); border-radius: 8px; flex-wrap: wrap; }
  .run-bar label { color: var(--dim); font-size: 12px; }
  select, button {
    background: var(--panel-2); color: var(--text); border: 1px solid var(--border);
    border-radius: 4px; padding: 6px 10px; font-size: 12.5px; cursor: pointer;
  }
  button.primary { background: var(--accent); color: #fff; border-color: var(--accent); font-weight: 600; }
  button:disabled { opacity: .5; cursor: default; }
  button:hover:not(:disabled) { filter: brightness(1.1); }
  #run-status { font-size: 12px; color: var(--dim); }
  .steps-table, .findings-table { width: 100%; border-collapse: collapse; font-size: 13px; margin-top: 8px; }
  .steps-table th, .findings-table th { text-align: left; color: var(--dim); font-weight: 500; padding: 6px 8px; border-bottom: 1px solid var(--border); }
  .steps-table td, .findings-table td { padding: 6px 8px; border-bottom: 1px solid #1c1f28; vertical-align: top; }
  .status-ok { color: var(--low); } .status-blocked { color: var(--critical); font-weight: 600; } .status-error { color: var(--medium); }
  tr.finding-row.critical td:first-child { border-left: 3px solid var(--critical); }
  tr.finding-row.high td:first-child { border-left: 3px solid var(--high); }
  tr.finding-row.medium td:first-child { border-left: 3px solid var(--medium); }
  tr.finding-row.low td:first-child { border-left: 3px solid var(--low); }
  .cds-bar-track { width: 80px; height: 8px; background: #262b36; border-radius: 4px; overflow: hidden; display: inline-block; vertical-align: middle; }
  .cds-bar-fill { height: 100%; }
  .why ul { margin: 2px 0 0; padding-left: 16px; color: var(--dim); font-size: 12px; }
  .terminal { background: #0a0c10; border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; margin-top: 8px; }
  .terminal pre { margin: 0; font-family: var(--mono); font-size: 12px; white-space: pre-wrap; color: #cbd3cd; }
  .no-findings { color: var(--low); font-size: 13px; padding: 10px 0; }
  .ground-truth { font-size: 12.5px; color: var(--dim); margin-top: 6px; }
  .clean-badge { color: var(--low); font-weight: 600; }
</style>
</head>
<body>
<header>
  <h1>SkillFence Lab Explorer</h1>
  <span class="root" id="root-path"></span>
  <div class="spacer"></div>
  <button id="refresh-btn">Refresh</button>
</header>
<div id="layout">
  <div id="sidebar">
    <div id="filter-wrap"><input id="filter" type="text" placeholder="Filter labs by name…"></div>
    <div id="lab-list"></div>
  </div>
  <div id="main"><div id="empty">Select a lab on the left. Every field shown is read live from its real files —
    <code>skill/manifest.yaml</code>, <code>skill/SKILL.md</code>, <code>README.md</code>, <code>ground-truth.yaml</code> —
    and "Run" actually executes it through the real SkillFence engine, the same as <code>skillfence run</code> from a terminal.</div></div>
</div>
<script>
let ALL_LABS = [];
let selectedName = null;

async function fetchJSON(url, opts) {
  const res = await fetch(url, opts);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error || `${url}: ${res.status}`);
  return body;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
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
    list.innerHTML = '<div style="padding:16px;color:var(--dim);font-size:12px;">No labs found under this root.</div>';
    return;
  }
  const byAst = {};
  for (const lab of ALL_LABS) {
    if (filterText && !(lab.name.toLowerCase().includes(filterText) || (lab.skill_name || "").toLowerCase().includes(filterText))) continue;
    (byAst[lab.ast] = byAst[lab.ast] || []).push(lab);
  }
  const asts = Object.keys(byAst).sort();
  if (asts.length === 0) {
    list.innerHTML = '<div style="padding:16px;color:var(--dim);font-size:12px;">No labs match that filter.</div>';
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
      const verdictBadge = lab.malicious === null ? "" :
        `<span class="badge ${lab.malicious ? "malicious" : "benign"}">${lab.malicious ? "malicious" : "benign"}</span>`;
      row.innerHTML = `
        <div class="skill">${esc(lab.title || lab.skill_name)}</div>
        <div class="meta">${esc(lab.name)}</div>
        <div class="meta">${verdictBadge}</div>
      `;
      list.appendChild(row);
    }
  }
}

function capRow(k, v) { return `<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`; }

function renderCapabilities(caps, security) {
  const fs = caps.filesystem || {};
  const proc = caps.process || {};
  const net = caps.network || {};
  const sec = caps.secrets || {};
  let netVal = net.enabled ? (net.domains && net.domains.length ? net.domains.join(", ") : "enabled, unrestricted") : "disabled";
  let rows = [
    capRow("filesystem.read", (fs.read || []).join(", ") || "[]"),
    capRow("filesystem.write", (fs.write || []).join(", ") || "[]"),
    capRow("process.execute", (proc.execute || []).join(", ") || "[]"),
    capRow("network", netVal),
    capRow("secrets.access", sec.access ? "true" : "false"),
  ];
  if (security && security.scanned) {
    rows.push(capRow("security.scanned", `true (${security.scan_tool || "unspecified tool"})`));
  }
  return `<div class="cap-grid">${rows.join("")}</div>`;
}

function renderFileTabs(name, skillMd, readme) {
  const tabs = [];
  const panels = [];
  if (skillMd) { tabs.push(["skillmd", "SKILL.md"]); panels.push(["skillmd", skillMd]); }
  if (readme) { tabs.push(["readme", "README.md"]); panels.push(["readme", readme]); }
  if (tabs.length === 0) return "";
  const tabsHtml = tabs.map((t, i) => `<div class="editor-tab${i === 0 ? " active" : ""}" data-panel="ft-${esc(name)}-${t[0]}">${t[1]}</div>`).join("");
  const panelsHtml = panels.map((p, i) => `<div class="code-panel${i === 0 ? " active" : ""}" id="ft-${esc(name)}-${p[0]}"><pre>${esc(p[1])}</pre></div>`).join("");
  return `<div class="editor-tabs">${tabsHtml}</div><div class="editor-body">${panelsHtml}</div>`;
}

function renderGroundTruth(gt) {
  if (!gt) return "";
  const ef = gt.expected_finding || {};
  return `<div class="ground-truth">Expected: ${gt.ground_truth && gt.ground_truth.malicious ? "malicious" : "benign"}` +
    (ef.ast ? ` — AST tags ${ef.ast.map(t => `<span class="tag">${esc(t)}</span>`).join("")}` : "") +
    (ef.severity_at_least ? ` — severity ≥ <strong>${esc(ef.severity_at_least)}</strong>` : "") + `</div>`;
}

async function selectLab(name) {
  selectedName = name;
  renderSidebar();
  const detail = await fetchJSON(`/api/lab/${name.split("/").map(encodeURIComponent).join("/")}`);
  const main = document.getElementById("main");
  main.innerHTML = `
    <p class="lab-title">${esc(detail.skill_name)}</p>
    <p class="lab-sub">${esc(detail.name)} &middot; v${esc(detail.version)}${detail.session_count ? ` &middot; ${detail.session_count} run(s) recorded` : ""}</p>
    <h2>Purpose</h2>
    <div>${(detail.purpose || []).map(p => `<div>&middot; ${esc(p)}</div>`).join("") || "<i>none declared</i>"}</div>
    <h2>Declared capabilities</h2>
    ${renderCapabilities(detail.capabilities, detail.security)}
    ${renderGroundTruth(detail.ground_truth)}
    <h2>Files</h2>
    ${renderFileTabs(detail.name, detail.skill_md, detail.readme) || "<i>no SKILL.md or README.md found</i>"}
    <h2>Run</h2>
    <div class="run-bar">
      <label>Decision on gate:</label>
      <select id="decision-select">
        <option value="reject">reject</option>
        <option value="approve_once">approve_once</option>
        <option value="allow_for_session">allow_for_session</option>
        <option value="allow_scoped">allow_scoped</option>
        <option value="quarantine_skill">quarantine_skill</option>
      </select>
      <button class="primary" id="run-btn" ${detail.runnable ? "" : "disabled"}>&#9654; Run</button>
      <span id="run-status"></span>
    </div>
    <div id="run-result"></div>
  `;
  document.querySelectorAll(".editor-tab").forEach(tab => {
    tab.onclick = () => {
      const tabs = tab.parentElement;
      const body = tabs.nextElementSibling;
      tabs.querySelectorAll(".editor-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      body.querySelectorAll(".code-panel").forEach(p => p.classList.remove("active"));
      document.getElementById(tab.getAttribute("data-panel")).classList.add("active");
    };
  });
  if (detail.runnable) {
    document.getElementById("run-btn").onclick = () => runLab(detail.name);
  }
}

function severityRank(sev) { return {critical: 4, high: 3, medium: 2, low: 1, none: 0}[sev] ?? 0; }

function renderSteps(steps) {
  if (!steps.length) return "";
  const rows = steps.map(s => `<tr><td>${esc(s.action)}</td><td class="status-${esc(s.status)}">${esc(s.status)}</td><td>${esc(s.detail || "")}</td></tr>`).join("");
  return `<h2>Run steps</h2><table class="steps-table"><thead><tr><th>Action</th><th>Status</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderFindings(findings) {
  if (!findings.length) return '<div class="no-findings">No findings — every action stayed within declared capability / low risk.</div>';
  const sorted = [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
  const rows = sorted.map(f => {
    const cdsPct = Math.round((f.cds || 0) * 100);
    const cdsColor = {ALLOW: "var(--low)", WARN: "var(--medium)", GATE: "var(--high)", BLOCK: "var(--critical)"}[f.cds_band] || "var(--dim)";
    const tags = (f.ast || []).map(t => `<span class="tag">${esc(t)}</span>`).join("");
    const why = (f.why_flagged || []).map(r => `<li>${esc(r)}</li>`).join("");
    return `
      <tr class="finding-row ${esc(f.severity)}">
        <td><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span></td>
        <td><div><strong>${esc(f.title)}</strong></div><div>${tags}</div><div class="why"><ul>${why}</ul></div></td>
        <td>${esc(f.resource || "-")}</td>
        <td><span class="cds-bar-track"><span class="cds-bar-fill" style="width:${cdsPct}%;background:${cdsColor}"></span></span>
            <div style="font-size:11px;color:var(--dim);">${(f.cds ?? 0).toFixed(2)} (${esc(f.cds_band || "-")})</div></td>
        <td>${esc(f.human_decision || f.status || "pending")}</td>
      </tr>`;
  }).join("");
  const explainBlocks = sorted.map(f => `<pre>${esc(f.explain)}</pre>`).join("\\n");
  return `<table class="findings-table"><thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Drift Score</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table>
          <div class="terminal">${explainBlocks}</div>`;
}

async function runLab(name) {
  const btn = document.getElementById("run-btn");
  const status = document.getElementById("run-status");
  const decision = document.getElementById("decision-select").value;
  btn.disabled = true;
  status.textContent = "running…";
  try {
    const result = await fetchJSON(`/api/lab/${name.split("/").map(encodeURIComponent).join("/")}/run?decision=${encodeURIComponent(decision)}`, {method: "POST"});
    status.textContent = `invocation #${result.invocation_number}`;
    document.getElementById("run-result").innerHTML = renderSteps(result.steps) + "<h2>Findings</h2>" + renderFindings(result.findings);
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
