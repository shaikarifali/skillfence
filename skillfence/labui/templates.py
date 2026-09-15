"""The Lab Explorer's single HTML page — the "Knightfall" visual identity
from the project's own campaign plan (Chapter/Trial structure, antique-
gold-on-dark-stone palette), applied to real, live lab data. The Chapter
names (`_CHAPTERS` below) are the plan's own AST01-AST10 mapping verbatim
-- not invented here. Per that plan's own rule ("Technical labels must
remain visible"), the AST0x code and every technical field stay visible
alongside the Chapter/Trial framing; the theme wraps the real data, it
never replaces or fictionalizes it.

Ships inside the pip package and has to render with zero internet access
(an air-gapped machine is a real, supported case -- same reasoning as
`dashboard.templates`), so there's no webfont/CDN request here: the
serif/mono stacks lean on solid system-font fallbacks instead.
"""

from __future__ import annotations

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SkillFence Lab Explorer</title>
<style>
:root{
  --bg:#120F0B; --surface:#1B1712; --surface-2:#241E17; --surface-3:#2E2619;
  --ink:#EDE3CC; --ink-dim:#B7A98A; --ink-faint:#8A7C60;
  --rule:#3B3222; --rule-strong:#4F4530;
  --gold:#C9A227; --gold-strong:#E8C46B; --gold-wash:#2A2411;
  --crit:#E36656; --crit-wash:#3A1E16;
  --high:#E0A24C; --high-wash:#332314;
  --med:#D2BB5C; --med-wash:#322A14;
  --ok:#8FB86C; --ok-wash:#202B18;
  --mono: ui-monospace, "SF Mono", "JetBrains Mono", Consolas, monospace;
  --serif: Georgia, "Iowan Old Style", "Palatino Linotype", "Times New Roman", serif;
  --shadow: 0 2px 4px rgba(0,0,0,.35), 0 14px 34px -14px rgba(0,0,0,.6);
}
@media (prefers-color-scheme: light){
  :root{
    --bg:#EBE3CC; --surface:#F8F3E4; --surface-2:#EFE6CC; --surface-3:#E4D8B8;
    --ink:#241C10; --ink-dim:#5B4E36; --ink-faint:#8A7C5E;
    --rule:#CBB98F; --rule-strong:#B4A177;
    --gold:#8A6A1F; --gold-strong:#6E5417; --gold-wash:#F1E7C6;
    --crit:#A5362A; --crit-wash:#F3DCD6;
    --high:#96601C; --high-wash:#F0E2CB;
    --med:#8A7420; --med-wash:#EFE7C6;
    --ok:#4C6B34; --ok-wash:#DDE7CC;
    --shadow: 0 1px 2px rgba(40,30,10,.08), 0 10px 26px -12px rgba(40,30,10,.25);
  }
}
:root{
  --ed-bg:#0F0D0A; --ed-bg-2:#171310; --ed-text:#DCD2B8;
  --ed-rule:#2E2718; --ed-heading:#E8C46B;
  --term-bg:#0A0908; --term-text:#D6CDB2; --term-dim:#8A7C60;
}

*{box-sizing:border-box;}
html,body{height:100%;}
body{ background:var(--bg); color:var(--ink); margin:0; font-family:var(--serif); font-size:15px; line-height:1.6; }
.mono,.chip,.tag,.wordmark,.evidence-th,.eyebrow,.trial-slug{ font-family:var(--mono); }
h1,h2,h3{ text-wrap:balance; font-weight:600; margin:0; }
p{ margin:0; }
::selection{ background:var(--gold-wash); }
button,select,input{ font:inherit; }
.divider{ height:1px; background:linear-gradient(90deg, var(--rule) 0%, var(--gold) 50%, var(--rule) 100%); opacity:.55; margin:0; position:relative; }
.divider::after{ content:"\\2726"; position:absolute; left:50%; top:50%; transform:translate(-50%,-50%); background:var(--bg); color:var(--gold); font-size:11px; padding:0 8px; }

.topbar{ display:flex; align-items:center; gap:16px; padding:12px 22px; background:var(--surface); border-bottom:1px solid var(--rule-strong); box-shadow:var(--shadow); position:relative; z-index:2; }
.crest{ width:20px; height:20px; flex-shrink:0; }
.wordmark{ font-weight:700; font-size:13.5px; letter-spacing:.06em; white-space:nowrap; color:var(--ink); text-transform:uppercase; }
.wordmark b{ color:var(--gold-strong); }
.root-path{ color:var(--ink-faint); font-size:11px; }
.spacer{ flex:1; }
.topbar button{ background:var(--surface-2); color:var(--ink-dim); border:1px solid var(--rule-strong); border-radius:4px; padding:6px 12px; font-size:11.5px; cursor:pointer; letter-spacing:.03em; }
.topbar button:hover{ border-color:var(--gold); color:var(--gold-strong); }

.shell{ display:flex; height:calc(100vh - 49px); }
#sidebar{ width:340px; flex-shrink:0; overflow-y:auto; border-right:1px solid var(--rule-strong); background:var(--surface); }
.filter-wrap{ padding:12px 14px; border-bottom:1px solid var(--rule); position:sticky; top:0; background:var(--surface); z-index:1; }
.filter-wrap input{ width:100%; background:var(--surface-2); color:var(--ink); border:1px solid var(--rule-strong); border-radius:4px; padding:7px 10px; font-size:12.5px; }
.filter-wrap input::placeholder{ color:var(--ink-faint); }
.filter-wrap input:focus{ outline:none; border-color:var(--gold); }
.cat-header{ padding:10px 14px 6px; background:var(--surface-2); border-bottom:1px solid var(--rule); border-top:1px solid var(--rule); }
.cat-header .roman{ font-family:var(--serif); font-weight:700; font-size:12.5px; color:var(--gold-strong); letter-spacing:.02em; }
.cat-header .chapter-name{ font-family:var(--serif); font-style:italic; font-size:12px; color:var(--ink-dim); }
.cat-header .ast-code{ font-family:var(--mono); font-size:9.5px; color:var(--ink-faint); letter-spacing:.06em; margin-top:2px; }
.lab-row{ padding:10px 14px; border-bottom:1px solid var(--rule); cursor:pointer; transition:background .1s ease; }
.lab-row:hover{ background:var(--surface-2); }
.lab-row.selected{ background:var(--gold-wash); border-left:3px solid var(--gold); padding-left:11px; }
.lab-row .skill{ font-family:var(--serif); font-weight:700; font-size:13.5px; color:var(--ink); }
.lab-row .slug{ color:var(--ink-faint); font-size:10.5px; font-family:var(--mono); margin-top:3px; }
.sigil{ display:inline-flex; align-items:center; gap:5px; font-size:10px; font-weight:700; letter-spacing:.05em; text-transform:uppercase; margin-top:6px; }
.sigil::before{ content:''; width:7px; height:7px; transform:rotate(45deg); }
.sigil.malicious{ color:var(--crit); } .sigil.malicious::before{ background:var(--crit); }
.sigil.benign{ color:var(--ok); } .sigil.benign::before{ background:var(--ok); }

#main{ flex:1; overflow-y:auto; padding:34px 44px 70px; }
#empty{ max-width:62ch; margin:90px auto; color:var(--ink-dim); font-size:15px; text-align:center; line-height:1.75; font-family:var(--serif); }
#empty code{ background:var(--surface-2); border:1px solid var(--rule); border-radius:3px; padding:1px 5px; font-size:.85em; font-family:var(--mono); color:var(--gold-strong); }

.eyebrow{ font-size:11px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:var(--gold-strong); }
.eyebrow .sep{ color:var(--ink-faint); margin:0 8px; }
.eyebrow .ast-tag{ color:var(--ink-faint); font-weight:600; }
.trial-title{ font-family:var(--serif); font-weight:700; font-size:32px; margin-top:8px; color:var(--ink); }
.trial-mission{ color:var(--ink-dim); font-size:14.5px; font-style:italic; margin-top:8px; max-width:70ch; }
.trial-slug{ color:var(--ink-faint); font-size:11.5px; margin-top:10px; }
.trial-meta{ margin-top:16px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }

.chip{ display:inline-flex; align-items:center; gap:5px; font-size:10.5px; font-weight:700; letter-spacing:.04em; padding:3px 10px; border-radius:2px; white-space:nowrap; text-transform:uppercase; border:1px solid currentColor; }
.chip-critical{ color:var(--crit); background:var(--crit-wash); }
.chip-high{ color:var(--high); background:var(--high-wash); }
.chip-medium{ color:var(--med); background:var(--med-wash); }
.chip-low, .chip-allow{ color:var(--ok); background:var(--ok-wash); }
.chip-none{ color:var(--ink-faint); background:var(--surface-2); border-color:var(--rule); }
.tag{ display:inline-block; font-size:10px; font-weight:600; letter-spacing:.02em; color:var(--ink-dim); background:var(--surface-2); border:1px solid var(--rule); padding:2px 8px; border-radius:2px; font-family:var(--mono); }

.oath{ margin-top:26px; padding:22px 26px; background:var(--surface); border:1px solid var(--rule-strong); border-radius:2px; box-shadow:var(--shadow); position:relative; }
.oath::before{ content:''; position:absolute; left:0; top:0; bottom:0; width:3px; background:var(--gold); }
.oath-label{ font-size:10.5px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:var(--gold-strong); margin-bottom:14px; }

.section-label{ margin-top:32px; margin-bottom:12px; font-size:11px; font-weight:700; letter-spacing:.1em; text-transform:uppercase; color:var(--ink-faint); display:flex; align-items:center; gap:10px; }
.section-label::after{ content:''; flex:1; height:1px; background:var(--rule); }

.ledger{ border:1px solid var(--rule-strong); border-radius:2px; overflow:hidden; background:var(--surface); }
table.evidence{ width:100%; border-collapse:collapse; }
.evidence-th{ text-align:left; font-size:10px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; color:var(--ink-faint); padding:9px 14px; border-bottom:1px solid var(--rule); background:var(--surface-2); }
.evidence-cell{ padding:9px 14px; border-bottom:1px solid var(--rule); font-size:13px; vertical-align:top; font-family:var(--mono); }
tr:last-child .evidence-cell{ border-bottom:none; }
.evidence-cell.k{ color:var(--ink-dim); font-family:var(--serif); width:170px; font-style:italic; }

.editor{ margin-top:6px; border:1px solid var(--ed-rule); border-radius:2px; overflow:hidden; box-shadow:var(--shadow); }
.editor-tabs{ display:flex; background:var(--ed-bg-2); border-bottom:1px solid var(--ed-rule); }
.editor-tab{ font-family:var(--mono); font-size:11px; color:var(--term-dim); padding:9px 16px; cursor:pointer; border-right:1px solid var(--ed-rule); background:transparent; letter-spacing:.02em; }
.editor-tab.active{ color:var(--ed-heading); background:var(--ed-bg); font-weight:600; }
.editor-tab:hover:not(.active){ color:var(--ed-text); }
.editor-body{ background:var(--ed-bg); max-height:380px; overflow-y:auto; padding:16px 18px; }
.editor-body pre{ margin:0; font-family:var(--mono); font-size:12.5px; line-height:1.7; white-space:pre-wrap; word-break:break-word; color:var(--ed-text); }
.code-panel{ display:none; } .code-panel.active{ display:block; }

.run-bar{ margin-top:8px; display:flex; align-items:center; gap:12px; padding:16px 20px; background:var(--gold-wash); border:1px solid var(--rule-strong); border-radius:2px; flex-wrap:wrap; }
.run-bar label{ color:var(--ink-dim); font-size:11.5px; font-family:var(--mono); }
.run-bar select{ background:var(--surface); color:var(--ink); border:1px solid var(--rule-strong); border-radius:3px; padding:6px 10px; font-size:12.5px; }
.run-btn{ display:flex; align-items:center; gap:8px; background:var(--gold); color:#1B1712; border:1px solid var(--gold-strong); border-radius:3px; padding:8px 18px; font-size:12px; font-weight:700; letter-spacing:.04em; text-transform:uppercase; cursor:pointer; }
.run-btn:hover:not(:disabled){ background:var(--gold-strong); }
.run-btn:disabled{ opacity:.4; cursor:default; }
#run-status{ font-size:12px; color:var(--ink-dim); font-family:var(--mono); }

.steps-table, .findings-table{ width:100%; border-collapse:collapse; font-size:13px; }
.steps-table th, .findings-table th{ text-align:left; color:var(--ink-faint); font-weight:700; font-size:10px; letter-spacing:.06em; text-transform:uppercase; padding:8px 12px; border-bottom:1px solid var(--rule); }
.steps-table td, .findings-table td{ padding:9px 12px; border-bottom:1px solid var(--rule); vertical-align:top; }
tr.finding-row.critical td:first-child{ border-left:3px solid var(--crit); }
tr.finding-row.high td:first-child{ border-left:3px solid var(--high); }
tr.finding-row.medium td:first-child{ border-left:3px solid var(--med); }
tr.finding-row.low td:first-child{ border-left:3px solid var(--ok); }
.status-ok{ color:var(--ok); font-weight:700; } .status-blocked{ color:var(--crit); font-weight:700; } .status-error{ color:var(--med); font-weight:700; }
.cds-track{ width:80px; height:7px; background:var(--surface-3); border-radius:2px; overflow:hidden; display:inline-block; vertical-align:middle; }
.cds-fill{ height:100%; }
.why ul{ margin:4px 0 0; padding-left:16px; color:var(--ink-dim); font-size:12px; }
.no-findings{ color:var(--ok); font-size:13.5px; font-weight:700; padding:14px 0; letter-spacing:.02em; }

.terminal{ margin-top:14px; border-radius:2px; overflow:hidden; border:1px solid var(--ed-rule); box-shadow:var(--shadow); }
.terminal-bar{ display:flex; align-items:center; gap:6px; padding:8px 12px; background:var(--ed-bg-2); border-bottom:1px solid var(--ed-rule); }
.terminal-dot{ width:8px; height:8px; border-radius:50%; background:var(--rule-strong); }
.terminal-bar span{ font-family:var(--mono); font-size:10px; color:var(--term-dim); margin-left:6px; letter-spacing:.03em; }
.terminal-body{ background:var(--term-bg); padding:14px 16px; font-family:var(--mono); font-size:12px; line-height:1.75; white-space:pre-wrap; color:var(--term-text); max-height:340px; overflow-y:auto; }

@media (prefers-reduced-motion: reduce){ *{ transition:none !important; } }
button:focus-visible, .lab-row:focus-visible, .editor-tab:focus-visible{ outline:2px solid var(--gold); outline-offset:2px; }
@media (max-width: 760px){ #sidebar{ width:230px; } #main{ padding:20px 18px; } .trial-title{ font-size:24px; } }
</style>
</head>
<body>
<div class="topbar">
  <svg class="crest" viewBox="0 0 24 24" fill="none"><path d="M12 2 L20 5 V11 C20 16 16.5 20 12 22 C7.5 20 4 16 4 11 V5 Z" stroke="#C9A227" stroke-width="1.4"/><path d="M12 6 L12 22 M6 11 H18" stroke="#C9A227" stroke-width="1" opacity=".6"/></svg>
  <div class="wordmark"><b>SkillFence</b> &middot; Lab Explorer</div>
  <div class="root-path" id="root-path"></div>
  <div class="spacer"></div>
  <button id="refresh-btn">&#8635; Refresh</button>
</div>
<div class="shell">
  <div id="sidebar">
    <div class="filter-wrap"><input id="filter" type="text" placeholder="Search the trials…"></div>
    <div id="lab-list"></div>
  </div>
  <div id="main">
    <div id="empty">Choose a trial from the left. Every field shown is read live from its real files —
    <code>skill/manifest.yaml</code>, <code>skill/SKILL.md</code>, <code>README.md</code>, <code>ground-truth.yaml</code> —
    and attempting a trial actually runs it through the real SkillFence engine, the same as
    <code>skillfence run</code> from a terminal. Nothing here is staged.</div>
  </div>
</div>
<script>
// The ten chapters, verbatim from the project's own Knightfall campaign plan
// (section 31) -- not invented for this page. Technical AST0x codes stay
// visible everywhere alongside these, per that plan's own rule.
const CHAPTERS = {
  AST01: {roman: "I",    name: "The False Knight"},
  AST02: {roman: "II",   name: "The Poisoned Forge"},
  AST03: {roman: "III",  name: "The Hungry Crown"},
  AST04: {roman: "IV",   name: "The Forged Seal"},
  AST05: {roman: "V",    name: "The Whispering Scroll"},
  AST06: {roman: "VI",   name: "The Broken Wall"},
  AST07: {roman: "VII",  name: "The Falling Oath"},
  AST08: {roman: "VIII", name: "The Blind Oracle"},
  AST09: {roman: "IX",   name: "The Shadow Council"},
  AST10: {roman: "X",    name: "The Fractured Realms"},
};
function chapterOf(ast) { return CHAPTERS[ast] || {roman: "?", name: ast}; }

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
function lastSegment(name) { const parts = name.split("/"); return parts[parts.length - 1]; }

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
    list.innerHTML = '<div style="padding:18px;color:var(--ink-faint);font-size:12px;">No trials found under this root.</div>';
    return;
  }
  const byAst = {};
  for (const lab of ALL_LABS) {
    if (filterText && !(lab.name.toLowerCase().includes(filterText) || (lab.skill_name || "").toLowerCase().includes(filterText))) continue;
    (byAst[lab.ast] = byAst[lab.ast] || []).push(lab);
  }
  const asts = Object.keys(byAst).sort();
  if (asts.length === 0) {
    list.innerHTML = '<div style="padding:18px;color:var(--ink-faint);font-size:12px;">No trials match that search.</div>';
    return;
  }
  for (const ast of asts) {
    const ch = chapterOf(ast);
    const header = document.createElement("div");
    header.className = "cat-header";
    header.innerHTML = `<div><span class="roman">Chapter ${ch.roman}</span> &middot; <span class="chapter-name">${esc(ch.name)}</span></div>
      <div class="ast-code">${esc(ast)} &middot; ${byAst[ast].length} trial(s)</div>`;
    list.appendChild(header);
    for (const lab of byAst[ast]) {
      const row = document.createElement("div");
      row.className = "lab-row" + (lab.name === selectedName ? " selected" : "");
      row.onclick = () => selectLab(lab.name);
      const sigil = lab.malicious === null ? "" : `<div class="sigil ${lab.malicious ? "malicious" : "benign"}">${lab.malicious ? "malicious" : "benign"}</div>`;
      row.innerHTML = `<div class="skill">${esc(lab.skill_name)}</div>
        <div class="slug">${esc(lastSegment(lab.name))}</div>
        ${sigil}`;
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
  return `<div class="trial-meta">
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
  const ch = chapterOf(detail.ast);
  const missionTitle = detail.ground_truth && detail.ground_truth.title;
  const mission = missionTitle ? `<div class="trial-mission">&ldquo;${esc(missionTitle)}&rdquo;</div>` : "";
  main.innerHTML = `
    <div class="eyebrow">Chapter ${ch.roman} &middot; ${esc(ch.name)}<span class="sep">/</span><span class="ast-tag">${esc(detail.ast)}</span></div>
    <div class="trial-title">${esc(detail.skill_name)}</div>
    ${mission}
    <div class="trial-slug">${esc(detail.name)} &middot; v${esc(detail.version)}${detail.session_count ? ` &middot; attempted ${detail.session_count}&times;` : " &middot; never attempted"}</div>
    <div class="trial-meta">${(detail.purpose || []).map(p => `<span class="tag">${esc(p)}</span>`).join("")}</div>
    ${renderGroundTruth(detail.ground_truth)}
    <div class="oath"><div class="oath-label">The Skill's Oath &mdash; declared capabilities</div>${renderCapabilities(detail.capabilities, detail.security)}</div>
    <div class="section-label">Dossier</div>
    ${renderFileTabs(detail.name, detail.skill_md, detail.readme) || "<p style='color:var(--ink-faint);font-size:13px;'>No SKILL.md or README.md found.</p>"}
    <div class="section-label">Attempt this Trial</div>
    <div class="run-bar">
      <label>Decision on gate</label>
      <select id="decision-select">
        <option value="reject">reject</option>
        <option value="approve_once">approve_once</option>
        <option value="allow_for_session">allow_for_session</option>
        <option value="allow_scoped">allow_scoped</option>
        <option value="quarantine_skill">quarantine_skill</option>
      </select>
      <button class="run-btn" id="run-btn" ${detail.runnable ? "" : "disabled"}>&#9876; Run</button>
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
  return `<div class="section-label">What Happened</div><table class="steps-table"><thead><tr><th>Action</th><th>Status</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderFindings(findings) {
  if (!findings.length) return '<div class="no-findings">&#10003; No findings &mdash; every action stayed within declared capability / low risk.</div>';
  const rank = {critical:4, high:3, medium:2, low:1, none:0};
  const sorted = [...findings].sort((a, b) => (rank[b.severity]||0) - (rank[a.severity]||0));
  const rows = sorted.map(f => {
    const cdsPct = Math.round((f.cds || 0) * 100);
    const cdsColor = {ALLOW:"var(--ok)", WARN:"var(--med)", GATE:"var(--high)", BLOCK:"var(--crit)"}[f.cds_band] || "var(--ink-faint)";
    const tags = (f.ast || []).map(t => `<span class="tag">${esc(t)}</span>`).join(" ");
    const why = (f.why_flagged || []).map(r => `<li>${esc(r)}</li>`).join("");
    return `<tr class="finding-row ${esc(f.severity)}">
      <td>${sevChip(f.severity)}</td>
      <td><div style="font-weight:700;">${esc(f.title)}</div><div style="margin-top:3px;">${tags}</div><div class="why"><ul>${why}</ul></div></td>
      <td style="font-family:var(--mono);font-size:12px;">${esc(f.resource || "-")}</td>
      <td><span class="cds-track"><span class="cds-fill" style="width:${cdsPct}%;background:${cdsColor}"></span></span>
          <div style="font-size:11px;color:var(--ink-faint);margin-top:2px;">${((f.cds === undefined || f.cds === null) ? 0 : f.cds).toFixed(2)} (${esc(f.cds_band || "-")})</div></td>
      <td style="font-size:12.5px;">${esc(f.human_decision || f.status || "pending")}</td>
    </tr>`;
  }).join("");
  const explainBlocks = sorted.map(f => esc(f.explain)).join("\\n\\n---\\n\\n");
  return `<div class="section-label">The Crown's Verdict</div>
    <table class="findings-table"><thead><tr><th>Severity</th><th>Finding</th><th>Resource</th><th>Drift Score</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table>
    <div class="terminal">
      <div class="terminal-bar"><div class="terminal-dot"></div><div class="terminal-dot"></div><div class="terminal-dot"></div><span>skillfence findings &mdash; raw output</span></div>
      <div class="terminal-body">${explainBlocks}</div>
    </div>`;
}

async function runLab(name) {
  const btn = document.getElementById("run-btn"), status = document.getElementById("run-status");
  const decision = document.getElementById("decision-select").value;
  btn.disabled = true;
  status.textContent = "the trial unfolds…";
  try {
    const result = await fetchJSON(`/api/lab/${name.split("/").map(encodeURIComponent).join("/")}/run?decision=${encodeURIComponent(decision)}`, {method: "POST"});
    status.textContent = `attempt #${result.invocation_number}`;
    document.getElementById("run-result").innerHTML = renderSteps(result.steps) + renderFindings(result.findings);
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
